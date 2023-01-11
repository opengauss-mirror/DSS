/*
 * Copyright (c) 2022 Huawei Technologies Co.,Ltd.
 *
 * DSS is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *
 *          http://license.coscl.org.cn/MulanPSL2
 *
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 * -------------------------------------------------------------------------
 *
 * dssserver.c
 *
 *
 * IDENTIFICATION
 *    src/service/dssserver.c
 *
 * -------------------------------------------------------------------------
 */

#include <stdio.h>
#include <stdlib.h>
#ifndef WIN32
#include <unistd.h>
#include <sys/types.h>
#endif
#include "cm_types.h"
#include "cm_signal.h"
#include "cm_utils.h"
#include "dss_errno.h"
#include "dss_signal.h"
#include "dss_instance.h"
#include "dss_mes.h"

#ifndef _NSIG
#define MAX_SIG_NUM 32
#else
#define MAX_SIG_NUM _NSIG
#endif

#ifdef __cplusplus
extern "C" {
#endif

#ifndef WIN32
static void handle_signal_terminal(int sig_no)
{
    g_dss_instance.abort_status = CM_TRUE;
}

status_t dss_signal_proc_with_graceful_exit(void)
{
    status_t ret = cm_regist_signal(SIGUSR1, handle_signal_terminal);
    DSS_RETURN_IF_ERROR(ret);
    return cm_regist_signal(SIGTERM, handle_signal_terminal);
}

status_t dss_signal_proc(void)
{
    DSS_RETURN_IF_ERROR(dss_ignore_signal_proc());
    DSS_RETURN_IF_ERROR(cm_regist_signal(SIGINT, SIG_DFL));
    DSS_RETURN_IF_ERROR(dss_coredump_signal_proc());
    return dss_signal_proc_with_graceful_exit();
}
#endif

static void dss_close_thread(dss_instance_t *inst)
{
    // pause lsnr thread
    uds_lsnr_t *lsnr = &inst->lsnr;
    cs_pause_uds_lsnr(lsnr);
    // close worker thread
    uint32 cfg_session_num = inst->inst_cfg.params.cfg_session_num;
    if (inst->threads != NULL) {
        for (uint32 i = 0; i < cfg_session_num; i++) {
            inst->threads[i].closed = CM_TRUE;
        }
        while (inst->thread_cnt != 0) {
            cm_sleep(1);
        }
        DSS_FREE_POINT(inst->threads);
    }

    // close lsnr thread
    cs_stop_uds_lsnr(lsnr);
    lsnr->status = LSNR_STATUS_STOPPED;

    // close time thread, should at end, no timer, no time
    cm_close_timer(g_timer());
}

static void dss_clean_server()
{
    dss_close_thread(&g_dss_instance);
    dss_stop_mes();
    dss_uninit_cm(&g_dss_instance);
    dss_free_log_ctrl(&g_dss_instance);
    if (g_dss_instance.lock_fd != CM_INVALID_INT32) {
        (void)cm_unlock_fd(g_dss_instance.lock_fd);
        cm_close_file(g_dss_instance.lock_fd);
    }
}

static void handle_main_wait(void)
{
    do {
        if (g_dss_instance.abort_status == CM_TRUE) {
            break;
        }
        dss_check_peer_inst(&g_dss_instance, DSS_INVALID_64);
        dss_ssl_ca_cert_expire();
        cm_sleep(500);
    } while (CM_TRUE);
    dss_clean_server();
}

typedef struct st_dss_srv_args {
    char dss_home[DSS_MAX_NAME_LEN];
} dss_srv_args_t;
typedef status_t (*dss_srv_arg_parser)(int argc, char **argv, int *argIdx, dss_srv_args_t *dss_args);
typedef struct st_dss_srv_arg_handler {
    char name[DSS_MAX_PATH_BUFFER_SIZE];
    dss_srv_arg_parser parser;
} dss_srv_arg_handler_t;

status_t dss_srv_parse_home(int argc, char **argv, int *argIdx, dss_srv_args_t *dss_args)
{
    if ((*argIdx + 1) >= argc || argv[*argIdx + 1] == NULL) {
        (void)printf("-D should specified home path.\n");
        return CM_ERROR;
    }
    char *home = (char *)argv[*argIdx + 1];
    if (realpath_file(home, dss_args->dss_home, DSS_MAX_PATH_BUFFER_SIZE) != CM_SUCCESS) {
        (void)printf("The path specified by -D is invalid.\n");
        return CM_ERROR;
    }
    if (!cm_dir_exist(dss_args->dss_home) || (access(dss_args->dss_home, R_OK) != 0)) {
        (void)printf("The path specified by -D is invalid.\n");
        return CM_ERROR;
    }
    (*argIdx)++;
    return CM_SUCCESS;
}
dss_srv_arg_handler_t g_dss_args_handler[] = {{"-D", dss_srv_parse_home}};

status_t dss_srv_parse_one_agr(int argc, char **argv, dss_srv_args_t *dss_args, int *argIdx)
{
    int support_args_count = sizeof(g_dss_args_handler) / sizeof(g_dss_args_handler[0]);
    for (int support_idx = 0; support_idx < support_args_count; support_idx++) {
        if (cm_str_equal(argv[*argIdx], g_dss_args_handler[support_idx].name)) {
            return g_dss_args_handler[support_idx].parser(argc, argv, argIdx, dss_args);
        }
    }
    (void)printf("invalid argument: %s\n", argv[*argIdx]);
    return CM_ERROR;
}

status_t dss_srv_parse_agrs(int argc, char **argv, dss_srv_args_t *dss_args)
{
    status_t ret;
    for (int i = 1; i < argc; i++) {
        ret = dss_srv_parse_one_agr(argc, argv, dss_args, &i);
        if (ret != CM_SUCCESS) {
            return ret;
        }
    }
    return CM_SUCCESS;
}

static void dss_srv_usage()
{
    (void)printf("Usage:\n"
                 "       dssserver [-h]\n"
                 "       dssserver [-D dss_home_path]\n"
                 "Option:\n"
                 "\t -h                 show the help information.\n"
                 "\t -D                 specify dss server home path.\n");
}

int main(int argc, char **argv)
{
#ifndef WIN32
    // check root
    if (geteuid() == 0 || getuid() != geteuid()) {
        (void)printf("The root user is not permitted to execute the dssserver "
                     "and the real uids must be the same as the effective uids.\n");
        (void)fflush(stdout);
        return CM_ERROR;
    }
#endif

    if (argc == 2) {
        if (cm_str_equal(argv[1], "-h")) {
            dss_srv_usage();
            return CM_SUCCESS;
        }
    }

    dss_srv_args_t dss_args;
    errno_t errcode = memset_s(&dss_args, sizeof(dss_args), 0, sizeof(dss_args));
    securec_check_ret(errcode);
    if (dss_srv_parse_agrs(argc, argv, &dss_args) != CM_SUCCESS) {
        (void)fflush(stdout);
        return CM_ERROR;
    }

    if (dss_startup(&g_dss_instance, dss_args.dss_home) != CM_SUCCESS) {
        printf("dss failed to startup.\n");
        fflush(stdout);
        dss_clean_server();
        LOG_RUN_ERR("dss failed to startup.");
        return CM_ERROR;
    }
#ifndef WIN32
    if (dss_signal_proc() != CM_SUCCESS) {
        printf("dss instance startup failed.\n");
        fflush(stdout);
        dss_clean_server();
        LOG_RUN_ERR("dss failed to startup.");
        return CM_ERROR;
    }
#endif
    (void)printf("DSS SERVER STARTED.\n");
    LOG_RUN_INF("DSS SERVER STARTED.\n");
    handle_main_wait();
    (void)printf("DSS SERVER END.\n");
    LOG_RUN_INF("DSS SERVER END.\n");
    return 0;
}

#ifdef __cplusplus
}
#endif
