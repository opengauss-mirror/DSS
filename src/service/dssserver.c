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
#include "dss_blackbox.h"
#include "dss_dyn.h"
#endif
#include "cm_types.h"
#include "cm_signal.h"
#include "cm_utils.h"
#include "dss_errno.h"
#include "dss_shm.h"
#include "dss_instance.h"
#include "dss_mes.h"
#include "dss_blackbox.h"
#include "dss_zero.h"
#include "cm_utils.h"
#include "dss_meta_buf.h"
#include "dss_syn_meta.h"
#include "dss_thv.h"

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
    DSS_RETURN_IF_ERROR(dss_sigcap_handle_reg());
    return dss_signal_proc_with_graceful_exit();
}
#endif

static void dss_close_background_task(dss_instance_t *inst)
{
    uint32 bg_task_base_id = dss_get_udssession_startid() - (uint32)DSS_BACKGROUND_TASK_NUM;
    for (uint32 i = 0; i < DSS_BACKGROUND_TASK_NUM; i++) {
#ifdef WIN32
        if (i == DSS_DYN_LOG_TASK) {
            continue;
        }
#endif
        uint32 bg_task_id = bg_task_base_id + i;
        if (inst->threads[bg_task_id].id != 0) {
            cm_close_thread(&inst->threads[bg_task_id]);
        }
    }
}

static void dss_close_thread(dss_instance_t *inst)
{
    // pause lsnr thread
    uds_lsnr_t *lsnr = &inst->lsnr;
    cm_latch_x(&inst->uds_lsnr_latch, DSS_DEFAULT_SESSIONID, NULL);
    cs_pause_uds_lsnr(lsnr);
    cm_unlatch(&inst->uds_lsnr_latch, NULL);
    // close worker thread
    dss_destroy_reactors();

    if (inst->threads != NULL) {
        dss_close_background_task(inst);
    }

    // close lsnr thread
    cs_stop_uds_lsnr(lsnr);
    lsnr->status = LSNR_STATUS_STOPPED;

    // close time thread, should at end, no timer, no time
    cm_close_timer(g_timer());
}

// only detach success, will destory shm memory
static void dss_destory_shm_memory()
{
    if (!g_shm_inited) {
        return;
    }
    if (g_vgs_info != NULL) {
        for (uint32 i = 0; i < DSS_MAX_VOLUME_GROUP_NUM; i++) {
            (void)cm_del_shm(SHM_TYPE_HASH, i);
        }
    }
    ga_destroy_global_area();
    (void)del_shm_by_key(CM_SHM_CTRL_KEY);
    cm_destroy_shm();
}

static void dss_clean_server()
{
    dss_close_thread(&g_dss_instance);
    dss_stop_mes();
    // may be close delete clean thread in mes, so after stop mes to free threads
    DSS_FREE_POINT(g_dss_instance.threads);
    DSS_FREE_POINT(g_delete_buf);
    dss_uninit_cm(&g_dss_instance);
    dss_free_log_ctrl();
    if (g_dss_instance.lock_fd != CM_INVALID_INT32) {
        (void)cm_unlock_fd(g_dss_instance.lock_fd);
        cm_close_file(g_dss_instance.lock_fd);
    }
    CM_FREE_PTR(cm_log_param_instance()->log_compress_buf);
    dss_destory_shm_memory();
    dss_uninit_zero_buf();
    CM_FREE_PTR(g_dss_session_ctrl.sessions);
}

static void handle_main_wait(void)
{
    int64 periods = 0;
    uint32 interval = 500;
    do {
        if (g_dss_instance.abort_status == CM_TRUE) {
            break;
        }
        if (!g_dss_instance.is_maintain) {
            dss_check_peer_inst(&g_dss_instance, DSS_INVALID_ID64);
        }
        if (periods == MILLISECS_PER_SECOND * SECONDS_PER_DAY / interval) {
            periods = 0;
            dss_ssl_ca_cert_expire();
        }
        if (dss_is_readwrite()) {
            dss_check_unreg_volume(g_dss_instance.handle_session);
        }

        dss_clean_all_sessions_latch();
        cm_sleep(interval);
        periods++;
    } while (CM_TRUE);
    dss_clean_server();
}

static status_t dss_recovery_background_task(dss_instance_t *inst)
{
    LOG_RUN_INF("create dss recovery background task.");
    uint32 recovery_thread_id = dss_get_udssession_startid() - (uint32)DSS_BACKGROUND_TASK_NUM;
    status_t status = cm_create_thread(
        dss_get_cm_lock_and_recover, 0, &g_dss_instance, &(g_dss_instance.threads[recovery_thread_id]));
    return status;
}

static status_t dss_hashmap_dynamic_extend_background_task(dss_instance_t *inst)
{
    LOG_RUN_INF("create dss hashmap extend background task.");
    uint32 hashmap_extend_idx = dss_get_hashmap_dynamic_extend_task_idx();
    status_t status = cm_create_thread(dss_hashmap_dynamic_extend_and_redistribute_proc, 0, &g_dss_instance,
        &(g_dss_instance.threads[hashmap_extend_idx]));
    return status;
}

static status_t dss_create_bg_task_set(dss_instance_t *inst, char *task_name, uint32 max_task_num,
    dss_get_bg_task_idx_func_t get_bg_task_idx, thread_entry_t bg_task_entry, dss_bg_task_info_t *bg_task_info_set,
    void *task_args)
{
    LOG_RUN_INF("create dss background task set for:%s.", task_name);

    uint32 task_num = g_vgs_info->group_num;
    if (task_num > max_task_num) {
        task_num = max_task_num;
    }

    uint32 vg_per_task = g_vgs_info->group_num / task_num;
    uint32 vg_left = g_vgs_info->group_num % task_num;

    uint32 vg_id = 0;
    uint32 cur_range = 0;

    for (uint32 i = 0; i < task_num; i++) {
        bg_task_info_set[i].task_num_max = task_num;
        bg_task_info_set[i].my_task_id = i;
        bg_task_info_set[i].vg_id_beg = vg_id;
        bg_task_info_set[i].task_args = task_args;
        if (vg_left > 0) {
            cur_range = vg_per_task + 1;
            vg_left--;
        } else {
            cur_range = vg_per_task;
        }
        bg_task_info_set[i].vg_id_end = bg_task_info_set[i].vg_id_beg + cur_range;
        vg_id = bg_task_info_set[i].vg_id_end;
        LOG_RUN_INF("task:%s id:%u, vg_range:[%u-%u).", task_name, bg_task_info_set[i].my_task_id,
            bg_task_info_set[i].vg_id_beg, bg_task_info_set[i].vg_id_end);

        uint32 work_idx = get_bg_task_idx(i);
        status_t status = cm_create_thread(bg_task_entry, 0, &(bg_task_info_set[i]), &(inst->threads[work_idx]));
        if (status != CM_SUCCESS) {
            return CM_ERROR;
        }
    }
    return CM_SUCCESS;
}

static status_t dss_create_meta_syn_bg_task_set(dss_instance_t *inst)
{
    if (!dss_is_syn_meta_enable()) {
        return CM_SUCCESS;
    }
    LOG_RUN_INF("create dss meta syn background task.");
    status_t status = dss_create_bg_task_set(inst, "dss meta syn background task", DSS_META_SYN_BG_TASK_NUM_MAX,
        dss_get_meta_syn_task_idx, dss_meta_syn_proc, inst->syn_meta_task, NULL);
    if (status != CM_SUCCESS) {
        LOG_RUN_ERR("Create dss meta syn background task set failed.");
    }
    return status;
}

static status_t dss_create_recycle_meta_bg_task_set(dss_instance_t *inst)
{
    LOG_RUN_INF("create dss recycle meta background task.");

    inst->recycle_meta.recycle_meta_args.time_clean_wait_time = DSS_RECYCLE_META_TRIGGER_WAIT_TIME;
    inst->recycle_meta.recycle_meta_args.trigger_clean_wait_time = DSS_RECYCLE_META_TRIGGER_WAIT_TIME;
    inst->recycle_meta.recycle_meta_args.recyle_meta_pos = &inst->inst_cfg.params.recyle_meta_pos;
    cm_init_cond(&inst->recycle_meta.recycle_meta_args.trigger_cond);

#if defined(_DEBUG) || defined(DEBUG) || defined(DB_DEBUG_VERSION)
    // set recyle_meta_pos from param cfg
#else
    // set recyle_meta_pos by default
    inst->recycle_meta.recycle_meta_args.recyle_meta_pos->hwm = DSS_RECYCLE_META_RECYCLE_RATE_HWM;
    inst->recycle_meta.recycle_meta_args.recyle_meta_pos->lwm = DSS_RECYCLE_META_RECYCLE_RATE_LWM;
#endif

    status_t status = dss_create_bg_task_set(inst, "dss recycle meta background task", DSS_RECYLE_META_TASK_NUM_MAX,
        dss_get_recycle_meta_task_idx, dss_recycle_meta_proc, inst->recycle_meta.recycle_meta_task,
        &inst->recycle_meta.recycle_meta_args);
    if (status != CM_SUCCESS) {
        LOG_RUN_ERR("Create dss recycle meta background task set failed.");
    }
    return status;
}

static status_t dss_alarm_check_background_task(dss_instance_t *inst)
{
    LOG_RUN_INF("create dss alarm check background task.");
    uint32 vg_usgae_alarm_thread_id = dss_get_alarm_check_task_idx();
    status_t status =
        cm_create_thread(dss_alarm_check_proc, 0, &g_dss_instance, &(g_dss_instance.threads[vg_usgae_alarm_thread_id]));
    return status;
}

#ifndef WIN32
static status_t dss_dyn_log_background_task(dss_instance_t *inst)
{
    LOG_RUN_INF("create dss dyn log background task.");
    uint32 dyn_log_thread_id = dss_get_dyn_log_task_idx();
    status_t status =
        cm_create_thread(dss_dyn_log_proc, 0, &g_dss_instance, &(g_dss_instance.threads[dyn_log_thread_id]));
    return status;
}
#endif

static status_t dss_init_background_tasks(void)
{
    status_t status = dss_recovery_background_task(&g_dss_instance);
    if (status != CM_SUCCESS) {
        LOG_RUN_ERR("Create dss recovery background task failed.");
        return status;
    }
    status = dss_create_meta_syn_bg_task_set(&g_dss_instance);
    if (status != CM_SUCCESS) {
        LOG_RUN_ERR("Create dss syn meta background task failed.");
        return status;
    }
    status = dss_hashmap_dynamic_extend_background_task(&g_dss_instance);
    if (status != CM_SUCCESS) {
        LOG_RUN_ERR("Create hashmap_extend meta background task failed.");
        return status;
    }

    status = dss_create_recycle_meta_bg_task_set(&g_dss_instance);
    if (status != CM_SUCCESS) {
        LOG_RUN_ERR("Create dss recycle meta background task failed.");
        return status;
    }
    status = dss_alarm_check_background_task(&g_dss_instance);
    if (status != CM_SUCCESS) {
        LOG_RUN_ERR("Create dss vg usage alarm background task failed.");
        return status;
    }
#ifndef WIN32
    status = dss_dyn_log_background_task(&g_dss_instance);
    if (status != CM_SUCCESS) {
        LOG_RUN_ERR("Create dss dyn log background task failed.");
        return status;
    }
#endif
    return status;
}

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
    uint32 len = (uint32)strlen(home);
    if (len == 0 || len >= DSS_MAX_PATH_BUFFER_SIZE) {
        (void)printf("the len of path specified by -D is invalid.\n");
        return CM_ERROR;
    }
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

status_t dss_srv_parse_maintain(int argc, char **argv, int *argIdx, dss_srv_args_t *dss_args)
{
    dss_args->is_maintain = true;
    return CM_SUCCESS;
}

dss_srv_arg_handler_t g_dss_args_handler[] = {{"-D", dss_srv_parse_home}, {"-M", dss_srv_parse_maintain}};

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
                 "\t -M                 DSS_MAINTAIN mode.\n"
                 "\t -h                 show the help information.\n"
                 "\t -D                 specify dss server home path.\n");
}
#ifndef WIN32
status_t dss_set_signal_block()
{
    int32 error;
    sigset_t sign_old_mask;
    (void)sigprocmask(0, NULL, &sign_old_mask);
    (void)sigprocmask(SIG_UNBLOCK, &sign_old_mask, NULL);
    sigset_t block_sigs;
    sigemptyset(&block_sigs);
    sigaddset(&block_sigs, SIG_DYN_LOG);
    error = pthread_sigmask(SIG_BLOCK, &block_sigs, NULL);
    if (error != EOK) {
        printf("Fail to set sigmask, error: %d.\n", error);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}
#endif

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
#ifndef WIN32
    if (dss_set_signal_block() != CM_SUCCESS) {
        (void)fflush(stdout);
        return CM_ERROR;
    }
    regist_exit_proc(dss_exit_proc);
#endif
    if (dss_startup(&g_dss_instance, dss_args) != CM_SUCCESS) {
        (void)printf("dss failed to startup.\n");
        fflush(stdout);
        dss_clean_server();
        LOG_RUN_ERR("dss failed to startup.");
        return CM_ERROR;
    }
#ifndef WIN32
    if (dss_update_state_file(CM_FALSE) != CM_SUCCESS) {
        LOG_RUN_WAR("failed to update core state file.");
        cm_reset_error();
    }
    if (dss_signal_proc() != CM_SUCCESS) {
        (void)printf("dss instance startup failed when register signal.\n");
        fflush(stdout);
        dss_clean_server();
        LOG_RUN_ERR("dss instance startup failed when register signal.");
        return CM_ERROR;
    }
#endif
    if (dss_init_background_tasks() != CM_SUCCESS) {
        (void)printf("DSS SERVER END.\n");
        fflush(stdout);
        dss_clean_server();
        LOG_RUN_ERR("dss failed to startup.");
        LOG_RUN_INF("DSS SERVER STARTED.\n");
        return CM_ERROR;
    }
    (void)printf("DSS SERVER STARTED.\n");
    LOG_RUN_INF("DSS SERVER STARTED.\n");
    log_param_t *log_param = cm_log_param_instance();
    log_param->log_instance_starting = CM_FALSE;
    handle_main_wait();
    (void)printf("DSS SERVER END.\n");
    LOG_RUN_INF("DSS SERVER END.\n");
    return 0;
}

#ifdef __cplusplus
}
#endif
