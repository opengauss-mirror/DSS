/*
 * Copyright (c) 2024 Huawei Technologies Co.,Ltd.
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
 * dsstbox.c
 *
 *
 * IDENTIFICATION
 *    src/tbox/dsstbox.c
 *
 * -------------------------------------------------------------------------
 */

#include "dsstbox.h"
#ifndef WIN32
#include <unistd.h>
#include <sys/types.h>
#endif
#include "cm_base.h"
#include "cm_signal.h"

#include "dss_log.h"
#include "dss_errno.h"
#include "dss_malloc.h"
#include "dss_file.h"
#include "dss_diskgroup.h"
#include "dsstbox_repair.h"
#include "dsstbox_miner.h"
#include "dss_args_parse.h"
#ifndef WIN32
#include "config.h"
#endif

#ifdef WIN32
#define DEF_DSS_VERSION "Windows does not support this feature because it is built using vs."
#endif

dss_log_def_t g_dss_dsstbox_log[] = {
    {LOG_DEBUG, "debug/dsstbox.dlog"},
    {LOG_OPER, "oper/dsstbox.olog"},
    {LOG_RUN, "run/dsstbox.rlog"},
    {LOG_ALARM, "alarm/dsstbox.alog"},
};

status_t dss_check_meta_type(const char *type)
{
    if ((cm_strcmpi(type, DSS_REPAIR_TYPE_FS_BLOCK) != 0) && (cm_strcmpi(type, DSS_REPAIR_TYPE_FT_BLOCK) != 0) &&
        (cm_strcmpi(type, DSS_REPAIR_TYPE_CORE_CTRL) != 0) && (cm_strcmpi(type, DSS_REPAIR_TYPE_ROOT) != 0) &&
        (cm_strcmpi(type, DSS_REPAIR_TYPE_VOLUME) != 0) && (cm_strcmpi(type, DSS_REPAIR_TYPE_HEADER) != 0)) {
        DSS_PRINT_ERROR("Invalid tbox ssrepair type:%s.\n", type);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

status_t dss_check_meta_id(const char *intput)
{
    uint64 id = 0;
    status_t status = cm_str2uint64(intput, &id);
    if (status == CM_ERROR) {
        DSS_PRINT_ERROR("intput:%s is not a valid uint64 meta id\n", intput);
        return CM_ERROR;
    }
    dss_block_id_t *block_id = (dss_block_id_t *)&id;
    if (block_id->volume >= DSS_MAX_VOLUMES) {
        DSS_PRINT_ERROR("block_id is invalid, id = %s.\n", dss_display_metaid(*block_id));
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static dss_args_t tbox_repair_args[] = {
    {'v', "vol_path", CM_TRUE, CM_TRUE, dss_check_volume_path, NULL, NULL, 0, NULL, NULL, 0},
    {'t', "type", CM_TRUE, CM_TRUE, dss_check_meta_type, NULL, NULL, 0, NULL, NULL, 0},
    {'i', "id", CM_FALSE, CM_TRUE, dss_check_meta_id, NULL, NULL, 0, NULL, NULL, 0},
    {'s', "au_size", CM_FALSE, CM_TRUE, cmd_check_au_size, NULL, NULL, 0, NULL, NULL, 0},
    {'k', "key_value", CM_TRUE, CM_TRUE, NULL, NULL, NULL, 0, NULL, NULL, 0},
};

// -i and -s is needed only when "-t fs_block"
static status_t check_repair_args(dss_args_t *cmd_args_set, int set_size)
{
    if (strcmp(cmd_args_set[DSS_REPAIR_ARG_TYPE].input_args, DSS_REPAIR_TYPE_FS_BLOCK) == 0) {
        if (!cmd_args_set[DSS_REPAIR_ARG_META_ID].inputed) {
            DSS_PRINT_ERROR("To repair %s, block_id must be specified by -i.\n", DSS_REPAIR_TYPE_FS_BLOCK);
            return CM_ERROR;
        }
        if (!cmd_args_set[DSS_REPAIR_ARG_AU_SIZE].inputed) {
            DSS_PRINT_ERROR("To repair %s, au_size must be specified by -s.\n", DSS_REPAIR_TYPE_FS_BLOCK);
            return CM_ERROR;
        }
        return CM_SUCCESS;
    } else if (strcmp(cmd_args_set[DSS_REPAIR_ARG_TYPE].input_args, DSS_REPAIR_TYPE_CORE_CTRL) == 0) {
        if (cmd_args_set[DSS_REPAIR_ARG_META_ID].inputed) {
            DSS_PRINT_ERROR("To repair %s, block_id specified by -i is not expected.\n", DSS_REPAIR_TYPE_CORE_CTRL);
            return CM_ERROR;
        }
        if (cmd_args_set[DSS_REPAIR_ARG_AU_SIZE].inputed) {
            DSS_PRINT_ERROR("To repair %s, au_size specified by -s is not expected.\n", DSS_REPAIR_TYPE_CORE_CTRL);
            return CM_ERROR;
        }
        return CM_SUCCESS;
    }
    return CM_SUCCESS;
}

static dss_args_set_t tbox_repair_args_set = {
    tbox_repair_args,
    sizeof(tbox_repair_args) / sizeof(dss_args_t),
    check_repair_args,
};

static void repair_help(const char *prog_name, int print_flag)
{
    (void)printf("\nUsage:%s ssrepair <-v vol_path> <-t type> <-i block_id> <-s au_size> <-k key_value>\n", prog_name);
    (void)printf("[TOOl BOX] Repairing Metadata on Physical Disks.\n");
    if (print_flag == DSS_HELP_SIMPLE) {
        return;
    }
    (void)printf("-v/--vol_path <vol_path>, <required>, the volume path of the host need to repair\n");
    (void)printf("-t/--type <type>, <required>, repair type for meta info.\n");
    (void)printf(
        "-i/--id <meta_id>, [optional], the meta id you want to repair only if you want to repair fs or ft.\n");
    (void)printf("-s/--au_size <au_size>, [optional] the size of single alloc uint of volume, unit is KB, "
                 "at least 2MB, at max 64M\n");
    (void)printf("-k/--key_value <key_value>, <required>, the meta id you want to repair.\n");
}

static status_t collect_repair_input(repair_input_def_t *input)
{
    input->vol_path = tbox_repair_args[DSS_REPAIR_ARG_VOL_PATH].input_args;
    input->type = tbox_repair_args[DSS_REPAIR_ARG_TYPE].input_args;

    // block_id
    status_t status = CM_SUCCESS;
    if (tbox_repair_args[DSS_REPAIR_ARG_META_ID].inputed) {
        status = cm_str2uint64(tbox_repair_args[DSS_REPAIR_ARG_META_ID].input_args, (uint64 *)&input->block_id);
        DSS_RETURN_IFERR2(status, DSS_PRINT_ERROR("[TBOX][REPAIR] block_id:%s is not a valid uint64\n",
                                      tbox_repair_args[DSS_REPAIR_ARG_META_ID].input_args));
    } else {
        input->block_id = DSS_INVALID_BLOCK_ID;
    }

    // au_size
    if (tbox_repair_args[DSS_REPAIR_ARG_AU_SIZE].inputed) {
        status = cm_str2uint32(tbox_repair_args[DSS_REPAIR_ARG_AU_SIZE].input_args, &input->au_size);
        DSS_RETURN_IFERR2(status, DSS_PRINT_ERROR("[TBOX][REPAIR] au_size:%s is not a valid uint32\n",
                                      tbox_repair_args[DSS_REPAIR_ARG_AU_SIZE].input_args));
    } else {
        input->au_size = 0;
    }

    // key_value
    input->key_value = tbox_repair_args[DSS_REPAIR_ARG_KEY_VALUE].input_args;
    LOG_RUN_INF("[TBOX][REPAIR] vol_path:%s type:%s, id:%s, au_size:%u, key_value:%s", input->vol_path, input->type,
        dss_display_metaid(input->block_id), input->au_size, input->key_value);
    return CM_SUCCESS;
}

static status_t repair_proc(void)
{
    repair_input_def_t input = {0};
    status_t status = collect_repair_input(&input);
    DSS_RETURN_IF_ERROR(status);

    DSS_RETURN_IFERR2(dss_repair_verify_disk_version(input.vol_path),
        DSS_PRINT_ERROR("[TBOX][REPAIR] verify disk version failed %s.\n", input.vol_path));

    if (strcmp(input.type, DSS_REPAIR_TYPE_FS_BLOCK) == 0) {
        status = dss_repair_fs_block(&input);
    } else if (strcmp(input.type, DSS_REPAIR_TYPE_CORE_CTRL) == 0) {
        status = dss_repair_core_ctrl(&input);
    } else {
        DSS_PRINT_ERROR("[TBOX][REPAIR] Only support -t fs_block or -t core_ctrl, and your type is %s.", input.type);
        status = CM_ERROR;
    }
    LOG_RUN_INF("[TBOX][REPAIR] vol_path:%s type:%s, id:%s, au_size:%u, key_value:%s result:%u", input.vol_path,
        input.type, dss_display_metaid(input.block_id), input.au_size, input.key_value, status);
    if (status != CM_SUCCESS) {
        (void)printf("[TBOX][REPAIR] Failed to execute repair meta info.\n");
    } else {
        (void)printf("[TBOX][REPAIR] Succeed to execute repair meta info.\n");
    }
    return status;
}

static dss_args_t tbox_miner_args[] = {
    {'g', "vg_name", CM_TRUE, CM_TRUE, dss_check_name, NULL, NULL, 0, NULL, NULL, 0},
    {'s', "start_lsn", CM_TRUE, CM_TRUE, cmd_check_uint64, NULL, NULL, 0, NULL, NULL, 0},
    {'n', "number", CM_TRUE, CM_TRUE, cmd_check_uint64, NULL, NULL, 0, NULL, NULL, 0},
    {'i', "index", CM_TRUE, CM_TRUE, dss_check_index, NULL, NULL, 0, NULL, NULL, 0},
    {'o', "offset", CM_TRUE, CM_TRUE, cmd_check_uint64, NULL, NULL, 0, NULL, NULL, 0},
    {'D', "DSS_HOME", CM_FALSE, CM_TRUE, cmd_check_dss_home, cmd_check_convert_dss_home, cmd_clean_check_convert, 0,
        NULL, NULL, 0},
};

static status_t miner_check_args(dss_args_t *cmd_args_set, int set_size)
{
    if (cmd_args_set == NULL || set_size <= 0) {
        DSS_PRINT_ERROR("[TBOX][MINER]args error.\n");
        return CM_ERROR;
    }
    if (!cmd_args_set[DSS_ARG_MINER_VG].inputed) {
        DSS_PRINT_ERROR("[TBOX][MINER]should set the vol path to load.\n");
        return CM_ERROR;
    }
    if (cmd_args_set[DSS_ARG_MINER_START_LSN].inputed && cmd_args_set[DSS_ARG_MINER_INDEX].inputed) {
        DSS_PRINT_ERROR("[TBOX][MINER]should not set the start_lsn and index at the same time.\n");
        return CM_ERROR;
    }
    if (cmd_args_set[DSS_ARG_MINER_NUMBER].inputed &&
        (!cmd_args_set[DSS_ARG_MINER_START_LSN].inputed || !cmd_args_set[DSS_ARG_MINER_INDEX].inputed)) {
        DSS_PRINT_ERROR("[TBOX][MINER]should set the number with start_lsn or index to show.\n");
        return CM_ERROR;
    }
    if (cmd_args_set[DSS_ARG_MINER_OFFSET].inputed && !cmd_args_set[DSS_ARG_MINER_INDEX].inputed) {
        DSS_PRINT_ERROR("[TBOX][MINER]should set the offset with index to show.\n");
        return CM_ERROR;
    }
    if (cmd_args_set[DSS_ARG_MINER_NUMBER].inputed && cmd_args_set[DSS_ARG_MINER_INDEX].inputed &&
        !cmd_args_set[DSS_ARG_MINER_OFFSET].inputed) {
        DSS_PRINT_ERROR("[TBOX][MINER]should set the offset and number with index to show.\n");
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static dss_args_set_t tbox_miner_args_set = {
    tbox_miner_args,
    sizeof(tbox_miner_args) / sizeof(dss_args_t),
    miner_check_args,
};
static inline void help_param_dsshome_for_box(void)
{
    (void)printf("-D/--DSS_HOME <DSS_HOME>, [optional], the run path of dsstbox, default value is $DSS_HOME.\n");
}

static void miner_help(const char *prog_name, int print_flag)
{
    (void)printf("\nUsage:");
    (void)printf("\n%s ssminer <-g vg_name> [-D DSS_HOME]\n", prog_name);
    (void)printf("%s ssminer <-g vg_name> <-s start_lsn> [-n number] [-D DSS_HOME]\n", prog_name);
    (void)printf("%s ssminer <-g vg_name> <-i index> [-o offset] [-n number] [-D DSS_HOME]\n", prog_name);
    (void)printf("[TOOl BOX] Parsing redo logs on physical disks.\n");
    if (print_flag == DSS_HELP_SIMPLE) {
        return;
    }
    (void)printf("-g/--vg_name <vg_name>, <required>, the volume group name.\n");
    (void)printf("-s/--start_lsn <start_lsn>, <required>, the start lsn to parse.\n");
    (void)printf(
        "-n/--number <number>, [optional], the number to parse. If this parameter is used with start_lsn, "
        "number records starting with lsn are displayed. If this parameter is used with index and offset, number"
        "records from the specified position are displayed.\n");
    (void)printf("-i/--index <index>, <required>, the index of redo buffer.\n");
    (void)printf("-o/--offset <offset>, [optional], the offset to parse. This parameter should be set with index.\n");
    help_param_dsshome_for_box();
}

static status_t miner_proc_inner(miner_run_ctx_def_t *ctx)
{
    status_t status;
    if (tbox_miner_args[DSS_ARG_MINER_NUMBER].inputed) {
        status = cm_str2uint64(tbox_miner_args[DSS_ARG_MINER_NUMBER].input_args, (uint64 *)&ctx->input.number);
        DSS_RETURN_IFERR2(status, DSS_PRINT_ERROR("[TBOX][MINER] number:%s is not a valid uint64.\n",
                                      tbox_miner_args[DSS_ARG_MINER_NUMBER].input_args));
        if (ctx->input.number == 0) {
            if (tbox_miner_args[DSS_ARG_MINER_START_LSN].inputed) {
                status =
                    cm_str2uint64(tbox_miner_args[DSS_ARG_MINER_START_LSN].input_args, (uint64 *)&ctx->input.start_lsn);
                DSS_RETURN_IFERR2(status, DSS_PRINT_ERROR("[TBOX][MINER] start_lsn:%s is not a valid uint64.\n",
                                              tbox_miner_args[DSS_ARG_MINER_START_LSN].input_args));
                if (ctx->input.start_lsn == 0) {
                    dss_print_redo_ctrl(&ctx->vg_item->dss_ctrl->redo_ctrl);
                    return CM_SUCCESS;
                }
            }
            DSS_PRINT_ERROR("[TBOX][MINER]number should not be 0.\n");
            return CM_ERROR;
        }
    }
    if (tbox_miner_args[DSS_ARG_MINER_START_LSN].inputed) {
        status = cm_str2uint64(tbox_miner_args[DSS_ARG_MINER_START_LSN].input_args, (uint64 *)&ctx->input.start_lsn);
        DSS_RETURN_IFERR2(status, DSS_PRINT_ERROR("[TBOX][MINER] start_lsn:%s is not a valid uint64.\n",
                                      tbox_miner_args[DSS_ARG_MINER_START_LSN].input_args));
        if (ctx->input.start_lsn == 0) {
            DSS_PRINT_ERROR("[TBOX][MINER]start_lsn should not be 0.\n");
            return CM_ERROR;
        }
        status = dss_print_redo_info_by_lsn(ctx);
    } else if (tbox_miner_args[DSS_ARG_MINER_INDEX].inputed) {
        status = cm_str2uint32(tbox_miner_args[DSS_ARG_MINER_INDEX].input_args, (uint32 *)&ctx->input.index);
        DSS_RETURN_IFERR2(status, DSS_PRINT_ERROR("[TBOX][MINER] index:%s is not a valid uint32.\n",
                                      tbox_miner_args[DSS_ARG_MINER_START_LSN].input_args));
        if (ctx->input.index >= ctx->count) {
            DSS_PRINT_ERROR(
                "[TBOX][MINER]No valid redo from index %u for count is %u.\n", ctx->input.index, ctx->count);
            return CM_ERROR;
        }                          
        if (tbox_miner_args[DSS_ARG_MINER_OFFSET].inputed) {
            status = cm_str2uint64(tbox_miner_args[DSS_ARG_MINER_OFFSET].input_args, (uint64 *)&ctx->input.offset);
            DSS_RETURN_IFERR2(status, DSS_PRINT_ERROR("[TBOX][MINER] offset:%s is not a valid uint64.\n",
                                          tbox_miner_args[DSS_ARG_MINER_OFFSET].input_args));
            status = dss_print_redo_info_by_index(ctx);
        } else {
            status = dss_print_redo_info(ctx);
        }
    } else {
        status = dss_print_redo_info(ctx);
    }
    return status;
}

static status_t miner_proc(void)
{
    status_t status;
    dss_config_t inst_cfg;
    char *home = tbox_miner_args[DSS_ARG_MINER_HOME].input_args;
    status = set_config_info(home, &inst_cfg);
    if (status != CM_SUCCESS) {
        DSS_PRINT_ERROR("[TBOX][MINER]Failed to set config info.\n");
        return status;
    }
    status =
        dss_init_loggers(&inst_cfg, g_dss_dsstbox_log, sizeof(g_dss_dsstbox_log) / sizeof(dss_log_def_t), "dsstbox");
    if (status != CM_SUCCESS) {
        DSS_PRINT_ERROR("[TBOX][MINER]DSS init loggers failed!\n");
        return status;
    }
    status = dss_load_vg_conf_info(&g_vgs_info, &inst_cfg);
    if (status != CM_SUCCESS) {
        DSS_PRINT_ERROR("[TBOX][MINER]Failed to load vg info from config, errcode is %d.\n", status);
        return status;
    }
    miner_run_ctx_def_t ctx = {0};
    ctx.input.vg_name = tbox_miner_args[DSS_ARG_MINER_VG].input_args;
    status = dss_init_miner_run_ctx(&ctx);
    if (status != CM_SUCCESS) {
        DSS_PRINT_ERROR("[TBOX][MINER]Failed to init miner run ctx.\n");
        return CM_ERROR;
    }
    status = miner_proc_inner(&ctx);
    if (status != CM_SUCCESS) {
        DSS_PRINT_ERROR("[TBOX][MINER]Failed to print expected redo info.\n");
    } else {
        DSS_PRINT_ERROR("[TBOX][MINER]Succeed to print expected redo info.\n");
    }
    DSS_FREE_POINT(ctx.vg_item->dss_ctrl);
    DSS_FREE_POINT(g_vgs_info);
    DSS_FREE_POINT(ctx.log_buf);
    return status;
}

// clang-format off
dss_admin_cmd_t g_dss_admin_tbox[] = {{"ssrepair", repair_help, repair_proc, &tbox_repair_args_set, CM_TRUE},
                                      {"ssminer", miner_help, miner_proc, &tbox_miner_args_set, CM_TRUE},
};

static bool32 get_tbox_idx(int argc, char **argv, uint32_t *idx)
{
    for (uint32 i = 0; i < sizeof(g_dss_admin_tbox) / sizeof(g_dss_admin_tbox[0]); ++i) {
        *idx = i;
        if (strcmp(g_dss_admin_tbox[i].cmd, argv[DSS_ARG_IDX_1]) == 0) {
            return CM_TRUE;
        }
    }
    return CM_FALSE;
}

// clang-format on
static void tbox_help(char *prog_name, dss_help_type help_type)
{
    (void)printf("Usage:dsstbox [command] [OPTIONS]\n\n");
    (void)printf("Usage:%s -h/--help show help information of dsstbox\n", prog_name);
    (void)printf("Usage:%s -a/--all show all help information of dsstbox\n", prog_name);
    (void)printf("Usage:%s -v/--version show version information of dsstbox\n", prog_name);
    (void)printf("commands:\n");
    for (uint32 i = 0; i < sizeof(g_dss_admin_tbox) / sizeof(g_dss_admin_tbox[0]); ++i) {
        g_dss_admin_tbox[i].help(prog_name, help_type);
    }
    (void)printf("\n\n");
}

void dss_help_tbox(int argc, char **argv, uint32_t *idx)
{
    if (argc < CMD_ARGS_AT_LEAST) {
        (void)printf("dsstbox: no operation specified.\n");
        (void)printf("dsstbox: Try \"dsstbox -h/--help\" for help information.\n");
        (void)printf("dsstbox: Try \"dsstbox -a/--all\" for detailed help information.\n");
        exit(EXIT_FAILURE);
    }
    if (cm_str_equal(argv[1], "-v") || cm_str_equal(argv[1], "--version")) {
        (void)printf("dsstbox %s\n", (char *)DEF_DSS_VERSION);
        exit(EXIT_SUCCESS);
    }
    if (cm_str_equal(argv[1], "-h") || cm_str_equal(argv[1], "--help")) {
        tbox_help(argv[0], DSS_HELP_SIMPLE);
        exit(EXIT_SUCCESS);
    }
    if (cm_str_equal(argv[1], "-a") || cm_str_equal(argv[1], "--all")) {
        tbox_help(argv[0], DSS_HELP_DETAIL);
        exit(EXIT_SUCCESS);
    }

    if (!get_tbox_idx(argc, argv, idx)) {
        (void)printf("tbox:%s can not find.\n", argv[DSS_ARG_IDX_1]);
        tbox_help(argv[0], DSS_HELP_SIMPLE);
        exit(EXIT_FAILURE);
    }
    if (argc > DSS_ARG_IDX_2 &&
        (strcmp(argv[DSS_ARG_IDX_2], "-h") == 0 || strcmp(argv[DSS_ARG_IDX_2], "--help") == 0)) {
        g_dss_admin_tbox[*idx].help(argv[0], DSS_HELP_DETAIL);
        exit(EXIT_SUCCESS);
    }
}

static status_t dss_exec_tbox_core(int argc, char **argv, uint32 tbox_idx)
{
    cmd_parse_init(g_dss_admin_tbox[tbox_idx].args_set->cmd_args, g_dss_admin_tbox[tbox_idx].args_set->args_size);
    if (cmd_parse_args(argc, argv, g_dss_admin_tbox[tbox_idx].args_set) != CM_SUCCESS) {
        int32 code;
        const char *message;
        cm_get_error(&code, &message);
        if (code != 0) {
            DSS_PRINT_ERROR("\ntbox %s error:%d %s.\n", g_dss_admin_tbox[tbox_idx].cmd, code, message);
        }
        return CM_ERROR;
    }
    status_t ret = g_dss_admin_tbox[tbox_idx].proc();
    cmd_parse_clean(g_dss_admin_tbox[tbox_idx].args_set->cmd_args, g_dss_admin_tbox[tbox_idx].args_set->args_size);
    return ret;
}

static status_t dss_exec_tbox(int argc, char **argv, uint32 idx)
{
    status_t status = dss_exec_tbox_core(argc, argv, idx);
    // write oper log
    return status;
}

int main(int argc, char **argv)
{
#ifndef WIN32
    // check root
    if (geteuid() == 0 || getuid() != geteuid()) {
        (void)printf("The root user is not permitted to execute the dsstbox "
                     "and the real uids must be the same as the effective uids.\n");
        (void)fflush(stdout);
        return CM_ERROR;
    }
    if (cm_regist_signal(SIGPIPE, SIG_IGN) != CM_SUCCESS) {
        (void)printf("Can't assign function for SIGPIPE.\n");
        return CM_ERROR;
    }
#endif
    uint32 idx;
    dss_help_tbox(argc, argv, &idx);
    dss_config_t inst_cfg;
    if (dss_set_cfg_dir(NULL, &inst_cfg) != CM_SUCCESS) {
        (void)printf("Environment variant DSS_HOME not found!\n");
        return CM_ERROR;
    }
    status_t ret = dss_load_local_server_config(&inst_cfg);
    if (ret != CM_SUCCESS) {
        (void)printf("load local server config failed during init loggers.\n");
        return CM_ERROR;
    }

    if (cm_start_timer(g_timer()) != CM_SUCCESS) {
        (void)printf("Aborted due to starting timer thread.\n");
        return CM_ERROR;
    }

    ret = dss_init_loggers(&inst_cfg, g_dss_dsstbox_log, sizeof(g_dss_dsstbox_log) / sizeof(dss_log_def_t), "dsstbox");
    if (ret != CM_SUCCESS) {
        (void)printf("%s\nDSS init loggers failed!\n", cm_get_errormsg(cm_get_error_code()));
        return ret;
    }
    LOG_RUN_INF("[TBOX] Begin to execute.");
    cm_reset_error();
    ret = dss_exec_tbox(argc, argv, idx);
    LOG_RUN_INF("[TBOX] execute finish result:%u.", ret);
    return ret;
}