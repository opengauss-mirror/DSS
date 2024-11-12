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
#include "cm_system.h"
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
    {LOG_AUDIT, "audit/dsstbox.aud"},
};

#define DSS_REPAIR_AUDIT_LOG_LEN SIZE_K(32)
#define DSS_REPAIR_AUDIT_SOURCE_LEN SIZE_K(2)
char g_repair_audit_source[DSS_REPAIR_AUDIT_SOURCE_LEN];
char g_repair_audit_buff[DSS_REPAIR_AUDIT_LOG_LEN];
typedef struct st_repair_audit_info {
    char date[CM_MAX_TIME_STRLEN];
    char user[CM_NAME_BUFFER_SIZE];
} repair_audit_info_t;
repair_audit_info_t g_audit_info;

static void dss_repair_init_audit()
{
    // user
    char *user_name = cm_sys_user_name();
    MEMS_RETVOID_IFERR(strcpy_s(g_audit_info.user, CM_NAME_BUFFER_SIZE, (const char *)user_name));

    // time
    int32 tz = g_timer()->tz;
    int32 tz_hour = TIMEZONE_GET_HOUR(tz);
    int32 tz_min = TIMEZONE_GET_MINUTE(tz);
    int32 ret = 0;
    if (tz_hour >= 0) {
        ret = snprintf_s(
            g_audit_info.date, CM_MAX_TIME_STRLEN, CM_MAX_TIME_STRLEN - 1, "UTC+%02d:%02d ", tz_hour, tz_min);
    } else {
        ret =
            snprintf_s(g_audit_info.date, CM_MAX_TIME_STRLEN, CM_MAX_TIME_STRLEN - 1, "UTC%02d:%02d ", tz_hour, tz_min);
    }

    if (ret == -1) {
        return;
    }
    (void)cm_date2str(
        g_timer()->now, "yyyy-mm-dd hh24:mi:ss.ff3", g_audit_info.date + ret, CM_MAX_TIME_STRLEN - (uint32)ret);
}

static void dss_repair_gen_audit_resource(repair_input_def_t *input)
{
    if (cm_strcmpi(input->type, DSS_REPAIR_TYPE_FS_BLOCK) == 0 ||
        cm_strcmpi(input->type, DSS_REPAIR_TYPE_FT_BLOCK) == 0 ||
        cm_strcmpi(input->type, DSS_REPAIR_TYPE_FS_AUX_BLOCK) == 0) {
        int32 ret = snprintf_s(g_repair_audit_source, DSS_REPAIR_AUDIT_SOURCE_LEN, DSS_REPAIR_AUDIT_SOURCE_LEN - 1,
            "volume(%s), meta_type(%s), block_id(%llu), au_size(%u)", input->vol_path, input->type,
            *(uint64 *)&input->block_id, input->au_size);
        if (SECUREC_UNLIKELY(ret == -1) || ret >= (int32)DSS_REPAIR_AUDIT_SOURCE_LEN) {
            g_repair_audit_source[DSS_REPAIR_AUDIT_SOURCE_LEN - 1] = '\0';
            return;
        }
    } else if (cm_strcmpi(input->type, DSS_REPAIR_TYPE_CORE_CTRL) == 0 ||
               cm_strcmpi(input->type, DSS_REPAIR_TYPE_VOLUME_HEADER) == 0 ||
               cm_strcmpi(input->type, DSS_REPAIR_TYPE_SOFTWARE_VERSION) == 0 ||
               cm_strcmpi(input->type, DSS_REPAIR_TYPE_ROOT_FT_BLOCK) == 0 ||
               cm_strcmpi(input->type, DSS_REPAIR_TYPE_VOLUME_CTRL) == 0) {
        int32 ret = snprintf_s(g_repair_audit_source, DSS_REPAIR_AUDIT_SOURCE_LEN, DSS_REPAIR_AUDIT_SOURCE_LEN - 1,
            "volume(%s), meta_type(%s)", input->vol_path, input->type);
        if (SECUREC_UNLIKELY(ret == -1) || ret >= (int32)DSS_REPAIR_AUDIT_SOURCE_LEN) {
            g_repair_audit_source[DSS_REPAIR_AUDIT_SOURCE_LEN - 1] = '\0';
            return;
        }
    } else {
        g_repair_audit_source[0] = '\0';
    }
    return;
}

static void dss_repair_create_audit_msg(repair_input_def_t *input, status_t result, int32 *log_len)
{
    dss_repair_gen_audit_resource(input);
    int32 ret = snprintf_s(g_repair_audit_buff, DSS_REPAIR_AUDIT_LOG_LEN, DSS_REPAIR_AUDIT_LOG_LEN - 1,
        "USER:[%u] \"%s\" "
        "ACTION:[8] \"ssrepair\" RESOURCE:[%u] \"%s\" RESULT:[7] \"%s\" CONTEXT:[%u] \"%s\"",
        (uint32)strlen(g_audit_info.user), g_audit_info.user,          // user
        (uint32)strlen(g_repair_audit_source), g_repair_audit_source,  // resource
        (result == CM_SUCCESS ? "SUCCESS" : "FAILURE"),                // result
        (uint32)strlen(input->key_value), input->key_value);           // context
    if (SECUREC_UNLIKELY(ret == -1) || ret >= (int32)DSS_REPAIR_AUDIT_LOG_LEN) {
        g_repair_audit_buff[DSS_REPAIR_AUDIT_LOG_LEN - 1] = '\0';
        return;
    }

    *log_len = ret;
    g_repair_audit_buff[*log_len] = '\0';
}

static void dss_repair_log_audit(repair_input_def_t *input, status_t result)
{
    int32 log_msg_len = 0;
    dss_repair_create_audit_msg(input, result, &log_msg_len);
    LOG_AUDIT("%s\nLENGTH: \"%d\"\n%s\n", g_audit_info.date, log_msg_len, g_repair_audit_buff);
}

status_t dss_check_meta_type(const char *type)
{
    if ((cm_strcmpi(type, DSS_REPAIR_TYPE_FS_BLOCK) != 0) && (cm_strcmpi(type, DSS_REPAIR_TYPE_FT_BLOCK) != 0) &&
        (cm_strcmpi(type, DSS_REPAIR_TYPE_CORE_CTRL) != 0) && (cm_strcmpi(type, DSS_REPAIR_TYPE_ROOT_FT_BLOCK) != 0) &&
        (cm_strcmpi(type, DSS_REPAIR_TYPE_VOLUME_CTRL) != 0) &&
        (cm_strcmpi(type, DSS_REPAIR_TYPE_VOLUME_HEADER) != 0) &&
        (cm_strcmpi(type, DSS_REPAIR_TYPE_SOFTWARE_VERSION) != 0) &&
        (cm_strcmpi(type, DSS_REPAIR_TYPE_FS_AUX_BLOCK) != 0)) {
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
    CM_RETURN_IFERR(cmd_parse_check(cmd_args_set, set_size));
    const char *repair_type = cmd_args_set[DSS_REPAIR_ARG_TYPE].input_args;
    if (cm_strcmpi(repair_type, DSS_REPAIR_TYPE_FS_BLOCK) == 0 ||
        cm_strcmpi(repair_type, DSS_REPAIR_TYPE_FT_BLOCK) == 0 ||
        cm_strcmpi(repair_type, DSS_REPAIR_TYPE_FS_AUX_BLOCK) == 0) {
        if (!cmd_args_set[DSS_REPAIR_ARG_META_ID].inputed) {
            DSS_PRINT_ERROR("To repair %s, block_id must be specified by -i.\n", repair_type);
            return CM_ERROR;
        }
        if (!cmd_args_set[DSS_REPAIR_ARG_AU_SIZE].inputed) {
            DSS_PRINT_ERROR("To repair %s, au_size must be specified by -s.\n", repair_type);
            return CM_ERROR;
        }
        return CM_SUCCESS;
    } else if (cm_strcmpi(repair_type, DSS_REPAIR_TYPE_CORE_CTRL) == 0 ||
               cm_strcmpi(repair_type, DSS_REPAIR_TYPE_VOLUME_HEADER) == 0 ||
               cm_strcmpi(repair_type, DSS_REPAIR_TYPE_SOFTWARE_VERSION) == 0 ||
               cm_strcmpi(repair_type, DSS_REPAIR_TYPE_ROOT_FT_BLOCK) == 0 ||
               cm_strcmpi(repair_type, DSS_REPAIR_TYPE_VOLUME_CTRL) == 0) {
        if (cmd_args_set[DSS_REPAIR_ARG_META_ID].inputed) {
            DSS_PRINT_ERROR("To repair %s, block_id specified by -i is not expected.\n", repair_type);
            return CM_ERROR;
        }
        if (cmd_args_set[DSS_REPAIR_ARG_AU_SIZE].inputed) {
            DSS_PRINT_ERROR("To repair %s, au_size specified by -s is not expected.\n", repair_type);
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
    (void)printf("\nUsage:%s ssrepair <-v vol_path> <-t type> [-i meta_id] [-s au_size] <-k key_value>\n", prog_name);
    (void)printf("[TOOl BOX] Repair Metadata on Physical Disks.\n");
    if (print_flag == DSS_HELP_SIMPLE) {
        return;
    }
    (void)printf("-v/--vol_path <vol_path>, <required>, the volume path of the host need to repair.\n");
    (void)printf("-t/--type <type>, <required>, repair type for meta info.\n");
    (void)printf("-i/--id <meta_id>, [optional], the meta id you want to repair.\n");
    (void)printf("-s/--au_size <au_size>, [optional], the size of single alloc unit of volume, unit is KB, "
                 "at least is 2MB, at most is 64MB.\n");
    (void)printf("-k/--key_value <key_value>, <required>, names of meta_data items and their target values.\n");
    (void)printf("Examples:\n");
    (void)printf("- repair core_ctrl on /dev/sda1:\n"
                 "\tdsstbox ssrepair -v /dev/sda1 -t core_ctrl -k \"volume_count=3,volume_attrs[2].id=2\"\n");
    (void)printf("- repair volume_ctrl on /dev/sda1:\n"
                 "\tdsstbox ssrepair -v /dev/sda1 -t volume_ctrl -k \"version=15,defs[2].flag=2\"\n");
    (void)printf("- repair root_ft_block on /dev/sda1:\n"
                 "\tdsstbox ssrepair -v /dev/sda1 -t root_ft_block "
                 "-k \"ft_block.common.flags=2,ft_root.items.count=16\"\n");
    (void)printf("- repair volume_header on /dev/sda2:\n"
                 "\tdsstbox ssrepair -v /dev/sda2 -t volume_header "
                 "-k \"vg_name=data_new,vol_type.entry_volume_name=/dev/sda1\"\n");
    (void)printf("- repair software_version on /dev/sda1:\n"
                 "\tdsstbox ssrepair -v /dev/sda1 -t software_version -k \"software_version=2\"\n");
    (void)printf("- repair fs_block on /dev/sda1:\n"
                 "\tdsstbox ssrepair -v /dev/sda1 -t fs_block -i 8919238324529152 -s 8192 "
                 "-k \"head.common.type=1,bitmap[1]=18446744073709551615\"\n");
    (void)printf("- repair ft_block on /dev/sda1:\n"
                 "\tdsstbox ssrepair -v /dev/sda1 -t ft_block -i 105553116275712 -s 8192 "
                 "-k \"common.type=0,node_num=16\"\n");
    (void)printf("- repair fs_aux_block on /dev/sda1:\n"
                 "\tdsstbox ssrepair -v /dev/sda1 -t fs_aux_block -i 96018151430434816 -s 8192 "
                 "-k \"head.common.type=2,bitmap[3]=1,bitmap[4]=0\"\n");
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

#define DSS_REPAIR_CONFIRM_RETRY_TIMES 3
static void dss_repair_confirm()
{
#ifdef WIN32
    return;
#else
    char confirm[DSS_MAX_CMD_LEN] = {'\0'};
    char *env_quiet = getenv("DSS_REPAIR_CONFIRM_QUIET");
    LOG_RUN_INF("DSS_REPAIR_CONFIRM_QUIET is %s.", (env_quiet == NULL ? "null" : env_quiet));
    if (env_quiet != NULL && cm_strcmpni(env_quiet, "TRUE", sizeof("TRUE")) == 0) {
        LOG_RUN_INF("Skip ssrepair confirmation.");
        return;
    }

    for (int i = DSS_REPAIR_CONFIRM_RETRY_TIMES; i > 0; --i) {
        (void)printf("Warning: ssrepair would directly modify meta data on disk, "
                     "which might cause damage to DSS if wrongly inputted.\n"
                     "You have to confirm that:\n"
                     "    (1) Your input is correct.\n"
                     "    (2) dssservers in all nodes are stopped.\n"
                     "Confirm and continue? Type in y/yes or n/no, and you have %d chances left:",
            i);
        (void)fflush(stdout);
        if (NULL == fgets(confirm, sizeof(confirm), stdin)) {
            (void)printf("\n");
            break;
        }

        if (cm_strcmpni(confirm, "y\n", sizeof("y\n")) == 0 || cm_strcmpni(confirm, "yes\n", sizeof("yes\n")) == 0) {
            LOG_RUN_INF("User input %s, operation confirmed.", confirm);
            (void)printf("Operation confirmed.\n");
            return;
        } else if (cm_strcmpni(confirm, "n\n", sizeof("n\n")) == 0 ||
                   cm_strcmpni(confirm, "no\n", sizeof("no\n")) == 0) {
            break;
        } else {
            (void)printf("\n");
        }
    }
    LOG_RUN_ERR("Operation NOT confirmed, quit.");
    (void)printf("Operation NOT confirmed, quit.\n");
    _exit(1);
#endif
}

static status_t repair_proc(void)
{
    repair_input_def_t input = {0};
    status_t status = collect_repair_input(&input);
    DSS_RETURN_IF_ERROR(status);

    // Only for -t software_version, version check is not needed.
    // For other types, version check is needed.
    if (cm_strcmpi(input.type, DSS_REPAIR_TYPE_SOFTWARE_VERSION) != 0) {
        DSS_RETURN_IFERR2(dss_repair_verify_disk_version(input.vol_path),
            DSS_PRINT_ERROR("[TBOX][REPAIR] verify disk version failed %s.\n", input.vol_path));
    }

    dss_repair_confirm();

    dss_repair_init_audit();

    if (cm_strcmpi(input.type, DSS_REPAIR_TYPE_FS_BLOCK) == 0) {
        status = dss_repair_fs_block(&input);
    } else if (cm_strcmpi(input.type, DSS_REPAIR_TYPE_FT_BLOCK) == 0) {
        status = dss_repair_ft_block(&input);
    } else if (cm_strcmpi(input.type, DSS_REPAIR_TYPE_CORE_CTRL) == 0) {
        status = dss_repair_core_ctrl(&input);
    } else if (cm_strcmpi(input.type, DSS_REPAIR_TYPE_VOLUME_HEADER) == 0) {
        status = dss_repair_volume_header(&input);
    } else if (cm_strcmpi(input.type, DSS_REPAIR_TYPE_SOFTWARE_VERSION) == 0) {
        status = dss_repair_software_version(&input);
    } else if (cm_strcmpi(input.type, DSS_REPAIR_TYPE_ROOT_FT_BLOCK) == 0) {
        status = dss_repair_root_ft_block(&input);
    } else if (cm_strcmpi(input.type, DSS_REPAIR_TYPE_VOLUME_CTRL) == 0) {
        status = dss_repair_volume_ctrl(&input);
    } else if (cm_strcmpi(input.type, DSS_REPAIR_TYPE_FS_AUX_BLOCK) == 0) {
        status = dss_repair_fs_aux(&input);
    } else {
        DSS_PRINT_ERROR("[TBOX][REPAIR] Only support -t "
                        "[fs_block|ft_block|core_ctrl|volume_header|software_version|"
                        "root_ft_block|volume_ctrl|fs_aux_block], "
                        "your type is %s.\n",
            input.type);
        status = CM_ERROR;
    }
    dss_repair_log_audit(&input, status);
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
        DSS_PRINT_ERROR("[TBOX][MINER]should set the vg name to show.\n");
        return CM_ERROR;
    }
    if (cmd_args_set[DSS_ARG_MINER_START_LSN].inputed && cmd_args_set[DSS_ARG_MINER_INDEX].inputed) {
        DSS_PRINT_ERROR("[TBOX][MINER]should not set the start_lsn and index at the same time.\n");
        return CM_ERROR;
    }
    if (cmd_args_set[DSS_ARG_MINER_NUMBER].inputed &&
        (!cmd_args_set[DSS_ARG_MINER_START_LSN].inputed && !cmd_args_set[DSS_ARG_MINER_INDEX].inputed)) {
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
            DSS_PRINT_ERROR("[TBOX][MINER]Generally, the value of number should be greater than 0. In special cases, to"
                            " display only the redo_ctrl information, set both number and start_lsn to 0.\n");
            return CM_ERROR;
        }
    }
    if (tbox_miner_args[DSS_ARG_MINER_START_LSN].inputed) {
        status = cm_str2uint64(tbox_miner_args[DSS_ARG_MINER_START_LSN].input_args, (uint64 *)&ctx->input.start_lsn);
        DSS_RETURN_IFERR2(status, DSS_PRINT_ERROR("[TBOX][MINER] start_lsn:%s is not a valid uint64.\n",
                                      tbox_miner_args[DSS_ARG_MINER_START_LSN].input_args));
        if (ctx->input.start_lsn == 0) {
            DSS_PRINT_ERROR("[TBOX][MINER]Generally, the value of start_lsn should be greater than 0. In special cases, to"
                            " display only the redo_ctrl information, set both number and start_lsn to 0.\n");
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
        DSS_PRINT_INF("[TBOX][MINER]Succeed to print expected redo info.\n");
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