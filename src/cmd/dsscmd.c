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
 * dsscmd.c
 *
 *
 * IDENTIFICATION
 *    src/cmd/dsscmd.c
 *
 * -------------------------------------------------------------------------
 */

#ifndef WIN32
#include <unistd.h>
#include <sys/types.h>
#endif

#include "cm_base.h"
#include "cm_config.h"
#include "cm_dlock.h"
#include "cm_list.h"
#include "cm_system.h"
#include "cm_cipher.h"
#include "cm_encrypt.h"
#include "cm_utils.h"
#include "cm_signal.h"
#include "cm_sec_file.h"

#include "dss_errno.h"
#include "dss_defs.h"
#include "dss_malloc.h"
#include "dss_file.h"
#include "dss_io_fence.h"
#include "dss_api.h"
#include "dss_api_impl.h"
#include "dsscmd_inq.h"
#include "dsscmd_cli_msg.h"
#include "dsscmd_volume.h"
#include "dsscmd_showdisk.h"
#include "dsscmd_du.h"
#include "dsscmd_find.h"
#include "dsscmd_encrypt.h"
#ifndef WIN32
#include "config.h"
#endif

#ifdef WIN32
#define DEF_DSS_VERSION "Windows does not support this feature because it is built using vs."
#endif

#define DSS_ARG_IDX_0 0
#define DSS_ARG_IDX_1 1
#define DSS_ARG_IDX_2 2
#define DSS_ARG_IDX_3 3
#define DSS_ARG_IDX_4 4
#define DSS_ARG_IDX_5 5

typedef enum en_dss_help_type {
    DSS_HELP_DETAIL = 0,
    DSS_HELP_SIMPLE,
} dss_help_type;

// cmd format : cmd subcmd [-f val]
#define CMD_ARGS_AT_LEAST 2
#define CMD_COMMAND_INJECTION_COUNT 22
#define DSS_MAX_PATH_SIZE 1003
#define DSS_DEFAULT_MEASURE "B"
#define DSS_SUBSTR_UDS_PATH "UDS:"
#define DSS_DEFAULT_VG_TYPE 't' /* show vg information in table format by default */
static const char dss_ls_print_flag[] = {'d', '-', 'l'};

// clang-format off
config_item_t g_dss_admin_parameters[] = {
    // name (30B)                     isdefault readonly  defaultvalue value runtime_value description range  datatype
    // comment
    // -------------                  --------- --------  ------------ ----- ------------- ----------- -----  --------
    // -----
    /* log */
    { "LOG_HOME",                  CM_TRUE, CM_TRUE,  "",      NULL, NULL, "-", "-",         "GS_TYPE_VARCHAR", NULL, 0,
        EFFECT_REBOOT, CFG_INS, NULL, NULL },
    { "_LOG_BACKUP_FILE_COUNT",    CM_TRUE, CM_FALSE, "20",    NULL, NULL, "-", "[0,128]",   "GS_TYPE_INTEGER", NULL, 1,
        EFFECT_REBOOT, CFG_INS, NULL, NULL },
    { "_LOG_MAX_FILE_SIZE",        CM_TRUE, CM_FALSE, "256M",  NULL, NULL, "-", "[1M,4G]",   "GS_TYPE_INTEGER", NULL, 2,
        EFFECT_REBOOT, CFG_INS, NULL, NULL },
    { "_LOG_FILE_PERMISSIONS",     CM_TRUE, CM_FALSE, "600",   NULL, NULL, "-", "[600-777]", "GS_TYPE_INTEGER", NULL, 3,
        EFFECT_REBOOT, CFG_INS, NULL, NULL },
    { "_LOG_PATH_PERMISSIONS",     CM_TRUE, CM_FALSE, "700",   NULL, NULL, "-", "[700-777]", "GS_TYPE_INTEGER", NULL, 4,
        EFFECT_REBOOT, CFG_INS, NULL, NULL },
    { "_LOG_LEVEL",                CM_TRUE, CM_FALSE, "519",     NULL, NULL, "-", "[0,4087]",  "GS_TYPE_INTEGER", NULL, 5,
        EFFECT_REBOOT, CFG_INS, NULL, NULL, NULL, NULL},
    { "_AUDIT_BACKUP_FILE_COUNT",  CM_TRUE, CM_FALSE, "20",    NULL, NULL, "-", "[0,128]",   "GS_TYPE_INTEGER", NULL, 6,
        EFFECT_REBOOT, CFG_INS, NULL, NULL, NULL, NULL},
    { "_AUDIT_MAX_FILE_SIZE",      CM_TRUE, CM_FALSE, "256M",  NULL, NULL, "-", "[1M,4G]",   "GS_TYPE_INTEGER", NULL, 7,
        EFFECT_REBOOT, CFG_INS, NULL, NULL, NULL, NULL},
    { "LSNR_PATH",                 CM_TRUE, CM_FALSE, "/tmp/", NULL, NULL, "-", "-",         "GS_TYPE_VARCHAR", NULL, 8,
        EFFECT_REBOOT, CFG_INS, NULL, NULL, NULL, NULL},
    { "_AUDIT_LEVEL",              CM_TRUE, CM_FALSE, "1",     NULL, NULL, "-", "-",         "GS_TYPE_VARCHAR", NULL, 9,
        EFFECT_REBOOT, CFG_INS, NULL, NULL, NULL, NULL},
};

// clang-format on
dss_log_def_t g_dss_admin_log[] = {
    {LOG_DEBUG, "debug/dsscmd.dlog"},
    {LOG_OPER, "oper/dsscmd.olog"},
    {LOG_RUN, "run/dsscmd.rlog"},
    {LOG_ALARM, "alarm/dsscmd.alog"},
};

typedef status_t (*cmd_parser_check_args_t)(const char *input_args);
typedef status_t (*cmd_parser_convert_args_t)(const char *input_args, void **convert_result, int *convert_size);
typedef void (*cmd_parser_clean_convert_args_t)(char *convert_result, int convert_size);
typedef struct st_dss_args_t {
    char short_name;                     // args short name
    const char *long_name;               // args long name ,can be null
    int32 required;                      // CM_TRUE required,  CM_FALSE optional
    int32 required_args;                 // CM_TRUE required,  CM_FALSE not need
    cmd_parser_check_args_t check_args;  // if want to check input_args, set it, can be NULL
    cmd_parser_convert_args_t convert_args;
    cmd_parser_clean_convert_args_t clean_convert_args;
    int32 inputed;     // CM_TRUE input-ed by user, CM_FALSE not input
    char *input_args;  // if required_args is CM_TRUE,  should get value from user
    void *convert_result;
    int32 convert_result_size;
} dss_args_t;

typedef status_t (*cmd_parse_check_t)(dss_args_t *cmd_args_set, int set_size);
typedef struct st_dss_args_set_t {
    dss_args_t *cmd_args;
    int32 args_size;
    cmd_parse_check_t args_check;
} dss_args_set_t;

typedef void (*dss_admin_help)(const char *prog_name, int print_flag);
typedef status_t (*dss_admin_cmd_proc)(void);
typedef struct st_dss_admin_cmd_t {
    char cmd[CM_MAX_NAME_LEN];
    dss_admin_help help;
    dss_admin_cmd_proc proc;
    dss_args_set_t *args_set;
} dss_admin_cmd_t;

typedef struct st_dss_print_help_t {
    char fmt;
    uint32 bytes;
} dss_print_help_t;

// just for cmd exist for much cmd at once
static void cmd_parse_init(dss_args_t *cmd_args_set, int set_size)
{
    for (int i = 0; i < set_size; i++) {
        cmd_args_set[i].inputed = CM_FALSE;
        cmd_args_set[i].input_args = NULL;
        cmd_args_set[i].convert_result = NULL;
        cmd_args_set[i].convert_result_size = 0;
    }
}

static void cmd_parse_clean(dss_args_t *cmd_args_set, int set_size)
{
    for (int i = 0; i < set_size; i++) {
        cmd_args_set[i].inputed = CM_FALSE;
        cmd_args_set[i].input_args = NULL;
        if (cmd_args_set[i].clean_convert_args != NULL) {
            cmd_args_set[i].clean_convert_args(cmd_args_set[i].convert_result, cmd_args_set[i].convert_result_size);
        }
        cmd_args_set[i].convert_result = NULL;
        cmd_args_set[i].convert_result_size = 0;
    }
}

// add uni-check function after here
// ------------------------
static status_t cmd_check_dss_home(const char *dss_home)
{
    return dss_check_path(dss_home);
}

static status_t cmd_check_uds(const char *uds)
{
    const char *uds_prefix = "UDS:";
    if (strlen(uds) < strlen(uds_prefix) || memcmp(uds, uds_prefix, strlen(uds_prefix)) != 0) {
        DSS_PRINT_ERROR("uds name should start with %s.\n", uds_prefix);
        return CM_ERROR;
    }
    return dss_check_path(uds + strlen(uds_prefix));
}

static status_t cmd_check_au_size(const char *au_size_str)
{
    uint32 min_multiple = DSS_MIN_AU_SIZE / SIZE_K(1);
    uint32 max_multiple = DSS_MAX_AU_SIZE / SIZE_K(1);
    uint32 au_size;
    status_t ret = cm_str2uint32(au_size_str, &au_size);
    if (ret != CM_SUCCESS) {
        DSS_PRINT_ERROR("au_size %s is error\n", au_size_str);
        return CM_ERROR;
    }

    if (au_size == 0 || au_size < min_multiple || au_size > max_multiple) {
        DSS_PRINT_ERROR(
            "au_size %u is error, au_size cannot be 0, au_size must greater than 2MB, smaller than 64MB!\n", au_size);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static status_t cmd_realpath_home(const char *input_args, char **convert_result, int *convert_size)
{
    uint32 len = (uint32)strlen(input_args);
    if (len == 0 ||len >= CM_FILE_NAME_BUFFER_SIZE) {
        DSS_PRINT_ERROR("the len of path is invalid.\n");
        return CM_ERROR;
    }
    *convert_result = (char *)malloc(CM_FILE_NAME_BUFFER_SIZE);
    if (*convert_result == NULL) {
        DSS_PRINT_ERROR("Malloc failed.\n");
        return CM_ERROR;
    }
    status_t status = realpath_file(input_args, *convert_result, CM_FILE_NAME_BUFFER_SIZE);
    if (status != CM_SUCCESS) {
        DSS_PRINT_ERROR("path is insecure, home: %s.\n", input_args);
        free(*convert_result);
        *convert_result = NULL;
        return status;
    }
    *convert_size = (int)CM_FILE_NAME_BUFFER_SIZE;
    return status;
}

static status_t cmd_check_convert_dss_home(const char *input_args, void **convert_result, int *convert_size)
{
    if (input_args == NULL) {
        *convert_result = NULL;
        *convert_size = 0;
        return CM_SUCCESS;
    }
    status_t status = cmd_realpath_home(input_args, (char **)convert_result, convert_size);
    if (status != CM_SUCCESS) {
        DSS_PRINT_ERROR("home realpth failed, home: %s.\n", input_args);
        return status;
    }
    return CM_SUCCESS;
}

static status_t dss_fetch_uds_path(char *server_path, char *path, char **file)
{
    char *pos = strrchr(server_path, '/');
    if (pos == NULL) {
        *file = server_path;
        path[0] = '.';
        path[1] = '\0';
        return CM_SUCCESS;
    }

    if (pos[1] == 0x00) {
        DSS_PRINT_ERROR("the format of UDS is wrong.\n");
        return CM_ERROR;
    }

    if (pos == server_path) {
        *file = (char *)(server_path + 1);
        path[0] = '/';
        path[1] = '\0';
    } else {
        *file = pos;
        errno_t errcode = memcpy_sp(path, (size_t)DSS_MAX_PATH_BUFFER_SIZE, server_path, (size_t)(pos - server_path));
        if (SECUREC_UNLIKELY(errcode != EOK)) {
            CM_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
            return CM_ERROR;
        }
        path[(int)(pos - server_path)] = '\0';
    }
    return CM_SUCCESS;
}

static status_t cmd_check_convert_uds_home(const char *input_args, void **convert_result, int *convert_size)
{
    const char *server_path = (const char *)(input_args + strlen(DSS_SUBSTR_UDS_PATH));
    char path[DSS_MAX_PATH_BUFFER_SIZE];
    char *file = NULL;
    status_t status;
    status = dss_fetch_uds_path((char *)server_path, (char *)path, (char **)&file);
    if (status != CM_SUCCESS) {
        DSS_PRINT_ERROR("Fetch uds path failed.\n");
        return CM_ERROR;
    }

    status = cmd_realpath_home(path, (char **)convert_result, convert_size);
    if (status != CM_SUCCESS) {
        DSS_PRINT_ERROR("home realpth failed, home: %s.\n", input_args);
        return status;
    }

    errno_t errcode = strcat_sp((char *)*convert_result, CM_FILE_NAME_BUFFER_SIZE, file);
    if (SECUREC_UNLIKELY(errcode != EOK)) {
        CM_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
        free(*convert_result);
        *convert_result = NULL;
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

void cmd_clean_check_convert(char *convert_result, int convert_size)
{
    if (convert_result != NULL) {
        free(convert_result);
    }
}

static status_t cmd_check_struct_name(const char *struct_name)
{
    if ((strcmp(struct_name, "core_ctrl") != 0) && (strcmp(struct_name, "vg_header") != 0) &&
        (strcmp(struct_name, "volume_ctrl") != 0) && (strcmp(struct_name, "root_ft_block") != 0)) {
        DSS_PRINT_ERROR("Incorrect struct_name input.\n");
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static status_t cmd_check_measure_type(const char *measure)
{
    if (strlen(measure) != 1) {
        DSS_PRINT_ERROR("The measure type len should be 1.\n");
        return CM_ERROR;
    }
    if ((measure[0] != 'B' && measure[0] != 'K' && measure[0] != 'M' && measure[0] != 'G' && measure[0] != 'T')) {
        DSS_PRINT_ERROR("measure_type error.\n");
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

static status_t cmd_check_inst_id(const char *inst_str)
{
    uint32 inst_id;
    status_t ret = cm_str2uint32(inst_str, &inst_id);
    if (ret != CM_SUCCESS) {
        DSS_PRINT_ERROR("The value of inst_id is invalid.\n");
        return CM_ERROR;
    }
    if (inst_id < DSS_MIN_INST_ID || inst_id >= DSS_MAX_INST_ID) {
        DSS_PRINT_ERROR("The value of inst_id should be in [%u, %u).\n", DSS_MIN_INST_ID, DSS_MAX_INST_ID);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static status_t cmd_check_show_type(const char *show_type)
{
    if (strlen(show_type) != 1) {
        DSS_PRINT_ERROR("The show type len should be 1.\n");
        return CM_ERROR;
    }
    if (show_type[0] != 'd' && show_type[0] != 't') {
        DSS_PRINT_ERROR("The show type should be [d|t].\n");
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static status_t cmd_check_inq_type(const char *inq_type)
{
    if (strcmp(inq_type, "lun") != 0 && strcmp(inq_type, "reg") != 0) {
        DSS_PRINT_ERROR("The show type should be [lun|reg].\n");
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static status_t cmd_check_disk_id(const char *id_str)
{
    uint64 id = 0;
    status_t status = cm_str2uint64(id_str, &id);
    if (status == CM_ERROR) {
        DSS_PRINT_ERROR("id_str:%s is not a valid uint64\n", id_str);
        return CM_ERROR;
    }
    dss_block_id_t *block_id = (dss_block_id_t *)&id;
    printf("id = %llu: \n", id);
    if (block_id->volume >= DSS_MAX_VOLUMES) {
        DSS_PRINT_ERROR("block_id is invalid, volume:%u.\n", (uint32)block_id->volume);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static status_t cmd_check_offset(const char *offset_str)
{
    int64 offset;
    status_t ret = cm_str2bigint(offset_str, &offset);
    if (ret != CM_SUCCESS) {
        DSS_PRINT_ERROR("The value of offset is invalid.\n");
        return CM_ERROR;
    }
    if (offset < 0 || offset % DSS_DISK_UNIT_SIZE != 0) {
        DSS_PRINT_ERROR("offset must be >= 0 and be align %d.\n", DSS_DISK_UNIT_SIZE);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static status_t cmd_check_format(const char *format)
{
    uint32 len = strlen(format);
    if (len == 0) {
        DSS_PRINT_ERROR("The value of format is invalid.\n");
        return CM_ERROR;
    }
    if (format[0] != 'c' && format[0] != 'h' && format[0] != 'u' && format[0] != 'l' && format[0] != 's' &&
        format[0] != 'x') {
        DSS_PRINT_ERROR("The name's letter of format should be [c|h|u|l|s|x].\n");
        return CM_ERROR;
    }
    if (format[1] != 0x00) {
        DSS_PRINT_ERROR("The name's letter of format should be [c|h|u|l|s|x].\n");
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static status_t cmd_check_read_size(const char *read_size_str)
{
    int32 read_size;
    status_t ret = cm_str2int(read_size_str, &read_size);
    if (ret != CM_SUCCESS) {
        DSS_PRINT_ERROR("The value of read_size is invalid.\n");
        return CM_ERROR;
    }

    if (read_size < 0) {
        DSS_PRINT_ERROR("The read_size should >= 0.\n");
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static status_t cmd_check_du_format(const char *du_format)
{
    uint32 len = strlen(du_format);
    if (len == 0) {
        DSS_PRINT_ERROR("The value of format is invalid.\n");
        return CM_ERROR;
    }
    int part_one = 0;
    int part_two = 0;
    int part_three = 0;
    for (uint32 i = 0; i < strlen(du_format); i++) {
        if (du_format[i] == 'B' || du_format[i] == 'K' || du_format[i] == 'M' || du_format[i] == 'G' ||
            du_format[i] == 'T') {
            if (part_one == 1) {
                DSS_PRINT_ERROR("The name's letter of du_format should be [BKMGT|sa|S].\n");
                return CM_ERROR;
            }
            part_one = 1;
        } else if (du_format[i] == 's' || du_format[i] == 'a') {
            if (part_two == 1) {
                DSS_PRINT_ERROR("The name's letter of du_format should be [BKMGT|sa|S].\n");
                return CM_ERROR;
            }
            part_two = 1;
        } else if (du_format[i] == 'S') {
            if (part_three == 1) {
                DSS_PRINT_ERROR("The name's letter of du_format should be [BKMGT|sa|S].\n");
                return CM_ERROR;
            }
            part_three = 1;
        } else {
            DSS_PRINT_ERROR("The name's letter of du_format should be [BKMGT|sa|S].\n");
            return CM_ERROR;
        }
    }
    return CM_SUCCESS;
}

static status_t cmd_check_cfg_name(const char *name)
{
    uint32 len = strlen(name);
    if (len == 0) {
        DSS_PRINT_ERROR("The value of name is invalid.\n");
        return CM_ERROR;
    }
    for (uint32 i = 0; i < len; i++) {
        if (!isalpha((int)name[i]) && !isdigit((int)name[i]) && name[i] != '-' && name[i] != '_') {
            DSS_PRINT_ERROR("The name's letter should be [aplha|digit|-|_].\n");
            return CM_ERROR;
        }
    }
    return CM_SUCCESS;
}

static status_t cmd_check_cfg_value(const char *value)
{
    uint32 len = strlen(value);
    if (len == 0) {
        DSS_PRINT_ERROR("The value is invalid.\n");
        return CM_ERROR;
    }
    for (uint32 i = 0; i < len; i++) {
        if (!isprint((int)value[i])) {
            DSS_PRINT_ERROR("The value's letter should be print-able.\n");
            return CM_ERROR;
        }
    }
    return CM_SUCCESS;
}

static status_t cmd_check_cfg_scope(const char *scope)
{
    const char *scope_memory = "memory";
    const char *scope_pfile = "pfile";
    const char *scope_both = "both";
    if (strcmp(scope, scope_memory) != 0 && strcmp(scope, scope_pfile) != 0 && strcmp(scope, scope_both) != 0) {
        DSS_PRINT_ERROR("scope should be [%s | %s | %s].\n", scope_memory, scope_pfile, scope_both);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

// ------------------------
// add uni-check function before here
static status_t cmd_parse_check(dss_args_t *cmd_args_set, int set_size)
{
    for (int i = 0; i < set_size; i++) {
        if (cmd_args_set[i].required && !cmd_args_set[i].inputed) {
            DSS_PRINT_ERROR(
                "args [-%c|--%s] needs input value.\n", cmd_args_set[i].short_name, cmd_args_set[i].long_name);
            return CM_ERROR;
        }
    }
    return CM_SUCCESS;
}

static status_t cmd_parse_short_name_args(int argc, char **argv, int *argc_idx, dss_args_t *cmd_args_set, int set_size)
{
    int i = *argc_idx;
    int j;
    for (j = 0; j < set_size; j++) {
        // not hit short name
        if (cmd_args_set[j].short_name != argv[i][DSS_ARG_IDX_1]) {
            continue;
        }

        // repeat args
        if (cmd_args_set[j].inputed) {
            DSS_PRINT_ERROR("%s repeat args.\n", argv[i]);
            return CM_ERROR;
        }

        // input -f and -f needs no args
        if (!cmd_args_set[j].required_args) {
            // input -fx
            if (argv[i][DSS_ARG_IDX_2] != 0x0) {
                DSS_PRINT_ERROR("%s should not with args.\n", argv[i]);
                return CM_ERROR;
            }
        } else {
            // input -f, and -f needs args
            if (argv[i][DSS_ARG_IDX_2] == 0x0 && (i + 1 >= argc)) {
                DSS_PRINT_ERROR("%s should with args.\n", argv[i]);
                return CM_ERROR;
            }

            if (argv[i][DSS_ARG_IDX_2] != 0x0) {
                // input -fx
                cmd_args_set[j].input_args = &argv[i][DSS_ARG_IDX_2];
            } else {
                // input -f x
                i++;
                cmd_args_set[j].input_args = argv[i];
            }

            // need to check args input
            if (cmd_args_set[j].check_args != NULL &&
                cmd_args_set[j].check_args(cmd_args_set[j].input_args) != CM_SUCCESS) {
                return CM_ERROR;
            }
            if (cmd_args_set[j].convert_args != NULL &&
                cmd_args_set[j].convert_args(cmd_args_set[j].input_args, &cmd_args_set[j].convert_result,
                    &cmd_args_set[j].convert_result_size) != CM_SUCCESS) {
                return CM_ERROR;
            }
        }
        cmd_args_set[j].inputed = CM_TRUE;
        break;
    }

    // no args hit
    if (j == set_size) {
        DSS_PRINT_ERROR("input %s hit no args.\n", argv[i]);
        return CM_ERROR;
    }
    *argc_idx = i;
    return CM_SUCCESS;
}

static status_t cmd_parse_long_name_args(int argc, char **argv, int *argc_idx, dss_args_t *cmd_args_set, int set_size)
{
    int i = *argc_idx;
    int j;
    for (j = 0; j < set_size; j++) {
        // hit long name
        if (cmd_args_set[j].long_name == NULL || strcmp(cmd_args_set[j].long_name, &argv[i][DSS_ARG_IDX_2]) != 0) {
            continue;
        }

        // repeat args
        if (cmd_args_set[j].inputed) {
            DSS_PRINT_ERROR("%s repeat args.\n", argv[i]);
            return CM_ERROR;
        }

        // input --format args
        if (cmd_args_set[j].required_args) {
            // input --format , and no more args
            if (i + 1 >= argc) {
                DSS_PRINT_ERROR("%s should with args.\n", argv[i]);
                return CM_ERROR;
            }
            i++;
            cmd_args_set[j].input_args = argv[i];

            // need to check args input
            if (cmd_args_set[j].check_args != NULL &&
                cmd_args_set[j].check_args(cmd_args_set[j].input_args) != CM_SUCCESS) {
                return CM_ERROR;
            }
            //
            if (cmd_args_set[j].convert_args != NULL &&
                cmd_args_set[j].convert_args(cmd_args_set[j].input_args, &cmd_args_set[j].convert_result,
                    &cmd_args_set[j].convert_result_size) != CM_SUCCESS) {
                return CM_ERROR;
            }
        }
        cmd_args_set[j].inputed = CM_TRUE;
        break;
    }

    // no args hit
    if (j == set_size) {
        DSS_PRINT_ERROR("input %s hit no args.\n", argv[i]);
        return CM_ERROR;
    }
    *argc_idx = i;
    return CM_SUCCESS;
}

static status_t cmd_parse_args(int argc, char **argv, dss_args_set_t *args_set)
{
    if (argc < CMD_ARGS_AT_LEAST || (args_set->args_size == 0 && argc > CMD_ARGS_AT_LEAST)) {
        DSS_PRINT_ERROR("args num %d error.\n", argc);
        return CM_ERROR;
    }
    // allow the cmd needs no args
    if (args_set->args_size == 0) {
        return CM_SUCCESS;
    }
    for (int i = CMD_ARGS_AT_LEAST; i < argc; i++) {
        if (argv[i][DSS_ARG_IDX_0] != '-') {
            DSS_PRINT_ERROR("%s should begin with -.\n", argv[i]);
            return CM_ERROR;
        }
        status_t status;
        if (argv[i][DSS_ARG_IDX_1] != '-') {
            status = cmd_parse_short_name_args(argc, argv, &i, args_set->cmd_args, args_set->args_size);
        } else {
            status = cmd_parse_long_name_args(argc, argv, &i, args_set->cmd_args, args_set->args_size);
        }
        if (status != CM_SUCCESS) {
            return status;
        }
    }
    if (args_set->args_check != NULL) {
        return args_set->args_check(args_set->cmd_args, args_set->args_size);
    }
    return cmd_parse_check(args_set->cmd_args, args_set->args_size);
}

static inline void help_param_dsshome(void)
{
    (void)printf("-D/--DSS_HOME <DSS_HOME>, [optional], the run path of dssserver, default value is $DSS_HOME\n");
}

static inline void help_param_uds(void)
{
    (void)printf("-U/--UDS <UDS:socket_domain>, [optional], the unix socket path of dssserver, "
                 "default value is UDS:/tmp/.dss_unix_d_socket\n");
}

static dss_args_t cmd_cv_args[] = {
    {'g', "vg_name", CM_TRUE, CM_TRUE, dss_check_name, NULL, NULL, 0, NULL, NULL, 0},
    {'v', "vol_name", CM_TRUE, CM_TRUE, dss_check_volume_path, NULL, NULL, 0, NULL, NULL, 0},
    {'s', "au_size", CM_FALSE, CM_TRUE, cmd_check_au_size, NULL, NULL, 0, NULL, NULL, 0},
    {'D', "DSS_HOME", CM_FALSE, CM_TRUE, cmd_check_dss_home, cmd_check_convert_dss_home, cmd_clean_check_convert, 0,
        NULL, NULL, 0},
};
static dss_args_set_t cmd_cv_args_set = {
    cmd_cv_args,
    sizeof(cmd_cv_args) / sizeof(dss_args_t),
    NULL,
};

static void cv_help(const char *prog_name, int print_flag)
{
    (void)printf("\nUsage:%s cv <-g vg_name> <-v vol_name> [-s au_size] [-D DSS_HOME]\n", prog_name);
    (void)printf("[manage command] create volume group\n");
    if (print_flag == DSS_HELP_SIMPLE) {
        return;
    }
    (void)printf("-g/--vg_name <vg_name>, <required>, the volume group name\n");
    (void)printf("-v/--vol_name <vol_name>, <required>, the volume name\n");
    (void)printf("-s/--au_size [au_size], [optional], the size of single alloc unit of volume, unit is KB, "
                 "at least 2MB, default value is 2MB\n");
    help_param_dsshome();
}

static status_t cv_proc(void)
{
    status_t status;

    const char *vg_name;
    const char *volume_name;
    dss_config_t cv_cfg;
    vg_name = cmd_cv_args[DSS_ARG_IDX_0].input_args;
    volume_name = cmd_cv_args[DSS_ARG_IDX_1].input_args;
    // Documentation Constraints:au_size=0 equals default_au_size
    int64 au_size = (cmd_cv_args[DSS_ARG_IDX_2].input_args) ? atoll(cmd_cv_args[DSS_ARG_IDX_2].input_args) : 0;
    char *home = cmd_cv_args[DSS_ARG_IDX_3].input_args;

    status = dss_set_cfg_dir(home, &cv_cfg);
    if (status != CM_SUCCESS) {
        DSS_PRINT_ERROR("Environment variant DSS_HOME not found!\n");
        return status;
    }
    status = dss_load_config(&cv_cfg);
    if (status != CM_SUCCESS) {
        DSS_PRINT_ERROR("Failed to load parameters!\n");
        return status;
    }
    status = dss_create_vg(vg_name, volume_name, &cv_cfg, (uint32)au_size);
    if (status != CM_SUCCESS) {
        DSS_PRINT_ERROR("Failed to create volume group, vg name is %s, volume name is %s.\n", vg_name, volume_name);
        return status;
    }
    DSS_PRINT_INF("Succeed to create volume group %s, entry volume is %s.\n", vg_name, volume_name);
    return CM_SUCCESS;
}

static status_t dss_uds_get_connection(const char *server_locator, dss_conn_t *conn)
{
    status_t status;
    if (strlen(server_locator) <= strlen(DSS_SUBSTR_UDS_PATH)) {
        LOG_DEBUG_ERR("the format of UDS is wrong\n");
        return CM_ERROR;
    }
    const char *server_path = (const char *)(server_locator + strlen(DSS_SUBSTR_UDS_PATH));
    if (server_path[0] == '~') {
        int32 ret;
        const char *sys_home_path = getenv(SYS_HOME);
        char abs_server_path[DSS_MAX_PATH_BUFFER_SIZE];

        ret = snprintf_s(abs_server_path, DSS_MAX_PATH_BUFFER_SIZE, DSS_MAX_PATH_BUFFER_SIZE - 1, "UDS:%s%s",
            sys_home_path, server_path + 1);
        if (ret < 0) {
            LOG_RUN_ERR("snprintf_s error %d", ret);
            return CM_ERROR;
        }

        status = dss_connect_ex((const char *)abs_server_path, NULL, NULL, conn);
        if (status != CM_SUCCESS) {
            LOG_DEBUG_ERR("Failed to connect,url:%s.\n", abs_server_path);
            return status;
        }
    } else {
        status = dss_connect_ex(server_locator, NULL, NULL, conn);
        if (status != CM_SUCCESS) {
            LOG_DEBUG_ERR("Failed to connect,url:%s.\n", server_locator);
            return status;
        }
    }

    return CM_SUCCESS;
}

static dss_args_t cmd_lsvg_args[] = {
    {'m', "measure_type", CM_FALSE, CM_TRUE, cmd_check_measure_type, NULL, NULL, 0, NULL, NULL, 0},
    {'t', "show_type", CM_FALSE, CM_TRUE, cmd_check_show_type, NULL, NULL, 0, NULL, NULL, 0},
    {'U', "UDS", CM_FALSE, CM_TRUE, cmd_check_uds, cmd_check_convert_uds_home, cmd_clean_check_convert, 0, NULL, NULL,
        0},
};
static dss_args_set_t cmd_lsvg_args_set = {
    cmd_lsvg_args,
    sizeof(cmd_lsvg_args) / sizeof(dss_args_t),
    NULL,
};

static void lsvg_help(const char *prog_name, int print_flag)
{
    (void)printf("\nUsage:%s lsvg [-m measure_type] [-t show_type] [-U UDS:socket_domain]\n", prog_name);
    (void)printf("[client command]Show information of volume group and disk usage space\n");
    if (print_flag == DSS_HELP_SIMPLE) {
        return;
    }
    (void)printf("-m/--measure_type <measure_type>, [optional], B show size by Byte, K show size by kB ,"
                 "M show size by MB ,G show size by GB,  T show size by TB, default show size by Byte\n");
    (void)printf("-t/--show_type <show_type>, [optional], d show information in detail , t show information in table, "
                 "default value is 't'\n");
    help_param_uds();
}

static status_t dss_load_volumes(vg_vlm_space_info_t *volume_space, dss_volume_def_t *defs, const dss_ctrl_t *dss_ctrl)
{
    double dss_vg_free = 0;
    double dss_vg_size = 0;
    for (uint32 vol_id = 0; vol_id < DSS_MAX_VOLUMES; vol_id++) {
        if (defs[vol_id].flag == VOLUME_FREE) {
            continue;
        }

        if (strcpy_s(volume_space->volume_space_info[vol_id].volume_name, DSS_MAX_VOLUME_PATH_LEN, defs[vol_id].name) != EOK) {
            return CM_ERROR;
        }

        double volume_free = (double)dss_ctrl->core.volume_attrs[vol_id].free;
        volume_space->volume_space_info[vol_id].volume_free = volume_free;

        dss_vg_free = dss_vg_free + volume_free;
        volume_space->vg_space_info.dss_vg_free = dss_vg_free;

        double volume_size = (double)dss_ctrl->core.volume_attrs[vol_id].size;
        volume_space->volume_space_info[vol_id].volume_size = volume_size;

        dss_vg_size = dss_vg_size + volume_size;
        volume_space->vg_space_info.dss_vg_size = dss_vg_size;

        double volume_used =
            (double)dss_ctrl->core.volume_attrs[vol_id].size - (double)dss_ctrl->core.volume_attrs[vol_id].free;
        volume_space->volume_space_info[vol_id].volume_used = volume_used;
    }
    return CM_SUCCESS;
}

static status_t dss_load_vginfo_sync_core(
    dss_conn_t *connection, dss_allvg_vlm_space_t *allvg_vlm_space_t, dss_vg_info_t *dss_vg_info)
{
    status_t status;
    for (uint32 vg_id = 0; vg_id < (uint32)dss_vg_info->group_num; vg_id++) {
        dss_vg_info_item_t *vg_item = &dss_vg_info->volume_group[vg_id];
        if (vg_item == NULL) {
            LOG_DEBUG_ERR("load vg item failed for vgid:%u.\n", vg_id);
            return CM_ERROR;
        }

        status = dss_load_ctrl_sync(connection, vg_item->vg_name, DSS_VG_INFO_CORE_CTRL);
        if (status != CM_SUCCESS) {
            LOG_DEBUG_ERR("load vginfo core ctrl failed, vg name %s.\n", vg_item->vg_name);
            return CM_ERROR;
        }

        status = dss_load_ctrl_sync(connection, vg_item->vg_name, DSS_VG_INFO_VOLUME_CTRL);
        if (status != CM_SUCCESS) {
            LOG_DEBUG_ERR("load vginfo volume ctrl failed, vg name %s.\n", vg_item->vg_name);
            return CM_ERROR;
        }

        dss_ctrl_t *dss_ctrl = vg_item->dss_ctrl;
        dss_core_ctrl_t *core_ctrl = &dss_ctrl->core;
        uint32 volume_count = core_ctrl->volume_count;

        dss_volume_ctrl_t *volume_ctrl = &dss_ctrl->volume;
        dss_volume_def_t *defs = volume_ctrl->defs;

        allvg_vlm_space_t->group_num++;
        if (strcpy_s(allvg_vlm_space_t->volume_group[vg_id].vg_name, DSS_MAX_NAME_LEN, vg_item->vg_name) != EOK) {
            return CM_ERROR;
        }
        allvg_vlm_space_t->volume_group[vg_id].volume_count = volume_count;
        vg_vlm_space_info_t *volume_space = &allvg_vlm_space_t->volume_group[vg_id];
        status = dss_load_volumes(volume_space, defs, dss_ctrl);
        if (status != CM_SUCCESS) {
            return status;
        }
    }
    return CM_SUCCESS;
}

static status_t dss_load_vginfo_sync(dss_conn_t *connection, dss_allvg_vlm_space_t *allvg_vlm_space_t)
{
    status_t status;
    dss_env_t *dss_env = dss_get_env();
    if (!dss_env->initialized) {
        DSS_THROW_ERROR(ERR_DSS_ENV_NOT_INITIALIZED);
        return CM_ERROR;
    }
    dss_vg_info_t *dss_vg_info = dss_env->dss_vg_info;
    dss_latch_s(&dss_env->latch);
    status = dss_load_vginfo_sync_core(connection, allvg_vlm_space_t, dss_vg_info);
    dss_unlatch(&dss_env->latch);
    return status;
}

double dss_convert_size(double size, const char *measure)
{
    double result = size;
    switch (measure[0]) {
        case 'T':
            result /= SIZE_T(1);
            break;
        case 'G':
            result /= SIZE_G(1);
            break;
        case 'M':
            result /= SIZE_M(1);
            break;
        case 'K':
            result /= SIZE_K(1);
            break;
        default:
            break;
    }
    return result;
}

static void lsvg_printf_vlm_info(vg_vlm_space_info_t *vg_vlm_info, const char *measure, bool32 detail)
{
    if (detail) {
        (void)printf("vg_name:%s\n", vg_vlm_info->vg_name);
        (void)printf("   volume_count:%u\n", vg_vlm_info->volume_count);
        (void)printf("   volumes:\n");
        for (uint32 vol_id = 0; vol_id < vg_vlm_info->volume_count; vol_id++) {
            (void)printf("      volume_name:%s\n", vg_vlm_info->volume_space_info[vol_id].volume_name);
            double volume_free = vg_vlm_info->volume_space_info[vol_id].volume_free;
            volume_free = dss_convert_size(volume_free, measure);
            double volume_size = vg_vlm_info->volume_space_info[vol_id].volume_size;
            volume_size = dss_convert_size(volume_size, measure);
            double volume_used = vg_vlm_info->volume_space_info[vol_id].volume_used;
            volume_used = dss_convert_size(volume_used, measure);
            (void)printf("      volume_free:%.05f\n", volume_free);
            (void)printf("      volume_size:%.05f\n", volume_size);
            (void)printf("      volume_used:%.05f\n", volume_used);
        }
    }
}

static void lsvg_printf_vg_info(
    const vg_vlm_space_info_t *vg_vlm_info, double dss_vg_recycle_size_tmp, const char *measure, bool32 detail)
{
    double dss_vg_used_percent = 0;
    double dss_vg_size = vg_vlm_info->vg_space_info.dss_vg_size;
    double dss_vg_free = vg_vlm_info->vg_space_info.dss_vg_free + dss_vg_recycle_size_tmp;
    double dss_vg_used = dss_vg_size - dss_vg_free;
    double dss_vg_recycle_size = dss_convert_size(dss_vg_recycle_size_tmp, measure);
    dss_vg_size = dss_convert_size(dss_vg_size, measure);
    dss_vg_free = dss_convert_size(dss_vg_free, measure);
    dss_vg_used = dss_convert_size(dss_vg_used, measure);

    dss_vg_used_percent = (dss_vg_used / dss_vg_size) * 100;
    if (detail) {
        (void)printf("   .recycle:\n");
        (void)printf("      recycle_size:%.05f\n", dss_vg_recycle_size);
        (void)printf("   vg_size:%.05f\n", dss_vg_size);
        (void)printf("   vg_free:%.05f\n", dss_vg_free);
        (void)printf("   vg_used:%.05f\n", dss_vg_used);
        (void)printf("   vg_used_percent:%.2lf\n", dss_vg_used_percent);
    } else {
        (void)printf("%-14s%-20u%-20.05f %-20.05f %-20.05f %-20.2lf\n", vg_vlm_info->vg_name, vg_vlm_info->volume_count,
            dss_vg_size, dss_vg_free, dss_vg_used, dss_vg_used_percent);
    }
}

static status_t lsvg_operate_dir_impl(vg_vlm_space_info_t *vg_vlm_info, double *dss_vg_recycle_size,
    dss_conn_t *connection, const char *measure, bool32 detail)
{
    errno_t ret;
    char dirpath[DSS_FILE_PATH_MAX_LENGTH];
    gft_node_t *node;
    if (vg_vlm_info == NULL) {
        LOG_DEBUG_ERR("Failed to find vg.\n");
        return CM_ERROR;
    }
    lsvg_printf_vlm_info(vg_vlm_info, measure, detail);
    ret = snprintf_s(dirpath, sizeof(dirpath), sizeof(dirpath) - 1, "+%s/.recycle", vg_vlm_info->vg_name);
    if (ret == -1) {
        DSS_THROW_ERROR(ERR_SYSTEM_CALL, ret);
        return CM_ERROR;
    }

    dss_dir_t *dir = dss_open_dir_impl(connection, dirpath, CM_TRUE);
    if (dir == NULL) {
        LOG_DEBUG_ERR("Failed to open dir %s.\n", dirpath);
        return CM_ERROR;
    }

    while ((node = (gft_node_t *)dss_read_dir_impl(connection, dir, CM_FALSE)) != NULL) {
        *dss_vg_recycle_size = *dss_vg_recycle_size + (double)node->size;
    }
    (void)dss_close_dir_impl(connection, dir);
    return CM_SUCCESS;
}

static status_t lsvg_info(dss_conn_t *connection, const char *measure, bool32 detail)
{
    status_t status;
    dss_allvg_vlm_space_t *allvg_vlm_space_info = NULL;
    allvg_vlm_space_info = (dss_allvg_vlm_space_t *)cm_malloc(sizeof(dss_allvg_vlm_space_t));
    if (allvg_vlm_space_info == NULL) {
        LOG_DEBUG_ERR("Malloc failed.\n");
        return CM_ERROR;
    }
    (void)memset_s(allvg_vlm_space_info, sizeof(dss_allvg_vlm_space_t), 0, sizeof(dss_allvg_vlm_space_t));
    status = dss_load_vginfo_sync(connection, allvg_vlm_space_info);
    if (status != CM_SUCCESS) {
        LOG_DEBUG_ERR("Failed to load vg information.\n");
        DSS_FREE_POINT(allvg_vlm_space_info);
        return status;
    }

    if (!detail) {
        (void)printf(
            "%-14s%-20s%-20s %-20s %-20s %-20s\n", "vg_name", "volume_count", "size", "free", "used", "percent(%)");
    }

    for (uint32 vg_id = 0; vg_id < (uint32)allvg_vlm_space_info->group_num; vg_id++) {
        double dss_vg_recycle_size = 0;
        vg_vlm_space_info_t *vg_vlm_info = &allvg_vlm_space_info->volume_group[vg_id];
        status = lsvg_operate_dir_impl(vg_vlm_info, &dss_vg_recycle_size, connection, measure, detail);
        if (status != CM_SUCCESS) {
            DSS_FREE_POINT(allvg_vlm_space_info);
            return status;
        }
        lsvg_printf_vg_info(vg_vlm_info, dss_vg_recycle_size, measure, detail);
    }

    DSS_FREE_POINT(allvg_vlm_space_info);
    return CM_SUCCESS;
}

static status_t get_server_locator(char *input_args, char *server_locator)
{
    if (input_args != NULL) {
        errno_t errcode = strcpy_s(server_locator, DSS_MAX_PATH_BUFFER_SIZE, input_args);
        if (errcode != EOK) {
            DSS_PRINT_ERROR("Failed to strcpy server_locator, err = %d.\n", errcode);
            return CM_ERROR;
        }
    } else {
        char name[CM_MAX_PATH_LEN] = "LSNR_PATH";
        char *value = NULL;
        status_t status = dss_get_cfg_param(name, &value);
        if (status != CM_SUCCESS) {
            DSS_PRINT_ERROR("get cfg param failed, by %s.\n", name);
            return CM_ERROR;
        }
        int ret = snprintf_s(
            server_locator, DSS_MAX_PATH_BUFFER_SIZE, DSS_MAX_PATH_BUFFER_SIZE - 1, "UDS:%s/.dss_unix_d_socket", value);
        if (ret < 0) {
            DSS_PRINT_ERROR("snsprintf_s server_locator failed.\n");
            return CM_ERROR;
        }
    }
    return CM_SUCCESS;
}

static status_t lsvg_get_parameter(char *server_locator, const char **measure, bool32 *detail)
{
    if (cmd_lsvg_args[DSS_ARG_IDX_0].input_args != NULL) {
        *measure = cmd_lsvg_args[DSS_ARG_IDX_0].input_args;
    } else {
        *measure = DSS_DEFAULT_MEASURE;
    }

    char show_type = DSS_DEFAULT_VG_TYPE;
    if (cmd_lsvg_args[DSS_ARG_IDX_1].input_args != NULL) {
        show_type = cmd_lsvg_args[DSS_ARG_IDX_1].input_args[0];
    }
    if (show_type == 'd') {
        (*detail) = CM_TRUE;
    } else if (show_type == 't') {
        (*detail) = CM_FALSE;
    } else {
        DSS_PRINT_ERROR("show_type error.\n");
        return CM_ERROR;
    }

    status_t status = get_server_locator(cmd_lsvg_args[DSS_ARG_IDX_2].input_args, server_locator);
    if (status != CM_SUCCESS) {
        DSS_PRINT_ERROR("Failed to get server_locator.\n");
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

static status_t lsvg_proc(void)
{
    status_t status;
    const char *measure;
    char server_locator[DSS_MAX_PATH_BUFFER_SIZE] = {0};
    bool32 detail;
    dss_conn_t connection;

    status = lsvg_get_parameter(server_locator, &measure, &detail);
    if (status != CM_SUCCESS) {
        return status;
    }

    status = dss_uds_get_connection(server_locator, &connection);
    if (status != CM_SUCCESS) {
        DSS_PRINT_ERROR("Failed to get uds connection.\n");
        return status;
    }

    status = lsvg_info(&connection, measure, detail);
    if (status != CM_SUCCESS) {
        dss_disconnect_ex(&connection);
        DSS_PRINT_ERROR("Failed to display lsvg info.\n");
        return status;
    }
    dss_disconnect_ex(&connection);
    DSS_PRINT_INF("Succeed to display lsvg info.\n");
    return CM_SUCCESS;
}

static status_t dss_load_local_server_config(
    dss_config_t *inst_cfg, config_item_t *client_parameters, uint32 item_count)
{
    char file_name[CM_MAX_PATH_LEN];
    char *home = dss_get_cfg_dir(inst_cfg);
    status_t res;

    if (snprintf_s(file_name, CM_MAX_PATH_LEN, CM_MAX_PATH_LEN - 1, "%s/cfg/%s", home, DSS_CFG_NAME) == -1) {
        cm_panic(0);
    }
    cm_init_config(client_parameters, item_count, &inst_cfg->config);
    inst_cfg->config.ignore = CM_TRUE; /* ignore unknown parameters */
    if (!cm_file_exist(file_name)) {
        return CM_SUCCESS;
    }
    res = cm_read_config(file_name, &inst_cfg->config);
    if (res != CM_SUCCESS) {
        LOG_DEBUG_ERR("Read config from %s failed.\n", file_name);
    }
    return res;
}

static dss_args_t cmd_adv_args[] = {
    {'g', "vg_name", CM_TRUE, CM_TRUE, dss_check_name, NULL, NULL, 0, NULL, NULL, 0},
    {'v', "vol_name", CM_TRUE, CM_TRUE, dss_check_volume_path, NULL, NULL, 0, NULL, NULL, 0},
    {'D', "DSS_HOME", CM_FALSE, CM_TRUE, cmd_check_dss_home, cmd_check_convert_dss_home, cmd_clean_check_convert, 0,
        NULL, NULL, 0},
    {'U', "UDS", CM_FALSE, CM_TRUE, cmd_check_uds, cmd_check_convert_uds_home, cmd_clean_check_convert, 0, NULL, NULL,
        0},
};
static dss_args_set_t cmd_adv_args_set = {
    cmd_adv_args,
    sizeof(cmd_adv_args) / sizeof(dss_args_t),
    NULL,
};

static void adv_help(const char *prog_name, int print_flag)
{
    (void)printf("\nUsage:%s adv <-g vg_name> <-v vol_name> [-D DSS_HOME] [-U UDS:socket_domain]\n", prog_name);
    (void)printf("[client command]add volume in volume group\n");
    if (print_flag == DSS_HELP_SIMPLE) {
        return;
    }
    (void)printf("-g/--vg_name <vg_name>, <required>, the volume group name need to add volume\n");
    (void)printf("-v/--vol_name <vol_name>, <required>, the volume name need to be added to volume group\n");
    help_param_uds();
}

static status_t get_connection_by_input_args(char *input_args, dss_conn_t *connection)
{
    char server_locator[DSS_MAX_PATH_BUFFER_SIZE] = {0};
    status_t status = get_server_locator(input_args, server_locator);
    if (status != CM_SUCCESS) {
        DSS_PRINT_ERROR("Failed to get server_locator.\n");
        return CM_ERROR;
    }

    status = dss_uds_get_connection(server_locator, connection);
    if (status != CM_SUCCESS) {
        DSS_PRINT_ERROR("Failed to get uds connection.\n");
        return status;
    }
    return CM_SUCCESS;
}

static status_t adv_proc(void)
{
    const char *vg_name = cmd_adv_args[DSS_ARG_IDX_0].input_args;
    const char *vol_path = cmd_adv_args[DSS_ARG_IDX_1].input_args;
    const char *home = cmd_adv_args[DSS_ARG_IDX_2].input_args;
    dss_conn_t connection;
    status_t status = get_connection_by_input_args(cmd_adv_args[DSS_ARG_IDX_3].input_args, &connection);
    if (status != CM_SUCCESS) {
        status = dss_add_volume_offline(home, vg_name, vol_path);
        if (status != CM_SUCCESS) {
            DSS_PRINT_ERROR("Failed to add volume offline, vg_name is %s, volume path is %s.\n", vg_name, vol_path);
        } else {
            DSS_PRINT_INF("Succeed to add volume offline, vg_name is %s, volume path is %s.\n", vg_name, vol_path);
        }
        return status;
    }

    status = dsscmd_adv_impl(&connection, vg_name, vol_path);
    if (status != CM_SUCCESS) {
        DSS_PRINT_ERROR("Failed to add volume online, vg_name is %s, volume path is %s.\n", vg_name, vol_path);
    } else {
        DSS_PRINT_INF("Succeed to add volume online, vg_name is %s, volume path is %s.\n", vg_name, vol_path);
    }

    dss_disconnect_ex(&connection);
    return status;
}

static dss_args_t cmd_mkdir_args[] = {
    {'p', "path", CM_TRUE, CM_TRUE, dss_check_device_path, NULL, NULL, 0, NULL, NULL, 0},
    {'d', "dir_name", CM_TRUE, CM_TRUE, dss_check_name, NULL, NULL, 0, NULL, NULL, 0},
    {'U', "UDS", CM_FALSE, CM_TRUE, cmd_check_uds, cmd_check_convert_uds_home, cmd_clean_check_convert, 0, NULL, NULL,
        0},
};
static dss_args_set_t cmd_mkdir_args_set = {
    cmd_mkdir_args,
    sizeof(cmd_mkdir_args) / sizeof(dss_args_t),
    NULL,
};

static void mkdir_help(const char *prog_name, int print_flag)
{
    (void)printf("\nUsage:%s mkdir <-p path> <-d dir_name> [-U UDS:socket_domain]\n", prog_name);
    (void)printf("[client command]make dir\n");
    if (print_flag == DSS_HELP_SIMPLE) {
        return;
    }
    (void)printf("-p/--path <path>, <required>, the name need to add dir\n");
    (void)printf("-d/--dir_name <dir_name>, <required>, the dir name need to be added to path\n");
    help_param_uds();
}

static status_t mkdir_proc(void)
{
    const char *path = cmd_mkdir_args[DSS_ARG_IDX_0].input_args;
    const char *dir_name = cmd_mkdir_args[DSS_ARG_IDX_1].input_args;
    dss_conn_t connection;
    status_t status = get_connection_by_input_args(cmd_mkdir_args[DSS_ARG_IDX_2].input_args, &connection);
    if (status != CM_SUCCESS) {
        return status;
    }

    status = dss_make_dir_impl(&connection, path, dir_name);
    if (status != CM_SUCCESS) {
        DSS_PRINT_ERROR("Failed to make dir, path is %s, dir name is %s.\n", path, dir_name);
    } else {
        DSS_PRINT_INF("Succeed to make dir, path is %s, dir name is %s.\n", path, dir_name);
    }
    dss_disconnect_ex(&connection);

    return status;
}

static dss_args_t cmd_touch_args[] = {
    {'p', "path", CM_TRUE, CM_TRUE, dss_check_device_path, NULL, NULL, 0, NULL, NULL, 0},
    {'U', "UDS", CM_FALSE, CM_TRUE, cmd_check_uds, cmd_check_convert_uds_home, cmd_clean_check_convert, 0, NULL, NULL,
        0},
};
static dss_args_set_t cmd_touch_args_set = {
    cmd_touch_args,
    sizeof(cmd_touch_args) / sizeof(dss_args_t),
    NULL,
};

static void touch_help(const char *prog_name, int print_flag)
{
    (void)printf("\nUsage:%s touch <-p path> [-U UDS:socket_domain]\n", prog_name);
    (void)printf("[client command]create file\n");
    if (print_flag == DSS_HELP_SIMPLE) {
        return;
    }
    (void)printf("-p/--path <path>, <required>, file need to touch, path must begin with '+'\n");
    help_param_uds();
}

static status_t touch_proc(void)
{
    const char *path = cmd_touch_args[DSS_ARG_IDX_0].input_args;
    dss_conn_t connection;
    status_t status = get_connection_by_input_args(cmd_touch_args[DSS_ARG_IDX_1].input_args, &connection);
    if (status != CM_SUCCESS) {
        return status;
    }

    status = (status_t)dss_create_file_impl(&connection, path, 0);
    if (status != CM_SUCCESS) {
        DSS_PRINT_ERROR("Failed to create file, name is %s.\n", path);
    } else {
        DSS_PRINT_INF("Succeed to create file, name is %s.\n", path);
    }
    dss_disconnect_ex(&connection);
    return status;
}

static dss_args_t cmd_ts_args[] = {
    {'U', "UDS", CM_FALSE, CM_TRUE, cmd_check_uds, cmd_check_convert_uds_home, cmd_clean_check_convert, 0, NULL, NULL,
        0},
};

static dss_args_set_t cmd_ts_args_set = {
    cmd_ts_args,
    sizeof(cmd_ts_args) / sizeof(dss_args_t),
    NULL,
};

static void ts_help(const char *prog_name, int print_flag)
{
    (void)printf("\nUsage:%s ts [-U UDS:socket_domain]\n", prog_name);
    (void)printf("[client command]Show current API invoking time\n");
    if (print_flag == DSS_HELP_SIMPLE) {
        return;
    }
    help_param_uds();
}

static status_t ts_proc(void)
{
    dss_conn_t connection;
    status_t status = get_connection_by_input_args(cmd_ts_args[DSS_ARG_IDX_0].input_args, &connection);
    if (status != CM_SUCCESS) {
        return status;
    }

    dss_session_stat_t time_stat[DSS_EVT_COUNT];
    status = dss_get_time_stat_on_server(&connection, time_stat, DSS_EVT_COUNT);
    if (status != CM_SUCCESS) {
        DSS_PRINT_ERROR("Failed to get time stat.\n");
        dss_disconnect_ex(&connection);
        return CM_ERROR;
    }
    char *time_stat_event[] = {"DSS_PREAD", "DSS_PWRITE"};
    (void)printf("|      event     |   count   | total_wait_time | avg_wait_time | max_single_time \n");
    (void)printf("+----------------+-----------+-----------------+---------------+-----------------\n");
    for (int i = 0; i < DSS_EVT_COUNT; i++) {
        if (time_stat[i].wait_count == 0) {
            (void)printf("|%-16s|%-11d|%-17d|%-15d|%-17d\n", time_stat_event[i], 0, 0, 0, 0);
            continue;
        }
        (void)printf("|%-16s|%-11lld|%-17lld|%-15lld|%-17lld\n", time_stat_event[i], time_stat[i].wait_count,
            time_stat[i].total_wait_time, time_stat[i].total_wait_time / time_stat[i].wait_count,
            time_stat[i].max_single_time);
    }
    (void)printf("+----------------+-----------+-----------------+---------------+-----------------\n");
    dss_disconnect_ex(&connection);
    return CM_SUCCESS;
}

static dss_args_t cmd_ls_args[] = {
    {'p', "path", CM_TRUE, CM_TRUE, dss_check_device_path, NULL, NULL, 0, NULL, NULL, 0},
    {'m', "measure_type", CM_FALSE, CM_TRUE, cmd_check_measure_type, NULL, NULL, 0, NULL, NULL, 0},
    {'U', "UDS", CM_FALSE, CM_TRUE, cmd_check_uds, cmd_check_convert_uds_home, cmd_clean_check_convert, 0, NULL, NULL,
        0},
};
static dss_args_set_t cmd_ls_args_set = {
    cmd_ls_args,
    sizeof(cmd_ls_args) / sizeof(dss_args_t),
    NULL,
};

static void ls_help(const char *prog_name, int print_flag)
{
    (void)printf("\nUsage:%s ls <-p path> [-m measure_type] [-U UDS:socket_domain]\n", prog_name);
    (void)printf("[client command]Show information of volume group and disk usage space\n");
    if (print_flag == DSS_HELP_SIMPLE) {
        return;
    }
    (void)printf("-p/--path <path>, <required>, show information for it\n");
    (void)printf("-m/--measure_type <measure_type>, [optional], B show size by Byte, K show size by kB ,"
                 "M show size by MB ,G show size by GB,  T show size by TB, default show size by Byte\n");
    help_param_uds();
}

static status_t ls_get_parameter(const char **path, const char **measure, char *server_locator)
{
    *path = cmd_ls_args[DSS_ARG_IDX_0].input_args;
    if (strlen(*path) > DSS_MAX_PATH_SIZE) {
        DSS_PRINT_ERROR("The path length exceeds the maximum %d\n", DSS_MAX_PATH_SIZE);
        return CM_ERROR;
    }

    *measure =
        cmd_ls_args[DSS_ARG_IDX_1].input_args != NULL ? cmd_ls_args[DSS_ARG_IDX_1].input_args : DSS_DEFAULT_MEASURE;
    status_t status = get_server_locator(cmd_ls_args[DSS_ARG_IDX_2].input_args, server_locator);
    if (status != CM_SUCCESS) {
        DSS_PRINT_ERROR("Failed to get server_locator.\n");
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static status_t dss_ls_print_node_info(gft_node_t *node, const char*measure)
{
    char time[512] = {0};
    if (cm_time2str(node->create_time, "YYYY-MM-DD HH24:mi:ss", time, sizeof(time)) != CM_SUCCESS) {
        DSS_PRINT_ERROR("Failed to get create time of node %s.\n", node->name);
        return CM_ERROR;
    }
    double size = (double)node->size;
    if (node->size != 0) {
        size = dss_convert_size(size, measure);
    }
    if (node->type >GFT_LINK) {
        DSS_PRINT_ERROR("Invalid node type %u.\n", node->type);
        return CM_ERROR;
    }
    char type = dss_ls_print_flag[node->type];
    double written_size = (double)node->written_size;
    if (node->written_size != 0) {
        written_size = dss_convert_size(written_size, measure);
    }
    (void)printf("%-5c%-20s%-14.05f %-14.05f %-64s\n", type, time, size, written_size, node->name);
    return CM_SUCCESS;
}

static status_t dss_ls_print_file(dss_conn_t *conn, const char *path, const char*measure)
{
    gft_node_t *node = NULL;
    dss_check_dir_output_t output_info = {&node, NULL, NULL};
    DSS_RETURN_IF_ERROR(dss_check_dir(conn->session, path, GFT_FILE, &output_info, CM_FALSE));
    if (node == NULL) {
        LOG_DEBUG_INF("Failed to find path %s with the file type", path);
        return CM_ERROR;
    }
    (void)printf("%-5s%-20s%-14s %-14s %-64s\n", "type", "time", "size", "written_size", "name");
    return dss_ls_print_node_info(node, measure);
}

static status_t dss_ls_try_print_link(dss_conn_t *conn, const char *path, const char*measure)
{
    if (dss_is_valid_link_path(path)) {
        gft_node_t *node = NULL;
        dss_check_dir_output_t output_info = {&node, NULL, NULL};
        DSS_RETURN_IF_ERROR(dss_check_dir(conn->session, path, GFT_LINK, &output_info, CM_FALSE));
        if (node != NULL) {
            (void)printf("%-5s%-20s%-14s %-14s %-64s\n", "type", "time", "size", "written_size", "name");
            return dss_ls_print_node_info(node, measure);
        }
    }
    LOG_DEBUG_INF("Failed to try print path %s with the link type", path);
    return CM_ERROR;
}

static status_t ls_proc_core(dss_conn_t *conn, const char *path, const char*measure)
{
    gft_node_t *node = NULL;
    dss_vg_info_item_t *vg_item = NULL;
    char name[DSS_MAX_NAME_LEN] = {0};
    status_t status = CM_ERROR;
    bool32 exist = false;
    gft_item_type_t type;
    DSS_RETURN_IFERR2(
        dss_find_vg_by_dir(path, name, &vg_item), DSS_PRINT_ERROR("Failed to find vg when ls the path %s.\n", path));
    DSS_RETURN_IFERR2(
        dss_exist_impl(conn, path, &exist, &type), DSS_PRINT_ERROR("Failed to check the path %s exists.\n", path));
    if (!exist) {
        DSS_PRINT_ERROR("The path %s is not exist.\n", path);
        return CM_ERROR;
    }
    if (type == GFT_FILE) {
        DSS_LOCK_VG_META_S_RETURN_ERROR(vg_item, conn->session);
        status = dss_ls_print_file(conn, path, measure);
        DSS_UNLOCK_VG_META_S(vg_item, conn->session);
        if (status == CM_SUCCESS) {
            DSS_PRINT_INF("Succeed to ls file info.\n");
            return status;
        }
    } else if (type == GFT_LINK || type == GFT_LINK_TO_FILE || type == GFT_LINK_TO_PATH) {
        DSS_LOCK_VG_META_S_RETURN_ERROR(vg_item, conn->session);
        status = dss_ls_try_print_link(conn, path, measure);
        DSS_UNLOCK_VG_META_S(vg_item, conn->session);
        if (status == CM_SUCCESS) {
            DSS_PRINT_INF("Succeed to ls link info.\n");
            return status;
        }
    }
    dss_dir_t *dir = dss_open_dir_impl(conn, path, CM_TRUE);
    if (dir == NULL) {
        DSS_PRINT_ERROR("Failed to open dir %s.\n", path);
        return CM_ERROR;
    }
    (void)printf("%-5s%-20s%-14s %-14s %-64s\n", "type", "time", "size", "written_size", "name");
    while ((node = dss_read_dir_impl(conn, dir, CM_TRUE)) != NULL) {
        status = dss_ls_print_node_info(node, measure);
        if (status != CM_SUCCESS) {
            (void)dss_close_dir_impl(conn, dir);
            return CM_ERROR;
        }
    }
    (void)dss_close_dir_impl(conn, dir);
    DSS_PRINT_INF("Succeed to ls dir info.\n");
    return CM_SUCCESS;
}

static status_t ls_proc(void)
{
    const char *path = NULL;
    char server_locator[DSS_MAX_PATH_BUFFER_SIZE] = {0};
    const char *measure = NULL;
    status_t status = ls_get_parameter(&path, &measure, server_locator);
    if (status != CM_SUCCESS) {
        return status;
    }

    dss_conn_t connection;
    status = dss_uds_get_connection(server_locator, &connection);
    if (status != CM_SUCCESS) {
        DSS_PRINT_ERROR("Failed to get uds connection.\n");
        return status;
    }

    status = ls_proc_core(&connection, path, measure);
    dss_disconnect_ex(&connection);
    return status;
}

static dss_args_t cmd_cp_args[] = {
    {'s', "src_file", CM_TRUE, CM_TRUE, dss_check_path_both, NULL, NULL, 0, NULL, NULL, 0},
    {'d', "dest_file", CM_TRUE, CM_TRUE, dss_check_path_both, NULL, NULL, 0, NULL, NULL, 0},
    {'U', "UDS", CM_FALSE, CM_TRUE, cmd_check_uds, cmd_check_convert_uds_home, cmd_clean_check_convert, 0, NULL, NULL,
        0},
};
static dss_args_set_t cmd_cp_args_set = {
    cmd_cp_args,
    sizeof(cmd_cp_args) / sizeof(dss_args_t),
    NULL,
};

static void cp_help(const char *prog_name, int print_flag)
{
    (void)printf("\nUsage:%s cp <-s src_file> <-d dest_file> [-U UDS:socket_domain]\n", prog_name);
    (void)printf("[client command]copy source file to destination file\n");
    if (print_flag == DSS_HELP_SIMPLE) {
        return;
    }
    (void)printf("-s/--src_file <src_file>, <required>, source file\n");
    (void)printf("-d/--dest_file <dest_file>, <required>, destination file\n");
    help_param_uds();
}

static status_t cp_proc(void)
{
    char *srcpath = cmd_cp_args[DSS_ARG_IDX_0].input_args;
    char *despath = cmd_cp_args[DSS_ARG_IDX_1].input_args;
    dss_conn_t connection;
    status_t status = get_connection_by_input_args(cmd_cp_args[DSS_ARG_IDX_2].input_args, &connection);
    if (status != CM_SUCCESS) {
        return status;
    }

    status = dss_copy_file_impl(&connection, srcpath, despath);
    if (status != CM_SUCCESS) {
        DSS_PRINT_ERROR("Failed to copy file from srcpath %s to destpath %s.\n", srcpath, despath);
#ifdef OPENGAUSS
        DSS_PRINT_ERROR("Check whether the Linux file: %s is 512-aligned.\n", srcpath);
#endif
    } else {
        DSS_PRINT_INF("Succeed to copy file from srcpath %s to destpath %s.\n", srcpath, despath);
    }
    dss_disconnect_ex(&connection);
    return status;
}

static dss_args_t cmd_rm_args[] = {
    {'p', "path", CM_TRUE, CM_TRUE, dss_check_device_path, NULL, NULL, 0, NULL, NULL, 0},
    {'U', "UDS", CM_FALSE, CM_TRUE, cmd_check_uds, cmd_check_convert_uds_home, cmd_clean_check_convert, 0, NULL, NULL,
        0},
};
static dss_args_set_t cmd_rm_args_set = {
    cmd_rm_args,
    sizeof(cmd_rm_args) / sizeof(dss_args_t),
    NULL,
};

static void rm_help(const char *prog_name, int print_flag)
{
    (void)printf("\nUsage:%s rm <-p path> [-U UDS:socket_domain]\n", prog_name);
    (void)printf("[client command]remove device\n");
    if (print_flag == DSS_HELP_SIMPLE) {
        return;
    }
    (void)printf("-p/--path <path>, <required>, device path, must begin with '+'\n");
    help_param_uds();
}

static status_t rm_proc(void)
{
    const char *path = cmd_rm_args[DSS_ARG_IDX_0].input_args;
    dss_conn_t connection;
    status_t status = get_connection_by_input_args(cmd_rm_args[DSS_ARG_IDX_1].input_args, &connection);
    if (status != CM_SUCCESS) {
        return status;
    }

    status = dss_remove_file_impl(&connection, path);
    if (status != CM_SUCCESS) {
        DSS_PRINT_ERROR("Failed to remove device %s.\n", path);
    } else {
        DSS_PRINT_INF("Succeed to remove device %s.\n", path);
    }
    dss_disconnect_ex(&connection);
    return status;
}

static dss_args_t cmd_rmv_args[] = {
    {'g', "vg_name", CM_TRUE, CM_TRUE, dss_check_name, NULL, NULL, 0, NULL, NULL, 0},
    {'v', "vol_name", CM_TRUE, CM_TRUE, dss_check_volume_path, NULL, NULL, 0, NULL, NULL, 0},
    {'U', "UDS", CM_FALSE, CM_TRUE, cmd_check_uds, cmd_check_convert_uds_home, cmd_clean_check_convert, 0, NULL, NULL,
        0},
};
static dss_args_set_t cmd_rmv_args_set = {
    cmd_rmv_args,
    sizeof(cmd_rmv_args) / sizeof(dss_args_t),
    NULL,
};

static void rmv_help(const char *prog_name, int print_flag)
{
    (void)printf("\nUsage:%s rmv <-g vg_name> <-v vol_name> [-U UDS:socket_domain]\n", prog_name);
    (void)printf("[client command]remove volume of volume group\n");
    if (print_flag == DSS_HELP_SIMPLE) {
        return;
    }
    (void)printf("-g/--vg_name <vg_name>, <required>, the volume group name need to remove volume\n");
    (void)printf("-v/--vol_name <vol_name>, <required>, the volue name need to be removed from volume group\n");
    help_param_uds();
}

static status_t rmv_proc(void)
{
    const char *vg_name = cmd_rmv_args[DSS_ARG_IDX_0].input_args;
    const char *vol_name = cmd_rmv_args[DSS_ARG_IDX_1].input_args;
    dss_conn_t connection;
    status_t status = get_connection_by_input_args(cmd_rmv_args[DSS_ARG_IDX_2].input_args, &connection);
    if (status != CM_SUCCESS) {
        return status;
    }

    status = dsscmd_rmv_impl(&connection, vg_name, vol_name);
    if (status != CM_SUCCESS) {
        DSS_PRINT_ERROR("Failed to remove volume, vg name is %s, volume name is %s.\n", vg_name, vol_name);
    } else {
        DSS_PRINT_INF("Succeed to remove volume, vg name is %s, volume name is %s.\n", vg_name, vol_name);
    }
    dss_disconnect_ex(&connection);
    return status;
}

static dss_args_t cmd_rmdir_args[] = {
    {'p', "path", CM_TRUE, CM_TRUE, dss_check_device_path, NULL, NULL, 0, NULL, NULL, 0},
    {'r', "recursive", CM_FALSE, CM_FALSE, NULL, NULL, NULL, 0, NULL, NULL, 0},
    {'U', "UDS", CM_FALSE, CM_TRUE, cmd_check_uds, cmd_check_convert_uds_home, cmd_clean_check_convert, 0, NULL, NULL,
        0},
};
static dss_args_set_t cmd_rmdir_args_set = {
    cmd_rmdir_args,
    sizeof(cmd_rmdir_args) / sizeof(dss_args_t),
    NULL,
};

static void rmdir_help(const char *prog_name, int print_flag)
{
    (void)printf("\nUsage:%s rmdir <-p path> [-r] [-U UDS:socket_domain path]\n", prog_name);
    (void)printf("[client command] remove dir or with it's contents recursively\n");
    if (print_flag == DSS_HELP_SIMPLE) {
        return;
    }
    (void)printf("-p/--path <path>, <required>, the name need to remove\n");
    (void)printf("-r/--recursive  [optional], remove dir and it's contents recursively\n");
    help_param_uds();
}

static status_t rmdir_proc(void)
{
    const char *path = cmd_rmdir_args[DSS_ARG_IDX_0].input_args;
    bool32 recursive = cmd_rmdir_args[DSS_ARG_IDX_1].inputed ? CM_TRUE : CM_FALSE;
    dss_conn_t connection;
    status_t status = get_connection_by_input_args(cmd_rmdir_args[DSS_ARG_IDX_2].input_args, &connection);
    if (status != CM_SUCCESS) {
        return status;
    }

    status = dss_remove_dir_impl(&connection, path, recursive);
    if (status != CM_SUCCESS) {
        DSS_PRINT_ERROR("Failed to rm dir, path is %s.\n", path);
    } else {
        DSS_PRINT_INF("Succeed to rm dir, path is %s.\n", path);
    }
    dss_disconnect_ex(&connection);
    return status;
}

static dss_args_t cmd_inq_args[] = {
    {'t', "inq_type", CM_TRUE, CM_TRUE, cmd_check_inq_type, NULL, NULL, 0, NULL, NULL, 0},
    {'D', "DSS_HOME", CM_FALSE, CM_TRUE, cmd_check_dss_home, cmd_check_convert_dss_home, cmd_clean_check_convert, 0,
        NULL, NULL, 0},
};
static dss_args_set_t cmd_inq_args_set = {
    cmd_inq_args,
    sizeof(cmd_inq_args) / sizeof(dss_args_t),
    NULL,
};

static void inq_help(const char *prog_name, int print_flag)
{
    (void)printf("\nUsage:%s inq <-t inq_type> [-D DSS_HOME]\n", prog_name);
    (void)printf("[raid command] inquiry LUN information or reservations\n");
    if (print_flag == DSS_HELP_SIMPLE) {
        return;
    }
    (void)printf("-t/--type <inq_type>, <required>, the type need to inquiry, values [lun|reg]"
                 "lun :inquiry LUN information, reg:inquiry reservations\n");
    help_param_dsshome();
}

static status_t inq_proc(void)
{
    status_t status;
    char *home = cmd_inq_args[DSS_ARG_IDX_1].input_args;
    if (cm_strcmpi(cmd_inq_args[DSS_ARG_IDX_0].input_args, "lun") == 0) {
        status = dss_inq_lun(home);
        if (status != CM_SUCCESS) {
            DSS_PRINT_ERROR("Failed to inquire lun info, status is %d.\n", status);
            return status;
        }
    } else if (cm_strcmpi(cmd_inq_args[DSS_ARG_IDX_0].input_args, "reg") == 0) {
        status = dss_inq_reg(home);
        if (status != CM_SUCCESS) {
            DSS_PRINT_ERROR("Failed to inquire reg info, status is %d.\n", status);
            return status;
        }
    } else {
        DSS_PRINT_ERROR("error inq_type.\n");
        return CM_ERROR;
    }
    DSS_PRINT_INF("Succeed to inquiry LUN information, or inquiry reservations.\n");
    return CM_SUCCESS;
}

static dss_args_t cmd_inq_req_args[] = {
    {'i', "inst_id", CM_TRUE, CM_TRUE, cmd_check_inst_id, NULL, NULL, 0, NULL, NULL, 0},
    {'D', "DSS_HOME", CM_FALSE, CM_TRUE, cmd_check_dss_home, cmd_check_convert_dss_home, cmd_clean_check_convert, 0,
        NULL, NULL, 0},
};
static dss_args_set_t cmd_inq_req_args_set = {
    cmd_inq_req_args,
    sizeof(cmd_inq_req_args) / sizeof(dss_args_t),
    NULL,
};

static void inq_reg_help(const char *prog_name, int print_flag)
{
    (void)printf("\nUsage:%s inq_reg <-i inst_id> [-D DSS_HOME]\n", prog_name);
    (void)printf("[raid command]check whether the node is registered\n");
    if (print_flag == DSS_HELP_SIMPLE) {
        return;
    }
    (void)printf("-i/--inst_id <inst_id>, <required>, the id of the host need to reg\n");
    help_param_dsshome();
}

static status_t inq_reg_proc(void)
{
    int64 host_id = atoll(cmd_inq_req_args[DSS_ARG_IDX_0].input_args);
    char *home = cmd_inq_req_args[DSS_ARG_IDX_1].input_args;
    status_t status = dss_inq_reg_core(home, host_id);
    if (status == CM_ERROR) {
        DSS_PRINT_ERROR("Failed to inq reg host %lld.\n", host_id);
    } else {
        DSS_PRINT_INF("Succeed to inq reg host %lld.\n", host_id);
    }
    return status;
}

static dss_args_set_t cmd_lscli_args_set = {
    NULL,
    0,
    NULL,
};

static void lscli_help(const char *prog_name, int print_flag)
{
    (void)printf("\nUsage:%s lscli\n", prog_name);
    (void)printf("[client command] Show information of client\n");
}

static status_t lscli_proc(void)
{
    errno_t errcode;
    dss_cli_info cli_info;

    cli_info.cli_pid = cm_sys_pid();
    cli_info.start_time = cm_sys_process_start_time(cli_info.cli_pid);
    errcode = strncpy_s(
        cli_info.process_name, sizeof(cli_info.process_name), cm_sys_program_name(), strlen(cm_sys_program_name()));
    if (errcode != EOK) {
        DSS_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
        DSS_PRINT_ERROR("Failed to lscli.\n");
        return CM_ERROR;
    }

    (void)printf("%-20s%-20s%-256s\n", "cli_pid", "start_time", "process_name");
    (void)printf("%-20llu%-20lld%-256s\n", cli_info.cli_pid, cli_info.start_time, cli_info.process_name);
    return CM_SUCCESS;
}

static dss_args_t cmd_kickh_args[] = {
    {'i', "inst_id", CM_TRUE, CM_TRUE, cmd_check_inst_id, NULL, NULL, 0, NULL, NULL, 0},
    {'D', "DSS_HOME", CM_FALSE, CM_TRUE, cmd_check_dss_home, cmd_check_convert_dss_home, cmd_clean_check_convert, 0,
        NULL, NULL, 0},
};
static dss_args_set_t cmd_kickh_args_set = {
    cmd_kickh_args,
    sizeof(cmd_kickh_args) / sizeof(dss_args_t),
    NULL,
};

static void kickh_help(const char *prog_name, int print_flag)
{
    (void)printf("\nUsage:%s kickh <-i inst_id> [-D DSS_HOME]\n", prog_name);
    (void)printf("[client command] kick off the host from the array\n");
    if (print_flag == DSS_HELP_SIMPLE) {
        return;
    }
    (void)printf("-i/--inst_id <inst_id>, <required>, the id of the host need to kick off\n");
    help_param_dsshome();
}

static status_t kickh_proc(void)
{
    int64 kick_hostid = atoll(cmd_kickh_args[DSS_ARG_IDX_0].input_args);
    char *home = cmd_kickh_args[DSS_ARG_IDX_1].input_args;

    status_t status = dss_kickh_core(home, kick_hostid);
    if (status != CM_SUCCESS) {
        DSS_PRINT_ERROR("Failed to kick host, kickid %lld.\n", kick_hostid);
        return CM_ERROR;
    }
    DSS_PRINT_INF("Succeed to kick host, kickid %lld.\n", kick_hostid);
    return CM_SUCCESS;
}

static dss_args_t cmd_reghl_args[] = {
    {'D', "DSS_HOME", CM_FALSE, CM_TRUE, cmd_check_dss_home, cmd_check_convert_dss_home, cmd_clean_check_convert, 0,
        NULL, NULL, 0},
};
static dss_args_set_t cmd_reghl_args_set = {
    cmd_reghl_args,
    sizeof(cmd_reghl_args) / sizeof(dss_args_t),
    NULL,
};

static void reghl_help(const char *prog_name, int print_flag)
{
    (void)printf("\nUsage:%s reghl [-D DSS_HOME]\n", prog_name);
    (void)printf("[manage command] register host to array\n");
    if (print_flag == DSS_HELP_SIMPLE) {
        return;
    }
    help_param_dsshome();
}

static status_t reghl_proc(void)
{
    char *home = cmd_reghl_args[DSS_ARG_IDX_0].input_args;
    status_t status = dss_reghl_core(home);
    if (status != CM_SUCCESS) {
        DSS_PRINT_ERROR("Failed to register.\n");
    } else {
        DSS_PRINT_INF("Succeed to register.\n");
    }
    return status;
}

static dss_args_t cmd_unreghl_args[] = {
    {'t', "type", CM_FALSE, CM_TRUE, NULL, NULL, NULL, 0, NULL, NULL, 0},
    {'D', "DSS_HOME", CM_FALSE, CM_TRUE, cmd_check_dss_home, cmd_check_convert_dss_home, cmd_clean_check_convert, 0,
        NULL, NULL, 0},
};
static dss_args_set_t cmd_unreghl_args_set = {
    cmd_unreghl_args,
    sizeof(cmd_unreghl_args) / sizeof(dss_args_t),
    NULL,
};

static void unreghl_help(const char *prog_name, int print_flag)
{
    (void)printf("\nUsage:%s unreghl [-t type] [-D DSS_HOME]\n", prog_name);
    (void)printf("[manage command] unregister host from array\n");
    if (print_flag == DSS_HELP_SIMPLE) {
        return;
    }
    (void)printf("-t/--type <type>, [optional], value is int, 0 without lock, otherwise with lock\n");
    help_param_dsshome();
}

static status_t unreghl_proc(void)
{
    int32 type = 1;
    status_t status;
    if (cmd_unreghl_args[DSS_ARG_IDX_0].input_args != NULL) {
        status = cm_str2int(cmd_unreghl_args[DSS_ARG_IDX_0].input_args, &type);
        if (status != CM_SUCCESS) {
            DSS_PRINT_ERROR("The value of type is invalid.\n");
            return CM_ERROR;
        }
    }

    char *home = cmd_unreghl_args[DSS_ARG_IDX_1].input_args;
    status = dss_unreghl_core(home, (type == 0) ? CM_FALSE : CM_TRUE);
    if (status != CM_SUCCESS) {
        DSS_PRINT_ERROR("Failed to unregister.\n");
    } else {
        DSS_PRINT_INF("Succeed to unregister.\n");
    }
    return status;
}

static dss_args_t cmd_auid_args[] = {
    {'a', "auid", CM_TRUE, CM_TRUE, cmd_check_disk_id, NULL, NULL, 0, NULL, NULL, 0},
};
static dss_args_set_t cmd_auid_args_set = {
    cmd_auid_args,
    sizeof(cmd_auid_args) / sizeof(dss_args_t),
    NULL,
};

static void auid_help(const char *prog_name, int print_flag)
{
    (void)printf("\nUsage:%s auid <-a auid>\n", prog_name);
    (void)printf("[tool command] show auid\n");
    if (print_flag == DSS_HELP_SIMPLE) {
        return;
    }
    (void)printf("-a/--auid <auid>, <required>, the auid will to show");
}

static status_t auid_proc(void)
{
    uint64 id = (uint64)atol(cmd_auid_args[DSS_ARG_IDX_0].input_args);
    auid_t *auid = (auid_t *)&id;
    (void)printf("id:%llu:\n", id);
    (void)printf("  volumeid:%llu\n", (uint64)auid->volume);
    (void)printf("  auid:%llu\n", (uint64)auid->au);
    (void)printf("  blockid:%llu\n", (uint64)auid->block);
    (void)printf("  item:%llu\n", (uint64)auid->item);
    return CM_SUCCESS;
}

#define DSS_CMD_PRINT_BLOCK_SIZE SIZE_K(4)
#define DSS_PRINT_RETURN_BYTES 16
#define DSS_PRINT_FMT_NUM 6

static dss_args_t cmd_examine_args[] = {
    {'p', "path", CM_TRUE, CM_TRUE, dss_check_device_path, NULL, NULL, 0, NULL, NULL, 0},
    {'o', "offset", CM_TRUE, CM_TRUE, cmd_check_offset, NULL, NULL, 0, NULL, NULL, 0},
    {'f', "format", CM_TRUE, CM_TRUE, cmd_check_format, NULL, NULL, 0, NULL, NULL, 0},
    {'s', "read_size", CM_FALSE, CM_TRUE, cmd_check_read_size, NULL, NULL, 0, NULL, NULL, 0},
    {'D', "DSS_HOME", CM_FALSE, CM_TRUE, cmd_check_dss_home, cmd_check_convert_dss_home, cmd_clean_check_convert, 0,
        NULL, NULL, 0},
    {'U', "UDS", CM_FALSE, CM_TRUE, cmd_check_uds, cmd_check_convert_uds_home, cmd_clean_check_convert, 0, NULL, NULL,
        0},
};
static dss_args_set_t cmd_examine_args_set = {
    cmd_examine_args,
    sizeof(cmd_examine_args) / sizeof(dss_args_t),
    NULL,
};

static void examine_help(const char *prog_name, int print_flag)
{
    (void)printf("\nUsage:%s examine <-p path> <-o offset> <-f format> [-s read_size] [-D DSS_HOME] "
                 "[-U UDS:socket_domain]\n",
        prog_name);
    (void)printf("[client command] display dss file content\n");
    if (print_flag == DSS_HELP_SIMPLE) {
        return;
    }
    (void)printf("-p/--path <path>, <required>, device path, must begin with '+'\n");
    (void)printf("-o/--offset <offset>, <required>, the offset of the file need to examine\n");
    (void)printf("-f/--format <format>, <required>, value is[c|h|u|l|s|x]\n"
                 "c char, h unsigned short, u unsigned int, l unsigned long, s string, x hex.\n");
    (void)printf("-s/--read_size <DSS_HOME>, [optional], size to show, default value is 512byte\n");
    help_param_dsshome();
    help_param_uds();
}

static inline char escape_char(char c)
{
    if (c > 0x1f && c < 0x7f) {
        return c;
    } else {
        return '.';
    }
}

static status_t print_buf(const char *o_buf, uint32 buf_size, char format, int64 offset, uint32 read_size)
{
    uint32 pos = 0;
    int16 index = -1;
    dss_print_help_t print_help[] = {{'c', sizeof(char)}, {'h', sizeof(uint16)}, {'u', sizeof(uint32)},
        {'l', sizeof(uint64)}, {'s', sizeof(char)}, {'x', sizeof(uint8)}};

    for (int16 i = 0; i < DSS_PRINT_FMT_NUM; i++) {
        if (format == print_help[i].fmt) {
            index = i;
            break;
        }
    }
    if (index == -1) {
        LOG_DEBUG_ERR("Invalid format.\n");
        return CM_ERROR;
    }

    while ((pos + print_help[index].bytes) <= read_size) {
        if (pos % DSS_PRINT_RETURN_BYTES == 0) {
            (void)printf("%016llx ", (uint64)offset + pos);
        }

        if (format == 'x') {
            (void)printf("%02x", *(uint8 *)(o_buf + pos));
        } else if (format == 'c') {
            (void)printf("%c", escape_char(*(o_buf + pos)));
        } else if (format == 'h') {
            (void)printf("%5hu", *(uint16 *)(o_buf + pos));
        } else if (format == 'u') {
            (void)printf("%10u", *(uint32 *)(o_buf + pos));
        } else if (format == 'l') {
            (void)printf("%20llu", *(uint64 *)(o_buf + pos));
        } else if (format == 's') {
            (void)printf("%c", escape_char(*(o_buf + pos)));
        }

        pos += print_help[index].bytes;

        if (pos % DSS_PRINT_RETURN_BYTES == 0) {
            (void)printf("\n");
        } else {
            if (format != 's') {
                (void)printf(" ");
            }
        }
    }
    if ((read_size / print_help[index].bytes) % (DSS_PRINT_RETURN_BYTES / print_help[index].bytes) != 0) {
        (void)printf("\n");
    }

    return CM_SUCCESS;
}

static status_t get_examine_parameter(char **path, int64 *offset, char *fmt)
{
    *path = cmd_examine_args[DSS_ARG_IDX_0].input_args;
    status_t status = cm_str2bigint(cmd_examine_args[DSS_ARG_IDX_1].input_args, offset);
    if (status != CM_SUCCESS) {
        LOG_DEBUG_ERR("Invalid offset.\n");
        return CM_ERROR;
    }
    *fmt = cmd_examine_args[DSS_ARG_IDX_2].input_args[0];
    return CM_SUCCESS;
}

static status_t get_examine_opt_parameter(char *server_locator, char **home, int32 *read_size)
{
    *read_size = DSS_DISK_UNIT_SIZE;
    if (cmd_examine_args[DSS_ARG_IDX_3].input_args != NULL) {
        *read_size = (int32)strtol(cmd_examine_args[DSS_ARG_IDX_3].input_args, NULL, CM_DEFAULT_DIGIT_RADIX);
    }
    if (*read_size <= 0) {
        LOG_DEBUG_ERR("Invalid read_size.\n");
        return CM_ERROR;
    }
    *home = cmd_examine_args[DSS_ARG_IDX_4].input_args;
    status_t status = get_server_locator(cmd_examine_args[DSS_ARG_IDX_5].input_args, server_locator);
    if (status != CM_SUCCESS) {
        DSS_PRINT_ERROR("Failed to get server_locator.\n");
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static status_t set_config_info(char *home)
{
    status_t status;
    dss_config_t inst_cfg;
    status = dss_set_cfg_dir(home, &inst_cfg);
    if (status != CM_SUCCESS) {
        LOG_DEBUG_ERR("Environment variant DSS_HOME not found!\n");
        return status;
    }

    status = dss_load_config(&inst_cfg);
    if (status != CM_SUCCESS) {
        LOG_DEBUG_ERR("Failed to load parameters!\n");
        return status;
    }

    status = dss_load_vg_conf_info(&g_vgs_info, &inst_cfg);
    if (status != CM_SUCCESS) {
        LOG_DEBUG_ERR("Failed to load vg info from config, errcode is %d.\n", status);
        return status;
    }
    return CM_SUCCESS;
}

static status_t print_file_proc(dss_conn_t *conn, int32 handle, int64 offset, int32 read_size, char fmt)
{
#ifndef WIN32
    char o_buf[DSS_CMD_PRINT_BLOCK_SIZE] __attribute__((__aligned__(DSS_DISK_UNIT_SIZE)));
#else
    char o_buf[DSS_CMD_PRINT_BLOCK_SIZE];
#endif
    int32 read_cnt = 0;
    int32 cur_read_size;
    int64 row_aligned_offset = (offset / DSS_PRINT_RETURN_BYTES) * DSS_PRINT_RETURN_BYTES;
    int64 print_offset = row_aligned_offset - (offset / DSS_DISK_UNIT_SIZE) * DSS_DISK_UNIT_SIZE;
    int64 offset_shift = offset - row_aligned_offset;

    while (read_cnt < read_size) {
        CM_RETURN_IFERR_EX(dss_read_file_impl(conn, handle, o_buf, sizeof(o_buf), &cur_read_size),
            LOG_DEBUG_ERR("Failed to read file.\n"));

        if (cur_read_size > read_size - read_cnt) {
            cur_read_size = read_size - read_cnt;
        }
        char *buf = o_buf + print_offset;
        uint32 buf_size = (uint32)(sizeof(o_buf) - print_offset);

        CM_RETURN_IFERR_EX(print_buf(buf, buf_size, fmt, offset - offset_shift, (uint32)(cur_read_size - print_offset)),
            LOG_DEBUG_ERR("Failed to print.\n"));

        read_cnt += cur_read_size;
        offset += (cur_read_size - print_offset) - offset_shift;
        print_offset = 0;
        offset_shift = 0;
    }
    return CM_SUCCESS;
}

static int64 adjust_readsize(int64 offset, int32 *read_size, int64 file_size)
{
    int64 unit_aligned_offset = (offset / DSS_DISK_UNIT_SIZE) * DSS_DISK_UNIT_SIZE;
    int64 new_read_size = *read_size;

    if (unit_aligned_offset != offset) {
        new_read_size += (offset - unit_aligned_offset);
    }

    if (new_read_size + unit_aligned_offset > file_size) {
        if (file_size < unit_aligned_offset) {
            new_read_size = 0;
        } else {
            new_read_size = file_size - unit_aligned_offset;
        }
    }

    if (new_read_size < 0) {
        new_read_size = 0;
    }

    if (new_read_size > INT32_MAX) {
        new_read_size = INT32_MAX;
    }

    *read_size = (int32)new_read_size;
    return unit_aligned_offset;
}

static status_t examine_proc(void)
{
    char *path;
    int64 offset;
    char format;
    int32 read_size = DSS_DISK_UNIT_SIZE;
    char *home = NULL;
    char server_locator[DSS_MAX_PATH_BUFFER_SIZE] = {0};
    dss_conn_t connection;

    status_t status = get_examine_parameter(&path, &offset, &format);
    if (status != CM_SUCCESS) {
        return status;
    }
    status = get_examine_opt_parameter(server_locator, &home, &read_size);
    if (status != CM_SUCCESS) {
        return status;
    }
    status = set_config_info(home);
    if (status != CM_SUCCESS) {
        DSS_PRINT_ERROR("Failed to load config info!\n");
        return status;
    }
    status = dss_uds_get_connection(server_locator, &connection);
    if (status != CM_SUCCESS) {
        DSS_PRINT_ERROR("Failed to get uds connection.\n");
        return status;
    }
    int32 handle;
    status = dss_open_file_impl(&connection, path, O_RDWR, &handle);
    if (status != CM_SUCCESS) {
        DSS_PRINT_ERROR("Failed to open dir, path is %s.\n", path);
        dss_disconnect_ex(&connection);
        return CM_ERROR;
    }

    int64 file_size = dss_seek_file_impl(&connection, handle, 0, SEEK_END);
    if (file_size == CM_INVALID_INT64) {
        DSS_PRINT_ERROR("Failed to seek file %s size.\n", path);
        (void)dss_close_file_impl(&connection, handle);
        dss_disconnect_ex(&connection);
        return CM_ERROR;
    }
    int64 unit_aligned_offset = adjust_readsize(offset, &read_size, file_size);

    unit_aligned_offset = dss_seek_file_impl(&connection, handle, unit_aligned_offset, SEEK_SET);
    if (unit_aligned_offset == -1) {
        DSS_PRINT_ERROR("Failed to seek file %s.\n", path);
        (void)dss_close_file_impl(&connection, handle);
        dss_disconnect_ex(&connection);
        return CM_ERROR;
    }
    (void)printf("filename is %s, offset is %lld.\n", path, offset);
    status = print_file_proc(&connection, handle, offset, read_size, format);
    if (status != CM_SUCCESS) {
        DSS_PRINT_ERROR("Failed to print file %s.\n", path);
    }
    (void)dss_close_file_impl(&connection, handle);
    dss_disconnect_ex(&connection);

    return status;
}

static dss_args_t cmd_dev_args[] = {
    {'p', "path", CM_TRUE, CM_TRUE, dss_check_volume_path, NULL, NULL, 0, NULL, NULL, 0},
    {'o', "offset", CM_TRUE, CM_TRUE, cmd_check_offset, NULL, NULL, 0, NULL, NULL, 0},
    {'f', "format", CM_TRUE, CM_TRUE, cmd_check_format, NULL, NULL, 0, NULL, NULL, 0},
};
static dss_args_set_t cmd_dev_args_set = {
    cmd_dev_args,
    sizeof(cmd_dev_args) / sizeof(dss_args_t),
    NULL,
};

static void dev_help(const char *prog_name, int print_flag)
{
    (void)printf("\nUsage:%s dev <-p path> <-o offset> <-f format> \n", prog_name);
    (void)printf("[client command] display dev file content\n");
    if (print_flag == DSS_HELP_SIMPLE) {
        return;
    }
    (void)printf("-p/--path <path>, <required>, the path of the host need to display\n");
    (void)printf("-o/--offset <offset>, <required>, the offset of the dev need to display\n");
    (void)printf("-f/--format <format>, <required>, value is[c|h|u|l|s|x]"
                 "c char, h unsigned short, u unsigned int, l unsigned long, s string, x hex.\n");
}

static status_t dev_proc(void)
{
    status_t status;
    const char *path = cmd_dev_args[DSS_ARG_IDX_0].input_args;
    dss_volume_t volume;
    status = dss_open_volume(path, NULL, DSS_INSTANCE_OPEN_FLAG, &volume);
    if (status != CM_SUCCESS) {
        DSS_PRINT_ERROR("Failed to open file %s.\n", path);
        return status;
    }

#ifndef WIN32
    char o_buf[DSS_CMD_PRINT_BLOCK_SIZE] __attribute__((__aligned__(DSS_DISK_UNIT_SIZE)));
#else
    char o_buf[DSS_CMD_PRINT_BLOCK_SIZE];
#endif

    int64 offset = 0;
    status = cm_str2bigint(cmd_dev_args[DSS_ARG_IDX_1].input_args, &offset);
    if (status != CM_SUCCESS) {
        dss_close_volume(&volume);
        DSS_PRINT_ERROR("The value of offset is invalid");
        return CM_ERROR;
    }

    (void)printf("filename is %s, offset is %lld.\n", path, offset);
    status = dss_read_volume(&volume, offset, o_buf, (int32)DSS_CMD_PRINT_BLOCK_SIZE);
    if (status != CM_SUCCESS) {
        dss_close_volume(&volume);
        DSS_PRINT_ERROR("Failed to read file %s.\n", path);
        return status;
    }
    dss_close_volume(&volume);
    char format = cmd_dev_args[DSS_ARG_IDX_2].input_args[0];
    status = print_buf(o_buf, DSS_CMD_PRINT_BLOCK_SIZE, format, offset, DSS_CMD_PRINT_BLOCK_SIZE);
    if (status != CM_SUCCESS) {
        DSS_PRINT_ERROR("Failed to print file %s.\n", path);
        return status;
    }
    return CM_SUCCESS;
}

static dss_args_t cmd_showdisk_args[] = {
    {'g', "vg_name", CM_TRUE, CM_TRUE, dss_check_name, NULL, NULL, 0, NULL, NULL, 0},
    {'s', "struct_name", CM_TRUE, CM_TRUE, cmd_check_struct_name, NULL, NULL, 0, NULL, NULL, 0},
    {'b', "block_id", CM_TRUE, CM_TRUE, cmd_check_disk_id, NULL, NULL, 0, NULL, NULL, 0},
    {'n', "node_id", CM_TRUE, CM_TRUE, cmd_check_inst_id, NULL, NULL, 0, NULL, NULL, 0},
    {'D', "DSS_HOME", CM_FALSE, CM_TRUE, cmd_check_dss_home, cmd_check_convert_dss_home, cmd_clean_check_convert, 0,
        NULL, NULL, 0},
};

static status_t showdisk_check_args(dss_args_t *cmd_args_set, int set_size)
{
    if (cmd_args_set == NULL || set_size <= 0) {
        DSS_PRINT_ERROR("args error.\n");
        return CM_ERROR;
    }
    if (!cmd_args_set[DSS_ARG_IDX_0].inputed) {
        DSS_PRINT_ERROR("should set the vg name to show.\n");
        return CM_ERROR;
    }
    if (!cmd_args_set[DSS_ARG_IDX_1].inputed && !cmd_args_set[DSS_ARG_IDX_2].inputed) {
        DSS_PRINT_ERROR("should at least set one way [struct_name | block_id] to show.\n");
        return CM_ERROR;
    }
    if (cmd_args_set[DSS_ARG_IDX_1].inputed && cmd_args_set[DSS_ARG_IDX_2].inputed) {
        DSS_PRINT_ERROR("should only set one way [struct_name | block_id] to show.\n");
        return CM_ERROR;
    }
    if (cmd_args_set[DSS_ARG_IDX_2].inputed && !cmd_args_set[DSS_ARG_IDX_3].inputed) {
        DSS_PRINT_ERROR("should set the block_id with node_id.\n");
        return CM_ERROR;
    }
    if (!cmd_args_set[DSS_ARG_IDX_2].inputed && cmd_args_set[DSS_ARG_IDX_3].inputed) {
        DSS_PRINT_ERROR("should not set the node_id without block_id.\n");
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static dss_args_set_t cmd_showdisk_args_set = {
    cmd_showdisk_args,
    sizeof(cmd_showdisk_args) / sizeof(dss_args_t),
    showdisk_check_args,
};

static void showdisk_help(const char *prog_name, int print_flag)
{
    (void)printf("\nUsage:%s showdisk <-g vg_name> <-s struct_name> [-D DSS_HOME]\n", prog_name);
    (void)printf("      %s showdisk <-g vg_name> <-b block_id> <-n node_id> [-D DSS_HOME]\n", prog_name);
    (void)printf("[client command] show disk information\n");
    if (print_flag == DSS_HELP_SIMPLE) {
        return;
    }
    (void)printf("-g/--vg_name <vg_name>, <required>, the volume group name\n");
    (void)printf("-s/--struct_name <struct_name>, <required>, the struct name of volume group, "
                 "the optional value(s):\n");
    (void)printf("    [core_ctrl | vg_header | volume_ctrl | root_ft_block]\n");
    (void)printf("-b/--block_id <block_id>, <required>, block id\n");
    (void)printf("-n/--node_id <node_id>, <required>, node id\n");
    help_param_dsshome();
}

static status_t showdisk_get_vg_item(dss_vg_info_item_t **vg_item, const char *vg_name)
{
    dss_vg_info_item_t *tmp_vg_item = dss_find_vg_item(vg_name);
    if (tmp_vg_item == NULL) {
        LOG_DEBUG_ERR("vg_name %s is not exist.\n", vg_name);
        return CM_ERROR;
    }
    *vg_item = tmp_vg_item;
    return CM_SUCCESS;
}

static status_t showdisk_struct_name_print(dss_vg_info_item_t *vg_item, const char *struct_name)
{
    status_t status;
    status = dss_read_meta_from_disk(vg_item, struct_name);
    if (status != CM_SUCCESS) {
        DSS_PRINT_ERROR("Failed to printf dss metadata.\n");
        return CM_ERROR;
    }
    DSS_PRINT_INF("Succeed to printf dss metadata.\n");
    return status;
}

static status_t showdisk_block_id_print(dss_vg_info_item_t *vg_item, uint64 block_id, uint64 node_id)
{
    status_t status = printf_dss_block_with_blockid(vg_item, block_id, node_id);
    if (status != CM_SUCCESS) {
        DSS_PRINT_ERROR("Failed to printf dss file block with block_id:%llu.\n", block_id);
        return CM_ERROR;
    }
    DSS_PRINT_INF("Succeed to printf dss file block with block_id:%llu.\n", block_id);
    return status;
}

static status_t showdisk_proc(void)
{
    const char *vg_name = cmd_showdisk_args[DSS_ARG_IDX_0].input_args;
    char *home = cmd_showdisk_args[DSS_ARG_IDX_4].input_args;
    status_t status;
    dss_vg_info_item_t *vg_item = NULL;
    status = set_config_info(home);
    if (status != CM_SUCCESS) {
        DSS_PRINT_ERROR("Failed to load config info!\n");
        return status;
    }

    status = showdisk_get_vg_item(&vg_item, vg_name);
    if (status != CM_SUCCESS) {
        DSS_PRINT_ERROR("Failed to get vg %s.\n", vg_name);
        return status;
    }
    if (cmd_showdisk_args[DSS_ARG_IDX_2].inputed) {
        // for block_id
        uint64 block_id = (uint64)atol(cmd_showdisk_args[DSS_ARG_IDX_2].input_args);
        uint64 node_id = (uint64)atol(cmd_showdisk_args[DSS_ARG_IDX_3].input_args);
        status = showdisk_block_id_print(vg_item, block_id, node_id);
    } else if (cmd_showdisk_args[DSS_ARG_IDX_1].inputed) {
        // for struct_name
        status = showdisk_struct_name_print(vg_item, cmd_showdisk_args[DSS_ARG_IDX_1].input_args);
    } else {
        DSS_PRINT_ERROR("none of struct_name and block_id.\n");
        return CM_ERROR;
    }

    return status;
}

static dss_args_t cmd_rename_args[] = {
    {'o', "old_name", CM_TRUE, CM_TRUE, dss_check_device_path, NULL, NULL, 0, NULL, NULL, 0},
    {'n', "new_name", CM_TRUE, CM_TRUE, dss_check_device_path, NULL, NULL, 0, NULL, NULL, 0},
    {'U', "UDS", CM_FALSE, CM_TRUE, cmd_check_uds, cmd_check_convert_uds_home, cmd_clean_check_convert, 0, NULL, NULL,
        0},
};
static dss_args_set_t cmd_rename_args_set = {
    cmd_rename_args,
    sizeof(cmd_rename_args) / sizeof(dss_args_t),
    NULL,
};

static void rename_help(const char *prog_name, int print_flag)
{
    (void)printf("\nUsage:%s rename <-o old_name> <-n new_name> [-U UDS:socket_domain]\n", prog_name);
    (void)printf("[client command] rename file, all file name must begin with '+'\n");
    if (print_flag == DSS_HELP_SIMPLE) {
        return;
    }
    (void)printf("-o/--old_name <old_name>, <required>, the old file name\n");
    (void)printf("-n/--new_name <new_name>, <required>, the new file name\n");
    help_param_uds();
}

static status_t rename_proc(void)
{
    const char *old_name = cmd_rename_args[DSS_ARG_IDX_0].input_args;
    const char *new_name = cmd_rename_args[DSS_ARG_IDX_1].input_args;
    dss_conn_t connection;
    status_t status = get_connection_by_input_args(cmd_rename_args[DSS_ARG_IDX_2].input_args, &connection);
    if (status != CM_SUCCESS) {
        return status;
    }

    status = dss_rename_file_impl(&connection, old_name, new_name);
    if (status != CM_SUCCESS) {
        DSS_PRINT_ERROR("Failed to rename file, old name is %s, new name is %s.\n", old_name, new_name);
    } else {
        DSS_PRINT_INF("Succeed to rename file, old name is %s, new name is %s.\n", old_name, new_name);
    }
    dss_disconnect_ex(&connection);
    return status;
}

static dss_args_t cmd_du_args[] = {
    {'p', "path", CM_TRUE, CM_TRUE, dss_check_device_path, NULL, NULL, 0, NULL, NULL, 0},
    {'f', "format", CM_FALSE, CM_TRUE, cmd_check_du_format, NULL, NULL, 0, NULL, NULL, 0},
    {'U', "UDS", CM_FALSE, CM_TRUE, cmd_check_uds, cmd_check_convert_uds_home, cmd_clean_check_convert, 0, NULL, NULL,
        0},
};
static dss_args_set_t cmd_du_args_set = {
    cmd_du_args,
    sizeof(cmd_du_args) / sizeof(dss_args_t),
    NULL,
};

static void du_help(const char *prog_name, int print_flag)
{
    (void)printf("\nUsage:%s du <-p path> [-f format] [-U UDS:socket_domain]\n", prog_name);
    (void)printf("[client command] show disk usage of the file/dir with optional params\n");
    if (print_flag == DSS_HELP_SIMPLE) {
        return;
    }
    (void)printf("-p/--path <path>, <required>, the old file name\n");
    (void)printf("-f/--format [format], [optional], the format to show, default value is Bs\n");
    (void)printf("support 3 types of format, do not need any separators between params\n");
    (void)printf("        [BKMGT] B: Byte, K: kB ,M: MB , G: GB, T: TB\n");
    (void)printf("        [sa] s: summarize, a: count all files, not just directories\n");
    (void)printf("        [S] S: for directories do not include size of subdirectories\n");
    help_param_uds();
}

static status_t du_proc(void)
{
    const char *path = cmd_du_args[DSS_ARG_IDX_0].input_args;
    const char *input_param = cmd_du_args[DSS_ARG_IDX_1].input_args;
    dss_conn_t connection;

    char path_buf[DSS_FILE_PATH_MAX_LENGTH];
    errno_t errcode = strcpy_s(path_buf, sizeof(path_buf), path);
    if (errcode != EOK) {
        DSS_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
        DSS_PRINT_ERROR("Failed to strcpy.\n");
        return CM_ERROR;
    }

    char params[DSS_DU_PARAM_LEN] = {0};
    status_t status = du_get_params(input_param, params, sizeof(params));
    if (status != CM_SUCCESS) {
        return status;
    }

    status = get_connection_by_input_args(cmd_du_args[DSS_ARG_IDX_2].input_args, &connection);
    if (status != CM_SUCCESS) {
        return status;
    }

    status = du_traverse_path(path_buf, sizeof(path_buf), &connection, params, sizeof(params));
    if (status != CM_SUCCESS) {
        DSS_PRINT_ERROR("Failed to traverse path %s.\n", path_buf);
    }
    dss_disconnect_ex(&connection);
    return status;
}

static dss_args_t cmd_find_args[] = {
    {'p', "path", CM_TRUE, CM_TRUE, dss_check_device_path, NULL, NULL, 0, NULL, NULL, 0},
    {'n', "name", CM_TRUE, CM_TRUE, dss_check_name, NULL, NULL, 0, NULL, NULL, 0},
    {'U', "UDS", CM_FALSE, CM_TRUE, cmd_check_uds, cmd_check_convert_uds_home, cmd_clean_check_convert, 0, NULL, NULL,
        0},
};
static dss_args_set_t cmd_find_args_set = {
    cmd_find_args,
    sizeof(cmd_find_args) / sizeof(dss_args_t),
    NULL,
};

static void find_help(const char *prog_name, int print_flag)
{
    (void)printf("\nUsage:%s find <-p path> <-n name> [-U UDS:socket_domain]\n", prog_name);
    (void)printf("[client command]find files by name from path recursively\n");
    if (print_flag == DSS_HELP_SIMPLE) {
        return;
    }
    (void)printf("-p/--path <path>, <required>, the path to find from\n");
    (void)printf("-n/--name <name>, <required>, the name to find, support unix style wildcards "
                 "(man 7 glob for detail)\n");
    help_param_uds();
}

static status_t find_proc(void)
{
    char *path = cmd_find_args[DSS_ARG_IDX_0].input_args;
    char *name = cmd_find_args[DSS_ARG_IDX_1].input_args;
    char server_locator[DSS_MAX_PATH_BUFFER_SIZE] = {0};
    status_t status = get_server_locator(cmd_find_args[DSS_ARG_IDX_2].input_args, server_locator);
    if (status != CM_SUCCESS) {
        DSS_PRINT_ERROR("Failed to get server_locator.\n");
        return CM_ERROR;
    }

    char path_buf[DSS_FILE_PATH_MAX_LENGTH];
    char name_buf[DSS_FILE_NAME_BUFFER_SIZE];

    errno_t errcode = strcpy_s(path_buf, sizeof(path_buf), path);
    if (errcode != EOK) {
        DSS_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
        DSS_PRINT_ERROR("Failed to strcpy.\n");
        return CM_ERROR;
    }

    errcode = strcpy_s(name_buf, sizeof(name_buf), name);
    if (errcode != EOK) {
        DSS_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
        DSS_PRINT_ERROR("Failed to strcpy.\n");
        return CM_ERROR;
    }

    dss_conn_t connection;
    status = dss_uds_get_connection(server_locator, &connection);
    if (status != CM_SUCCESS) {
        DSS_PRINT_ERROR("Failed to get uds connection.\n");
        return status;
    }

    status = find_traverse_path(&connection, path_buf, sizeof(path_buf), name_buf, sizeof(name_buf));
    if (status != CM_SUCCESS) {
        DSS_PRINT_ERROR("Failed to find traverse path %s.\n", path_buf);
    }
    dss_disconnect_ex(&connection);
    return status;
}

static dss_args_t cmd_ln_args[] = {
    {'s', "src_path", CM_TRUE, CM_TRUE, dss_check_device_path, NULL, NULL, 0, NULL, NULL, 0},
    {'t', "target_path", CM_TRUE, CM_TRUE, dss_check_device_path, NULL, NULL, 0, NULL, NULL, 0},
    {'U', "UDS", CM_FALSE, CM_TRUE, cmd_check_uds, cmd_check_convert_uds_home, cmd_clean_check_convert, 0, NULL, NULL,
        0},
};
static dss_args_set_t cmd_ln_args_set = {
    cmd_ln_args,
    sizeof(cmd_ln_args) / sizeof(dss_args_t),
    NULL,
};

static void ln_help(const char *prog_name, int print_flag)
{
    (void)printf("\nUsage:%s ln <-s src_path> <-t target_path> [-U UDS:socket_domain]\n", prog_name);
    (void)printf("[client command]make links between files\n");
    if (print_flag == DSS_HELP_SIMPLE) {
        return;
    }
    (void)printf("-s/--src_path <src_path>, <required>, the source path to link\n");
    (void)printf("-t/--target_path <target_path>, <required>, the target path to link\n");
    help_param_uds();
}

static status_t ln_proc(void)
{
    char *oldpath = cmd_ln_args[DSS_ARG_IDX_0].input_args;
    char *newpath = cmd_ln_args[DSS_ARG_IDX_1].input_args;
    dss_conn_t connection;
    status_t status = get_connection_by_input_args(cmd_ln_args[DSS_ARG_IDX_2].input_args, &connection);
    if (status != CM_SUCCESS) {
        return status;
    }

    status = dss_symlink_impl(&connection, oldpath, newpath);
    if (status == CM_SUCCESS) {
        DSS_PRINT_INF("Success to link %s to %s.\n", newpath, oldpath);
    } else {
        DSS_PRINT_ERROR("Failed to link %s to %s.\n", newpath, oldpath);
    }
    dss_disconnect_ex(&connection);
    return status;
}

static dss_args_t cmd_readlink_args[] = {
    {'p', "path", CM_TRUE, CM_TRUE, dss_check_device_path, NULL, NULL, 0, NULL, NULL, 0},
    {'U', "UDS", CM_FALSE, CM_TRUE, cmd_check_uds, cmd_check_convert_uds_home, cmd_clean_check_convert, 0, NULL, NULL,
        0},
};
static dss_args_set_t cmd_readlink_args_set = {
    cmd_readlink_args,
    sizeof(cmd_readlink_args) / sizeof(dss_args_t),
    NULL,
};

static void readlink_help(const char *prog_name, int print_flag)
{
    (void)printf("\nUsage:%s readlink <-p path> [-U UDS:socket_domain]\n", prog_name);
    (void)printf("[client command]read link path\n");
    if (print_flag == DSS_HELP_SIMPLE) {
        return;
    }
    (void)printf("-p/--path <path>, <required>, the link path to read\n");
    help_param_uds();
}

static status_t readlink_proc(void)
{
    char *link_path = cmd_readlink_args[DSS_ARG_IDX_0].input_args;
    dss_conn_t connection;
    status_t status = get_connection_by_input_args(cmd_readlink_args[DSS_ARG_IDX_1].input_args, &connection);
    if (status != CM_SUCCESS) {
        return status;
    }

    bool32 is_link = false;
    status = dss_islink_impl(&connection, link_path, &is_link);
    if (status != CM_SUCCESS) {
        DSS_PRINT_ERROR("Failed to confirm that the path %s is a soft link.\n", link_path);
        dss_disconnect_ex(&connection);
        return CM_ERROR;
    }
    if (status == CM_SUCCESS && !is_link) {
        DSS_PRINT_ERROR("The path %s does not exist or is not a soft link.\n", link_path);
        dss_disconnect_ex(&connection);
        return CM_ERROR;
    }

    char path_convert[DSS_FILE_PATH_MAX_LENGTH] = {0};
    status = dss_readlink_impl(&connection, link_path, (char *)path_convert, sizeof(path_convert));
    if (status == CM_SUCCESS) {
        DSS_PRINT_INF("link: %s link to: %s.\n", link_path, path_convert);
    } else {
        DSS_PRINT_ERROR("Failed to read link %s.\n", link_path);
    }

    dss_disconnect_ex(&connection);
    return status;
}

static dss_args_t cmd_unlink_args[] = {
    {'p', "path", CM_TRUE, CM_TRUE, dss_check_device_path, NULL, NULL, 0, NULL, NULL, 0},
    {'U', "UDS", CM_FALSE, CM_TRUE, cmd_check_uds, cmd_check_convert_uds_home, cmd_clean_check_convert, 0, NULL, NULL,
        0},
};
static dss_args_set_t cmd_unlink_args_set = {
    cmd_unlink_args,
    sizeof(cmd_unlink_args) / sizeof(dss_args_t),
    NULL,
};

static void unlink_help(const char *prog_name, int print_flag)
{
    (void)printf("\nUsage:%s unlink <-p path> [-U UDS:socket_domain]\n", prog_name);
    (void)printf("[client command] unlink path\n");
    if (print_flag == DSS_HELP_SIMPLE) {
        return;
    }
    (void)printf("-p/--path <path>, <required>, the link path to unlink\n");
    help_param_uds();
}

static status_t unlink_proc(void)
{
    char *link = cmd_unlink_args[DSS_ARG_IDX_0].input_args;
    dss_conn_t connection;
    status_t status = get_connection_by_input_args(cmd_unlink_args[DSS_ARG_IDX_1].input_args, &connection);
    if (status != CM_SUCCESS) {
        return status;
    }

    status = dss_unlink_impl(&connection, link);
    if (status != CM_SUCCESS) {
        DSS_PRINT_ERROR("Failed to unlink %s.\n", link);
    } else {
        DSS_PRINT_INF("Succeed to unlink %s.\n", link);
    }
    dss_disconnect_ex(&connection);
    return status;
}

static dss_args_set_t cmd_encrypt_args_set = {
    NULL,
    0,
    NULL,
};

static void encrypt_help(const char *prog_name, int print_flag)
{
    (void)printf("\nUsage:%s encrypt\n", prog_name);
    (void)printf("[client command] password encrypt\n");
}

static status_t dss_save_random_file(const uchar *value, int32 value_len)
{
    char file_name[CM_FILE_NAME_BUFFER_SIZE];
    char dir_name[CM_FILE_NAME_BUFFER_SIZE];
    int32 handle;
    PRTS_RETURN_IFERR(snprintf_s(
        dir_name, CM_FILE_NAME_BUFFER_SIZE, CM_FILE_NAME_BUFFER_SIZE - 1, "%s/dss_protect", g_inst_cfg->home));
    PRTS_RETURN_IFERR(snprintf_s(file_name, CM_FILE_NAME_BUFFER_SIZE, CM_FILE_NAME_BUFFER_SIZE - 1, "%s/dss_protect/%s",
        g_inst_cfg->home, DSS_FKEY_FILENAME));
    if (!cm_dir_exist(dir_name)) {
        DSS_RETURN_IF_ERROR(cm_create_dir(dir_name));
    }
    if (access(file_name, R_OK | F_OK) == 0) {
        (void)chmod(file_name, S_IRUSR | S_IWUSR);
        DSS_RETURN_IF_ERROR(cm_overwrite_file(file_name));
        DSS_RETURN_IF_ERROR(cm_remove_file(file_name));
    }
    DSS_RETURN_IF_ERROR(
        cm_open_file_ex(file_name, O_SYNC | O_CREAT | O_RDWR | O_TRUNC | O_BINARY, S_IRUSR | S_IWUSR, &handle));
    status_t ret = cm_write_file(handle, value, value_len);
    cm_close_file(handle);
    return ret;
}

static status_t encrypt_proc(void)
{
    status_t status;
    char plain[CM_PASSWD_MAX_LEN + 1] = {0};
    status = dss_catch_input_text(plain, CM_PASSWD_MAX_LEN + 1);
    if (status != CM_SUCCESS) {
        (void)(memset_s(plain, CM_PASSWD_MAX_LEN + 1, 0, CM_PASSWD_MAX_LEN + 1));
        DSS_PRINT_ERROR("Failed to encrypt password when catch input.\n");
        return CM_ERROR;
    }
    cipher_t cipher;
    status = cm_encrypt_pwd((uchar *)plain, (uint32)strlen(plain), &cipher);
    if (status != CM_SUCCESS) {
        (void)(memset_s(plain, CM_PASSWD_MAX_LEN + 1, 0, CM_PASSWD_MAX_LEN + 1));
        DSS_PRINT_ERROR("Failed to encrypt password.\n");
        return CM_ERROR;
    }
    (void)(memset_s(plain, CM_PASSWD_MAX_LEN + 1, 0, CM_PASSWD_MAX_LEN + 1));
    status = dss_save_random_file(cipher.rand, RANDOM_LEN + 1);
    if (status != CM_SUCCESS) {
        DSS_PRINT_ERROR("Failed to save random component");
        return CM_ERROR;
    }
    (void)(memset_s(cipher.rand, RANDOM_LEN + 1, 0, RANDOM_LEN + 1));
    char buf[CM_MAX_SSL_CIPHER_LEN] = {0};
    uint32_t buf_len = CM_MAX_SSL_CIPHER_LEN;
    status = cm_base64_encode((uchar *)&cipher, (uint32)sizeof(cipher_t), buf, &buf_len);
    if (status != CM_SUCCESS) {
        DSS_PRINT_ERROR("Failed to encrypt password when encode.\n");
        return CM_ERROR;
    }
    (void)printf("Cipher: \t\t%s\n", buf);
    return CM_SUCCESS;
}

static dss_args_t cmd_setcfg_args[] = {
    {'n', "name", CM_TRUE, CM_TRUE, cmd_check_cfg_name, NULL, NULL, 0, NULL, NULL, 0},
    {'v', "value", CM_TRUE, CM_TRUE, cmd_check_cfg_value, NULL, NULL, 0, NULL, NULL, 0},
    {'s', "scope", CM_FALSE, CM_TRUE, cmd_check_cfg_scope, NULL, NULL, 0, NULL, NULL, 0},
    {'U', "UDS", CM_FALSE, CM_TRUE, cmd_check_uds, cmd_check_convert_uds_home, cmd_clean_check_convert, 0, NULL, NULL,
        0},
};
static dss_args_set_t cmd_setcfg_args_set = {
    cmd_setcfg_args,
    sizeof(cmd_setcfg_args) / sizeof(dss_args_t),
    NULL,
};

static void setcfg_help(const char *prog_name, int print_flag)
{
    (void)printf("\nUsage:%s setcfg <-n name> <-v value> [-s scope] [-U UDS:socket_domain]\n", prog_name);
    (void)printf("[client command] set config value by name\n");
    if (print_flag == DSS_HELP_SIMPLE) {
        return;
    }
    (void)printf("-n/--name <name>, <required>, the config name to set\n");
    (void)printf("-v/--value <value>, <required>, the value of the config name to set\n");
    (void)printf("-s/--scope <scope>, [optional], the scope to save the config\n");
    (void)printf("scope optional values: [memory | pfile | both]. default value is both\n"
                 "Memory indicates that the modification is made in memory and takes effect immediately;\n"
                 "Pfile indicates that the modification is performed in the pfile. \n"
                 "The database must be restarted for the modification to take effect.\n");
    help_param_uds();
}

static status_t setcfg_proc(void)
{
    char *name = cmd_setcfg_args[DSS_ARG_IDX_0].input_args;
    if (cm_strcmpi(name, "_LOG_LEVEL") != 0 && cm_strcmpi(name, "_LOG_MAX_FILE_SIZE") != 0 &&
        cm_strcmpi(name, "_LOG_BACKUP_FILE_COUNT") != 0 && cm_strcmpi(name, "_AUDIT_MAX_FILE_SIZE") != 0 &&
        cm_strcmpi(name, "_AUDIT_BACKUP_FILE_COUNT") != 0 && cm_strcmpi(name, "_AUDIT_LEVEL") != 0) {
        DSS_PRINT_ERROR("Invalid name when set cfg.\n");
        return DSS_ERROR;
    }
    char *value = cmd_setcfg_args[DSS_ARG_IDX_1].input_args;
    char *scope =
        cmd_setcfg_args[DSS_ARG_IDX_2].input_args != NULL ? cmd_setcfg_args[DSS_ARG_IDX_2].input_args : "both";
    dss_conn_t connection;
    status_t status = get_connection_by_input_args(cmd_setcfg_args[DSS_ARG_IDX_3].input_args, &connection);
    if (status != CM_SUCCESS) {
        return status;
    }

    status = dss_setcfg_impl(&connection, name, value, scope);
    if (status != CM_SUCCESS) {
        DSS_PRINT_ERROR("Failed to set cfg, name is %s, value is %s.\n", name, value);
    } else {
        DSS_PRINT_INF("Succeed to set cfg, name is %s, value is %s.\n", name, value);
    }

    dss_disconnect_ex(&connection);
    return status;
}

static dss_args_t cmd_getcfg_args[] = {
    {'n', "name", CM_TRUE, CM_TRUE, cmd_check_cfg_name, NULL, NULL, 0, NULL, NULL, 0},
    {'U', "UDS", CM_FALSE, CM_TRUE, cmd_check_uds, cmd_check_convert_uds_home, cmd_clean_check_convert, 0, NULL, NULL,
        0},
};
static dss_args_set_t cmd_getcfg_args_set = {
    cmd_getcfg_args,
    sizeof(cmd_getcfg_args) / sizeof(dss_args_t),
    NULL,
};

static void getcfg_help(const char *prog_name, int print_flag)
{
    (void)printf("\nUsage:%s getcfg <-n name> [-U UDS:socket_domain]\n", prog_name);
    (void)printf("[client command] get config value by name\n");
    if (print_flag == DSS_HELP_SIMPLE) {
        return;
    }
    (void)printf("-n/--name <name>, <required>, the config name to set\n");
    help_param_uds();
}

static status_t getcfg_proc(void)
{
    char *name = cmd_getcfg_args[DSS_ARG_IDX_0].input_args;
    dss_conn_t connection;
    status_t status = get_connection_by_input_args(cmd_getcfg_args[DSS_ARG_IDX_1].input_args, &connection);
    if (status != CM_SUCCESS) {
        return status;
    }

    char value[DSS_PARAM_BUFFER_SIZE] = {0};
    status = dss_getcfg_impl(&connection, name, value, DSS_PARAM_BUFFER_SIZE);
    if (status != CM_SUCCESS) {
        DSS_PRINT_ERROR("Failed to get cfg, name is %s, value is %s.\n", name, (strlen(value) == 0) ? NULL : value);
    } else {
        DSS_PRINT_INF("Succeed to get cfg, name is %s, value is %s.\n", name, (strlen(value) == 0) ? NULL : value);
    }

    dss_disconnect_ex(&connection);
    return status;
}

static dss_args_t cmd_getstatus_args[] = {
    {'U', "UDS", CM_FALSE, CM_TRUE, cmd_check_uds, cmd_check_convert_uds_home, cmd_clean_check_convert, 0, NULL, NULL,
        0},
};

static dss_args_set_t cmd_getstatus_args_set = {
    cmd_getstatus_args,
    sizeof(cmd_getstatus_args) / sizeof(dss_args_t),
    NULL,
};

static void getstatus_help(const char *prog_name, int print_flag)
{
    (void)printf("\nUsage:%s getstatus [-U UDS:socket_domain]\n", prog_name);
    (void)printf("[client command] get dss server status\n");
    if (print_flag == DSS_HELP_SIMPLE) {
        return;
    }
    help_param_uds();
}

static status_t getstatus_proc(void)
{
    dss_conn_t connection;
    status_t status = get_connection_by_input_args(cmd_getstatus_args[DSS_ARG_IDX_0].input_args, &connection);
    if (status != CM_SUCCESS) {
        return status;
    }
    dss_server_status_t dss_status;
    status = dss_get_inst_status_on_server(&connection, &dss_status);
    if (status != CM_SUCCESS) {
        DSS_PRINT_ERROR("Failed to get server status.\n");
    } else {
        DSS_PRINT_INF("Server status of instance %d is %s and %s.\nMaster id is %d .\n", dss_status.local_instance_id,
            dss_status.instance_status, dss_status.server_status, dss_status.master_id);
    }
    dss_disconnect_ex(&connection);
    return status;
}

static dss_args_t cmd_stopdss_args[] = {
    {'U', "UDS", CM_FALSE, CM_TRUE, cmd_check_uds, cmd_check_convert_uds_home, cmd_clean_check_convert, 0, NULL, NULL,
        0},
};
static dss_args_set_t cmd_stopdss_args_set = {
    cmd_stopdss_args,
    sizeof(cmd_stopdss_args) / sizeof(dss_args_t),
    NULL,
};

static void stopdss_help(const char *prog_name, int print_flag)
{
    (void)printf("\nUsage:%s stopdss [-U UDS:socket_domain]\n", prog_name);
    (void)printf("[client command] stop dss server\n");
    if (print_flag == DSS_HELP_SIMPLE) {
        return;
    }
    help_param_uds();
}

static status_t stopdss_proc(void)
{
    dss_conn_t connection;
    status_t status = get_connection_by_input_args(cmd_stopdss_args[DSS_ARG_IDX_0].input_args, &connection);
    if (status != CM_SUCCESS) {
        return status;
    }

    status = dss_stop_server_impl(&connection);
    if (status != CM_SUCCESS) {
        DSS_PRINT_ERROR("Failed to stop server.\n");
    } else {
        DSS_PRINT_INF("Succeed to stop server.\n");
    }
    dss_disconnect_ex(&connection);
    return status;
}

static const char command_injection_check_list[] = {
    '|', ';', '&', '$', '<', '>', '`', '\\', '\'', '\"', '{', '}', '(', ')', '[', ']', '~', '*', '?', ' ', '!', '\n'};

static status_t dss_check_command_injection(const char *param)
{
    if (param == NULL) {
        DSS_THROW_ERROR(ERR_DSS_FILE_PATH_ILL, "[null]", "param cannot be a null string.");
        return CM_ERROR;
    }
    uint64 len = strlen(param);
    for (uint64 i = 0; i < len; i++) {
        for (uint32 j = 0; j < CMD_COMMAND_INJECTION_COUNT; j++) {   
            if (param[i] == command_injection_check_list[j]) {
                DSS_PRINT_ERROR(
                    "Failed to check command injection, %s has %c.\n", param, command_injection_check_list[j]);
                return CM_ERROR;
            }
        }
    }
    return CM_SUCCESS;
}

static status_t cmd_check_user_or_group_name(const char *param)
{
    status_t status = dss_check_command_injection(param);
    if (status != CM_SUCCESS) {
        DSS_PRINT_ERROR("Failed to check name %s.\n", param);
        return CM_ERROR;
    }
    status = dss_check_name(param);
    if (status != CM_SUCCESS) {
        DSS_PRINT_ERROR("Failed to check name %s.\n", param);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static status_t cmd_check_scandisk_path(const char *param)
{
    status_t status = dss_check_command_injection(param);
    if (status != CM_SUCCESS) {
        DSS_PRINT_ERROR("Failed to check path %s.\n", param);
        return CM_ERROR;
    }
    status = dss_check_volume_path(param);
    if (status != CM_SUCCESS) {
        DSS_PRINT_ERROR("Failed to check name %s.\n", param);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static status_t cmd_check_file_type(const char *type)
{
    if (strcmp(type, "block") == 0) {
        return CM_SUCCESS;
    }
    DSS_PRINT_ERROR("Failed to check file type, only support block type.\n");
    return CM_ERROR;
}

static dss_args_t cmd_scandisk_args[] = {
    {'t', "type", CM_TRUE, CM_TRUE, cmd_check_file_type, NULL, NULL, 0, NULL, NULL, 0},
    {'p', "path", CM_TRUE, CM_TRUE, cmd_check_scandisk_path, NULL, NULL, 0, NULL, NULL, 0},
    {'u', "user_name", CM_TRUE, CM_TRUE, cmd_check_user_or_group_name, NULL, NULL, 0, NULL, NULL, 0},
    {'g', "group_name", CM_TRUE, CM_TRUE, cmd_check_user_or_group_name, NULL, NULL, 0, NULL, NULL, 0},
};

static dss_args_set_t cmd_scandisk_args_set = {
    cmd_scandisk_args,
    sizeof(cmd_scandisk_args) / sizeof(dss_args_t),
    NULL,
};

static void scandisk_help(const char *prog_name, int print_flag)
{
    (void)printf("\nUsage:%s scandisk <-t type> <-p path> <-u user_name> <-g group_name>\n", prog_name);
    (void)printf("[client command] Scan disk to rebuild soft link\n");
    if (print_flag == DSS_HELP_SIMPLE) {
        return;
    }
    (void)printf("-t/--type <type>, <required>, file type\n");
    (void)printf("-p/--path <path>, <required>, find disk path\n");
    (void)printf("-u/--user_name <user_name>, <required>, user name\n");
    (void)printf("-g/--group_name <group_name>, <required>, group name\n");
}

static status_t scandisk_proc(void)
{
#ifdef WIN32
    DSS_PRINT_ERROR("Windows does not support scan disk.\n");
    return CM_ERROR;
#else
    char *path = cmd_scandisk_args[DSS_ARG_IDX_1].input_args;
    char *user_name = cmd_scandisk_args[DSS_ARG_IDX_2].input_args;
    char *group_name = cmd_scandisk_args[DSS_ARG_IDX_3].input_args;

    char cmd[DSS_PARAM_BUFFER_SIZE] = {0};
    int ret = snprintf_s(cmd, DSS_PARAM_BUFFER_SIZE, DSS_PARAM_BUFFER_SIZE - 1,
        "ls -l %s* 2>/dev/null |grep ' %s \\+%s '|grep '^b'| awk -F\" %s\" '{print \"%s\" $2}' | awk '{print $1}'",
        path, user_name, group_name, path, path);
    if (ret < 0) {
        DSS_PRINT_ERROR("snprintf_s query cmd failed.\n");
        return CM_ERROR;
    }
    char result[DSS_PARAM_BUFFER_SIZE] = {0};
    FILE *ptr = popen(cmd, "r");
    if (ptr == NULL) {
        DSS_PRINT_ERROR("Failed to scan disk when popen.\n");
        return CM_ERROR;
    }
    int32 handle = -1;
    while (fgets(result, DSS_PARAM_BUFFER_SIZE, ptr) != NULL) {
        result[strlen(result) - 1] = '\0';
        handle = open(result, O_RDWR, 0);
        if (handle == -1) {
            (void)pclose(ptr);
            DSS_THROW_ERROR(ERR_DSS_VOLUME_OPEN, result, cm_get_os_error());
            DSS_PRINT_ERROR("Failed to scan disk when open handle.\n");
            return CM_ERROR;
        }
        ret = close(handle);
        if (ret != 0) {
            (void)pclose(ptr);
            DSS_PRINT_ERROR("Failed to scan disk when close handle.\n");
            return CM_ERROR;
        }
    }
    ret = pclose(ptr);
    if (ret != 0) {
        DSS_PRINT_ERROR("Failed to scan disk when pclose.\n");
        return CM_ERROR;
    }
    DSS_PRINT_INF("Succeed to scan disk.\n");
    return CM_SUCCESS;
#endif
}

static dss_args_t cmd_clean_vglock_args[] = {
    {'D', "DSS_HOME", CM_FALSE, CM_TRUE, cmd_check_dss_home, cmd_check_convert_dss_home, cmd_clean_check_convert, 0,
        NULL, NULL, 0},
};

static dss_args_set_t cmd_clean_vglock_args_set = {
    cmd_clean_vglock_args,
    sizeof(cmd_clean_vglock_args) / sizeof(dss_args_t),
    NULL,
};

static void clean_vglock_help(const char *prog_name, int print_flag)
{
    (void)printf("\nUsage:%s clean_vglock [-D DSS_HOME]\n", prog_name);
    (void)printf("[manage command] clean vg lock\n");
    if (print_flag == DSS_HELP_SIMPLE) {
        return;
    }
    help_param_dsshome();
}

static status_t clean_vglock_proc(void)
{
    char *home = cmd_clean_vglock_args[DSS_ARG_IDX_0].input_args;
    status_t status = dss_clean_vg_lock(home, DSS_MAX_INST_ID);
    if (status != CM_SUCCESS) {
        DSS_PRINT_ERROR("Failed to clean vg lock.\n");
    } else {
        DSS_PRINT_INF("Succeed to clean vg lock.\n");
    }
    return status;
}

// clang-format off
dss_admin_cmd_t g_dss_admin_cmd[] = { {"cv", cv_help, cv_proc, &cmd_cv_args_set},
                                      {"lsvg", lsvg_help, lsvg_proc, &cmd_lsvg_args_set},
                                      {"adv", adv_help, adv_proc, &cmd_adv_args_set},
                                      {"mkdir", mkdir_help, mkdir_proc, &cmd_mkdir_args_set},
                                      {"touch", touch_help, touch_proc, &cmd_touch_args_set},
                                      {"ts", ts_help, ts_proc, &cmd_ts_args_set},
                                      {"ls", ls_help, ls_proc, &cmd_ls_args_set},
                                      {"cp", cp_help, cp_proc, &cmd_cp_args_set},
                                      {"rm", rm_help, rm_proc, &cmd_rm_args_set},
                                      {"rmv", rmv_help, rmv_proc, &cmd_rmv_args_set},
                                      {"rmdir", rmdir_help, rmdir_proc, &cmd_rmdir_args_set},
                                      {"inq", inq_help, inq_proc, &cmd_inq_args_set},
                                      {"inq_reg", inq_reg_help, inq_reg_proc, &cmd_inq_req_args_set},
                                      {"lscli", lscli_help, lscli_proc, &cmd_lscli_args_set},
                                      {"kickh", kickh_help, kickh_proc, &cmd_kickh_args_set},
                                      {"reghl", reghl_help, reghl_proc, &cmd_reghl_args_set},
                                      {"unreghl", unreghl_help, unreghl_proc, &cmd_unreghl_args_set},
                                      {"auid", auid_help, auid_proc, &cmd_auid_args_set},
                                      {"examine", examine_help, examine_proc, &cmd_examine_args_set},
                                      {"dev", dev_help, dev_proc, &cmd_dev_args_set},
                                      {"showdisk", showdisk_help, showdisk_proc, &cmd_showdisk_args_set},
                                      {"rename", rename_help, rename_proc, &cmd_rename_args_set},
                                      {"du", du_help, du_proc, &cmd_du_args_set},
                                      {"find", find_help, find_proc, &cmd_find_args_set},
                                      {"ln", ln_help, ln_proc, &cmd_ln_args_set},
                                      {"readlink", readlink_help, readlink_proc, &cmd_readlink_args_set},
                                      {"unlink", unlink_help, unlink_proc, &cmd_unlink_args_set},
                                      {"encrypt", encrypt_help, encrypt_proc, &cmd_encrypt_args_set},
                                      {"setcfg", setcfg_help, setcfg_proc, &cmd_setcfg_args_set},
                                      {"getcfg", getcfg_help, getcfg_proc, &cmd_getcfg_args_set},
                                      {"getstatus", getstatus_help, getstatus_proc, &cmd_getstatus_args_set},
                                      {"stopdss", stopdss_help, stopdss_proc, &cmd_stopdss_args_set},
                                      {"scandisk", scandisk_help, scandisk_proc, &cmd_scandisk_args_set},
                                      {"clean_vglock", clean_vglock_help, clean_vglock_proc,
                                          &cmd_clean_vglock_args_set},
};

// clang-format on
static void help(char *prog_name, dss_help_type help_type)
{
    (void)printf("Usage:dsscmd [command] [OPTIONS]\n\n");
    (void)printf("Usage:%s -h/--help show help information of dsscmd\n", prog_name);
    (void)printf("Usage:%s -a/--all show all help information of dsscmd\n", prog_name);
    (void)printf("Usage:%s -v/--version show version information of dsscmd\n", prog_name);
    (void)printf("commands:\n");
    for (uint32 i = 0; i < sizeof(g_dss_admin_cmd) / sizeof(g_dss_admin_cmd[0]); ++i) {
        g_dss_admin_cmd[i].help(prog_name, help_type);
    }
    (void)printf("\n\n");
}

static status_t execute_one_cmd(int argc, char **argv, uint32 cmd_idx)
{
    cmd_parse_init(g_dss_admin_cmd[cmd_idx].args_set->cmd_args, g_dss_admin_cmd[cmd_idx].args_set->args_size);
    if (cmd_parse_args(argc, argv, g_dss_admin_cmd[cmd_idx].args_set) != CM_SUCCESS) {
        int32 code;
        const char *message;
        cm_get_error(&code, &message);
        if (code != 0) {
            DSS_PRINT_ERROR("\ncmd %s error:%d %s.\n", g_dss_admin_cmd[cmd_idx].cmd, code, message);
        }
        return CM_ERROR;
    }
    status_t ret = g_dss_admin_cmd[cmd_idx].proc();
    cmd_parse_clean(g_dss_admin_cmd[cmd_idx].args_set->cmd_args, g_dss_admin_cmd[cmd_idx].args_set->args_size);
    return ret;
}

static status_t dss_cmd_append_oper_log(char *log_buf, void *buf, uint32 *offset)
{
    uint32 len = (uint32)strlen(buf);
    errno_t errcode = memcpy_s(log_buf + *offset, CM_MAX_LOG_CONTENT_LENGTH - *offset, buf, len);
    if (errcode != EOK) {
        DSS_PRINT_ERROR("Copying buf to log_buf failed.\n");
        return CM_ERROR;
    }
    *offset += len;
    return CM_SUCCESS;
}

static void dss_cmd_oper_log(int argc, char **argv, status_t status)
{
    char log_buf[CM_MAX_LOG_CONTENT_LENGTH] = {0};
    uint32 offset = 0;

    if (!LOG_OPER_ON) {
        return;
    }

    DSS_RETURN_DRIECT_IFERR(dss_cmd_append_oper_log(log_buf, "dsscmd", &offset));

    for (int i = 1; i < argc; i++) {
        DSS_RETURN_DRIECT_IFERR(dss_cmd_append_oper_log(log_buf, " ", &offset));
        DSS_RETURN_DRIECT_IFERR(dss_cmd_append_oper_log(log_buf, argv[i], &offset));
    }

    char result[DSS_MAX_PATH_BUFFER_SIZE];
    int32 ret = snprintf_s(
        result, DSS_MAX_PATH_BUFFER_SIZE, DSS_MAX_PATH_BUFFER_SIZE - 1, ". execute result %d.", (int32)status);
    if (ret == -1) {
        return;
    }
    DSS_RETURN_DRIECT_IFERR(dss_cmd_append_oper_log(log_buf, result, &offset));

    if (offset + 1 > CM_MAX_LOG_CONTENT_LENGTH) {
        DSS_PRINT_ERROR("Oper log len %u exceeds max %u.\n", offset, CM_MAX_LOG_CONTENT_LENGTH);
        return;
    }
    log_buf[offset + 1] = '\0';
    cm_write_oper_log(log_buf, offset);
}

static bool32 get_cmd_idx(int argc, char **argv, uint32_t *idx)
{
    for (uint32 i = 0; i < sizeof(g_dss_admin_cmd) / sizeof(g_dss_admin_cmd[0]); ++i) {
        if (strcmp(g_dss_admin_cmd[i].cmd, argv[DSS_ARG_IDX_1]) == 0) {
            *idx = i;
            return CM_TRUE;
        }
    }
    return CM_FALSE;
}

void execute_help_cmd(int argc, char **argv, uint32_t *idx)
{
    if (argc < CMD_ARGS_AT_LEAST) {
        (void)printf("dsscmd: no operation specified.\n");
        (void)printf("dsscmd: Try \"dsscmd -h/--help\" for help information.\n");
        (void)printf("dsscmd: Try \"dsscmd -a/--all\" for detailed help information.\n");
        exit(EXIT_FAILURE);
    }
    if (cm_str_equal(argv[1], "-v") || cm_str_equal(argv[1], "--version")) {
        (void)printf("dsscmd %s\n", (char *)DEF_DSS_VERSION);
        exit(EXIT_SUCCESS);
    }
    if (cm_str_equal(argv[1], "-a") || cm_str_equal(argv[1], "--all")) {
        help(argv[0], DSS_HELP_DETAIL);
        exit(EXIT_SUCCESS);
    }
    if (cm_str_equal(argv[1], "-h") || cm_str_equal(argv[1], "--help")) {
        help(argv[0], DSS_HELP_SIMPLE);
        exit(EXIT_SUCCESS);
    }
    if (!get_cmd_idx(argc, argv, idx)) {
        (void)printf("cmd:%s can not find.\n", argv[DSS_ARG_IDX_1]);
        help(argv[0], DSS_HELP_SIMPLE);
        exit(EXIT_FAILURE);
    }
    if (argc > DSS_ARG_IDX_2 &&
        (strcmp(argv[DSS_ARG_IDX_2], "-h") == 0 || strcmp(argv[DSS_ARG_IDX_2], "--help") == 0)) {
        g_dss_admin_cmd[*idx].help(argv[0], DSS_HELP_DETAIL);
        exit(EXIT_SUCCESS);
    }
}

static status_t execute_cmd(int argc, char **argv, uint32 idx)
{
    status_t status = execute_one_cmd(argc, argv, idx);
    dss_cmd_oper_log(argc, argv, status);
    return status;
}

int main(int argc, char **argv)
{
#ifndef WIN32
    // check root
    if (geteuid() == 0 || getuid() != geteuid()) {
        (void)printf("The root user is not permitted to execute the dsscmd "
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
    execute_help_cmd(argc, argv, &idx);
    dss_config_t inst_cfg;
    if (dss_set_cfg_dir(NULL, &inst_cfg) != CM_SUCCESS) {
        (void)printf("Environment variant DSS_HOME not found!\n");
        return CM_ERROR;
    }
    status_t ret = dss_load_local_server_config(
        &inst_cfg, g_dss_admin_parameters, sizeof(g_dss_admin_parameters) / sizeof(config_item_t));
    if (ret != CM_SUCCESS) {
        (void)printf("load local server config failed during init loggers.\n");
        return CM_ERROR;
    }

    if (cm_start_timer(g_timer()) != CM_SUCCESS) {
        (void)printf("Aborted due to starting timer thread.\n");
        return CM_ERROR;
    }

    ret = dss_init_loggers(&inst_cfg, g_dss_admin_log, sizeof(g_dss_admin_log) / sizeof(dss_log_def_t), "dsscmd");
    if (ret != CM_SUCCESS) {
        (void)printf("%s\nDSS init loggers failed!\n", cm_get_errormsg(cm_get_error_code()));
        return ret;
    }
    cm_reset_error();
    return execute_cmd(argc, argv, idx);
}
