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
 * dss_args_parse.c
 *
 *
 * IDENTIFICATION
 *    src/common/dss_args_parse.c
 *
 * -------------------------------------------------------------------------
 */

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

#include "dss_log.h"
#include "dss_defs.h"
#include "dss_errno.h"
#include "dss_param.h"
#include "dss_file.h"
#include "dss_args_parse.h"
#ifdef __cplusplus
extern "C" {
#endif

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

status_t cmd_parse_args(int argc, char **argv, dss_args_set_t *args_set)
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

// just for cmd exist for much cmd at once
void cmd_parse_init(dss_args_t *cmd_args_set, int set_size)
{
    for (int i = 0; i < set_size; i++) {
        cmd_args_set[i].inputed = CM_FALSE;
        cmd_args_set[i].input_args = NULL;
        cmd_args_set[i].convert_result = NULL;
        cmd_args_set[i].convert_result_size = 0;
    }
}

void cmd_parse_clean(dss_args_t *cmd_args_set, int set_size)
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

status_t cmd_check_au_size(const char *au_size_str)
{
    uint32 min_multiple = DSS_MIN_AU_SIZE / SIZE_K(1);
    uint32 max_multiple = DSS_MAX_AU_SIZE / SIZE_K(1);
    uint32 au_size;
    status_t ret = cm_str2uint32(au_size_str, &au_size);
    if (ret != CM_SUCCESS) {
        DSS_PRINT_ERROR("au_size %s is error!\n", au_size_str);
        return CM_ERROR;
    }
    if (au_size == 0 || au_size < min_multiple || au_size > max_multiple) {
        DSS_PRINT_ERROR(
            "au_size %u is error, au_size cannot be 0, must greater than 2MB, smaller than 64MB!\n", au_size);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

status_t cmd_check_dss_home(const char *dss_home)
{
    return dss_check_path(dss_home);
}

status_t cmd_realpath_home(const char *input_args, char **convert_result, int *convert_size)
{
    uint32 len = (uint32)strlen(input_args);
    if (len == 0 || len >= CM_FILE_NAME_BUFFER_SIZE) {
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

status_t cmd_check_convert_dss_home(const char *input_args, void **convert_result, int *convert_size)
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

void cmd_clean_check_convert(char *convert_result, int convert_size)
{
    if (convert_result != NULL) {
        CM_FREE_PTR(convert_result);
    }
}
status_t cmd_check_uint64(const char *str)
{
    uint64 num;
    status_t status = cm_str2uint64(str, &num);
    if (status == CM_ERROR) {
        DSS_PRINT_ERROR("%s is not a valid uint64\n", str);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

status_t set_config_info(char *home, dss_config_t *inst_cfg)
{
    status_t status;
    status = dss_set_cfg_dir(home, inst_cfg);
    if (status != CM_SUCCESS) {
        LOG_DEBUG_ERR("Environment variant DSS_HOME not found!\n");
        return status;
    }

    status = dss_load_config(inst_cfg);
    if (status != CM_SUCCESS) {
        LOG_DEBUG_ERR("Failed to load parameters!\n");
        return status;
    }
    return CM_SUCCESS;
}

status_t dss_get_vg_item(dss_vg_info_item_t **vg_item, const char *vg_name)
{
    dss_vg_info_item_t *tmp_vg_item = dss_find_vg_item(vg_name);
    if (tmp_vg_item == NULL) {
        LOG_DEBUG_ERR("vg_name %s is not exist.\n", vg_name);
        return CM_ERROR;
    }
    *vg_item = tmp_vg_item;
    return CM_SUCCESS;
}

config_item_t g_dss_admin_parameters[] = {
    // name (30B)                     isdefault readonly  defaultvalue value runtime_value description range  datatype
    // comment
    // -------------                  --------- --------  ------------ ----- ------------- ----------- -----  --------
    // -----
    /* log */
    {"LOG_HOME", CM_TRUE, ATTR_READONLY, "", NULL, NULL, "-", "-", "GS_TYPE_VARCHAR", NULL, 0, EFFECT_REBOOT, CFG_INS,
        NULL, NULL},
    {"_LOG_BACKUP_FILE_COUNT", CM_TRUE, ATTR_NONE, "20", NULL, NULL, "-", "[0,128]", "GS_TYPE_INTEGER", NULL, 1,
        EFFECT_REBOOT, CFG_INS, NULL, NULL},
    {"_LOG_MAX_FILE_SIZE", CM_TRUE, ATTR_NONE, "256M", NULL, NULL, "-", "[1M,4G]", "GS_TYPE_INTEGER", NULL, 2,
        EFFECT_REBOOT, CFG_INS, NULL, NULL},
    {"_LOG_FILE_PERMISSIONS", CM_TRUE, ATTR_READONLY, "600", NULL, NULL, "-", "[600-777]", "GS_TYPE_INTEGER", NULL, 3,
        EFFECT_REBOOT, CFG_INS, NULL, NULL},
    {"_LOG_PATH_PERMISSIONS", CM_TRUE, ATTR_READONLY, "700", NULL, NULL, "-", "[700-777]", "GS_TYPE_INTEGER", NULL, 4,
        EFFECT_REBOOT, CFG_INS, NULL, NULL},
    {"_LOG_LEVEL", CM_TRUE, ATTR_NONE, "519", NULL, NULL, "-", "[0,4087]", "GS_TYPE_INTEGER", NULL, 5, EFFECT_REBOOT,
        CFG_INS, NULL, NULL, NULL, NULL},
    {"_AUDIT_BACKUP_FILE_COUNT", CM_TRUE, ATTR_NONE, "20", NULL, NULL, "-", "[0,128]", "GS_TYPE_INTEGER", NULL, 6,
        EFFECT_REBOOT, CFG_INS, NULL, NULL, NULL, NULL},
    {"_AUDIT_MAX_FILE_SIZE", CM_TRUE, ATTR_NONE, "256M", NULL, NULL, "-", "[1M,4G]", "GS_TYPE_INTEGER", NULL, 7,
        EFFECT_REBOOT, CFG_INS, NULL, NULL, NULL, NULL},
    {"LSNR_PATH", CM_TRUE, ATTR_READONLY, "/tmp/", NULL, NULL, "-", "-", "GS_TYPE_VARCHAR", NULL, 8, EFFECT_REBOOT,
        CFG_INS, NULL, NULL, NULL, NULL},
    {"_AUDIT_LEVEL", CM_TRUE, ATTR_NONE, "1", NULL, NULL, "-", "-", "GS_TYPE_VARCHAR", NULL, 9, EFFECT_REBOOT, CFG_INS,
        NULL, NULL, NULL, NULL},
    {"CLUSTER_RUN_MODE", CM_TRUE, ATTR_NONE, "cluster_primary", NULL, NULL, "-", "-", "GS_TYPE_VARCHAR", NULL, 10,
        EFFECT_REBOOT, CFG_INS, NULL, NULL, NULL, NULL},
    { "LOG_COMPRESSED",  CM_TRUE, ATTR_READONLY, "FALSE", NULL, NULL, "-", "[FALSE,TRUE]",  "GS_TYPE_BOOLEAN", NULL,
        11, EFFECT_REBOOT, CFG_INS, NULL, NULL, NULL, NULL},
};

static status_t dss_load_local_server_config_core(
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

status_t dss_load_local_server_config(dss_config_t *inst_cfg)
{
    return dss_load_local_server_config_core(
        inst_cfg, g_dss_admin_parameters, sizeof(g_dss_admin_parameters) / sizeof(config_item_t));
}

#ifdef __cplusplus
}
#endif