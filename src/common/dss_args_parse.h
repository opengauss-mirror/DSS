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
 * dss_args_parse.h
 *
 *
 * IDENTIFICATION
 *    src/common/dss_args_parse.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef DSS_ARGS_PARSE_H_
#define DSS_ARGS_PARSE_H_

#include "cm_base.h"
#include "dss_ctrl_def.h"

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
    bool8 log_necessary;  // Logs are necessary for commands which write disks, and unnecessary for others.
} dss_admin_cmd_t;

typedef enum en_dss_help_type {
    DSS_HELP_DETAIL = 0,
    DSS_HELP_SIMPLE,
} dss_help_type;

#define DSS_ARG_IDX_0 0
#define DSS_ARG_IDX_1 1
#define DSS_ARG_IDX_2 2
#define DSS_ARG_IDX_3 3
#define DSS_ARG_IDX_4 4
#define DSS_ARG_IDX_5 5
#define DSS_ARG_IDX_6 6
#define DSS_ARG_IDX_7 7
#define DSS_ARG_IDX_8 8
#define DSS_ARG_IDX_9 9
#define DSS_ARG_IDX_10 10
#define CMD_ARGS_AT_LEAST 2

status_t cmd_parse_args(int argc, char **argv, dss_args_set_t *args_set);
void cmd_parse_init(dss_args_t *cmd_args_set, int set_size);
void cmd_parse_clean(dss_args_t *cmd_args_set, int set_size);
status_t cmd_check_au_size(const char *au_size_str);
status_t dss_load_local_server_config(dss_config_t *inst_cfg);
status_t cmd_check_uint64(const char *lsn_str);
status_t cmd_check_dss_home(const char *dss_home);
status_t cmd_check_convert_dss_home(const char *input_args, void **convert_result, int *convert_size);
status_t cmd_realpath_home(const char *input_args, char **convert_result, int *convert_size);
void cmd_clean_check_convert(char *convert_result, int convert_size);
status_t set_config_info(char *home, dss_config_t *inst_cfg);
status_t dss_get_vg_item(dss_vg_info_item_t **vg_item, const char *vg_name);
#endif