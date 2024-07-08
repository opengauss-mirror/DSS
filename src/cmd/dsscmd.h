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
 * dsscmd.h
 *
 *
 * IDENTIFICATION
 *    src/cmd/dsscmd.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __DSSCMD_H__
#define __DSSCMD_H__

#include "dss_defs.h"
#include "dss_interaction.h"

#define CMD_ARGS_AT_LEAST 2

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

typedef enum en_dss_help_type {
    DSS_HELP_DETAIL = 0,
    DSS_HELP_SIMPLE,
} dss_help_type;

typedef void (*dss_admin_help)(const char *prog_name, int print_flag);

status_t get_server_locator(char *input_args, char *server_locator);

status_t dss_uds_get_connection(const char *server_locator, dss_conn_t *conn);

void dss_cmd_set_path_optional();

int32 execute_help_cmd(int argc, char **argv, uint32_t *idx, bool8 *go_ahead);

status_t execute_cmd(int argc, char **argv, uint32 idx);

void clean_cmd();

#endif