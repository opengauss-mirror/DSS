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
 * dsscmd_interactive.h
 *
 *
 * IDENTIFICATION
 *    src/cmd/dsscmd_interactive.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __DSSCMD_INTERACTIVE_H__
#define __DSSCMD_INTERACTIVE_H__

#include "cm_utils.h"
#include "dss_defs.h"
#include "dss_args_parse.h"
#include "dsscmd.h"

#define VERSION_SHORT       (g_run_interatively ? "v" : "-v")
#define VERSION_LONG        (g_run_interatively ? "version" : "--version")
#define ALL_SHORT           (g_run_interatively ? "a" : "-a")
#define ALL_LONG            (g_run_interatively ? "all" : "--all")
#define HELP_SHORT          (g_run_interatively ? "h" : "-h")
#define HELP_LONG           (g_run_interatively ? "help" : "--help")

#define CMD_KEY_ASCII_BS    8
#define CMD_KEY_ASCII_DEL   127
#define CMD_KEY_ASCII_LF    10
#define CMD_KEY_ASCII_CR    13
#define CMD_KEY_ESCAPE      27
#define CMD_KEY_UP          65
#define CMD_KEY_DOWN        66
#define CMD_KEY_DEL         51

#define MAX_INPUT_LEN       6144
#define MAX_CMD_LEN         MAX_INPUT_LEN + 1
#define DSS_MAX_ARG_NUM     30
#define DSS_UTF8_CHR_SIZE   6
#define STDOUT              1
#define DSS_UTF8_MULTI_BYTES_MASK 0x80
#define IS_VALID_UTF8_CHAR(c) (((c) & 0xC0) == 0x80)  // 10xxxxxx
#define DSS_CMD_MAX_HISTORY_SIZE 20

#define dss_cmd_write(len, fmt, ...)    write(STDOUT, fmt, len)

typedef void (*dss_interactive_cmd_proc)(int argc, char **args);

typedef struct st_dss_interactive_cmd_t {
    char cmd[CM_MAX_NAME_LEN];
    dss_admin_help help;
    dss_interactive_cmd_proc proc;
} dss_interactive_cmd_t;

extern char g_cur_path[DSS_FILE_PATH_MAX_LENGTH];

extern bool8 g_run_interatively;

status_t dss_cmd_check_device_path(const char *path);

status_t cmd_check_convert_path(const char *input_args, void **convert_result, int *convert_size);

void cmd_print_interactive_help(char *prog_name, dss_help_type help_type);

void dss_cmd_run_interactively();

#endif