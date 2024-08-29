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

status_t get_server_locator(const char *input_uds_home_args, char *server_locator);

void dss_cmd_set_path_optional();

int32 execute_help_cmd(int argc, char **argv, uint32_t *idx, bool8 *go_ahead);

status_t execute_cmd(int argc, char **argv, uint32 idx);

void clean_cmd();

#endif