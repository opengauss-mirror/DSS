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
 * dsscmd_du.h
 *
 *
 * IDENTIFICATION
 *    src/cmd/dsscmd_du.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef DSSCMD_DU_H_
#define DSSCMD_DU_H_

#include "dsscmd_cli_msg.h"

#define DSS_DU_PARAM_LEN 3

status_t du_traverse_path(char *path, size_t path_size, dss_conn_t *conn, const char *params, size_t params_size);
status_t du_get_params(const char *input, char *params, size_t params_size);

#endif
