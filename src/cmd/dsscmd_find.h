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
 * dsscmd_find.h
 *
 *
 * IDENTIFICATION
 *    src/cmd/dsscmd_find.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef DSSCMD_FIND_H_
#define DSSCMD_FIND_H_

#include "dsscmd_cli_msg.h"

status_t find_traverse_path(dss_conn_t *conn, char *path, size_t path_size, char *name, size_t name_size);

#endif
