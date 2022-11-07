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
 * dsscmd_cli_msg.h
 *
 *
 * IDENTIFICATION
 *    src/cmd/dsscmd_cli_msg.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef DSSCMD_CLI_MSG_H_
#define DSSCMD_CLI_MSG_H_

#include "dss_api_impl.h"

status_t dsscmd_adv_impl(dss_conn_t *conn, const char *vg_name, const char *volume_name);
status_t dsscmd_rmv_impl(dss_conn_t *conn, const char *vg_name, const char *volume_name);
status_t dss_unregister_host_sync(dss_conn_t *connection);
status_t dss_kick_host_sync(dss_conn_t *connection, int64 kick_hostid);
status_t dss_register_host_sync(dss_conn_t *connection);

#endif
