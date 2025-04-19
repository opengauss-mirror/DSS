/*
 * Copyright (c) Huawei Technologies Co.,Ltd. 2024-2024 all rigths reserved.
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
 * dss_cli_conn.h
 *
 *
 * IDENTIFICATION
 *    src/common_api/dss_cli_conn.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __DSS_CLI_CONN_H__
#define __DSS_CLI_CONN_H__

#include <stdio.h>
#include <stdbool.h>
#include "dss_errno.h"
#include "time.h"
#include "cm_types.h"
#include "dss_thv.h"
#include "dss_protocol.h"
#include "dss_session.h"

#ifdef __cplusplus
extern "C" {
#endif

#define HANDLE_VALUE(handle) ((handle) - (DSS_HANDLE_BASE))
#define DB_DSS_DEFAULT_UDS_PATH "UDS:/tmp/.dss_unix_d_socket"
extern char g_dss_inst_path[CM_MAX_PATH_LEN];
extern int32 g_dss_uds_conn_timeout;

typedef struct st_dss_conn {
    dss_packet_t pack;  // for sending
    cs_pipe_t pipe;
    void *cli_vg_handles;
    bool32 flag;
    void *session;
    uint32 server_version;
    uint32 proto_version;
#ifdef ENABLE_DSSTEST
    pid_t conn_pid;
#endif
    dss_cli_info_t cli_info;
} dss_conn_t;

typedef struct st_dss_conn_opt {
    int32 timeout;
    char *user_name;
} dss_conn_opt_t;

status_t dss_conn_create(pointer_t *result);
status_t dss_conn_opts_create(pointer_t *result);
void dss_conn_opts_release(pointer_t thv_addr);
void dss_conn_release(pointer_t thv_addr);
status_t dss_try_conn(dss_conn_opt_t *options, dss_conn_t *conn);
void dss_clt_env_init(void);
status_t dss_enter_api(dss_conn_t **conn);
void dss_leave_api(dss_conn_t *conn, bool32 get_api_volume_error);
status_t dss_connect(const char *server_locator, dss_conn_opt_t *options, dss_conn_t *conn);
void dss_disconnect(dss_conn_t *conn);
void dss_init_conn(dss_conn_t *conn);

#ifdef __cplusplus
}
#endif

#endif  // __DSS_CLI_CONN_H__
