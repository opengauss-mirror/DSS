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
 * dss_service.h
 *
 *
 * IDENTIFICATION
 *    src/service/dss_service.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __DSS_SERVICE_H__
#define __DSS_SERVICE_H__
#include "dss_latch.h"
#include "dss_session.h"
#include "dss_instance.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef status_t (*dss_srv_proc)(dss_session_t *session);
typedef status_t (*dss_srv_proc_err)(dss_session_t *session);

typedef struct st_dss_cmd_hdl {
    int32 cmd;
    dss_srv_proc proc;
    dss_srv_proc_err proc_err;
    bool32 exec_on_active;
} dss_cmd_hdl_t;
#ifndef WIN32
status_t dss_signal_proc(void);
status_t dss_signal_proc_with_graceful_exit(void);
#endif
#define DSS_PROCESS_GET_MASTER_ID 50
static inline void dss_inc_active_sessions(dss_session_t *session)
{
    if (session->recv_pack.head->cmd != DSS_CMD_SWITCH_LOCK &&
        session->recv_pack.head->cmd != DSS_CMD_DISABLE_GRAB_LOCK) {
        (void)cm_atomic_inc(&g_dss_instance.active_sessions);
        LOG_DEBUG_INF("session:%u inc active_sessions to:%lld for cmd:%u", session->id, g_dss_instance.active_sessions,
            (uint32)session->recv_pack.head->cmd);
    }
}

static inline void dss_dec_active_sessions(dss_session_t *session)
{
    if (session->recv_pack.head->cmd != DSS_CMD_SWITCH_LOCK &&
        session->recv_pack.head->cmd != DSS_CMD_DISABLE_GRAB_LOCK) {
        (void)cm_atomic_dec(&g_dss_instance.active_sessions);
        LOG_DEBUG_INF("session:%u dec active_sessions to:%lld for cmd:%u", session->id, g_dss_instance.active_sessions,
            (uint32)session->recv_pack.head->cmd);
    }
}

status_t dss_get_exec_nodeid(dss_session_t *session, uint32 *currid, uint32 *remoteid);
void dss_wait_session_pause(dss_instance_t *inst);
void dss_wait_background_pause(dss_instance_t *inst);
void dss_set_session_running(dss_instance_t *inst, uint32 sid);
status_t dss_diag_proto_type(dss_session_t *session);
status_t dss_process_handshake_cmd(dss_session_t *session, dss_cmd_type_e cmd);
status_t dss_process_command(dss_session_t *session);
status_t dss_proc_standby_req(dss_session_t *session);
status_t dss_process_single_cmd(dss_session_t **session);
void dss_release_session_res(dss_session_t *session);

#ifdef __cplusplus
}
#endif
#endif
