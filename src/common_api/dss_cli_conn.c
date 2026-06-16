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
 * dss_cli_conn.c
 *
 *
 * IDENTIFICATION
 *    src/common_api/dss_cli_conn.c
 *
 * -------------------------------------------------------------------------
 */

#include "dss_cli_conn.h"
#include "dss_api_impl.h"
#include "dss_malloc.h"
#include "dss_log.h"
#include "dss_thv.h"
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

char g_dss_inst_path[CM_MAX_PATH_LEN] = {0};

/*
 * Client connection lifecycle counters (all guarded by conn_latch):
 *
 *   conn_inflight         - threads inside dss_try_conn (from entry until return).
 *   conn_establishing_cnt - UDS connect() succeeded, handshake/init not finished yet.
 *                           Does NOT mean the connection is ready for IO.
 *   conn_ready_cnt        - handshake and vol-handle init completed; THV-held connections
 *                           that may be used by dss_enter_api until dss_conn_release.
 *
 * dss_destroy() is deferred until all three counters are zero.
 * These counters are file-local; do not infer IO readiness from conn_establishing_cnt alone.
 */
typedef struct st_dss_conn_info {
    latch_t conn_latch;
    uint32 conn_establishing_cnt;
    uint32 conn_ready_cnt;
    uint32 conn_inflight;
    bool32 isinit;
    int32 timeout;  // - 1: never time out
} dss_conn_info_t;
static dss_conn_info_t g_dss_conn_info = {{0, 0, 0, 0, 0}, 0, 0, 0, CM_FALSE, 0};

static void dss_conn_track_inflight(bool32 inc)
{
    cm_latch_x(&g_dss_conn_info.conn_latch, 1, NULL);
    if (inc) {
        g_dss_conn_info.conn_inflight++;
    } else if (g_dss_conn_info.conn_inflight > 0) {
        g_dss_conn_info.conn_inflight--;
    }
    cm_unlatch(&g_dss_conn_info.conn_latch, NULL);
}

static void dss_try_destroy_client_env(void)
{
    bool32 should_destroy = CM_FALSE;

    cm_latch_x(&g_dss_conn_info.conn_latch, 1, NULL);
    if (g_dss_conn_info.conn_establishing_cnt == 0 && g_dss_conn_info.conn_ready_cnt == 0 &&
        g_dss_conn_info.conn_inflight == 0) {
        should_destroy = CM_TRUE;
    }
    cm_unlatch(&g_dss_conn_info.conn_latch, NULL);
    if (should_destroy) {
        dss_destroy();
    }
}

static void dss_conn_on_connect_ok(void)
{
    cm_latch_x(&g_dss_conn_info.conn_latch, 1, NULL);
    g_dss_conn_info.conn_establishing_cnt++;
    cm_unlatch(&g_dss_conn_info.conn_latch, NULL);
}

static void dss_conn_on_establish_fail(void)
{
    cm_latch_x(&g_dss_conn_info.conn_latch, 1, NULL);
    if (g_dss_conn_info.conn_establishing_cnt > 0) {
        g_dss_conn_info.conn_establishing_cnt--;
    }
    cm_unlatch(&g_dss_conn_info.conn_latch, NULL);
}

static void dss_conn_on_establish_ok(void)
{
    cm_latch_x(&g_dss_conn_info.conn_latch, 1, NULL);
    if (g_dss_conn_info.conn_establishing_cnt > 0) {
        g_dss_conn_info.conn_establishing_cnt--;
    }
    g_dss_conn_info.conn_ready_cnt++;
    cm_unlatch(&g_dss_conn_info.conn_latch, NULL);
}

static void dss_conn_on_release(void)
{
    cm_latch_x(&g_dss_conn_info.conn_latch, 1, NULL);
    if (g_dss_conn_info.conn_ready_cnt > 0) {
        g_dss_conn_info.conn_ready_cnt--;
    }
    cm_unlatch(&g_dss_conn_info.conn_latch, NULL);
}

void dss_conn_release(pointer_t thv_addr)
{
    dss_conn_t *conn = (dss_conn_t *)thv_addr;
    if (conn->pipe.link.uds.closed != CM_TRUE) {
        LOG_DEBUG_INF("[DSS_CONNECT] client disconnect on release, sock=%d, tid=%u, ready_cnt=%u, establishing_cnt=%u",
            (int)conn->pipe.link.uds.sock, dss_get_current_thread_id(), g_dss_conn_info.conn_ready_cnt,
            g_dss_conn_info.conn_establishing_cnt);
        dss_destroy_vol_handle_sync(conn);
        dss_disconnect(conn);
        dss_conn_on_release();
        dss_try_destroy_client_env();
    }
    DSS_FREE_POINT(conn);
}

void dss_conn_opts_release(pointer_t thv_addr)
{
    DSS_FREE_POINT(thv_addr);
}

static char *dss_get_inst_path(void)
{
    if (g_dss_inst_path[0] != '\0') {
        return g_dss_inst_path;
    }
    return DB_DSS_DEFAULT_UDS_PATH;
}

static thv_ctrl_t g_dss_thv_ctrls[] = {
    {NULL, dss_conn_create, dss_conn_release},
    {NULL, dss_conn_opts_create, dss_conn_opts_release},
};

void dss_clt_env_init(void)
{
    if (g_dss_conn_info.isinit == CM_FALSE) {
        cm_latch_x(&g_dss_conn_info.conn_latch, 1, NULL);
        if (g_dss_conn_info.isinit == CM_FALSE) {
            status_t status = cm_launch_thv(g_dss_thv_ctrls, sizeof(g_dss_thv_ctrls) / sizeof(g_dss_thv_ctrls[0]));
            if (status != CM_SUCCESS) {
                LOG_RUN_ERR("Dss client initialization failed.");
                cm_unlatch(&g_dss_conn_info.conn_latch, NULL);
                return;
            }
            g_dss_conn_info.isinit = CM_TRUE;
        }
        cm_unlatch(&g_dss_conn_info.conn_latch, NULL);
    }
}

status_t dss_try_conn(dss_conn_opt_t *options, dss_conn_t *conn)
{
    status_t status = CM_ERROR;
    uint32 max_open_file = DSS_MAX_OPEN_FILES;

    dss_conn_track_inflight(CM_TRUE);

    dss_free_packet_buffer(&conn->pack);
    status = dss_connect(dss_get_inst_path(), options, conn);
    if (status != CM_SUCCESS) {
        LOG_RUN_ERR("[DSS_CONNECT] client try_conn connect failed, path=%s, timeout=%d, tid=%u, status=%d, "
                    "err_code=%d, errno=%d, errmsg=%s",
            dss_get_inst_path(), (options != NULL ? options->timeout : g_dss_uds_conn_timeout),
            dss_get_current_thread_id(), status, cm_get_error_code(), cm_get_os_error(), strerror(cm_get_os_error()));
        LOG_RUN_ERR_INHIBIT(LOG_INHIBIT_LEVEL1, "Dss client connet server failed.");
        dss_conn_track_inflight(CM_FALSE);
        dss_try_destroy_client_env();
        return CM_ERROR;
    }

    /* Socket is open; handshake not done yet — not ready for IO. */
    dss_conn_on_connect_ok();

    conn->proto_version = DSS_PROTO_VERSION;
    status = dss_cli_handshake(conn, max_open_file);
    if (status != CM_SUCCESS) {
        LOG_RUN_ERR_INHIBIT(LOG_INHIBIT_LEVEL1, "Dss client handshake to server failed.");
        dss_disconnect(conn);
        dss_conn_on_establish_fail();
        dss_conn_track_inflight(CM_FALSE);
        dss_try_destroy_client_env();
        return CM_ERROR;
    }

    status = dss_init_vol_handle_sync(conn);
    if (status != CM_SUCCESS) {
        LOG_RUN_ERR_INHIBIT(LOG_INHIBIT_LEVEL1, "Dss client init vol handle failed.");
        dss_disconnect(conn);
        dss_conn_on_establish_fail();
        dss_conn_track_inflight(CM_FALSE);
        dss_try_destroy_client_env();
        return CM_ERROR;
    }

    dss_conn_on_establish_ok();
    dss_conn_track_inflight(CM_FALSE);
    return CM_SUCCESS;
}

status_t dss_conn_opts_create(pointer_t *result)
{
    dss_conn_opt_t *options = (dss_conn_opt_t *)cm_malloc(sizeof(dss_conn_opt_t));
    if (options == NULL) {
        DSS_THROW_ERROR(ERR_ALLOC_MEMORY, sizeof(dss_conn_opt_t), "dss_conn_opts_create");
        return CM_ERROR;
    }
    (void)memset_s(options, sizeof(dss_conn_opt_t), 0, sizeof(dss_conn_opt_t));
    *result = options;
    return CM_SUCCESS;
}

static status_t dss_conn_sync(dss_conn_opt_t *options, dss_conn_t *conn)
{
    status_t ret = CM_ERROR;
    int timeout = (options != NULL ? options->timeout : g_dss_uds_conn_timeout);
    uint32 attempt = 0;
    /* 305 等瞬态 connect 超时：有限次重试，成功路径仍是一次 1s 内完成 */
    const uint32 max_attempt = 3;

    do {
        ret = dss_try_conn(options, conn);
        if (ret == CM_SUCCESS) {
            break;
        }
        if (cm_get_os_error() == ENOENT) {
            break;
        }
        if (timeout == DSS_CONN_NEVER_TIMEOUT) {
            continue;
        }
        attempt++;
        if (attempt < max_attempt) {
            cm_reset_error();
            LOG_DEBUG_INF("[DSS_CONNECT] client connect retry, attempt=%u, tid=%u, err_code=%d",
                attempt + 1, dss_get_current_thread_id(), cm_get_error_code());
        }
    } while (timeout == DSS_CONN_NEVER_TIMEOUT || attempt < max_attempt);

    return ret;
}

status_t dss_conn_create(pointer_t *result)
{
    dss_conn_t *conn = (dss_conn_t *)cm_malloc(sizeof(dss_conn_t));
    if (conn == NULL) {
        DSS_THROW_ERROR(ERR_ALLOC_MEMORY, sizeof(dss_conn_t), "dss_conn_create");
        return CM_ERROR;
    }

    (void)memset_s(conn, sizeof(dss_conn_t), 0, sizeof(dss_conn_t));

    // init packet
    dss_init_packet(&conn->pack, conn->pipe.options);
    dss_conn_opt_t *options = NULL;
    (void)cm_get_thv(GLOBAL_THV_OBJ1, CM_FALSE, (pointer_t *)&options);
    if (dss_conn_sync(options, conn) != CM_SUCCESS) {
        DSS_THROW_ERROR(ERR_DSS_CONNECT_FAILED, cm_get_os_error(), strerror(cm_get_os_error()));
        DSS_FREE_POINT(conn);
        return CM_ERROR;
    }
#ifdef ENABLE_DSSTEST
    conn->conn_pid = getpid();
#endif
    *result = conn;
    return CM_SUCCESS;
}

static status_t dss_get_conn(dss_conn_t **conn)
{
    cm_reset_error();
    dss_clt_env_init();
    if (cm_get_thv(GLOBAL_THV_OBJ0, CM_TRUE, (pointer_t *)conn) != CM_SUCCESS) {
        LOG_RUN_ERR("[DSS_CONNECT] client create connection failed, tid=%u, err_code=%d, errno=%d",
            dss_get_current_thread_id(), cm_get_error_code(), cm_get_os_error());
        return CM_ERROR;
    }

#ifdef ENABLE_DSSTEST
    if ((*conn)->flag && (*conn)->conn_pid != getpid()) {
        LOG_RUN_INF("Dss client need re-connect, last conn pid:%llu.", (uint64)(*conn)->conn_pid);
        dss_disconnect(*conn);
        if (dss_conn_sync(NULL, *conn) != CM_SUCCESS) {
            LOG_RUN_ERR("[DSS API] ABORT INFO: dss server stoped, application need restart.");
            cm_fync_logfile();
            dss_exit(1);
        }
        (*conn)->conn_pid = getpid();
    }
#endif

    if ((*conn)->pipe.link.uds.closed) {
        LOG_RUN_ERR("[DSS API] ABORT INFO : dss server stoped, application need restart.");
        cm_fync_logfile();
        dss_exit(1);
    }
    return CM_SUCCESS;
}

status_t dss_enter_api(dss_conn_t **conn)
{
    status_t status = dss_get_conn(conn);
    if (status != CM_SUCCESS) {
        return status;
    }
    while (dss_cli_session_lock((*conn), (*conn)->session) != CM_SUCCESS) {
        dss_destroy_thv(GLOBAL_THV_OBJ0);
        LOG_RUN_INF("Begin to reconnect dss server.");
        status = dss_get_conn(conn);
        if (status != CM_SUCCESS) {
            LOG_RUN_ERR("Failed to reconnect dss server.");
            return status;
        }
    }
    return CM_SUCCESS;
}

void dss_leave_api(dss_conn_t *conn, bool32 get_api_volume_error)
{
    cm_spin_unlock(&((dss_session_t *)(conn->session))->shm_lock);
    LOG_DEBUG_INF("Succeed to unlock session %u shm lock", ((dss_session_t *)(conn->session))->id);
    if (get_api_volume_error) {
        dss_get_api_volume_error();
    }
}

#ifdef __cplusplus
}
#endif
