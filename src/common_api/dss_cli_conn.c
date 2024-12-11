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

#ifdef __cplusplus
extern "C" {
#endif

char g_dss_inst_path[CM_MAX_PATH_LEN] = {0};
typedef struct st_dss_conn_info {
    // protect connections
    latch_t conn_latch;
    uint32 conn_num;
    bool32 isinit;
    int32 timeout;  // - 1: never time out
} dss_conn_info_t;
static dss_conn_info_t g_dss_conn_info = {{0, 0, 0, 0, 0}, 0, CM_FALSE, 0};

void dss_conn_release(pointer_t thv_addr)
{
    dss_conn_t *conn = (dss_conn_t *)thv_addr;
    if (conn->pipe.link.uds.closed != CM_TRUE) {
        dss_destroy_vol_handle_sync(conn);
        dss_disconnect(conn);
        cm_latch_x(&g_dss_conn_info.conn_latch, 1, NULL);
        g_dss_conn_info.conn_num--;
        if (g_dss_conn_info.conn_num == 0) {
            dss_destroy();
        }
        cm_unlatch(&g_dss_conn_info.conn_latch, NULL);
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
    // establish connection
    status_t status = CM_ERROR;
    cm_latch_x(&g_dss_conn_info.conn_latch, 1, NULL);
    do {
        // avoid buffer leak when disconnect
        dss_free_packet_buffer(&conn->pack);
        status = dss_connect(dss_get_inst_path(), options, conn);
        DSS_BREAK_IFERR2(status, LOG_RUN_ERR_INHIBIT(LOG_INHIBIT_LEVEL1, "Dss client connet server failed."));
        uint32 max_open_file = DSS_MAX_OPEN_FILES;
        conn->proto_version = DSS_PROTO_VERSION;
        status = dss_cli_handshake(conn, max_open_file);
        DSS_BREAK_IFERR3(status, LOG_RUN_ERR_INHIBIT(LOG_INHIBIT_LEVEL1, "Dss client handshake to server failed."),
            dss_disconnect(conn));

        status = dss_init_vol_handle_sync(conn);
        DSS_BREAK_IFERR3(status, LOG_RUN_ERR_INHIBIT(LOG_INHIBIT_LEVEL1, "Dss client init vol handle failed."),
            dss_disconnect(conn));

        g_dss_conn_info.conn_num++;
    } while (0);
    cm_unlatch(&g_dss_conn_info.conn_latch, NULL);
    return status;
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
    do {
        ret = dss_try_conn(options, conn);
        if (ret == CM_SUCCESS) {
            break;
        }
        if (cm_get_os_error() == ENOENT) {
            break;
        }
    } while (timeout == DSS_CONN_NEVER_TIMEOUT);
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
        LOG_RUN_ERR("[DSS API] ABORT INFO : dss server stoped, application need restart.");
        cm_fync_logfile();
        dss_exit(1);
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
