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
 * dss_api_impl.c
 *
 *
 * IDENTIFICATION
 *    src/common_api/dss_api_impl.c
 *
 * -------------------------------------------------------------------------
 */

#include "dss_system.h"
#include "dss_copyfile.h"
#include "dss_defs.h"
#include "dss_diskgroup.h"
#include "dss_file.h"
#include "dss_file_def.h"
#include "dss_latch.h"
#include "dss_malloc.h"
#include "dss_session.h"
#include "dss_api_impl.h"

#ifdef __cplusplus
extern "C" {
#endif

status_t dss_apply_refresh_file_table(dss_conn_t *conn, dss_dir_t *dir);
status_t dss_apply_extending_file(dss_conn_t *conn, int32 handle, int32 size, bool32 is_read, int64 offset)
{
    uint64 fid;
    ftid_t ftid;
    int32 errcode = -1;
    char *errmsg = NULL;
    dss_packet_t *send_pack;
    dss_packet_t *ack_pack;
    dss_env_t *dss_env = dss_get_env();
    if (handle >= (int32)dss_env->max_open_file || handle < 0) {
        return CM_ERROR;
    }

    dss_file_context_t *context = &dss_env->files[handle];
    if (context->flag == DSS_FILE_CONTEXT_FLAG_FREE) {
        return CM_ERROR;
    }
    fid = context->fid;
    ftid = context->node->id;

    LOG_DEBUG_INF("Apply extending file:%s, handle:%d, curr size:%llu, curr written_size:%llu.", context->node->name,
        handle, context->node->size, context->node->written_size);
    // make up packet
    dss_init_set(&conn->pack);

    send_pack = &conn->pack;
    send_pack->head->cmd = DSS_CMD_EXTEND_FILE;
    send_pack->head->flags = 0;

    // 1. fid
    CM_RETURN_IFERR(dss_put_int64(send_pack, fid));
    // 2. ftid
    CM_RETURN_IFERR(dss_put_int64(send_pack, *(uint64 *)&ftid));
    // 3. offset
    CM_RETURN_IFERR(dss_put_int64(send_pack, (uint64)offset));
    // 4. size
    CM_RETURN_IFERR(dss_put_int32(send_pack, (uint32)size));
    // 5. vg name
    CM_RETURN_IFERR(dss_put_str(send_pack, context->vg_name));
    // 6. vgid
    CM_RETURN_IFERR(dss_put_int32(send_pack, context->vgid));
    // 7. is_read
    CM_RETURN_IFERR(dss_put_int32(send_pack, is_read));

    // send it and wait for ack
    ack_pack = &conn->pack;
    status_t ret = dss_call_ex(&conn->pipe, send_pack, ack_pack);
    DSS_RETURN_IFERR2(ret, LOG_RUN_ERR("Failed to send message when extend file."));

    // check return state
    if (ack_pack->head->result != CM_SUCCESS) {
        dss_cli_get_err(ack_pack, &errcode, &errmsg);
        DSS_THROW_ERROR_EX(errcode, "%s", errmsg);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

status_t dss_apply_refresh_file(dss_conn_t *conn, dss_file_context_t *context, dss_block_id_t blockid)
{
    int32 errcode = -1;
    char *errmsg = NULL;
    uint64 fid = context->fid;
    ftid_t ftid = context->node->id;

    // make up packet
    dss_init_set(&conn->pack);
    dss_packet_t *send_pack = &conn->pack;
    send_pack->head->cmd = DSS_CMD_REFRESH_FILE;
    send_pack->head->flags = 0;

    LOG_DEBUG_INF(
        "Apply refresh file:%s, curr size:%llu, refresh ft id:%llu, refresh entry id:%llu, refresh block id:%llu.",
        context->node->name, context->node->size, *(uint64 *)&ftid, *(uint64 *)&(context->node->entry),
        *(uint64 *)&blockid);
    // 1. fid
    CM_RETURN_IFERR(dss_put_int64(send_pack, fid));
    // 2. ftid
    CM_RETURN_IFERR(dss_put_int64(send_pack, *(uint64 *)&ftid));
    // 3. vg name
    CM_RETURN_IFERR(dss_put_str(send_pack, context->vg_name));
    // 4. vgid
    CM_RETURN_IFERR(dss_put_int32(send_pack, context->vgid));
    // 5. blockid
    CM_RETURN_IFERR(dss_put_int64(send_pack, *(uint64 *)&blockid));

    // send it and wait for ack
    dss_packet_t *ack_pack = &conn->pack;
    status_t status = dss_call_ex(&conn->pipe, send_pack, ack_pack);
    DSS_RETURN_IFERR2(status, LOG_RUN_ERR("Failed to send message when refresh file."));

    // check return state
    if (ack_pack->head->result != CM_SUCCESS) {
        dss_cli_get_err(ack_pack, &errcode, &errmsg);
        DSS_THROW_ERROR_EX(errcode, "%s", errmsg);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

status_t dss_apply_refresh_volume(dss_conn_t *conn, dss_file_context_t *context, auid_t auid)
{
    dss_packet_t *send_pack;
    dss_packet_t *ack_pack;
    int32 errcode = -1;
    char *errmsg = NULL;

    // make up packet
    dss_init_set(&conn->pack);

    send_pack = &conn->pack;
    send_pack->head->cmd = DSS_CMD_REFRESH_VOLUME;
    send_pack->head->flags = 0;

    // 1. volume id
    uint32 volumeid = ((uint32)(auid.volume));
    CM_RETURN_IFERR(dss_put_int32(send_pack, volumeid));
    // 2. vg name
    CM_RETURN_IFERR(dss_put_str(send_pack, context->vg_name));
    // 3. vgid
    CM_RETURN_IFERR(dss_put_int32(send_pack, context->vgid));

    // send it and wait for ack
    ack_pack = &conn->pack;
    CM_RETURN_IFERR(dss_call_ex(&conn->pipe, send_pack, ack_pack));

    // check return state
    if (ack_pack->head->result != CM_SUCCESS) {
        dss_cli_get_err(ack_pack, &errcode, &errmsg);
        DSS_THROW_ERROR_EX(errcode, "%s", errmsg);
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

status_t dss_refresh_volume_handle(dss_conn_t *conn, dss_file_context_t *context, auid_t auid)
{
    dss_vg_info_item_t *vg_item = context->vg_item;
    if (vg_item->dss_ctrl->volume.defs[auid.volume].flag == VOLUME_FREE) {
        LOG_DEBUG_ERR("Refresh volume failed,vg:%s, volumeid:%u.", context->vg_name, auid.volume);
        return CM_ERROR;
    }
    status_t status;
    int cli_flags = DSS_CLI_OPEN_FLAG;
    dss_cli_vg_handles_t *cli_vg_handles = (dss_cli_vg_handles_t *)(conn->cli_vg_handles);
    dss_simple_volume_t *simple_vol = &cli_vg_handles->vg_vols[vg_item->id].volume_handle[auid.volume];
    status = dss_open_simple_volume(vg_item->dss_ctrl->volume.defs[auid.volume].name, cli_flags, simple_vol);
    if (status != CM_SUCCESS) {
        LOG_DEBUG_ERR("Open volume failed,vg:%s, volumeid:%u.", context->vg_name, auid.volume);
        return CM_ERROR;
    }

    simple_vol->id = auid.volume;
    simple_vol->version = vg_item->dss_ctrl->volume.defs[auid.volume].version;
    LOG_DEBUG_INF("The client refresh volume:(id:%u, handle:%d) and open.", simple_vol->id, simple_vol->handle);
    return CM_SUCCESS;
}

status_t dss_reopen_volume_handle(dss_conn_t *conn, dss_file_context_t *context, auid_t auid)
{
    dss_vg_info_item_t *vg_item = context->vg_item;

    status_t status;
    int cli_flags = DSS_CLI_OPEN_FLAG;
    dss_cli_vg_handles_t *cli_vg_handles = (dss_cli_vg_handles_t *)(conn->cli_vg_handles);
    dss_simple_volume_t *simple_vol = &cli_vg_handles->vg_vols[vg_item->id].volume_handle[auid.volume];
    dss_close_simple_volume(simple_vol);

    status = dss_open_simple_volume(vg_item->dss_ctrl->volume.defs[auid.volume].name, cli_flags, simple_vol);
    if (status != CM_SUCCESS) {
        LOG_DEBUG_ERR("Open volume failed,vg:%s, volumeid:%u.", context->vg_name, auid.volume);
        return CM_ERROR;
    }

    simple_vol->id = auid.volume;
    simple_vol->version = vg_item->dss_ctrl->volume.defs[auid.volume].version;
    LOG_DEBUG_INF("The client reopen volume:(id:%u, handle:%d) and open.", simple_vol->id, simple_vol->handle);
    return CM_SUCCESS;
}

status_t dss_lock_vg_s(dss_vg_info_item_t *vg_item, dss_session_t *session)
{
    dss_latch_offset_t latch_offset;
    latch_offset.type = DSS_LATCH_OFFSET_SHMOFFSET;
    latch_offset.offset.shm_offset = dss_get_vg_latch_shm_offset(vg_item);
    return dss_cli_lock_shm_meta_s(session, &latch_offset, vg_item->vg_latch, NULL);
}

#define DSS_LOCK_VG_META_S_RETURN_ERROR(vg_item, session, latch) \
    do {                                                         \
        if (dss_lock_vg_s((vg_item), (session)) != CM_SUCCESS) { \
            if ((latch) != NULL) {                               \
                dss_unlatch((latch));                            \
            }                                                    \
            return CM_ERROR;                                     \
        }                                                        \
    } while (0)

#define DSS_LOCK_VG_META_S_RETURN_NULL(vg_item, session, latch) \
    do {                                                        \
        if (dss_lock_vg_s(vg_item, session) != CM_SUCCESS) {    \
            if ((latch) != NULL) {                              \
                dss_unlatch(latch);                             \
            }                                                   \
            return NULL;                                        \
        }                                                       \
    } while (0)

#define DSS_UNLOCK_VG_META_S(vg_item, session) dss_unlock_shm_meta((session), (vg_item)->vg_latch)

status_t dss_apply_refresh_file_table(dss_conn_t *conn, dss_dir_t *dir)
{
    dss_packet_t *send_pack;
    dss_packet_t *ack_pack;
    int32 errcode = -1;
    char *errmsg = NULL;
    dss_block_id_t blockid;

    blockid = dir->cur_ftid;
    blockid.item = 0;
    // make up packet
    dss_init_set(&conn->pack);

    send_pack = &conn->pack;
    send_pack->head->cmd = DSS_CMD_REFRESH_FILE_TABLE;
    send_pack->head->flags = 0;

    // 1. blockid
    DSS_RETURN_IF_ERROR(dss_put_int64(send_pack, *(uint64 *)&blockid));
    // 2. vg name
    DSS_RETURN_IF_ERROR(dss_put_str(send_pack, dir->vg_item->vg_name));
    // 3. vgid
    DSS_RETURN_IF_ERROR(dss_put_int32(send_pack, dir->vg_item->id));

    // send it and wait for ack
    ack_pack = &conn->pack;
    DSS_RETURN_IF_ERROR(dss_call_ex(&conn->pipe, send_pack, ack_pack));

    // check return state
    if (ack_pack->head->result != CM_SUCCESS) {
        dss_cli_get_err(ack_pack, &errcode, &errmsg);
        DSS_THROW_ERROR_EX(errcode, "%s", errmsg);
        return CM_ERROR;
    }

    LOG_DEBUG_INF("Apply to refresh file table blockid:%llu, vgid:%u, vg name:%s.", DSS_ID_TO_U64(blockid),
        dir->vg_item->id, dir->vg_item->vg_name);

    return CM_SUCCESS;
}

static inline void dss_init_conn(dss_conn_t *conn)
{
    conn->flag = CM_FALSE;
    conn->cli_vg_handles = NULL;
    conn->session = NULL;
}

status_t dss_alloc_conn(dss_conn_t **conn)
{
    dss_conn_t *_conn = (dss_conn_t *)cm_malloc_align(DSSAPI_BLOCK_SIZE, sizeof(dss_conn_t));
    if (_conn != NULL) {
        dss_init_conn(_conn);
        *conn = _conn;
        return CM_SUCCESS;
    }

    return CM_ERROR;
}

void dss_free_conn(dss_conn_t *conn)
{
    DSS_FREE_POINT(conn);
    return;
}

static status_t dss_check_url_format(const char *url, text_t *uds)
{
    uint32 len = (uint32)strlen(url);
    if (len <= uds->len) {
        return CM_ERROR;
    }

    return (cm_strcmpni(url, uds->str, uds->len) != 0) ? CM_ERROR : CM_SUCCESS;
}

status_t dss_connect(const char *server_locator, dss_conn_opt_t options, char *user_name, dss_conn_t *conn)
{
    if (server_locator == NULL) {
        DSS_THROW_ERROR(ERR_DSS_UDS_INVALID_URL, "NULL", 0);
        return CM_ERROR;
    }

    if ((conn->flag == CM_TRUE) && (conn->pipe.link.uds.closed == CM_FALSE)) {
        return CM_SUCCESS;
    }

    conn->flag = CM_FALSE;
    text_t uds = {"UDS:", 4};
    if (dss_check_url_format(server_locator, &uds) != CM_SUCCESS) {
        DSS_THROW_ERROR(ERR_DSS_UDS_INVALID_URL, server_locator, strlen(server_locator));
        return ERR_DSS_UDS_INVALID_URL;
    }
    conn->cli_vg_handles = NULL;
    conn->pipe.options = 0;
    conn->pipe.connect_timeout = DSS_UDS_CONNECT_TIMEOUT;
    conn->pipe.socket_timeout = DSS_UDS_SOCKET_TIMEOUT;
    conn->pipe.link.uds.sock = CS_INVALID_SOCKET;
    conn->pipe.link.uds.closed = CM_TRUE;
    conn->pipe.type = CS_TYPE_DOMAIN_SCOKET;
    conn->session = NULL;
    status_t ret = cs_connect_ex(
        server_locator, &conn->pipe, NULL, (const char *)(server_locator + uds.len), (const char *)CM_NULL_TEXT.str);
    if (ret != CM_SUCCESS) {
        LOG_DEBUG_ERR("connect server failed, uds path:%s", server_locator);
        return ret;
    }
    dss_init_packet(&conn->pack, conn->pipe.options);

    conn->flag = CM_TRUE;

    return CM_SUCCESS;
}

void dss_disconnect(dss_conn_t *conn)
{
    if (conn->flag == CM_TRUE) {
        cs_disconnect(&conn->pipe);
        dss_free_packet_buffer(&conn->pack);
        conn->flag = CM_FALSE;
    }

    return;
}

status_t dss_init_vol_handle_sync(dss_conn_t *conn)
{
    if (!conn->flag) {
        return CM_ERROR;
    }

    if (conn->cli_vg_handles) {
        return CM_SUCCESS;
    }

    conn->cli_vg_handles = cm_malloc(sizeof(dss_cli_vg_handles_t));
    if (conn->cli_vg_handles == NULL) {
        return CM_ERROR;
    }

    status_t status;
    dss_cli_vg_handles_t *cli_vg_handles = (dss_cli_vg_handles_t *)(conn->cli_vg_handles);

    int cli_flags = DSS_CLI_OPEN_FLAG;
    for (uint32 i = 0; i < g_vgs_info->group_num; i++) {
        for (uint32 vid = 0; vid < DSS_MAX_VOLUMES; ++vid) {
            cli_vg_handles->vg_vols[i].volume_handle[vid].handle = DSS_INVALID_HANDLE;
            cli_vg_handles->vg_vols[i].volume_handle[vid].unaligned_handle = DSS_INVALID_HANDLE;
            cli_vg_handles->vg_vols[i].volume_handle[vid].id = vid;
        }

        status = dss_init_vol_handle(&g_vgs_info->volume_group[i], cli_flags, &cli_vg_handles->vg_vols[i]);
        if (status != CM_SUCCESS) {
            for (int32 j = (int32)(i - 1); j >= 0; j--) {
                dss_destroy_vol_handle(&g_vgs_info->volume_group[j], &cli_vg_handles->vg_vols[j], DSS_MAX_VOLUMES);
            }

            return status;
        }
    }

    cli_vg_handles->group_num = g_vgs_info->group_num;
    return CM_SUCCESS;
}

static status_t dss_get_home_core(dss_packet_t *send_pack, dss_packet_t *ack_pack, char **home)
{
    int32 errcode = -1;
    char *errmsg = NULL;

    // check return state
    if (ack_pack->head->result != CM_SUCCESS) {
        dss_cli_get_err(ack_pack, &errcode, &errmsg);
        DSS_THROW_ERROR_EX(errcode, "%s", errmsg);
        return CM_ERROR;
    }

    text_t extra_info = CM_NULL_TEXT;
    dss_init_get(ack_pack);
    if (dss_get_text(ack_pack, &extra_info) != CM_SUCCESS) {
        DSS_THROW_ERROR(ERR_DSS_CLI_EXEC_FAIL, dss_get_cmd_desc(DSS_CMD_GET_HOME), "get home info connect error");
        return CM_ERROR;
    }
    if (extra_info.len == 0 || extra_info.len >= DSS_MAX_PATH_BUFFER_SIZE) {
        DSS_THROW_ERROR(ERR_DSS_CLI_EXEC_FAIL, dss_get_cmd_desc(DSS_CMD_GET_HOME), "get home info length error");
        return CM_ERROR;
    }
    char *home_str = extra_info.str;
    home_str[extra_info.len] = '\0';
    *home = home_str;
    LOG_DEBUG_INF("Client get home is %s.", home_str);
    return CM_SUCCESS;
}

status_t dss_get_home_sync(dss_conn_t *conn, char **home)
{
    dss_packet_t *send_pack = NULL;
    dss_packet_t *ack_pack = NULL;

    // make up packet
    dss_init_packet(&conn->pack, conn->pipe.options);
    dss_init_set(&conn->pack);

    send_pack = &conn->pack;
    send_pack->head->cmd = DSS_CMD_GET_HOME;
    send_pack->head->flags = 0;
    // send it and wait for ack
    ack_pack = &conn->pack;
    CM_RETURN_IFERR(dss_call_ex(&conn->pipe, send_pack, ack_pack));

    return dss_get_home_core(send_pack, ack_pack, home);
}

status_t dss_set_session_sync(dss_conn_t *conn)
{
    dss_packet_t *send_pack = NULL;
    dss_packet_t *ack_pack = NULL;
    int32 errcode = -1;
    char *errmsg = NULL;

    // make up packet
    dss_init_packet(&conn->pack, conn->pipe.options);
    dss_init_set(&conn->pack);

    send_pack = &conn->pack;
    send_pack->head->cmd = DSS_CMD_SET_SESSIONID;
    send_pack->head->flags = 0;

    dss_cli_info cli_info;
    cli_info.cli_pid = cm_sys_pid();
    cli_info.start_time = cm_sys_process_start_time(cli_info.cli_pid);
    LOG_DEBUG_INF("The process start time is:%lld.", cli_info.start_time);

    errno_t err;
    err = strcpy_s(cli_info.process_name, sizeof(cli_info.process_name), cm_sys_program_name());
    if (err != EOK) {
        LOG_DEBUG_ERR("System call strcpy_s error %d.", errcode);
        return CM_ERROR;
    }

    CM_RETURN_IFERR(dss_put_data(send_pack, &cli_info, sizeof(cli_info)));

    ack_pack = &conn->pack;
    CM_RETURN_IFERR(dss_call_ex(&conn->pipe, send_pack, ack_pack));

    if (ack_pack->head->result != CM_SUCCESS) {
        dss_cli_get_err(ack_pack, &errcode, &errmsg);
        DSS_THROW_ERROR_EX(errcode, "%s", errmsg);
        return CM_ERROR;
    }

    text_t extra_info = CM_NULL_TEXT;
    uint32 sid = DSS_INVALID_SESSIONID;
    dss_init_get(ack_pack);
    if (dss_get_text(ack_pack, &extra_info) != CM_SUCCESS || extra_info.len != sizeof(uint32)) {
        LOG_DEBUG_ERR("get sid info connect error");
        return ERR_DSS_CLI_EXEC_FAIL;
    }

    sid = *(uint32 *)extra_info.str;
    dss_env_t *dss_env = dss_get_env();

    uint32 max_cfg_sess = dss_env->inst_cfg.params.cfg_session_num;
    if (dss_env->inst_cfg.params.inst_cnt > 1) {
        max_cfg_sess += dss_env->inst_cfg.params.channel_num + dss_env->inst_cfg.params.work_thread_cnt;
    }

    if (sid >= max_cfg_sess) {
        LOG_DEBUG_ERR("sid error");
        return ERR_DSS_SESSION_INVALID_ID;
    }

    dss_session_t *sessions = (dss_session_t *)(dss_env->session);
    conn->session = &(sessions[sid]);

    return CM_SUCCESS;
}

// NOTE:just for dsscmd because not support many threads in one process.
status_t dss_connect_ex(const char *server_locator, dss_conn_opt_t options, char *user_name, dss_conn_t *conn)
{
    status_t status;
    dss_env_t *dss_env = dss_get_env();
    dss_init_conn(conn);
    status = dss_connect(server_locator, options, user_name, conn);
    if (status != CM_SUCCESS) {
        LOG_DEBUG_ERR("Failed to connect to DSS server via server locator:%s.", server_locator);
        return status;
    }

    char *home = NULL;
    status = dss_get_home_sync(conn, &home);
    if (status != CM_SUCCESS) {
        LOG_DEBUG_ERR("Failed to read DSS_INSTANCE start up dir.");
        dss_disconnect(conn);
        return status;
    }

    dss_latch_x(&dss_env->conn_latch);

    status = dss_init(DSS_DEFAULT_OPEN_FILES_NUM, home);
    if (status != CM_SUCCESS) {
        dss_unlatch(&dss_env->conn_latch);
        LOG_DEBUG_ERR("Failed to init env.");
        dss_disconnect(conn);
        return status;
    }

    status = dss_set_session_sync(conn);
    if (status != CM_SUCCESS) {
        dss_unlatch(&dss_env->conn_latch);
        LOG_DEBUG_ERR("Failed to initialize session.");
        dss_disconnect(conn);
        return status;
    }

    status = dss_init_vol_handle_sync(conn);
    if (status != CM_SUCCESS) {
        dss_unlatch(&dss_env->conn_latch);
        LOG_DEBUG_ERR("Failed to initialize volume handles.");
        dss_disconnect(conn);
        return status;
    }

    dss_env->conn_count++;
    dss_unlatch(&dss_env->conn_latch);

    return CM_SUCCESS;
}

void dss_disconnect_ex(dss_conn_t *conn)
{
    dss_env_t *dss_env = dss_get_env();

    dss_destroy_vol_handle_sync(conn);
    dss_disconnect(conn);
    dss_latch_x(&dss_env->conn_latch);
    if (dss_env->conn_count > 0) {
        dss_env->conn_count--;
    }

    if (dss_env->conn_count == 0) {
        dss_destroy();
    }
    uint32 count = dss_env->conn_count;
    dss_unlatch(&dss_env->conn_latch);
    LOG_DEBUG_INF("Remain conn count:%u when disconnect.", count);

    return;
}

status_t dss_make_dir_impl(dss_conn_t *conn, const char *parent, const char *dir_name)
{
    dss_packet_t *send_pack;
    dss_packet_t *ack_pack;
    int32 errcode = -1;
    char *errmsg = NULL;

    LOG_DEBUG_INF("dss make dir entry, parent:%s, dir_name:%s", parent, dir_name);

    // make up packet
    dss_init_set(&conn->pack);

    send_pack = &conn->pack;
    send_pack->head->cmd = DSS_CMD_MKDIR;
    send_pack->head->flags = 0;

    // 1. parent
    DSS_RETURN_IF_ERROR(dss_check_device_path(parent));
    DSS_RETURN_IF_ERROR(dss_put_str(send_pack, parent));
    // 2. dir_name
    DSS_RETURN_IF_ERROR(dss_check_name(dir_name));
    DSS_RETURN_IF_ERROR(dss_put_str(send_pack, dir_name));

    // send it and wait for ack
    ack_pack = &conn->pack;
    DSS_RETURN_IF_ERROR(dss_call_ex(&conn->pipe, send_pack, ack_pack));

    // check return state
    if (ack_pack->head->result != CM_SUCCESS) {
        dss_cli_get_err(ack_pack, &errcode, &errmsg);
        DSS_THROW_ERROR_EX(errcode, "%s", errmsg);
        return CM_ERROR;
    }
    LOG_DEBUG_INF("dss make dir leave");
    return CM_SUCCESS;
}

status_t dss_remove_dir_impl(dss_conn_t *conn, const char *dir, bool recursive)
{
    dss_packet_t *send_pack;
    dss_packet_t *ack_pack;
    int32 errcode = -1;
    char *errmsg = NULL;

    LOG_DEBUG_INF("dss remove dir entry, dir:%s, recursive:%d", dir, recursive);

    // make up packet
    dss_init_set(&conn->pack);

    send_pack = &conn->pack;
    send_pack->head->cmd = DSS_CMD_RMDIR;
    send_pack->head->flags = 0;

    // 1. dir_name
    DSS_RETURN_IF_ERROR(dss_check_device_path(dir));
    DSS_RETURN_IF_ERROR(dss_put_str(send_pack, dir));

    // 2. recursive -r
    DSS_RETURN_IF_ERROR(dss_put_int32(send_pack, recursive));

    // send it and wait for ack
    ack_pack = &conn->pack;
    DSS_RETURN_IF_ERROR(dss_call_ex(&conn->pipe, send_pack, ack_pack));

    // check return state
    if (ack_pack->head->result != CM_SUCCESS) {
        dss_cli_get_err(ack_pack, &errcode, &errmsg);
        DSS_THROW_ERROR_EX(errcode, "%s", errmsg);
        return CM_ERROR;
    }
    LOG_DEBUG_INF("dss remove dir leave");
    return CM_SUCCESS;
}

static dss_dir_t *dss_open_dir_impl_core(dss_conn_t *conn, const char *dir_path, dss_env_t *dss_env)
{
    char name[DSS_MAX_NAME_LEN];
    uint32_t beg_pos = 0;
    status_t status = dss_get_name_from_path(dir_path, &beg_pos, name);
    if (status != CM_SUCCESS) {
        LOG_DEBUG_ERR("Failed to get name from path %s,%d.", dir_path, status);
        return NULL;
    }

    if (name[0] == 0) {
        LOG_DEBUG_ERR("Failed to get name from path %s.", dir_path);
        return NULL;
    }

    gft_node_t *node = NULL;
    dss_vg_info_item_t *vg_item = dss_find_vg_item(name);
    if (vg_item == NULL) {
        LOG_DEBUG_ERR("Failed to find vg, %s.", name);
        DSS_THROW_ERROR(ERR_DSS_VG_NOT_EXIST, name);
        return NULL;
    }

    DSS_LOCK_VG_META_S_RETURN_NULL(vg_item, conn->session, NULL);
    dss_vg_info_item_t *dir_vg_item;
    dss_check_dir_output_t output_info = {&node, &dir_vg_item, NULL};
    status = dss_check_dir(dir_path, GFT_PATH, &output_info, CM_TRUE);
    if (status != CM_SUCCESS) {
        DSS_UNLOCK_VG_META_S(vg_item, conn->session);
        LOG_DEBUG_ERR("dss check dir failed, when open dir impl, dir_path:%s.", dir_path);
        return NULL;
    }
    if (dir_vg_item->id != vg_item->id) {
        DSS_UNLOCK_VG_META_S(vg_item, conn->session);
        vg_item = dir_vg_item;
        DSS_LOCK_VG_META_S_RETURN_NULL(vg_item, conn->session, NULL);
    }
    dss_dir_t *dir = (dss_dir_t *)cm_malloc(sizeof(dss_dir_t));
    if (dir == NULL) {
        DSS_UNLOCK_VG_META_S(vg_item, conn->session);
        LOG_DEBUG_ERR("Failed to malloc.");
        return NULL;
    }
    dir->cur_ftid = node->items.first;
    dir->vg_item = vg_item;
    dir->version = DSS_GET_ROOT_BLOCK(vg_item->dss_ctrl)->ft_block.common.version;
    dir->pftid = *(uint64 *)&node->id;
    DSS_UNLOCK_VG_META_S(vg_item, conn->session);

    LOG_DEBUG_INF("dss open dir leave");
    return dir;
}

dss_dir_t *dss_open_dir_impl(dss_conn_t *conn, const char *dir_path, bool32 refresh_recursive)
{
    if (dir_path == NULL) {
        return NULL;
    }
    LOG_DEBUG_INF("dss open dir entry, dir_path:%s", dir_path);

    dss_env_t *dss_env = dss_get_env();
    if (!dss_env->initialized) {
        return NULL;
    }

    // make up packet
    dss_init_set(&conn->pack);

    dss_packet_t *send_pack = &conn->pack;
    send_pack->head->cmd = DSS_CMD_OPEN_DIR;
    send_pack->head->flags = 0;

    // 1. PATH
    if (dss_check_device_path(dir_path) != CM_SUCCESS) {
        return NULL;
    }
    status_t status = dss_put_str(send_pack, dir_path);
    if (status != CM_SUCCESS) {
        return NULL;
    }
    status = dss_put_int32(send_pack, refresh_recursive);
    if (status != CM_SUCCESS) {
        return NULL;
    }
    // send it and wait for ack
    dss_packet_t *ack_pack = &conn->pack;
    status = dss_call_ex(&conn->pipe, send_pack, ack_pack);
    if (status != CM_SUCCESS) {
        LOG_RUN_ERR("Failed to send message when open path(%s).", dir_path);
        return NULL;
    }
    // check return state
    int32 errcode = -1;
    char *errmsg = NULL;
    if (ack_pack->head->result != CM_SUCCESS) {
        dss_cli_get_err(ack_pack, &errcode, &errmsg);
        DSS_THROW_ERROR_EX(errcode, "%s", errmsg);
        return NULL;
    }
    return dss_open_dir_impl_core(conn, dir_path, dss_env);
}

dss_dir_item_handle dss_read_dir_impl(dss_conn_t *conn, dss_dir_t *dir, bool32 skip_delete)
{
    if (!dir) {
        return NULL;
    }

    dss_env_t *dss_env = dss_get_env();
    if (!dss_env->initialized) {
        return NULL;
    }

    if (dss_cmp_auid(dir->cur_ftid, DSS_INVALID_ID64)) {
        return NULL;
    }

    status_t status = dss_apply_refresh_file_table(conn, dir);
    if (status != CM_SUCCESS) {
        LOG_DEBUG_ERR("Failed to apply to refresh file table.");
        return NULL;
    }

    DSS_LOCK_VG_META_S_RETURN_NULL(dir->vg_item, conn->session, NULL);

    gft_node_t *node = dss_get_ft_node_by_ftid(dir->vg_item, dir->cur_ftid, CM_FALSE, CM_FALSE);
    while (node != NULL) {
        dir->cur_ftid = node->next;
        dir->cur_node = *node;
        if (!skip_delete || node->flags != DSS_FT_NODE_FLAG_DEL) {
            DSS_UNLOCK_VG_META_S(dir->vg_item, conn->session);
            return (dss_dir_item_handle)&dir->cur_node;
        }
        if (dss_cmp_auid(dir->cur_ftid, DSS_INVALID_ID64)) {
            DSS_UNLOCK_VG_META_S(dir->vg_item, conn->session);
            return NULL;
        }
        DSS_UNLOCK_VG_META_S(dir->vg_item, conn->session);
        status = dss_apply_refresh_file_table(conn, dir);
        if (status != CM_SUCCESS) {
            LOG_DEBUG_ERR("Failed to apply to refresh file table.");
            return NULL;
        }
        DSS_LOCK_VG_META_S_RETURN_NULL(dir->vg_item, conn->session, NULL);
        node = dss_get_ft_node_by_ftid(dir->vg_item, dir->cur_ftid, CM_FALSE, CM_FALSE);
    }
    DSS_UNLOCK_VG_META_S(dir->vg_item, conn->session);
    return NULL;
}

status_t dss_close_dir_impl(dss_conn_t *conn, dss_dir_t *dir)
{
    dss_packet_t *send_pack;
    dss_packet_t *ack_pack;
    status_t status;
    int32 errcode = -1;
    char *errmsg = NULL;
    if (!dir || !dir->vg_item) {
        return CM_ERROR;
    }

    // close operation just free resource, no need check server if down.
    dss_env_t *dss_env = dss_get_env();
    CM_RETURN_IF_FALSE(dss_env->initialized);

    // make up packet
    dss_init_set(&conn->pack);
    send_pack = &conn->pack;
    send_pack->head->cmd = DSS_CMD_CLOSE_DIR;
    send_pack->head->flags = 0;

    // 1. pftid
    uint64 pftid = dir->pftid;
    status = dss_put_int64(send_pack, pftid);
    DSS_RETURN_IFERR2(status, DSS_FREE_POINT(dir));

    // 2. vg name
    status = dss_put_str(send_pack, dir->vg_item->vg_name);
    DSS_RETURN_IFERR2(status, DSS_FREE_POINT(dir));

    // 3. vgid
    status = dss_put_int32(send_pack, dir->vg_item->id);
    DSS_FREE_POINT(dir);
    DSS_RETURN_IF_ERROR(status);

    // send it and wait for ack
    ack_pack = &conn->pack;
    status = dss_call_ex(&conn->pipe, send_pack, ack_pack);
    DSS_RETURN_IFERR2(status, LOG_DEBUG_ERR("Failed to send message when close path."));
    // check return state
    if (ack_pack->head->result != CM_SUCCESS) {
        dss_cli_get_err(ack_pack, &errcode, &errmsg);
        DSS_THROW_ERROR_EX(errcode, "%s", errmsg);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

status_t dss_create_file_impl(dss_conn_t *conn, const char *file_path, int flag)
{
    dss_packet_t *send_pack;
    dss_packet_t *ack_pack;
    int32 errcode = -1;
    char *errmsg = NULL;

    LOG_DEBUG_INF("dss create file entry, file path:%s, flag:%d", file_path, flag);

    // make up packet
    dss_init_set(&conn->pack);

    send_pack = &conn->pack;
    send_pack->head->cmd = DSS_CMD_CREATE_FILE;
    send_pack->head->flags = 0;

    // 1. name
    DSS_RETURN_IF_ERROR(dss_check_device_path(file_path));
    DSS_RETURN_IF_ERROR(dss_put_str(send_pack, file_path));
    // 2. flag
    DSS_RETURN_IF_ERROR(dss_put_int32(send_pack, (uint32)flag));

    // send it and wait for ack
    ack_pack = &conn->pack;
    DSS_RETURN_IF_ERROR(dss_call_ex(&conn->pipe, send_pack, ack_pack));

    // check return state
    if (ack_pack->head->result != CM_SUCCESS) {
        dss_cli_get_err(ack_pack, &errcode, &errmsg);
        DSS_THROW_ERROR_EX(errcode, "%s", errmsg);
        return CM_ERROR;
    }

    LOG_DEBUG_INF("dss create file leave");
    return CM_SUCCESS;
}

status_t dss_remove_file_impl(dss_conn_t *conn, const char *file_path)
{
    dss_packet_t *send_pack;
    dss_packet_t *ack_pack;
    int32 errcode = -1;
    char *errmsg = NULL;
    LOG_DEBUG_INF("dss remove file entry, file path:%s", file_path);

    // make up packet
    dss_init_set(&conn->pack);

    send_pack = &conn->pack;
    send_pack->head->cmd = DSS_CMD_DELETE_FILE;
    send_pack->head->flags = 0;

    // 1. file_name
    DSS_RETURN_IF_ERROR(dss_check_device_path(file_path));
    DSS_RETURN_IF_ERROR(dss_put_str(send_pack, file_path));

    // send it and wait for ack
    ack_pack = &conn->pack;
    DSS_RETURN_IF_ERROR(dss_call_ex(&conn->pipe, send_pack, ack_pack));

    // check return state
    if (ack_pack->head->result != CM_SUCCESS) {
        dss_cli_get_err(ack_pack, &errcode, &errmsg);
        DSS_THROW_ERROR_EX(errcode, "%s", errmsg);
        return CM_ERROR;
    }

    LOG_DEBUG_INF("dss remove file leave");
    return CM_SUCCESS;
}

status_t dss_find_vg_by_file_path(const char *path, dss_vg_info_item_t **vg_item)
{
    dss_env_t *dss_env = dss_get_env();
    if (!dss_env->initialized) {
        DSS_THROW_ERROR(ERR_DSS_ENV_NOT_INITIALIZED);
        return CM_ERROR;
    }

    uint32_t beg_pos = 0;
    char vg_name[DSS_MAX_NAME_LEN];
    status_t status = dss_get_name_from_path(path, &beg_pos, vg_name);
    DSS_RETURN_IFERR2(status, LOG_DEBUG_ERR("Failed to get name from path:%s, status:%d.", path, status));

    *vg_item = dss_find_vg_item(vg_name);
    if (*vg_item == NULL) {
        LOG_DEBUG_ERR("Failed to find VG:%s.", vg_name);
        DSS_THROW_ERROR(ERR_DSS_VG_NOT_EXIST, vg_name);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static status_t dss_get_ftid_by_path_on_server(dss_conn_t *conn, const char *path, ftid_t *ftid, char *vg_name)
{
    dss_packet_t *send_pack;
    dss_packet_t *ack_pack;
    int32 errcode = -1;
    char *errmsg = NULL;

    LOG_DEBUG_INF("begin to get ftid by path: %s", path);
    dss_init_set(&conn->pack);
    send_pack = &conn->pack;
    send_pack->head->cmd = DSS_CMD_GET_FTID_BY_PATH;
    send_pack->head->flags = 0;

    DSS_RETURN_IF_ERROR(dss_put_str(send_pack, path));

    ack_pack = &conn->pack;
    DSS_RETURN_IF_ERROR(dss_call_ex(&conn->pipe, send_pack, ack_pack));

    if (ack_pack->head->result != CM_SUCCESS) {
        dss_cli_get_err(ack_pack, &errcode, &errmsg);
        DSS_THROW_ERROR_EX(errcode, "%s", errmsg);
        return CM_ERROR;
    }

    text_t extra_info = CM_NULL_TEXT;
    dss_init_get(ack_pack);
    if (dss_get_text(ack_pack, &extra_info) != CM_SUCCESS) {
        DSS_THROW_ERROR(ERR_DSS_CLI_EXEC_FAIL, dss_get_cmd_desc(DSS_CMD_GET_FTID_BY_PATH), "get result connect error");
        LOG_DEBUG_ERR("get result connect error.");
        return CM_ERROR;
    }
    if (extra_info.len == 0 || extra_info.len > sizeof(dss_find_node_t)) {
        DSS_THROW_ERROR(ERR_DSS_CLI_EXEC_FAIL, dss_get_cmd_desc(DSS_CMD_GET_FTID_BY_PATH), "get result length error");
        LOG_DEBUG_ERR("get result length error.");
        return CM_ERROR;
    }
    dss_find_node_t find_node = *(dss_find_node_t *)extra_info.str;
    *ftid = find_node.ftid;
    errno_t err = strncpy_sp(vg_name, DSS_MAX_NAME_LEN, find_node.vg_name, DSS_MAX_NAME_LEN);
    if (err != EOK) {
        DSS_THROW_ERROR(ERR_SYSTEM_CALL, err);
        return CM_ERROR;
    }

    LOG_DEBUG_INF("dss get node ftid: %llu, vg: %s by path: %s", DSS_ID_TO_U64(*ftid), vg_name, path);
    return CM_SUCCESS;
}

gft_node_t *dss_get_node_by_path_impl(dss_conn_t *conn, const char *path)
{
    ftid_t ftid;
    if (dss_check_device_path(path) != CM_SUCCESS) {
        return NULL;
    }
    char vg_name[DSS_MAX_NAME_LEN];
    if (dss_get_ftid_by_path_on_server(conn, path, &ftid, (char *)vg_name) != CM_SUCCESS) {
        return NULL;
    }
    dss_vg_info_item_t *vg_item = dss_find_vg_item(vg_name);
    if (vg_item == NULL) {
        LOG_DEBUG_ERR("Failed to find vg,vg name %s.", vg_name);
        DSS_THROW_ERROR(ERR_DSS_VG_NOT_EXIST, vg_name);
        return NULL;
    }

    DSS_LOCK_VG_META_S_RETURN_NULL(vg_item, conn->session, NULL);
    gft_node_t *node = dss_get_ft_node_by_ftid(vg_item, ftid, CM_FALSE, CM_FALSE);
    DSS_UNLOCK_VG_META_S(vg_item, conn->session);
    return node;
}

status_t dss_init_file_context(dss_file_context_t *context, gft_node_t *out_node, dss_vg_info_item_t *vg_item)
{
    context->flag = DSS_FILE_CONTEXT_FLAG_USED;
    context->offset = 0;
    context->next = DSS_INVALID_ID32;
    context->node = out_node;
    context->vg_item = vg_item;
    context->vgid = vg_item->id;
    context->fid = out_node->fid;
    context->vol_offset = 0;
    context->tid = cm_get_current_thread_id();
    if (strcpy_s(context->vg_name, DSS_MAX_NAME_LEN, vg_item->vg_name) != EOK) {
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

status_t dss_open_file_inner(dss_vg_info_item_t *vg_item, gft_node_t *ft_node, int *handle)
{
    dss_env_t *dss_env = dss_get_env();
    dss_latch_x(&dss_env->latch);
    if (dss_env->has_opened_files >= dss_env->max_open_file) {
        dss_unlatch(&dss_env->latch);
        LOG_DEBUG_ERR("The opened files has exceeded the max open file number.%u,%u.", dss_env->has_opened_files,
            dss_env->max_open_file);
        return CM_ERROR;
    }

    *handle = (int)dss_env->file_free_first;
    cm_assert(dss_env->file_free_first != DSS_INVALID_ID32);
    dss_file_context_t *context = &dss_env->files[*handle];
    uint32 next = context->next;

    status_t ret = dss_init_file_context(context, ft_node, vg_item);
    DSS_RETURN_IFERR2(ret, dss_unlatch(&dss_env->latch));
    dss_env->file_free_first = next;
    dss_env->has_opened_files++;
    dss_unlatch(&dss_env->latch);
    return CM_SUCCESS;
}

status_t dss_open_file_impl(dss_conn_t *conn, const char *file_path, int flag, int *handle)
{
    status_t status;
    dss_vg_info_item_t *vg_item = NULL;
    gft_node_t *ft_node = NULL;

    LOG_DEBUG_INF("dss begin to open file, file path:%s, flag:%d", file_path, flag);
    DSS_RETURN_IF_ERROR(dss_check_device_path(file_path));
    DSS_RETURN_IF_ERROR(dss_find_vg_by_file_path(file_path, &vg_item));
    DSS_RETURN_IF_ERROR(dss_open_file_on_server(conn, file_path, flag));
    DSS_LOCK_VG_META_S_RETURN_ERROR(vg_item, conn->session, NULL);
    do {
        dss_vg_info_item_t *file_vg_item = NULL;
        dss_check_dir_output_t output_info = {&ft_node, &file_vg_item, NULL};
        status = dss_check_dir(file_path, GFT_FILE, &output_info, CM_TRUE);
        if (status != CM_SUCCESS) {
            LOG_DEBUG_ERR("Failed to check dir when open file impl, errcode:%d.", cm_get_error_code());
            break;
        }
        if (file_vg_item->id != vg_item->id) {
            DSS_UNLOCK_VG_META_S(vg_item, conn->session);
            vg_item = file_vg_item;
            DSS_LOCK_VG_META_S_RETURN_ERROR(vg_item, conn->session, NULL);
        }
        status = dss_open_file_inner(vg_item, ft_node, handle);
    } while (0);
    DSS_UNLOCK_VG_META_S(vg_item, conn->session);

    if (status != CM_SUCCESS) {
        // Try to close the handle opened on the server to avoid resource leakage.
        // But here in theory it shouldn't depend on ft_node not being NULL
        if (ft_node != NULL) {
            (void)dss_close_file_on_server(conn, vg_item, ft_node->fid, ft_node->id);
        }
        return status;
    }
    LOG_DEBUG_INF("dss open file successfully, file_path:%s, flag:%d, handle:%d, fsize:%llu, fwritten_size:%llu",
        file_path, flag, *handle, ft_node->size, ft_node->written_size);
    return CM_SUCCESS;
}

static status_t dss_check_file_env(dss_conn_t *conn, int32 handle, int32 size, dss_file_context_t **context)
{
    if (size < 0) {
        LOG_DEBUG_ERR("File size is invalid:%d.", size);
        return CM_ERROR;
    }

    dss_env_t *dss_env = dss_get_env();
    if (!dss_env->initialized) {
        DSS_THROW_ERROR(ERR_DSS_ENV_NOT_INITIALIZED);
        LOG_DEBUG_ERR("dss env not initialized.");
        return CM_ERROR;
    }

    if (handle >= (int32)dss_env->max_open_file || handle < 0) {
        DSS_THROW_ERROR(
            ERR_DSS_INVALID_PARAM, "value of handle must be a positive integer and less than max_open_file.");
        LOG_DEBUG_ERR("File handle is invalid:%d.", handle);
        return CM_ERROR;
    }

    dss_file_context_t *file_cxt = &dss_env->files[handle];

    dss_latch_s(&file_cxt->latch);
    if (file_cxt->flag == DSS_FILE_CONTEXT_FLAG_FREE) {
        dss_unlatch(&file_cxt->latch);
        LOG_DEBUG_ERR("Failed to r/w, file is closed, handle:%d, context id:%u.", handle, file_cxt->id);
        return CM_ERROR;
    }

    CM_ASSERT(handle == (int32)file_cxt->id);

    if (file_cxt->node == NULL) {
        dss_unlatch(&file_cxt->latch);
        LOG_DEBUG_ERR("file node is null, handle:%d, context id:%u.", handle, file_cxt->id);
        return CM_ERROR;
    }

    dss_unlatch(&file_cxt->latch);

    *context = file_cxt;
    return CM_SUCCESS;
}

status_t dss_close_file_impl(dss_conn_t *conn, int handle)
{
    char *fname = NULL;

    LOG_DEBUG_INF("dss close file entry, handle:%d", handle);

    dss_file_context_t *context = NULL;
    DSS_RETURN_IF_ERROR(dss_check_file_env(conn, handle, 0, &context));

    dss_latch_x(&context->latch);
    fname = context->node->name;

    status_t ret = dss_close_file_on_server(conn, context->vg_item, context->fid, context->node->id);
    if (ret != CM_SUCCESS) {
        dss_unlatch(&context->latch);
        LOG_DEBUG_INF("Failed to fclose, handle:%d, fname:%s, fid:%llu.", handle, fname, context->fid);
        return ret;
    }
    context->flag = DSS_FILE_CONTEXT_FLAG_FREE;
    context->offset = 0;
    context->node = NULL;
    context->tid = 0;
    dss_unlatch(&context->latch);
    LOG_DEBUG_INF("Success to fclose, handle:%d, fname:%s, fid:%llu.", handle, fname, context->fid);

    /* release file context to freelist */
    dss_env_t *dss_env = dss_get_env();
    dss_latch_x(&dss_env->latch);
    context->next = dss_env->file_free_first;
    dss_env->file_free_first = context->id;
    dss_env->has_opened_files--;
    dss_unlatch(&dss_env->latch);
    return CM_SUCCESS;
}

status_t dss_exist_dir_or_file_impl(dss_conn_t *conn, const char *path, bool *result, uint8 cmd)
{
    dss_packet_t *send_pack;
    dss_packet_t *ack_pack;
    int32 errcode = -1;
    char *errmsg = NULL;

    LOG_DEBUG_INF("dss exits file entry, name:%s", path);

    // make up packet
    dss_init_set(&conn->pack);

    send_pack = &conn->pack;
    send_pack->head->cmd = cmd;
    send_pack->head->flags = 0;

    DSS_RETURN_IF_ERROR(dss_check_device_path(path));
    DSS_RETURN_IF_ERROR(dss_put_str(send_pack, path));

    // send it and wait for ack
    ack_pack = &conn->pack;
    DSS_RETURN_IF_ERROR(dss_call_ex(&conn->pipe, send_pack, ack_pack));

    // check return state
    if (ack_pack->head->result != CM_SUCCESS) {
        dss_cli_get_err(ack_pack, &errcode, &errmsg);
        DSS_THROW_ERROR_EX(errcode, "%s", errmsg);
        return CM_ERROR;
    }

    text_t extra_info = CM_NULL_TEXT;
    dss_init_get(ack_pack);
    if (dss_get_text(ack_pack, &extra_info) != CM_SUCCESS) {
        DSS_THROW_ERROR(ERR_DSS_CLI_EXEC_FAIL, dss_get_cmd_desc(cmd), "get result connect error");
        LOG_DEBUG_ERR("get result connect error.");
        return CM_ERROR;
    }
    if (extra_info.len == 0 || extra_info.len > sizeof(bool32)) {
        DSS_THROW_ERROR(ERR_DSS_CLI_EXEC_FAIL, dss_get_cmd_desc(cmd), "get result length error");
        LOG_DEBUG_ERR("get result length error.");
        return CM_ERROR;
    }
    *result = *(bool32 *)extra_info.str;

    LOG_DEBUG_INF("dss exits file or dir leave, name:%s, result:%d", path, *result);
    return CM_SUCCESS;
}

status_t dss_exist_file_impl(dss_conn_t *conn, const char *name, bool *result)
{
    return dss_exist_dir_or_file_impl(conn, name, result, DSS_CMD_EXIST_FILE);
}

static status_t dss_validate_seek_origin(int origin, int64 offset, dss_file_context_t *context, int64 *new_offset)
{
    if (origin == SEEK_SET) {
        if (offset > (int64)DSS_MAX_FILE_SIZE) {
            LOG_DEBUG_ERR("Invalid parameter offset:%lld, context offset:%lld.", offset, context->offset);
            return CM_ERROR;
        }
        *new_offset = offset;
    } else if (origin == SEEK_CUR) {
        if (offset > (int64)DSS_MAX_FILE_SIZE || context->offset > (int64)DSS_MAX_FILE_SIZE ||
            offset + context->offset > (int64)DSS_MAX_FILE_SIZE) {
            LOG_DEBUG_ERR("Invalid parameter offset:%lld, context offset:%lld.", offset, context->offset);
            return CM_ERROR;
        }
        *new_offset = context->offset + offset;
    } else if (origin == SEEK_END || origin == DSS_SEEK_MAXWR) {  // for get alloced size, or actual used size
        if (offset > 0) {
            LOG_DEBUG_ERR("Invalid parameter offset:%lld, context offset:%lld.", offset, context->offset);
            return CM_ERROR;
        }
    } else {
        LOG_DEBUG_ERR("Invalid parameter origin:%d, when seek file.", origin);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

status_t dss_exist_dir_impl(dss_conn_t *conn, const char *name, bool *result)
{
    return dss_exist_dir_or_file_impl(conn, name, result, DSS_CMD_EXIST_DIR);
}

int64 dss_seek_file_impl_core(dss_rw_param_t *param, int64 offset, int origin)
{
    status_t status;
    int64 new_offset = 0;
    int64 size;
    bool32 need_refresh = ((origin == SEEK_END) || (origin == DSS_SEEK_MAXWR));

    dss_conn_t *conn = param->conn;
    int handle = param->handle;
    dss_file_context_t *context = param->context;

    CM_ASSERT(handle == (int32)context->id);

    DSS_RETURN_IF_ERROR(dss_validate_seek_origin(origin, offset, context, &new_offset));
    DSS_LOCK_VG_META_S_RETURN_ERROR(context->vg_item, conn->session, NULL);
    size = (int64)context->node->size;
    DSS_UNLOCK_VG_META_S(context->vg_item, conn->session);

    if (new_offset > size || need_refresh) {
        dss_block_id_t blockid;
        dss_set_blockid(&blockid, DSS_INVALID_ID64);
        status = dss_apply_refresh_file(conn, context, blockid);
        DSS_RETURN_IFERR2(status, LOG_DEBUG_ERR("Failed to apply refresh file,fid:%llu.", context->fid));

        DSS_LOCK_VG_META_S_RETURN_ERROR(context->vg_item, conn->session, NULL);
        size = (int64)context->node->size;
        DSS_UNLOCK_VG_META_S(context->vg_item, conn->session);

        if (offset > size) {
            LOG_DEBUG_ERR("Invalid parameter offset is greater than size, offset:%lld, new_offset:%lld,"
                          " file size:%llu, vgid:%u, fid:%llu, node fid:%llu, need_refresh:%d.",
                offset, new_offset, context->node->size, context->vg_item->id, context->fid, context->node->fid,
                need_refresh);
            DSS_THROW_ERROR(ERR_DSS_FILE_SEEK, context->vg_item->id, context->fid, offset, context->node->size);
            return CM_ERROR;
        }

        if (need_refresh) {
            new_offset = size + offset;
#ifdef OPENGAUSS
            if (DSS_SEEK_MAXWR == origin) {
                new_offset = (int64)context->node->written_size;
                LOG_DEBUG_INF("Success to seek(origin:%d) file:%s, offset:%lld, fsize:%llu, written_size:%llu.", origin,
                    context->node->name, new_offset, context->node->size, context->node->written_size);
            }
#endif
        }
        LOG_DEBUG_INF("Apply to refresh file, offset:%lld, size:%lld, need_refresh:%d.", offset, size, need_refresh);
    }
    if (new_offset == 0) {
        context->vol_offset = 0;
    }
    context->offset = new_offset;
    return new_offset;
}

void dss_init_rw_param(
    dss_rw_param_t *param, dss_conn_t *conn, int handle, dss_file_context_t *ctx, int64 offset, bool32 atomic)
{
    param->conn = conn;
    param->handle = handle;
    param->dss_env = dss_get_env();
    param->context = ctx;
    param->offset = offset;
    param->atom_oper = atomic;
}

int64 dss_seek_file_impl(dss_conn_t *conn, int handle, int64 offset, int origin)
{
    LOG_DEBUG_INF("dss seek file entry, handle:%d, offset:%lld, origin:%d", handle, offset, origin);

    dss_file_context_t *context = NULL;
    DSS_RETURN_IF_ERROR(dss_check_file_env(conn, handle, 0, &context));

    dss_rw_param_t param;

    dss_latch_x(&context->latch);
    dss_init_rw_param(&param, conn, handle, context, context->offset, DSS_FALSE);
    int64 new_offset = dss_seek_file_impl_core(&param, offset, origin);
    dss_unlatch(&context->latch);

    LOG_DEBUG_INF("dss seek file leave, new_offset:%lld", new_offset);
    return new_offset;
}

typedef struct str_files_rw_ctx {
    dss_conn_t *conn;
    dss_file_context_t *file_ctx;
    dss_env_t *env;
    int32 handle;
    int32 size;
    bool32 read;
    int64 offset;
} files_rw_ctx_t;

static status_t dss_alloc_block_core(
    files_rw_ctx_t rw_ctx, dss_fs_block_t *entry_fs_block, uint32 block_count, dss_fs_block_t **second_block)
{
    status_t status;
    dss_conn_t *conn = rw_ctx.conn;
    dss_file_context_t *context = rw_ctx.file_ctx;
    int32 handle = rw_ctx.handle;
    int32 size = rw_ctx.size;
    bool32 is_read = rw_ctx.read;
    dss_vg_info_item_t *vg_item = context->vg_item;
    dss_block_id_t second_block_id = entry_fs_block->bitmap[block_count];
    if (dss_cmp_blockid(second_block_id, DSS_INVALID_ID64)) {
        // allocate block
        DSS_UNLOCK_VG_META_S(context->vg_item, conn->session);

        if (!is_read) {
            status = dss_apply_extending_file(conn, handle, size, is_read, rw_ctx.offset);
            DSS_RETURN_IFERR2(status, LOG_RUN_ERR("Failed to extend file entry fs block."));
        }

        status = dss_apply_refresh_file(conn, context, entry_fs_block->head.id);
        DSS_RETURN_IFERR2(status, LOG_RUN_ERR("Failed to refresh entry fs block."));
        DSS_LOCK_VG_META_S_RETURN_ERROR(context->vg_item, conn->session, NULL);
        second_block_id = entry_fs_block->bitmap[block_count];
        *second_block = (dss_fs_block_t *)dss_find_block_in_shm(
            vg_item, second_block_id, DSS_BLOCK_TYPE_FS, DSS_FALSE, NULL, CM_FALSE);
        if ((*second_block) == NULL) {
            DSS_UNLOCK_VG_META_S(context->vg_item, conn->session);
            status = dss_apply_refresh_file(conn, context, second_block_id);
            DSS_RETURN_IFERR2(status, LOG_RUN_ERR("Failed to refresh second fs block."));
            DSS_LOCK_VG_META_S_RETURN_ERROR(context->vg_item, conn->session, NULL);
            *second_block = (dss_fs_block_t *)dss_find_block_in_shm(
                vg_item, second_block_id, DSS_BLOCK_TYPE_FS, DSS_FALSE, NULL, CM_FALSE);
            if ((*second_block) == NULL) {
                DSS_UNLOCK_VG_META_S(context->vg_item, conn->session);
                DSS_THROW_ERROR(ERR_DSS_INVALID_ID, "fs_block", *(uint64 *)&second_block_id);
                LOG_RUN_ERR("Failed to find block:%llu in mem.", DSS_ID_TO_U64(second_block_id));
                return CM_ERROR;
            }
        }
    } else {
        *second_block = (dss_fs_block_t *)dss_find_block_in_shm(
            vg_item, second_block_id, DSS_BLOCK_TYPE_FS, DSS_FALSE, NULL, CM_FALSE);
        if ((*second_block) == NULL) {
            DSS_UNLOCK_VG_META_S(context->vg_item, conn->session);

            status = dss_apply_refresh_file(conn, context, second_block_id);
            if (status != CM_SUCCESS) {
                LOG_RUN_ERR("Failed to refresh file.");
                return CM_ERROR;
            }

            DSS_LOCK_VG_META_S_RETURN_ERROR(context->vg_item, conn->session, NULL);
            *second_block = (dss_fs_block_t *)dss_find_block_in_shm(
                vg_item, second_block_id, DSS_BLOCK_TYPE_FS, DSS_FALSE, NULL, CM_FALSE);
            if ((*second_block) == NULL) {
                DSS_UNLOCK_VG_META_S(context->vg_item, conn->session);
                LOG_RUN_ERR("Failed to find block:%llu in mem.", DSS_ID_TO_U64(second_block_id));
                return CM_ERROR;
            }
        }
    }
    return CM_SUCCESS;
}

// get secondary FSB, index of AU within FSB and offset within AU,
// essentially a wrapper around dss_get_fs_block_info_by_offset()
static status_t dss_alloc_block(files_rw_ctx_t rw_ctx, dss_fs_block_t *entry_fs_block, dss_fs_block_t **scnd_block,
    uint32 *au_count, uint32 *au_offset)
{
    uint32 block_count = 0;
    uint32 block_au_count;
    dss_conn_t *conn = rw_ctx.conn;
    dss_file_context_t *context = rw_ctx.file_ctx;
    dss_vg_info_item_t *vg_item = context->vg_item;

    uint64 au_size = dss_get_vg_au_size(vg_item->dss_ctrl);
    status_t ret = dss_get_fs_block_info_by_offset(rw_ctx.offset, au_size, &block_count, &block_au_count, au_offset);
    if (ret != CM_SUCCESS) {
        DSS_UNLOCK_VG_META_S(context->vg_item, conn->session);
        LOG_RUN_ERR("The offset(%lld) is not correct,real block count:%u.", rw_ctx.offset, block_count);
        return CM_ERROR;
    }

    dss_fs_block_t *second_block = NULL;
    DSS_RETURN_IF_ERROR(dss_alloc_block_core(rw_ctx, entry_fs_block, block_count, &second_block));
    *au_count = block_au_count;
    *scnd_block = second_block;
    return CM_SUCCESS;
}

static status_t dss_check_refresh_file(
    dss_env_t *dss_env, dss_conn_t *conn, dss_file_context_t *context, bool32 is_read, int32 *total_size)
{
    uint32 tmp_total_size = (uint32)(*total_size);
#ifdef OPENGAUSS
    bool32 need_refresh = tmp_total_size > context->node->written_size;
#else
    bool32 need_refresh = tmp_total_size > context->node->size;
#endif

    if (is_read && need_refresh) {
        DSS_UNLOCK_VG_META_S(context->vg_item, conn->session);
        dss_block_id_t blockid;
        dss_set_blockid(&blockid, DSS_INVALID_ID64);
        status_t status = dss_apply_refresh_file(conn, context, blockid);
        if (status != CM_SUCCESS) {
            LOG_RUN_ERR("Failed to apply refresh file:%s, fid:%llu.", context->node->name, context->fid);
            return CM_ERROR;
        }
        DSS_LOCK_VG_META_S_RETURN_ERROR(context->vg_item, conn->session, NULL);
        if (tmp_total_size > context->node->size) {
            *total_size = (int32)context->node->size;
        }
    }

    return CM_SUCCESS;
}

#ifdef OPENGAUSS
static status_t dss_update_written_size(dss_env_t *dss_env, dss_conn_t *conn, dss_file_context_t *context, int64 offset)
{
    int32 errcode = -1;
    char *errmsg = NULL;
    uint64 fid = context->fid;
    ftid_t ftid = context->node->id;

    // make up packet
    dss_init_set(&conn->pack);

    dss_packet_t *send_pack = &conn->pack;
    send_pack->head->cmd = DSS_CMD_UPDATE_WRITTEN_SIZE;
    send_pack->head->flags = 0;

    // 2. ftid
    CM_RETURN_IFERR(dss_put_int64(send_pack, *(uint64 *)&ftid));
    // 3. vg name
    CM_RETURN_IFERR(dss_put_str(send_pack, context->vg_name));
    // 4. written_size
    CM_RETURN_IFERR(dss_put_int64(send_pack, offset));

    // send it and wait for ack
    dss_packet_t *ack_pack = &conn->pack;
    if (dss_call_ex(&conn->pipe, send_pack, ack_pack) != CM_SUCCESS) {
        LOG_RUN_ERR("Failed to send message when update file size.");
        return CM_ERROR;
    }

    // check return state
    if (ack_pack->head->result != CM_SUCCESS) {
        dss_cli_get_err(ack_pack, &errcode, &errmsg);
        DSS_THROW_ERROR_EX(errcode, "%s", errmsg);
        return CM_ERROR;
    }
    LOG_DEBUG_INF("Success to update written_size for file:\"%s\", fid:%llu, updated size:%lld.", context->node->name,
        fid, offset);
    return CM_SUCCESS;
}

static status_t dss_check_file_written_size(dss_env_t *dss_env, dss_conn_t *conn, dss_file_context_t *context,
    uint32 start_offset, bool32 is_read, int32 *total_size)
{
    /* openGauss: 1. read ends at actual written size 2. writes does not stall reads. */
    if (is_read && start_offset + *total_size > context->node->written_size) {
        DSS_UNLOCK_VG_META_S(context->vg_item, conn->session);
        dss_block_id_t blockid;
        dss_set_blockid(&blockid, DSS_INVALID_ID64);
        status_t status = dss_apply_refresh_file(conn, context, blockid);
        if (status != CM_SUCCESS) {
            LOG_DEBUG_ERR("Failed to apply refresh file:%s, fid:%llu.", context->node->name, context->fid);
            return CM_ERROR;
        }
        DSS_LOCK_VG_META_S_RETURN_ERROR(context->vg_item, conn->session, NULL);
        if (start_offset > context->node->written_size) {
            LOG_DEBUG_ERR("Failed to read beyond end of file:%s, written_size:%llu, size:%llu, start_offset:%u.",
                context->node->name, context->node->written_size, context->node->size, start_offset);
            DSS_UNLOCK_VG_META_S(context->vg_item, conn->session);
            return CM_ERROR;
        } else {
            LOG_DEBUG_INF("Success to refresh file:\"%s\", written_size:%llu, size:%llu.", context->node->name,
                context->node->written_size, context->node->size);
        }
    }
    return CM_SUCCESS;
}
#endif

status_t dss_read_write_file_core(dss_rw_param_t *param, void *buf, int32 size, int32 *read_size, bool32 is_read)
{
    status_t status = CM_SUCCESS;
    int32 total_size = size;
    int32 read_cnt = 0;

    dss_conn_t *conn = param->conn;
    int handle = param->handle;
    dss_env_t *dss_env = param->dss_env;
    dss_file_context_t *context = param->context;

    DSS_SET_PTR_VALUE_IF_NOT_NULL(read_size, 0);
    DSS_LOCK_VG_META_S_RETURN_ERROR(context->vg_item, conn->session, NULL);

    gft_node_t *node = context->node;
    dss_vg_info_item_t *vg_item = context->vg_item;
    dss_fs_block_header *entry_block = (dss_fs_block_header *)dss_find_block_in_shm(
        vg_item, node->entry, DSS_BLOCK_TYPE_FS, DSS_FALSE, NULL, CM_FALSE);
    if (!entry_block) {
        DSS_UNLOCK_VG_META_S(context->vg_item, conn->session);
        LOG_DEBUG_ERR("Can not find entry block in memory,entry blockid:%llu,nodeid:%llu.", DSS_ID_TO_U64(node->entry),
            DSS_ID_TO_U64(node->id));
        return CM_ERROR;
    }

    CM_RETURN_IFERR(dss_check_refresh_file(dss_env, conn, context, is_read, &total_size));

    dss_fs_block_t *entry_fs_block = (dss_fs_block_t *)entry_block;
    uint64 au_size = dss_get_vg_au_size(vg_item->dss_ctrl);
    do {
        files_rw_ctx_t rw_ctx;
        rw_ctx.conn = conn;
        rw_ctx.env = dss_env;
        rw_ctx.file_ctx = context;
        rw_ctx.handle = handle;
        rw_ctx.size = size;
        rw_ctx.read = is_read;
        rw_ctx.offset = (param->atom_oper ? param->offset : context->offset);

        dss_fs_block_t *second_block = NULL;
        uint32 block_au_count = 0;
        uint32 au_offset = 0;
        CM_RETURN_IFERR(dss_alloc_block(rw_ctx, entry_fs_block, &second_block, &block_au_count, &au_offset));

        auid_t auid = second_block->bitmap[block_au_count];
        if (dss_cmp_auid(auid, DSS_INVALID_ID64)) {
            // allocate au or refresh second block
            DSS_UNLOCK_VG_META_S(context->vg_item, conn->session);
            if (!is_read) {
                status = dss_apply_extending_file(conn, handle, size, is_read, rw_ctx.offset);
                DSS_RETURN_IFERR2(status, LOG_DEBUG_ERR("Failed to extend file second block."));
            }
            auid = second_block->bitmap[block_au_count];
            if (dss_cmp_auid(auid, DSS_INVALID_ID64)) {
                status = dss_apply_refresh_file(conn, context, second_block->head.id);
                DSS_RETURN_IFERR2(status, LOG_DEBUG_ERR("Failed to refresh second block."));
            }
            DSS_LOCK_VG_META_S_RETURN_ERROR(context->vg_item, conn->session, NULL);
            auid = second_block->bitmap[block_au_count];
        }

        uint64 vol_offset = (uint64)dss_get_au_offset(vg_item, auid);
        vol_offset = vol_offset + (uint64)au_offset;

        if (auid.volume >= DSS_MAX_VOLUMES) {
            if (is_read && block_au_count == second_block->head.used_num && au_offset == 0) {
                DSS_SET_PTR_VALUE_IF_NOT_NULL(read_size, 0);
                DSS_UNLOCK_VG_META_S(context->vg_item, conn->session);
                return CM_SUCCESS;
            }
            DSS_UNLOCK_VG_META_S(context->vg_item, conn->session);
            DSS_THROW_ERROR(ERR_DSS_INVALID_ID, "au", *(uint64 *)&auid);
            LOG_DEBUG_ERR("Auid is invalid, volume:%u, fname:%s, fsize:%llu, written_size:%llu.", (uint32)auid.volume,
                node->name, node->size, node->written_size);
            return CM_ERROR;
        }

        dss_cli_vg_handles_t *cli_vg_handles = (dss_cli_vg_handles_t *)(conn->cli_vg_handles);
        dss_simple_volume_t *vol = &cli_vg_handles->vg_vols[vg_item->id].volume_handle[auid.volume];
        if (vol->handle == DSS_INVALID_HANDLE) {
            DSS_UNLOCK_VG_META_S(context->vg_item, conn->session);
            status = dss_apply_refresh_volume(conn, context, auid);
            if (status != CM_SUCCESS) {
                LOG_DEBUG_ERR("Failed to refresh volume, auid:%llu.", DSS_ID_TO_U64(auid));
                return status;
            }
            DSS_LOCK_VG_META_S_RETURN_ERROR(context->vg_item, conn->session, NULL);
            status = dss_refresh_volume_handle(conn, context, auid);
            if (status != CM_SUCCESS) {
                DSS_UNLOCK_VG_META_S(context->vg_item, conn->session);
                LOG_DEBUG_ERR("Failed to refresh volume handle, auid:%llu.", DSS_ID_TO_U64(auid));
                return status;
            }
        }
        // volume maybe be remove and add again.
        if (vol->version != vg_item->dss_ctrl->volume.defs[auid.volume].version) {
            status = dss_reopen_volume_handle(conn, context, auid);
            if (status != CM_SUCCESS) {
                DSS_UNLOCK_VG_META_S(context->vg_item, conn->session);
                LOG_DEBUG_ERR("Failed to reopen volume, auid:%llu.", DSS_ID_TO_U64(auid));
                return status;
            }
        }
#ifdef OPENGAUSS
        DSS_RETURN_IFERR2(dss_check_file_written_size(dss_env, conn, context, rw_ctx.offset, is_read, &total_size),
            DSS_SET_PTR_VALUE_IF_NOT_NULL(read_size, read_cnt));
        dss_vg_info_item_t *first_vg_item = dss_get_first_vg_item();
        if (strcmp(first_vg_item->vg_name, vg_item->vg_name) == 0 && auid.volume == 0) {
            if (g_log_offset == DSS_INVALID_64) {
                uint64 log_offset = dss_get_log_offset(au_size);
                g_log_offset = au_size + log_offset;
            }
            if (vol_offset < g_log_offset) {
                LOG_RUN_ERR("The volume offset:%llu is invalid! Redo log buf:%llu cannot be written.", vol_offset,
                    g_log_offset);
                CM_ASSERT(0);
            }
        }
#endif

        int32 real_size;
        if ((uint32)total_size > au_size - au_offset) {
            real_size = (int32)(au_size - au_offset);
            total_size -= real_size;
        } else {
            real_size = total_size;
            total_size = 0;
        }

        // wrongly writing superau area
        if (vol_offset < au_size) {
            LOG_RUN_ERR("The volume offset:%llu is invalid!", vol_offset);
            CM_ASSERT(0);
        }

        dss_volume_t volume;
        volume.handle = vol->handle;
        volume.unaligned_handle = vol->unaligned_handle;
        volume.id = vol->id;
        volume.name_p = vg_item->dss_ctrl->volume.defs[auid.volume].name;
#ifdef ENABLE_GLOBAL_CACHE
        volume.image = vol->image;
        volume.ctx = vol->ctx;
#endif
        volume.vg_type = vol->vg_type;
        if (is_read) {
            status = dss_read_volume(&volume, (int64)vol_offset, buf, real_size);
        } else {
            status = dss_write_volume(&volume, (int64)vol_offset, buf, real_size);
        }
        if (status != CM_SUCCESS) {
            DSS_UNLOCK_VG_META_S(context->vg_item, conn->session);
            LOG_DEBUG_ERR("Failed to read write file:(id:%u, handle:%d, unaligned_handle:%d), offset:%llu, size:%d.",
                 volume.id, volume.handle, volume.unaligned_handle, vol_offset, real_size);
            return status;
        }
        read_cnt += real_size;
        if (param->atom_oper) {
            param->offset += real_size;
        } else {
            context->offset += real_size;
            context->vol_offset = (int64)vol_offset;
        }
        buf = (void *)(((char *)buf) + real_size);
        if (param->atom_oper) {
            if (is_read && param->offset >= context->node->size) {
                break;
            }
        } else if (is_read && context->offset >= context->node->size) {
            break;
        }
    } while (total_size > 0);

    DSS_UNLOCK_VG_META_S(context->vg_item, conn->session);
    DSS_SET_PTR_VALUE_IF_NOT_NULL(read_size, read_cnt);

#ifdef OPENGAUSS /* tracking real written size may hinder performance, hence disabled otherwise */
    int64 offset = (param->atom_oper ? param->offset : context->offset);
    bool32 need_update = offset > context->node->written_size && !is_read;
    if (need_update) { /* updates written size outside of locking */
        LOG_DEBUG_INF("Start update_written_size for file:\"%s\", curr offset:%llu, curr written_size:%llu.",
            node->name, offset, node->written_size);
        status = dss_update_written_size(dss_env, conn, context, offset);
    }
#endif
    return status;
}

status_t dss_read_write_file(dss_conn_t *conn, int32 handle, void *buf, int32 size, int32 *read_size, bool32 is_read)
{
    status_t status;
    dss_file_context_t *context = NULL;
    dss_rw_param_t param;
    LOG_DEBUG_INF("dss read write file entry, handle:%d, is_read:%u", handle, is_read);

    DSS_RETURN_IF_ERROR(dss_check_file_env(conn, handle, size, &context));

    dss_latch_x(&context->latch);
    dss_init_rw_param(&param, conn, handle, context, context->offset, DSS_FALSE);
    status = dss_read_write_file_core(&param, buf, size, read_size, is_read);
    dss_unlatch(&context->latch);
    LOG_DEBUG_INF("dss read write file leave");

    return status;
}

status_t dss_write_file_impl(dss_conn_t *conn, int handle, const void *buf, int size)
{
    return dss_read_write_file(conn, handle, (void *)buf, size, NULL, DSS_FALSE);
}

status_t dss_read_file_impl(dss_conn_t *conn, int handle, void *buf, int size, int *read_size)
{
    if (read_size == NULL) {
        return CM_ERROR;
    }

    return dss_read_write_file(conn, handle, buf, size, read_size, DSS_TRUE);
}

status_t dss_refresh_file_impl(dss_rw_param_t *param)
{
    int64 size;
    dss_conn_t *conn = param->conn;
    dss_file_context_t *context = param->context;
    int64 offset = param->offset;

    CM_ASSERT(param->handle == (int32)context->id);

    if (offset > (int64)DSS_MAX_FILE_SIZE) {
        LOG_DEBUG_ERR("Invalid parameter offset:%lld, context offset:%lld.", offset, context->offset);
        return CM_ERROR;
    }
    DSS_LOCK_VG_META_S_RETURN_ERROR(context->vg_item, conn->session, NULL);
    size = (int64)context->node->size;
    DSS_UNLOCK_VG_META_S(context->vg_item, conn->session);

    if (offset >= size) {
        dss_block_id_t blockid;
        dss_set_blockid(&blockid, DSS_INVALID_ID64);
        if (dss_apply_refresh_file(conn, context, blockid) != CM_SUCCESS) {
            LOG_DEBUG_ERR("Failed to apply refresh file,fid:%llu.", context->fid);
            return CM_ERROR;
        }

        DSS_LOCK_VG_META_S_RETURN_ERROR(context->vg_item, conn->session, NULL);
        size = (int64)context->node->size;
        DSS_UNLOCK_VG_META_S(context->vg_item, conn->session);

        if (offset > size) {
            LOG_DEBUG_ERR("Invalid parameter offset is greater than size, offset:%lld,"
                          " file size:%llu, vgid:%u, fid:%llu, node fid:%llu.",
                offset, context->node->size, context->vg_item->id, context->fid, context->node->fid);
            DSS_THROW_ERROR(ERR_DSS_FILE_SEEK, context->vg_item->id, context->fid, offset, context->node->size);
            return CM_ERROR;
        }
        LOG_DEBUG_INF("Apply to refresh file, offset:%lld, size:%lld.", offset, size);
    }
    return CM_SUCCESS;
}

status_t dss_pwrite_file_impl(dss_conn_t *conn, int handle, const void *buf, int size, long long offset)
{
    status_t status;
    dss_file_context_t *context = NULL;
    dss_rw_param_t param;

    CM_RETURN_IFERR(dss_check_file_env(conn, handle, size, &context));
    LOG_DEBUG_INF("dss pwrite file %s, handle:%d, offset:%lld", context->node->name, handle, offset);

    dss_latch_s(&context->latch);
    dss_init_rw_param(&param, conn, handle, context, offset, DSS_TRUE);
    if (dss_refresh_file_impl(&param) != CM_SUCCESS) {
        dss_unlatch(&context->latch);
        return CM_ERROR;
    }
    status = dss_read_write_file_core(&param, (void *)buf, size, NULL, DSS_FALSE);
    dss_unlatch(&context->latch);
    LOG_DEBUG_INF("dss pwrite file leave");

    return status;
}

status_t dss_pread_file_impl(dss_conn_t *conn, int handle, void *buf, int size, long long offset, int *read_size)
{
    if (read_size == NULL) {
        return CM_ERROR;
    }

    status_t status;
    dss_file_context_t *context = NULL;
    dss_rw_param_t param;

    LOG_DEBUG_INF("dss pread file entry, handle:%d, offset:%lld", handle, offset);
    CM_RETURN_IFERR(dss_check_file_env(conn, handle, size, &context));

    dss_latch_s(&context->latch);
    dss_init_rw_param(&param, conn, handle, context, offset, DSS_TRUE);
    if (dss_refresh_file_impl(&param) != CM_SUCCESS) {
        dss_unlatch(&context->latch);
        return CM_ERROR;
    }
    if ((uint64)param.offset == context->node->size || size == 0) {
        *read_size = 0;
        dss_unlatch(&context->latch);
        return CM_SUCCESS;
    }
    status = dss_read_write_file_core(&param, buf, size, read_size, DSS_TRUE);

    dss_unlatch(&context->latch);
    LOG_DEBUG_INF("dss pread file leave");
    return status;
}

status_t dss_copy_file_impl(dss_conn_t *conn, const char *src, const char *dest)
{
    return dss_copy_file(*conn, src, dest);
}

status_t dss_rename_file_impl(dss_conn_t *conn, const char *src, const char *dst)
{
    dss_packet_t *send_pack = NULL;
    dss_packet_t *ack_pack = NULL;
    int32 errcode = -1;
    char *errmsg = NULL;

    // make up packet
    dss_init_set(&conn->pack);

    send_pack = &conn->pack;
    send_pack->head->cmd = DSS_CMD_RENAME_FILE;
    send_pack->head->flags = 0;

    // 1. src
    DSS_RETURN_IF_ERROR(dss_check_device_path(src));
    DSS_RETURN_IF_ERROR(dss_put_str(send_pack, src));
    // 2. dst
    DSS_RETURN_IF_ERROR(dss_check_device_path(dst));
    DSS_RETURN_IF_ERROR(dss_put_str(send_pack, dst));

    // send it and wait for ack
    ack_pack = &conn->pack;
    DSS_RETURN_IF_ERROR(dss_call_ex(&conn->pipe, send_pack, ack_pack));

    // check return state
    if (ack_pack->head->result != CM_SUCCESS) {
        dss_cli_get_err(ack_pack, &errcode, &errmsg);
        DSS_THROW_ERROR_EX(errcode, "%s", errmsg);
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

status_t dss_truncate_impl(dss_conn_t *conn, int handle, uint64 length)
{
    int32 errcode = -1;
    char *errmsg = NULL;

    dss_file_context_t *context = NULL;
    DSS_RETURN_IF_ERROR(dss_check_file_env(conn, handle, 0, &context));

    LOG_DEBUG_INF("Truncating file via handle(%d), file name: %s, node size: %lld, length: %lld.", handle,
        context->node->name, context->node->size, length);

    dss_latch_x(&context->latch);

    uint64 fid = context->fid;
    ftid_t ftid = context->node->id;
    int64 offset = context->offset;

    dss_init_set(&conn->pack);
    dss_packet_t *send_pack = &conn->pack;
    send_pack->head->cmd = DSS_CMD_TRUNCATE_FILE;
    send_pack->head->flags = 0;

    DSS_RETURN_IFERR2(dss_put_int64(send_pack, fid), dss_unlatch(&context->latch));
    DSS_RETURN_IFERR2(dss_put_int64(send_pack, *(uint64 *)&ftid), dss_unlatch(&context->latch));
    DSS_RETURN_IFERR2(dss_put_int64(send_pack, (uint64)offset), dss_unlatch(&context->latch));
    DSS_RETURN_IFERR2(dss_put_int64(send_pack, length), dss_unlatch(&context->latch));
    DSS_RETURN_IFERR2(dss_put_str(send_pack, context->vg_name), dss_unlatch(&context->latch));
    DSS_RETURN_IFERR2(dss_put_int32(send_pack, context->vgid), dss_unlatch(&context->latch));

    dss_packet_t *ack_pack = &conn->pack;
    DSS_RETURN_IFERR2(dss_call_ex(&conn->pipe, send_pack, ack_pack), dss_unlatch(&context->latch));

    if (ack_pack->head->result != CM_SUCCESS) {
        dss_unlatch(&context->latch);
        dss_cli_get_err(ack_pack, &errcode, &errmsg);
        DSS_THROW_ERROR_EX(errcode, "%s", errmsg);
        return CM_ERROR;
    }

    dss_unlatch(&context->latch);
    return CM_SUCCESS;
}

void dss_destroy_vol_handle_sync(dss_conn_t *conn)
{
    if (!conn->cli_vg_handles) {
        return;
    }

    dss_cli_vg_handles_t *cli_vg_handles = (dss_cli_vg_handles_t *)(conn->cli_vg_handles);
    for (uint32 i = 0; i < g_vgs_info->group_num; i++) {
        dss_destroy_vol_handle(&g_vgs_info->volume_group[i], &cli_vg_handles->vg_vols[i], DSS_MAX_VOLUMES);
    }

    DSS_FREE_POINT(conn->cli_vg_handles);
    conn->cli_vg_handles = NULL;
}

void dss_heartbeat_entry(thread_t *thread)
{
    return;
}

static status_t dss_init_err_proc(
    dss_env_t *dss_env, bool32 detach, bool32 destroy, const char *errmsg, status_t errcode)
{
    if (detach == CM_TRUE) {
        ga_detach_area();
    }

    if (destroy == CM_TRUE) {
        cm_destroy_shm();
    }

    dss_unlatch(&dss_env->latch);

    if (errmsg != NULL) {
        LOG_DEBUG_ERR("init error: %s", errmsg);
    }

    return errcode;
}

static status_t dss_init_shm(dss_env_t *dss_env, char *home)
{
    status_t status = dss_set_cfg_dir(home, &dss_env->inst_cfg);
    if (status != CM_SUCCESS) {
        return dss_init_err_proc(dss_env, CM_FALSE, CM_FALSE, "Environment variant DSS_HOME not found", status);
    }

    status = dss_load_config(&dss_env->inst_cfg);
    if (status != CM_SUCCESS) {
        return dss_init_err_proc(dss_env, CM_FALSE, CM_FALSE, "load config failed", status);
    }

    uint32 shm_key = (uint32)(dss_env->inst_cfg.params.shm_key << (uint8)DSS_MAX_SHM_KEY_BITS) +
                     (uint32)dss_env->inst_cfg.params.inst_id;
    status = cm_init_shm(shm_key);
    if (status != CM_SUCCESS) {
        return dss_init_err_proc(dss_env, CM_FALSE, CM_FALSE, "Failed to init shared memory", status);
    }

    status = ga_attach_area(CM_SHM_ATTACH_RW);
    if (status != CM_SUCCESS) {
        return dss_init_err_proc(dss_env, CM_FALSE, CM_TRUE, "Failed to attach shared area", status);
    }

    return CM_SUCCESS;
}

static status_t dss_init_files(dss_env_t *dss_env, uint32 max_open_files)
{
    dss_env->max_open_file = max_open_files;
    // sizeof(zfs_file_context_t) is 24, and max_open_files is limited.
    // so context_size will not exceed the max value of uint32
    uint32 context_size = max_open_files * (uint32)sizeof(dss_file_context_t);
    if (context_size == 0) {
        return dss_init_err_proc(dss_env, CM_TRUE, CM_TRUE, "max_open_files error", CM_ERROR);
    }
    dss_env->files = (dss_file_context_t *)cm_malloc(context_size);
    if (dss_env->files == NULL) {
        return dss_init_err_proc(dss_env, CM_TRUE, CM_TRUE, "alloc memory failed", ERR_ALLOC_MEMORY);
    }
    errno_t rc = memset_s(dss_env->files, context_size, 0, context_size);
    if (rc != EOK) {
        DSS_FREE_POINT(dss_env->files);
        CM_THROW_ERROR(ERR_SYSTEM_CALL, rc);
        return dss_init_err_proc(dss_env, CM_TRUE, CM_TRUE, "memory init failed", CM_ERROR);
    }
    dss_file_context_t *context = dss_env->files;
    for (uint32 i = 0; i < dss_env->max_open_file; i++) {
        context = &dss_env->files[i];
        if (i == dss_env->max_open_file - 1) {
            context->next = CM_INVALID_ID32;
        } else {
            context->next = i + 1;
        }
        context->id = i;
    }
    return CM_SUCCESS;
}

status_t dss_init(uint32 max_open_files, char *home)
{
    DSS_STATIC_ASSERT(DSS_BLOCK_SIZE / sizeof(gft_node_t) <= (1 << DSS_MAX_BIT_NUM_ITEM));
    DSS_STATIC_ASSERT(sizeof(dss_root_ft_block_t) == 256);

    if (max_open_files > DSS_MAX_OPEN_FILES) {
        LOG_DEBUG_ERR("exceed DSS_MAX_OPEN_FILES.");
        return ERR_DSS_INVALID_PARAM;
    }

    dss_env_t *dss_env = dss_get_env();
    if (dss_env->initialized) {
        return CM_SUCCESS;
    }

    dss_latch_x(&dss_env->latch);
    if (dss_env->initialized) {
        return dss_init_err_proc(dss_env, CM_FALSE, CM_FALSE, NULL, CM_SUCCESS);
    }

    CM_RETURN_IFERR(dss_init_shm(dss_env, home));

    dss_share_vg_info_t *share_vg_info = (dss_share_vg_info_t *)ga_object_addr(GA_INSTANCE_POOL, 0);
    if (share_vg_info == NULL) {
        return dss_init_err_proc(dss_env, CM_TRUE, CM_TRUE, "Failed to attach shared vg info", CM_ERROR);
    }

    status_t status = dss_get_vg_info(share_vg_info, &dss_env->dss_vg_info);
    if (status != CM_SUCCESS) {
        return dss_init_err_proc(dss_env, CM_TRUE, CM_TRUE, "Failed to get shared vg info", status);
    }

    dss_env->session = (dss_session_t *)ga_object_addr(GA_SESSION_POOL, 0);
    if (dss_env->session == NULL) {
        return dss_init_err_proc(dss_env, CM_TRUE, CM_TRUE, "Failed to attach shared session info", CM_ERROR);
    }
    CM_RETURN_IFERR(dss_init_files(dss_env, max_open_files));

    for (int32_t i = 0; i < (int32_t)dss_env->dss_vg_info->group_num; i++) {
        dss_vg_info_item_t *item = &dss_env->dss_vg_info->volume_group[i];
        cm_attach_shm(SHM_TYPE_HASH, item->buffer_cache->shm_id, 0, CM_SHM_ATTACH_RW);
    }

    status = cm_create_thread(dss_heartbeat_entry, SIZE_K(512), NULL, &dss_env->thread_heartbeat);
    if (status != CM_SUCCESS) {
        return dss_init_err_proc(dss_env, CM_TRUE, CM_TRUE, "DSS failed to create heartbeat thread", status);
    }

    dss_env->initialized = CM_TRUE;
    dss_unlatch(&dss_env->latch);

    return CM_SUCCESS;
}

void dss_destroy_vg_info(dss_env_t *dss_env)
{
    dss_vg_info_t *dss_vg_info = dss_env->dss_vg_info;
    if (dss_vg_info == NULL) {
        return;
    }
    for (uint32 i = 0; i < dss_vg_info->group_num; i++) {
        for (uint32 j = 0; j < DSS_MAX_VOLUMES; j++) {
            if (dss_vg_info->volume_group[i].volume_handle[j].handle != DSS_INVALID_HANDLE) {
                dss_close_volume(&dss_vg_info->volume_group[i].volume_handle[j]);
            }
        }
    }
    ga_detach_area();
    DSS_FREE_POINT(dss_vg_info);
}

void dss_destroy(void)
{
    dss_env_t *dss_env = dss_get_env();
    dss_latch_x(&dss_env->latch);
    if (!dss_env->initialized) {
        dss_unlatch(&dss_env->latch);
        return;
    }

    cm_close_thread_nowait(&dss_env->thread_heartbeat);

    if (dss_env->files) {
        DSS_FREE_POINT(dss_env->files);
    }
    dss_destroy_vg_info(dss_env);
    dss_env->initialized = 0;
    dss_unlatch(&dss_env->latch);
}

status_t dss_symlink_impl(dss_conn_t *conn, const char *oldpath, const char *newpath)
{
    dss_packet_t *send_pack = NULL;
    dss_packet_t *ack_pack = NULL;
    int32 errcode = -1;
    char *errmsg = NULL;

    // make up packet
    dss_init_set(&conn->pack);

    send_pack = &conn->pack;
    send_pack->head->cmd = DSS_CMD_SYMLINK;
    send_pack->head->flags = 0;

    DSS_RETURN_IF_ERROR(dss_check_device_path(oldpath));
    DSS_RETURN_IF_ERROR(dss_check_device_path(newpath));
    DSS_RETURN_IF_ERROR(dss_put_str(send_pack, oldpath));
    DSS_RETURN_IF_ERROR(dss_put_str(send_pack, newpath));

    // send it and wait for ack
    ack_pack = &conn->pack;
    DSS_RETURN_IF_ERROR(dss_call_ex(&conn->pipe, send_pack, ack_pack));

    // check return state
    if (ack_pack->head->result != CM_SUCCESS) {
        dss_cli_get_err(ack_pack, &errcode, &errmsg);
        DSS_THROW_ERROR_EX(errcode, "%s", errmsg);
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

status_t dss_unlink_impl(dss_conn_t *conn, const char *link)
{
    dss_packet_t *send_pack;
    dss_packet_t *ack_pack;
    int32 errcode = -1;
    char *errmsg = NULL;

    LOG_DEBUG_INF("dss unlink entry, link:%s", link);

    // make up packet
    dss_init_set(&conn->pack);

    send_pack = &conn->pack;
    send_pack->head->cmd = DSS_CMD_UNLINK;
    send_pack->head->flags = 0;

    DSS_RETURN_IF_ERROR(dss_check_device_path(link));
    DSS_RETURN_IF_ERROR(dss_put_str(send_pack, link));

    // send it and wait for ack
    ack_pack = &conn->pack;
    DSS_RETURN_IF_ERROR(dss_call_ex(&conn->pipe, send_pack, ack_pack));

    // check return state
    if (ack_pack->head->result != CM_SUCCESS) {
        dss_cli_get_err(ack_pack, &errcode, &errmsg);
        DSS_THROW_ERROR_EX(errcode, "%s", errmsg);
        return CM_ERROR;
    }

    LOG_DEBUG_INF("dss unlink leave");
    return CM_SUCCESS;
}

status_t dss_islink_impl(dss_conn_t *conn, const char *path, bool *result)
{
    dss_packet_t *send_pack;
    dss_packet_t *ack_pack;
    int32 errcode = -1;
    char *errmsg = NULL;

    // make up packet
    dss_init_set(&conn->pack);

    send_pack = &conn->pack;
    send_pack->head->cmd = DSS_CMD_ISLINK;
    send_pack->head->flags = 0;

    DSS_RETURN_IF_ERROR(dss_check_device_path(path));
    DSS_RETURN_IF_ERROR(dss_put_str(send_pack, path));

    // send it and wait for ack
    ack_pack = &conn->pack;
    DSS_RETURN_IF_ERROR(dss_call_ex(&conn->pipe, send_pack, ack_pack));

    // check return state
    if (ack_pack->head->result != CM_SUCCESS) {
        dss_cli_get_err(ack_pack, &errcode, &errmsg);
        DSS_THROW_ERROR_EX(errcode, "%s", errmsg);
        return CM_ERROR;
    }

    text_t extra_info = CM_NULL_TEXT;
    dss_init_get(ack_pack);
    status_t ret = dss_get_text(ack_pack, &extra_info);
    DSS_RETURN_IFERR2(ret, LOG_DEBUG_ERR("islink get result connect error"));
    if (extra_info.len == 0 || extra_info.len > sizeof(bool32)) {
        LOG_DEBUG_ERR("islink get result length error");
        return CM_ERROR;
    }
    *result = *(bool32 *)extra_info.str;

    return CM_SUCCESS;
}

status_t dss_readlink_impl(dss_conn_t *conn, const char *dir_path, char *out_str, size_t str_len)
{
    dss_packet_t *send_pack;
    dss_packet_t *ack_pack;
    int32 errcode = -1;
    char *errmsg = NULL;

    // make up packet
    dss_init_set(&conn->pack);

    send_pack = &conn->pack;
    send_pack->head->cmd = DSS_CMD_READLINK;
    send_pack->head->flags = 0;

    DSS_RETURN_IF_ERROR(dss_check_device_path(dir_path));
    DSS_RETURN_IF_ERROR(dss_put_str(send_pack, dir_path));

    // send it and wait for ack
    ack_pack = &conn->pack;
    DSS_RETURN_IF_ERROR(dss_call_ex(&conn->pipe, send_pack, ack_pack));

    // check return state
    if (ack_pack->head->result != CM_SUCCESS) {
        dss_cli_get_err(ack_pack, &errcode, &errmsg);
        DSS_THROW_ERROR_EX(errcode, "%s", errmsg);
        return CM_ERROR;
    }

    text_t extra_info = CM_NULL_TEXT;
    dss_init_get(ack_pack);
    if (dss_get_text(ack_pack, &extra_info) != CM_SUCCESS) {
        DSS_THROW_ERROR(ERR_DSS_CLI_EXEC_FAIL, dss_get_cmd_desc(DSS_CMD_READLINK), "readlink get connect error");
        LOG_DEBUG_ERR("readlink get result connect error");
        return CM_ERROR;
    }
    if (extra_info.len == 0 || extra_info.len >= DSS_FILE_PATH_MAX_LENGTH) {
        DSS_THROW_ERROR(ERR_DSS_CLI_EXEC_FAIL, dss_get_cmd_desc(DSS_CMD_READLINK), "readlink get length error");
        LOG_DEBUG_ERR("readlink get result length error");
        return CM_ERROR;
    }
    char *dst_str = extra_info.str;
    dst_str[extra_info.len] = '\0';
    errno_t err = strcpy_s(out_str, str_len, dst_str);
    if (SECUREC_UNLIKELY(err != EOK)) {
        DSS_THROW_ERROR(ERR_DSS_INVALID_PARAM, "value of str_len is not large enough.");
        return CM_ERROR;
    }

    LOG_DEBUG_INF("Client readlink %s.", dst_str);
    return CM_SUCCESS;
}

status_t dss_get_fname_impl(int handle, char *fname, int fname_size)
{
    dss_env_t *dss_env = dss_get_env();
    if (!dss_env->initialized) {
        DSS_THROW_ERROR(ERR_DSS_ENV_NOT_INITIALIZED);
        return CM_ERROR;
    }
    if (handle < 0 || (uint32)handle >= dss_env->max_open_file) {
        DSS_THROW_ERROR(
            ERR_DSS_INVALID_PARAM, "value of handle must be a positive integer and less than max_open_file.");
        return CM_ERROR;
    }
    if (fname_size < 0) {
        DSS_THROW_ERROR(ERR_DSS_INVALID_PARAM, "value of fname_size is a positive number.");
        return CM_ERROR;
    }
    dss_file_context_t *context = &dss_env->files[handle];
    DSS_RETURN_IF_NULL(context->node);
    int len = (fname_size > DSS_MAX_NAME_LEN) ? DSS_MAX_NAME_LEN : fname_size;
    errno_t errcode = strcpy_s(fname, (size_t)len, context->node->name);
    if (SECUREC_UNLIKELY(errcode != EOK)) {
        DSS_THROW_ERROR(ERR_DSS_INVALID_PARAM, "value of fname_size is not large enough.");
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

gft_node_t *dss_get_node_by_handle_impl(dss_conn_t *conn, int handle)
{
    dss_file_context_t *context = NULL;
    if (dss_check_file_env(conn, handle, 0, &context) != CM_SUCCESS) {
        return NULL;
    }
    return context->node;
}

static status_t get_fd(dss_rw_param_t *param, int32 size, bool32 is_read, int *fd, int64 *vol_offset)
{
    status_t status = CM_SUCCESS;
    dss_conn_t *conn = param->conn;
    int handle = param->handle;
    dss_env_t *dss_env = param->dss_env;
    dss_file_context_t *context = param->context;
    int32 total_size = size;

    DSS_LOCK_VG_META_S_RETURN_ERROR(context->vg_item, conn->session, NULL);

    gft_node_t *node = context->node;
    dss_vg_info_item_t *vg_item = context->vg_item;
    dss_fs_block_header *entry_block = (dss_fs_block_header *)dss_find_block_in_shm(
        vg_item, node->entry, DSS_BLOCK_TYPE_FS, DSS_FALSE, NULL, CM_FALSE);
    if (!entry_block) {
        DSS_UNLOCK_VG_META_S(context->vg_item, conn->session);
        LOG_DEBUG_ERR("Can not find entry block in memory, entry blockid:%llu, nodeid:%llu.",
            DSS_ID_TO_U64(node->entry), DSS_ID_TO_U64(node->id));
        return CM_ERROR;
    }

    CM_RETURN_IFERR(dss_check_refresh_file(dss_env, conn, context, is_read, &total_size));

    dss_fs_block_t *entry_fs_block = (dss_fs_block_t *)entry_block;
    uint64 au_size = dss_get_vg_au_size(vg_item->dss_ctrl);

    /* for aio, one IO needs to be in the same AU. */
    uint32 start_block_count, start_block_au_count, end_block_count, end_block_au_count;
    do {
        status =
            dss_get_fs_block_info_by_offset(param->offset, au_size, &start_block_count, &start_block_au_count, NULL);
        DSS_BREAK_IF_ERROR(status);
        status = dss_get_fs_block_info_by_offset(
            param->offset + size - 1, au_size, &end_block_count, &end_block_au_count, NULL);
    } while (0);

    DSS_RETURN_IFERR2(status, DSS_UNLOCK_VG_META_S(context->vg_item, conn->session));

    if (start_block_count != end_block_count || start_block_au_count != end_block_au_count) {
        DSS_UNLOCK_VG_META_S(context->vg_item, conn->session);
        return CM_ERROR;
    }

    files_rw_ctx_t rw_ctx;
    rw_ctx.conn = conn;
    rw_ctx.env = dss_env;
    rw_ctx.file_ctx = context;
    rw_ctx.handle = handle;
    rw_ctx.size = size;
    rw_ctx.read = is_read;
    rw_ctx.offset = param->offset;

    dss_fs_block_t *second_block = NULL;
    uint32 block_au_count = 0;
    uint32 au_offset = 0;
    CM_RETURN_IFERR(dss_alloc_block(rw_ctx, entry_fs_block, &second_block, &block_au_count, &au_offset));

    auid_t auid = second_block->bitmap[block_au_count];
    if (dss_cmp_auid(auid, DSS_INVALID_ID64)) {
        // allocate au
        DSS_UNLOCK_VG_META_S(context->vg_item, conn->session);
        if (!is_read) {
            status = dss_apply_extending_file(conn, handle, size, is_read, rw_ctx.offset);
            DSS_RETURN_IFERR2(status, LOG_DEBUG_ERR("Failed to extend file second block."));
        }
        auid = second_block->bitmap[block_au_count];
        if (dss_cmp_auid(auid, DSS_INVALID_ID64)) {
            status = dss_apply_refresh_file(conn, context, second_block->head.id);
            DSS_RETURN_IFERR2(status, LOG_DEBUG_ERR("Failed to refresh second block."));
        }
        DSS_LOCK_VG_META_S_RETURN_ERROR(context->vg_item, conn->session, NULL);
        auid = second_block->bitmap[block_au_count];
    }

    *vol_offset = dss_get_au_offset(vg_item, auid);
    *vol_offset = *vol_offset + (int64)au_offset;
    cm_panic(*((uint64 *)vol_offset) >= au_size);  // wrongly writing superau area

    if (auid.volume >= DSS_MAX_VOLUMES) {
        DSS_UNLOCK_VG_META_S(context->vg_item, conn->session);
        DSS_THROW_ERROR(ERR_DSS_INVALID_ID, "au", *(uint64 *)&auid);
        LOG_DEBUG_ERR("Auid is invalid, volume:%u, fname:%s, fsize:%llu, written_size:%llu.", (uint32)auid.volume,
            node->name, node->size, node->written_size);
        return CM_ERROR;
    }

    dss_cli_vg_handles_t *cli_vg_handles = (dss_cli_vg_handles_t *)(conn->cli_vg_handles);
    dss_simple_volume_t *vol = &cli_vg_handles->vg_vols[vg_item->id].volume_handle[auid.volume];
    if (vol->handle == DSS_INVALID_HANDLE) {
        DSS_UNLOCK_VG_META_S(context->vg_item, conn->session);
        status = dss_apply_refresh_volume(conn, context, auid);
        if (status != CM_SUCCESS) {
            LOG_DEBUG_ERR("Failed to refresh volume, auid:%llu.", DSS_ID_TO_U64(auid));
            return status;
        }
        DSS_LOCK_VG_META_S_RETURN_ERROR(context->vg_item, conn->session, NULL);
        status = dss_refresh_volume_handle(conn, context, auid);
        if (status != CM_SUCCESS) {
            DSS_UNLOCK_VG_META_S(context->vg_item, conn->session);
            LOG_DEBUG_ERR("Failed to refresh volume handle, auid:%llu.", DSS_ID_TO_U64(auid));
            return status;
        }
    }

    /* reopen */
    if (vol->version != vg_item->dss_ctrl->volume.defs[auid.volume].version) {
        status = dss_reopen_volume_handle(conn, context, auid);
        if (status != CM_SUCCESS) {
            DSS_UNLOCK_VG_META_S(context->vg_item, conn->session);
            LOG_DEBUG_ERR("Failed to reopen volume, auid:%llu.", DSS_ID_TO_U64(auid));
            return status;
        }
    }

#ifdef OPENGAUSS
    DSS_RETURN_IFERR2(dss_check_file_written_size(dss_env, conn, context, rw_ctx.offset, is_read, &total_size),
        DSS_UNLOCK_VG_META_S(context->vg_item, conn->session));
#endif

    /* get the real block device descriptor */
    *fd = vol->handle;

    DSS_UNLOCK_VG_META_S(context->vg_item, conn->session);

#ifdef OPENGAUSS
    int64 offset = param->offset + size;
    bool32 need_update = offset > context->node->written_size && !is_read;
    if (need_update) {
        LOG_DEBUG_INF("Start update_written_size for file:\"%s\", curr offset:%llu, curr written_size:%llu.",
            node->name, offset, node->written_size);
        status = dss_update_written_size(dss_env, conn, context, offset);
    }
#endif
    return status;
}

status_t dss_get_fd_by_offset(
    dss_conn_t *conn, int handle, long long offset, int32 size, bool32 is_read, int *fd, int64 *vol_offset)
{
    *fd = DSS_INVALID_HANDLE;

    status_t status;
    dss_file_context_t *context = NULL;
    dss_rw_param_t param;

    CM_RETURN_IFERR(dss_check_file_env(conn, handle, size, &context));
    LOG_DEBUG_INF("Begin get file fd in aio, filename:%s, handle:%d, offset:%lld", context->node->name, handle, offset);

    dss_latch_s(&context->latch);
    dss_init_rw_param(&param, conn, handle, context, offset, DSS_TRUE);
    status_t ret = dss_refresh_file_impl(&param);
    DSS_RETURN_IFERR2(ret, dss_unlatch(&context->latch));
    status = get_fd(&param, size, is_read, fd, vol_offset);

    dss_unlatch(&context->latch);
    LOG_DEBUG_INF("get file descriptor in aio leave");
    return status;
}

status_t get_au_size_impl(dss_conn_t *conn, int handle, long long *au_size)
{
    dss_file_context_t *context = NULL;

    LOG_DEBUG_INF("get_au_size_impl, handle:%d", handle);
    CM_RETURN_IFERR(dss_check_file_env(conn, handle, 0, &context));

    *au_size = context->vg_item->dss_ctrl->core.au_size;
    return CM_SUCCESS;
}

status_t dss_setcfg_impl(dss_conn_t *conn, const char *name, const char *value, const char *scope)
{
    dss_packet_t *send_pack;
    dss_packet_t *ack_pack;
    int32 errcode = -1;
    char *errmsg = NULL;

    // make up packet
    dss_init_set(&conn->pack);

    send_pack = &conn->pack;
    send_pack->head->cmd = DSS_CMD_SETCFG;
    send_pack->head->flags = 0;

    // name value scope
    DSS_RETURN_IF_ERROR(dss_check_name(name));
    DSS_RETURN_IF_ERROR(dss_put_str(send_pack, name));
    DSS_RETURN_IF_ERROR(dss_put_str(send_pack, value));
    DSS_RETURN_IF_ERROR(dss_put_str(send_pack, scope));

    // send it and wait for ack
    ack_pack = &conn->pack;
    DSS_RETURN_IF_ERROR(dss_call_ex(&conn->pipe, send_pack, ack_pack));

    // check return state
    if (ack_pack->head->result != CM_SUCCESS) {
        dss_cli_get_err(ack_pack, &errcode, &errmsg);
        DSS_THROW_ERROR_EX(errcode, "%s", errmsg);
        return CM_ERROR;
    }
    LOG_DEBUG_INF("dss set cfg leave");
    return CM_SUCCESS;
}

status_t dss_getcfg_impl(dss_conn_t *conn, const char *name, char *out_str, size_t str_len)
{
    dss_packet_t *send_pack;
    dss_packet_t *ack_pack;
    int32 errcode = -1;
    char *errmsg = NULL;

    // make up packet
    dss_init_set(&conn->pack);

    send_pack = &conn->pack;
    send_pack->head->cmd = DSS_CMD_GETCFG;
    send_pack->head->flags = 0;

    // name
    DSS_RETURN_IF_ERROR(dss_check_name(name));
    DSS_RETURN_IF_ERROR(dss_put_str(send_pack, name));

    // send it and wait for ack
    ack_pack = &conn->pack;
    DSS_RETURN_IF_ERROR(dss_call_ex(&conn->pipe, send_pack, ack_pack));

    // check return state
    if (ack_pack->head->result != CM_SUCCESS) {
        dss_cli_get_err(ack_pack, &errcode, &errmsg);
        DSS_THROW_ERROR_EX(errcode, "%s", errmsg);
        return CM_ERROR;
    }

    text_t extra_info = CM_NULL_TEXT;
    uint32_t len = DSS_MAX_PACKET_SIZE - sizeof(dss_packet_head_t) - sizeof(int32);
    dss_init_get(ack_pack);

    status_t ret = dss_get_text(ack_pack, &extra_info);
    DSS_RETURN_IFERR2(
        ret, DSS_THROW_ERROR(ERR_DSS_CLI_EXEC_FAIL, dss_get_cmd_desc(DSS_CMD_GETCFG), "get cfg connect error"));
    if (extra_info.len < sizeof(uint32) || extra_info.len >= len) {
        DSS_THROW_ERROR(ERR_DSS_CLI_EXEC_FAIL, dss_get_cmd_desc(DSS_CMD_GETCFG), "get cfg length error");
        return CM_ERROR;
    }
    if (extra_info.len == sizeof(uint32)) {
        LOG_DEBUG_INF("Client get cfg is NULL.");
        return CM_SUCCESS;
    }
    char *value_str = extra_info.str + sizeof(uint32);
    value_str[extra_info.len - sizeof(uint32)] = '\0';
    errno_t err = strcpy_s(out_str, str_len, value_str);
    if (SECUREC_UNLIKELY(err != EOK)) {
        DSS_THROW_ERROR(ERR_DSS_INVALID_PARAM, "value of str_len is not large enough when getcfg.");
        return CM_ERROR;
    }
    LOG_DEBUG_INF("Client get cfg is %s.", out_str);
    return CM_SUCCESS;
}

void dss_get_api_volume_error(void)
{
    int32 code = cm_get_error_code();
    // volume open/seek/read write fail for I/O, just exit
    if (code == ERR_DSS_VOLUME_SYSTEM_IO) {
        LOG_RUN_ERR("[DSS API] ABORT INFO : volume operate failed for I/O ERROR, errcode:%d.", code);
        cm_fync_logfile();
        _exit(1);
    }
    return;
}

status_t dss_stop_server_impl(dss_conn_t *conn)
{
    dss_packet_t *send_pack;
    dss_packet_t *ack_pack;
    int32 errcode = -1;
    char *errmsg = NULL;

    // make up packet
    dss_init_set(&conn->pack);

    send_pack = &conn->pack;
    send_pack->head->cmd = DSS_CMD_STOP_SERVER;
    send_pack->head->flags = 0;

    // send it and wait for ack
    ack_pack = &conn->pack;
    DSS_RETURN_IF_ERROR(dss_call_ex(&conn->pipe, send_pack, ack_pack));

    // check return state
    if (ack_pack->head->result != CM_SUCCESS) {
        dss_cli_get_err(ack_pack, &errcode, &errmsg);
        DSS_THROW_ERROR_EX(errcode, "%s", errmsg);
        LOG_DEBUG_ERR("dss stop server failed");
        return CM_ERROR;
    }
    LOG_DEBUG_INF("dss stop server leave");
    return CM_SUCCESS;
}

#ifdef __cplusplus
}
#endif
