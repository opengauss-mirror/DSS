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

#include "cm_system.h"
#include "dss_copyfile.h"
#include "dss_defs.h"
#include "dss_diskgroup.h"
#include "dss_file.h"
#include "dss_file_def.h"
#include "dss_latch.h"
#include "dss_malloc.h"
#include "dss_api_impl.h"
#include "dss_defs.h"
#include "dss_fs_aux.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DSS_ACCMODE 00000003
#define DSS_OPEN_MODE(flag) ((flag + 1) & DSS_ACCMODE)
int32 g_dss_uds_conn_timeout = DSS_UDS_CONNECT_TIMEOUT;

typedef struct str_files_rw_ctx {
    dss_conn_t *conn;
    dss_file_context_t *file_ctx;
    dss_env_t *env;
    int32 handle;
    int32 size;
    bool32 read;
    int64 offset;
} files_rw_ctx_t;

status_t dss_load_ctrl_sync(dss_conn_t *conn, const char *vg_name, uint32 index)
{
    CM_RETURN_IFERR(dss_check_name(vg_name));
    dss_load_ctrl_info_t send_info;
    send_info.vg_name = vg_name;
    send_info.index = index;
    return dss_msg_interact(conn, DSS_CMD_LOAD_CTRL, (void *)&send_info, NULL);
}

status_t dss_add_or_remove_volume(dss_conn_t *conn, const char *vg_name, const char *volume_name, uint8 cmd)
{
    DSS_RETURN_IF_ERROR(dss_check_name(vg_name));
    DSS_RETURN_IF_ERROR(dss_check_volume_path(volume_name));
    dss_add_or_remove_info_t send_info;
    send_info.vg_name = vg_name;
    send_info.volume_name = volume_name;
    return dss_msg_interact(conn, cmd, (void *)&send_info, NULL);
}

status_t dss_kick_host_sync(dss_conn_t *conn, int64 kick_hostid)
{
    return dss_msg_interact(conn, DSS_CMD_KICKH, (void *)&kick_hostid, NULL);
}

status_t dss_apply_refresh_file_table(dss_conn_t *conn, dss_dir_t *dir);
status_t dss_apply_refresh_volume(dss_conn_t *conn, dss_file_context_t *context, auid_t auid);
status_t dss_refresh_volume_handle(dss_conn_t *conn, dss_file_context_t *context, auid_t auid);
status_t dss_reopen_volume_handle(dss_conn_t *conn, dss_file_context_t *context, auid_t auid);

status_t dss_apply_extending_file(dss_conn_t *conn, int32 handle, int64 size, int64 offset)
{
    dss_env_t *dss_env = dss_get_env();
    if (handle >= (int32)dss_env->max_open_file || handle < 0) {
        return CM_ERROR;
    }

    dss_file_context_t *context = &dss_env->files[handle];
    if (context->flag == DSS_FILE_CONTEXT_FLAG_FREE) {
        return CM_ERROR;
    }

    LOG_DEBUG_INF("Apply extending file:%s, handle:%d, curr size:%llu, curr written_size:%llu, offset:%lld, size:%lld.",
        context->node->name, handle, context->node->size, context->node->written_size, offset, size);
    dss_extend_info_t send_info;
    send_info.fid = context->fid;
    send_info.ftid = *(uint64 *)&(context->node->id);
    send_info.offset = offset;
    send_info.size = size;
    send_info.vg_name = context->vg_name;
    send_info.vg_id = context->vgid;
    return dss_msg_interact(conn, DSS_CMD_EXTEND_FILE, (void *)&send_info, NULL);
}

status_t dss_apply_fallocate_file(dss_conn_t *conn, int32 handle, int32 mode, int64 offset, int64 size)
{
    dss_env_t *dss_env = dss_get_env();
    if (handle >= (int32)dss_env->max_open_file || handle < 0) {
        return CM_ERROR;
    }

    dss_file_context_t *context = &dss_env->files[handle];
    if (context->flag == DSS_FILE_CONTEXT_FLAG_FREE) {
        return CM_ERROR;
    }

    LOG_DEBUG_INF(
        "Apply fallocate file:%s, handle:%d, curr size:%llu, curr written_size:%llu, mode:%d, offset:%lld, size:%lld.",
        context->node->name, handle, context->node->size, context->node->written_size, mode, offset, size);

    dss_fallocate_info_t send_info;
    send_info.fid = context->fid;
    send_info.ftid = *(uint64 *)&(context->node->id);
    send_info.offset = offset;
    send_info.size = size;
    send_info.vg_id = context->vgid;
    send_info.mode = mode;
    return dss_msg_interact(conn, DSS_CMD_FALLOCATE_FILE, (void *)&send_info, NULL);
}

status_t dss_apply_refresh_file(dss_conn_t *conn, dss_file_context_t *context, int64 offset)
{
    int32 errcode = -1;
    char *errmsg = NULL;
    uint64 fid = context->fid;
    ftid_t ftid = context->node->id;

    // make up packet
    dss_init_set(&conn->pack, conn->proto_version);
    dss_packet_t *send_pack = &conn->pack;
    send_pack->head->cmd = DSS_CMD_REFRESH_FILE;
    send_pack->head->flags = 0;

    LOG_DEBUG_INF(
        "Apply refresh file:%s, curr size:%llu, refresh ft id:%llu, refresh entry id:%llu, refresh offset:%llu.",
        context->node->name, context->node->size, DSS_ID_TO_U64(ftid), DSS_ID_TO_U64(context->node->entry), offset);
    // 1. fid
    CM_RETURN_IFERR(dss_put_int64(send_pack, fid));
    // 2. ftid
    CM_RETURN_IFERR(dss_put_int64(send_pack, *(uint64 *)&ftid));
    // 3. vg name
    CM_RETURN_IFERR(dss_put_str(send_pack, context->vg_name));
    // 4. vgid
    CM_RETURN_IFERR(dss_put_int32(send_pack, context->vgid));
    // 5. offset
    CM_RETURN_IFERR(dss_put_int64(send_pack, (uint64)offset));

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

static status_t dss_check_apply_refresh_file(dss_conn_t *conn, dss_file_context_t *context, int64 offset)
{
    bool32 is_valid = CM_FALSE;
    do {
        DSS_UNLOCK_VG_META_S(context->vg_item, conn->session);
        status_t status = dss_apply_refresh_file(conn, context, offset);
        if (status != CM_SUCCESS) {
            LOG_RUN_ERR("Failed to apply refresh file:%s, fid:%llu.", context->node->name, context->fid);
            return CM_ERROR;
        }
        DSS_LOCK_VG_META_S_RETURN_ERROR(context->vg_item, conn->session);
        is_valid = dss_is_fs_meta_valid(context->node);
        if (is_valid) {
            break;
        }
        LOG_DEBUG_INF("The node:%s name:%s is invalid, need refresh from server again.",
            dss_display_metaid(context->node->id), context->node->name);
        cm_sleep(DSS_READ_REMOTE_INTERVAL);
    } while (!is_valid);
    return CM_SUCCESS;
}

static status_t dss_check_find_fs_block(files_rw_ctx_t *rw_ctx, dss_fs_pos_desc_t *fs_pos)
{
    dss_conn_t *conn = rw_ctx->conn;
    dss_file_context_t *context = rw_ctx->file_ctx;
    gft_node_t *node = context->node;

    uint64 au_size = dss_get_vg_au_size(context->vg_item->dss_ctrl);

    fs_pos->is_valid = CM_FALSE;

    if (node->flags & DSS_FT_NODE_FLAG_INVALID_FS_META) {
        LOG_DEBUG_INF("File:%llu, node:%s is not invalid.", node->fid, dss_display_metaid(node->id));
        return CM_SUCCESS;
    }

    status_t status = dss_get_fs_block_info_by_offset(
        rw_ctx->offset, au_size, &fs_pos->block_count, &fs_pos->block_au_count, &fs_pos->au_offset);
    if (status != CM_SUCCESS) {
        DSS_UNLOCK_VG_META_S(context->vg_item, conn->session);
        LOG_DEBUG_ERR("The offset:%llu is not correct.", rw_ctx->offset);
        return CM_ERROR;
    }

    fs_pos->entry_fs_block =
        dss_find_fs_block(conn->session, context->vg_item, node, node->entry, CM_FALSE, NULL, DSS_ENTRY_FS_INDEX);
    if (fs_pos->entry_fs_block == NULL) {
        // no error report here
        return CM_SUCCESS;
    }

    auid_t auid = fs_pos->entry_fs_block->bitmap[fs_pos->block_count];
    if (dss_cmp_auid(auid, CM_INVALID_ID64)) {
        return CM_SUCCESS;
    }

    fs_pos->second_fs_block =
        dss_find_fs_block(conn->session, context->vg_item, node, auid, CM_FALSE, NULL, (uint16)fs_pos->block_count);
    if (fs_pos->second_fs_block == NULL) {
        // no error report here
        return CM_SUCCESS;
    }

    auid = fs_pos->second_fs_block->bitmap[fs_pos->block_au_count];
    if (dss_cmp_auid(auid, CM_INVALID_ID64)) {
        return CM_SUCCESS;
    }
    fs_pos->data_auid = auid;

    if (DSS_IS_FILE_INNER_INITED(node->flags) && DSS_BLOCK_ID_IS_AUX(auid)) {
        fs_pos->fs_aux = dss_find_fs_aux(
            conn->session, context->vg_item, node, auid, CM_FALSE, NULL, (uint16)fs_pos->block_au_count);
        if (fs_pos->fs_aux == NULL) {
            return CM_SUCCESS;
        }

        fs_pos->is_exist_aux = CM_TRUE;
        fs_pos->data_auid = fs_pos->fs_aux->head.data_id;
        LOG_DEBUG_INF("Found fs aux block:%llu, data_id:%llu, version:%llu, for fs_aux.parent:%llu, file:%llu, node:%llu.",
            DSS_ID_TO_U64(fs_pos->fs_aux->head.common.id), DSS_ID_TO_U64(fs_pos->fs_aux->head.data_id),
            fs_pos->fs_aux->head.common.version, DSS_ID_TO_U64(fs_pos->fs_aux->head.ftid), node->fid,
            DSS_ID_TO_U64(node->id));
    }
    fs_pos->is_valid = CM_TRUE;
    return CM_SUCCESS;
}

static status_t dss_check_refresh_file_by_size(
    dss_conn_t *conn, dss_file_context_t *context, dss_rw_param_t *param, int32 *total_size)
{
    int64 offset = 0;
    bool32 need_refresh = CM_FALSE;
    uint32 tmp_total_size = (uint32)*total_size;
    if (param->is_read) {
        if (param->atom_oper) {
            offset = param->offset;
        } else {
            offset = context->offset;
        }
        need_refresh = ((tmp_total_size + (uint64)offset) > context->node->written_size);
    }
    if (!dss_is_fs_meta_valid(context->node) || need_refresh) {
        status_t status = dss_check_apply_refresh_file(conn, context, 0);
        if (status != CM_SUCCESS) {
            LOG_RUN_ERR("Failed to apply refresh file:%s, fid:%llu.", context->node->name, context->fid);
            return CM_ERROR;
        }
        // check if read data from offset with tmp_total_size more than the node->size
        if (param->is_read && ((tmp_total_size + (uint64)offset) > (uint64)context->node->size)) {
            // no data to read
            if ((uint64)offset >= (uint64)context->node->size) {
                LOG_DEBUG_INF("Node:%s has no data to read.", dss_display_metaid(context->node->id));
                *total_size = 0;
                // no enough data to read
            } else {
                LOG_DEBUG_INF("Node:%s has no enough data to read form offset.", dss_display_metaid(context->node->id));
                *total_size = (int32)((uint64)context->node->size - (uint64)offset);
            }
        }
    }
    return CM_SUCCESS;
}

static void dss_check_file_written_size(
    dss_conn_t *conn, dss_file_context_t *context, uint32 start_offset, bool32 is_read, int32 *total_size)
{
    uint32 tmp_total_size = (uint32)*total_size;
    if (is_read && ((tmp_total_size + start_offset) > context->node->written_size)) {
        // no data to read
        if (start_offset >= context->node->written_size) {
            LOG_DEBUG_INF("Node:%s has no data to read.", dss_display_metaid(context->node->id));
            *total_size = 0;
            // no enough data to read
        } else {
            LOG_DEBUG_INF("Node:%s has no enough data to read form offset.", dss_display_metaid(context->node->id));
            *total_size = (int32)((uint64)context->node->written_size - (uint64)start_offset);
        }
        if (*total_size > 0) {
            tmp_total_size = (uint32)*total_size;
            // write can do write 513, but read can NOT read 513, only can read 512 + 512, need to fix
            tmp_total_size = CM_CALC_ALIGN(tmp_total_size, DSS_BLOCK_SIZE);
            *total_size = (int32)tmp_total_size;
        }
    }
    LOG_DEBUG_INF("Success to refresh file:%s, written_size:%llu, size:%llu.", context->node->name,
        context->node->written_size, context->node->size);
}

static status_t dss_check_refresh_file_by_offset(
    dss_conn_t *conn, dss_file_context_t *context, int64 offset, bool32 is_read)
{
    // posix do pwrite if ofset more than node->size, pread return count 0 witch errno is success
    if (!dss_is_fs_meta_valid(context->node) || (is_read && (uint64)offset >= context->node->written_size)) {
        if (dss_check_apply_refresh_file(conn, context, 0) != CM_SUCCESS) {
            LOG_DEBUG_ERR("Failed to apply refresh file, fid:%llu.", context->fid);
            return CM_ERROR;
        }
        LOG_DEBUG_INF("Apply to refresh file, offset:%lld, size:%lld", offset, context->node->written_size);
    }
    return CM_SUCCESS;
}

static status_t dss_check_apply_extending_file(
    dss_conn_t *conn, dss_file_context_t *context, int32 handle, int64 size, int64 offset)
{
    DSS_UNLOCK_VG_META_S(context->vg_item, conn->session);
    status_t status = dss_apply_extending_file(conn, handle, size, offset);
    if (status != CM_SUCCESS) {
        LOG_RUN_ERR("Failed to apply extending file, fid:%llu.", context->fid);
        return CM_ERROR;
    }
    DSS_LOCK_VG_META_S_RETURN_ERROR(context->vg_item, conn->session);
    return dss_check_apply_refresh_file(conn, context, offset);
}

static status_t dss_check_refresh_volume(dss_conn_t *conn, dss_file_context_t *context, auid_t auid, bool32 *is_refresh)
{
    status_t status;
    dss_vg_info_item_t *vg_item = context->vg_item;
    dss_cli_vg_handles_t *dss_cli_vg_handles = (dss_cli_vg_handles_t *)(conn->cli_vg_handles);
    dss_simple_volume_t *vol = &dss_cli_vg_handles->vg_vols[vg_item->id].volume_handle[auid.volume];

    if (vol->handle == DSS_INVALID_HANDLE) {
        DSS_UNLOCK_VG_META_S(context->vg_item, conn->session);
        status = dss_apply_refresh_volume(conn, context, auid);
        if (status != CM_SUCCESS) {
            LOG_DEBUG_ERR("Failed to refresh volum, auid:%s.", dss_display_metaid(auid));
            return status;
        }
        DSS_LOCK_VG_META_S_RETURN_ERROR(context->vg_item, conn->session);
        status = dss_refresh_volume_handle(conn, context, auid);
        if (status != CM_SUCCESS) {
            DSS_UNLOCK_VG_META_S(context->vg_item, conn->session);
            LOG_DEBUG_ERR("Failed to refresh volume handle, auid:%s.", dss_display_metaid(auid));
            return status;
        }
        *is_refresh = CM_TRUE;
    }

    // volume maybe be remove and add again
    if (vol->version != vg_item->dss_ctrl->volume.defs[auid.volume].version) {
        status = dss_reopen_volume_handle(conn, context, auid);
        if (status != CM_SUCCESS) {
            DSS_UNLOCK_VG_META_S(context->vg_item, conn->session);
            LOG_DEBUG_ERR("Failed to reopen volume handle, auid:%s.", dss_display_metaid(auid));
            return status;
        }
        *is_refresh = CM_TRUE;
    }

    if (!dss_is_fs_meta_valid(context->node)) {
        if (dss_check_apply_refresh_file(conn, context, 0) != CM_SUCCESS) {
            LOG_DEBUG_ERR("Failed to apply refresh file, fid:%llu.", context->fid);
            return CM_ERROR;
        }
        *is_refresh = CM_TRUE;
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
    dss_init_set(&conn->pack, conn->proto_version);

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
    if (vg_item->dss_ctrl->volume.defs[auid.volume].flag != VOLUME_OCCUPY) {
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
    dss_init_set(&conn->pack, conn->proto_version);

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

    LOG_DEBUG_INF("Apply to refresh file table blockid:%s, vgid:%u, vg name:%s.", dss_display_metaid(blockid),
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

status_t dss_connect(const char *server_locator, dss_conn_opt_t *options, dss_conn_t *conn)
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
    int timeout = options != NULL ? options->timeout : g_dss_uds_conn_timeout;
    conn->pipe.connect_timeout = timeout < 0 ? DSS_UDS_CONNECT_TIMEOUT : timeout;
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
            DSS_FREE_POINT(conn->cli_vg_handles);
            return status;
        }
    }

    cli_vg_handles->group_num = g_vgs_info->group_num;
    return CM_SUCCESS;
}

status_t dss_set_session_id(dss_conn_t *conn, uint32 sid)
{
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

static status_t dss_set_server_info(dss_conn_t *conn, char *home, uint32 sid, uint32 max_open_file)
{
    status_t status = dss_init(max_open_file, home);
    DSS_RETURN_IFERR3(status, LOG_RUN_ERR_INHIBIT(LOG_INHIBIT_LEVEL1, "Dss client init failed."), dss_disconnect(conn));

    status = dss_set_session_id(conn, sid);
    DSS_RETURN_IFERR3(status, LOG_RUN_ERR_INHIBIT(LOG_INHIBIT_LEVEL1, "Dss client failed to initialize session."),
        dss_disconnect(conn));
    return CM_SUCCESS;
}

status_t dss_cli_handshake(dss_conn_t *conn, uint32 max_open_file)
{
    dss_cli_info cli_info;
    cli_info.cli_pid = cm_sys_pid();
    status_t status = cm_sys_process_start_time(cli_info.cli_pid, &cli_info.start_time);
    if (status != CM_SUCCESS) {
        LOG_RUN_ERR("Failed to get process start time pid %llu.\n", cli_info.cli_pid);
        return CM_ERROR;
    }
    LOG_DEBUG_INF("The process start time is:%lld.", cli_info.start_time);

    errno_t err;
    err = strcpy_s(cli_info.process_name, sizeof(cli_info.process_name), cm_sys_program_name());
    if (err != EOK) {
        LOG_DEBUG_ERR("System call strcpy_s error %d.", err);
        return CM_ERROR;
    }

    dss_get_server_info_t output_info = {NULL, DSS_INVALID_SESSIONID};
    CM_RETURN_IFERR(dss_msg_interact(conn, DSS_CMD_HANDSHAKE, (void *)&cli_info, (void *)&output_info));
    return dss_set_server_info(conn, output_info.home, output_info.sid, max_open_file);
}

// NOTE:just for dsscmd because not support many threads in one process.
status_t dss_connect_ex(const char *server_locator, dss_conn_opt_t *options, dss_conn_t *conn)
{
    status_t status = CM_ERROR;
    dss_env_t *dss_env = dss_get_env();
    dss_init_conn(conn);
    do {
        status = dss_connect(server_locator, options, conn);
        DSS_BREAK_IFERR2(status, LOG_RUN_ERR_INHIBIT(LOG_INHIBIT_LEVEL1, "Dss client connet server failed."));
        uint32 max_open_file = DSS_DEFAULT_OPEN_FILES_NUM;
        conn->proto_version = DSS_PROTO_VERSION;
        status = dss_cli_handshake(conn, max_open_file);
        DSS_BREAK_IFERR3(status, LOG_RUN_ERR_INHIBIT(LOG_INHIBIT_LEVEL1, "Dss client handshake to server failed."),
            dss_disconnect(conn));

        status = dss_init_vol_handle_sync(conn);
        DSS_BREAK_IFERR3(status, LOG_RUN_ERR_INHIBIT(LOG_INHIBIT_LEVEL1, "Dss client init vol handle failed."),
            dss_disconnect(conn));
        dss_env->conn_count++;
    } while (0);
    return status;
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
    DSS_RETURN_IF_ERROR(dss_check_device_path(parent));
    DSS_RETURN_IF_ERROR(dss_check_name(dir_name));
    LOG_DEBUG_INF("dss make dir entry, parent:%s, dir_name:%s", parent, dir_name);
    dss_make_dir_info_t send_info;
    send_info.parent = parent;
    send_info.name = dir_name;
    status_t status = dss_msg_interact(conn, DSS_CMD_MKDIR, (void *)&send_info, NULL);
    LOG_DEBUG_INF("dss make dir leave");
    return status;
}

status_t dss_remove_dir_impl(dss_conn_t *conn, const char *dir, bool32 recursive)
{
    DSS_RETURN_IF_ERROR(dss_check_device_path(dir));
    LOG_DEBUG_INF("dss remove dir entry, dir:%s, recursive:%d", dir, recursive);
    dss_remove_dir_info_t send_info;
    send_info.name = dir;
    send_info.recursive = recursive;
    status_t status = dss_msg_interact(conn, DSS_CMD_RMDIR, (void *)&send_info, NULL);
    LOG_DEBUG_INF("dss remove dir leave");
    return status;
}

static dss_dir_t *dss_open_dir_impl_core(dss_conn_t *conn, dss_find_node_t *find_node)
{
    dss_vg_info_item_t *vg_item = dss_find_vg_item(find_node->vg_name);
    if (vg_item == NULL) {
        LOG_RUN_ERR("Failed to find vg, %s.", find_node->vg_name);
        DSS_THROW_ERROR(ERR_DSS_VG_NOT_EXIST, find_node->vg_name);
        return NULL;
    }

    DSS_LOCK_VG_META_S_RETURN_NULL(vg_item, conn->session);
    gft_node_t *node = dss_get_ft_node_by_ftid(conn->session, vg_item, find_node->ftid, CM_FALSE, CM_FALSE);
    if (node == NULL) {
        DSS_THROW_ERROR(ERR_DSS_INVALID_ID, "find_node ftid", *(uint64 *)&find_node->ftid);
        DSS_UNLOCK_VG_META_S(vg_item, conn->session);
        return NULL;
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
    dir->pftid = node->id;
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

    // 1. PATH
    if (dss_check_device_path(dir_path) != CM_SUCCESS) {
        return NULL;
    }
    dss_find_node_t *find_node;
    dss_open_dir_info_t send_info;
    send_info.dir_path = dir_path;
    send_info.refresh_recursive = refresh_recursive;
    status_t status = dss_msg_interact(conn, DSS_CMD_OPEN_DIR, (void *)&send_info, (void *)&find_node);
    if (status != CM_SUCCESS) {
        return NULL;
    }
    return dss_open_dir_impl_core(conn, find_node);
}

gft_node_t *dss_read_dir_impl(dss_conn_t *conn, dss_dir_t *dir, bool32 skip_delete)
{
    if (dir == NULL) {
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

    DSS_LOCK_VG_META_S_RETURN_NULL(dir->vg_item, conn->session);

    gft_node_t *node = dss_get_ft_node_by_ftid(conn->session, dir->vg_item, dir->cur_ftid, CM_FALSE, CM_FALSE);
    while (node != NULL) {
        dir->cur_ftid = node->next;
        dir->cur_node = *node;
        if (!skip_delete || ((node->flags & DSS_FT_NODE_FLAG_DEL) == 0)) {
            DSS_UNLOCK_VG_META_S(dir->vg_item, conn->session);
            return &dir->cur_node;
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
        DSS_LOCK_VG_META_S_RETURN_NULL(dir->vg_item, conn->session);
        node = dss_get_ft_node_by_ftid(conn->session, dir->vg_item, dir->cur_ftid, CM_FALSE, CM_FALSE);
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
    dss_init_set(&conn->pack, conn->proto_version);
    send_pack = &conn->pack;
    send_pack->head->cmd = DSS_CMD_CLOSE_DIR;
    send_pack->head->flags = 0;

    // 1. pftid
    uint64 pftid = *(uint64 *)&dir->pftid;
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
    dss_init_set(&conn->pack, conn->proto_version);

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
    dss_init_set(&conn->pack, conn->proto_version);

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
    dss_init_set(&conn->pack, conn->proto_version);
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
    if (extra_info.len != sizeof(dss_find_node_t)) {
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

    LOG_DEBUG_INF("dss get node ftid: %s, vg: %s by path: %s", dss_display_metaid(*ftid), vg_name, path);
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

    DSS_LOCK_VG_META_S_RETURN_NULL(vg_item, conn->session);
    gft_node_t *node = dss_get_ft_node_by_ftid(conn->session, vg_item, ftid, CM_FALSE, CM_FALSE);
    DSS_UNLOCK_VG_META_S(vg_item, conn->session);
    return node;
}

status_t dss_init_file_context(
    dss_file_context_t *context, gft_node_t *out_node, dss_vg_info_item_t *vg_item, dss_file_mode_e mode)
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
    context->mode = mode;
    return CM_SUCCESS;
}

status_t dss_open_file_inner(dss_vg_info_item_t *vg_item, gft_node_t *ft_node, dss_file_mode_e mode, int *handle)
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

    status_t ret = dss_init_file_context(context, ft_node, vg_item, mode);
    DSS_RETURN_IFERR2(ret, dss_unlatch(&dss_env->latch));
    dss_env->file_free_first = next;
    dss_env->has_opened_files++;
    dss_unlatch(&dss_env->latch);
    return CM_SUCCESS;
}

status_t dss_open_file_on_server(dss_conn_t *conn, const char *file_path, int flag, dss_find_node_t **find_node)
{
    dss_open_file_info_t send_info;
    send_info.file_path = file_path;
    send_info.flag = flag;
    return dss_msg_interact(conn, DSS_CMD_OPEN_FILE, (void *)&send_info, (void *)find_node);
}

status_t dss_open_file_impl(dss_conn_t *conn, const char *file_path, int flag, int *handle)
{
    status_t status = CM_ERROR;
    gft_node_t *ft_node = NULL;
    dss_find_node_t *find_node = NULL;
    LOG_DEBUG_INF("dss begin to open file, file path:%s, flag:%d", file_path, flag);
    DSS_RETURN_IF_ERROR(dss_check_device_path(file_path));
    DSS_RETURN_IF_ERROR(dss_open_file_on_server(conn, file_path, flag, &find_node));
    dss_vg_info_item_t *vg_item = dss_find_vg_item(find_node->vg_name);
    if (vg_item == NULL) {
        LOG_RUN_ERR("Failed to find vg, vg name %s.", find_node->vg_name);
        DSS_THROW_ERROR(ERR_DSS_VG_NOT_EXIST, find_node->vg_name);
        return CM_ERROR;
    }
    DSS_LOCK_VG_META_S_RETURN_ERROR(vg_item, conn->session);
    do {
        ft_node = dss_get_ft_node_by_ftid(conn->session, vg_item, find_node->ftid, CM_FALSE, CM_FALSE);
        if (ft_node == NULL) {
            DSS_THROW_ERROR(ERR_DSS_INVALID_ID, "find_node ftid", *(uint64 *)&find_node->ftid);
            status = CM_ERROR;
            break;
        }
        status = dss_open_file_inner(vg_item, ft_node, DSS_OPEN_MODE(flag), handle);
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

status_t dss_latch_context_by_handle(
    dss_conn_t *conn, int32 handle, dss_file_context_t **context, dss_latch_mode_e latch_mode)
{
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

    dss_latch(&file_cxt->latch, latch_mode, ((dss_session_t *)conn->session)->id);
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

    *context = file_cxt;
    return CM_SUCCESS;
}

status_t dss_close_file_impl(dss_conn_t *conn, int handle)
{
    char *fname = NULL;

    LOG_DEBUG_INF("dss close file entry, handle:%d", handle);

    dss_file_context_t *context = NULL;
    DSS_RETURN_IF_ERROR(dss_latch_context_by_handle(conn, handle, &context, LATCH_MODE_EXCLUSIVE));
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

status_t dss_exist_impl(dss_conn_t *conn, const char *path, bool32 *result, gft_item_type_t *type)
{
    dss_packet_t *send_pack;
    dss_packet_t *ack_pack;
    int32 errcode = -1;
    char *errmsg = NULL;

    LOG_DEBUG_INF("dss exits file entry, name:%s", path);

    // make up packet
    dss_init_set(&conn->pack, conn->proto_version);

    send_pack = &conn->pack;
    send_pack->head->cmd = DSS_CMD_EXIST;
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

    dss_init_get(ack_pack);
    if (dss_get_int32(ack_pack, (int32 *)result) != CM_SUCCESS) {
        DSS_THROW_ERROR(ERR_DSS_CLI_EXEC_FAIL, dss_get_cmd_desc(DSS_CMD_EXIST), "get result data error");
        LOG_DEBUG_ERR("get result data error.");
        return CM_ERROR;
    }
    if (dss_get_int32(ack_pack, (int32 *)type) != CM_SUCCESS) {
        DSS_THROW_ERROR(ERR_DSS_CLI_EXEC_FAIL, dss_get_cmd_desc(DSS_CMD_EXIST), "get type data error");
        LOG_DEBUG_ERR("get type data error.");
        return CM_ERROR;
    }

    LOG_DEBUG_INF("dss exits file or dir leave, name:%s, result:%d, type:%u", path, *result, *type);
    return CM_SUCCESS;
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

    if (dss_validate_seek_origin(origin, offset, context, &new_offset) != CM_SUCCESS) {
        DSS_UNLOCK_VG_META_S(context->vg_item, conn->session);
        return CM_ERROR;
    }

    size = cm_atomic_get(&context->node->size);
    if (!dss_is_fs_meta_valid(context->node) || new_offset > size || need_refresh) {
        status = dss_check_apply_refresh_file(conn, context, 0);
        DSS_RETURN_IFERR2(status, LOG_DEBUG_ERR("Failed to apply refresh file,fid:%llu.", context->fid));
        size = cm_atomic_get(&context->node->size);

        if (offset > size && param->is_read) {
            LOG_DEBUG_ERR("Invalid parameter offset is greater than size, offset:%lld, new_offset:%lld,"
                          " file size:%llu, vgid:%u, fid:%llu, node fid:%llu, need_refresh:%d.",
                offset, new_offset, context->node->size, context->vg_item->id, context->fid, context->node->fid,
                need_refresh);
            DSS_THROW_ERROR(ERR_DSS_FILE_SEEK, context->vg_item->id, context->fid, offset, context->node->size);
            DSS_UNLOCK_VG_META_S(context->vg_item, conn->session);
            return CM_ERROR;
        }
        LOG_DEBUG_INF("Apply to refresh file, offset:%lld, size:%lld, need_refresh:%d.", offset, size, need_refresh);
    }
    if (origin == SEEK_END) {
        new_offset = (int64)context->node->written_size + offset;
    } else if (origin == DSS_SEEK_MAXWR) {
        new_offset = (int64)context->node->written_size;
    }
    if (new_offset < 0) {
        DSS_THROW_ERROR(ERR_DSS_FILE_SEEK, context->vg_item->id, context->fid, offset, context->node->size);
        DSS_UNLOCK_VG_META_S(context->vg_item, conn->session);
        return CM_ERROR;
    }
    if (new_offset == 0) {
        context->vol_offset = 0;
    }
    context->offset = new_offset;
    LOG_DEBUG_INF("Success to seek(origin:%d) file:%s, offset:%lld, fsize:%llu, written_size:%llu.", origin,
        context->node->name, new_offset, context->node->size, context->node->written_size);
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
    param->is_read = DSS_FALSE;
}

static int64 dss_seek_file_prepare(
    dss_conn_t *conn, dss_file_context_t *context, dss_rw_param_t *param, int64 offset, int origin)
{
    DSS_LOCK_VG_META_S_RETURN_ERROR(context->vg_item, conn->session);
    int64 ret = dss_seek_file_impl_core(param, offset, origin);
    if (ret == CM_ERROR) {
        return CM_ERROR;
    }
    DSS_UNLOCK_VG_META_S(context->vg_item, conn->session);
    return ret;
}

int64 dss_seek_file_impl(dss_conn_t *conn, int handle, int64 offset, int origin)
{
    LOG_DEBUG_INF("dss seek file entry, handle:%d, offset:%lld, origin:%d", handle, offset, origin);

    dss_file_context_t *context = NULL;
    DSS_RETURN_IF_ERROR(dss_latch_context_by_handle(conn, handle, &context, LATCH_MODE_EXCLUSIVE));

    dss_rw_param_t param;
    dss_init_rw_param(&param, conn, handle, context, context->offset, DSS_FALSE);
    int64 new_offset = dss_seek_file_prepare(conn, context, &param, offset, origin);
    dss_unlatch(&context->latch);

    LOG_DEBUG_INF("dss seek file leave, new_offset:%lld", new_offset);
    return new_offset;
}

static status_t dss_check_ready_fs_block(files_rw_ctx_t *rw_ctx, dss_fs_pos_desc_t *fs_pos)
{
    dss_conn_t *conn = rw_ctx->conn;
    dss_file_context_t *context = rw_ctx->file_ctx;
    gft_node_t *node = context->node;
    uint64 au_size = dss_get_vg_au_size(context->vg_item->dss_ctrl);

    bool32 read_has_refresh = CM_FALSE;
    do {
        status_t status = dss_check_find_fs_block(rw_ctx, fs_pos);
        DSS_RETURN_IFERR2(status, LOG_RUN_ERR("Failed to find fs block."));
        if (fs_pos->is_valid) {
            if (!rw_ctx->read) {
                return CM_SUCCESS;
            }

            if (!fs_pos->is_exist_aux || DSS_BLOCK_ID_IS_INITED(fs_pos->data_auid)) {
                return CM_SUCCESS;
            }

            // one read, one au
            int32 cur_size = rw_ctx->size;
            if (cur_size > (int32)(au_size - fs_pos->au_offset)) {
                cur_size = (int32)(au_size - fs_pos->au_offset);
            }

            int32 inited_size = 0;
            dss_get_inited_size_with_fs_aux(context->vg_item, fs_pos->fs_aux, rw_ctx->offset, cur_size, &inited_size);
            if (inited_size == cur_size) {
                return CM_SUCCESS;
            }

            if (read_has_refresh) {
                return CM_SUCCESS;
            }
            read_has_refresh = CM_TRUE;
            fs_pos->is_valid = CM_FALSE;
        }

        // try ask help from server
        if (!rw_ctx->read) {
            status = dss_check_apply_extending_file(conn, context, rw_ctx->handle, rw_ctx->size, rw_ctx->offset);
            DSS_RETURN_IFERR2(status, LOG_RUN_ERR("Failed to extend file fs block."));
        } else {
            // when be written, need to wait server to write zero
            status = dss_check_apply_refresh_file(conn, context, rw_ctx->offset);
            DSS_RETURN_IFERR2(status, LOG_RUN_ERR("Failed to refresh fs block"));
            // after check from server, if try to read, but no more data to read, go back to caller
            if (rw_ctx->read && (uint64)rw_ctx->offset >= node->written_size) {
                break;
            }
        }
    } while (CM_TRUE);
    return CM_SUCCESS;
}

static status_t dss_update_written_size(
    dss_env_t *dss_env, dss_conn_t *conn, dss_file_context_t *context, int64 offset, int64 size)
{
    int32 errcode = -1;
    char *errmsg = NULL;
    uint64 fid = context->fid;
    ftid_t ftid = context->node->id;

    // make up packet
    dss_init_set(&conn->pack, conn->proto_version);

    dss_packet_t *send_pack = &conn->pack;
    send_pack->head->cmd = DSS_CMD_UPDATE_WRITTEN_SIZE;
    send_pack->head->flags = 0;

    // 1. fid
    CM_RETURN_IFERR(dss_put_int64(send_pack, *(uint64 *)&context->node->fid));
    // 2. ftid
    CM_RETURN_IFERR(dss_put_int64(send_pack, *(uint64 *)&ftid));
    // 3. vg id
    CM_RETURN_IFERR(dss_put_int32(send_pack, context->vgid));
    // 4. offset
    CM_RETURN_IFERR(dss_put_int64(send_pack, (uint64)offset));
    // 5. size
    CM_RETURN_IFERR(dss_put_int64(send_pack, (uint64)size));

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
    LOG_DEBUG_INF("Success to update written_size for file:\"%s\", fid:%llu, updated offset:%lld, size:%lld.",
        context->node->name, fid, offset, size);
    return CM_SUCCESS;
}

static void dss_api_check_need_updt_fs_aux(dss_file_context_t *context, files_rw_ctx_t *rw_ctx,
    dss_fs_pos_desc_t *fs_pos, int32 real_size, bool32 *need_updt_fs_aux)
{
    if (rw_ctx->offset % DSS_PAGE_SIZE != 0 || (rw_ctx->offset + real_size) % DSS_PAGE_SIZE != 0) {
        *need_updt_fs_aux = CM_TRUE;
    } else {
        int32 inited_size = 0;
        dss_get_inited_size_with_fs_aux(context->vg_item, fs_pos->fs_aux, rw_ctx->offset, real_size, &inited_size);
        if (real_size != inited_size) {
            *need_updt_fs_aux = CM_TRUE;
        }
    }
}

static void dss_read_write_check_need_updt_fs_aux(
    dss_rw_param_t *param, files_rw_ctx_t *rw_ctx, dss_fs_pos_desc_t *fs_pos, int32 real_size, bool32 *need_updt_fs_aux)
{
    dss_file_context_t *context = param->context;
    gft_node_t *node = context->node;

    // try to avoid too much update for fs_aux info
    if (DSS_IS_FILE_INNER_INITED(node->flags) && !param->is_read && !(*need_updt_fs_aux) && fs_pos->fs_aux != NULL &&
        (uint64)(rw_ctx->offset + real_size) > node->min_inited_size) {
        dss_api_check_need_updt_fs_aux(context, rw_ctx, fs_pos, real_size, need_updt_fs_aux);
    }
}

status_t dss_read_write_file_core(dss_rw_param_t *param, void *buf, int32 size, int32 *read_size)
{
    status_t status = CM_SUCCESS;
    int32 total_size = size;
    int32 read_cnt = 0;

    dss_conn_t *conn = param->conn;
    int handle = param->handle;
    dss_env_t *dss_env = param->dss_env;
    dss_file_context_t *context = param->context;

    DSS_SET_PTR_VALUE_IF_NOT_NULL(read_size, 0);
    DSS_LOCK_VG_META_S_RETURN_ERROR(context->vg_item, conn->session);

    CM_RETURN_IFERR(dss_check_refresh_file_by_size(conn, context, param, &total_size));
    // after refresh, still has no data, read return with 0, may truncate by others
    if (param->is_read && total_size == 0) {
        *read_size = 0;
        DSS_UNLOCK_VG_META_S(context->vg_item, conn->session);
        return CM_SUCCESS;
    }

    gft_node_t *node = context->node;
    dss_vg_info_item_t *vg_item = context->vg_item;

    dss_fs_pos_desc_t fs_pos = {0};
    uint64 au_size = dss_get_vg_au_size(vg_item->dss_ctrl);

    uint32 retry_time = 0;
    int64 base_offset = (param->atom_oper ? param->offset : context->offset);
    bool32 need_updt_fs_aux = CM_FALSE;
    files_rw_ctx_t rw_ctx;
    do {
        rw_ctx.conn = conn;
        rw_ctx.env = dss_env;
        rw_ctx.file_ctx = context;
        rw_ctx.handle = handle;
        rw_ctx.size = total_size;
        rw_ctx.read = param->is_read;
        rw_ctx.offset = (param->atom_oper ? param->offset : context->offset);

        // after refresh, still has no data, read return with 0, may truncate by others
        dss_check_file_written_size(conn, context, rw_ctx.offset, param->is_read, &total_size);
        if (param->is_read && total_size == 0) {
            *read_size = 0;
            DSS_UNLOCK_VG_META_S(context->vg_item, conn->session);
            return CM_SUCCESS;
        }

        status = dss_check_ready_fs_block(&rw_ctx, &fs_pos);
        if (status != CM_SUCCESS) {
            LOG_RUN_ERR("The offset:%lld to ready block fail.", rw_ctx.offset);
            return CM_ERROR;
        }

        if (rw_ctx.read && !fs_pos.is_valid) {
            *read_size = 0;
            DSS_UNLOCK_VG_META_S(context->vg_item, conn->session);
            return CM_SUCCESS;
        }

        auid_t auid = fs_pos.data_auid;
        if (auid.volume >= DSS_MAX_VOLUMES) {
            DSS_UNLOCK_VG_META_S(context->vg_item, conn->session);
            DSS_THROW_ERROR(ERR_DSS_INVALID_ID, "au", *(uint64 *)&auid);
            DSS_ASSERT_LOG(0, "Auid is invalid, volume:%u, fname:%s, fsize:%llu, written_size:%llu.",
                (uint32)auid.volume, node->name, node->size, node->written_size);
            return CM_ERROR;
        }

        LOG_DEBUG_INF("Found auid:%llu for node:%llu, name:%s.", DSS_ID_TO_U64(auid), DSS_ID_TO_U64(context->node->id),
            context->node->name);

        bool32 is_refresh = CM_FALSE;
        status = dss_check_refresh_volume(conn, context, auid, &is_refresh);
        if (status != CM_SUCCESS) {
            LOG_DEBUG_ERR("Refresh volume:%llu fail.", (uint64)auid.volume);
            return CM_ERROR;
        }
        // so bad need start from begin again
        if (is_refresh) {
            // dss_check_refrsh_volume may unlock the vg, other task may truncate this file, need recheck from begin
            retry_time++;
            LOG_DEBUG_INF("Node:%s, name:%s, fsize:%llu, written_size:%llu, retry_time:%u.",
                dss_display_metaid(node->id), node->name, node->size, node->written_size, retry_time);
            continue;
        }
        dss_cli_vg_handles_t *cli_vg_handles = (dss_cli_vg_handles_t *)(conn->cli_vg_handles);
        dss_simple_volume_t *vol = &cli_vg_handles->vg_vols[vg_item->id].volume_handle[auid.volume];
        uint64 vol_offset = (uint64)dss_get_au_offset(vg_item, auid);
        vol_offset = vol_offset + (uint64)fs_pos.au_offset;
        // wrongly writing superau area
        if (vol_offset < au_size) {
            LOG_RUN_ERR("The volume offset:%llu is invalid!", vol_offset);
            CM_ASSERT(0);
        }
#ifdef OPENGAUSS
        dss_vg_info_item_t *first_vg_item = dss_get_first_vg_item();
        if (strcmp(first_vg_item->vg_name, vg_item->vg_name) == 0 && auid.volume == 0) {
            if (g_log_offset == DSS_INVALID_64) {
                uint32 log_offset = dss_get_log_size(au_size);
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
        if ((uint32)total_size > au_size - fs_pos.au_offset) {
            real_size = (int32)(au_size - fs_pos.au_offset);
            total_size -= real_size;
        } else {
            real_size = total_size;
            total_size = 0;
        }

        dss_volume_t volume;
        volume.handle = vol->handle;
        volume.unaligned_handle = vol->unaligned_handle;
        volume.id = vol->id;
        volume.name_p = vg_item->dss_ctrl->volume.defs[auid.volume].name;
        volume.vg_type = vol->vg_type;
        if (param->is_read) {
            LOG_DEBUG_INF("Begin to read volume %s, offset:%lld, size:%d, fname:%s, fsize:%llu, fwritten_size:%llu.",
                volume.name_p, vol_offset, real_size, node->name, node->size, node->written_size);
            status = dss_read_volume_with_fs_aux(
                vg_item, node, fs_pos.fs_aux, &volume, (int64)vol_offset, rw_ctx.offset, buf, real_size);
        } else {
            LOG_DEBUG_INF("Begin to write volume %s, offset:%lld, size:%d, fname:%s, fsize:%llu, fwritten_size:%llu.",
                volume.name_p, vol_offset, real_size, node->name, node->size, node->written_size);
            status = dss_write_volume(&volume, (int64)vol_offset, buf, real_size);
        }
        if (status != CM_SUCCESS) {
            DSS_UNLOCK_VG_META_S(context->vg_item, conn->session);
            LOG_DEBUG_ERR("Failed to read write file:(id:%u, handle:%d, unaligned_handle:%d), offset:%llu, size:%d.",
                volume.id, volume.handle, volume.unaligned_handle, vol_offset, real_size);
            return status;
        }

        dss_read_write_check_need_updt_fs_aux(param, &rw_ctx, &fs_pos, real_size, &need_updt_fs_aux);

        read_cnt += real_size;
        if (param->atom_oper) {
            param->offset += real_size;
        } else {
            context->offset += real_size;
            context->vol_offset = (int64)vol_offset;
        }
        buf = (void *)(((char *)buf) + real_size);
        if (param->atom_oper) {
            if (param->is_read && param->offset >= context->node->size) {
                break;
            }
        } else if (param->is_read && context->offset >= context->node->size) {
            break;
        }
    } while (total_size > 0);

    DSS_UNLOCK_VG_META_S(context->vg_item, conn->session);
    DSS_SET_PTR_VALUE_IF_NOT_NULL(read_size, read_cnt);

    /* tracking real written size may hinder performance, hence disabled otherwise */
    int64 offset = (param->atom_oper ? param->offset : context->offset);
    bool32 need_update = offset > context->node->written_size && !param->is_read;
    if (need_update || need_updt_fs_aux) { /* updates written size outside of locking */
        LOG_DEBUG_INF("Start update_written_size for file:\"%s\", curr offset:%llu, curr written_size:%llu, size:%d.",
            node->name, base_offset, node->written_size, size);
        status = dss_update_written_size(dss_env, conn, context, base_offset, (int64)size);
    }

    return status;
}

status_t dss_read_write_file(dss_conn_t *conn, int32 handle, void *buf, int32 size, int32 *read_size, bool32 is_read)
{
    status_t status;
    dss_file_context_t *context = NULL;
    dss_rw_param_t param;

    if (size < 0) {
        LOG_DEBUG_ERR("File size is invalid: %d.", size);
        return CM_ERROR;
    }
    LOG_DEBUG_INF("dss read write file entry, handle:%d, is_read:%u", handle, is_read);

    DSS_RETURN_IF_ERROR(dss_latch_context_by_handle(conn, handle, &context, LATCH_MODE_EXCLUSIVE));
    bool mode_match = is_read ? (context->mode & DSS_FILE_MODE_READ) : (context->mode & DSS_FILE_MODE_WRITE);
    if (!mode_match) {
        dss_unlatch(&context->latch);
        DSS_THROW_ERROR(ERR_DSS_FILE_RDWR_INSUFF_PER, is_read ? "read" : "write", context->mode);
        return CM_ERROR;
    }
    dss_init_rw_param(&param, conn, handle, context, context->offset, DSS_FALSE);
    param.is_read = is_read;
    status = dss_read_write_file_core(&param, buf, size, read_size);
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

static status_t dss_pwrite_file_prepare(dss_conn_t *conn, dss_file_context_t *context, long long offset)
{
    DSS_LOCK_VG_META_S_RETURN_ERROR(context->vg_item, conn->session);
    status_t status = dss_check_refresh_file_by_offset(conn, context, offset, CM_FALSE);
    if (status != CM_SUCCESS) {
        return status;
    }
    DSS_UNLOCK_VG_META_S(context->vg_item, conn->session);
    return CM_SUCCESS;
}

status_t dss_pwrite_file_impl(dss_conn_t *conn, int handle, const void *buf, int size, long long offset)
{
    status_t status;
    dss_file_context_t *context = NULL;
    dss_rw_param_t param;

    CM_RETURN_IFERR(dss_latch_context_by_handle(conn, handle, &context, LATCH_MODE_SHARE));
    LOG_DEBUG_INF("dss pwrite file %s, handle:%d, offset:%lld, size:%d", context->node->name, handle, offset, size);
    if (!(context->mode & DSS_FILE_MODE_WRITE)) {
        dss_unlatch(&context->latch);
        DSS_THROW_ERROR(ERR_DSS_FILE_RDWR_INSUFF_PER, "pwrite", context->mode);
        return CM_ERROR;
    }

    dss_init_rw_param(&param, conn, handle, context, offset, DSS_TRUE);
    param.is_read = DSS_FALSE;
    if (dss_pwrite_file_prepare(conn, context, offset) != CM_SUCCESS) {
        dss_unlatch(&context->latch);
        return CM_ERROR;
    }
    status = dss_read_write_file_core(&param, (void *)buf, size, NULL);
    dss_unlatch(&context->latch);
    LOG_DEBUG_INF("dss pwrite file leave, result: %d", status);

    return status;
}

static status_t dss_pread_file_prepare(
    dss_conn_t *conn, dss_file_context_t *context, int size, long long offset, bool32 *read_end)
{
    *read_end = CM_FALSE;
    DSS_LOCK_VG_META_S_RETURN_ERROR(context->vg_item, conn->session);
    status_t status = dss_check_refresh_file_by_offset(conn, context, offset, CM_TRUE);
    if (status != CM_SUCCESS) {
        return status;
    }
    if ((uint64)offset == context->node->size || size == 0) {
        *read_end = CM_TRUE;
    }
    DSS_UNLOCK_VG_META_S(context->vg_item, conn->session);
    return CM_SUCCESS;
}

status_t dss_pread_file_impl(dss_conn_t *conn, int handle, void *buf, int size, long long offset, int *read_size)
{
    status_t status;
    dss_file_context_t *context = NULL;
    dss_rw_param_t param;

    CM_RETURN_IFERR(dss_latch_context_by_handle(conn, handle, &context, LATCH_MODE_SHARE));
    LOG_DEBUG_INF(
        "dss pread file entry, name:%s, handle:%d, offset:%lld, size:%d", context->node->name, handle, offset, size);
    if (!(context->mode & DSS_FILE_MODE_READ)) {
        dss_unlatch(&context->latch);
        DSS_THROW_ERROR(ERR_DSS_FILE_RDWR_INSUFF_PER, "pread", context->mode);
        return CM_ERROR;
    }

    dss_init_rw_param(&param, conn, handle, context, offset, DSS_TRUE);
    param.is_read = DSS_TRUE;
    do {
        bool32 read_end = CM_FALSE;
        status = dss_pread_file_prepare(conn, context, size, offset, &read_end);
        DSS_BREAK_IF_ERROR(status);
        if (read_end) {
            *read_size = 0;
            break;
        }
        status = dss_read_write_file_core(&param, buf, size, read_size);
    } while (0);

    dss_unlatch(&context->latch);
    LOG_DEBUG_INF("dss pread file leave, result: %d", status);
    return status;
}

status_t dss_fallocate_impl(dss_conn_t *conn, int handle, int mode, long long int offset, long long int length)
{
    status_t status;
    dss_file_context_t *context = NULL;

    if (mode < 0) {
        LOG_DEBUG_ERR("File mode is invalid:%d.", mode);
        DSS_THROW_ERROR(ERR_DSS_INVALID_PARAM, "mode must be a positive integer");
        return CM_ERROR;
    }

    if (offset > (int64)DSS_MAX_FILE_SIZE) {
        LOG_DEBUG_ERR("Offset is invalid:%lld.", offset);
        DSS_THROW_ERROR(ERR_DSS_INVALID_PARAM, "offset must less than DSS_MAX_FILE_SIZE");
        return CM_ERROR;
    }

    if (length < 0) {
        LOG_DEBUG_ERR("File length is invalid:%lld.", length);
        DSS_THROW_ERROR(ERR_DSS_INVALID_PARAM, "length must be a positive integer");
        return CM_ERROR;
    }

    if (length > (int64)DSS_MAX_FILE_SIZE) {
        LOG_DEBUG_ERR("File length is invalid:%lld.", length);
        DSS_THROW_ERROR(ERR_DSS_INVALID_PARAM, "length must less than DSS_MAX_FILE_SIZE");
        return CM_ERROR;
    }

    CM_RETURN_IFERR(dss_latch_context_by_handle(conn, handle, &context, LATCH_MODE_SHARE));
    LOG_DEBUG_INF("dss fallocate file, name:%s, handle:%d, mode:%d, offset:%lld, length:%lld", context->node->name,
        handle, mode, offset, length);
    if (!(context->mode & DSS_FILE_MODE_WRITE)) {
        dss_unlatch(&context->latch);
        DSS_THROW_ERROR(ERR_DSS_FILE_RDWR_INSUFF_PER, "fallocate", context->mode);
        return CM_ERROR;
    }

    status = dss_apply_fallocate_file(conn, handle, mode, offset, length);
    dss_unlatch(&context->latch);

    LOG_DEBUG_INF("dss fallocate file leave, result: %d", status);
    return status;
}

static status_t dss_get_addr_core(dss_rw_param_t *param, char *pool_name, char *image_name, char *obj_addr,
    unsigned int *obj_id, unsigned long int *obj_offset)
{
    status_t status = CM_SUCCESS;
    dss_conn_t *conn = param->conn;
    int handle = param->handle;
    dss_env_t *dss_env = param->dss_env;
    dss_file_context_t *context = param->context;

    DSS_LOCK_VG_META_S_RETURN_ERROR(context->vg_item, conn->session);

    gft_node_t *node = context->node;
    dss_vg_info_item_t *vg_item = context->vg_item;
    dss_fs_pos_desc_t fs_pos = {0};

    files_rw_ctx_t rw_ctx;
    rw_ctx.conn = conn;
    rw_ctx.env = dss_env;
    rw_ctx.file_ctx = context;
    rw_ctx.handle = handle;
    rw_ctx.size = 0;
    rw_ctx.read = DSS_TRUE;
    rw_ctx.offset = param->offset;

    CM_RETURN_IFERR(dss_check_ready_fs_block(&rw_ctx, &fs_pos));
    if (!fs_pos.is_valid) {
        DSS_UNLOCK_VG_META_S(context->vg_item, conn->session);
        DSS_THROW_ERROR(ERR_DSS_INVALID_ID, "au", *(uint64 *)&fs_pos.data_auid);
        return CM_ERROR;
    }

    auid_t auid = fs_pos.data_auid;
    uint64 vol_offset = (uint64)dss_get_au_offset(vg_item, auid);
    vol_offset = vol_offset + (uint64)fs_pos.au_offset;

    if (auid.volume >= DSS_MAX_VOLUMES) {
        DSS_UNLOCK_VG_META_S(context->vg_item, conn->session);
        DSS_THROW_ERROR(ERR_DSS_INVALID_ID, "au", *(uint64 *)&auid);
        DSS_ASSERT_LOG(0, "Auid is invalid, volume:%u, fname:%s, fsize:%llu, written_size:%llu.", (uint32)auid.volume,
            node->name, node->size, node->written_size);
        return CM_ERROR;
    }

    /* now support ceph only */
    char *name = vg_item->dss_ctrl->volume.defs[auid.volume].name;
    rbd_config_param *config = ceph_parse_rbd_configs(name);
    if (config->rbd_handle == NULL) {
        DSS_UNLOCK_VG_META_S(context->vg_item, conn->session);
        return CM_ERROR;
    }
    strcpy_s(pool_name, strlen(config->pool_name) + 1, config->pool_name);
    strcpy_s(image_name, strlen(config->image_name) + 1, config->image_name);
    ceph_client_get_data_addr(config->rbd_handle, config->rados_handle, vol_offset, obj_offset, obj_addr, obj_id);

    DSS_UNLOCK_VG_META_S(context->vg_item, conn->session);
    return status;
}

status_t dss_get_addr_impl(dss_conn_t *conn, int32 handle, long long offset, char *pool_name, char *image_name,
    char *obj_addr, unsigned int *obj_id, unsigned long int *obj_offset)
{
    status_t status;
    dss_file_context_t *context = NULL;
    dss_rw_param_t param;

    CM_RETURN_IFERR(dss_latch_context_by_handle(conn, handle, &context, LATCH_MODE_SHARE));
    LOG_DEBUG_INF("dss get ceph address, handle:%d, offset:%lld", handle, offset);

    dss_init_rw_param(&param, conn, handle, context, offset, DSS_TRUE);
    param.is_read = DSS_TRUE;
    bool32 read_end = CM_FALSE;
    if (dss_pread_file_prepare(conn, context, offset, 0, &read_end) != CM_SUCCESS) {
        dss_unlatch(&context->latch);
        return CM_ERROR;
    }
    status = dss_get_addr_core(&param, pool_name, image_name, obj_addr, obj_id, obj_offset);

    dss_unlatch(&context->latch);
    LOG_DEBUG_INF("dss get ceph address leave");
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
    dss_init_set(&conn->pack, conn->proto_version);

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

status_t dss_truncate_impl(dss_conn_t *conn, int handle, long long int length)
{
    int32 errcode = -1;
    char *errmsg = NULL;

    if (length < 0) {
        DSS_THROW_ERROR(ERR_DSS_INVALID_PARAM, "length must be a positive integer");
        LOG_DEBUG_ERR("File length is invalid:%lld.", length);
        return CM_ERROR;
    }

    if (length > (int64)DSS_MAX_FILE_SIZE) { 
        DSS_THROW_ERROR(ERR_DSS_INVALID_PARAM, "length must less than DSS_MAX_FILE_SIZE");
        LOG_DEBUG_ERR("File length is invalid:%lld.", length);
        return CM_ERROR;
    }

    dss_file_context_t *context = NULL;
    DSS_RETURN_IF_ERROR(dss_latch_context_by_handle(conn, handle, &context, LATCH_MODE_EXCLUSIVE));

    LOG_DEBUG_INF("Truncating file via handle(%d), file name: %s, node size: %lld, length: %lld.", handle,
        context->node->name, context->node->size, length);

    uint64 fid = context->fid;
    ftid_t ftid = context->node->id;

    dss_init_set(&conn->pack, conn->proto_version);
    dss_packet_t *send_pack = &conn->pack;
    send_pack->head->cmd = DSS_CMD_TRUNCATE_FILE;
    send_pack->head->flags = 0;

    DSS_RETURN_IFERR2(dss_put_int64(send_pack, fid), dss_unlatch(&context->latch));
    DSS_RETURN_IFERR2(dss_put_int64(send_pack, *(uint64 *)&ftid), dss_unlatch(&context->latch));
    DSS_RETURN_IFERR2(dss_put_int64(send_pack, (uint64)length), dss_unlatch(&context->latch));
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
#ifdef ENABLE_DSSTEST
        if (dss_env->inittor_pid == getpid()) {
#endif
            return dss_init_err_proc(dss_env, CM_FALSE, CM_FALSE, NULL, CM_SUCCESS);
#ifdef ENABLE_DSSTEST
        } else {
            LOG_RUN_INF("Dss client need re-initalization dss env, last init pid:%llu.", (uint64)dss_env->inittor_pid);
            (void)dss_init_err_proc(dss_env, CM_TRUE, CM_TRUE, "need reinit by a new process", CM_SUCCESS);

            dss_env->initialized = CM_FALSE;
            dss_env->inittor_pid = 0;
        }
#endif
    }

    CM_RETURN_IFERR(dss_init_shm(dss_env, home));

    dss_share_vg_info_t *share_vg_info = (dss_share_vg_info_t *)ga_object_addr(GA_INSTANCE_POOL, 0);
    if (share_vg_info == NULL) {
        return dss_init_err_proc(dss_env, CM_TRUE, CM_TRUE, "Failed to attach shared vg info", CM_ERROR);
    }
    status_t status = dss_get_vg_info(share_vg_info, NULL);
    if (status != CM_SUCCESS) {
        return dss_init_err_proc(dss_env, CM_TRUE, CM_TRUE, "Failed to get shared vg info", status);
    }
    dss_env->session = (dss_session_t *)ga_object_addr(GA_SESSION_POOL, 0);
    if (dss_env->session == NULL) {
        return dss_init_err_proc(dss_env, CM_TRUE, CM_TRUE, "Failed to attach shared session info", CM_ERROR);
    }
    CM_RETURN_IFERR(dss_init_files(dss_env, max_open_files));

    for (int32_t i = 0; i < (int32_t)g_vgs_info->group_num; i++) {
        dss_vg_info_item_t *item = &g_vgs_info->volume_group[i];
        (void)cm_attach_shm(SHM_TYPE_HASH, item->buffer_cache->shm_id, 0, CM_SHM_ATTACH_RW);
    }

    status = cm_create_thread(dss_heartbeat_entry, SIZE_K(512), NULL, &dss_env->thread_heartbeat);
    if (status != CM_SUCCESS) {
        return dss_init_err_proc(dss_env, CM_TRUE, CM_TRUE, "DSS failed to create heartbeat thread", status);
    }

#ifdef ENABLE_DSSTEST
    dss_env->inittor_pid = getpid();
#endif

    dss_env->initialized = CM_TRUE;
    dss_unlatch(&dss_env->latch);

    return CM_SUCCESS;
}

void dss_destroy_vg_info(dss_env_t *dss_env)
{
    if (g_vgs_info == NULL) {
        return;
    }
    for (uint32 i = 0; i < g_vgs_info->group_num; i++) {
        for (uint32 j = 0; j < DSS_MAX_VOLUMES; j++) {
            if (g_vgs_info->volume_group[i].volume_handle[j].handle != DSS_INVALID_HANDLE) {
                dss_close_volume(&g_vgs_info->volume_group[i].volume_handle[j]);
            }
        }
    }
    ga_detach_area();
    dss_free_vg_info();
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
    dss_init_set(&conn->pack, conn->proto_version);

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
    dss_init_set(&conn->pack, conn->proto_version);

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

status_t dss_islink_impl(dss_conn_t *conn, const char *path, bool32 *result)
{
    dss_packet_t *send_pack;
    dss_packet_t *ack_pack;
    int32 errcode = -1;
    char *errmsg = NULL;

    // make up packet
    dss_init_set(&conn->pack, conn->proto_version);

    send_pack = &conn->pack;
    send_pack->head->cmd = DSS_CMD_EXIST;
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

    dss_init_get(ack_pack);
    gft_item_type_t type = GFT_PATH;
    if (dss_get_int32(ack_pack, (int32 *)result) != CM_SUCCESS) {
        DSS_THROW_ERROR(ERR_DSS_CLI_EXEC_FAIL, dss_get_cmd_desc(DSS_CMD_EXIST), "get result data error");
        LOG_DEBUG_ERR("get result data error.");
        return CM_ERROR;
    }
    if (dss_get_int32(ack_pack, (int32 *)&type) != CM_SUCCESS) {
        DSS_THROW_ERROR(ERR_DSS_CLI_EXEC_FAIL, dss_get_cmd_desc(DSS_CMD_EXIST), "get type data error");
        LOG_DEBUG_ERR("get type data error.");
        return CM_ERROR;
    }
    if (*result && (type == GFT_LINK || type == GFT_LINK_TO_FILE || type == GFT_LINK_TO_PATH)) {
        *result = CM_TRUE;
    } else {
        *result = CM_FALSE;
    }
    return CM_SUCCESS;
}

status_t dss_readlink_impl(dss_conn_t *conn, const char *dir_path, char *out_str, size_t str_len)
{
    dss_packet_t *send_pack;
    dss_packet_t *ack_pack;
    int32 errcode = -1;
    char *errmsg = NULL;

    // make up packet
    dss_init_set(&conn->pack, conn->proto_version);

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

static void dss_get_fd_check_fs_aux(dss_rw_param_t *param, files_rw_ctx_t *rw_ctx, dss_fs_pos_desc_t *fs_pos,
    int32 *real_count, bool32 *need_updt_fs_aux)
{
    dss_file_context_t *context = param->context;
    gft_node_t *node = context->node;
    int32 inited_size = 0;

    bool32 need_check_fs_aux = CM_FALSE;
    if (param->is_read && real_count != NULL) {
        need_check_fs_aux = CM_TRUE;
    }

#ifdef OPENGAUSS
    need_check_fs_aux = CM_TRUE;
#endif
    // try to avoid too much update for fs aux info
    if (DSS_IS_FILE_INNER_INITED(node->flags) && need_check_fs_aux) {
        if (!param->is_read) {
            if (!(*need_updt_fs_aux) && fs_pos->fs_aux != NULL &&
                (uint64)(rw_ctx->offset + rw_ctx->size) > node->min_inited_size) {
                dss_api_check_need_updt_fs_aux(context, rw_ctx, fs_pos, rw_ctx->size, need_updt_fs_aux);
            }
        } else if (real_count != NULL) {
            // all part read by node->min_written_size
            if ((uint64)(rw_ctx->offset + rw_ctx->size) <= node->min_inited_size) {
                *real_count = rw_ctx->size;
            } else if ((uint64)rw_ctx->offset < node->min_inited_size) {
                // the first part read by node->min_written_size
                *real_count = (int32)(node->min_inited_size - rw_ctx->offset);
                // the left part read by fs aux
                dss_get_inited_size_with_fs_aux(
                    context->vg_item, fs_pos->fs_aux, node->min_inited_size, rw_ctx->size - *real_count, &inited_size);
                *real_count += inited_size;
            } else {
                // all part ead by fs aux
                dss_get_inited_size_with_fs_aux(
                    context->vg_item, fs_pos->fs_aux, rw_ctx->offset, rw_ctx->size, &inited_size);
                *real_count = inited_size;
            }
        }
    }
}

static status_t get_fd(dss_rw_param_t *param, int32 size, int *fd, int64 *vol_offset, int32 *real_count)
{
    status_t status = CM_SUCCESS;
    dss_conn_t *conn = param->conn;
    int handle = param->handle;
    dss_env_t *dss_env = param->dss_env;
    dss_file_context_t *context = param->context;
    int32 total_size = size;

    DSS_LOCK_VG_META_S_RETURN_ERROR(context->vg_item, conn->session);
    CM_RETURN_IFERR(dss_check_refresh_file_by_size(conn, context, param, &total_size));
    // after refresh, still has no data, read return error, may truncate by others
    if (param->is_read && total_size == 0) {
        DSS_UNLOCK_VG_META_S(context->vg_item, conn->session);
        return CM_ERROR;
    }
    gft_node_t *node = context->node;
    dss_vg_info_item_t *vg_item = context->vg_item;

    dss_fs_pos_desc_t fs_pos = {0};
    uint64 au_size = dss_get_vg_au_size(vg_item->dss_ctrl);
    uint32 retry_time = 0;

    bool32 need_updt_fs_aux = CM_FALSE;
    files_rw_ctx_t rw_ctx;
    do {
        rw_ctx.conn = conn;
        rw_ctx.env = dss_env;
        rw_ctx.file_ctx = context;
        rw_ctx.handle = handle;
        rw_ctx.size = size;
        rw_ctx.read = param->is_read;
        rw_ctx.offset = param->offset;

        // after refresh, still has no data, read return error, may truncate by others
        dss_check_file_written_size(conn, context, rw_ctx.offset, param->is_read, &total_size);
        if (param->is_read && total_size == 0) {
            LOG_DEBUG_ERR(
                "Fail by size, entry blockid:%llu, nodeid:%llu.", DSS_ID_TO_U64(node->entry), DSS_ID_TO_U64(node->id));
            DSS_UNLOCK_VG_META_S(context->vg_item, conn->session);
            return CM_ERROR;
        }

        /* for aio, one IO needs to be in the same AU. */
        uint32 start_block_count, start_block_au_count, end_block_count, end_block_au_count;
        do {
            status = dss_get_fs_block_info_by_offset(
                param->offset, au_size, &start_block_count, &start_block_au_count, NULL);
            DSS_BREAK_IF_ERROR(status);
            status = dss_get_fs_block_info_by_offset(
                param->offset + size - 1, au_size, &end_block_count, &end_block_au_count, NULL);
        } while (0);

        DSS_RETURN_IFERR2(status, DSS_UNLOCK_VG_META_S(context->vg_item, conn->session));

        if (start_block_count != end_block_count || start_block_au_count != end_block_au_count) {
            LOG_DEBUG_ERR(
                "start_block_count:%u != end_block_count:%u || start_block_au_count:%u != end_block_au_count:%u.",
                start_block_count, end_block_count, start_block_au_count, end_block_au_count);
            DSS_UNLOCK_VG_META_S(context->vg_item, conn->session);
            return CM_ERROR;
        }

        status = dss_check_ready_fs_block(&rw_ctx, &fs_pos);
        if (status != CM_SUCCESS) {
            LOG_RUN_ERR("The offset:%lld to ready block fail.", rw_ctx.offset);
            return CM_ERROR;
        }

        if (param->is_read && !fs_pos.is_valid) {
            DSS_UNLOCK_VG_META_S(context->vg_item, conn->session);
            return CM_ERROR;
        }

        auid_t auid = fs_pos.data_auid;
        if (auid.volume >= DSS_MAX_VOLUMES) {
            DSS_UNLOCK_VG_META_S(context->vg_item, conn->session);
            DSS_THROW_ERROR(ERR_DSS_INVALID_ID, "au", *(uint64 *)&auid);
            DSS_ASSERT_LOG(0, "Auid is invalid, volume:%u, fname:%s, fsize:%llu, written_size:%llu.",
                (uint32)auid.volume, node->name, node->size, node->written_size);
            return CM_ERROR;
        }

        LOG_DEBUG_INF("Found auid:%llu for node:%llu, name:%s.", DSS_ID_TO_U64(auid), DSS_ID_TO_U64(context->node->id),
            context->node->name);

        bool32 is_refresh = CM_FALSE;
        status = dss_check_refresh_volume(conn, context, auid, &is_refresh);
        if (status != CM_SUCCESS) {
            LOG_RUN_ERR("Refresh volume:%llu fail.", (uint64)auid.volume);
            return CM_ERROR;
        }
        // so bad need start from begin again
        if (is_refresh) {
            // dss_check_refrsh_volume may unlock the vg, other task may truncate this file, need recheck from begin
            retry_time++;
            LOG_DEBUG_INF("Node:%s, name:%s, fsize:%llu, written_size:%llu, retry_time:%u.",
                dss_display_metaid(node->id), node->name, node->size, node->written_size, retry_time);
            continue;
        }
        dss_cli_vg_handles_t *cli_vg_handles = (dss_cli_vg_handles_t *)(conn->cli_vg_handles);
        dss_simple_volume_t *vol = &cli_vg_handles->vg_vols[vg_item->id].volume_handle[auid.volume];

        *vol_offset = dss_get_au_offset(vg_item, auid);
        *vol_offset = *vol_offset + (int64)fs_pos.au_offset;
        uint64 super_au_size = CM_CALC_ALIGN(DSS_VOLUME_HEAD_SIZE, au_size);
        // wrongly writing superau area
        DSS_ASSERT_LOG(*((uint64 *)vol_offset) >= super_au_size, "The volume offset:%llu is invalid!", *vol_offset);

        /* get the real block device descriptor */
        *fd = vol->handle;
        cm_panic(vol->handle > 0);
        dss_get_fd_check_fs_aux(param, &rw_ctx, &fs_pos, real_count, &need_updt_fs_aux);
        break;
    } while (CM_TRUE);
    DSS_UNLOCK_VG_META_S(context->vg_item, conn->session);

#ifdef OPENGAUSS
    int64 offset = param->offset + size;
    bool32 need_update = offset > context->node->written_size && !param->is_read;
    if (need_update) {
        LOG_DEBUG_INF("Start update_written_size for file:\"%s\", curr offset:%llu, curr written_size:%llu.",
            node->name, offset, node->written_size);
        status = dss_update_written_size(dss_env, conn, context, param->offset, (int64)size);
    }
#endif

    return status;
}

static status_t dss_get_fd_prepare(dss_conn_t *conn, dss_file_context_t *context, long long offset, bool32 is_read)
{
    DSS_LOCK_VG_META_S_RETURN_ERROR(context->vg_item, conn->session);
    status_t status = dss_check_refresh_file_by_offset(conn, context, offset, is_read);
    if (status != CM_SUCCESS) {
        return status;
    }
    DSS_UNLOCK_VG_META_S(context->vg_item, conn->session);
    return CM_SUCCESS;
}

status_t dss_get_fd_by_offset(dss_conn_t *conn, int handle, long long offset, int32 size, bool32 is_read, int *fd,
    int64 *vol_offset, int32 *real_count)
{
    *fd = DSS_INVALID_HANDLE;

    status_t status;
    dss_file_context_t *context = NULL;
    dss_rw_param_t param;

    CM_RETURN_IFERR(dss_latch_context_by_handle(conn, handle, &context, LATCH_MODE_SHARE));
    LOG_DEBUG_INF("Begin get file fd in aio, filename:%s, handle:%d, offset:%lld", context->node->name, handle, offset);

    dss_init_rw_param(&param, conn, handle, context, offset, DSS_TRUE);
    param.is_read = is_read;

    status = dss_get_fd_prepare(conn, context, offset, is_read);
    DSS_RETURN_IFERR2(status, dss_unlatch(&context->latch));

    status = get_fd(&param, size, fd, vol_offset, real_count);

    dss_unlatch(&context->latch);
    LOG_DEBUG_INF("get file descriptor in aio leave, result: %d", status);
    return status;
}

status_t get_au_size_impl(dss_conn_t *conn, int handle, long long *au_size)
{
    dss_file_context_t *context = NULL;

    LOG_DEBUG_INF("get_au_size_impl, handle:%d", handle);
    CM_RETURN_IFERR(dss_latch_context_by_handle(conn, handle, &context, LATCH_MODE_SHARE));

    *au_size = context->vg_item->dss_ctrl->core.au_size;
    return CM_SUCCESS;
}

status_t dss_compare_size_equal_impl(const char *vg_name, long long *au_size)
{
    dss_vg_info_item_t *vg_item = dss_find_vg_item(vg_name);
    if (vg_name == NULL || vg_item == NULL) {
        dss_free_vg_info();
        LOG_DEBUG_ERR("Failed to find vg info from config, vg name is null\n");
        return CM_ERROR;
    }
    *au_size = vg_item->dss_ctrl->core.au_size;

    open_global_rbd_handle();
    rbd_config_param *config = ceph_parse_rbd_configs(vg_item->entry_path);
    if (config == NULL || config->rbd_handle == NULL) {
        return CM_ERROR;
    }
    long long obj_size;
    ceph_client_get_object_size(config->rbd_handle, &obj_size);
    if (*au_size != obj_size) {
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

status_t dss_setcfg_impl(dss_conn_t *conn, const char *name, const char *value, const char *scope)
{
    dss_packet_t *send_pack;
    dss_packet_t *ack_pack;
    int32 errcode = -1;
    char *errmsg = NULL;

    // make up packet
    dss_init_set(&conn->pack, conn->proto_version);

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
    dss_init_set(&conn->pack, conn->proto_version);

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
    if (extra_info.len >= len) {
        DSS_THROW_ERROR(ERR_DSS_CLI_EXEC_FAIL, dss_get_cmd_desc(DSS_CMD_GETCFG), "get cfg length error");
        return CM_ERROR;
    }
    if (extra_info.len == 0) {
        LOG_DEBUG_INF("Client get cfg is NULL.");
        return CM_SUCCESS;
    }

    errno_t err = strncpy_s(out_str, str_len, extra_info.str, extra_info.len);
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
    dss_init_set(&conn->pack, conn->proto_version);

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

status_t dss_set_stat_info(dss_stat_info_t item, gft_node_t *node)
{
    item->type = (dss_item_type_t)node->type;
    item->size = node->size;
    item->written_size = node->written_size;
    item->create_time = node->create_time;
    item->update_time = node->update_time;
    int32 errcode = memcpy_s(item->name, DSS_MAX_NAME_LEN, node->name, DSS_MAX_NAME_LEN);
    if (SECUREC_UNLIKELY(errcode != EOK)) {
        DSS_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
        return DSS_ERROR;
    }
    return DSS_SUCCESS;
}

status_t dss_fstat_impl(dss_conn_t *conn, int handle, dss_stat_info_t item)
{
    dss_file_context_t *context = NULL;
    DSS_RETURN_IF_ERROR(dss_latch_context_by_handle(conn, handle, &context, LATCH_MODE_SHARE));
    status_t ret = dss_set_stat_info(item, context->node);
    dss_unlatch(&context->latch);
    return ret;
}

status_t dss_aio_check_need_updt_fs_aux(dss_rw_param_t *param, int32 size, bool32 *need_update)
{
    dss_conn_t *conn = param->conn;
    dss_file_context_t *context = param->context;
    long long offset = param->offset;

    *need_update = CM_FALSE;
    if (context->node->min_inited_size >= (uint64)(offset + size)) {
        return CM_SUCCESS;
    }

    uint64 au_size = dss_get_vg_au_size(context->vg_item->dss_ctrl);

    dss_fs_pos_desc_t fs_pos = {0};
    files_rw_ctx_t rw_ctx;
    rw_ctx.conn = conn;
    rw_ctx.env = param->dss_env;
    rw_ctx.file_ctx = context;
    rw_ctx.handle = param->handle;
    rw_ctx.read = CM_TRUE; // should NOT apply extend for aio post

    int64 top_size = (context->node->size > (param->offset + size)) ? (offset + size) : context->node->size;
    int64 left_size = size;
    int64 cur_size = 0;

    do {
        int64 align_size = (int64)CM_CALC_ALIGN((uint64)(offset + 1), au_size);
        if (offset + left_size > align_size) {
            cur_size = align_size - offset;
        } else {
            cur_size = left_size;
        }

        rw_ctx.offset = offset;
        rw_ctx.size = (int32)cur_size;

        status_t status = dss_check_ready_fs_block(&rw_ctx, &fs_pos);
        DSS_RETURN_IF_ERROR(status);
        if (!fs_pos.is_valid) {
            LOG_RUN_ERR("Fail to find fs block for file:%s, fid:%llu, fti:%llu, cur offset:%llu, size:%lld,"
                "written_size:%llu, file size:%llu.",
                context->node->name, context->node->fid, DSS_ID_TO_U64(context->node->id), offset, cur_size,
                context->node->written_size, (uint64)context->node->size);
            return CM_ERROR;
        }
    
        if (fs_pos.fs_aux != NULL) {
            // if found one, ignore others
            bool32 is_inited = dss_check_fs_aux_inited(context->vg_item, fs_pos.fs_aux, offset, cur_size);
            if (!is_inited) {
                *need_update = CM_TRUE;
                break;
            }
        }

        offset += cur_size;
        left_size -= cur_size;
    } while (offset < top_size);

    return CM_SUCCESS;
}

static status_t dss_aio_post_pwrite_file_prepare(
    dss_rw_param_t *param, int32 size, bool32 *need_update, int64 *new_offset)
{
    dss_conn_t *conn = param->conn;
    dss_file_context_t *context = param->context;
    long long offset = param->offset;

    *need_update = CM_FALSE;
    *new_offset = 0;

    DSS_LOCK_VG_META_S_RETURN_ERROR(context->vg_item, conn->session);
    status_t status = dss_check_refresh_file_by_offset(conn, context, offset, CM_FALSE);
    if (status != CM_SUCCESS) {
        return CM_ERROR;
    }

    *new_offset = offset + size;
    *need_update = ((uint64)*new_offset > context->node->written_size);
    if (*need_update) {
        LOG_DEBUG_INF("Start update written size fo file:%s, cur offset:%llu, cur wrriten size:%llu, size:%d.",
            context->node->name, offset, context->node->written_size, size);
    } else {
        if (DSS_IS_FILE_INNER_INITED(context->node->flags)) {
            status = dss_aio_check_need_updt_fs_aux(param, size, need_update);
            if (status != CM_SUCCESS) {
                DSS_UNLOCK_VG_META_S(context->vg_item, conn->session);
                return CM_ERROR;
            }
        }
    }

    DSS_UNLOCK_VG_META_S(context->vg_item, conn->session);
    return CM_SUCCESS;
}

status_t dss_aio_post_pwrite_file_impl(dss_conn_t *conn, int handle, long long offset, int size)
{
    status_t status;
    dss_file_context_t *context = NULL;
    dss_rw_param_t param;

    DSS_RETURN_IF_ERROR(dss_latch_context_by_handle(conn, handle, &context, LATCH_MODE_SHARE));
    LOG_DEBUG_INF("Begin get file fd in aio, filename:%s, handle:%d, offset:%lld, size:%d", context->node->name, handle,
        offset, size);

    dss_init_rw_param(&param, conn, handle, context, offset, DSS_TRUE);

    bool32 need_update;
    int64 new_offset;
    status = dss_aio_post_pwrite_file_prepare(&param, size, &need_update, &new_offset);
    DSS_RETURN_IFERR2(status, dss_unlatch(&context->latch));

    if (need_update) {
        LOG_DEBUG_INF("Start update_written_size for file:\"%s\", cur offset:%llu, cur written_size:%llu, size:%d.",
            context->node->name, offset, context->node->written_size, size);
        dss_env_t *dss_env = dss_get_env();
        status = dss_update_written_size(dss_env, conn, context, offset, (int64)size);
    }
    dss_unlatch(&context->latch);
    LOG_DEBUG_INF("end post pwrite in aio leave, result:%d", status);

    return CM_SUCCESS;
}

static status_t dss_get_phy_size_prepare(dss_conn_t *conn, dss_file_context_t *context, long long *size)
{
    *size = 0;
    DSS_LOCK_VG_META_S_RETURN_ERROR(context->vg_item, conn->session);
    status_t status = dss_check_apply_refresh_file(conn, context, 0);
    if (status != CM_SUCCESS) {
        return status;
    }
    *size = cm_atomic_get(&context->node->size);
    DSS_UNLOCK_VG_META_S(context->vg_item, conn->session);
    return CM_SUCCESS;
}

status_t dss_get_phy_size_impl(dss_conn_t *conn, int handle, long long *size)
{
    dss_file_context_t *context = NULL;
    DSS_RETURN_IF_ERROR(dss_latch_context_by_handle(conn, handle, &context, LATCH_MODE_SHARE));

    status_t status = dss_get_phy_size_prepare(conn, context, size);
    if (status != DSS_SUCCESS) {
        LOG_DEBUG_ERR("Failed to apply refresh file,fid:%llu.", context->fid);
        dss_unlatch(&context->latch);
        return DSS_ERROR;
    }
    *size = context->node->size;
    dss_unlatch(&context->latch);
    return status;
}
static status_t dss_encode_load_ctrl(dss_conn_t *conn, dss_packet_t *pack, void *send_info)
{
    dss_load_ctrl_info_t *info = (dss_load_ctrl_info_t *)send_info;
    CM_RETURN_IFERR(dss_put_str(pack, info->vg_name));
    CM_RETURN_IFERR(dss_put_int32(pack, info->index));
    return CM_SUCCESS;
}

static status_t dss_encode_handshake(dss_conn_t *conn, dss_packet_t *pack, void *send_info)
{
    CM_RETURN_IFERR(dss_put_data(pack, send_info, sizeof(dss_cli_info)));
    return CM_SUCCESS;
}

static status_t dss_decode_handshake(dss_packet_t *ack_pack, void *ack)
{
    text_t ack_info = CM_NULL_TEXT;
    CM_RETURN_IFERR(dss_get_text(ack_pack, &ack_info));
    if (ack_info.len == 0 || ack_info.len >= DSS_MAX_PATH_BUFFER_SIZE) {
        DSS_THROW_ERROR(ERR_DSS_CLI_EXEC_FAIL, dss_get_cmd_desc(DSS_CMD_HANDSHAKE), "get home info length error");
        return CM_ERROR;
    }
    dss_get_server_info_t *output_info = (dss_get_server_info_t *)ack;
    output_info->home = ack_info.str;
    CM_RETURN_IFERR(dss_get_int32(ack_pack, (int32 *)&output_info->sid));
    return CM_SUCCESS;
}

static status_t dss_encode_add_or_remove_volume(dss_conn_t *conn, dss_packet_t *pack, void *send_info)
{
    dss_add_or_remove_info_t *info = (dss_add_or_remove_info_t *)send_info;
    CM_RETURN_IFERR(dss_put_str(pack, info->vg_name));
    CM_RETURN_IFERR(dss_put_str(pack, info->volume_name));
    return CM_SUCCESS;
}

static status_t dss_encode_extend_file(dss_conn_t *conn, dss_packet_t *pack, void *send_info)
{
    dss_extend_info_t *info = (dss_extend_info_t *)send_info;
    // 1. fid
    CM_RETURN_IFERR(dss_put_int64(pack, info->fid));
    // 2. ftid
    CM_RETURN_IFERR(dss_put_int64(pack, info->ftid));
    // 3. offset
    CM_RETURN_IFERR(dss_put_int64(pack, (uint64)info->offset));
    // 4. size
    CM_RETURN_IFERR(dss_put_int64(pack, (uint64)info->size));
    // 5. vg name
    CM_RETURN_IFERR(dss_put_str(pack, info->vg_name));
    // 6. vgid
    CM_RETURN_IFERR(dss_put_int32(pack, info->vg_id));
    return CM_SUCCESS;
}

static status_t dss_encode_make_dir(dss_conn_t *conn, dss_packet_t *pack, void *send_info)
{
    dss_make_dir_info_t *info = (dss_make_dir_info_t *)send_info;
    // 1. parent
    CM_RETURN_IFERR(dss_put_str(pack, info->parent));
    // 2. dir_name
    CM_RETURN_IFERR(dss_put_str(pack, info->name));
    return CM_SUCCESS;
}

static status_t dss_encode_remove_dir(dss_conn_t *conn, dss_packet_t *pack, void *send_info)
{
    dss_remove_dir_info_t *info = (dss_remove_dir_info_t *)send_info;
    // 1. dir_name
    CM_RETURN_IFERR(dss_put_str(pack, info->name));
    // 2. recursive -r
    CM_RETURN_IFERR(dss_put_int32(pack, info->recursive));
    return CM_SUCCESS;
}

static status_t dss_encode_open_dir(dss_conn_t *conn, dss_packet_t *pack, void *send_info)
{
    dss_open_dir_info_t *info = (dss_open_dir_info_t *)send_info;
    /* 1. dir name */
    CM_RETURN_IFERR(dss_put_str(pack, info->dir_path));
    /* 2. flag */
    CM_RETURN_IFERR(dss_put_int32(pack, info->refresh_recursive));
    return CM_SUCCESS;
}

static status_t dss_decode_open_dir(dss_packet_t *ack_pack, void *ack)
{
    CM_RETURN_IFERR(dss_get_data(ack_pack, sizeof(dss_find_node_t), (void **)ack));
    return CM_SUCCESS;
}

static status_t dss_encode_open_file(dss_conn_t *conn, dss_packet_t *pack, void *send_info)
{
    dss_open_file_info_t *info = (dss_open_file_info_t *)send_info;
    /* 1. file name */
    CM_RETURN_IFERR(dss_put_str(pack, info->file_path));
    /* 2. flag */
    CM_RETURN_IFERR(dss_put_int32(pack, (uint32)info->flag));
    return CM_SUCCESS;
}

static status_t dss_decode_open_file(dss_packet_t *ack_pack, void *ack)
{
    CM_RETURN_IFERR(dss_get_data(ack_pack, sizeof(dss_find_node_t), (void **)ack));
    return CM_SUCCESS;
}

static status_t dss_encode_kickh(dss_conn_t *conn, dss_packet_t *pack, void *send_info)
{
    CM_RETURN_IFERR(dss_put_int64(pack, *(uint64 *)send_info));
    return CM_SUCCESS;
}

static status_t dss_encode_fallocate_file(dss_conn_t *conn, dss_packet_t *pack, void *send_info)
{
    dss_fallocate_info_t *info = (dss_fallocate_info_t *)send_info;
    CM_RETURN_IFERR(dss_put_int64(pack, info->fid));
    CM_RETURN_IFERR(dss_put_int64(pack, info->ftid));
    CM_RETURN_IFERR(dss_put_int64(pack, (uint64)info->offset));
    CM_RETURN_IFERR(dss_put_int64(pack, (uint64)info->size));
    CM_RETURN_IFERR(dss_put_int32(pack, info->vg_id));
    CM_RETURN_IFERR(dss_put_int32(pack, (uint32)info->mode));
    return CM_SUCCESS;
}

typedef status_t (*dss_encode_packet_proc_t)(dss_conn_t *conn, dss_packet_t *pack, void *send_info);
typedef status_t (*dss_decode_packet_proc_t)(dss_packet_t *ack_pack, void *ack);
typedef struct st_dss_packet_proc {
    dss_encode_packet_proc_t encode_proc;
    dss_decode_packet_proc_t decode_proc;
    char *cmd_info;
} dss_packet_proc_t;

dss_packet_proc_t g_dss_packet_proc[DSS_CMD_END] = {
    [DSS_CMD_MKDIR] = {dss_encode_make_dir, NULL, "make dir"},
    [DSS_CMD_RMDIR] = {dss_encode_remove_dir, NULL, "remove dir"},
    [DSS_CMD_OPEN_DIR] = {dss_encode_open_dir, dss_decode_open_dir, "open dir"},
    [DSS_CMD_OPEN_FILE] = {dss_encode_open_file, dss_decode_open_file, "open file"},
    [DSS_CMD_EXTEND_FILE] = {dss_encode_extend_file, NULL, "extend file"},
    [DSS_CMD_ADD_VOLUME] = {dss_encode_add_or_remove_volume, NULL, "add volume"},
    [DSS_CMD_REMOVE_VOLUME] = {dss_encode_add_or_remove_volume, NULL, "remove volume"},
    [DSS_CMD_KICKH] = {dss_encode_kickh, NULL, "kickh"},
    [DSS_CMD_LOAD_CTRL] = {dss_encode_load_ctrl, NULL, "load ctrl"},
    [DSS_CMD_HANDSHAKE] = {dss_encode_handshake, dss_decode_handshake, "handshake with server"},
    [DSS_CMD_FALLOCATE_FILE] = {dss_encode_fallocate_file, NULL, "fallocate file"},
};

status_t dss_decode_packet(dss_packet_proc_t *make_proc, dss_packet_t *ack_pack, void *ack)
{
    if (ack == NULL || make_proc->decode_proc == NULL) {
        return CM_SUCCESS;
    }
    dss_init_get(ack_pack);
    status_t ret = make_proc->decode_proc(ack_pack, ack);
    DSS_RETURN_IFERR2(ret, LOG_DEBUG_ERR("Decode %s msg failed", make_proc->cmd_info));
    return ret;
}

status_t dss_msg_interact(dss_conn_t *conn, uint8 cmd, void *send_info, void *ack)
{
    dss_packet_t *send_pack = &conn->pack;
    dss_packet_t *ack_pack = &conn->pack;
    dss_packet_proc_t *make_proc;
    do {
        dss_init_packet(&conn->pack, conn->pipe.options);
        dss_init_set(&conn->pack, conn->proto_version);
        send_pack->head->cmd = cmd;
        send_pack->head->flags = 0;
        make_proc = &g_dss_packet_proc[cmd];
        DSS_RETURN_IF_ERROR(make_proc->encode_proc(conn, send_pack, send_info));
        ack_pack = &conn->pack;
        DSS_RETURN_IF_ERROR(dss_call_ex(&conn->pipe, send_pack, ack_pack));

        // check return state
        if (ack_pack->head->result != CM_SUCCESS) {
            int32 errcode = dss_get_pack_err(conn, ack_pack);
            if (errcode == ERR_DSS_VERSION_NOT_MATCH) {
                continue;
            }
            return errcode;
        }
        break;
    } while (1);
    conn->server_version = dss_get_version(ack_pack);
    conn->proto_version = MIN(DSS_PROTO_VERSION, conn->server_version);
    return dss_decode_packet(make_proc, ack_pack, ack);
}

#ifdef __cplusplus
}
#endif
