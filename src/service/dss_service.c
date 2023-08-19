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
 * dss_service.c
 *
 *
 * IDENTIFICATION
 *    src/service/dss_service.c
 *
 * -------------------------------------------------------------------------
 */

#include "cm_system.h"
#include "dss_instance.h"
#include "dss_io_fence.h"
#include "dss_malloc.h"
#include "dss_open_file.h"
#include "dss_srv_proc.h"
#include "dss_syncpoint.h"
#include "dss_mes.h"
#include "dss_api.h"
#include "dss_service.h"

#ifdef __cplusplus
extern "C" {
#endif

static inline bool32 dss_need_exec_remote(bool32 exec_on_active, bool32 local_req)
{
    dss_config_t *cfg = dss_get_inst_cfg();
    uint32 master_id = dss_get_master_id();
    uint32 curr_id = (uint32)(cfg->params.inst_id);
    return ((curr_id != master_id) && (exec_on_active) && (local_req == CM_TRUE));
}

#define DSS_PROCESS_GET_MASTER_ID 50
void dss_get_exec_nodeid(dss_session_t *session, uint32 *currid, uint32 *remoteid)
{
    dss_config_t *cfg = dss_get_inst_cfg();
    *currid = (uint32)(cfg->params.inst_id);
    *remoteid = dss_get_master_id();
    while (*remoteid == DSS_INVALID_ID32) {
        cm_sleep(DSS_PROCESS_GET_MASTER_ID);
        *remoteid = dss_get_master_id();
    }
    LOG_DEBUG_INF("Start processing remote requests(%d), remote node(%u),current node(%u).",
        (session->recv_pack.head == NULL) ? -1 : session->recv_pack.head->cmd, *remoteid, *currid);
    return;
}

#define DSS_PROCESS_REMOTE_INTERVAL 50
static status_t dss_process_remote(dss_session_t *session)
{
    uint32 remoteid = DSS_INVALID_ID32;
    uint32 currid = DSS_INVALID_ID32;
    status_t ret = CM_ERROR;
    dss_get_exec_nodeid(session, &currid, &remoteid);
   
    LOG_DEBUG_INF("Start processing remote requests(%d), remote node(%u),current node(%u).",
        session->recv_pack.head->cmd, remoteid, currid);
    status_t remote_result = CM_ERROR;
    while (CM_TRUE) {
        ret = dss_exec_sync(session, remoteid, currid, &remote_result);
        if (ret != CM_SUCCESS) {
            LOG_DEBUG_ERR(
                "End of processing the remote request(%d) failed, remote node(%u),current node(%u), result code(%d).",
                session->recv_pack.head->cmd, remoteid, currid, ret);
            if (session->recv_pack.head->cmd == DSS_CMD_SWITCH_LOCK) {
                return ret;
            }
            cm_sleep(DSS_PROCESS_REMOTE_INTERVAL);
            dss_get_exec_nodeid(session, &currid, &remoteid);
            continue;
        }
        break;
    }
    LOG_DEBUG_INF("The remote request(%d) is processed successfully, remote node(%u),current node(%u).",
        session->recv_pack.head->cmd, remoteid, currid);
    return remote_result;
}

static status_t dss_diag_proto_type(dss_session_t *session)
{
    link_ready_ack_t ack;
    uint32 proto_code = 0;
    int32 size;
    errno_t rc_memzero;
    status_t ret = cs_read_bytes(&session->pipe, (char *)&proto_code, sizeof(proto_code), &size);
    DSS_RETURN_IFERR2(ret, LOG_RUN_ERR("Instance recieve protocol failed, errno:%d.", errno));

    if (size != (int32)sizeof(proto_code) || proto_code != DSS_PROTO_CODE) {
        DSS_THROW_ERROR(ERR_INVALID_PROTOCOL);
        LOG_RUN_ERR("Instance recieve invalid protocol:%u.", proto_code);
        return CM_ERROR;
    }

    session->proto_type = PROTO_TYPE_GS;
    rc_memzero = memset_s(&ack, sizeof(link_ready_ack_t), 0, sizeof(link_ready_ack_t));
    DSS_SECUREC_RETURN_IF_ERROR(rc_memzero, CM_ERROR);
    ack.endian = (IS_BIG_ENDIAN ? (uint8)1 : (uint8)0);
    ack.version = CS_LOCAL_VERSION;
    return cs_send_bytes(&session->pipe, (char *)&ack, sizeof(link_ready_ack_t));
}

static void dss_clean_open_files(dss_session_t *session)
{
    if (cm_sys_process_alived(session->cli_info.cli_pid, session->cli_info.start_time)) {
        LOG_DEBUG_INF("Process:%s is alive, pid:%llu, start_time:%lld.", session->cli_info.process_name,
            session->cli_info.cli_pid, session->cli_info.start_time);
        return;
    }

    dss_vg_info_item_t *vg_item;
    for (uint32 i = 0; i < VGS_INFO->group_num; i++) {
        vg_item = &VGS_INFO->volume_group[i];
        dss_clean_open_files_in_vg(session, vg_item, session->cli_info.cli_pid);
    }
    LOG_RUN_INF("Clean open files for pid:%llu.", session->cli_info.cli_pid);
}

void dss_release_session_res(dss_session_t *session)
{
    dss_clean_session_latch(dss_get_session_ctrl(), session);
    dss_clean_open_files(session);
    dss_destroy_session(session);
}

status_t dss_process_single_cmd(dss_session_t *session)
{
    status_t status;
    if (session->proto_type == PROTO_TYPE_UNKNOWN) {
        LOG_DEBUG_INF("session %u begin check protocal type.", session->id);
        /* fetch protocol type */
        status = dss_diag_proto_type(session);
        if (status != CM_SUCCESS) {
            LOG_RUN_ERR("Failed to get protocol type!");
            dss_clean_reactor_session(session);
            return CM_ERROR;
        }
    } else {
        status = dss_process_command(session);
    }
    if (session->is_closed) {
        LOG_RUN_INF("Session:%u end to do service.", session->id);
        dss_clean_reactor_session(session);
    } else {
        dss_session_detach_workthread(session);
    }
    return status;
}

void dss_session_entry(thread_t *thread)
{
    dss_session_t *session = (dss_session_t *)thread->argument;
    LOG_RUN_INF("Session:%u begin to do service.", session->id);

    dss_init_packet(&session->recv_pack, CM_FALSE);
    dss_init_packet(&session->send_pack, CM_FALSE);

    cm_set_thread_name("DSS_SERVER");
    session->pipe.socket_timeout = (int32)CM_SOCKET_TIMEOUT;

    /* fetch protocol type */
    if (dss_diag_proto_type(session) != CM_SUCCESS) {
        dss_destroy_session(session);
        cm_release_thread(thread);
        LOG_RUN_ERR("Failed to get protocol type!");
        return;
    }
    session->status = DSS_SESSION_STATUS_RUNNING;
    session->curr_lsn = cm_get_curr_lsn();
    (void)cm_atomic_inc(&g_dss_instance.active_sessions);
    while (!thread->closed) {
        if (session->status == DSS_SESSION_STATUS_PAUSED) {
            cm_sleep(DSS_SESSION_PAUSED_WAIT);
            continue;
        }
        /* process request command */
        if ((dss_process_command(session) != CM_SUCCESS) && (session->is_closed == CM_TRUE)) {
            break;
        }
        if (session->status == DSS_SESSION_STATUS_PAUSING) {
            session->status = DSS_SESSION_STATUS_PAUSED;
            LOG_DEBUG_INF("Set session:%u paused.", session->id);
        }
    }
    session->status = DSS_SESSION_STATUS_IDLE;
    LOG_RUN_INF("Session:%u end to do service.", session->id);

    session->is_closed = CM_TRUE;
    dss_release_session_res(session);
    cm_release_thread(thread);
    (void)cm_atomic_dec(&g_dss_instance.active_sessions);
}

static void dss_return_error(dss_session_t *session)
{
    int32 code;
    const char *message = NULL;
    dss_packet_t *send_pack = NULL;

    CM_ASSERT(session != NULL);
    send_pack = &session->send_pack;
    dss_init_set(send_pack);
    send_pack->head->cmd = session->recv_pack.head->cmd;
    send_pack->head->result = (uint8)CM_ERROR;
    send_pack->head->flags = 0;
    cm_get_error(&code, &message);
    // volume open/seek/read write fail for I/O, just abort
    if (code == ERR_DSS_VOLUME_SYSTEM_IO) {
        LOG_RUN_ERR("[DSS] ABORT INFO: volume operate failed for I/O ERROR, errcode:%d.", code);
        cm_fync_logfile();
        _exit(1);
    }
    (void)dss_put_int32(send_pack, (uint32)code);
    (void)dss_put_str_with_cutoff(send_pack, message);
    status_t status = dss_write(&session->pipe, send_pack);
    if (status != CM_SUCCESS) {
        LOG_DEBUG_ERR("Failed to reply,size:%u, cmd:%u.", send_pack->head->size, send_pack->head->cmd);
    }
    cm_reset_error();
}

static void dss_return_success(dss_session_t *session)
{
    CM_ASSERT(session != NULL);
    status_t status;
    dss_packet_t *send_pack = NULL;
    send_pack = &session->send_pack;
    send_pack->head->cmd = session->recv_pack.head->cmd;
    send_pack->head->result = (uint8)CM_SUCCESS;
    send_pack->head->flags = 0;

    status = dss_write(&session->pipe, send_pack);
    if (status != CM_SUCCESS) {
        LOG_DEBUG_ERR("Failed to reply message,size:%u, cmd:%u.", send_pack->head->size, send_pack->head->cmd);
    }
}

static status_t dss_set_audit_resource(char *resource, uint32 audit_type, const char *format, ...)
{
    if ((cm_log_param_instance()->audit_level & audit_type) == 0) {
        return CM_SUCCESS;
    }
    va_list args;
    va_start(args, format);
    int32 ret =
        vsnprintf_s(resource, (size_t)DSS_FILE_PATH_MAX_LENGTH, (size_t)(DSS_FILE_PATH_MAX_LENGTH - 1), format, args);
    DSS_SECUREC_SS_RETURN_IF_ERROR(ret, CM_ERROR);
    va_end(args);
    return CM_SUCCESS;
}

static status_t dss_process_mkdir(dss_session_t *session)
{
    char *parent = NULL;
    char *dir = NULL;

    dss_init_get(&session->recv_pack);
    DSS_RETURN_IF_ERROR(dss_get_str(&session->recv_pack, &parent));
    DSS_RETURN_IF_ERROR(dss_get_str(&session->recv_pack, &dir));
    DSS_RETURN_IF_ERROR(dss_set_audit_resource(session->audit_info.resource, DSS_AUDIT_MODIFY, "%s/%s", parent, dir));
    return dss_make_dir(session, (const char *)parent, (const char *)dir);
}

static status_t dss_process_rmdir(dss_session_t *session)
{
    char *dir = NULL;
    int32 recursive = 0;
    dss_init_get(&session->recv_pack);
    DSS_RETURN_IF_ERROR(dss_get_str(&session->recv_pack, &dir));
    DSS_RETURN_IF_ERROR(dss_get_int32(&session->recv_pack, &recursive));
    DSS_RETURN_IF_ERROR(dss_set_audit_resource(session->audit_info.resource, DSS_AUDIT_MODIFY, "%s", dir));
    return dss_remove_dir(session, (const char *)dir, (bool32)recursive);
}

static status_t dss_process_create_file(dss_session_t *session)
{
    char *file_ptr = NULL;
    text_t text;
    text_t sub = CM_NULL_TEXT;
    int32 flag;

    dss_init_get(&session->recv_pack);
    DSS_RETURN_IF_ERROR(dss_get_str(&session->recv_pack, &file_ptr));
    DSS_RETURN_IF_ERROR(dss_get_int32(&session->recv_pack, &flag));
    DSS_RETURN_IF_ERROR(dss_set_audit_resource(session->audit_info.resource, DSS_AUDIT_MODIFY, "%s", file_ptr));

    cm_str2text(file_ptr, &text);
    bool32 result = cm_fetch_rtext(&text, '/', '\0', &sub);
    DSS_RETURN_IF_FALSE2(
        result, DSS_THROW_ERROR(ERR_DSS_FILE_PATH_ILL, sub.str, ", which is not a complete absolute path name."));
    if (text.len == 0) {
        DSS_THROW_ERROR(ERR_DSS_FILE_CREATE, "file name is null.");
        return CM_ERROR;
    }
    result = (bool32)(text.len < DSS_MAX_NAME_LEN);
    DSS_RETURN_IF_FALSE2(result, DSS_THROW_ERROR(ERR_DSS_FILE_PATH_ILL, text.str, "name length should less than 64."));

    char parent_str[DSS_FILE_PATH_MAX_LENGTH];
    char name_str[DSS_MAX_NAME_LEN];
    DSS_RETURN_IF_ERROR(cm_text2str(&sub, parent_str, sizeof(parent_str)));
    DSS_RETURN_IF_ERROR(cm_text2str(&text, name_str, sizeof(name_str)));

    return dss_create_file(session, (const char *)parent_str, (const char *)name_str, flag);
}

static status_t dss_process_delete_file(dss_session_t *session)
{
    char *name = NULL;
    dss_init_get(&session->recv_pack);
    status_t status = dss_get_str(&session->recv_pack, &name);
    DSS_RETURN_IFERR2(status, LOG_DEBUG_ERR("delete file get file name failed."));
    DSS_RETURN_IF_ERROR(dss_set_audit_resource(session->audit_info.resource, DSS_AUDIT_MODIFY, "%s", name));
    return dss_remove_file(session, (const char *)name);
}

static status_t dss_process_exist(dss_session_t *session)
{
    bool32 result = CM_FALSE;
    gft_item_type_t type;
    char *name = NULL;
    dss_init_get(&session->recv_pack);
    DSS_RETURN_IF_ERROR(dss_get_str(&session->recv_pack, &name));
    DSS_RETURN_IF_ERROR(dss_set_audit_resource(session->audit_info.resource, DSS_AUDIT_QUERY, "%s", name));
    DSS_RETURN_IF_ERROR(dss_exist_item(session, (const char *)name, &result, &type));

    DSS_RETURN_IF_ERROR(dss_put_int32(&session->send_pack, (uint32)result));
    DSS_RETURN_IF_ERROR(dss_put_int32(&session->send_pack, (uint32)type));
    return CM_SUCCESS;
}

static status_t dss_process_open_file(dss_session_t *session)
{
    char *name = NULL;
    int32 flag;
    dss_init_get(&session->recv_pack);
    DSS_RETURN_IF_ERROR(dss_get_str(&session->recv_pack, &name));
    DSS_RETURN_IF_ERROR(dss_get_int32(&session->recv_pack, &flag));
    DSS_RETURN_IF_ERROR(dss_set_audit_resource(session->audit_info.resource, DSS_AUDIT_MODIFY, "%s", name));

    return dss_open_file(session, (const char *)name, flag);
}

static status_t dss_process_close_file(dss_session_t *session)
{
    uint64 fid;
    char *vg_name = NULL;
    uint32 vgid;
    ftid_t ftid;
    dss_init_get(&session->recv_pack);
    DSS_RETURN_IF_ERROR(dss_get_int64(&session->recv_pack, (int64 *)&fid));
    DSS_RETURN_IF_ERROR(dss_get_str(&session->recv_pack, &vg_name));
    DSS_RETURN_IF_ERROR(dss_get_int32(&session->recv_pack, (int32 *)&vgid));
    DSS_RETURN_IF_ERROR(dss_get_int64(&session->recv_pack, (int64 *)&ftid));
    DSS_RETURN_IF_ERROR(dss_set_audit_resource(session->audit_info.resource, DSS_AUDIT_MODIFY,
        "vg_name:%s, fid:%llu, ftid:%llu", vg_name, fid, *(uint64 *)&ftid));

    dss_vg_info_item_t *vg_item = dss_find_vg_item(vg_name);
    bool32 result = (bool32)(vg_item != NULL);
    DSS_RETURN_IF_FALSE2(result, DSS_THROW_ERROR(ERR_DSS_VG_NOT_EXIST, vg_name));

    DSS_RETURN_IF_ERROR(dss_close_file(session, vg_item, *(uint64 *)&ftid));
    DSS_LOG_DEBUG_OP(
        "Succeed to close file, ftid:%llu, fid:%llu, vg: %s, session pid:%llu, v:%u, au:%llu, block:%u, item:%u.",
        *(int64 *)&ftid, fid, vg_item->vg_name, session->cli_info.cli_pid, ftid.volume, (uint64)ftid.au, ftid.block,
        ftid.item);
    bool32 should_rm_file = DSS_FALSE;
    gft_node_t *node;
    (void)dss_check_rm_file(session, vg_item, ftid, &should_rm_file, &node);
    if (should_rm_file) {
        if (!dss_is_readwrite()) {
            LOG_DEBUG_INF(
                "Ignores to remove delay file when close file, because the instance is not in readwrite, fid: %llu",
                fid);
            return CM_SUCCESS;
        }
        DSS_ASSERT_LOG(dss_need_exec_local(), "only masterid %u can be readwrite.", dss_get_master_id());
        status_t status = dss_remove_dir_file_by_node(session, vg_item, node);
        DSS_RETURN_IFERR2(status, LOG_DEBUG_INF("Failed to remove delay file when close file, fid: %llu", fid));
        DSS_LOG_DEBUG_OP("Succeed to remove file when close file, ftid%llu, fid:%llu, vg: %s, session pid:%llu, v:%u, "
                         "au:%llu, block:%u, item:%u.",
            *(int64 *)&ftid, fid, vg_item->vg_name, session->cli_info.cli_pid, ftid.volume, (uint64)ftid.au, ftid.block,
            ftid.item);
    }

    return CM_SUCCESS;
}

static status_t dss_process_open_dir(dss_session_t *session)
{
    char *name = NULL;
    int32 refresh_recursive;
    dss_init_get(&session->recv_pack);
    DSS_RETURN_IF_ERROR(dss_get_str(&session->recv_pack, &name));
    DSS_RETURN_IF_ERROR(dss_get_int32(&session->recv_pack, &refresh_recursive));
    DSS_RETURN_IF_ERROR(dss_set_audit_resource(session->audit_info.resource, DSS_AUDIT_MODIFY, "%s", name));

    return dss_open_dir(session, (const char *)name, (bool32)refresh_recursive);
}

static status_t dss_process_close_dir(dss_session_t *session)
{
    uint64 ftid;
    char *vg_name = NULL;
    uint32 vgid;

    dss_init_get(&session->recv_pack);
    DSS_RETURN_IF_ERROR(dss_get_int64(&session->recv_pack, (int64 *)&ftid));
    DSS_RETURN_IF_ERROR(dss_get_str(&session->recv_pack, &vg_name));
    DSS_RETURN_IF_ERROR(dss_get_int32(&session->recv_pack, (int32 *)&vgid));
    DSS_RETURN_IF_ERROR(dss_set_audit_resource(
        session->audit_info.resource, DSS_AUDIT_MODIFY, "vg_name:%s, ftid:%llu", vg_name, *(uint64 *)&ftid));
    dss_close_dir(session, vg_name, ftid);
    return CM_SUCCESS;
}

static status_t dss_process_extending_file(dss_session_t *session)
{
    dss_node_data_t node_data;

    dss_init_get(&session->recv_pack);
    DSS_RETURN_IF_ERROR(dss_get_int64(&session->recv_pack, (int64 *)&node_data.fid));
    DSS_RETURN_IF_ERROR(dss_get_int64(&session->recv_pack, (int64 *)&node_data.ftid));
    DSS_RETURN_IF_ERROR(dss_get_int64(&session->recv_pack, &node_data.offset));
    DSS_RETURN_IF_ERROR(dss_get_int32(&session->recv_pack, &node_data.size));
    DSS_RETURN_IF_ERROR(dss_get_str(&session->recv_pack, &node_data.vg_name));
    DSS_RETURN_IF_ERROR(dss_get_int32(&session->recv_pack, (int32 *)&node_data.vgid));
    DSS_RETURN_IF_ERROR(dss_set_audit_resource(session->audit_info.resource, DSS_AUDIT_MODIFY,
        "vg_name:%s, fid:%llu, ftid:%llu", node_data.vg_name, node_data.fid, *(uint64 *)&node_data.ftid));

    return dss_extend(session, &node_data);
}

static status_t dss_process_truncate_file(dss_session_t *session)
{
    uint64 fid;
    ftid_t ftid;
    int64 offset;
    uint64 length;
    uint32 vgid;
    char *vg_name = NULL;

    dss_init_get(&session->recv_pack);
    DSS_RETURN_IF_ERROR(dss_get_int64(&session->recv_pack, (int64 *)&fid));
    DSS_RETURN_IF_ERROR(dss_get_int64(&session->recv_pack, (int64 *)&ftid));
    DSS_RETURN_IF_ERROR(dss_get_int64(&session->recv_pack, &offset));
    DSS_RETURN_IF_ERROR(dss_get_int64(&session->recv_pack, (int64 *)&length));
    DSS_RETURN_IF_ERROR(dss_get_str(&session->recv_pack, &vg_name));
    DSS_RETURN_IF_ERROR(dss_get_int32(&session->recv_pack, (int32 *)&vgid));
    DSS_RETURN_IF_ERROR(dss_set_audit_resource(session->audit_info.resource, DSS_AUDIT_MODIFY,
        "vg_name:%s, fid:%llu, ftid:%llu", vg_name, fid, *(uint64 *)&ftid));
    LOG_DEBUG_INF("Truncate file ft id:%llu, offset:%lld, length:%llu", *(uint64 *)&ftid, offset, length);
    return dss_truncate(session, fid, ftid, offset, length, vg_name);
}

static status_t dss_process_add_volume(dss_session_t *session)
{
    char *vg_name = NULL;
    char *volume_name = NULL;
    dss_init_get(&session->recv_pack);
    DSS_RETURN_IF_ERROR(dss_get_str(&session->recv_pack, &vg_name));
    DSS_RETURN_IF_ERROR(dss_get_str(&session->recv_pack, &volume_name));
    DSS_RETURN_IF_ERROR(dss_set_audit_resource(
        session->audit_info.resource, DSS_AUDIT_MODIFY, "vg_name:%s, volume_name:%s", vg_name, volume_name));

    return dss_add_volume(session, vg_name, volume_name);
}

static status_t dss_process_remove_volume(dss_session_t *session)
{
    char *vg_name = NULL;
    char *volume_name = NULL;
    dss_init_get(&session->recv_pack);
    DSS_RETURN_IF_ERROR(dss_get_str(&session->recv_pack, &vg_name));
    DSS_RETURN_IF_ERROR(dss_get_str(&session->recv_pack, &volume_name));
    DSS_RETURN_IF_ERROR(dss_set_audit_resource(
        session->audit_info.resource, DSS_AUDIT_MODIFY, "vg_name:%s, volume_name:%s", vg_name, volume_name));

    return dss_remove_volume(session, vg_name, volume_name);
}

static status_t dss_process_refresh_file(dss_session_t *session)
{
    uint64 fid;
    ftid_t ftid;
    uint32 vgid;
    dss_block_id_t blockid;

    dss_init_get(&session->recv_pack);
    DSS_RETURN_IF_ERROR(dss_get_int64(&session->recv_pack, (int64 *)&fid));
    DSS_RETURN_IF_ERROR(dss_get_int64(&session->recv_pack, (int64 *)&ftid));
    char *name_str = NULL;
    DSS_RETURN_IF_ERROR(dss_get_str(&session->recv_pack, &name_str));
    DSS_RETURN_IF_ERROR(dss_get_int32(&session->recv_pack, (int32 *)&vgid));
    DSS_RETURN_IF_ERROR(dss_get_int64(&session->recv_pack, (int64 *)&blockid));
    DSS_RETURN_IF_ERROR(dss_set_audit_resource(session->audit_info.resource, DSS_AUDIT_MODIFY,
        "vg_name:%s, block_id:%lld, fid:%llu, ftid:%llu", name_str, *(uint64 *)&blockid, fid, *(uint64 *)&ftid));

    return dss_refresh_file(session, fid, ftid, name_str, blockid);
}

static status_t dss_process_get_home(dss_session_t *session)
{
    char *server_home = dss_get_cfg_dir(ZFS_CFG);
    DSS_RETURN_IF_ERROR(dss_set_audit_resource(session->audit_info.resource, DSS_AUDIT_QUERY, "%s", server_home));
    DSS_LOG_DEBUG_OP("Server home is %s, when get home.", server_home);
    text_t data;
    cm_str2text(server_home, &data);
    data.len++; // for keeping the '\0'
    return dss_put_text(&session->send_pack, &data);
}

static status_t dss_process_refresh_volume(dss_session_t *session)
{
    uint32 volumeid;
    uint32 vgid;
    dss_init_get(&session->recv_pack);
    DSS_RETURN_IF_ERROR(dss_get_int32(&session->recv_pack, (int32 *)&volumeid));
    if (volumeid >= DSS_MAX_VOLUMES) {
        LOG_DEBUG_ERR("Volume id:%u overflow.", volumeid);
        return CM_ERROR;
    }
    char *name_str = NULL;
    DSS_RETURN_IF_ERROR(dss_get_str(&session->recv_pack, &name_str));
    DSS_RETURN_IF_ERROR(dss_get_int32(&session->recv_pack, (int32 *)&vgid));
    DSS_RETURN_IF_ERROR(dss_set_audit_resource(
        session->audit_info.resource, DSS_AUDIT_MODIFY, "vg_name:%s, volume_id:%u", name_str, volumeid));

    return dss_refresh_volume(session, name_str, vgid, volumeid);
}

static status_t dss_process_rename(dss_session_t *session)
{
    char *src = NULL;
    char *dst = NULL;
    dss_init_get(&session->recv_pack);
    DSS_RETURN_IF_ERROR(dss_get_str(&session->recv_pack, &src));
    DSS_RETURN_IF_ERROR(dss_get_str(&session->recv_pack, &dst));
    DSS_RETURN_IF_ERROR(dss_set_audit_resource(session->audit_info.resource, DSS_AUDIT_MODIFY, "%s, %s", src, dst));
    return dss_rename_file(session, src, dst);
}

static status_t dss_process_loadctrl(dss_session_t *session)
{
    char *vg_name = NULL;
    uint32 index = 0;
    dss_init_get(&session->recv_pack);
    DSS_RETURN_IF_ERROR(dss_get_str(&session->recv_pack, &vg_name));
    DSS_RETURN_IF_ERROR(dss_get_int32(&session->recv_pack, (int32 *)&index));
    DSS_RETURN_IF_ERROR(
        dss_set_audit_resource(session->audit_info.resource, DSS_AUDIT_MODIFY, "vg_name:%s, index:%u", vg_name, index));

    return dss_load_ctrl(session, vg_name, index);
}

static status_t dss_process_set_sessionid(dss_session_t *session)
{
    dss_init_get(&session->recv_pack);
    dss_cli_info *cli_info;
    DSS_RETURN_IF_ERROR(dss_get_data(&session->recv_pack, sizeof(dss_cli_info), (void **)&cli_info));
    errno_t errcode;
    errcode = memcpy_s(&session->cli_info, sizeof(dss_cli_info), cli_info, sizeof(dss_cli_info));
    securec_check_ret(errcode);
    DSS_RETURN_IF_ERROR(dss_set_audit_resource(session->audit_info.resource, DSS_AUDIT_MODIFY, "%u", session->id));

    LOG_RUN_INF("The client has connected, session id:%u, pid:%llu, process name:%s.st_time:%lld", session->id,
        session->cli_info.cli_pid, session->cli_info.process_name, session->cli_info.start_time);

    return dss_put_int32(&session->send_pack, session->id);
}

static status_t dss_process_refresh_file_table(dss_session_t *session)
{
    uint32 vgid;
    dss_block_id_t blockid;

    dss_init_get(&session->recv_pack);
    DSS_RETURN_IF_ERROR(dss_get_int64(&session->recv_pack, (int64 *)&blockid));
    char *name_str = NULL;
    DSS_RETURN_IF_ERROR(dss_get_str(&session->recv_pack, &name_str));
    DSS_RETURN_IF_ERROR(dss_get_int32(&session->recv_pack, (int32 *)&vgid));
    DSS_RETURN_IF_ERROR(dss_set_audit_resource(
        session->audit_info.resource, DSS_AUDIT_MODIFY, "vg_name:%s, blockid:%llu", name_str, *(uint64 *)&blockid));

    return dss_refresh_ft_block(session, name_str, vgid, blockid);
}

static status_t dss_process_symlink(dss_session_t *session)
{
    char *new_path = NULL;
    char *dst_path = NULL;
    text_t text;
    text_t sub = CM_NULL_TEXT;
    dss_init_get(&session->recv_pack);
    DSS_RETURN_IF_ERROR(dss_get_str(&session->recv_pack, &dst_path));
    DSS_RETURN_IF_ERROR(dss_get_str(&session->recv_pack, &new_path));
    DSS_RETURN_IF_ERROR(
        dss_set_audit_resource(session->audit_info.resource, DSS_AUDIT_MODIFY, "%s, %s", dst_path, new_path));

    cm_str2text(new_path, &text);
    bool32 result = cm_fetch_rtext(&text, '/', '\0', &sub);
    DSS_RETURN_IF_FALSE2(result, LOG_DEBUG_ERR("not a complete absolute path name(%s %s)", T2S(&sub), T2S(&text)));

    char parent_str[DSS_FILE_PATH_MAX_LENGTH];
    char name_str[DSS_MAX_NAME_LEN];
    DSS_RETURN_IF_ERROR(cm_text2str(&sub, parent_str, sizeof(parent_str)));
    DSS_RETURN_IF_ERROR(cm_text2str(&text, name_str, sizeof(name_str)));
    DSS_RETURN_IF_ERROR(dss_create_link(session, parent_str, name_str));
    status_t status = dss_write_link_file(session, new_path, dst_path);
    if (status != CM_SUCCESS) {
        DSS_RETURN_IF_ERROR(dss_remove_link(session, (const char *)new_path));
        return status;
    }

    return CM_SUCCESS;
}

static status_t dss_process_readlink(dss_session_t *session)
{
    char *link_path = NULL;
    char name[DSS_FILE_PATH_MAX_LENGTH];
    uint32 res_len = 0;

    dss_init_get(&session->recv_pack);
    DSS_RETURN_IF_ERROR(dss_get_str(&session->recv_pack, &link_path));
    DSS_RETURN_IF_ERROR(dss_set_audit_resource(session->audit_info.resource, DSS_AUDIT_QUERY, "%s", link_path));
    DSS_RETURN_IF_ERROR(dss_read_link(session, link_path, name, &res_len));
    DSS_LOG_DEBUG_OP("Link is %s, when read link.", link_path);
    text_t data;
    cm_str2text(name, &data);
    data.len++; // for keeping the '\0'
    return dss_put_text(&session->send_pack, &data);
}

static status_t dss_process_unlink(dss_session_t *session)
{
    char *link = NULL;
    dss_init_get(&session->recv_pack);
    DSS_RETURN_IF_ERROR(dss_get_str(&session->recv_pack, &link));
    DSS_RETURN_IF_ERROR(dss_set_audit_resource(session->audit_info.resource, DSS_AUDIT_MODIFY, "%s", link));

    return dss_remove_link(session, (const char *)link);
}

status_t dss_process_update_file_written_size(dss_session_t *session)
{
    uint64 written_size;
    dss_block_id_t blockid;
    char *vg_name = NULL;

    dss_init_get(&session->recv_pack);
    DSS_RETURN_IF_ERROR(dss_get_int64(&session->recv_pack, (int64 *)&blockid));
    DSS_RETURN_IF_ERROR(dss_get_str(&session->recv_pack, &vg_name));
    DSS_RETURN_IF_ERROR(dss_get_int64(&session->recv_pack, (int64 *)&written_size));
    DSS_RETURN_IF_ERROR(dss_set_audit_resource(
        session->audit_info.resource, DSS_AUDIT_MODIFY, "vg_name:%s, block_id:%lld", vg_name, *(uint64 *)&blockid));
    return dss_update_file_written_size(session, vg_name, written_size, blockid);
}

static status_t dss_process_get_ftid_by_path(dss_session_t *session)
{
    char *path = NULL;
    ftid_t ftid;
    dss_vg_info_item_t *vg_item;
    dss_init_get(&session->recv_pack);
    DSS_RETURN_IF_ERROR(dss_get_str(&session->recv_pack, &path));
    DSS_RETURN_IF_ERROR(dss_get_ftid_by_path(session, path, &ftid, &vg_item));
    DSS_RETURN_IF_ERROR(dss_set_audit_resource(session->audit_info.resource, DSS_AUDIT_QUERY, "%s", path));

    dss_find_node_t find_node;
    find_node.ftid = ftid;
    errno_t err = strncpy_sp(find_node.vg_name, DSS_MAX_NAME_LEN, vg_item->vg_name, DSS_MAX_NAME_LEN);
    bool32 result = (bool32)(err == EOK);
    DSS_RETURN_IF_FALSE2(result, DSS_THROW_ERROR(ERR_SYSTEM_CALL, err));

    text_t data = {(char *)&find_node, sizeof(dss_find_node_t)};
    return dss_put_text(&session->send_pack, &data);
}

#define DSS_SERVER_STATUS_OFFSET(i) ((uint32)(i) - (uint32)DSS_STATUS_NORMAL)
static char *g_dss_instance_rdwr_type[DSS_SERVER_STATUS_OFFSET(DSS_SERVER_STATUS_END)] = {
    [DSS_SERVER_STATUS_OFFSET(DSS_STATUS_NORMAL)] = "NORMAL",
    [DSS_SERVER_STATUS_OFFSET(DSS_STATUS_READONLY)] = "READONLY",
    [DSS_SERVER_STATUS_OFFSET(DSS_STATUS_READWRITE)] = "READWRITE",
};

char *dss_get_dss_server_status(int32 server_status)
{
    if (server_status < DSS_STATUS_NORMAL || server_status > DSS_STATUS_READWRITE) {
        return "unknown";
    }
    return g_dss_instance_rdwr_type[DSS_SERVER_STATUS_OFFSET(server_status)];
}

#define DSS_INSTANCE_STATUS_OFFSET(i) ((uint32)(i) - (uint32)DSS_STATUS_PREPARE)
static char *g_dss_instance_status_desc[DSS_INSTANCE_STATUS_OFFSET(DSS_INSTANCE_STATUS_END)] = {
    [DSS_INSTANCE_STATUS_OFFSET(DSS_STATUS_PREPARE)] = "prepare",
    [DSS_INSTANCE_STATUS_OFFSET(DSS_STATUS_RECOVERY)] = "recovery",
    [DSS_INSTANCE_STATUS_OFFSET(DSS_STATUS_SWITCH)] = "switch",
    [DSS_INSTANCE_STATUS_OFFSET(DSS_STATUS_OPEN)] = "open",
};

char *dss_get_dss_instance_status(int32 instance_status)
{
    if (instance_status < DSS_STATUS_PREPARE || instance_status > DSS_STATUS_OPEN) {
        return "unknown";
    }
    return g_dss_instance_status_desc[DSS_INSTANCE_STATUS_OFFSET(instance_status)];
}

// get dssserver status:open, recovery or switch
static status_t dss_process_get_inst_status(dss_session_t *session)
{
    dss_server_status_t *dss_status = NULL;
    DSS_RETURN_IF_ERROR(
        dss_reserv_text_buf(&session->send_pack, (uint32)sizeof(dss_server_status_t), (char **)&dss_status));

    dss_status->instance_status_id = g_dss_instance.status;
    dss_status->server_status_id = dss_get_server_status_flag();
    dss_status->local_instance_id = g_dss_instance.inst_cfg.params.inst_id;
    dss_status->master_id = dss_get_master_id();
    char *dss_instance_status = dss_get_dss_instance_status(dss_status->instance_status_id);
    uint32 errcode = strcpy_s(dss_status->instance_status, DSS_MAX_STATUS_LEN, dss_instance_status);
    MEMS_RETURN_IFERR(errcode);
 
    char *dss_server_status = dss_get_dss_server_status(dss_status->server_status_id);
    errcode = strcpy_s(dss_status->server_status, DSS_MAX_STATUS_LEN, dss_server_status);
    MEMS_RETURN_IFERR(errcode);
 
    DSS_RETURN_IF_ERROR(dss_set_audit_resource(
        session->audit_info.resource, DSS_AUDIT_MODIFY, "status:%s", dss_status->instance_status));
    DSS_LOG_DEBUG_OP("Server status is %s.", dss_status->instance_status);
    return CM_SUCCESS;
}

static status_t dss_process_get_time_stat(dss_session_t *session)
{
    uint64 size = sizeof(dss_session_stat_t) * DSS_EVT_COUNT;
    dss_session_stat_t *time_stat = NULL;
    DSS_RETURN_IF_ERROR(dss_reserv_text_buf(&session->send_pack, size, (char **)&time_stat));

    errno_t errcode = memset_s(time_stat, (size_t)size, 0,(size_t)size);
    securec_check_ret(errcode);
    uint32 max_cfg_sess = g_dss_instance.inst_cfg.params.cfg_session_num;
    dss_session_ctrl_t *session_ctrl = dss_get_session_ctrl();
    cm_spin_lock(&session_ctrl->lock, NULL);
    for (uint32 i = 0; i < max_cfg_sess; i++) {
        if (session_ctrl->sessions[i].is_used && !session_ctrl->sessions[i].is_closed) {
            for (uint32 j = 0; j < DSS_EVT_COUNT; j++) {
                int64 count = (int64)session_ctrl->sessions[i].dss_session_stat[j].wait_count;
                int64 total_time = (int64)session_ctrl->sessions[i].dss_session_stat[j].total_wait_time;
                int64 max_sgl_time = (int64)session_ctrl->sessions[i].dss_session_stat[j].max_single_time;

                time_stat[j].wait_count += count;
                time_stat[j].total_wait_time += total_time;
                time_stat[j].max_single_time = (atomic_t)MAX((int64)time_stat[j].max_single_time, max_sgl_time);

                (void)cm_atomic_add(&session_ctrl->sessions[i].dss_session_stat[j].wait_count, -count);
                (void)cm_atomic_add(&session_ctrl->sessions[i].dss_session_stat[j].total_wait_time, -total_time);
                (void)cm_atomic_cas(&session_ctrl->sessions[i].dss_session_stat[j].max_single_time, max_sgl_time, 0);
            }
        }
    }
    cm_spin_unlock(&session_ctrl->lock);

    return CM_SUCCESS;
}

void dss_wait_session_pause(dss_instance_t *inst)
{
    uds_lsnr_t *lsnr = &inst->lsnr;
    LOG_DEBUG_INF("Begin to set session paused.");
    cs_pause_uds_lsnr(lsnr);
    dss_pause_reactors();
    while (inst->active_sessions != 0) {
        cm_sleep(1);
    }
    LOG_DEBUG_INF("Succeed to pause all session.");
}

void dss_set_session_running(dss_instance_t *inst)
{
    LOG_DEBUG_INF("Begin to set session running.");
    uds_lsnr_t *lsnr = &inst->lsnr;
    dss_continue_reactors();
    lsnr->status = LSNR_STATUS_RUNNING;
    LOG_DEBUG_INF("Succeed to run all sessions.");
}

static status_t dss_process_setcfg(dss_session_t *session)
{
    char *name = NULL;
    char *value = NULL;
    char *scope = NULL;
    dss_init_get(&session->recv_pack);
    DSS_RETURN_IF_ERROR(dss_get_str(&session->recv_pack, &name));
    DSS_RETURN_IF_ERROR(dss_get_str(&session->recv_pack, &value));
    DSS_RETURN_IF_ERROR(dss_get_str(&session->recv_pack, &scope));
    DSS_RETURN_IF_ERROR(dss_set_audit_resource(session->audit_info.resource, DSS_AUDIT_MODIFY, "%s", name));

    return dss_set_cfg_param(name, value, scope);
}

static status_t dss_process_getcfg(dss_session_t *session)
{
    char *name = NULL;
    char *value = NULL;
    dss_init_get(&session->recv_pack);
    DSS_RETURN_IF_ERROR(dss_get_str(&session->recv_pack, &name));
    DSS_RETURN_IF_ERROR(dss_set_audit_resource(session->audit_info.resource, DSS_AUDIT_QUERY, "%s", name));

    DSS_RETURN_IF_ERROR(dss_get_cfg_param(name, &value));
    DSS_LOG_DEBUG_OP("Server value is %s, when get cfg.", value);
    text_t data;
    cm_str2text(value, &data);
    // SSL default value is NULL
    if (value != NULL) {
        data.len++; // for keeping the '\0'
    }
    return dss_put_text(&session->send_pack, &data);
}

static status_t dss_process_stop_server(dss_session_t *session)
{
    dss_init_get(&session->recv_pack);
    DSS_RETURN_IF_ERROR(dss_set_audit_resource(session->audit_info.resource, DSS_AUDIT_MODIFY, "%u", session->id));
    g_dss_instance.abort_status = CM_TRUE;

    return CM_SUCCESS;
}

// process switch lock,just master id can do
static status_t dss_process_switch_lock(dss_session_t *session)
{
    uint32 master_id = dss_get_master_id();
    dss_config_t *cfg = dss_get_inst_cfg();
    uint32 curr_id = (uint32)(cfg->params.inst_id);
    int32 switch_id;
    dss_init_get(&session->recv_pack);
    DSS_RETURN_IF_ERROR(dss_get_int32(&session->recv_pack, &switch_id));
    if ((uint32)switch_id == master_id) {
        LOG_DEBUG_INF("switchid is equal to current master_id, which is %u.", master_id);
        return CM_SUCCESS;
    }
    if (master_id != curr_id) {
        LOG_DEBUG_ERR("current id is %u, just master id %u can do switch lock.", curr_id, master_id);
        return CM_ERROR;
    }
    cm_spin_lock(&g_dss_instance.switch_lock, NULL);
    dss_wait_session_pause(&g_dss_instance);
    g_dss_instance.status = DSS_STATUS_SWITCH;
    status_t ret = CM_SUCCESS;
    // trans lock
    if (g_dss_instance.cm_res.is_valid) {
        dss_set_server_status_flag(DSS_STATUS_READONLY);
        LOG_RUN_INF("inst %u set status flag %u when trans lock.", curr_id, DSS_STATUS_READONLY);
        ret = cm_res_trans_lock(&g_dss_instance.cm_res.mgr, DSS_CM_LOCK, (uint32)switch_id);
        if (ret != CM_SUCCESS) {
            dss_set_session_running(&g_dss_instance);
            dss_set_server_status_flag(DSS_STATUS_READWRITE);
            LOG_RUN_INF("inst %u set status flag %u when failed to trans lock.", curr_id, DSS_STATUS_READWRITE);
            g_dss_instance.status = DSS_STATUS_OPEN;
            cm_spin_unlock(&g_dss_instance.switch_lock);
            LOG_DEBUG_ERR("cm do switch lock failed from %u to %u.", curr_id, master_id);
            return ret;
        }
        dss_set_master_id((uint32)switch_id);
        dss_set_session_running(&g_dss_instance);
        g_dss_instance.status = DSS_STATUS_OPEN;
    } else {
        dss_set_session_running(&g_dss_instance);
        g_dss_instance.status = DSS_STATUS_OPEN;
        cm_spin_unlock(&g_dss_instance.switch_lock);
        LOG_DEBUG_ERR("Only with cm can switch lock.");
        return CM_ERROR;
    }
    LOG_RUN_INF("Old main server %u switch lock to new main server %u successfully.", curr_id, (uint32)switch_id);
    cm_spin_unlock(&g_dss_instance.switch_lock);
    return CM_SUCCESS;
}
/*
    1 curr_id == master_id, just return success;
    2 curr_id != master_id, just send message to master_id to do switch lock
    then master_id to do:
    (1) set status switch
    (2) lsnr pause
    (3) trans lock
*/
static status_t dss_process_remote_switch_lock(dss_session_t *session, uint32 curr_id, uint32 master_id)
{
    dss_init_set(&session->recv_pack);
    session->recv_pack.head->cmd = DSS_CMD_SWITCH_LOCK;
    session->recv_pack.head->flags = 0;
    LOG_DEBUG_INF("Try to switch lock to %u by %u.", curr_id, master_id);
    (void)dss_put_int32(&session->recv_pack, curr_id);
    return dss_process_remote(session);
}

static status_t dss_process_set_main_inst(dss_session_t *session)
{
    status_t status = CM_ERROR;
    DSS_RETURN_IF_ERROR(dss_reload_cluster_run_mode_param(g_inst_cfg));
    dss_config_t *cfg = dss_get_inst_cfg();
    uint32 curr_id = (uint32)(cfg->params.inst_id);
    uint32 master_id;
    DSS_RETURN_IF_ERROR(dss_set_audit_resource(
        session->audit_info.resource, DSS_AUDIT_MODIFY, "set %u as master", curr_id));
    while (CM_TRUE) {
        master_id = dss_get_master_id();
        if (master_id == curr_id) {
            session->recv_pack.head->cmd = DSS_CMD_SET_MAIN_INST;
            LOG_RUN_INF("Main server %u is set successfully by %u.", curr_id, master_id);
            return CM_SUCCESS;
        }
        if (!cm_spin_timed_lock(&g_dss_instance.switch_lock, DSS_PROCESS_REMOTE_INTERVAL)) {
            LOG_DEBUG_INF("Spin switch_lock timed out, just continue.");
            continue;
        }
        if (!g_dss_instance.is_maintain) {
            status = dss_process_remote_switch_lock(session, curr_id, master_id);
            if (status != CM_SUCCESS) {
                LOG_DEBUG_ERR("Failed to switch lock to %u by %u.", curr_id, master_id);
                cm_spin_unlock(&g_dss_instance.switch_lock);
                cm_sleep(DSS_PROCESS_REMOTE_INTERVAL);
                continue;
            }
        }
        break;
    }
    session->recv_pack.head->cmd = DSS_CMD_SET_MAIN_INST;
    g_dss_instance.status = DSS_STATUS_SWITCH;
    dss_set_master_id(curr_id);
    status = dss_refresh_meta_info(session);
    if (status != CM_SUCCESS) {
        g_dss_instance.status = DSS_STATUS_OPEN;
        cm_spin_unlock(&g_dss_instance.switch_lock);
        LOG_RUN_ERR("[DSS] ABORT INFO: dss instance %u refresh meta failed, result(%d).", curr_id, status);
        cm_fync_logfile();
        _exit(1);
    }
    dss_set_server_status_flag(DSS_STATUS_READWRITE);
    LOG_RUN_INF("inst %u set status flag %u when set main inst.", curr_id, DSS_STATUS_READWRITE);
    g_dss_instance.status = DSS_STATUS_OPEN;
    LOG_RUN_INF("Main server %u is set successfully by %u.", curr_id, master_id);
    cm_spin_unlock(&g_dss_instance.switch_lock);
    return CM_SUCCESS;
}

// clang-format off
static dss_cmd_hdl_t g_dss_cmd_handle[] = {
    // modify
    { DSS_CMD_MKDIR, dss_process_mkdir, NULL, CM_TRUE },
    { DSS_CMD_RMDIR, dss_process_rmdir, NULL, CM_TRUE },
    { DSS_CMD_OPEN_DIR, dss_process_open_dir, NULL, CM_FALSE },
    { DSS_CMD_CLOSE_DIR, dss_process_close_dir, NULL, CM_FALSE },
    { DSS_CMD_OPEN_FILE, dss_process_open_file, NULL, CM_FALSE },
    { DSS_CMD_CLOSE_FILE, dss_process_close_file, NULL, CM_FALSE },
    { DSS_CMD_CREATE_FILE, dss_process_create_file, NULL, CM_TRUE },
    { DSS_CMD_DELETE_FILE, dss_process_delete_file, NULL, CM_TRUE },
    { DSS_CMD_EXTEND_FILE, dss_process_extending_file, NULL, CM_TRUE },
    { DSS_CMD_ATTACH_FILE, NULL, NULL, CM_FALSE },
    { DSS_CMD_DETACH_FILE, NULL, NULL, CM_FALSE },
    { DSS_CMD_RENAME_FILE, dss_process_rename, NULL, CM_TRUE },
    { DSS_CMD_REFRESH_FILE, dss_process_refresh_file, NULL, CM_FALSE },
    { DSS_CMD_TRUNCATE_FILE, dss_process_truncate_file, NULL, CM_TRUE },
    { DSS_CMD_REFRESH_FILE_TABLE, dss_process_refresh_file_table, NULL, CM_FALSE },
    { DSS_CMD_CONSOLE, NULL, NULL, CM_FALSE },
    { DSS_CMD_ADD_VOLUME, dss_process_add_volume, NULL, CM_TRUE },
    { DSS_CMD_REMOVE_VOLUME, dss_process_remove_volume, NULL, CM_TRUE },
    { DSS_CMD_REFRESH_VOLUME, dss_process_refresh_volume, NULL, CM_FALSE },
    { DSS_CMD_LOAD_CTRL, dss_process_loadctrl, NULL, CM_FALSE },
    { DSS_CMD_SET_SESSIONID, dss_process_set_sessionid, NULL, CM_FALSE },
    { DSS_CMD_UPDATE_WRITTEN_SIZE, dss_process_update_file_written_size, NULL, CM_TRUE },
    { DSS_CMD_STOP_SERVER, dss_process_stop_server, NULL, CM_FALSE },
    { DSS_CMD_SETCFG, dss_process_setcfg, NULL, CM_FALSE },
    { DSS_CMD_SYMLINK, dss_process_symlink, NULL, CM_TRUE },
    { DSS_CMD_UNLINK, dss_process_unlink, NULL, CM_TRUE },
    { DSS_CMD_SET_MAIN_INST, dss_process_set_main_inst, NULL, CM_FALSE },
    { DSS_CMD_SWITCH_LOCK, dss_process_switch_lock, NULL, CM_FALSE },
    // query
    { DSS_CMD_GET_HOME, dss_process_get_home, NULL, CM_FALSE },
    { DSS_CMD_EXIST, dss_process_exist, NULL, CM_FALSE },
    { DSS_CMD_READLINK, dss_process_readlink, NULL, CM_FALSE },
    { DSS_CMD_GET_FTID_BY_PATH, dss_process_get_ftid_by_path, NULL, CM_FALSE },
    { DSS_CMD_GETCFG, dss_process_getcfg, NULL, CM_FALSE },
    { DSS_CMD_GET_INST_STATUS, dss_process_get_inst_status, NULL, CM_FALSE },
    { DSS_CMD_GET_TIME_STAT, dss_process_get_time_stat, NULL, CM_FALSE },
};

dss_cmd_hdl_t g_dss_remote_handle = { DSS_CMD_EXEC_REMOTE, dss_process_remote, NULL, CM_FALSE };
// clang-format on
static dss_cmd_hdl_t *dss_get_cmd_handle(int32 cmd, bool32 local_req)
{
    int32 mid_pos = 0;
    int32 begin_pos = 0;
    int32 end_pos = ARRAY_NUM(g_dss_cmd_handle) - 1;
    dss_cmd_hdl_t *handle = NULL;
    while (end_pos >= begin_pos) {
        /* mid_pos is the average of begin_pos and end_pos */
        mid_pos = (begin_pos + end_pos) / 2;
        if (cmd == g_dss_cmd_handle[mid_pos].cmd) {
            handle = &g_dss_cmd_handle[mid_pos];
            break;
        } else if (cmd < g_dss_cmd_handle[mid_pos].cmd) {
            end_pos = mid_pos - 1;
        } else {
            begin_pos = mid_pos + 1;
        }
    }

    if (handle != NULL) {
        if (dss_need_exec_remote(handle->exec_on_active, local_req)) {
            handle = &g_dss_remote_handle;
        }
    }

    return handle;
}

static status_t dss_exec_cmd(dss_session_t *session, bool32 local_req)
{
    DSS_LOG_DEBUG_OP(
        "Receive command:%d, server status is %d.", session->recv_pack.head->cmd, (int32)g_dss_instance.status);

    dss_cmd_hdl_t *handle = NULL;
    if (session->recv_pack.head->cmd < DSS_CMD_END) {
        handle = dss_get_cmd_handle(session->recv_pack.head->cmd, local_req);
    }

    if ((handle == NULL) || (handle->proc == NULL)) {
        LOG_DEBUG_ERR("the req cmd: %d is not valid.", session->recv_pack.head->cmd);
        return CM_ERROR;
    }

    session->audit_info.action = dss_get_cmd_desc(session->recv_pack.head->cmd);
    status_t status = handle->proc(session);
    if (local_req) {
        sql_record_audit_log(session, status, session->recv_pack.head->cmd);
    }
    return status;
}

#define DSS_WAIT_TIMEOUT 5
status_t dss_process_command(dss_session_t *session)
{
    status_t status = CM_SUCCESS;
    bool32 ready = CM_FALSE;

    cm_reset_error();
    if (cs_wait(&session->pipe, CS_WAIT_FOR_READ, DSS_WAIT_TIMEOUT, &ready) != CM_SUCCESS) {
        session->is_closed = CM_TRUE;
        return CM_ERROR;
    }

    if (ready == CM_FALSE) {
        return CM_SUCCESS;
    }
    dss_init_set(&session->send_pack);
    status = dss_read(&session->pipe, &session->recv_pack, CM_FALSE);
    if (status != CM_SUCCESS) {
        LOG_RUN_ERR("Failed to read message sent by %s.", session->cli_info.process_name);
        session->is_closed = CM_TRUE;
        return CM_ERROR;
    }
    date_t time_start = g_timer()->now;
    date_t time_now = 0;
    while (g_dss_instance.status != DSS_STATUS_OPEN) {
        if (dss_can_cmd_type_no_open(session->recv_pack.head->cmd)) {
            status = dss_exec_cmd(session, CM_TRUE);
            if (status != CM_SUCCESS) {
                LOG_DEBUG_ERR("Failed to execute command:%d.", session->recv_pack.head->cmd);
                dss_return_error(session);
                return CM_ERROR;
            } else {
                dss_return_success(session);
                return CM_SUCCESS;
            }
        }
        DSS_GET_CM_LOCK_LONG_SLEEP;
        LOG_RUN_INF("The status %d of instance %lld is not open, just wait.\n", (int32)g_dss_instance.status,
            dss_get_inst_cfg()->params.inst_id);
        time_now = g_timer()->now;
        if (time_now - time_start > DSS_MAX_FAIL_TIME_WITH_CM * MICROSECS_PER_SECOND) {
            LOG_RUN_ERR("[DSS] ABORT INFO: Fail to change status open for %d seconds, exit.", DSS_MAX_FAIL_TIME_WITH_CM);
            cm_fync_logfile();
            _exit(1);
        }
    }
    status = dss_exec_cmd(session, CM_TRUE);
    if (status != CM_SUCCESS) {
        LOG_DEBUG_ERR("Failed to execute command:%d.", session->recv_pack.head->cmd);
        dss_return_error(session);
        return CM_ERROR;
    } else {
        dss_return_success(session);
    }
    return CM_SUCCESS;
}

status_t dss_proc_standby_req(dss_session_t *session)
{
    if (dss_is_readonly() == CM_TRUE && !dss_need_exec_local()) {
        dss_config_t *cfg = dss_get_inst_cfg();
        uint32 id = (uint32)(cfg->params.inst_id);
        LOG_RUN_ERR("The local node(%u) is in readonly state and cannot execute remote requests.", id);
        return CM_ERROR;
    }

    return dss_exec_cmd(session, CM_FALSE);
}

#ifdef __cplusplus
}
#endif
