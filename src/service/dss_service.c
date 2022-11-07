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

#include "dss_system.h"
#include "dss_instance.h"
#include "dss_io_fence.h"
#include "dss_malloc.h"
#include "dss_open_file.h"
#include "dss_srv_proc.h"
#include "dss_syncpoint.h"
#include "dss_mes.h"
#include "dss_api.h"
#include "dss_service.h"

static inline bool32 dss_need_exec_remote(bool32 exec_on_active, bool32 local_req)
{
    return ((dss_is_readonly() == CM_TRUE) && (exec_on_active) && (local_req == CM_TRUE));
}

static status_t dss_process_remote(dss_session_t *session)
{
    dss_config_t *cfg = dss_get_inst_cfg();
    uint32 remoteid = dss_get_master_id();
    uint32 currid = (uint32)(cfg->params.inst_id);
    status_t ret = CM_ERROR;
    if (remoteid == DSS_INVALID_ID32) {
        ret = dss_polling_master_id(session);
        if (ret != CM_SUCCESS) {
            LOG_RUN_ERR("dss server polling master dss server id failed, current dss node(%u).", currid);
            return ret;
        }
        remoteid = dss_get_master_id();
        if (remoteid == DSS_INVALID_ID32) {
            LOG_RUN_ERR("dss server polling master dss server id error.");
            return CM_ERROR;
        }
    }
    LOG_DEBUG_INF("Start processing remote requests(%d), remote node(%u),current node(%u).",
        session->recv_pack.head->cmd, remoteid, currid);
    ret = dss_exec_sync(session, remoteid, currid);
    if (ret != CM_SUCCESS) {
        LOG_DEBUG_ERR(
            "End of processing the remote request(%d) failed, remote node(%u),current node(%u), result code(%d).",
            session->recv_pack.head->cmd, remoteid, currid, ret);
        return ret;
    }
    LOG_DEBUG_INF("The remote request(%d) is processed successfully, remote node(%u),current node(%u).",
        session->recv_pack.head->cmd, remoteid, currid);
    return ret;
}

static status_t dss_diag_proto_type(dss_session_t *session)
{
    link_ready_ack_t ack;
    uint32 proto_code = 0;
    int32 size;
    errno_t rc_memzero;
    status_t ret = cs_read_bytes(&session->pipe, (char *)&proto_code, sizeof(proto_code), &size);
    if (ret != CM_SUCCESS) {
        LOG_RUN_ERR("Instance recieve protocol failed, errno:%d.", errno);
        return ret;
    }

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
    session->curr_lsn = cm_get_curr_lsn();
    (void)cm_atomic_inc(&g_dss_instance.thread_cnt);
    while (!thread->closed) {
        /* process request command */
        if ((dss_process_command(session) != CM_SUCCESS) && (session->is_closed == CM_TRUE)) {
            break;
        }
    }
    LOG_RUN_INF("Session:%u end to do service.", session->id);

    dss_clean_session_latch(dss_get_session_ctrl(), session);
    dss_clean_open_files(session);
    dss_destroy_session(session);
    cm_release_thread(thread);
    (void)cm_atomic_dec(&g_dss_instance.thread_cnt);
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
        _exit(1);
    }
    (void)dss_put_int32(send_pack, (uint32)code);
    (void)dss_put_str_with_cutoff(send_pack, message);
    status_t status = dss_write(&session->pipe, send_pack);
    if (status != CM_SUCCESS) {
        LOG_DEBUG_ERR("Failed to reply,size:%u.", send_pack->head->size);
    }
    cm_reset_error();
}

static void dss_return_success(dss_session_t *session)
{
    CM_ASSERT(session != NULL);
    status_t status;
    dss_packet_t *send_pack = NULL;
    send_pack = &session->send_pack;
    dss_init_set(send_pack);
    send_pack->head->cmd = session->recv_pack.head->cmd;
    send_pack->head->result = (uint8)CM_SUCCESS;
    send_pack->head->flags = 0;
    if (session->send_info.len > 0) {
        status = dss_put_text(send_pack, &session->send_info);
        if (status != CM_SUCCESS) {
            return;
        }
        session->send_info.len = 0;
    }
    status = dss_write(&session->pipe, send_pack);
    if (status != CM_SUCCESS) {
        LOG_DEBUG_ERR("Failed to reply message,size:%u.", send_pack->head->size);
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
    int32 ret =
        snprintf_s(session->audit_info.resource, DSS_FILE_PATH_MAX_LENGTH, DSS_FILE_PATH_MAX_LENGTH - 1, "%s", dir);
    DSS_SECUREC_SS_RETURN_IF_ERROR(ret, CM_ERROR);
    return dss_remove_dir(session, (const char *)dir, (bool)recursive);
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
    if (!cm_fetch_rtext(&text, '/', '\0', &sub)) {
        LOG_DEBUG_ERR("not a complete absolute path name(%s %s)", T2S(&sub), T2S(&text));
        return CM_ERROR;
    }
    if (text.len >= DSS_MAX_NAME_LEN) {
        DSS_THROW_ERROR(ERR_DSS_FILE_PATH_ILL, text.str, "name length should less than 64.");
        return CM_ERROR;
    }

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
    if (dss_get_str(&session->recv_pack, &name) != CM_SUCCESS) {
        LOG_DEBUG_ERR("delete file get file name failed.");
        return CM_ERROR;
    }
    DSS_RETURN_IF_ERROR(dss_set_audit_resource(session->audit_info.resource, DSS_AUDIT_MODIFY, "%s", name));
    return dss_remove_file(session, (const char *)name);
}

static status_t dss_process_exist_dir(dss_session_t *session)
{
    bool32 result = CM_FALSE;
    char *name = NULL;
    dss_init_get(&session->recv_pack);
    DSS_RETURN_IF_ERROR(dss_get_str(&session->recv_pack, &name));
    DSS_RETURN_IF_ERROR(dss_set_audit_resource(session->audit_info.resource, DSS_AUDIT_QUERY, "%s", name));
    DSS_RETURN_IF_ERROR(dss_exist_item(session, (const char *)name, GFT_PATH, &result));

    session->send_info.str = dss_init_sendinfo_buf(session->recv_pack.init_buf);
    session->send_info.len = sizeof(bool32);
    *(bool32 *)session->send_info.str = result;
    return CM_SUCCESS;
}

static status_t dss_process_islink(dss_session_t *session)
{
    bool32 result = CM_FALSE;
    char *name = NULL;
    dss_init_get(&session->recv_pack);
    DSS_RETURN_IF_ERROR(dss_get_str(&session->recv_pack, &name));
    DSS_RETURN_IF_ERROR(dss_set_audit_resource(session->audit_info.resource, DSS_AUDIT_QUERY, "%s", name));
    DSS_RETURN_IF_ERROR(dss_exist_item(session, (const char *)name, GFT_LINK, &result));

    session->send_info.str = dss_init_sendinfo_buf(session->recv_pack.init_buf);
    session->send_info.len = sizeof(bool32);
    *(bool32 *)session->send_info.str = result;
    return CM_SUCCESS;
}

static status_t dss_process_exist(dss_session_t *session)
{
    bool32 result = CM_FALSE;
    char *name = NULL;
    dss_init_get(&session->recv_pack);
    DSS_RETURN_IF_ERROR(dss_get_str(&session->recv_pack, &name));
    DSS_RETURN_IF_ERROR(dss_set_audit_resource(session->audit_info.resource, DSS_AUDIT_QUERY, "%s", name));
    DSS_RETURN_IF_ERROR(dss_exist_item(session, (const char *)name, GFT_FILE, &result));

    session->send_info.str = dss_init_sendinfo_buf(session->recv_pack.init_buf);
    session->send_info.len = sizeof(bool32);
    *(bool32 *)session->send_info.str = result;
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
    if (vg_item == NULL) {
        LOG_DEBUG_ERR("Failed to find vg, %s.", vg_name);
        return CM_ERROR;
    }
    DSS_RETURN_IF_ERROR(dss_close_file(session, vg_item, *(uint64 *)&ftid));
    DSS_LOG_DEBUG_OP(
        "Succeed to close file, ftid:%llu, fid:%llu, vg: %s, session pid:%llu, v:%u, au:%llu, block:%u, item:%u.",
        *(int64 *)&ftid, fid, vg_item->vg_name, session->cli_info.cli_pid, ftid.volume, (uint64)ftid.au, ftid.block,
        ftid.item);
    bool32 should_rm_file = DSS_FALSE;
    gft_node_t *node;
    (void)dss_check_rm_file(vg_item, ftid, &should_rm_file, &node);
    if (should_rm_file) {
#ifdef OPENGAUSS
        if (!dss_is_readwrite()) {
            LOG_DEBUG_INF(
                "Ignores to remove delay file when close file, because the instance is not in readwrite, fid: %llu",
                fid);
            return CM_SUCCESS;
        }
#endif
        status_t status = dss_remove_dir_file_by_node(session, vg_item, node);
        if (status != CM_SUCCESS) {
            LOG_DEBUG_INF("Failed to remove delay file when close file, fid: %llu", fid);
            return CM_SUCCESS;
        }
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
    uint64 fid;
    ftid_t ftid;
    int64 offset;
    int32 size;
    uint32 vgid;
    bool32 is_read;
    char *vg_name = NULL;

    dss_init_get(&session->recv_pack);
    DSS_RETURN_IF_ERROR(dss_get_int64(&session->recv_pack, (int64 *)&fid));
    DSS_RETURN_IF_ERROR(dss_get_int64(&session->recv_pack, (int64 *)&ftid));
    DSS_RETURN_IF_ERROR(dss_get_int64(&session->recv_pack, &offset));
    DSS_RETURN_IF_ERROR(dss_get_int32(&session->recv_pack, &size));
    DSS_RETURN_IF_ERROR(dss_get_str(&session->recv_pack, &vg_name));
    DSS_RETURN_IF_ERROR(dss_get_int32(&session->recv_pack, (int32 *)&vgid));
    DSS_RETURN_IF_ERROR(dss_get_int32(&session->recv_pack, (int32 *)&is_read));
    DSS_RETURN_IF_ERROR(dss_set_audit_resource(session->audit_info.resource, DSS_AUDIT_MODIFY,
        "vg_name:%s, fid:%llu, ftid:%llu", vg_name, fid, *(uint64 *)&ftid));

    return dss_extend(session, fid, ftid, offset, vg_name, vgid, is_read);
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

static status_t dss_process_register_host(dss_session_t *session)
{
    status_t status = CM_SUCCESS;
    dss_init_get(&session->recv_pack);
    DSS_RETURN_IF_ERROR(dss_set_audit_resource(
        session->audit_info.resource, DSS_AUDIT_MODIFY, "%lld", ZFS_INST->inst_cfg.params.inst_id));

    status = dss_iof_register_all(ZFS_INST->inst_cfg.params.inst_id, CM_TRUE);
    if (status != CM_SUCCESS) {
        LOG_DEBUG_ERR(
            "Failed to register to array, hostid %lld, status %d.", ZFS_INST->inst_cfg.params.inst_id, status);
        return status;
    }

    return CM_SUCCESS;
}

static status_t dss_process_unregister_host(dss_session_t *session)
{
    status_t status = CM_SUCCESS;
    dss_init_get(&session->recv_pack);
    DSS_RETURN_IF_ERROR(dss_set_audit_resource(
        session->audit_info.resource, DSS_AUDIT_MODIFY, "%lld", ZFS_INST->inst_cfg.params.inst_id));

    status = dss_iof_unregister_all(ZFS_INST->inst_cfg.params.inst_id, CM_TRUE);
    if (status != CM_SUCCESS) {
        LOG_DEBUG_ERR(
            "Failed to unregister from array, hostid %lld, status %d.", ZFS_INST->inst_cfg.params.inst_id, status);
        return status;
    }

    return CM_SUCCESS;
}

static status_t dss_process_kick_host(dss_session_t *session)
{
    int64 kick_hostid = 0;
    status_t status = CM_SUCCESS;
    dss_init_get(&session->recv_pack);
    DSS_RETURN_IF_ERROR(dss_get_int64(&session->recv_pack, &kick_hostid));
    DSS_RETURN_IF_ERROR(dss_set_audit_resource(
        session->audit_info.resource, DSS_AUDIT_MODIFY, "%lld, %lld", ZFS_INST->inst_cfg.params.inst_id, kick_hostid));

    status = dss_iof_sync_all_vginfo(session, VGS_INFO);
    if (status != CM_SUCCESS) {
        LOG_DEBUG_ERR("Sync all vginfo failed, status %d.", status);
        return status;
    }

    status = dss_iof_kick_all(ZFS_INST->inst_cfg.params.inst_id, kick_hostid, CM_TRUE);
    if (status != CM_SUCCESS) {
        LOG_DEBUG_ERR("Failed to kick host, curr hostid %lld, kick hostid %lld, status %d.",
            ZFS_INST->inst_cfg.params.inst_id, kick_hostid, status);
        return status;
    }

    return CM_SUCCESS;
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
    session->send_info.str = dss_init_sendinfo_buf(session->recv_pack.init_buf);
    int32 ret =
        snprintf_s(session->send_info.str, DSS_MAX_PATH_BUFFER_SIZE, DSS_MAX_PATH_BUFFER_SIZE - 1, "%s", server_home);
    DSS_SECUREC_SS_RETURN_IF_ERROR(ret, CM_ERROR);
    session->send_info.len = (uint32)ret;
    DSS_LOG_DEBUG_OP("Server home is %s, when get home.", session->send_info.str);
    return CM_SUCCESS;
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
    status_t ret = dss_rename_file(session, src, dst);
    if (ret != CM_SUCCESS) {
        // try delete exist dst file first, see posix rename
        int32 err_code = cm_get_error_code();
        if (err_code == ERR_DSS_FILE_RENAME_EXIST) {
            cm_reset_error();
            ret = dss_remove_file(session, dst);
        }
        if (ret == CM_SUCCESS) {
            ret = dss_rename_file(session, src, dst);
        }
    }
    return ret;
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

    LOG_RUN_INF("The client has connected, pid:%llu, process name:%s.st_time:%lld", session->cli_info.cli_pid,
        session->cli_info.process_name, session->cli_info.start_time);

    session->send_info.str = dss_init_sendinfo_buf(session->recv_pack.init_buf);
    *(uint32 *)session->send_info.str = session->id;
    session->send_info.len = sizeof(uint32);
    return CM_SUCCESS;
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
    if (!cm_fetch_rtext(&text, '/', '\0', &sub)) {
        LOG_DEBUG_ERR("not a complete absolute path name(%s %s)", T2S(&sub), T2S(&text));
        return CM_ERROR;
    }

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
    uint32 res_len = 0;
    session->send_info.str = dss_init_sendinfo_buf(session->recv_pack.init_buf);

    dss_init_get(&session->recv_pack);
    DSS_RETURN_IF_ERROR(dss_get_str(&session->recv_pack, &link_path));
    DSS_RETURN_IF_ERROR(dss_set_audit_resource(session->audit_info.resource, DSS_AUDIT_QUERY, "%s", link_path));
    DSS_RETURN_IF_ERROR(dss_read_link(session, link_path, session->send_info.str, &res_len));

    session->send_info.len = res_len;
    return CM_SUCCESS;
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

    session->send_info.str = dss_init_sendinfo_buf(session->recv_pack.init_buf);
    session->send_info.len = sizeof(dss_find_node_t);
    dss_find_node_t find_node;
    find_node.ftid = ftid;
    errno_t err = strncpy_sp(find_node.vg_name, DSS_MAX_NAME_LEN, vg_item->vg_name, DSS_MAX_NAME_LEN);
    if (err != EOK) {
        DSS_THROW_ERROR(ERR_SYSTEM_CALL, err);
        return CM_ERROR;
    }
    err = memcpy_sp(session->send_info.str, sizeof(dss_find_node_t), (char *)&find_node, sizeof(dss_find_node_t));
    if (err != EOK) {
        DSS_THROW_ERROR(ERR_SYSTEM_CALL, err);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static status_t dss_process_set_status(dss_session_t *session)
{
    int32 dss_status;
    dss_init_get(&session->recv_pack);
    DSS_RETURN_IF_ERROR(dss_get_int32(&session->recv_pack, &dss_status));
    DSS_RETURN_IF_ERROR(dss_set_audit_resource(session->audit_info.resource, DSS_AUDIT_MODIFY, "%u", session->id));
    LOG_DEBUG_INF("dss server current status(%d), set status(%d).", dss_get_server_status_flag(), dss_status);
    if ((dss_status == DSS_STATUS_READWRITE) && !dss_is_readwrite()) {
        status_t status = dss_refresh_meta_info(session);
        if (status != CM_SUCCESS) {
            LOG_DEBUG_ERR("dss server set status(%d) refresh meta fialed, result(%d).", dss_status, status);
            return status;
        }
    }
    LOG_DEBUG_INF("Dss set server status %d.", dss_status);
    dss_set_server_status_flag(dss_status);
    return CM_SUCCESS;
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
    session->send_info.str = dss_init_sendinfo_buf(session->recv_pack.init_buf);
    uint32_t len = DSS_MAX_PACKET_SIZE - sizeof(dss_packet_head_t) - sizeof(int32) - sizeof(uint32);
    int32 ret = snprintf_s(session->send_info.str + sizeof(uint32), len, len - 1, "%s", value);
    DSS_SECUREC_SS_RETURN_IF_ERROR(ret, CM_ERROR);
    session->send_info.len = (uint32)ret + sizeof(uint32);
    DSS_LOG_DEBUG_OP("Server value is %s, when get cfg.", session->send_info.str);
    return CM_SUCCESS;
}

static status_t dss_process_stop_server(dss_session_t *session)
{
    dss_init_get(&session->recv_pack);
    DSS_RETURN_IF_ERROR(dss_set_audit_resource(session->audit_info.resource, DSS_AUDIT_MODIFY, "%u", session->id));
    g_dss_instance.abort_status = CM_TRUE;

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
    { DSS_CMD_TRUNCATE_FILE, dss_process_truncate_file, NULL, CM_FALSE },
    { DSS_CMD_REFRESH_FILE_TABLE, dss_process_refresh_file_table, NULL, CM_FALSE },
    { DSS_CMD_CONSOLE, NULL, NULL, CM_FALSE },
    { DSS_CMD_ADD_VOLUME, dss_process_add_volume, NULL, CM_TRUE },
    { DSS_CMD_REMOVE_VOLUME, dss_process_remove_volume, NULL, CM_TRUE },
    { DSS_CMD_REFRESH_VOLUME, dss_process_refresh_volume, NULL, CM_FALSE },
    { DSS_CMD_REGH, dss_process_register_host, NULL, CM_FALSE },
    { DSS_CMD_KICKH, dss_process_kick_host, NULL, CM_FALSE },
    { DSS_CMD_UNREGH, dss_process_unregister_host, NULL, CM_FALSE },
    { DSS_CMD_LOAD_CTRL, dss_process_loadctrl, NULL, CM_FALSE },
    { DSS_CMD_SET_SESSIONID, dss_process_set_sessionid, NULL, CM_FALSE },
    { DSS_CMD_UPDATE_WRITTEN_SIZE, dss_process_update_file_written_size, NULL, CM_TRUE },
    { DSS_CMD_STOP_SERVER, dss_process_stop_server, NULL, CM_FALSE },
    { DSS_CMD_SETCFG, dss_process_setcfg, NULL, CM_FALSE },
    { DSS_CMD_SET_STATUS, dss_process_set_status, NULL, CM_FALSE },
    { DSS_CMD_SYMLINK, dss_process_symlink, NULL, CM_TRUE },
    { DSS_CMD_UNLINK, dss_process_unlink, NULL, CM_TRUE },
    // query
    { DSS_CMD_GET_HOME, dss_process_get_home, NULL, CM_FALSE },
    { DSS_CMD_EXIST_FILE, dss_process_exist, NULL, CM_FALSE },
    { DSS_CMD_EXIST_DIR, dss_process_exist_dir, NULL, CM_FALSE },
    { DSS_CMD_ISLINK, dss_process_islink, NULL, CM_FALSE },
    { DSS_CMD_READLINK, dss_process_readlink, NULL, CM_FALSE },
    { DSS_CMD_GET_FTID_BY_PATH, dss_process_get_ftid_by_path, NULL, CM_FALSE },
    { DSS_CMD_GETCFG, dss_process_getcfg, NULL, CM_FALSE },
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
    session->send_info.len = 0;
    DSS_LOG_DEBUG_OP("Receive command:%d.", session->recv_pack.head->cmd);

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
    sql_record_audit_log(session, status, session->recv_pack.head->cmd);
    return status;
}

status_t dss_process_command(dss_session_t *session)
{
    status_t status = CM_SUCCESS;
    bool32 ready = CM_FALSE;

    cm_reset_error();
    if (cs_wait(&session->pipe, CS_WAIT_FOR_READ, session->pipe.socket_timeout, &ready) != CM_SUCCESS) {
        session->is_closed = CM_TRUE;
        return CM_ERROR;
    }

    if (ready == CM_FALSE) {
        return CM_SUCCESS;
    }

    status = dss_read(&session->pipe, &session->recv_pack, CM_FALSE);
    if (status != CM_SUCCESS) {
        LOG_RUN_ERR("Failed to read message sent by %s.", session->cli_info.process_name);
        session->is_closed = CM_TRUE;
        return CM_ERROR;
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
    if (dss_is_readonly() == CM_TRUE) {
        dss_config_t *cfg = dss_get_inst_cfg();
        uint32 id = (uint32)(cfg->params.inst_id);
        LOG_RUN_ERR("The local node(%u) is in readonly state and cannot execute remote requests.", id);
        return CM_ERROR;
    }

    return dss_exec_cmd(session, CM_FALSE);
}
