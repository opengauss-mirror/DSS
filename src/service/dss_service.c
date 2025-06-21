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

#include "dss_service.h"
#include "cm_system.h"
#include "dss_instance.h"
#include "dss_io_fence.h"
#include "dss_malloc.h"
#include "dss_open_file.h"
#include "dss_srv_proc.h"
#include "dss_mes.h"
#include "dss_api.h"
#include "dss_thv.h"
#include "dss_hp_interface.h"

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

static uint32 dss_get_master_proto_ver(void)
{
    uint32 master_id = dss_get_master_id();
    if (master_id >= DSS_MAX_INSTANCES) {
        return DSS_PROTO_VERSION;
    }
    uint32 master_proto_ver = (uint32)cm_atomic32_get((atomic32_t *)&g_dss_instance.cluster_proto_vers[master_id]);
    if (master_proto_ver == DSS_INVALID_VERSION) {
        return DSS_PROTO_VERSION;
    }
    master_proto_ver = MIN(master_proto_ver, DSS_PROTO_VERSION);
    return master_proto_ver;
}

status_t dss_get_exec_nodeid(dss_session_t *session, uint32 *currid, uint32 *remoteid)
{
    dss_config_t *cfg = dss_get_inst_cfg();
    *currid = (uint32)(cfg->params.inst_id);
    *remoteid = dss_get_master_id();
    while (*remoteid == DSS_INVALID_ID32) {
        if (get_instance_status_proc() == DSS_STATUS_RECOVERY) {
            DSS_THROW_ERROR(ERR_DSS_RECOVER_CAUSE_BREAK);
            LOG_RUN_ERR_INHIBIT(LOG_INHIBIT_LEVEL1, "Master id is invalid.");
            return CM_ERROR;
        }
        *remoteid = dss_get_master_id();
        cm_sleep(DSS_PROCESS_GET_MASTER_ID);
    }
    LOG_DEBUG_INF("Start processing remote requests(%d), remote node(%u),current node(%u).",
        (session->recv_pack.head == NULL) ? -1 : session->recv_pack.head->cmd, *remoteid, *currid);
    return CM_SUCCESS;
}

#define DSS_PROCESS_REMOTE_INTERVAL 50
static status_t dss_process_remote(dss_session_t *session)
{
    uint32 remoteid = DSS_INVALID_ID32;
    uint32 currid = DSS_INVALID_ID32;
    status_t ret = CM_ERROR;
    DSS_RETURN_IF_ERROR(dss_get_exec_nodeid(session, &currid, &remoteid));

    LOG_DEBUG_INF("Start processing remote requests(%d), remote node(%u),current node(%u).",
        session->recv_pack.head->cmd, remoteid, currid);
    status_t remote_result = CM_ERROR;
    while (CM_TRUE) {
        if (get_instance_status_proc() == DSS_STATUS_RECOVERY) {
            DSS_THROW_ERROR(ERR_DSS_RECOVER_CAUSE_BREAK);
            LOG_RUN_INF("Req break by recovery");
            return CM_ERROR;
        }

        ret = dss_exec_sync(session, remoteid, currid, &remote_result);
        if (ret != CM_SUCCESS) {
            LOG_DEBUG_ERR(
                "End of processing the remote request(%d) failed, remote node(%u),current node(%u), result code(%d).",
                session->recv_pack.head->cmd, remoteid, currid, ret);
            if (session->recv_pack.head->cmd == DSS_CMD_SWITCH_LOCK) {
                return ret;
            }
            cm_sleep(DSS_PROCESS_REMOTE_INTERVAL);
            DSS_RETURN_IF_ERROR(dss_get_exec_nodeid(session, &currid, &remoteid));
            if (currid == remoteid) {
                DSS_THROW_ERROR(ERR_DSS_MASTER_CHANGE);
                LOG_RUN_INF("Req break if currid is equal to remoteid, just try again.");
                return CM_ERROR;
            }
            continue;
        }
        break;
    }
    LOG_DEBUG_INF("The remote request(%d) is processed successfully, remote node(%u),current node(%u), result(%u).",
        session->recv_pack.head->cmd, remoteid, currid, remote_result);
    return remote_result;
}

status_t dss_diag_proto_type(dss_session_t *session)
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

static void dss_clean_session_hotpatch_latch(dss_session_t *session)
{
    if (session->is_holding_hotpatch_latch) {
        LOG_DEBUG_INF("Clean sid:%u is holding hotpatch latch, now clean it.", session->id);
        dss_hp_unlatch(session->id);
        session->is_holding_hotpatch_latch = CM_FALSE;
    }
}

void dss_release_session_res(dss_session_t *session)
{
    dss_server_session_lock(session);
    dss_clean_session_latch(session, CM_FALSE);
    dss_clean_session_hotpatch_latch(session);
    dss_clean_open_files(session);
    dss_destroy_session_inner(session);
    cm_spin_unlock(&session->shm_lock);
    LOG_DEBUG_INF("Succeed to unlock session %u shm lock", session->id);
    cm_spin_unlock(&session->lock);
}

status_t dss_process_single_cmd(dss_session_t **session)
{
    status_t status = dss_process_command(*session);
    if ((*session)->is_closed) {
        LOG_RUN_INF("Session:%u end to do service, thread id is %u, connect time is %llu, try to clean source.",
            (*session)->id, (*session)->cli_info.thread_id, (*session)->cli_info.connect_time);
        dss_clean_reactor_session(*session);
        *session = NULL;
    } else {
        dss_session_detach_workthread(*session);
    }
    return status;
}

static void dss_return_error(dss_session_t *session)
{
    int32 code;
    const char *message = NULL;
    dss_packet_t *send_pack = NULL;

    CM_ASSERT(session != NULL);
    send_pack = &session->send_pack;
    dss_init_set(send_pack, session->proto_version);
    send_pack->head->cmd = session->recv_pack.head->cmd;
    send_pack->head->result = (uint8)CM_ERROR;
    send_pack->head->flags = 0;
    cm_get_error(&code, &message);
    // volume open/seek/read write fail for I/O, just abort
    if (code == ERR_DSS_VOLUME_SYSTEM_IO) {
        LOG_RUN_ERR("[DSS] ABORT INFO: volume operate failed for I/O ERROR, errcode:%d.", code);
        cm_fync_logfile();
        dss_exit(1);
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
    dss_set_version(send_pack, session->proto_version);
    dss_set_client_version(send_pack, session->client_version);

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
        vsnprintf_s(resource, (size_t)DSS_MAX_AUDIT_PATH_LENGTH, (size_t)(DSS_MAX_AUDIT_PATH_LENGTH - 1), format, args);
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
    DSS_LOG_DEBUG_OP("Begin to mkdir:%s, in path:%s", dir, parent);
    status_t status = dss_make_dir(session, (const char *)parent, (const char *)dir);
    if (status == CM_SUCCESS) {
        LOG_DEBUG_INF("Succeed to mkdir:%s in path:%s", dir, parent);
        return status;
    }
    LOG_DEBUG_ERR("Failed to mkdir:%s in path:%s", dir, parent);
    return status;
}

static status_t dss_process_rmdir(dss_session_t *session)
{
    char *dir = NULL;
    int32 recursive = 0;
    dss_init_get(&session->recv_pack);
    DSS_RETURN_IF_ERROR(dss_get_str(&session->recv_pack, &dir));
    DSS_RETURN_IF_ERROR(dss_get_int32(&session->recv_pack, &recursive));
    DSS_RETURN_IF_ERROR(dss_set_audit_resource(session->audit_info.resource, DSS_AUDIT_MODIFY, "%s", dir));
    DSS_LOG_DEBUG_OP("Begin to rmdir:%s.", dir);
    status_t status = dss_remove_dir(session, (const char *)dir, (bool32)recursive);
    if (status == CM_SUCCESS) {
        LOG_DEBUG_INF("Succeed to rmdir:%s", dir);
        return status;
    }
    LOG_DEBUG_ERR("Failed to rmdir:%s", dir);
    return status;
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

    DSS_LOG_DEBUG_OP("Begin to create file:%s in path:%s.", name_str, parent_str);
    status_t status = dss_create_file(session, (const char *)parent_str, (const char *)name_str, flag);
    if (status == CM_SUCCESS) {
        LOG_DEBUG_INF("Succeed to create file:%s in path:%s", name_str, parent_str);
        return status;
    }
    LOG_DEBUG_ERR("Failed to create file:%s in path:%s", name_str, parent_str);
    return status;
}

static status_t dss_process_delete_file(dss_session_t *session)
{
    char *name = NULL;
    dss_init_get(&session->recv_pack);
    status_t status = dss_get_str(&session->recv_pack, &name);
    DSS_RETURN_IFERR2(status, LOG_DEBUG_ERR("delete file get file name failed."));
    DSS_RETURN_IF_ERROR(dss_set_audit_resource(session->audit_info.resource, DSS_AUDIT_MODIFY, "%s", name));
    DSS_LOG_DEBUG_OP("Begin to rm file:%s", name);
    status = dss_remove_file(session, (const char *)name);
    if (status == CM_SUCCESS) {
        LOG_DEBUG_INF("Succeed to rm file:%s", name);
        return status;
    }
    LOG_DEBUG_ERR("Failed to rm file:%s", name);
    return status;
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
    dss_find_node_t find_info;
    status_t status = dss_open_file(session, (const char *)name, flag, &find_info);
    if (status == CM_SUCCESS) {
        DSS_RETURN_IF_ERROR(dss_put_data(&session->send_pack, &find_info, sizeof(dss_find_node_t)));
    }
    return status;
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

    DSS_LOG_DEBUG_OP("Begin to close file, fid:%llu, %s", fid, dss_display_metaid(ftid));
    DSS_RETURN_IF_ERROR(dss_close_file(session, vg_item, *(uint64 *)&ftid));
    LOG_DEBUG_INF("Succeed to close file, ftid:%s, fid:%llu, vg: %s, session pid:%llu.", dss_display_metaid(ftid), fid,
        vg_item->vg_name, session->cli_info.cli_pid);
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
    dss_find_node_t find_info;
    DSS_LOG_DEBUG_OP("Begin to open dir:%s, is_refresh:%d", name, refresh_recursive);
    status_t status = dss_open_dir(session, (const char *)name, (bool32)refresh_recursive, &find_info);
    if (status == CM_SUCCESS) {
        DSS_RETURN_IF_ERROR(dss_put_data(&session->send_pack, &find_info, sizeof(dss_find_node_t)));
        LOG_DEBUG_INF("Succeed to open dir:%s, ftid: %s", name, dss_display_metaid(find_info.ftid));
        return status;
    }
    LOG_DEBUG_ERR("Failed to open dir:%s", name);
    return status;
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
    DSS_LOG_DEBUG_OP("Begin to close dir, ftid:%llu, vg:%s.", ftid, vg_name);
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
    DSS_RETURN_IF_ERROR(dss_get_int64(&session->recv_pack, &node_data.size));
    DSS_RETURN_IF_ERROR(dss_get_str(&session->recv_pack, &node_data.vg_name));
    DSS_RETURN_IF_ERROR(dss_get_int32(&session->recv_pack, (int32 *)&node_data.vgid));
    DSS_RETURN_IF_ERROR(dss_set_audit_resource(session->audit_info.resource, DSS_AUDIT_MODIFY,
        "extend vg_name:%s, fid:%llu, ftid:%llu, offset:%lld, size:%lld", node_data.vg_name, node_data.fid,
        *(uint64 *)&node_data.ftid, node_data.offset, node_data.size));

    return dss_extend(session, &node_data);
}

static status_t dss_process_fallocate_file(dss_session_t *session)
{
    dss_node_data_t node_data;

    dss_init_get(&session->recv_pack);
    DSS_RETURN_IF_ERROR(dss_get_int64(&session->recv_pack, (int64 *)&node_data.fid));
    DSS_RETURN_IF_ERROR(dss_get_int64(&session->recv_pack, (int64 *)&node_data.ftid));
    DSS_RETURN_IF_ERROR(dss_get_int64(&session->recv_pack, &node_data.offset));
    DSS_RETURN_IF_ERROR(dss_get_int64(&session->recv_pack, &node_data.size));
    DSS_RETURN_IF_ERROR(dss_get_int32(&session->recv_pack, (int32 *)&node_data.vgid));
    DSS_RETURN_IF_ERROR(dss_get_int32(&session->recv_pack, (int32 *)&node_data.mode));
    DSS_RETURN_IF_ERROR(dss_set_audit_resource(session->audit_info.resource, DSS_AUDIT_MODIFY,
        "fallocate vg_id:%u, fid:%llu, ftid:%llu, offset:%lld, size:%lld, mode:%d", node_data.vgid, node_data.fid,
        *(uint64 *)&node_data.ftid, node_data.offset, node_data.size, node_data.mode));

    LOG_DEBUG_INF("fallocate vg_id:%u, fid:%llu, ftid:%llu, offset:%lld, size:%lld, mode:%d", node_data.vgid,
        node_data.fid, *(uint64 *)&node_data.ftid, node_data.offset, node_data.size, node_data.mode);

    return dss_do_fallocate(session, &node_data);
}

static status_t dss_process_truncate_file(dss_session_t *session)
{
    uint64 fid;
    ftid_t ftid;
    int64 length;
    uint32 vgid;
    char *vg_name = NULL;

    dss_init_get(&session->recv_pack);
    DSS_RETURN_IF_ERROR(dss_get_int64(&session->recv_pack, (int64 *)&fid));
    DSS_RETURN_IF_ERROR(dss_get_int64(&session->recv_pack, (int64 *)&ftid));
    DSS_RETURN_IF_ERROR(dss_get_int64(&session->recv_pack, (int64 *)&length));
    DSS_RETURN_IF_ERROR(dss_get_str(&session->recv_pack, &vg_name));
    DSS_RETURN_IF_ERROR(dss_get_int32(&session->recv_pack, (int32 *)&vgid));
    DSS_RETURN_IF_ERROR(dss_set_audit_resource(session->audit_info.resource, DSS_AUDIT_MODIFY,
        "vg_name:%s, fid:%llu, ftid:%llu, length:%lld", vg_name, fid, *(uint64 *)&ftid, length));
    LOG_DEBUG_INF("Truncate file ft id:%llu, length:%lld", *(uint64 *)&ftid, length);
    return dss_truncate(session, fid, ftid, length, vg_name);
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
    int64 offset;

    dss_init_get(&session->recv_pack);
    DSS_RETURN_IF_ERROR(dss_get_int64(&session->recv_pack, (int64 *)&fid));
    DSS_RETURN_IF_ERROR(dss_get_int64(&session->recv_pack, (int64 *)&ftid));
    char *name_str = NULL;
    DSS_RETURN_IF_ERROR(dss_get_str(&session->recv_pack, &name_str));
    DSS_RETURN_IF_ERROR(dss_get_int32(&session->recv_pack, (int32 *)&vgid));
    DSS_RETURN_IF_ERROR(dss_get_int64(&session->recv_pack, (int64 *)&offset));
    DSS_RETURN_IF_ERROR(dss_set_audit_resource(session->audit_info.resource, DSS_AUDIT_MODIFY,
        "vg_name:%s, offset:%lld, fid:%llu, ftid:%llu", name_str, offset, fid, *(uint64 *)&ftid));

    return dss_refresh_file(session, fid, ftid, name_str, offset);
}

static status_t dss_process_handshake(dss_session_t *session)
{
    dss_init_get(&session->recv_pack);
    session->client_version = dss_get_version(&session->recv_pack);
    uint32 current_proto_ver = dss_get_master_proto_ver();
    session->proto_version = MIN(session->client_version, current_proto_ver);
    dss_cli_info_t *cli_info;
    DSS_RETURN_IF_ERROR(dss_get_data(&session->recv_pack, sizeof(dss_cli_info_t), (void **)&cli_info));
    errno_t errcode;
    cm_spin_lock(&session->lock, NULL);
    errcode = memcpy_s(&session->cli_info, sizeof(dss_cli_info_t), cli_info, sizeof(dss_cli_info_t));
    cm_spin_unlock(&session->lock);
    securec_check_ret(errcode);
    LOG_RUN_INF(
        "[DSS_CONNECT]The client has connected, session id:%u, pid:%llu, process name:%s.st_time:%lld, objectid:%u",
        session->id, session->cli_info.cli_pid, session->cli_info.process_name, session->cli_info.start_time,
        session->objectid);
    char *server_home = dss_get_cfg_dir(ZFS_CFG);
    DSS_RETURN_IF_ERROR(dss_set_audit_resource(session->audit_info.resource, DSS_AUDIT_QUERY, "%s", server_home));
    LOG_RUN_INF("[DSS_CONNECT]Server home is %s, when get home.", server_home);
    uint32 server_pid = getpid();
    text_t data;
    cm_str2text(server_home, &data);
    data.len++;  // for keeping the '\0'
    DSS_RETURN_IF_ERROR(dss_put_text(&session->send_pack, &data));
    DSS_RETURN_IF_ERROR(dss_put_int32(&session->send_pack, session->objectid));
    if (session->proto_version >= DSS_VERSION_2) {
        DSS_RETURN_IF_ERROR(dss_put_int32(&session->send_pack, server_pid));
    }
    return CM_SUCCESS;
}

static status_t dss_process_refresh_volume(dss_session_t *session)
{
    uint32 volumeid;
    uint32 vgid;
    bool32 is_force = CM_FALSE;
    dss_init_get(&session->recv_pack);
    DSS_RETURN_IF_ERROR(dss_get_int32(&session->recv_pack, (int32 *)&volumeid));
    
#ifdef OPENGAUSS
    if (volumeid == CM_INVALID_ID32) {
        is_force = true;
    }
#endif

    if (volumeid >= DSS_MAX_VOLUMES && !is_force) {
        LOG_DEBUG_ERR("Volume id:%u overflow.", volumeid);
        return CM_ERROR;
    }
    char *name_str = NULL;
    DSS_RETURN_IF_ERROR(dss_get_str(&session->recv_pack, &name_str));
    DSS_RETURN_IF_ERROR(dss_get_int32(&session->recv_pack, (int32 *)&vgid));
    DSS_RETURN_IF_ERROR(dss_set_audit_resource(
        session->audit_info.resource, DSS_AUDIT_MODIFY, "vg_name:%s, volume_id:%u", name_str, volumeid));

    return dss_refresh_volume(session, name_str, vgid, volumeid, is_force);
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
    if (strlen(text.str) >= DSS_MAX_NAME_LEN) {
        DSS_THROW_ERROR(ERR_DSS_LINK_CREATE, "the length of name is too long");
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
    char name[DSS_FILE_PATH_MAX_LENGTH];
    uint32 res_len = 0;

    dss_init_get(&session->recv_pack);
    DSS_RETURN_IF_ERROR(dss_get_str(&session->recv_pack, &link_path));
    DSS_RETURN_IF_ERROR(dss_set_audit_resource(session->audit_info.resource, DSS_AUDIT_QUERY, "%s", link_path));
    DSS_RETURN_IF_ERROR(dss_read_link(session, link_path, name, &res_len));
    DSS_LOG_DEBUG_OP("Link is %s, when read link.", name);
    text_t data;
    cm_str2text(name, &data);
    data.len++;  // for keeping the '\0'
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
    uint64 fid;
    int64 offset;
    int64 size;
    dss_block_id_t ftid;
    uint32 vg_id;

    dss_init_get(&session->recv_pack);
    DSS_RETURN_IF_ERROR(dss_get_int64(&session->recv_pack, (int64 *)&fid));
    DSS_RETURN_IF_ERROR(dss_get_int64(&session->recv_pack, (int64 *)&ftid));
    DSS_RETURN_IF_ERROR(dss_get_int32(&session->recv_pack, (int32 *)&vg_id));
    DSS_RETURN_IF_ERROR(dss_get_int64(&session->recv_pack, (int64 *)&offset));
    DSS_RETURN_IF_ERROR(dss_get_int64(&session->recv_pack, (int64 *)&size));
    DSS_RETURN_IF_ERROR(dss_set_audit_resource(session->audit_info.resource, DSS_AUDIT_MODIFY,
        "vg_id:%u, fid:%llu, ftid:%llu, offset:%lld, size:%lld", vg_id, fid, *(uint64 *)&ftid, offset, size));
    return dss_update_file_written_size(session, vg_id, offset, size, ftid, fid);
}

static status_t dss_process_get_ftid_by_path(dss_session_t *session)
{
    char *path = NULL;
    ftid_t ftid;
    dss_vg_info_item_t *vg_item = NULL;
    dss_init_get(&session->recv_pack);
    DSS_RETURN_IF_ERROR(dss_get_str(&session->recv_pack, &path));
    DSS_RETURN_IF_ERROR(dss_set_audit_resource(session->audit_info.resource, DSS_AUDIT_QUERY, "%s", path));
    DSS_RETURN_IF_ERROR(dss_get_ftid_by_path(session, path, &ftid, &vg_item));

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
    dss_status->is_maintain = g_dss_instance.is_maintain;
    char *dss_instance_status = dss_get_dss_instance_status(dss_status->instance_status_id);
    errno_t errcode = strcpy_s(dss_status->instance_status, DSS_MAX_STATUS_LEN, dss_instance_status);
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
    uint64 size = sizeof(dss_stat_item_t) * DSS_EVT_COUNT;
    dss_stat_item_t *time_stat = NULL;
    DSS_RETURN_IF_ERROR(dss_reserv_text_buf(&session->send_pack, (uint32)size, (char **)&time_stat));

    errno_t errcode = memset_s(time_stat, (size_t)size, 0, (size_t)size);
    securec_check_ret(errcode);
    dss_session_ctrl_t *session_ctrl = dss_get_session_ctrl();
    dss_session_t *tmp_session = NULL;
    cm_spin_lock(&session_ctrl->lock, NULL);
    for (uint32 i = 0; i < session_ctrl->alloc_sessions; i++) {
        tmp_session = session_ctrl->sessions[i];
        if (tmp_session->is_used && !tmp_session->is_closed) {
            for (uint32 j = 0; j < DSS_EVT_COUNT; j++) {
                int64 count = (int64)tmp_session->dss_session_stat[j].wait_count;
                int64 total_time = (int64)tmp_session->dss_session_stat[j].total_wait_time;
                int64 max_sgl_time = (int64)tmp_session->dss_session_stat[j].max_single_time;

                time_stat[j].wait_count += count;
                time_stat[j].total_wait_time += total_time;
                time_stat[j].max_single_time = (atomic_t)MAX((int64)time_stat[j].max_single_time, max_sgl_time);

                (void)cm_atomic_add(&tmp_session->dss_session_stat[j].wait_count, -count);
                (void)cm_atomic_add(&tmp_session->dss_session_stat[j].total_wait_time, -total_time);
                (void)cm_atomic_cas(&tmp_session->dss_session_stat[j].max_single_time, max_sgl_time, 0);
            }
        }
    }
    cm_spin_unlock(&session_ctrl->lock);

    return CM_SUCCESS;
}

static status_t dss_process_hotpatch_inner(dss_session_t *session)
{
    int32 operation;
    dss_init_get(&session->recv_pack);
    DSS_RETURN_IF_ERROR(dss_get_int32(&session->recv_pack, &operation));
    char *patch_path = NULL;
    switch ((dss_hp_operation_cmd_e)operation) {
        case DSS_HP_OP_LOAD:
            DSS_RETURN_IF_ERROR(dss_get_str(&session->recv_pack, &patch_path));
            DSS_RETURN_IF_ERROR(dss_set_audit_resource(
                session->audit_info.resource, DSS_AUDIT_MODIFY, "%s %s", DSS_HP_OPERATION_LOAD, patch_path));
            DSS_RETURN_IF_ERROR(dss_hp_load(patch_path));
            break;
        case DSS_HP_OP_ACTIVE:
            DSS_RETURN_IF_ERROR(dss_get_str(&session->recv_pack, &patch_path));
            DSS_RETURN_IF_ERROR(dss_set_audit_resource(
                session->audit_info.resource, DSS_AUDIT_MODIFY, "%s %s", DSS_HP_OPERATION_ACTIVE, patch_path));
            DSS_RETURN_IF_ERROR(dss_hp_active(patch_path));
            break;
        case DSS_HP_OP_DEACTIVE:
            DSS_RETURN_IF_ERROR(dss_get_str(&session->recv_pack, &patch_path));
            DSS_RETURN_IF_ERROR(dss_set_audit_resource(
                session->audit_info.resource, DSS_AUDIT_MODIFY, "%s %s", DSS_HP_OPERATION_DEACTIVE, patch_path));
            DSS_RETURN_IF_ERROR(dss_hp_deactive(patch_path));
            break;
        case DSS_HP_OP_UNLOAD:
            DSS_RETURN_IF_ERROR(dss_get_str(&session->recv_pack, &patch_path));
            DSS_RETURN_IF_ERROR(dss_set_audit_resource(
                session->audit_info.resource, DSS_AUDIT_MODIFY, "%s %s", DSS_HP_OPERATION_UNLOAD, patch_path));
            DSS_RETURN_IF_ERROR(dss_hp_unload(patch_path));
            break;
        case DSS_HP_OP_REFRESH:
            DSS_RETURN_IF_ERROR(
                dss_set_audit_resource(session->audit_info.resource, DSS_AUDIT_MODIFY, "%s", DSS_HP_OPERATION_REFRESH));
            DSS_RETURN_IF_ERROR(dss_hp_refresh_patch_info());
            break;
        case DSS_HP_OP_INVALID:
        default:
            DSS_THROW_ERROR(ERR_INVALID_PARAM, "hotpatch operation");
            LOG_RUN_ERR("[HotPatch] Unsupported hotpatch operation: %u", operation);
            DSS_RETURN_IF_ERROR(
                dss_set_audit_resource(session->audit_info.resource, DSS_AUDIT_MODIFY, "invalid op:%d", operation));
            return CM_ERROR;
    }
    return CM_SUCCESS;
}

static status_t dss_process_hotpatch(dss_session_t *session)
{
    if (dss_hp_check_is_inited() != CM_SUCCESS) {
        DSS_RETURN_IF_ERROR(
            dss_set_audit_resource(session->audit_info.resource, DSS_AUDIT_MODIFY, "hotpatch not supported"));
        return CM_ERROR;
    }
    dss_hp_latch_x(session->id);
    session->is_holding_hotpatch_latch = CM_TRUE;
    status_t ret = dss_process_hotpatch_inner(session);
    dss_hp_unlatch(session->id);
    session->is_holding_hotpatch_latch = CM_FALSE;
    return ret;
}

static bool is_buffer_sufficient(dss_packet_t *pack, const dss_hp_info_view_row_t *hp_info_view_row)
{
    size_t estimated_size = sizeof(uint32) + CM_ALIGN4(strlen(hp_info_view_row->patch_name) + 1) + sizeof(uint32) +
                            CM_ALIGN4(strlen(hp_info_view_row->patch_lib_state) + 1) +
                            CM_ALIGN4(strlen(hp_info_view_row->patch_commit) + 1) +
                            CM_ALIGN4(strlen(hp_info_view_row->patch_bin_version) + 1);
    return (uint32)estimated_size <= DSS_REMAIN_SIZE(pack);
}

static status_t put_hotpatch_info(dss_packet_t *pack, const dss_hp_info_view_row_t *hp_info_view_row)
{
    DSS_RETURN_IF_ERROR(dss_put_int32(pack, hp_info_view_row->patch_number));
    DSS_RETURN_IF_ERROR(dss_put_str(pack, hp_info_view_row->patch_name));
    DSS_RETURN_IF_ERROR(dss_put_int32(pack, (uint32)hp_info_view_row->patch_state));
    DSS_RETURN_IF_ERROR(dss_put_str(pack, hp_info_view_row->patch_lib_state));
    DSS_RETURN_IF_ERROR(dss_put_str(pack, hp_info_view_row->patch_commit));
    DSS_RETURN_IF_ERROR(dss_put_str(pack, hp_info_view_row->patch_bin_version));
    return CM_SUCCESS;
}

static status_t dss_process_query_hotpatch_inner(dss_session_t *session, uint32 start_patch_number, bool32 *is_finished)
{
    uint32 total_count;
    bool32 is_same_version = CM_FALSE;
    *is_finished = CM_FALSE;
    DSS_RETURN_IF_ERROR(dss_hp_get_patch_count(&total_count, &is_same_version));
    // 1. total_count
    DSS_RETURN_IF_ERROR(dss_put_int32(&session->send_pack, total_count));
    uint32 *cur_batch_count_loc =
        (uint32 *)(DSS_WRITE_ADDR(&session->send_pack));  // keep the location of cur_batch_count
    uint32 cur_batch_count = 0;
    // 2. cur_batch_count
    // For now just occupy the place, value would be modified later.
    DSS_RETURN_IF_ERROR(dss_put_int32(&session->send_pack, cur_batch_count));
    // 3. hotpatch info
    for (uint32 patch_number = start_patch_number; patch_number <= total_count; ++patch_number) {
        dss_hp_info_view_row_t hp_info_view_row;
        DSS_RETURN_IF_ERROR(dss_hp_get_patch_info_row(patch_number, &hp_info_view_row));
        // Before putting, verify the remaining buffer space.
        if (!is_buffer_sufficient(&session->send_pack, &hp_info_view_row)) {
            LOG_RUN_INF("[HotPatch] Buffer insufficient for %dth patch.", patch_number);
            break;
        }
        DSS_RETURN_IF_ERROR(put_hotpatch_info(&session->send_pack, &hp_info_view_row));
        ++cur_batch_count;
    }
    // Modify cur_batch_count to its actual value.
    *cur_batch_count_loc = cur_batch_count;
    // start_patch_number starts from 1, not zero. So when finished, start_patch_number + cur_batch_count - 1 =
    // total_count.
    if (start_patch_number + cur_batch_count > total_count) {
        *is_finished = CM_TRUE;  // Tell the caller to release the latch.
    }
    return CM_SUCCESS;
}

static status_t dss_process_query_hotpatch(dss_session_t *session)
{
    if (dss_hp_check_is_inited() != CM_SUCCESS) {
        DSS_RETURN_IF_ERROR(
            dss_set_audit_resource(session->audit_info.resource, DSS_AUDIT_QUERY, "hotpatch not supported"));
        return CM_ERROR;
    }
    dss_init_get(&session->recv_pack);
    int start_patch_number;
    DSS_RETURN_IF_ERROR(dss_get_int32(&session->recv_pack, &start_patch_number));
    DSS_RETURN_IF_ERROR(dss_set_audit_resource(
        session->audit_info.resource, DSS_AUDIT_QUERY, "start_patch_number: %u", start_patch_number));
    if (start_patch_number == 1) {
        dss_hp_latch_s(session->id);  // Latch only at the first interaction.
        session->is_holding_hotpatch_latch = CM_TRUE;
    }
    bool32 is_finished;
    status_t ret = dss_process_query_hotpatch_inner(session, (uint32)start_patch_number, &is_finished);
    // Hotpatch info may be too many to be transmitted to client in one message.
    // So one message would carry only some of them and client may query multiple times.
    // If transmission not finished in this interaction, dsscmd would not disconnect the session.
    // Thus, the latch should be kept and wait to be released by foillowing query.
    if (ret != CM_SUCCESS || is_finished == CM_TRUE) {
        dss_hp_unlatch(session->id);
        session->is_holding_hotpatch_latch = CM_FALSE;
    }
    return ret;
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

void dss_wait_background_pause(dss_instance_t *inst)
{
    LOG_DEBUG_INF("Begin to set background paused.");
    while (inst->is_cleaning || inst->is_checking) {
        cm_sleep(1);
    }
    LOG_DEBUG_INF("Succeed to pause background task.");
}

void dss_set_session_running(dss_instance_t *inst, uint32 sid)
{
    LOG_DEBUG_INF("Begin to set session running.");
    cm_latch_x(&inst->uds_lsnr_latch, sid, NULL);
    if (inst->abort_status) {
        LOG_RUN_INF("dssserver is aborting, no need to set sessions running.");
        cm_unlatch(&inst->uds_lsnr_latch, NULL);
        return;
    }
    uds_lsnr_t *lsnr = &inst->lsnr;
    dss_continue_reactors();
    lsnr->status = LSNR_STATUS_RUNNING;
    cm_unlatch(&inst->uds_lsnr_latch, NULL);
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
    if (strlen(value) != 0 && cm_str_equal_ins(name, "SSL_PWD_CIPHERTEXT")) {
        DSS_LOG_DEBUG_OP("Server value is ***, when get cfg.");
    } else {
        DSS_LOG_DEBUG_OP("Server value is %s, when get cfg.", value);
    }
    text_t data;
    cm_str2text(value, &data);
    // SSL default value is NULL
    if (value != NULL) {
        data.len++;  // for keeping the '\0'
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
static status_t dss_process_switch_lock_inner(dss_session_t *session, uint32 switch_id)
{
    dss_config_t *inst_cfg = dss_get_inst_cfg();
    uint32 curr_id = (uint32)inst_cfg->params.inst_id;
    uint32 master_id = dss_get_master_id();
    if ((uint32)switch_id == master_id) {
        LOG_RUN_INF("[SWITCH]switchid is equal to current master_id, which is %u.", master_id);
        return CM_SUCCESS;
    }
    if (master_id != curr_id) {
        LOG_RUN_ERR("[SWITCH]current id is %u, just master id %u can do switch lock.", curr_id, master_id);
        return CM_ERROR;
    }
    dss_wait_session_pause(&g_dss_instance);
    g_dss_instance.status = DSS_STATUS_SWITCH;
    dss_wait_background_pause(&g_dss_instance);
    dss_close_delay_clean_background_task(&g_dss_instance);
#ifdef ENABLE_DSSTEST
    dss_set_server_status_flag(DSS_STATUS_READONLY);
    LOG_RUN_INF("[SWITCH]inst %u set status flag %u when trans lock.", curr_id, DSS_STATUS_READONLY);
    dss_set_master_id((uint32)switch_id);
    dss_set_session_running(&g_dss_instance, session->id);
    g_dss_instance.status = DSS_STATUS_OPEN;
#endif
    status_t ret = CM_SUCCESS;
    // trans lock
    if (g_dss_instance.cm_res.is_valid) {
        dss_set_server_status_flag(DSS_STATUS_READONLY);
        LOG_RUN_INF("[SWITCH]inst %u set status flag %u when trans lock.", curr_id, DSS_STATUS_READONLY);
        ret = cm_res_trans_lock(&g_dss_instance.cm_res.mgr, DSS_CM_LOCK, (uint32)switch_id);
        if (ret != CM_SUCCESS) {
            dss_set_session_running(&g_dss_instance, session->id);
            dss_set_server_status_flag(DSS_STATUS_READWRITE);
            LOG_RUN_INF("[SWITCH]inst %u set status flag %u when failed to trans lock.", curr_id, DSS_STATUS_READWRITE);
            g_dss_instance.status = DSS_STATUS_OPEN;
            LOG_RUN_ERR("[SWITCH]cm do switch lock failed from %u to %u.", curr_id, master_id);
            return ret;
        }
        dss_set_master_id((uint32)switch_id);
        dss_set_session_running(&g_dss_instance, session->id);
        g_dss_instance.status = DSS_STATUS_OPEN;
    } else {
        dss_set_session_running(&g_dss_instance, session->id);
        g_dss_instance.status = DSS_STATUS_OPEN;
        LOG_RUN_ERR("[SWITCH]Only with cm can switch lock.");
        return CM_ERROR;
    }
    LOG_RUN_INF(
        "[SWITCH]Old main server %u switch lock to new main server %u successfully.", curr_id, (uint32)switch_id);
    return CM_SUCCESS;
}

static status_t dss_process_switch_lock(dss_session_t *session)
{
    int32 switch_id;
    dss_init_get(&session->recv_pack);
    if (dss_get_int32(&session->recv_pack, &switch_id) != CM_SUCCESS) {
        return CM_ERROR;
    }
    cm_unlatch(&g_dss_instance.switch_latch, LATCH_STAT(LATCH_SWITCH));  // when mes process req, will latch s
    cm_latch_x(&g_dss_instance.switch_latch, session->id, LATCH_STAT(LATCH_SWITCH));
    dss_set_recover_thread_id(dss_get_current_thread_id());
    status_t ret = dss_process_switch_lock_inner(session, (uint32)switch_id);
    dss_set_recover_thread_id(0);
    // no need to unlatch, for dss_process_message will
    return ret;
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
    dss_instance_status_e old_status = g_dss_instance.status;
    g_dss_instance.status = DSS_STATUS_SWITCH;
    uint32 current_proto_ver = dss_get_master_proto_ver();
    dss_init_set(&session->recv_pack, current_proto_ver);
    session->recv_pack.head->cmd = DSS_CMD_SWITCH_LOCK;
    session->recv_pack.head->flags = 0;
    LOG_RUN_INF("[SWITCH] Try to switch lock to %u by %u.", curr_id, master_id);
    (void)dss_put_int32(&session->recv_pack, curr_id);
    status_t status = dss_process_remote(session);
    if (status != CM_SUCCESS) {
        LOG_RUN_ERR("[SWITCH] Failed to switch lock to %u by %u.", curr_id, master_id);
        g_dss_instance.status = old_status;
    }
    return status;
}

static status_t dss_process_set_main_inst(dss_session_t *session)
{
    status_t status = CM_ERROR;
    dss_config_t *cfg = dss_get_inst_cfg();
    uint32 curr_id = (uint32)(cfg->params.inst_id);
    uint32 master_id;
    DSS_RETURN_IF_ERROR(
        dss_set_audit_resource(session->audit_info.resource, DSS_AUDIT_MODIFY, "set %u as master", curr_id));
    while (CM_TRUE) {
        master_id = dss_get_master_id();
        if (master_id == curr_id) {
            session->recv_pack.head->cmd = DSS_CMD_SET_MAIN_INST;
            LOG_RUN_INF("[SWITCH] Main server %u is set successfully by %u.", curr_id, master_id);
            return CM_SUCCESS;
        }
        if (get_instance_status_proc() == DSS_STATUS_RECOVERY) {
            session->recv_pack.head->cmd = DSS_CMD_SET_MAIN_INST;
            DSS_THROW_ERROR(ERR_DSS_RECOVER_CAUSE_BREAK);
            LOG_RUN_INF("[SWITCH] Set main inst break by recovery");
            return CM_ERROR;
        }
        if (!cm_latch_timed_x(
            &g_dss_instance.switch_latch, session->id, DSS_PROCESS_REMOTE_INTERVAL, LATCH_STAT(LATCH_SWITCH))) {
            LOG_RUN_INF("[SWITCH] Spin switch lock timed out, just continue.");
            continue;
        }
        status = dss_process_remote_switch_lock(session, curr_id, master_id);
        if (status != CM_SUCCESS) {
            cm_unlatch(&g_dss_instance.switch_latch, LATCH_STAT(LATCH_SWITCH));
            if (cm_get_error_code() == ERR_DSS_RECOVER_CAUSE_BREAK) {
                session->recv_pack.head->cmd = DSS_CMD_SET_MAIN_INST;
                LOG_RUN_INF("[SWITCH] Try set main break because master id is invalid.");
                return CM_ERROR;
            }
            cm_sleep(DSS_PROCESS_REMOTE_INTERVAL);
            continue;
        }
        break;
    }
    session->recv_pack.head->cmd = DSS_CMD_SET_MAIN_INST;
    dss_set_recover_thread_id(dss_get_current_thread_id());
    g_dss_instance.status = DSS_STATUS_RECOVERY;
    dss_set_master_id(curr_id);
    status = dss_refresh_meta_info(session);
    if (status != CM_SUCCESS) {
        g_dss_instance.status = DSS_STATUS_OPEN;
        cm_unlatch(&g_dss_instance.switch_latch, LATCH_STAT(LATCH_SWITCH));
        LOG_RUN_ERR("[DSS][SWITCH] ABORT INFO: dss instance %u refresh meta failed, result(%d).", curr_id, status);
        cm_fync_logfile();
        dss_exit(1);
    }
    dss_set_server_status_flag(DSS_STATUS_READWRITE);
    LOG_RUN_INF("[SWITCH] inst %u set status flag %u when set main inst.", curr_id, DSS_STATUS_READWRITE);
    g_dss_instance.status = DSS_STATUS_OPEN;
    dss_set_recover_thread_id(0);
    LOG_RUN_INF("[SWITCH] Main server %u is set successfully by %u.", curr_id, master_id);
    cm_unlatch(&g_dss_instance.switch_latch, LATCH_STAT(LATCH_SWITCH));
    return CM_SUCCESS;
}
static status_t dss_process_disable_grab_lock_inner(dss_session_t *session, uint32 curr_id)
{
    status_t ret = CM_ERROR;
    if (g_dss_instance.cm_res.is_valid) {
        dss_wait_session_pause(&g_dss_instance);
        g_dss_instance.status = DSS_STATUS_SWITCH;
        dss_wait_background_pause(&g_dss_instance);
        dss_close_delay_clean_background_task(&g_dss_instance);
        dss_set_server_status_flag(DSS_STATUS_READONLY);
        LOG_RUN_INF("[RELEASE LOCK]inst %u set status flag %u when release lock.", curr_id, DSS_STATUS_READONLY);
        ret = cm_res_unlock(&g_dss_instance.cm_res.mgr, DSS_CM_LOCK);
        if (ret != CM_SUCCESS) {
            LOG_RUN_ERR("[RELEASE LOCK] inst %u release cm lock failed, cm error is %d.", curr_id, (int32)ret);
            uint32 lock_owner_id = DSS_INVALID_ID32;
            ret = cm_res_get_lock_owner(&g_dss_instance.cm_res.mgr, DSS_CM_LOCK, &lock_owner_id);
            if (lock_owner_id == curr_id) {
                dss_set_server_status_flag(DSS_STATUS_READWRITE);
                LOG_RUN_INF(
                    "[RELEASE LOCK]inst %u set status flag %u when failed to unlock and lock owner is no change.",
                    curr_id, DSS_STATUS_READWRITE);
            } else {
                dss_set_master_id(DSS_INVALID_ID32);
                LOG_RUN_INF("[RELEASE LOCK]inst %u set status flag %u when failed to unlock, cm error is %d, "
                            "lock_owner_id is %u.",
                    curr_id, DSS_STATUS_READONLY, (int32)ret, lock_owner_id);
            }
            dss_set_session_running(&g_dss_instance, session->id);
            LOG_RUN_ERR("[RELEASE LOCK] cm release lock failed from %u.", curr_id);
            return CM_ERROR;
        }
        dss_set_master_id(DSS_INVALID_ID32);
        dss_set_session_running(&g_dss_instance, session->id);
    } else {
        LOG_RUN_ERR("[RELEASE LOCK] Only with cm can release lock.");
        return CM_ERROR;
    }
    return ret;
}

static status_t dss_process_disable_grab_lock(dss_session_t *session)
{
    dss_config_t *cfg = dss_get_inst_cfg();
    uint32 curr_id = (uint32)(cfg->params.inst_id);
    uint32 master_id;
    status_t ret;
    DSS_RETURN_IF_ERROR(dss_set_audit_resource(
        session->audit_info.resource, DSS_AUDIT_MODIFY, "%u if it is master to disable grab lock", curr_id));
    if (g_dss_instance.is_maintain || g_dss_instance.inst_cfg.params.nodes_list.inst_cnt <= 1) {
        LOG_RUN_ERR("[RELEASE LOCK]No need to disable grab lock when dssserver is maintain or just one inst.");
        return CM_ERROR;
    }
    if (g_dss_instance.is_releasing_lock) {
        LOG_RUN_INF("[RELEASE LOCK]One session is releasing lock, just return.");
        return CM_ERROR;
    }
    while (CM_TRUE) {
        if (!cm_latch_timed_x(
                &g_dss_instance.switch_latch, session->id, DSS_PROCESS_REMOTE_INTERVAL, LATCH_STAT(LATCH_SWITCH))) {
            LOG_RUN_INF("[RELEASE LOCK]Spin switch lock timed out, just continue.");
            continue;
        }
        g_dss_instance.is_releasing_lock = CM_TRUE;
        master_id = dss_get_master_id();
        if (master_id != curr_id) {
            LOG_RUN_INF("[RELEASE LOCK]No need to release lock.");
            g_dss_instance.is_releasing_lock = CM_FALSE;
            cm_unlatch(&g_dss_instance.switch_latch, LATCH_STAT(LATCH_SWITCH));
            return CM_SUCCESS;
        }
        ret = dss_process_disable_grab_lock_inner(session, curr_id);
        break;
    }
    g_dss_instance.status = DSS_STATUS_OPEN;
    g_dss_instance.is_releasing_lock = CM_FALSE;
    if (ret == CM_SUCCESS) {
        g_dss_instance.no_grab_lock = CM_TRUE;
        cm_unlatch(&g_dss_instance.switch_latch, LATCH_STAT(LATCH_SWITCH));
        LOG_RUN_INF("[RELEASE LOCK]Curr_id %u disable grab lock successfully.", curr_id);
        return CM_SUCCESS;
    }
    cm_unlatch(&g_dss_instance.switch_latch, LATCH_STAT(LATCH_SWITCH));
    return ret;
}
static status_t dss_process_enable_grab_lock(dss_session_t *session)
{
    dss_config_t *cfg = dss_get_inst_cfg();
    uint32 curr_id = (uint32)(cfg->params.inst_id);
    DSS_RETURN_IF_ERROR(
        dss_set_audit_resource(session->audit_info.resource, DSS_AUDIT_MODIFY, "set %u enable grab lock", curr_id));
    g_dss_instance.no_grab_lock = CM_FALSE;
    LOG_RUN_INF("Curr_id %u enable grab lock successfully.", curr_id);
    return CM_SUCCESS;
}

static status_t dss_process_enable_upgrades(dss_session_t *session)
{
    dss_config_t *cfg = dss_get_inst_cfg();
    uint32 curr_id = (uint32)(cfg->params.inst_id);
    dss_get_version_output_t get_version_output = {.all_same = DSS_TRUE, .min_version = DSS_PROTO_VERSION};
    DSS_RETURN_IF_ERROR(dss_set_audit_resource(session->audit_info.resource, DSS_AUDIT_MODIFY,
        "enable upgrades", curr_id));
    int ret = dss_bcast_get_protocol_version(&get_version_output);
    if (ret != CM_SUCCESS) {
        // If any node return ERR_DSS_UNSUPPORTED_CMD, we assume old node exists.
        if (ret == ERR_DSS_UNSUPPORTED_CMD || ret == ERR_MES_WAIT_OVERTIME) {
            cm_reset_error();
            DSS_THROW_ERROR(ERR_DSS_VERSION_NOT_ALL_SAME);
            return ERR_DSS_VERSION_NOT_ALL_SAME;
        }
        cm_reset_error();
        DSS_THROW_ERROR(ERR_DSS_VERSION_BCAST_ERROR);
        return ERR_DSS_VERSION_BCAST_ERROR;
    }
    if (!get_version_output.all_same) {
        DSS_THROW_ERROR(ERR_DSS_VERSION_NOT_ALL_SAME);
        return ERR_DSS_VERSION_NOT_ALL_SAME;
    }
    dss_vg_info_item_t *vg_item = &g_vgs_info->volume_group[0];
    if (get_version_output.min_version > vg_item->dss_ctrl->vg_info.proto_version) {
        return dss_write_global_version_to_disk(vg_item, get_version_output.min_version);
    }
    return CM_SUCCESS;
}

static dss_cmd_hdl_t g_dss_cmd_handle[DSS_CMD_TYPE_OFFSET(DSS_CMD_END)] = {
    // modify
    [DSS_CMD_TYPE_OFFSET(DSS_CMD_MKDIR)] = {DSS_CMD_MKDIR, dss_process_mkdir, NULL, CM_TRUE},
    [DSS_CMD_TYPE_OFFSET(DSS_CMD_RMDIR)] = {DSS_CMD_RMDIR, dss_process_rmdir, NULL, CM_TRUE},
    [DSS_CMD_TYPE_OFFSET(DSS_CMD_OPEN_DIR)] = {DSS_CMD_OPEN_DIR, dss_process_open_dir, NULL, CM_FALSE},
    [DSS_CMD_TYPE_OFFSET(DSS_CMD_CLOSE_DIR)] = {DSS_CMD_CLOSE_DIR, dss_process_close_dir, NULL, CM_FALSE},
    [DSS_CMD_TYPE_OFFSET(DSS_CMD_OPEN_FILE)] = {DSS_CMD_OPEN_FILE, dss_process_open_file, NULL, CM_FALSE},
    [DSS_CMD_TYPE_OFFSET(DSS_CMD_CLOSE_FILE)] = {DSS_CMD_CLOSE_FILE, dss_process_close_file, NULL, CM_FALSE},
    [DSS_CMD_TYPE_OFFSET(DSS_CMD_CREATE_FILE)] = {DSS_CMD_CREATE_FILE, dss_process_create_file, NULL, CM_TRUE},
    [DSS_CMD_TYPE_OFFSET(DSS_CMD_DELETE_FILE)] = {DSS_CMD_DELETE_FILE, dss_process_delete_file, NULL, CM_TRUE},
    [DSS_CMD_TYPE_OFFSET(DSS_CMD_EXTEND_FILE)] = {DSS_CMD_EXTEND_FILE, dss_process_extending_file, NULL, CM_TRUE},
    [DSS_CMD_TYPE_OFFSET(DSS_CMD_ATTACH_FILE)] = {DSS_CMD_ATTACH_FILE, NULL, NULL, CM_FALSE},
    [DSS_CMD_TYPE_OFFSET(DSS_CMD_DETACH_FILE)] = {DSS_CMD_DETACH_FILE, NULL, NULL, CM_FALSE},
    [DSS_CMD_TYPE_OFFSET(DSS_CMD_RENAME_FILE)] = {DSS_CMD_RENAME_FILE, dss_process_rename, NULL, CM_TRUE},
    [DSS_CMD_TYPE_OFFSET(DSS_CMD_REFRESH_FILE)] = {DSS_CMD_REFRESH_FILE, dss_process_refresh_file, NULL, CM_FALSE},
    [DSS_CMD_TYPE_OFFSET(DSS_CMD_TRUNCATE_FILE)] = {DSS_CMD_TRUNCATE_FILE, dss_process_truncate_file, NULL, CM_TRUE},
    [DSS_CMD_TYPE_OFFSET(DSS_CMD_REFRESH_FILE_TABLE)] = {DSS_CMD_REFRESH_FILE_TABLE, dss_process_refresh_file_table,
        NULL, CM_FALSE},
    [DSS_CMD_TYPE_OFFSET(DSS_CMD_FALLOCATE_FILE)] = {DSS_CMD_FALLOCATE_FILE, dss_process_fallocate_file, NULL, CM_TRUE},
    [DSS_CMD_TYPE_OFFSET(DSS_CMD_ADD_VOLUME)] = {DSS_CMD_ADD_VOLUME, dss_process_add_volume, NULL, CM_TRUE},
    [DSS_CMD_TYPE_OFFSET(DSS_CMD_REMOVE_VOLUME)] = {DSS_CMD_REMOVE_VOLUME, dss_process_remove_volume, NULL, CM_TRUE},
    [DSS_CMD_TYPE_OFFSET(DSS_CMD_REFRESH_VOLUME)] = {DSS_CMD_REFRESH_VOLUME, dss_process_refresh_volume, NULL,
        CM_FALSE},
    [DSS_CMD_TYPE_OFFSET(DSS_CMD_LOAD_CTRL)] = {DSS_CMD_LOAD_CTRL, dss_process_loadctrl, NULL, CM_FALSE},
    [DSS_CMD_TYPE_OFFSET(DSS_CMD_UPDATE_WRITTEN_SIZE)] = {DSS_CMD_UPDATE_WRITTEN_SIZE,
        dss_process_update_file_written_size, NULL, CM_TRUE},
    [DSS_CMD_TYPE_OFFSET(DSS_CMD_STOP_SERVER)] = {DSS_CMD_STOP_SERVER, dss_process_stop_server, NULL, CM_FALSE},
    [DSS_CMD_TYPE_OFFSET(DSS_CMD_SETCFG)] = {DSS_CMD_SETCFG, dss_process_setcfg, NULL, CM_FALSE},
    [DSS_CMD_TYPE_OFFSET(DSS_CMD_SYMLINK)] = {DSS_CMD_SYMLINK, dss_process_symlink, NULL, CM_TRUE},
    [DSS_CMD_TYPE_OFFSET(DSS_CMD_UNLINK)] = {DSS_CMD_UNLINK, dss_process_unlink, NULL, CM_TRUE},
    [DSS_CMD_TYPE_OFFSET(DSS_CMD_SET_MAIN_INST)] = {DSS_CMD_SET_MAIN_INST, dss_process_set_main_inst, NULL, CM_FALSE},
    [DSS_CMD_TYPE_OFFSET(DSS_CMD_SWITCH_LOCK)] = {DSS_CMD_SWITCH_LOCK, dss_process_switch_lock, NULL, CM_FALSE},
    [DSS_CMD_TYPE_OFFSET(DSS_CMD_DISABLE_GRAB_LOCK)] = {DSS_CMD_DISABLE_GRAB_LOCK, dss_process_disable_grab_lock, NULL,
        CM_FALSE},
    [DSS_CMD_TYPE_OFFSET(DSS_CMD_ENABLE_GRAB_LOCK)] = {DSS_CMD_ENABLE_GRAB_LOCK, dss_process_enable_grab_lock, NULL,
        CM_FALSE},
    [DSS_CMD_TYPE_OFFSET(DSS_CMD_HOTPATCH)] = {DSS_CMD_HOTPATCH, dss_process_hotpatch, NULL, CM_FALSE},
    [DSS_CMD_TYPE_OFFSET(DSS_CMD_ENABLE_UPGRADES)] = {DSS_CMD_ENABLE_UPGRADES, dss_process_enable_upgrades, NULL,
        CM_TRUE},
    // query
    [DSS_CMD_TYPE_OFFSET(DSS_CMD_HANDSHAKE)] = {DSS_CMD_HANDSHAKE, dss_process_handshake, NULL, CM_FALSE},
    [DSS_CMD_TYPE_OFFSET(DSS_CMD_EXIST)] = {DSS_CMD_EXIST, dss_process_exist, NULL, CM_FALSE},
    [DSS_CMD_TYPE_OFFSET(DSS_CMD_READLINK)] = {DSS_CMD_READLINK, dss_process_readlink, NULL, CM_FALSE},
    [DSS_CMD_TYPE_OFFSET(DSS_CMD_GET_FTID_BY_PATH)] = {DSS_CMD_GET_FTID_BY_PATH, dss_process_get_ftid_by_path, NULL,
        CM_TRUE},
    [DSS_CMD_TYPE_OFFSET(DSS_CMD_GETCFG)] = {DSS_CMD_GETCFG, dss_process_getcfg, NULL, CM_FALSE},
    [DSS_CMD_TYPE_OFFSET(DSS_CMD_GET_INST_STATUS)] = {DSS_CMD_GET_INST_STATUS, dss_process_get_inst_status, NULL,
        CM_FALSE},
    [DSS_CMD_TYPE_OFFSET(DSS_CMD_GET_TIME_STAT)] = {DSS_CMD_GET_TIME_STAT, dss_process_get_time_stat, NULL, CM_FALSE},
    [DSS_CMD_TYPE_OFFSET(DSS_CMD_QUERY_HOTPATCH)] = {DSS_CMD_QUERY_HOTPATCH, dss_process_query_hotpatch, NULL,
        CM_FALSE},
};

dss_cmd_hdl_t g_dss_remote_handle = {DSS_CMD_EXEC_REMOTE, dss_process_remote, NULL, CM_FALSE};

static dss_cmd_hdl_t *dss_get_cmd_handle(int32 cmd)
{
    if (cmd >= DSS_CMD_BEGIN && cmd < DSS_CMD_END) {
        return &g_dss_cmd_handle[DSS_CMD_TYPE_OFFSET(cmd)];
    }
    return NULL;
}

static status_t dss_check_proto_version(dss_session_t *session)
{
    session->client_version = dss_get_client_version(&session->recv_pack);
    uint32 current_proto_ver = dss_get_master_proto_ver();
    current_proto_ver = MIN(current_proto_ver, session->client_version);
    session->proto_version = current_proto_ver;
    if (session->proto_version != dss_get_version(&session->recv_pack)) {
        LOG_RUN_INF("[CHECK_PROTO]The client protocol version need be changed, old protocol version is %u, new "
                    "protocol version is %u.",
            dss_get_version(&session->recv_pack), session->proto_version);
        DSS_THROW_ERROR(ERR_DSS_VERSION_NOT_MATCH, dss_get_version(&session->recv_pack), session->proto_version);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static status_t dss_exec_cmd(dss_session_t *session, bool32 local_req)
{
    DSS_LOG_DEBUG_OP(
        "Receive command:%d, server status is %d.", session->recv_pack.head->cmd, (int32)g_dss_instance.status);
    // remote req need process for proto_version
    session->proto_version = dss_get_version(&session->recv_pack);
    dss_cmd_hdl_t *handle = dss_get_cmd_handle(session->recv_pack.head->cmd);

    if ((handle == NULL) || (handle->proc == NULL)) {
        LOG_DEBUG_ERR("the req cmd: %d is not valid.", session->recv_pack.head->cmd);
        // In rolling upgrade scenarios, the source node needs to detect error code.
        return ERR_DSS_UNSUPPORTED_CMD;
    }

    status_t status;
    do {
        cm_reset_error();
        dss_inc_active_sessions(session);
        if (dss_can_cmd_type_no_open(session->recv_pack.head->cmd)) {
            status = handle->proc(session);
        } else if (!dss_need_exec_remote(handle->exec_on_active, local_req)) {
            // if cur node is standby, may reset it to recovery to do recovery
            if (g_dss_instance.status != DSS_STATUS_OPEN && g_dss_instance.status != DSS_STATUS_PREPARE) {
                LOG_RUN_INF("Req forbided by recovery for cmd:%u", (uint32)session->recv_pack.head->cmd);
                dss_dec_active_sessions(session);
                cm_sleep(DSS_PROCESS_REMOTE_INTERVAL);
                continue;
            }
            status = handle->proc(session);
        } else {
            status = g_dss_remote_handle.proc(session);
        }
        dss_dec_active_sessions(session);
        if (status != CM_SUCCESS &&
            (cm_get_error_code() == ERR_DSS_RECOVER_CAUSE_BREAK || cm_get_error_code() == ERR_DSS_MASTER_CHANGE)) {
            LOG_RUN_INF("Req breaked by error %d for cmd:%u", cm_get_error_code(), session->recv_pack.head->cmd);
            cm_sleep(DSS_PROCESS_REMOTE_INTERVAL);
            continue;
        }
        break;
    } while (CM_TRUE);

    session->audit_info.action = dss_get_cmd_desc(session->recv_pack.head->cmd);

    if (local_req) {
        sql_record_audit_log(session, status, session->recv_pack.head->cmd);
    }
    return status;
}

void dss_process_cmd_wait_be_open(dss_session_t *session)
{
    while (g_dss_instance.status != DSS_STATUS_OPEN) {
        DSS_GET_CM_LOCK_LONG_SLEEP;
        LOG_RUN_INF("The status %d of instance %lld is not open, just wait.\n", (int32)g_dss_instance.status,
            dss_get_inst_cfg()->params.inst_id);
    }
}

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
    dss_init_set(&session->send_pack, session->proto_version);
    status = dss_read(&session->pipe, &session->recv_pack, CM_FALSE);
    if (status != CM_SUCCESS) {
        LOG_RUN_ERR("Failed to read message sent by %s.", session->cli_info.process_name);
        session->is_closed = CM_TRUE;
        return CM_ERROR;
    }
    status = dss_check_proto_version(session);
    if (status != CM_SUCCESS) {
        dss_return_error(session);
        return CM_ERROR;
    }

    if (!dss_can_cmd_type_no_open(session->recv_pack.head->cmd)) {
        dss_process_cmd_wait_be_open(session);
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

status_t dss_process_handshake_cmd(dss_session_t *session, dss_cmd_type_e cmd)
{
    status_t status = CM_ERROR;
    bool32 ready = CM_FALSE;
    do {
        cm_reset_error();
        if (cs_wait(&session->pipe, CS_WAIT_FOR_READ, session->pipe.socket_timeout, &ready) != CM_SUCCESS) {
            LOG_RUN_ERR("[DSS_CONNECT]session %u wait handshake cmd %u failed.", session->id, cmd);
            return CM_ERROR;
        }
        if (ready == CM_FALSE) {
            LOG_RUN_ERR("[DSS_CONNECT]session %u wait handshake cmd %u timeout.", session->id, cmd);
            return CM_ERROR;
        }
        dss_init_set(&session->send_pack, session->proto_version);
        status = dss_read(&session->pipe, &session->recv_pack, CM_FALSE);
        if (status != CM_SUCCESS) {
            LOG_RUN_ERR("[DSS_CONNECT]session %u read handshake cmd %u msg failed.", session->id, cmd);
            return CM_ERROR;
        }
        status = dss_check_proto_version(session);
        if (status != CM_SUCCESS) {
            dss_return_error(session);
            continue;
        }
        break;
    } while (CM_TRUE);
    if (session->recv_pack.head->cmd != cmd) {
        LOG_RUN_ERR("[DSS_CONNECT]session %u wait handshake cmd %u, but get msg cmd %u.", session->id, cmd,
            session->recv_pack.head->cmd);
        return CM_ERROR;
    }
    status = dss_exec_cmd(session, CM_TRUE);
    if (status != CM_SUCCESS) {
        LOG_RUN_ERR(
            "[DSS_CONNECT]Failed to execute command:%d, session %u.", session->recv_pack.head->cmd, session->id);
        dss_return_error(session);
        return CM_ERROR;
    } else {
        dss_return_success(session);
    }
    return status;
}
#ifdef __cplusplus
}
#endif
