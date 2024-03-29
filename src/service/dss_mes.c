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
 * dss_mes.c
 *
 *
 * IDENTIFICATION
 *    src/service/dss_mes.c
 *
 * -------------------------------------------------------------------------
 */

#include "cm_types.h"
#include "dss_malloc.h"
#include "dss_session.h"
#include "dss_file.h"
#include "dss_service.h"
#include "dss_instance.h"
#include "dss_api.h"
#include "dss_mes.h"

#ifndef WIN32
static __thread char *g_thv_read_buf = NULL;
#else
__declspec(thread) char *g_thv_read_buf = NULL;
#endif

void dss_proc_broadcast_req(dss_session_t *session, mes_msg_t *msg);
void dss_proc_syb2active_req(dss_session_t *session, mes_msg_t *msg);
void dss_proc_loaddisk_req(dss_session_t *session, mes_msg_t *msg);
void dss_proc_join_cluster_req(dss_session_t *session, mes_msg_t *msg);
void dss_proc_refresh_ft_by_primary_req(dss_session_t *session, mes_msg_t *msg);
void dss_proc_get_ft_block_req(dss_session_t *session, mes_msg_t *msg);

void dss_proc_normal_ack(dss_session_t *session, mes_msg_t *msg)
{
    dss_message_head_t *dss_head = (dss_message_head_t *)msg->buffer;
    LOG_DEBUG_INF("Receive ack(%u),src inst(%u), dst inst(%u).", (uint32)(dss_head->dss_cmd),
        (uint32)(dss_head->src_inst), (uint32)(dss_head->dst_inst));
}

dss_processor_t g_dss_processors[DSS_CMD_CEIL] = {
    [DSS_CMD_REQ_BROADCAST] = {dss_proc_broadcast_req, CM_TRUE, CM_TRUE, MES_PRIORITY_ONE, "dss broadcast"},
    [DSS_CMD_ACK_BROADCAST_WITH_MSG] = {dss_proc_normal_ack, CM_FALSE, CM_FALSE, MES_PRIORITY_ONE,
        "dss broadcast ack with data"},
    [DSS_CMD_REQ_SYB2ACTIVE] = {dss_proc_syb2active_req, CM_TRUE, CM_TRUE, MES_PRIORITY_ONE,
        "dss standby to active req"},
    [DSS_CMD_ACK_SYB2ACTIVE] = {dss_proc_normal_ack, CM_FALSE, CM_FALSE, MES_PRIORITY_ONE,
        "dss active to standby ack"},
    [DSS_CMD_REQ_LOAD_DISK] = {dss_proc_loaddisk_req, CM_TRUE, CM_TRUE, MES_PRIORITY_ZERO,
        "dss standby load disk to active req"},
    [DSS_CMD_ACK_LOAD_DISK] = {dss_proc_normal_ack, CM_FALSE, CM_FALSE, MES_PRIORITY_ZERO,
        "dss active load disk to standby ack"},
    [DSS_CMD_REQ_JOIN_CLUSTER] = {dss_proc_join_cluster_req, CM_TRUE, CM_TRUE, MES_PRIORITY_ONE,
        "dss standby join in cluster to active req"},
    [DSS_CMD_ACK_JOIN_CLUSTER] = {dss_proc_normal_ack, CM_FALSE, CM_FALSE, MES_PRIORITY_ONE,
        "dss active proc join in cluster to standby ack"},
    [DSS_CMD_REQ_REFRESH_FT] = {dss_proc_refresh_ft_by_primary_req, CM_TRUE, CM_TRUE, MES_PRIORITY_ONE,
        "dss standby refresh ft by primary req"},
    [DSS_CMD_ACK_REFRESH_FT] = {dss_proc_normal_ack, CM_FALSE, CM_FALSE, MES_PRIORITY_ONE,
        "dss active proc ft to standby ack"},
    [DSS_CMD_REQ_GET_FT_BLOCK] = {dss_proc_get_ft_block_req, CM_TRUE, CM_TRUE, MES_PRIORITY_ZERO,
        "dss standby get ft block req"},
    [DSS_CMD_ACK_GET_FT_BLOCK] = {dss_proc_normal_ack, CM_FALSE, CM_FALSE, MES_PRIORITY_ZERO,
        "dss active proc get ft block ack"},
};

static inline mes_priority_t dss_get_cmd_pro_id(dss_mes_command_t cmd)
{
    return g_dss_processors[cmd].prio_id;
}

static void dss_init_mes_head(dss_message_head_t *head, uint32 cmd, uint32 flags, uint16 src_inst, uint16 dst_inst,
    uint32 size, uint32 version, ruid_type ruid)
{
    (void)memset_s(head, DSS_MES_MSG_HEAD_SIZE, 0, DSS_MES_MSG_HEAD_SIZE);
    head->sw_proto_ver = DSS_PROTO_VERSION;
    head->msg_proto_ver = version;
    head->size = size;
    head->dss_cmd = cmd;
    head->ruid = ruid;
    head->src_inst = src_inst;
    head->dst_inst = dst_inst;
    head->flags = flags | dss_get_cmd_pro_id(cmd);
}

static dss_bcast_ack_cmd_t dss_get_bcast_ack_cmd(dss_bcast_req_cmd_t bcast_op)
{
    switch (bcast_op) {
        case BCAST_REQ_DEL_DIR_FILE:
            return BCAST_ACK_DEL_FILE;
        case BCAST_REQ_INVALIDATE_FS_META:
            return BCAST_ACK_INVALIDATE_FS_META;
        default:
            LOG_RUN_ERR("Invalid broadcast request type");
            break;
    }
    return BCAST_ACK_END;
}

static void dss_proc_broadcast_req_inner(dss_session_t *session, dss_notify_req_msg_t *req)
{
    status_t status = CM_ERROR;

    if ((req->vg_name[0] == 0) || (g_vgs_info == NULL)) {
        LOG_DEBUG_ERR("Failed to find vg, vg name is null.");
        return;
    }
    DSS_LOG_DEBUG_OP("check file ftid: %llu, vg_name: %s\n", req->ftid, req->vg_name);
    dss_vg_info_item_t *vg_item = dss_find_vg_item(req->vg_name);
    if (vg_item == NULL) {
        DSS_THROW_ERROR(ERR_DSS_VG_NOT_EXIST, req->vg_name);
        LOG_DEBUG_ERR("Failed to find vg, %s.", req->vg_name);
        return;
    }

    bool32 cmd_ack = CM_FALSE;
    switch (req->type) {
        case BCAST_REQ_DEL_DIR_FILE:
            status = dss_check_open_file_remote(session, req->vg_name, req->ftid, &cmd_ack);
            break;
        case BCAST_REQ_INVALIDATE_FS_META:
            status = dss_invalidate_fs_meta_remote(session, req->vg_name, req->ftid, &cmd_ack);
            break;
        default:
            LOG_DEBUG_ERR("invalid broadcast req type");
            return;
    }
    dss_config_t *inst_cfg = dss_get_inst_cfg();
    dss_params_t *param = &inst_cfg->params;
    dss_message_head_t *req_head = &req->dss_head;
    uint16 dst_inst = req_head->src_inst;
    uint16 src_inst = (uint16)param->inst_id;
    uint32 version = req_head->msg_proto_ver;
    ruid_type ruid = req_head->ruid;
    dss_notify_ack_msg_t ack_check;
    dss_init_mes_head(&ack_check.dss_head, DSS_CMD_ACK_BROADCAST_WITH_MSG, 0, src_inst, dst_inst, sizeof(dss_notify_ack_msg_t), version, ruid);
    ack_check.type = dss_get_bcast_ack_cmd(req->type);
    ack_check.result = status;
    ack_check.cmd_ack = cmd_ack;
    int ret = mes_send_response(dst_inst, ack_check.dss_head.flags, ruid, (char *)&ack_check,
        sizeof(dss_notify_ack_msg_t));
    if (ret != CM_SUCCESS) {
        LOG_DEBUG_ERR("send message failed, src inst(%hhu), dst inst(%hhu) ret(%d) ", src_inst, dst_inst, ret);
        return;
    }
    DSS_LOG_DEBUG_OP("send message succeed, notify %llu  result: %u. cmd=%u, src_inst=%hhu, "
                     "dst_inst=%hhu.", req->ftid, cmd_ack, ack_check.dss_head.dss_cmd,
                     ack_check.dss_head.src_inst, ack_check.dss_head.dst_inst);
}

int32 dss_process_broadcast_ack(dss_notify_ack_msg_t *ack, dss_recv_msg_t *recv_msg_output)
{
    int32 ret = ERR_DSS_MES_ILL;
    switch (ack->type) {
        case BCAST_ACK_DEL_FILE:
        case BCAST_ACK_INVALIDATE_FS_META:
            ret = ack->result;
            recv_msg_output->cmd_ack = ack->cmd_ack;
            break;
        default:
            LOG_DEBUG_ERR("invalid broadcast ack type");
            break;
    }
    return ret;
}

static void dss_ack_version_not_match(dss_session_t *session, dss_message_head_t *req_head, uint32 version)
{
    dss_config_t *inst_cfg = dss_get_inst_cfg();
    dss_params_t *param = &inst_cfg->params;
    uint16 dst_inst = req_head->src_inst;
    uint16 src_inst = (uint16)param->inst_id;
    ruid_type ruid = req_head->ruid;
    dss_message_head_t ack_head;
    uint32 cmd = (req_head->dss_cmd == DSS_CMD_REQ_BROADCAST) ? DSS_CMD_ACK_BROADCAST_WITH_MSG : DSS_CMD_ACK_SYB2ACTIVE;
    dss_init_mes_head(&ack_head, cmd, 0, src_inst, dst_inst, DSS_MES_MSG_HEAD_SIZE, version, ruid);
    ack_head.result = ERR_DSS_VERSION_NOT_MATCH;
    int ret = mes_send_response(dst_inst, ack_head.flags, ruid, (char *)&ack_head, DSS_MES_MSG_HEAD_SIZE);
    if (ret != CM_SUCCESS) {
        LOG_DEBUG_ERR("send version not match message failed, src inst(%hhu), dst inst(%hhu) ret(%d)",
            src_inst, dst_inst, ret);
        return;
    }
    LOG_RUN_INF("send version not match message succeed, src inst(%hhu), dst inst(%hhu), ack msg version (%hhu)",
        src_inst, dst_inst, version);
}

void dss_proc_broadcast_req(dss_session_t *session, mes_msg_t *msg)
{
    if (msg->size < sizeof(dss_notify_req_msg_t)) {
        LOG_DEBUG_ERR("invalid message req size");
        return;
    }
    dss_notify_req_msg_t *req = (dss_notify_req_msg_t *)msg->buffer;
    LOG_DEBUG_INF("Try proc broadcast req, head cmd is %u, req cmd is %u.", req->dss_head.dss_cmd, req->type);
    dss_proc_broadcast_req_inner(session, req);
    return;
}

static void dss_set_cluster_proto_vers(uint8 inst_id, uint32 version)
{
    if (inst_id >= DSS_MAX_INSTANCES) {
        LOG_DEBUG_ERR("Invalid request inst_id:%hhu, version is %u.", inst_id, version);
        return;
    }
    bool32 set_flag = CM_FALSE;
    do {
        uint32 cur_version = (uint32)cm_atomic32_get((atomic32_t *)&g_dss_instance.cluster_proto_vers[inst_id]);
        if (cur_version == version) {
            break;
        }
        set_flag = cm_atomic32_cas(
            (atomic32_t *)&g_dss_instance.cluster_proto_vers[inst_id], (int32)cur_version, (int32)version);
    } while (!set_flag);
}

static int dss_handle_broadcast_msg(mes_msg_list_t *responses, dss_recv_msg_t *recv_msg_output)
{
    int ret;
    dss_message_head_t *ack_head;
    uint16 src_inst;
    for (uint32 i = 0; i < responses->count; i++) {
        mes_msg_t *msg = &responses->messages[i];
        ack_head = (dss_message_head_t *)msg->buffer;
        src_inst = responses->messages[i].src_inst;
        dss_set_cluster_proto_vers((uint8)src_inst, ack_head->sw_proto_ver);
        if (ack_head->result == ERR_DSS_VERSION_NOT_MATCH) {
            recv_msg_output->version_not_match_inst |= ((uint64)0x1 << src_inst);
            continue;
        }
        if (ack_head->size < sizeof(dss_notify_ack_msg_t)) {
            DSS_THROW_ERROR(ERR_DSS_MES_ILL, "msg len is invalid");
            return ERR_DSS_MES_ILL;
        }
        dss_notify_ack_msg_t *ack = (dss_notify_ack_msg_t *)ack_head;
        ret = dss_process_broadcast_ack(ack, recv_msg_output);
        DSS_RETURN_IFERR2(
            ret, DSS_THROW_ERROR(ERR_DSS_FILE_OPENING_REMOTE, ack_head->src_inst, ack_head->dss_cmd));
    }
    return DSS_SUCCESS;
}

static void dss_release_broadcast_msg(mes_msg_list_t *responses)
{
    for (uint32 i = 0; i < responses->count; i++) {
        mes_release_msg(&responses->messages[i]);
    }
}

static int dss_handle_recv_broadcast_msg(ruid_type ruid, uint32 timeout, uint64 *succ_ack_inst,
    dss_recv_msg_t *recv_msg_output)
{
    mes_msg_list_t responses;
    int ret = mes_broadcast_get_response(ruid, &responses, timeout);
    if (ret != DSS_SUCCESS) {
        LOG_DEBUG_INF("Try broadcast get response failed, ret is %d, ruid is %llu.", ret, ruid);
        return ret;
    }
    ret = dss_handle_broadcast_msg(&responses, recv_msg_output);
    if (ret != DSS_SUCCESS) {
        dss_release_broadcast_msg(&responses);
        LOG_DEBUG_INF("Try broadcast get response failed, ret is %d, ruid is %llu.", ret, ruid);
        return ret;
    }
    // do not care ret, just check get ack msg
    for (uint32 i = 0; i < responses.count; i++) {
        uint32 src_inst = responses.messages[i].src_inst;
        *succ_ack_inst |= ((uint64)0x1 << src_inst);
    }
    *succ_ack_inst = *succ_ack_inst & (~recv_msg_output->version_not_match_inst);
    dss_release_broadcast_msg(&responses);
    return ret;
}

uint32 dss_get_broadcast_proto_ver(uint64 succ_inst)
{
    uint64 inst_mask;
    uint64 cur_work_inst_map = dss_get_inst_work_status();
    uint64 need_send_inst = (~succ_inst & cur_work_inst_map);
    uint32 inst_proto_ver;
    uint32 broadcast_proto_vers = DSS_PROTO_VERSION;
    for (uint32 i = 0; i < DSS_MAX_INSTANCES; i++) {
        inst_mask = ((uint64)0x1 << i);
        if ((need_send_inst & inst_mask) == 0) {
            continue;
        }
        inst_proto_ver = (uint32)cm_atomic32_get((atomic32_t *)&g_dss_instance.cluster_proto_vers[i]);
        if (inst_proto_ver == DSS_INVALID_VERSION) {
            continue;
        }
        broadcast_proto_vers = MIN(broadcast_proto_vers, inst_proto_ver);
    }
    return broadcast_proto_vers;
}

void dss_get_valid_inst(uint64 valid_inst, uint32 *arr, uint32 count)
{
    uint32 i = 0;
    for (uint32 j = 0; j < DSS_MAX_INSTANCES; j++) {
        if (DSS_IS_INST_SEND(valid_inst, j)) {
            arr[i] = j;
            i++;
        }
    }
}

#define DSS_BROADCAST_MSG_TRY_MAX 5
#define DSS_BROADCAST_MSG_TRY_SLEEP_TIME 200
static status_t dss_broadcast_msg_with_try(
    dss_message_head_t *dss_head, dss_recv_msg_t *recv_msg, unsigned int timeout)
{
    int32 ret = DSS_SUCCESS;

    dss_config_t *inst_cfg = dss_get_inst_cfg();
    dss_params_t *param = &inst_cfg->params;
    uint64 succ_req_inst = 0;
    uint64 succ_ack_inst = 0;
    uint32 i = 0;
    // init last send err with all
    uint64 cur_work_inst_map = dss_get_inst_work_status();
    uint64 snd_err_inst_map = (~recv_msg->succ_inst & cur_work_inst_map);
    uint64 last_inst_inst_map = 0;
    uint64 new_added_inst_map = 0;
    uint64 valid_inst = 0;
    uint64 valid_inst_mask = 0;
    do {
        // only send the last-send-failed and new added
        cm_reset_error();
        valid_inst_mask = ((cur_work_inst_map & snd_err_inst_map) | new_added_inst_map);
        valid_inst = (param->inst_map) & (~((uint64)0x1 << (uint64)(param->inst_id))) & valid_inst_mask;
        valid_inst = (~recv_msg->version_not_match_inst & valid_inst);
        if (valid_inst == 0) {
            if (recv_msg->version_not_match_inst != 0) {
                recv_msg->version_not_match_inst = 0;
                return ERR_DSS_VERSION_NOT_MATCH;
            }
            LOG_DEBUG_INF("No inst need to broadcast.");
            return CM_SUCCESS;
        }
        LOG_DEBUG_INF("Try broadcast num is %u, head cmd is %u.", i, dss_head->dss_cmd);
        uint32 count = cm_bitmap64_count(valid_inst);
        uint32 valid_inst_arr[DSS_MAX_INSTANCES] ={0};
        dss_get_valid_inst(valid_inst, valid_inst_arr, count);
        (void)mes_broadcast_request_sp((inst_type *)valid_inst_arr, count, dss_head->flags, &dss_head->ruid, (char *)dss_head, dss_head->size);
        succ_req_inst = valid_inst;
        ret = dss_handle_recv_broadcast_msg(dss_head->ruid, timeout, &succ_ack_inst, recv_msg);
        uint64 succ_inst = valid_inst & succ_ack_inst;
        LOG_DEBUG_INF(
            "Try broadcast num is %u, valid_inst is %llu, succ_inst is %llu.", i, valid_inst, succ_inst);
        if (succ_inst != 0) {
            recv_msg->succ_inst = recv_msg->succ_inst | succ_inst;
        }
        if (ret == CM_SUCCESS && succ_req_inst == succ_ack_inst) {
            if (recv_msg->version_not_match_inst != 0) {
                recv_msg->version_not_match_inst = 0;
                return ERR_DSS_VERSION_NOT_MATCH;
            }
            return ret;
        }
        // ready for next try only new added and (send req failed or recv ack  failed)
        snd_err_inst_map = valid_inst_mask & (~(succ_req_inst & succ_ack_inst));
        last_inst_inst_map = cur_work_inst_map;
        cur_work_inst_map = dss_get_inst_work_status();
        new_added_inst_map = (~last_inst_inst_map & cur_work_inst_map);
        cm_sleep(DSS_BROADCAST_MSG_TRY_SLEEP_TIME);
        i++;
    } while (i < DSS_BROADCAST_MSG_TRY_MAX);
    cm_reset_error();
    DSS_THROW_ERROR(ERR_DSS_MES_ILL, "Failed to broadcast msg with try.");
    LOG_RUN_ERR("[DSS] THROW UP ERROR WHEN BROADCAST FAILED, errcode:%d", cm_get_error_code());
    return CM_ERROR;
}

static status_t dss_broadcast_msg(
    char *req_buf, uint32 size, dss_recv_msg_t *recv_msg, unsigned int timeout)
{
    return dss_broadcast_msg_with_try((dss_message_head_t *)req_buf, recv_msg, timeout);
}

static bool32 dss_check_srv_status(mes_msg_t *msg)
{
    date_t time_start = g_timer()->now;
    date_t time_now = 0;
    dss_message_head_t *dss_head = (dss_message_head_t *)(msg->buffer);
    dss_config_t *inst_cfg = dss_get_inst_cfg();
    uint32 max_time = inst_cfg->params.master_lock_timeout;
    while (g_dss_instance.status != DSS_STATUS_OPEN &&
            (dss_head->dss_cmd != DSS_CMD_REQ_JOIN_CLUSTER && dss_head->dss_cmd != DSS_CMD_ACK_JOIN_CLUSTER)) {
        LOG_DEBUG_INF("Could not exec remote req for the dssserver is not open or msg not join cluster, src node:%u.",
            (uint32)(dss_head->src_inst));
        DSS_GET_CM_LOCK_LONG_SLEEP;
        time_now = g_timer()->now;
        if (time_now - time_start > max_time * MICROSECS_PER_SECOND) {
            LOG_RUN_ERR("Fail to change status open for %d seconds when exec remote req.", max_time);
            return CM_FALSE;
        }
    }
    return CM_TRUE;
}

static status_t dss_prepare_ack_msg(
    dss_session_t *session, status_t ret, char **ack_buf, uint32 *ack_size, uint32 version)
{
    int32 code;
    const char *message = NULL;
    dss_packet_t *send_pack = &session->send_pack;

    if (ret != CM_SUCCESS) {
        dss_init_set(send_pack, version);
        *ack_buf = DSS_WRITE_ADDR(send_pack);
        cm_get_error(&code, &message);
        CM_RETURN_IFERR(dss_put_int32(send_pack, code));
        CM_RETURN_IFERR(dss_put_str(send_pack, message));
    } else {
        *ack_buf = send_pack->buf + sizeof(dss_packet_head_t);
    }
    *ack_size = send_pack->head->size - sizeof(dss_packet_head_t);
    return CM_SUCCESS;
}

void dss_proc_remote_req_err(dss_session_t *session, dss_message_head_t *req_dss_head, unsigned char cmd, int32 ret)
{
    dss_message_head_t ack;
    char *ack_buf = NULL;
    uint32 ack_size = 0;
    status_t status = dss_prepare_ack_msg(session, ret, &ack_buf, &ack_size, req_dss_head->msg_proto_ver);
    if (status != CM_SUCCESS) {
        LOG_DEBUG_ERR("The dssserver prepare ack msg failed, src node:%u, dst node:%u.", req_dss_head->src_inst,
            req_dss_head->dst_inst);
        return;
    }
    uint16 src_inst = req_dss_head->dst_inst;
    uint16 dst_inst = req_dss_head->src_inst;
    ruid_type ruid = req_dss_head->ruid;
    uint32 version = req_dss_head->msg_proto_ver;
    dss_init_mes_head(
        &ack, cmd, 0, src_inst, dst_inst, ack_size + DSS_MES_MSG_HEAD_SIZE, version, ruid);
    ack.result = ret;
    (void)mes_send_response_x(dst_inst, ack.flags, ruid, 2, &ack, DSS_MES_MSG_HEAD_SIZE, ack_buf, ack_size);
}

static status_t dss_process_remote_req_prepare(dss_session_t *session, mes_msg_t *msg, dss_processor_t *processor)
{
    dss_message_head_t *dss_head = (dss_message_head_t *)msg->buffer;
    // ready the ack connection
    dss_check_peer_by_inst(&g_dss_instance, dss_head->src_inst);
    if (dss_head->dss_cmd != DSS_CMD_REQ_BROADCAST && !dss_need_exec_local()) {
        LOG_RUN_ERR("Proc msg cmd:%u from remote node:%u fail, can NOT exec here.", (uint32)dss_head->dss_cmd,
            dss_head->src_inst);
        return CM_ERROR;
    }
    if (dss_check_srv_status(msg) != CM_TRUE) {
        LOG_RUN_ERR("Proc msg cmd:%u from remote node:%u fail, local status fail.", (uint32)dss_head->dss_cmd,
            dss_head->src_inst);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static status_t dss_process_remote_ack_prepare(dss_session_t *session, mes_msg_t *msg, dss_processor_t *processor)
{
    if (dss_check_srv_status(msg) != CM_TRUE) {
        dss_message_head_t *dss_head = (dss_message_head_t *)msg->buffer;
        LOG_RUN_ERR("Proc msg cmd:%u from remote node:%u fail, local status fail.", (uint32)dss_head->dss_cmd,
            dss_head->src_inst);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static void dss_process_message(uint32 work_idx, ruid_type ruid, mes_msg_t *msg)
{
    cm_reset_error();

    dss_config_t *inst_cfg = dss_get_inst_cfg();
    uint32 mes_sess_cnt = inst_cfg->params.channel_num + inst_cfg->params.work_thread_cnt;
    if (work_idx >= mes_sess_cnt) {
        cm_panic(0);
    }
    if (msg->size < DSS_MES_MSG_HEAD_SIZE) {
        LOG_DEBUG_ERR("invalid message req size.");
        return;
    }
    dss_message_head_t *dss_head = (dss_message_head_t *)msg->buffer;
    LOG_DEBUG_INF("Proc msg cmd:%u, src node:%u, dst node:%u begin.", 
        (uint32)(dss_head->dss_cmd), (uint32)(dss_head->src_inst), (uint32)(dss_head->dst_inst));

    dss_session_ctrl_t *session_ctrl = dss_get_session_ctrl();
    dss_session_t *session = &session_ctrl->sessions[work_idx];
    status_t ret;
    if (dss_head->size < DSS_MES_MSG_HEAD_SIZE) {
        LOG_DEBUG_ERR("Invalid message size");
        return;
    }
    dss_set_cluster_proto_vers((uint8)dss_head->src_inst, dss_head->sw_proto_ver);
    if (dss_head->msg_proto_ver > DSS_PROTO_VERSION) {
        uint32 curr_proto_ver = MIN(dss_head->sw_proto_ver, DSS_PROTO_VERSION);
        dss_ack_version_not_match(session, dss_head, curr_proto_ver);
        return;
    }
    if (dss_head->dss_cmd >= DSS_CMD_CEIL) {
        LOG_DEBUG_ERR("Invalid request received,cmd is %u.", (uint8)dss_head->dss_cmd);
        return;
    }
    dss_init_packet(&session->recv_pack, CM_FALSE);
    dss_init_packet(&session->send_pack, CM_FALSE);
    dss_init_set(&session->send_pack, dss_head->msg_proto_ver);
    session->proto_version = dss_head->msg_proto_ver;
    LOG_DEBUG_INF("dss process message, cmd is %u, proto_version is %u.", dss_head->dss_cmd, dss_head->msg_proto_ver);
    dss_processor_t *processor = &g_dss_processors[dss_head->dss_cmd];

    // from here, the proc need to give the ack and release message buf
    cm_latch_s(&g_dss_instance.switch_latch, DSS_DEFAULT_SESSIONID, CM_FALSE, LATCH_STAT(LATCH_SWITCH));
    if (processor->is_req) {
        ret = dss_process_remote_req_prepare(session, msg, processor);
    } else {
        ret = dss_process_remote_ack_prepare(session, msg, processor);
    }
    if (ret != CM_SUCCESS) {
        cm_unlatch(&g_dss_instance.switch_latch, LATCH_STAT(LATCH_SWITCH));
        return;
    }
    processor->proc(session, msg);
    cm_unlatch(&g_dss_instance.switch_latch, LATCH_STAT(LATCH_SWITCH));

    LOG_DEBUG_INF("Proc msg cmd:%u, src node:%u, dst node:%u end.", 
        (uint32)(dss_head->dss_cmd), (uint32)(dss_head->src_inst), (uint32)(dss_head->dst_inst));
}

// add function
static status_t dss_register_proc(void)
{
    mes_register_proc_func(dss_process_message);
    return CM_SUCCESS;
}

#define DSS_MES_PRIO_CNT 2
static void dss_set_mes_buffer_pool(unsigned long long recv_msg_buf_size, mes_profile_t *profile)
{
    uint32 pool_idx;
    for (uint32 i = 0; i < profile->priority_cnt; i++) {
        pool_idx = 0;
        profile->buffer_pool_attr[i].pool_count = DSS_BUFFER_POOL_NUM;
        profile->buffer_pool_attr[i].queue_count = DSS_MSG_BUFFER_QUEUE_NUM;

        // 64 buffer pool
        profile->buffer_pool_attr[i].buf_attr[pool_idx].count =
            (uint32)(recv_msg_buf_size * DSS_FIRST_BUFFER_RATIO) / DSS_FIRST_BUFFER_LENGTH;
        profile->buffer_pool_attr[i].buf_attr[pool_idx].size = DSS_FIRST_BUFFER_LENGTH;

        // 128 buffer pool
        pool_idx++;
        profile->buffer_pool_attr[i].buf_attr[pool_idx].count =
            (uint32)(recv_msg_buf_size * DSS_SECOND_BUFFER_RATIO) / DSS_SECOND_BUFFER_LENGTH;
        profile->buffer_pool_attr[i].buf_attr[pool_idx].size = DSS_SECOND_BUFFER_LENGTH;

        // 32k buffer pool
        pool_idx++;
        profile->buffer_pool_attr[i].buf_attr[pool_idx].count =
            (uint32)(recv_msg_buf_size * DSS_THIRDLY_BUFFER_RATIO) / DSS_THIRD_BUFFER_LENGTH;
        profile->buffer_pool_attr[i].buf_attr[pool_idx].size = DSS_THIRD_BUFFER_LENGTH;
    }
}

static void dss_set_group_task_num(dss_config_t *dss_profile, mes_profile_t *mes_profile)
{
    uint32 work_thread_cnt_load_meta =
        (uint32)(dss_profile->params.work_thread_cnt * DSS_WORK_THREAD_LOAD_DATA_PERCENT);
    if (work_thread_cnt_load_meta == 0) {
        work_thread_cnt_load_meta = 1;
    }
    uint32 work_thread_cnt_comm = (dss_profile->params.work_thread_cnt - work_thread_cnt_load_meta);
    mes_profile->send_directly = CM_TRUE;
    mes_profile->send_task_count[MES_PRIORITY_ZERO] = 0;
    mes_profile->work_task_count[MES_PRIORITY_ZERO] = work_thread_cnt_load_meta;
    mes_profile->recv_task_count[MES_PRIORITY_ZERO] = MAX(1, (uint32)(work_thread_cnt_load_meta * DSS_RECV_WORK_THREAD_RATIO));

    mes_profile->send_task_count[MES_PRIORITY_ONE] = 0;
    mes_profile->work_task_count[MES_PRIORITY_ONE] = work_thread_cnt_comm;
    mes_profile->recv_task_count[MES_PRIORITY_ONE] = MAX(1, (uint32)(work_thread_cnt_comm * DSS_RECV_WORK_THREAD_RATIO));
}

#define DSS_MES_FRAG_SIZE (32 * 1024)
static status_t dss_set_mes_profile(mes_profile_t *profile)
{
    errno_t errcode = memset_sp(profile, sizeof(mes_profile_t), 0, sizeof(mes_profile_t));
    securec_check_ret(errcode);

    dss_config_t *inst_cfg = dss_get_inst_cfg();
    profile->inst_id = (uint32)inst_cfg->params.inst_id;
    profile->pipe_type = (mes_pipe_type_t)inst_cfg->params.pipe_type;
    profile->channel_cnt = inst_cfg->params.channel_num;
    profile->conn_created_during_init = 0;
    profile->mes_elapsed_switch = inst_cfg->params.elapsed_switch;
    profile->inst_cnt = inst_cfg->params.inst_cnt;
    uint32 inst_cnt = 0;
    for (uint32 i = 0; i < DSS_MAX_INSTANCES; i++) {
        uint64_t inst_mask = ((uint64)0x1 << i);
        if ((inst_cfg->params.inst_map & inst_mask) == 0) {
            continue;
        }
        errcode = strncpy_s(
            profile->inst_net_addr[inst_cnt].ip, CM_MAX_IP_LEN, inst_cfg->params.nodes[i], strlen(inst_cfg->params.nodes[i]));
        if (errcode != EOK) {
            DSS_RETURN_IFERR2(CM_ERROR, DSS_THROW_ERROR(ERR_SYSTEM_CALL, (errcode)));
        }
        profile->inst_net_addr[inst_cnt].port = inst_cfg->params.ports[i];
        profile->inst_net_addr[inst_cnt].need_connect = CM_TRUE;
        profile->inst_net_addr[inst_cnt].inst_id = i;
        inst_cnt++;
        if (inst_cnt == inst_cfg->params.inst_cnt) {
            break;
        }
    }
    profile->priority_cnt = DSS_MES_PRIO_CNT;
    profile->frag_size = DSS_MES_FRAG_SIZE;
    profile->max_wait_time = inst_cfg->params.mes_wait_timeout;
    profile->connect_timeout = CM_CONNECT_TIMEOUT;
    profile->socket_timeout = CM_NETWORK_IO_TIMEOUT;

    dss_set_mes_buffer_pool(inst_cfg->params.mes_pool_size, profile);
    dss_set_group_task_num(inst_cfg, profile);
    profile->tpool_attr.enable_threadpool = CM_FALSE;
    return CM_SUCCESS;
}

static status_t dss_create_mes_session(void)
{
    dss_config_t *inst_cfg = dss_get_inst_cfg();
    uint32 mes_sess_cnt = inst_cfg->params.channel_num + inst_cfg->params.work_thread_cnt;
    dss_session_ctrl_t *session_ctrl = dss_get_session_ctrl();
    cm_spin_lock(&session_ctrl->lock, NULL);
    if (session_ctrl->used_count > 0) {
        DSS_RETURN_IFERR3(CM_ERROR,
            LOG_RUN_ERR("dss_create_mes_session failed, mes must occupy first %u sessions.", mes_sess_cnt),
            cm_spin_unlock(&session_ctrl->lock));
    }

    for (uint32 i = 0; i < mes_sess_cnt; i++) {
        session_ctrl->sessions[i].is_direct = CM_TRUE;
        session_ctrl->sessions[i].is_closed = CM_FALSE;
        session_ctrl->sessions[i].is_used = CM_FALSE;
    }
    session_ctrl->used_count = mes_sess_cnt;
    cm_spin_unlock(&session_ctrl->lock);
    return CM_SUCCESS;
}

status_t dss_startup_mes(void)
{
    if (g_dss_instance.is_maintain) {
        return CM_SUCCESS;
    }
    dss_config_t *inst_cfg = dss_get_inst_cfg();
    if (inst_cfg->params.inst_cnt <= 1) {
        return CM_SUCCESS;
    }

    status_t status = dss_register_proc();
    DSS_RETURN_IFERR2(status, LOG_RUN_ERR("dss_register_proc failed."));

    mes_profile_t profile;
    status = dss_set_mes_profile(&profile);
    DSS_RETURN_IFERR2(status, LOG_RUN_ERR("dss_set_mes_profile failed."));

    status = dss_create_mes_session();
    DSS_RETURN_IFERR2(status, LOG_RUN_ERR("dss_set_mes_profile failed."));

    regist_remote_read_proc(dss_read_volume_remote);
    regist_invalidate_other_nodes_proc(dss_invalidate_other_nodes);
    regist_broadcast_check_file_open_proc(dss_broadcast_check_file_open);
    regist_refresh_ft_by_primary_proc(dss_refresh_ft_by_primary);
    regist_get_node_by_path_remote_proc(dss_get_node_by_path_remote);
    return mes_init(&profile);
}

void dss_stop_mes(void)
{
    if (g_dss_instance.is_maintain) {
        return;
    }
    dss_config_t *inst_cfg = dss_get_inst_cfg();
    if (g_inst_cfg != NULL && inst_cfg->params.inst_cnt <= 1) {
        return;
    }
    mes_uninit();
}

status_t dss_notify_sync(char *buffer, uint32 size, dss_recv_msg_t *recv_msg)
{
    CM_ASSERT(buffer != NULL);
    CM_ASSERT(size < SIZE_K(1));
    dss_config_t *inst_cfg = dss_get_inst_cfg();
    uint32 timeout = inst_cfg->params.mes_wait_timeout;
    status_t status = dss_broadcast_msg(buffer, size, recv_msg, timeout);
    return status;
}

status_t dss_notify_expect_bool_ack(
    dss_vg_info_item_t *vg_item, dss_bcast_req_cmd_t cmd, uint64 ftid, bool32 *cmd_ack)
{
    if (g_dss_instance.is_maintain) {
        return CM_SUCCESS;
    }
    dss_recv_msg_t recv_msg = {CM_TRUE, *cmd_ack, DSS_PROTO_VERSION, 0, 0};
    recv_msg.broadcast_proto_ver = dss_get_broadcast_proto_ver(0);
    dss_notify_req_msg_t req;
    status_t status;
    dss_config_t *inst_cfg = dss_get_inst_cfg();
    dss_params_t *param = &inst_cfg->params;
    do {
        req.ftid = ftid;
        req.type = cmd;
        errno_t err = strncpy_s(req.vg_name, DSS_MAX_NAME_LEN, vg_item->vg_name, strlen(vg_item->vg_name));
        if (err != EOK) {
            DSS_THROW_ERROR(ERR_SYSTEM_CALL, err);
            return CM_ERROR;
        }
        LOG_DEBUG_INF("notify other dss instance to do cmd %u, ftid:%llu in vg:%s.", cmd, ftid, vg_item->vg_name);
        dss_init_mes_head(&req.dss_head, DSS_CMD_REQ_BROADCAST, 0, (uint16)param->inst_id, CM_INVALID_ID16,
            sizeof(dss_notify_req_msg_t), recv_msg.broadcast_proto_ver, 0);
        status = dss_notify_sync((char *)&req, req.dss_head.size, &recv_msg);
        if (status == ERR_DSS_VERSION_NOT_MATCH) {
            uint32 new_proto_ver = dss_get_broadcast_proto_ver(recv_msg.succ_inst);
            LOG_RUN_INF("[CHECK_PROTO]broadcast msg proto version has changed, old is %hhu, new is %hhu",
                recv_msg.broadcast_proto_ver, new_proto_ver);
            recv_msg.broadcast_proto_ver = new_proto_ver;
            recv_msg.version_not_match_inst = 0;
            // if msg has been changed, need rewrite req
            continue;
        } else {
            break;
        }
    } while (CM_TRUE);
    if (status != CM_SUCCESS) {
        LOG_RUN_ERR("[DSS] ABORT INFO: Failed to notify other dss instance, cmd: %u, file: %llu, vg: %s, errcode:%d, "
                    "OS errno:%d, OS errmsg:%s.",
            cmd, ftid, vg_item->vg_name, cm_get_error_code(), errno, strerror(errno));
        cm_fync_logfile();
        _exit(1);
    }
    *cmd_ack = recv_msg.cmd_ack;
    return status;
}

status_t dss_invalidate_other_nodes(dss_vg_info_item_t *vg_item, uint64 ftid, bool32 *cmd_ack)
{
    return dss_notify_expect_bool_ack(vg_item, BCAST_REQ_INVALIDATE_FS_META, ftid, cmd_ack);
}

status_t dss_broadcast_check_file_open(dss_vg_info_item_t *vg_item, uint64 ftid, bool32 *cmd_ack)
{
    return dss_notify_expect_bool_ack(vg_item, BCAST_REQ_DEL_DIR_FILE, ftid, cmd_ack);
}

static void dss_check_inst_conn(uint32_t id, uint64 old_inst_stat, uint64 cur_inst_stat)
{
    if (old_inst_stat == cur_inst_stat) {
        return;
    }
    if (old_inst_stat == 0) {
        (void)mes_connect_instance(id);
    } else {
        (void)mes_disconnect_instance(id);
    }
}

void dss_check_mes_conn(uint64 cur_inst_map)
{
    dss_config_t *inst_cfg = dss_get_inst_cfg();

    uint64 old_inst_map = dss_get_inst_work_status();
    if (old_inst_map == cur_inst_map) {
        return;
    }
    dss_set_inst_work_status(cur_inst_map);
    uint32 inst_cnt = 0;
    for (uint32_t id = 0; id < DSS_MAX_INSTANCES; id++) {
        if (id == inst_cfg->params.inst_id) {
            continue;
        }
        uint64_t inst_mask = ((uint64)0x1 << id);
        if ((inst_cfg->params.inst_map & inst_mask) == 0) {
            continue;
        }
        dss_check_inst_conn(id, (old_inst_map & inst_mask), (cur_inst_map & inst_mask));
        inst_cnt++;
        if (inst_cnt == inst_cfg->params.inst_cnt) {
            break;
        }
    }
}

static uint32 dss_get_remote_proto_ver(uint32 remoteid)
{
    if (remoteid >= DSS_MAX_INSTANCES) {
        LOG_DEBUG_ERR("Invalid remote id:%u.", remoteid);
        return DSS_PROTO_VERSION;
    }
    uint32 remote_proto_ver = (uint32)cm_atomic32_get((atomic32_t *)&g_dss_instance.cluster_proto_vers[remoteid]);
    if (remote_proto_ver == DSS_INVALID_VERSION) {
        return DSS_PROTO_VERSION;
    }
    remote_proto_ver = MIN(remote_proto_ver, DSS_PROTO_VERSION);
    return remote_proto_ver;
}

static int dss_get_mes_response(ruid_type ruid, mes_msg_t *response, int timeout_ms)
{
    int ret = mes_get_response(ruid, response, timeout_ms);
    if (ret == CM_SUCCESS) {
        dss_message_head_t *ack_head = (dss_message_head_t *)response->buffer;
        if (ack_head->size < DSS_MES_MSG_HEAD_SIZE) {
            LOG_RUN_ERR("Invalid message size");
            DSS_THROW_ERROR(ERR_DSS_MES_ILL, "msg len is invalid");
            mes_release_msg(response);
            return ERR_DSS_MES_ILL;
        }
        dss_set_cluster_proto_vers((uint8)ack_head->src_inst, ack_head->sw_proto_ver);
    }
    return ret;
}

status_t dss_exec_sync(dss_session_t *session, uint32 remoteid, uint32 currtid, status_t *remote_result)
{
    status_t ret = CM_ERROR;
    dss_message_head_t dss_head;
    mes_msg_t msg;
    dss_message_head_t *ack_head = NULL;
    dss_config_t *inst_cfg = dss_get_inst_cfg();
    uint32 timeout = inst_cfg->params.mes_wait_timeout;
    uint32 new_proto_ver = dss_get_version(&session->recv_pack);
    do {
        uint32 buf_size = DSS_MES_MSG_HEAD_SIZE + session->recv_pack.head->size;
        // 1.init mes head, dss head, dssbody
        dss_init_mes_head(
            &dss_head, DSS_CMD_REQ_SYB2ACTIVE, 0, (uint16)currtid, (uint16)remoteid, buf_size, new_proto_ver, 0);
        // 2. send request to remote
        ret = mes_send_request_x(
            dss_head.dst_inst, dss_head.flags, &dss_head.ruid, 2, &dss_head, DSS_MES_MSG_HEAD_SIZE, session->recv_pack.buf, session->recv_pack.head->size);
        char *err_msg = "The dss server fails to send messages to the remote node";
        DSS_RETURN_IFERR2(ret, LOG_RUN_ERR("%s, src node(%u), dst node(%u).", err_msg, currtid, remoteid));
        // 3. receive msg from remote
        ret = dss_get_mes_response(dss_head.ruid, &msg, timeout);
        DSS_RETURN_IFERR2(ret,
            LOG_RUN_ERR("dss server receive msg from remote failed, src node:%u, dst node:%u, cmd:%u.",
                currtid, remoteid, session->recv_pack.head->cmd));
        // 4. attach remote execution result
        ack_head = (dss_message_head_t *)msg.buffer;
        if (ack_head->result == ERR_DSS_VERSION_NOT_MATCH) {
            session->client_version = dss_get_client_version(&session->recv_pack);
            new_proto_ver = MIN(ack_head->sw_proto_ver, DSS_PROTO_VERSION);
            new_proto_ver = MIN(new_proto_ver, session->client_version);
            session->proto_version = new_proto_ver;
            if (session->proto_version != dss_get_version(&session->recv_pack)) {
                LOG_RUN_INF("[CHECK_PROTO]The client protocol version need be changed, old protocol version is %u, new protocol "
                            "version is %u",
                    dss_get_version(&session->recv_pack), session->proto_version);
                DSS_THROW_ERROR(
                    ERR_DSS_VERSION_NOT_MATCH, dss_get_version(&session->recv_pack), session->proto_version);
                *remote_result = ERR_DSS_VERSION_NOT_MATCH;
                mes_release_msg(&msg);
                return ret;
            } else {
                dss_head.msg_proto_ver = new_proto_ver;
                // if msg version has changed, please motify your change
                mes_release_msg(&msg);
                continue;
            }
        } else {
            break;
        }
    } while (CM_TRUE);
    // errcode|errmsg
    // data
    *remote_result = ack_head->result;
    uint32 body_size = ack_head->size - DSS_MES_MSG_HEAD_SIZE;
    if (*remote_result != CM_SUCCESS) {
        if (ack_head->size < sizeof(dss_remote_exec_fail_ack_t)) {
            DSS_RETURN_IFERR3(
                CM_ERROR, DSS_THROW_ERROR(ERR_DSS_MES_ILL, "msg len is invalid"), mes_release_msg(&msg));
        }
        dss_remote_exec_fail_ack_t *fail_ack = (dss_remote_exec_fail_ack_t *)msg.buffer;
        DSS_THROW_ERROR(ERR_DSS_PROCESS_REMOTE, fail_ack->err_code, fail_ack->err_msg);
    } else if (body_size > 0) {
        dss_remote_exec_succ_ack_t *succ_ack = (dss_remote_exec_succ_ack_t *)msg.buffer;
        LOG_DEBUG_INF("dss server receive msg from remote node, cmd:%u, ack to cli data size:%u.", 
            session->recv_pack.head->cmd, body_size);
        // do not parse the format
        ret = dss_put_data(&session->send_pack, succ_ack->body_buf, body_size);
    }
    mes_release_msg(&msg);
    return ret;
}

status_t dss_exec_on_remote(uint8 cmd, char *req, int32 req_size, char *ack, int ack_size, status_t *remote_result)
{
    status_t ret = CM_ERROR;
    dss_message_head_t *dss_head = (dss_message_head_t *)req;
    dss_message_head_t *ack_head = NULL;
    dss_session_t *session = NULL;
    uint32 remoteid = DSS_INVALID_ID32;
    uint32 currid = DSS_INVALID_ID32;
    dss_config_t *inst_cfg = dss_get_inst_cfg();
    uint32 timeout = inst_cfg->params.mes_wait_timeout;
    mes_msg_t msg;
    if (dss_create_session(NULL, &session) != CM_SUCCESS) {
        LOG_RUN_ERR("Exec cmd:%u on remote node create session fail.", (uint32)cmd);
        return CM_ERROR;
    }

    dss_get_exec_nodeid(session, &currid, &remoteid);
    LOG_DEBUG_INF("Exec cmd:%u on remote node:%u begin.", (uint32)cmd, remoteid);
    do {
        uint32 proto_ver = dss_get_remote_proto_ver(remoteid);
        // 1. init msg head
        dss_init_mes_head(dss_head, cmd, 0, (uint16)currid, (uint16)remoteid, req_size, proto_ver, 0);
        // 2. send request to remote
        ret = mes_send_request(remoteid, dss_head->flags, &dss_head->ruid, req, dss_head->size);
        if (ret != CM_SUCCESS) {
            LOG_RUN_ERR("Exec cmd:%u on remote node:%u  send msg fail.", (uint32)cmd, remoteid);
            dss_destroy_session(session);
            return ERR_DSS_MES_ILL;
        }
        // 3. receive msg from remote
        ret = dss_get_mes_response(dss_head->ruid, &msg, timeout);
        if (ret != CM_SUCCESS) {
            LOG_RUN_ERR("Exec cmd:%u on remote node:%u  recv msg fail.", (uint32)cmd, remoteid);
            dss_destroy_session(session);
            return ERR_DSS_MES_ILL;
        }
        ack_head = (dss_message_head_t *)msg.buffer;
        if (ack_head->result == ERR_DSS_VERSION_NOT_MATCH) {
            //if msg version has changed, please motify your change
            mes_release_msg(&msg);
            continue;
        }
        break;
    } while (CM_TRUE);
    // 4. attach remote execution result
    *remote_result = ack_head->result;
    LOG_DEBUG_INF("dss server receive msg from remote node, cmd:%u, ack to cli data size:%hu, remote_result:%u.", 
        ack_head->dss_cmd, ack_head->size, (uint32)*remote_result);
    if (*remote_result != CM_SUCCESS) {
        if (ack_head->size < sizeof(dss_remote_exec_fail_ack_t)) {
            DSS_THROW_ERROR(ERR_DSS_MES_ILL, "msg len is invalid");
            DSS_RETURN_IFERR3(CM_ERROR, dss_destroy_session(session), mes_release_msg(&msg));
        }
        dss_remote_exec_fail_ack_t *fail_ack = (dss_remote_exec_fail_ack_t *)msg.buffer;
        DSS_THROW_ERROR(ERR_DSS_PROCESS_REMOTE, fail_ack->err_code, fail_ack->err_msg);
    } else {
        if (ack_head->size != ack_size) {
            DSS_THROW_ERROR(ERR_DSS_MES_ILL, "msg len is invalid");
            DSS_RETURN_IFERR3(CM_ERROR, dss_destroy_session(session), mes_release_msg(&msg));
        }
        errno_t err = memcpy_s(ack, (size_t)ack_size, msg.buffer, (size_t)ack_head->size);
        if (err != EOK) {
            CM_THROW_ERROR(ERR_SYSTEM_CALL, err);
            ret = CM_ERROR;
        }
    }

    mes_release_msg(&msg);
    dss_destroy_session(session);
    LOG_DEBUG_INF("Exec cmd:%u on remote node:%u end.", (uint32)cmd, remoteid);
    return ret;
}

void dss_proc_syb2active_req(dss_session_t *session, mes_msg_t *msg)
{
    dss_message_head_t req_head = *(dss_message_head_t *)(msg->buffer);
    uint32 size = req_head.size - DSS_MES_MSG_HEAD_SIZE;
    uint16 srcid = req_head.src_inst;
    uint16 dstid = req_head.dst_inst;
    ruid_type ruid = req_head.ruid;
    if (size > DSS_MAX_PACKET_SIZE) {
        LOG_DEBUG_ERR(
            "The dss server receive msg from remote failed, src node:%u, dst node:%u, size is %u.", srcid, dstid, size);
        return;
    }
    LOG_DEBUG_INF("The dss server receive messages from remote node, src node:%u, dst node:%u.", srcid, dstid);
    errno_t errcode = memcpy_s(session->recv_pack.buf, size, msg->buffer + DSS_MES_MSG_HEAD_SIZE, size);
    if (errcode != EOK) {
        LOG_DEBUG_ERR("The dss server memcpy msg failed, src node:%u, dst node:%u.", srcid, dstid);
        return;
    }
    status_t ret = dss_proc_standby_req(session);
    char *body_buf = NULL;
    uint32 body_size = 0;
    status_t status = dss_prepare_ack_msg(session, ret, &body_buf, &body_size, req_head.msg_proto_ver);
    if (status != CM_SUCCESS) {
        LOG_DEBUG_ERR("The dss server prepare ack msg failed, src node:%u, dst node:%u.", srcid, dstid);
        return;
    }
    LOG_DEBUG_INF("The dss server send messages to the remote node, src node:%u, dst node:%u, cmd:%u,ack size:%u.",
        srcid, dstid, session->send_pack.head->cmd, body_size);
    dss_message_head_t ack;
    dss_init_mes_head(
        &ack, DSS_CMD_ACK_SYB2ACTIVE, 0, dstid, srcid, body_size + DSS_MES_MSG_HEAD_SIZE, req_head.msg_proto_ver, ruid);
    ack.result = ret;
    ret = mes_send_response_x(ack.dst_inst, ack.flags, ack.ruid, 2, &ack, DSS_MES_MSG_HEAD_SIZE, body_buf, body_size);
    if (ret != CM_SUCCESS) {
        LOG_DEBUG_ERR("The dss server fails to send messages to the remote node, src node:%u, dst node:%u.",
            (uint32)(ack.src_inst), (uint32)(ack.dst_inst));
        return;
    }
    LOG_DEBUG_INF("The dss server send messages to the remote node success, src node:%u, dst node:%u.",
        (uint32)(ack.src_inst), (uint32)(ack.dst_inst));
}

status_t dss_send2standby(big_packets_ctrl_t *ack, const char *buf)
{
    dss_message_head_t *dss_head = &ack->dss_head;
    status_t ret = mes_send_response_x(dss_head->dst_inst, dss_head->flags, dss_head->ruid, 2, ack,
        sizeof(big_packets_ctrl_t), buf, dss_head->size - sizeof(big_packets_ctrl_t));
    if (ret != CM_SUCCESS) {
        LOG_RUN_ERR("The dssserver fails to send messages to the remote node, src node:%u, dst node:%u.",
            (uint32)(dss_head->src_inst), (uint32)(dss_head->dst_inst));
        return ret;
    }

    LOG_DEBUG_INF("The dss server send messages to the remote node success, src node:%u, dst node:%u.",
        (uint32)(dss_head->src_inst), (uint32)(dss_head->dst_inst));
    return ret;
}

static void dss_loaddisk_lock(char *vg_name)
{
    dss_vg_info_item_t *vg_item = dss_find_vg_item(vg_name);
    if (vg_item != NULL) {
        dss_lock_vg_mem_s_force(vg_item);
    }
}

static void dss_loaddisk_unlock(char *vg_name)
{
    dss_vg_info_item_t *vg_item = dss_find_vg_item(vg_name);
    if (vg_item != NULL) {
        dss_unlock_vg_mem(vg_item);
    }
}

static void dss_load_shm_lock_s_force(dss_session_t *session, dss_vg_info_item_t*vg_item)
{
    dss_lock_vg_mem_s_force(vg_item);
    (void)dss_lock_shm_meta_s_without_stack(session, vg_item->vg_latch, CM_TRUE, SPIN_WAIT_FOREVER);
}

static void dss_load_shm_unlock(dss_session_t *session, dss_vg_info_item_t*vg_item)
{
    dss_unlock_vg_mem(vg_item);
    dss_unlock_shm_meta_without_stack(session, vg_item->vg_latch);
}

static int32 dss_batch_load_core(dss_session_t *session, dss_loaddisk_req_t *req, char *read_buff, uint32 version)
{
    uint32 remain = req->size;
    uint32 read_total = 0;
    big_packets_ctrl_t ctrl;
    dss_message_head_t *req_dss_head = &req->dss_head;
    (void)memset_s(&ctrl, sizeof(big_packets_ctrl_t), 0, sizeof(big_packets_ctrl_t));
    dss_init_mes_head(&ctrl.dss_head, DSS_CMD_ACK_LOAD_DISK, 0, req_dss_head->dst_inst, req_dss_head->src_inst,
        sizeof(big_packets_ctrl_t), version, req_dss_head->ruid);
    ctrl.totalsize = req->size;
    while (remain > 0) {
        if (session && session->is_closed) {
            LOG_RUN_ERR("session:%u is closed.", session->id);
            return CM_ERROR;
        }
        uint64 roffset = req->offset + read_total;
        uint32 each_size = (remain <= DSS_LOADDISK_BUFFER_SIZE) ? remain : DSS_LOADDISK_BUFFER_SIZE;
        if (dss_read_volume_4standby(req->vg_name, req->volumeid, (int64)roffset, read_buff, each_size) != CM_SUCCESS) {
            LOG_RUN_ERR("read volume for standby failed, vg name[%s], volume id[%u].", req->vg_name, req->volumeid);
            return DSS_READ4STANDBY_ERR;
        }
        read_total += each_size;
        remain -= each_size;

        ctrl.cursize = each_size;
        ctrl.endflag = (remain == 0) ? CM_TRUE : CM_FALSE;
        ctrl.dss_head.size = each_size + sizeof(big_packets_ctrl_t);
        if (dss_send2standby(&ctrl, read_buff) != CM_SUCCESS) {
            LOG_RUN_ERR(
                "read volume for standby send msg failed, vg name[%s], volume id[%u].", req->vg_name, req->volumeid);
            return CM_ERROR;
        }

        LOG_DEBUG_INF("load disk from active info vg name(%s) volume id(%u) msg seq(%hu) msg len(%u).", req->vg_name,
            req->volumeid, ctrl.seq, ctrl.cursize);
        
        ctrl.offset += each_size;
        ctrl.seq++;
    }
    return CM_SUCCESS;
}

int32 dss_batch_load(dss_session_t *session, dss_loaddisk_req_t *req, uint32 version)
{
    if (req->size % DSS_DISK_UNIT_SIZE != 0) {
        return DSS_READ4STANDBY_ERR;
    }
    if (g_thv_read_buf == NULL) {
        g_thv_read_buf = (char *)cm_malloc_align(DSS_DISK_UNIT_SIZE, DSS_LOADDISK_BUFFER_SIZE);
        if (g_thv_read_buf == NULL) {
            DSS_RETURN_IFERR2(
                DSS_READ4STANDBY_ERR, DSS_THROW_ERROR(ERR_ALLOC_MEMORY, DSS_LOADDISK_BUFFER_SIZE, "g_thv_read_buf"));
        }
    }
    dss_loaddisk_lock(req->vg_name);
    int32 ret = dss_batch_load_core(session, req, g_thv_read_buf, version);
    dss_loaddisk_unlock(req->vg_name);
    return ret;
}

void dss_proc_loaddisk_req(dss_session_t *session, mes_msg_t *msg)
{
    int32 ret = CM_ERROR;
    dss_loaddisk_req_t *req = (dss_loaddisk_req_t *)msg->buffer;
    dss_message_head_t *req_dss_head = &req->dss_head;
    if (req_dss_head->size != sizeof(dss_loaddisk_req_t)) {
        LOG_RUN_ERR("Invalid reveive msg size from remote failed, src node(%hu), dst node(%hu).",
            req_dss_head->src_inst, req_dss_head->dst_inst);
        return;
    }
    
    if (dss_is_readonly() == CM_TRUE) {
        dss_config_t *cfg = dss_get_inst_cfg();
        LOG_RUN_ERR("The local node:%u is in readonly state and cannot execute remote loaddisk requests.",
            (uint32)(cfg->params.inst_id));
        dss_proc_remote_req_err(session, req_dss_head, DSS_CMD_ACK_LOAD_DISK, ret);
        return;
    }
    LOG_DEBUG_INF("Exec load disk req, src node(%hu), volume id:%u, offset:%llu, size:%u.",
        req_dss_head->src_inst, req->volumeid, req->offset, req->size);
    if (dss_check_srv_status(msg) != CM_TRUE) {
        dss_proc_remote_req_err(session, req_dss_head, DSS_CMD_ACK_LOAD_DISK, ret);
        return;
    }
    ret = dss_batch_load(session, req, req_dss_head->msg_proto_ver);
    if (ret != CM_SUCCESS) {
        LOG_RUN_ERR("Exec load disk req failed, src node:%u, volume id:%u, offset:%llu, size:%u.", (uint32)(req_dss_head->src_inst),
            req->volumeid, req->offset, req->size);
        dss_proc_remote_req_err(session, &req->dss_head, DSS_CMD_ACK_LOAD_DISK, ret);
    }
    return;
}

static status_t dss_init_readvlm_remote_params(
    dss_loaddisk_req_t *req, const char *entry, uint32 *currid, uint32 *remoteid, dss_session_t *session)
{
    errno_t errcode = memset_s(req, sizeof(dss_loaddisk_req_t), 0, sizeof(dss_loaddisk_req_t));
    securec_check_ret(errcode);
    errcode = memcpy_s(req->vg_name, DSS_MAX_NAME_LEN, entry, DSS_MAX_NAME_LEN);
    securec_check_ret(errcode);
    dss_get_exec_nodeid(session, currid, remoteid);
    if (*currid == *remoteid) {
        LOG_DEBUG_ERR("read from current node %u no need to send message.", *currid);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static bool32 dss_packets_verify(big_packets_ctrl_t *lastctrl, big_packets_ctrl_t *ctrl)
{
    if ((ctrl->endflag != CM_TRUE) || (ctrl->cursize + ctrl->offset != ctrl->totalsize)) {
        return CM_FALSE;
    }

    *lastctrl = *ctrl;
    return CM_TRUE;
}

static status_t dss_rec_msgs(ruid_type ruid, void *buf, uint32 size)
{
    mes_msg_t msg;
    big_packets_ctrl_t lastctrl;
    (void)memset_s(&lastctrl, sizeof(big_packets_ctrl_t), 0, sizeof(big_packets_ctrl_t));
    big_packets_ctrl_t *ctrl;
    dss_config_t *inst_cfg = dss_get_inst_cfg();
    uint32 timeout = inst_cfg->params.mes_wait_timeout;
    do {
        status_t ret = dss_get_mes_response(ruid, &msg, timeout);
        if (ret != CM_SUCCESS) {
            LOG_RUN_ERR("dss server receive msg from remote node failed, result:%d.", ret);
            return ret;
        }
        dss_message_head_t *ack_head = (dss_message_head_t *)msg.buffer;
        if (ack_head->result == ERR_DSS_VERSION_NOT_MATCH) {
            mes_release_msg(&msg);
            return ERR_DSS_VERSION_NOT_MATCH;
        }
        if (ack_head->size < sizeof(big_packets_ctrl_t)) {
            ret = CM_ERROR;
            LOG_RUN_ERR("Dss load disk from remote node failed invalid size, msg len(%d) error.", ack_head->size);
            if (ack_head->size == DSS_MES_MSG_HEAD_SIZE) {
                ret = ack_head->result;
            }
            mes_release_msg(&msg);
            return ret;
        }
        ctrl = (big_packets_ctrl_t *)msg.buffer;
        if (dss_packets_verify(&lastctrl, ctrl) == CM_FALSE) {
            mes_release_msg(&msg);
            LOG_RUN_ERR("dss server receive msg verify failed.");
            return CM_ERROR;
        }
        if (size < ctrl->offset + ctrl->cursize || ack_head->size != (sizeof(big_packets_ctrl_t) + ctrl->cursize)) {
            mes_release_msg(&msg);
            LOG_RUN_ERR("dss server receive msg size is invalid.");
            return CM_ERROR;
        }
        errno_t errcode =
            memcpy_s((char *)buf + ctrl->offset, ctrl->cursize, msg.buffer + sizeof(big_packets_ctrl_t), ctrl->cursize);
        mes_release_msg(&msg);
        securec_check_ret(errcode);
    } while (ctrl->endflag != CM_TRUE);

    return CM_SUCCESS;
}

static status_t dss_read_volume_remote_core(dss_session_t *session, dss_loaddisk_req_t *req, void *buf)
{
    status_t ret = CM_ERROR;
    do {
        dss_message_head_t *dss_head = &req->dss_head;
        LOG_DEBUG_INF("Ready msg cmd:%u, src node:%u, dst node:%u end",
            dss_head->dss_cmd, (uint32)(dss_head->src_inst), (uint32)(dss_head->dst_inst));
        // 2. send request to remote
        ret = mes_send_request(dss_head->dst_inst, dss_head->flags, &dss_head->ruid, (char *)req, dss_head->size);
        if (ret != CM_SUCCESS) {
            LOG_RUN_ERR("The dssserver fails to send messages to the remote node, src node (%u), dst node(%u).",
                dss_head->src_inst, dss_head->dst_inst);
            return ret;
        }
        // 3. receive msg from remote
        ret = dss_rec_msgs(dss_head->ruid, buf, req->size);
        if (ret == ERR_DSS_VERSION_NOT_MATCH) {
            req->dss_head.msg_proto_ver = dss_get_remote_proto_ver(req->dss_head.dst_inst);
            // if msg version has changed, please motify your change
            continue;
        }
        break;
    } while (CM_TRUE);
    return ret;
}

status_t dss_read_volume_remote(const char *vg_name, dss_volume_t *volume, int64 offset, void *buf, int32 size)
{
    status_t ret = CM_ERROR;
    dss_loaddisk_req_t req;
    dss_session_t *session = NULL;
    uint32 remoteid = DSS_INVALID_ID32;
    uint32 currid = DSS_INVALID_ID32;
    uint32 volumeid = volume->id;

    if (dss_create_session(NULL, &session) != CM_SUCCESS) {
        LOG_RUN_ERR("read volume from active node create session failed.");
        return CM_ERROR;
    }

    ret = dss_init_readvlm_remote_params(&req, vg_name, &currid, &remoteid, session);
    if (ret != CM_SUCCESS || currid == remoteid) {
        dss_destroy_session(session);
        return CM_ERROR;
    }

    LOG_DEBUG_INF(
        "instance %u start to load %d data of disk(%s) from the primary node:%u.", currid, size, vg_name, remoteid);
    req.volumeid = volumeid;
    req.offset= (uint64)offset;
    req.size = (uint32)size;
    // 1. init msg head
    uint32 remote_proto_ver = dss_get_remote_proto_ver(remoteid);
    dss_init_mes_head(&req.dss_head, DSS_CMD_REQ_LOAD_DISK, 0, (uint16)currid, (uint16)remoteid, sizeof(dss_loaddisk_req_t), remote_proto_ver, 0);
    ret = dss_read_volume_remote_core(session, &req, buf);
    dss_destroy_session(session);
    if (ret != CM_SUCCESS) {
        LOG_RUN_ERR(
            "The dssserver receive messages from remote node failed, src node:%u, dst node:%u.", currid, remoteid);
        return ret;
    }

    LOG_DEBUG_INF("load disk(%s) data from the active node success.", vg_name);
    return CM_SUCCESS;
}

status_t dss_join_cluster(bool32 *join_succ)
{
    *join_succ = CM_FALSE;

    LOG_DEBUG_INF("Try join cluster begin.");

    dss_join_cluster_req_t req;
    dss_config_t *cfg = dss_get_inst_cfg();
    req.reg_id = (uint32)(cfg->params.inst_id);

    status_t remote_result;
    dss_join_cluster_ack_t ack;
    status_t ret = dss_exec_on_remote(DSS_CMD_REQ_JOIN_CLUSTER, (char *)&req, sizeof(dss_join_cluster_req_t),
        (char *)&ack, sizeof(dss_join_cluster_ack_t), &remote_result);
    if (ret != CM_SUCCESS || remote_result != CM_SUCCESS) {
        LOG_RUN_ERR("Try join cluster exec fail.");
        return CM_ERROR;
    }
    if (ack.is_reg) {
        *join_succ = CM_TRUE;
    }

    LOG_DEBUG_INF("Try join cluster exec result:%u.", (uint32)*join_succ);
    return CM_SUCCESS;
}

void dss_proc_join_cluster_req(dss_session_t *session, mes_msg_t *msg)
{
    dss_message_head_t *req_head = (dss_message_head_t *)msg->buffer;
    if (req_head->size != sizeof(dss_join_cluster_req_t)) {
        LOG_RUN_ERR("Proc join cluster from remote node:%u check req msg fail.", (uint32)(req_head->src_inst));
        return;
    }

    dss_join_cluster_req_t *req = (dss_join_cluster_req_t *)msg->buffer;
    uint16 dst_inst = req_head->src_inst;
    uint16 src_inst = req_head->dst_inst;
    uint32 version = req_head->msg_proto_ver;
    ruid_type ruid = req_head->ruid;
    // please solve with your proto_ver
    LOG_DEBUG_INF(
        "Proc join cluster from remote node:%u reg node:%u begin.", (uint32)(req_head->src_inst), req->reg_id);
    
    // only in the work_status map can join the cluster

    dss_join_cluster_ack_t ack;
    dss_init_mes_head(&ack.ack_head, DSS_CMD_ACK_JOIN_CLUSTER, 0, src_inst, dst_inst, sizeof(dss_join_cluster_ack_t), version, ruid);
    ack.is_reg = CM_FALSE;
    ack.ack_head.result = CM_SUCCESS;
    uint64 work_status = dss_get_inst_work_status();
    uint64 inst_mask = ((uint64)0x1 << req->reg_id);
    if (work_status & inst_mask) {
        ack.is_reg = CM_TRUE;
    }

    LOG_DEBUG_INF("Proc join cluster from remote node:%u, reg node:%u, is_reg:%u.", (uint32)(req_head->src_inst),
        req->reg_id, (uint32)ack.is_reg);
    int send_ret = mes_send_response(dst_inst, ack.ack_head.flags, ruid, (char *)&ack, ack.ack_head.size);
    if (send_ret != CM_SUCCESS) {
        LOG_RUN_ERR("Proc join cluster from remote node:%u, reg node:%u send ack fail.", (uint32)dst_inst,
            req->reg_id);
        return;
    }

    LOG_DEBUG_INF("Proc join cluster from remote node:%u, reg node:%u send ack size:%u end.",
        (uint32)dst_inst, req->reg_id, ack.ack_head.size);
}

static status_t dss_get_node_by_path_inner(dss_session_t *session, dss_check_dir_output_t *output_info,
    dss_get_ft_block_ack_t *ack, dss_vg_info_item_t *ack_vg_item, dss_ft_block_t **shm_block)
{
    if (dss_cmp_blockid(ack->parent_node_id, DSS_INVALID_64)) {
        return CM_SUCCESS;
    }
    if (!dss_read_remote_checksum(ack->parent_block, DSS_BLOCK_SIZE)) {
        DSS_THROW_ERROR(ERR_DSS_MES_ILL, "Invalid get ft block ack msg block checksum error.");
        return CM_ERROR;
    }
    if (is_ft_root_block(ack->parent_node_id)) {
        dss_root_ft_block_t *ft_block = (dss_root_ft_block_t *)ack->parent_block;
        if (ack->parent_node_id.item >= ft_block->ft_block.node_num) {
            DSS_THROW_ERROR(ERR_DSS_MES_ILL, "Invalid get ft block ack msg parent_node_id item error.");
            return CM_ERROR;
        }
        char *root = ack_vg_item->dss_ctrl->root;
        errno_t errcode = memcpy_s(root, DSS_BLOCK_SIZE, ack->parent_block, DSS_BLOCK_SIZE);
        if (errcode != EOK) {
            CM_THROW_ERROR(ERR_SYSTEM_CALL, (errcode));
            return CM_ERROR;
        }
        if (output_info->parent_node != NULL) {
            *output_info->parent_node =
                (gft_node_t *)((root + sizeof(dss_root_ft_block_t)) + ack->parent_node_id.item * sizeof(gft_node_t));
        }
        return CM_SUCCESS;
    }
    dss_block_id_t block_id = ack->parent_node_id;
    block_id.item = 0;
    *shm_block = NULL;
    status_t ret = dss_refresh_block_in_shm(
        session, *output_info->item, block_id, DSS_BLOCK_TYPE_FT, ack->parent_block, (char **)shm_block);
    if (ret == CM_SUCCESS && output_info->parent_node != NULL) {
        *output_info->parent_node = dss_get_ft_node_by_block(*shm_block, ack->parent_node_id.item);
    }
    return ret;
}

status_t dss_get_node_by_path_remote(dss_session_t *session, const char *dir_path, gft_item_type_t type,
    dss_check_dir_output_t *output_info, bool32 is_throw_err)
{
    dss_get_ft_block_req_t req;
    req.type = type;
    errno_t errcode = strncpy_s(req.path, sizeof(req.path), dir_path, strlen(dir_path));
    DSS_SECUREC_SS_RETURN_IF_ERROR(errcode, CM_ERROR);

    status_t remote_result;
    dss_get_ft_block_ack_t ack;
    status_t ret = dss_exec_on_remote(DSS_CMD_REQ_GET_FT_BLOCK, (char *)&req, sizeof(dss_get_ft_block_req_t),
        (char *)&ack, sizeof(dss_get_ft_block_ack_t), &remote_result);
    DSS_RETURN_IFERR2(ret, LOG_RUN_ERR("Try get node by path remote failed."));
    DSS_RETURN_IF_ERROR(remote_result);
    if (dss_cmp_blockid(ack.node_id, DSS_INVALID_64)) {
        DSS_THROW_ERROR(ERR_DSS_MES_ILL, "Invalid get ft block id ack msg error.");
        return CM_ERROR;
    }
    if (!dss_read_remote_checksum(ack.block, DSS_BLOCK_SIZE)) {
        DSS_THROW_ERROR(ERR_DSS_MES_ILL, "Invalid get ft block ack msg block checksum error.");
        return CM_ERROR;
    }
    dss_vg_info_item_t *ack_vg_item = dss_find_vg_item(ack.vg_name);
    if (ack_vg_item == NULL) {
        DSS_THROW_ERROR(ERR_DSS_MES_ILL, "Invalid get ft block ack msg vg_name is not exist.");
        return CM_ERROR;
    }
    if (output_info->item != NULL) {
        *output_info->item = ack_vg_item;
    }
    dss_ft_block_t *shm_block = NULL;
    dss_block_id_t block_id = ack.node_id;
    if (is_ft_root_block(ack.node_id)) {
        dss_root_ft_block_t *ft_block = (dss_root_ft_block_t *)ack.block;
        if (ack.node_id.item >= ft_block->ft_block.node_num) {
            DSS_THROW_ERROR(ERR_DSS_MES_ILL, "Invalid get ft block ack msg node_id item error.");
            return CM_ERROR;
        }
        char *root = ack_vg_item->dss_ctrl->root;
        errcode = memcpy_s(root, DSS_BLOCK_SIZE, ack.block, DSS_BLOCK_SIZE);
        securec_check_ret(errcode);
        if (output_info->out_node != NULL) {
            *output_info->out_node =
                (gft_node_t *)((root + sizeof(dss_root_ft_block_t)) + ack.node_id.item * sizeof(gft_node_t));
        }
    } else {
        block_id.item = 0;
        ret = dss_refresh_block_in_shm(
            session, *output_info->item, block_id, DSS_BLOCK_TYPE_FT, ack.block, (char **)&shm_block);
        DSS_RETURN_IF_ERROR(ret);
        if (output_info->out_node != NULL) {
            *output_info->out_node = dss_get_ft_node_by_block(shm_block, ack.node_id.item);
        }
    }
    return dss_get_node_by_path_inner(session, output_info, &ack, ack_vg_item, &shm_block);
}

status_t dss_refresh_ft_by_primary(dss_block_id_t blockid, uint32 vgid, char *vg_name)
{
    LOG_DEBUG_INF("Try refresh ft by primary begin.");

    dss_refresh_ft_req_t req;

    req.blockid = blockid;
    req.vgid = vgid;

    if (strncpy_s(req.vg_name, sizeof(req.vg_name), vg_name, strlen(vg_name)) != EOK) {
        LOG_DEBUG_ERR("Try refresh ft by primary req vg_name fail.");
        return CM_ERROR;
    }

    status_t remote_result;
    dss_refresh_ft_ack_t ack;

    status_t ret = dss_exec_on_remote(DSS_CMD_REQ_REFRESH_FT, (char *)&req, sizeof(dss_refresh_ft_req_t), (char *)&ack,
        sizeof(dss_refresh_ft_ack_t), &remote_result);
    if (ret != CM_SUCCESS || remote_result != CM_SUCCESS) {
        LOG_DEBUG_ERR("Try refresh ft by primary exec on remote fail.");
        return CM_ERROR;
    }

    LOG_DEBUG_INF("Try refresh ft by primary result:%u.", ack.is_ok);
    if (!ack.is_ok) {
        LOG_DEBUG_ERR("Try refresh ft by primary ack is not ok.");
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

static status_t dss_proc_get_ft_block_req_core(
    dss_session_t *session, dss_get_ft_block_req_t *req, dss_get_ft_block_ack_t *ack, dss_vg_info_item_t **vg_item)
{
    gft_node_t *out_node = NULL;
    gft_node_t *parent_node = NULL;
    dss_vg_info_item_t *file_vg_item = *vg_item;
    dss_check_dir_output_t output_info = {&out_node, &file_vg_item, &parent_node, CM_FALSE};
    DSS_RETURN_IF_ERROR(dss_check_dir(session, req->path, req->type, &output_info, CM_TRUE));
    if (file_vg_item->id != (*vg_item)->id) {
        LOG_DEBUG_INF("Change shm lock when get link path :%s, src vg id:%u, dst vg id:%u.", req->path, (*vg_item)->id,
            file_vg_item->id);
        dss_load_shm_unlock(session, *vg_item);
        *vg_item = file_vg_item;
        dss_load_shm_lock_s_force(session, *vg_item);
    }
    ack->node_id = out_node->id;
    DSS_LOG_DEBUG_OP("Req out node, v:%u,au:%llu,block:%u,item:%u,type:%d,path:%s.", out_node->id.volume,
        (uint64)out_node->id.au, out_node->id.block, out_node->id.item, req->type, req->path);
    dss_ft_block_t *block = dss_get_ft_block_by_node(out_node);
    errno_t errcode = memcpy_s(ack->block, DSS_BLOCK_SIZE, block, DSS_BLOCK_SIZE);
    if (errcode != EOK) {
        CM_THROW_ERROR(ERR_SYSTEM_CALL, (errcode));
        return CM_ERROR;
    }
    errcode = strncpy_sp(ack->vg_name, DSS_MAX_NAME_LEN, file_vg_item->vg_name, strlen(file_vg_item->vg_name));
    if (errcode != EOK) {
        CM_THROW_ERROR(ERR_SYSTEM_CALL, (errcode));
        return CM_ERROR;
    }
    if (parent_node != NULL) {
        ack->parent_node_id = parent_node->id;
        DSS_LOG_DEBUG_OP("Req parent node, v:%u,au:%llu,block:%u,item:%u,type:%d,path:%s.", parent_node->id.volume,
            (uint64)parent_node->id.au, parent_node->id.block, parent_node->id.item, req->type, req->path);
        block = dss_get_ft_block_by_node(parent_node);
        errcode = memcpy_s(ack->parent_block, DSS_BLOCK_SIZE, block, DSS_BLOCK_SIZE);
        if (errcode != EOK) {
            CM_THROW_ERROR(ERR_SYSTEM_CALL, (errcode));
            return CM_ERROR;
        }
    } else {
        dss_set_blockid(&ack->parent_node_id, DSS_INVALID_64);
    }
    return CM_SUCCESS;
}

void dss_proc_get_ft_block_req(dss_session_t *session, mes_msg_t *msg)
{
    if (msg->size != sizeof(dss_get_ft_block_req_t)) {
        LOG_RUN_ERR("Get ft block from remote node check req msg size fail.");
        return;
    }
    dss_get_ft_block_req_t *req = (dss_get_ft_block_req_t *)msg->buffer;
    uint16 src_inst = req->dss_head.dst_inst;
    uint16 dst_inst = req->dss_head.src_inst;
    ruid_type ruid = req->dss_head.ruid;
    uint32 proto_ver = req->dss_head.msg_proto_ver;
    // please solve with your proto_ver
    if (req->type > GFT_LINK) {
        LOG_RUN_ERR(
            "Get ft block from remote node:%u check req msg type:%d fail.", (uint32)dst_inst, req->type);
        dss_proc_remote_req_err(session, &req->dss_head, DSS_CMD_ACK_GET_FT_BLOCK, CM_ERROR);
        return;
    }
    status_t status = dss_check_device_path(req->path);
    if (status != CM_SUCCESS) {
        dss_proc_remote_req_err(session, &req->dss_head, DSS_CMD_ACK_GET_FT_BLOCK, status);
        return;
    }
    LOG_DEBUG_INF("Get ft block from remote node:%u, path:%s begin.", (uint32)dst_inst, req->path);
    uint32 beg_pos = 0;
    char vg_name[DSS_MAX_NAME_LEN];
    status = dss_get_name_from_path(req->path, &beg_pos, vg_name);
    if (status != CM_SUCCESS) {
        dss_proc_remote_req_err(session, &req->dss_head, DSS_CMD_ACK_GET_FT_BLOCK, status);
    }
    dss_get_ft_block_ack_t ack;
    dss_init_mes_head(&ack.ack_head, DSS_CMD_ACK_GET_FT_BLOCK, 0, src_inst, dst_inst, sizeof(dss_get_ft_block_ack_t), proto_ver, ruid);
    dss_vg_info_item_t *vg_item = dss_find_vg_item(vg_name);
    if (vg_item == NULL) {
        LOG_RUN_ERR("invalid vg name: %s ,Get vg item fail.", vg_name);
        DSS_THROW_ERROR(ERR_DSS_VG_NOT_EXIST, vg_name);
        return;
    }
    dss_load_shm_lock_s_force(session, vg_item);
    status = dss_proc_get_ft_block_req_core(session, req, &ack, &vg_item);
    dss_load_shm_unlock(session, vg_item);
    if (status != CM_SUCCESS) {
        dss_proc_remote_req_err(session, &req->dss_head, DSS_CMD_ACK_GET_FT_BLOCK, status);
        return;
    }
    ack.ack_head.result = CM_SUCCESS;
    int send_ret = mes_send_response(dst_inst, ack.ack_head.flags, ruid, (char *)&ack, ack.ack_head.size);
    if (send_ret != CM_SUCCESS) {
        LOG_RUN_ERR(
            "Get ft block from remote node:%u, path:%s send ack fail.", (uint32)(dst_inst), req->path);
    } else {
        LOG_DEBUG_INF("Get ft block from remote node:%u, path:%s end.", (uint32)(dst_inst), req->path);
    }
}

void dss_proc_refresh_ft_by_primary_req(dss_session_t *session, mes_msg_t *msg)
{
    dss_message_head_t *req_head = (dss_message_head_t *)msg->buffer;
    if (req_head->size != sizeof(dss_refresh_ft_req_t)) {
        LOG_RUN_ERR("Refresh ft by primary from remote node:%u check req msg fail.", (uint32)(req_head->src_inst));
        return;
    }

    dss_refresh_ft_req_t *refresh_ft_req = (dss_refresh_ft_req_t *)msg->buffer;
    // please solve with your proto_ver
    LOG_DEBUG_INF("Refresh ft by primary from remote node:%u, blockid:%llu, vgid:%u, vg_name:%s begin.",
        (uint32)(req_head->src_inst), DSS_ID_TO_U64(refresh_ft_req->blockid), refresh_ft_req->vgid,
        refresh_ft_req->vg_name);
    if (dss_refresh_ft_block(session, refresh_ft_req->vg_name, refresh_ft_req->vgid, refresh_ft_req->blockid) != CM_SUCCESS) {
        LOG_RUN_ERR("Refresh ft by primary from remote node:%u, blockid:%llu, vgid:%u, vg_name:%s refresh fail.",
            (uint32)(req_head->src_inst), DSS_ID_TO_U64(refresh_ft_req->blockid), refresh_ft_req->vgid,
            refresh_ft_req->vg_name);
        dss_proc_remote_req_err(session, &refresh_ft_req->dss_head, DSS_CMD_ACK_REFRESH_FT, CM_ERROR);
        return;
    }
    uint16 dst_inst = req_head->src_inst;
    uint16 src_inst = req_head->dst_inst;
    uint32 version = req_head->msg_proto_ver;
    ruid_type ruid = req_head->ruid;
    dss_refresh_ft_ack_t ack;
    dss_init_mes_head(
        &ack.ack_head, DSS_CMD_ACK_REFRESH_FT, 0, src_inst, dst_inst, sizeof(dss_refresh_ft_ack_t), version, ruid);
    ack.is_ok = CM_TRUE;
    ack.ack_head.result = CM_SUCCESS;
    int send_ret = mes_send_response(dst_inst, ack.ack_head.flags, ruid, (char *)&ack, ack.ack_head.size);
    if (send_ret != CM_SUCCESS) {
        LOG_RUN_ERR("Refresh ft by primary from remote node:%u, blockid:%llu, vgid:%u, vg_name:%s send ack fail.",
            (uint32)dst_inst, DSS_ID_TO_U64(refresh_ft_req->blockid), refresh_ft_req->vgid,
            refresh_ft_req->vg_name);
        return;
    }

    LOG_DEBUG_INF("Refresh ft by primary from remote node:%u, blockid:%llu, vgid:%u, vg_name:%s refresh end.",
        (uint32)dst_inst, DSS_ID_TO_U64(refresh_ft_req->blockid), refresh_ft_req->vgid,
        refresh_ft_req->vg_name);
}