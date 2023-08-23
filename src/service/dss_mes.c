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

void dss_proc_broadcast_req(dss_session_t *session, mes_message_t *msg);
void dss_proc_broadcast_ack2(dss_session_t *session, mes_message_t *msg);
void dss_proc_syb2active_req(dss_session_t *session, mes_message_t *msg);
void dss_proc_loaddisk_req(dss_session_t *session, mes_message_t *msg);
void dss_proc_join_cluster_req(dss_session_t *session, mes_message_t *msg);
void dss_proc_refresh_ft_by_primary_req(dss_session_t *session, mes_message_t *msg);

void dss_proc_normal_ack(dss_session_t *session, mes_message_t *msg)
{
    LOG_DEBUG_INF("Receive ack(%u),src inst(%u), dst inst(%u).", (uint32)(msg->head->cmd),
        (uint32)(msg->head->src_inst), (uint32)(msg->head->dst_inst));
    mes_notify_msg_recv(msg);
}

dss_processor_t g_dss_processors[DSS_CMD_CEIL] = {
    [DSS_CMD_REQ_BROADCAST] = {dss_proc_broadcast_req, CM_TRUE, CM_TRUE, MES_TASK_GROUP_ZERO, "dss broadcast"},
    [DSS_CMD_ACK_BROADCAST_WITH_MSG] = {dss_proc_broadcast_ack2, CM_FALSE, CM_FALSE, MES_TASK_GROUP_ZERO,
        "dss broadcast ack with data"},
    [DSS_CMD_REQ_SYB2ACTIVE] = {dss_proc_syb2active_req, CM_TRUE, CM_TRUE, MES_TASK_GROUP_ZERO,
        "dss standby to active req"},
    [DSS_CMD_ACK_SYB2ACTIVE] = {dss_proc_normal_ack, CM_FALSE, CM_FALSE, MES_TASK_GROUP_ZERO,
        "dss active to standby ack"},
    [DSS_CMD_REQ_LOAD_DISK] = {dss_proc_loaddisk_req, CM_TRUE, CM_TRUE, MES_TASK_GROUP_ONE,
        "dss standby load disk to active req"},
    [DSS_CMD_ACK_LOAD_DISK] = {dss_proc_normal_ack, CM_FALSE, CM_FALSE, MES_TASK_GROUP_ONE,
        "dss active load disk to standby ack"},
    [DSS_CMD_REQ_JOIN_CLUSTER] = {dss_proc_join_cluster_req, CM_TRUE, CM_TRUE, MES_TASK_GROUP_ZERO,
        "dss standby join in cluster to active req"},
    [DSS_CMD_ACK_JOIN_CLUSTER] = {dss_proc_normal_ack, CM_FALSE, CM_FALSE, MES_TASK_GROUP_ZERO,
        "dss active proc join in cluster to standby ack"},
    [DSS_CMD_REQ_REFRESH_FT] = {dss_proc_refresh_ft_by_primary_req, CM_TRUE, CM_TRUE, MES_TASK_GROUP_ZERO,
        "dss standby refresh ft by primary req"},
    [DSS_CMD_ACK_REFRESH_FT] = {dss_proc_normal_ack, CM_FALSE, CM_FALSE, MES_TASK_GROUP_ZERO,
        "dss active refresh ft to standby ack"},
};

void dss_proc_broadcast_ack2(dss_session_t *session, mes_message_t *msg)
{
    mes_notify_broadcast_msg_recv_and_cahce(msg);
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

static void dss_proc_broadcast_req_inner(dss_session_t *session, mes_message_t *msg)
{
    status_t status = CM_ERROR;
    if (msg->head->size < sizeof(mes_message_head_t) + sizeof(dss_bcast_req_cmd_t) + sizeof(dss_notify_req_msg_t)) {
        LOG_DEBUG_ERR("invalid broadcast req size");
        return;
    }
    char *data = msg->buffer + sizeof(mes_message_head_t);
    dss_bcast_req_cmd_t bcast_op = *(dss_bcast_req_cmd_t *)data;
    dss_notify_req_msg_t *check =
        (dss_notify_req_msg_t *)(msg->buffer + sizeof(mes_message_head_t) + sizeof(dss_bcast_req_cmd_t));
    if ((check->vg_name[0] == 0) || (g_vgs_info == NULL)) {
        LOG_DEBUG_ERR("Failed to find vg, vg name is null.");
        return;
    }
    DSS_LOG_DEBUG_OP("check file ftid: %llu, vg_name: %s\n", check->ftid, check->vg_name);
    dss_vg_info_item_t *vg_item = dss_find_vg_item(check->vg_name);
    if (vg_item == NULL) {
        DSS_THROW_ERROR(ERR_DSS_VG_NOT_EXIST, check->vg_name);
        LOG_DEBUG_ERR("Failed to find vg, %s.", check->vg_name);
        return;
    }

    bool32 cmd_ack = CM_FALSE;
    switch (bcast_op) {
        case BCAST_REQ_DEL_DIR_FILE:
            status = dss_check_open_file_remote(session, check->vg_name, check->ftid, &cmd_ack);
            break;
        case BCAST_REQ_INVALIDATE_FS_META:
            status = dss_invalidate_fs_meta_remote(session, check->vg_name, check->ftid, &cmd_ack);
            break;
        default:
            LOG_DEBUG_ERR("invalid broadcast req type");
            return;
    }

    LOG_DEBUG_INF("The cmd_ack:%u when notify cmd:%u, vg:%s, ftid:%llu.", (uint32)cmd_ack, bcast_op, check->vg_name,
        check->ftid);

    uint32 size = sizeof(dss_mes_ack_with_data_t) + sizeof(int) + sizeof(bool32);
    char send_msg[sizeof(dss_mes_ack_with_data_t) + sizeof(int) + sizeof(bool32)];

    dss_mes_ack_with_data_t *ack = (dss_mes_ack_with_data_t *)send_msg;
    mes_init_ack_head(msg->head, &ack->head, DSS_CMD_ACK_BROADCAST_WITH_MSG, size, session->id);
    ack->type = dss_get_bcast_ack_cmd(bcast_op);
    *(int *)(ack->data) = status;

    char *cmd_ack_ptr = ack->data + sizeof(int);
    *(bool32 *)cmd_ack_ptr = cmd_ack;
    int ret = mes_send_data(&ack->head);
    if (ret != CM_SUCCESS) {
        LOG_DEBUG_ERR("send message failed, src inst(%u), dst inst(%u) ret(%d) ", (uint32)msg->head->src_inst,
            (uint32)msg->head->dst_inst, ret);
        return;
    }
    DSS_LOG_DEBUG_OP("send message succeed, notify: %llu  result: %u. cmd=%hhu, rsn=%llu, src_inst=%hhu, "
                     "dst_inst=%hhu, src_sid=%hu, dst_sid=%hu.",
        check->ftid, cmd_ack, ack->head.cmd, ack->head.rsn, ack->head.src_inst, ack->head.dst_inst, ack->head.src_sid,
        ack->head.dst_sid);
}

int32 dss_process_broadcast_ack(dss_session_t *session, char *data, unsigned int len, dss_recv_msg_t *recv_msg_output)
{
    int32 ret = ERR_DSS_MES_ILL;

    if (len < sizeof(dss_bcast_ack_cmd_t) + sizeof(int32) + sizeof(bool32)) {
        LOG_DEBUG_ERR("invalid broadcast ack buffer");
        return ret;
    }
    dss_bcast_ack_cmd_t bcast_op = *(dss_bcast_ack_cmd_t *)data;
    switch (bcast_op) {
        case BCAST_ACK_DEL_FILE:
        case BCAST_ACK_INVALIDATE_FS_META:
            ret = *(int32 *)(data + sizeof(dss_bcast_ack_cmd_t));
            recv_msg_output->cmd_ack = *(bool32 *)(data + sizeof(dss_bcast_ack_cmd_t) + sizeof(int32));
            break;
        default:
            LOG_DEBUG_ERR("invalid broadcast ack type");
            break;
    }
    return ret;
}

void dss_proc_broadcast_req(dss_session_t *session, mes_message_t *msg)
{
    char *data = msg->buffer + sizeof(mes_message_head_t);
    if (msg->head->size < sizeof(mes_message_head_t) + sizeof(dss_bcast_req_cmd_t)) {
        LOG_DEBUG_ERR("invalid broadcast req size");
        mes_release_message_buf(msg);
        return;
    }
    dss_bcast_req_cmd_t bcast_op = *(dss_bcast_req_cmd_t *)data;
    LOG_DEBUG_INF("Try proc broadcast req, head rsn is %llu, head cmd is %u, req cmd is %u.", msg->head->rsn,
        msg->head->cmd, bcast_op);
    dss_proc_broadcast_req_inner(session, msg);
    mes_release_message_buf(msg);
    return;
}

static int dss_handle_broadcast_msg(
    dss_session_t *session, uint64 succ_inst, char *recv_msg[CM_MAX_INSTANCES], dss_recv_msg_t *recv_msg_output)
{
    uint32 i;
    uint32 len;
    char *data;
    int ret;
    mes_message_head_t *head;

    for (i = 0; i < CM_MAX_INSTANCES; i++) {
        if (DSS_IS_INST_SEND(succ_inst, i) && recv_msg[i] != NULL) {
            head = (mes_message_head_t *)recv_msg[i];
            data = recv_msg[i] + sizeof(mes_message_head_t);
            len = head->size - sizeof(mes_message_head_t);
            ret = dss_process_broadcast_ack(session, data, len, recv_msg_output);
            DSS_RETURN_IFERR2(ret, DSS_THROW_ERROR(ERR_DSS_FILE_OPENING_REMOTE, head->src_inst, head->cmd));
        }
    }
    return DSS_SUCCESS;
}

static void dss_release_broadcast_msg(dss_session_t *session, uint64 succ_inst, char *recv_msg[CM_MAX_INSTANCES])
{
    uint32 i;
    mes_message_t msg;
    for (i = 0; i < CM_MAX_INSTANCES; i++) {
        if (DSS_IS_INST_SEND(succ_inst, i) && recv_msg[i] != NULL) {
            msg.buffer = recv_msg[i];
            msg.head = (mes_message_head_t *)recv_msg[i];
            mes_release_message_buf(&msg);
        }
    }
}

static int dss_handle_recv_broadcast_msg(dss_session_t *session, uint64 succ_req_inst, uint32 timeout,
    uint64 *succ_ack_inst, dss_recv_msg_t *recv_msg_output)
{
    int ret;
    char *recv_msg[CM_MAX_INSTANCES] = {0};

    ret = mes_wait_acks_and_recv_msg(session->id, timeout, succ_req_inst, recv_msg);
    if (ret == DSS_SUCCESS) {
        ret = dss_handle_broadcast_msg(session, succ_req_inst, recv_msg, recv_msg_output);
    }

    // do not care ret, just check get ack msg
    for (uint32 i = 0; i < CM_MAX_INSTANCES; i++) {
        if (recv_msg[i] != NULL) {
            *succ_ack_inst |= ((uint64)0x1 << i);
        }
    }

    dss_release_broadcast_msg(session, succ_req_inst, recv_msg);
    return ret;
}

#define DSS_BROADCAST_MSG_TRY_MAX 5
#define DSS_BROADCAST_MSG_TRY_SLEEP_TIME 200
static status_t dss_broadcast_msg_with_try(dss_session_t *session, mes_message_head_t *head, const char *buffer,
    dss_recv_msg_t *recv_msg, unsigned int timeout)
{
    int32 ret = DSS_SUCCESS;

    dss_config_t *inst_cfg = dss_get_inst_cfg();
    dss_params_t *param = &inst_cfg->params;
    uint64 succ_req_inst = 0;
    uint64 succ_ack_inst = 0;
    uint32 i = 0;
    // init last send err with all
    uint64 cur_work_inst_map = dss_get_inst_work_status();
    uint64 snd_err_inst_map = cur_work_inst_map;
    uint64 last_inst_inst_map = 0;
    uint64 new_added_inst_map = 0;
    uint64 vaild_inst = 0;
    uint64 vaild_inst_mask = 0;
    dss_bcast_req_t *req = (dss_bcast_req_t *)buffer;
    do {
        // only send the last-send-failed and new added
        cm_reset_error();
        vaild_inst_mask = ((cur_work_inst_map & snd_err_inst_map) | new_added_inst_map);
        vaild_inst = (param->inst_map) & (~((uint64)0x1 << (uint64)(param->inst_id))) & vaild_inst_mask;
        LOG_DEBUG_INF("Try broadcast num is %u, head rsn is %llu, head cmd is %u, req cmd is %u.", i, head->rsn,
            head->cmd, req->type);
        mes_broadcast2(session->id, vaild_inst, head, (const void *)buffer, &succ_req_inst);
        if (!recv_msg->handle_recv_msg && timeout > 0) {
            ret = mes_wait_acks(session->id, timeout);
        } else {
            ret = dss_handle_recv_broadcast_msg(session, succ_req_inst, timeout, &succ_ack_inst, recv_msg);
        }
        LOG_DEBUG_INF(
            "Try broadcast num is %u, valid_inst is %llu, succ_req_inst is %llu.", i, vaild_inst, succ_req_inst);
        if (ret == CM_SUCCESS && succ_req_inst == vaild_inst) {
            return ret;
        }
        // ready for next try only new added and (send req failed or recv ack  failed)
        snd_err_inst_map = vaild_inst_mask & (~(succ_req_inst & succ_ack_inst));
        last_inst_inst_map = cur_work_inst_map;
        cur_work_inst_map = dss_get_inst_work_status();
        new_added_inst_map = (~last_inst_inst_map & cur_work_inst_map);
        // re-snd with new rsn
        head->rsn = mes_get_rsn(session->id);
        cm_sleep(DSS_BROADCAST_MSG_TRY_SLEEP_TIME);
        i++;
    } while (i < DSS_BROADCAST_MSG_TRY_MAX);
    DSS_THROW_ERROR(ERR_DSS_MES_ILL, "Failed to broadcast msg with try.");
    return CM_ERROR;
}

static status_t dss_broadcast_msg(
    dss_session_t *session, const char *buffer, uint32 size, dss_recv_msg_t *recv_msg, unsigned int timeout)
{
    dss_config_t *inst_cfg = dss_get_inst_cfg();
    dss_params_t *param = &inst_cfg->params;
    mes_message_head_t head;

    MES_INIT_MESSAGE_HEAD(&head, DSS_CMD_REQ_BROADCAST, 0, param->inst_id, 0, session->id, CM_INVALID_ID16);
    head.size = (uint16)(size + sizeof(mes_message_head_t));
    head.rsn = mes_get_rsn(session->id);
    return dss_broadcast_msg_with_try(session, &head, buffer, recv_msg, timeout);
}

static bool32 dss_check_srv_status(mes_message_t *msg)
{
    date_t time_start = g_timer()->now;
    date_t time_now = 0;
    mes_message_head_t head = *(msg->head);
    while (g_dss_instance.status != DSS_STATUS_OPEN &&
            (msg->head->cmd != DSS_CMD_REQ_JOIN_CLUSTER && msg->head->cmd != DSS_CMD_ACK_JOIN_CLUSTER)) {
        LOG_DEBUG_INF(
            "Could not exec remote req for the dssserver is not open or msg not join cluster, src node:%u.",
            (uint32)(head.src_inst));
        DSS_GET_CM_LOCK_LONG_SLEEP;
        time_now = g_timer()->now;
        if (time_now - time_start > DSS_MAX_FAIL_TIME_WITH_CM * MICROSECS_PER_SECOND) {
            LOG_RUN_ERR("Fail to change status open for %d seconds when exec remote req.", DSS_MAX_FAIL_TIME_WITH_CM);
            return CM_FALSE;
        }
    }
    return CM_TRUE;
}

static status_t dss_prepare_ack_msg(dss_session_t *session, status_t ret)
{
    int32 code;
    const char *message = NULL;
    dss_packet_t *send_pack = &session->send_pack;

    if (ret != CM_SUCCESS) {
        dss_init_set(send_pack);
        CM_RETURN_IFERR(dss_put_int32(send_pack, ret));
        cm_get_error(&code, &message);
        CM_RETURN_IFERR(dss_put_int32(send_pack, code));
        return dss_put_str(send_pack, message);
    }
    return CM_SUCCESS;
}

void dss_proc_remote_req_err(dss_session_t *session, mes_message_head_t *head, unsigned char cmd, int32 ret)
{
    mes_message_head_t ack;
    status_t status = dss_prepare_ack_msg(session, ret);
    if (status != CM_SUCCESS) {
        LOG_DEBUG_ERR("The dssserver prepare ack msg failed, src node:%u, dst node:%u.", head->src_inst, head->dst_inst);
        return;
    }
    ack.size = (uint16)((session->send_pack.head->size - sizeof(dss_packet_head_t)) + sizeof(mes_message_head_t));
    mes_init_ack_head(head, &ack, cmd, ack.size, session->id);
    (void)mes_send_data2(&ack, session->send_pack.buf + sizeof(dss_packet_head_t));
}

static status_t dss_process_remote_req_prepare(dss_session_t *session, mes_message_t *msg, dss_processor_t *processor)
{
    // ready the ack connection
    dss_check_peer_by_inst(&g_dss_instance, msg->head->src_inst);
    if (msg->head->cmd != DSS_CMD_REQ_BROADCAST && !dss_need_exec_local()) {
        LOG_RUN_ERR("Proc msg cmd:%u from remote node:%u fail, can NOT exec here.", (uint32)msg->head->cmd,
            msg->head->src_inst);
        return CM_ERROR;
    }
    if (dss_check_srv_status(msg) != CM_TRUE) {
        LOG_RUN_ERR("Proc msg cmd:%u from remote node:%u fail, local status fail.", (uint32)msg->head->cmd,
            msg->head->src_inst);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static status_t dss_process_remote_ack_prepare(dss_session_t *session, mes_message_t *msg, dss_processor_t *processor)
{
    if (dss_check_srv_status(msg) != CM_TRUE) {
        LOG_RUN_ERR("Proc msg cmd:%u from remote node:%u fail, local status fail.", (uint32)msg->head->cmd,
            msg->head->src_inst);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static void dss_process_message(uint32 work_idx, mes_message_t *msg)
{
    cm_reset_error();
    dss_config_t *inst_cfg = dss_get_inst_cfg();
    uint32 mes_sess_cnt = inst_cfg->params.channel_num + inst_cfg->params.work_thread_cnt;

    if (work_idx >= mes_sess_cnt) {
        cm_panic(0);
    }

    LOG_DEBUG_INF("Proc msg cmd:%u, src node:%u, dst node:%u, src sid:%u, dst sid:%u, rsn:%llu begin.", 
        (uint32)(msg->head->cmd), (uint32)(msg->head->src_inst), (uint32)(msg->head->dst_inst),
        (uint32)(msg->head->src_sid), (uint32)(msg->head->dst_sid), msg->head->rsn);
    if (msg->head->cmd >= DSS_CMD_CEIL) {
        LOG_DEBUG_ERR("Invalid request received,cmd is %u.", (uint8)msg->head->cmd);
        mes_release_message_buf(msg);
        return;
    }

    LOG_DEBUG_INF("dss process message, cmd is %u.", (uint8)msg->head->cmd);
    dss_processor_t *processor = &g_dss_processors[msg->head->cmd];
    dss_session_ctrl_t *session_ctrl = dss_get_session_ctrl();
    dss_session_t *session = &session_ctrl->sessions[work_idx];
    
    status_t ret;

    dss_init_packet(&session->recv_pack, CM_FALSE);
    dss_init_packet(&session->send_pack, CM_FALSE);
    dss_init_set(&session->send_pack);

    // resv this for success op
    ret = dss_put_int32(&session->send_pack, CM_SUCCESS);
    if (ret != CM_SUCCESS) {
        mes_release_message_buf(msg);
        return;
    }

    if (processor->is_req) {
        ret = dss_process_remote_req_prepare(session, msg, processor);
    } else {
        ret = dss_process_remote_ack_prepare(session, msg, processor);
    }
    if (ret != CM_SUCCESS) {
        mes_release_message_buf(msg);
        return;
    }

    // from here, the proc need to give the ack and release message buf
    processor->proc(session, msg);

    LOG_DEBUG_INF("Proc msg cmd:%u, src node:%u, dst node:%u, src sid:%u, dst sid:%u, rsn:%llu end.", 
        (uint32)(msg->head->cmd), (uint32)(msg->head->src_inst), (uint32)(msg->head->dst_inst),
        (uint32)(msg->head->src_sid), (uint32)(msg->head->dst_sid), msg->head->rsn);
}

// add function
static status_t dss_register_proc(void)
{
    for (uint32 i = DSS_CMD_REQ_BROADCAST; i < DSS_CMD_CEIL; i++) {
        mes_set_msg_enqueue(i, g_dss_processors[i].is_enqueue);
    }
    mes_register_proc_func(dss_process_message);
    return CM_SUCCESS;
}

static void dss_set_mes_buffer_pool(unsigned long long recv_msg_buf_size, mes_profile_t *profile)
{
    uint32 pool_idx = 0;

    profile->buffer_pool_attr.pool_count = DSS_BUFFER_POOL_NUM;
    profile->buffer_pool_attr.queue_count = DSS_MSG_BUFFER_QUEUE_NUM;

    // 64 buffer pool
    profile->buffer_pool_attr.buf_attr[pool_idx].count =
        (uint32)(recv_msg_buf_size * DSS_FIRST_BUFFER_RATIO) / DSS_FIRST_BUFFER_LENGTH;
    profile->buffer_pool_attr.buf_attr[pool_idx].size = DSS_FIRST_BUFFER_LENGTH;

    // 128 buffer pool
    pool_idx++;
    profile->buffer_pool_attr.buf_attr[pool_idx].count =
        (uint32)(recv_msg_buf_size * DSS_SECOND_BUFFER_RATIO) / DSS_SECOND_BUFFER_LENGTH;
    profile->buffer_pool_attr.buf_attr[pool_idx].size = DSS_SECOND_BUFFER_LENGTH;

    // 32k buffer pool
    pool_idx++;
    profile->buffer_pool_attr.buf_attr[pool_idx].count =
        (uint32)(recv_msg_buf_size * DSS_THIRDLY_BUFFER_RATIO) / DSS_THIRD_BUFFER_LENGTH;
    profile->buffer_pool_attr.buf_attr[pool_idx].size = DSS_THIRD_BUFFER_LENGTH;
}

void dss_set_command_group(void)
{
    // group 0
    for (uint8 i = 0; i < DSS_CMD_CEIL; i++) {
        mes_set_command_task_group(i, g_dss_processors[i].group_id);
    }
}

static inline void dss_set_group_task_num(dss_config_t *dss_profile, mes_profile_t *mes_profile)
{
    uint32 work_thread_cnt_load_meta =
        (uint32)(dss_profile->params.work_thread_cnt * DSS_WORK_THREAD_LOAD_DATA_PERCENT);
    if (work_thread_cnt_load_meta == 0) {
        work_thread_cnt_load_meta = 1;
    }
    uint32 work_thread_cnt_comm = (dss_profile->params.work_thread_cnt - work_thread_cnt_load_meta);
    mes_profile->task_group[MES_TASK_GROUP_ZERO] = work_thread_cnt_comm;
    mes_profile->task_group[MES_TASK_GROUP_ONE] = work_thread_cnt_load_meta;
    mes_profile->task_group[MES_TASK_GROUP_TWO] = 0;
    mes_profile->task_group[MES_TASK_GROUP_THREE] = 0;
}

static status_t dss_set_mes_profile(mes_profile_t *profile)
{
    errno_t errcode = memset_sp(profile, sizeof(mes_profile_t), 0, sizeof(mes_profile_t));
    securec_check_ret(errcode);

    dss_config_t *inst_cfg = dss_get_inst_cfg();
    profile->inst_id = (uint32)inst_cfg->params.inst_id;
    profile->pipe_type = inst_cfg->params.pipe_type;
    profile->channel_cnt = inst_cfg->params.channel_num;
    profile->work_thread_cnt = inst_cfg->params.work_thread_cnt;
    profile->conn_created_during_init = 0;
    profile->mes_elapsed_switch = inst_cfg->params.elapsed_switch;

    uint32 inst_cnt = 0;
    for (uint32 i = 0; i < DSS_MAX_INSTANCES; i++) {
        uint64_t inst_mask = ((uint64)0x1 << i);
        if ((inst_cfg->params.inst_map & inst_mask) == 0) {
            continue;
        }
        errcode = strncpy_s(
            profile->inst_net_addr[i].ip, CM_MAX_IP_LEN, inst_cfg->params.nodes[i], strlen(inst_cfg->params.nodes[i]));
        if (errcode != EOK) {
            DSS_RETURN_IFERR2(CM_ERROR, DSS_THROW_ERROR(ERR_SYSTEM_CALL, (errcode)));
        }
        profile->inst_net_addr[i].port = inst_cfg->params.ports[i];
        inst_cnt++;
        if (inst_cnt == inst_cfg->params.inst_cnt) {
            break;
        }
    }
    // need to set to max because mes, if inst id is [7, 8], and inst_cnt is 2 not work
    // should set inst_cnt to max
    profile->inst_cnt = DSS_MAX_INSTANCES;

    dss_set_mes_buffer_pool(inst_cfg->params.mes_pool_size, profile);
    dss_set_group_task_num(inst_cfg, profile);
    dss_set_command_group();
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
    regist_refresh_ft_by_primary_proc(dss_refresh_ft_by_primary);
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

status_t dss_notify_sync(
    dss_session_t *session, dss_bcast_req_cmd_t cmd, const char *buffer, uint32 size, dss_recv_msg_t *recv_msg)
{
    CM_ASSERT(buffer != NULL);
    CM_ASSERT(cmd < BCAST_REQ_END);
    CM_ASSERT(size < SIZE_K(1));

    uint32 req_size = sizeof(dss_bcast_req_t) + size + 1;
    char *tmp = cm_malloc(req_size);
    if (tmp == NULL) {
        DSS_RETURN_IFERR2(CM_ERROR, DSS_THROW_ERROR(ERR_ALLOC_MEMORY, req_size, "tmp"));
    }
    dss_bcast_req_t *bcast_req = (dss_bcast_req_t *)tmp;
    bcast_req->type = cmd;
    errno_t err = memcpy_sp(bcast_req->buffer, size, buffer, size);
    if (err != EOK) {
        DSS_RETURN_IFERR3(CM_ERROR, DSS_THROW_ERROR(ERR_SYSTEM_CALL, err), DSS_FREE_POINT(tmp));
    }
    bcast_req->buffer[size] = '\0';
    status_t status = dss_broadcast_msg(session, (void *)bcast_req, req_size, recv_msg, DSS_MES_LONG_WAIT_TIMEOUT);
    DSS_FREE_POINT(tmp);
    return status;
}

status_t dss_notify_expect_bool_ack(
    dss_session_t *session, dss_vg_info_item_t *vg_item, dss_bcast_req_cmd_t cmd, uint64 ftid, bool32 *cmd_ack)
{
    if (g_dss_instance.is_maintain) {
        return CM_SUCCESS;
    }
    dss_notify_req_msg_t check;
    check.ftid = ftid;
    *cmd_ack = CM_FALSE;
    errno_t err = strncpy_s(check.vg_name, DSS_MAX_NAME_LEN, vg_item->vg_name, strlen(vg_item->vg_name));
    if (err != EOK) {
        DSS_THROW_ERROR(ERR_SYSTEM_CALL, err);
        return CM_ERROR;
    }
    LOG_DEBUG_INF("notify other dss instance to check file open, ftid:%llu in vg:%s.", ftid, vg_item->vg_name);
    dss_recv_msg_t recv_msg = {CM_TRUE, CM_FALSE};
    status_t status = dss_notify_sync(session, cmd, (char *)&check, sizeof(dss_notify_req_msg_t), &recv_msg);
    if (status != CM_SUCCESS) {
        LOG_RUN_ERR("[DSS] ABORT INFO: Failed to notify other dss instance, cmd: %u, file: %llu, vg: %s, errcode:%d, "
                    "OS errno:%d, OS errmsg:%s.",
            cmd, ftid, vg_item->vg_name, cm_get_error_code(), errno, strerror(errno));
        return CM_ERROR;
    }
    if (recv_msg.cmd_ack) {
        *cmd_ack = CM_TRUE;
    }
    return status;
}

status_t dss_invalidate_other_nodes(dss_session_t *session, dss_vg_info_item_t *vg_item, uint64 ftid, bool32 *cmd_ack)
{
    return dss_notify_expect_bool_ack(session, vg_item, BCAST_REQ_INVALIDATE_FS_META, ftid, cmd_ack);
}

static void dss_check_inst_conn(uint32_t id, uint64 old_inst_stat, uint64 cur_inst_stat)
{
    if (old_inst_stat == cur_inst_stat) {
        return;
    }

    dss_config_t *inst_cfg = dss_get_inst_cfg();
    if (old_inst_stat == 0) {
        (void)mes_connect(id, inst_cfg->params.nodes[id], inst_cfg->params.ports[id]);
    } else {
        mes_disconnect(id);
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

status_t dss_exec_sync(dss_session_t *session, uint32 remoteid, uint32 currtid, status_t *remote_result)
{
    status_t ret = CM_ERROR;
    mes_message_head_t head;
    mes_message_t msg;
    uint32 code = 0;
    uint16 cpsize;
    char *cpybuffer = NULL;
    uint32 size = session->recv_pack.head->size;

    // 1. init msg head
    MES_INIT_MESSAGE_HEAD(&head, DSS_CMD_REQ_SYB2ACTIVE, 0, currtid, remoteid, session->id, CM_INVALID_ID16);
    head.size = (uint16)(size + sizeof(mes_message_head_t));
    head.rsn = mes_get_rsn(session->id);
    // 2. send request to remote
    ret = mes_send_data2(&head, session->recv_pack.buf);
    char *err_msg = "The dss server fails to send messages to the remote node";
    DSS_RETURN_IFERR2(ret, LOG_RUN_ERR("%s, src node:%u, dst node:%u.", err_msg, currtid, remoteid));
    // 3. receive msg from remote
    ret = mes_allocbuf_and_recv_data((uint16)session->id, &msg, DSS_MES_WAIT_TIMEOUT);
    DSS_RETURN_IFERR2(ret,
        LOG_RUN_ERR("dss server receive msg from remote node failed, src node:%u, dst node:%u cmd:%u, azk size:%lu.", 
            currtid, remoteid, session->recv_pack.head->cmd, head.size - sizeof(mes_message_head_t)));
 
    // 4. attach remote execution result
    // remote_result|errcode|errmsg
    // remote result|data
    *remote_result = *(int32 *)(msg.buffer + sizeof(mes_message_head_t));
    if (*remote_result != CM_SUCCESS) {
        code = *(int32 *)(msg.buffer + sizeof(mes_message_head_t) + sizeof(int32));
        cpsize = msg.head->size - sizeof(mes_message_head_t) - 2 * sizeof(int32);
        cpybuffer = msg.buffer + sizeof(mes_message_head_t) + 2 * sizeof(int32);
        DSS_THROW_ERROR(ERR_DSS_PROCESS_REMOTE, code, cpybuffer);
    } else {
        cpsize = msg.head->size - sizeof(mes_message_head_t) - sizeof(int32);
        cpybuffer = msg.buffer + sizeof(mes_message_head_t) + sizeof(int32);
        LOG_DEBUG_INF("dss server receive msg from remote node, src node:%u, dst node:%u cmd:%u, azk size:%lu.", 
            currtid, remoteid, session->recv_pack.head->cmd, msg.head->size - sizeof(mes_message_head_t));
        // do not parse the format
        ret = dss_put_data(&session->send_pack, cpybuffer, cpsize);
    }

    mes_release_message_buf(&msg);
    return ret;
}

status_t dss_exec_on_remote(uint8 cmd, char *req, int32 req_size, char *ack, int ack_size, status_t *remote_result)
{
    status_t ret = CM_ERROR;
    mes_message_head_t head;
    dss_session_t *session = NULL;
    uint32 remoteid = DSS_INVALID_ID32;
    uint32 currid = DSS_INVALID_ID32;
    uint32 code;
    uint32 cpsize;
    uint16 data_offset;
    char *cpybuffer = NULL;

    if (dss_create_session(NULL, &session) != CM_SUCCESS) {
        LOG_RUN_ERR("Exec cmd:%u on remote ndoe create session fail.", (uint32)cmd);
        return CM_ERROR;
    }

    dss_get_exec_nodeid(session, &currid, &remoteid);
    LOG_DEBUG_INF("Exec cmd:%u on remote node:%u begin.", (uint32)cmd, remoteid);

    // 1. init msg head
    MES_INIT_MESSAGE_HEAD(&head, cmd, 0, currid, remoteid, session->id, CM_INVALID_ID16);
    head.size = (uint16)(req_size + sizeof(mes_message_head_t));
    head.rsn = mes_get_rsn(session->id);
 
    // 2. send request to remote
    ret = mes_send_data2(&head, req);
    if (ret != CM_SUCCESS) {
        LOG_RUN_ERR("Exec cmd:%u on remote node:%u  send msg fail.", (uint32)cmd, remoteid);
        dss_destroy_session(session);
        return ret;
    }

    // 3. receive msg from remote
    mes_message_t msg;
    ret = mes_allocbuf_and_recv_data((uint16)session->id, &msg, DSS_MES_WAIT_TIMEOUT);
    if (ret != CM_SUCCESS) {
        LOG_RUN_ERR("Exec cmd:%u on remote node:%u  recv msg fail.", (uint32)cmd, remoteid);
        dss_destroy_session(session);
        return ret;
    }

    // 4. attach remote execution result
    // remote_result|errcode|errmsg
    // remote result|data
    data_offset = sizeof(mes_message_head_t);
    *remote_result = *(int32 *)(msg.buffer + data_offset);
    LOG_DEBUG_INF("dss server receive msg from remote node, src node:%u, dst node:%u cmd:%u, azk size:%lu, result:%u.", 
        currid, remoteid, head.cmd, msg.head->size - sizeof(mes_message_head_t), (uint32)*remote_result);
    if (*remote_result != CM_SUCCESS) {
        // skip result
        data_offset += sizeof(int32);
        code = *(int32 *)(msg.buffer + data_offset);
        // skip code
        data_offset += sizeof(int32);
        cpsize = (uint32)(msg.head->size - data_offset);
        cpybuffer = (msg.buffer + data_offset);
        DSS_THROW_ERROR(ERR_DSS_PROCESS_REMOTE, code, cpybuffer);
    } else {
        // skip result
        data_offset += sizeof(int32);
        // skip length
        data_offset += sizeof(int32);
        cpsize = (uint32)(msg.head->size - data_offset);
        cpybuffer = (msg.buffer + data_offset);
        // do not parse the format
        errno_t err = memcpy_s(ack, (size_t)ack_size, cpybuffer, (size_t)cpsize);
        if (err != EOK) {
            CM_THROW_ERROR(ERR_SYSTEM_CALL, err);
            ret = CM_ERROR;
        }
    }

    mes_release_message_buf(&msg);
    dss_destroy_session(session);
    LOG_DEBUG_INF("Exec cmd:%u on remote node:%u end.", (uint32)cmd, remoteid);
    return ret;
}

void dss_proc_syb2active_req(dss_session_t *session, mes_message_t *msg)
{
    uint32 size = msg->head->size - sizeof(mes_message_head_t);
    mes_message_head_t head = *(mes_message_head_t *)(msg->buffer);
    uint32 srcid = (uint32)(head.src_inst);
    uint32 dstid = (uint32)(head.dst_inst);
    if (size > DSS_MAX_PACKET_SIZE) {
        LOG_DEBUG_ERR(
            "The dss server receive msg from remote failed, src node:%u, dst node:%u, size is %u.", srcid, dstid, size);
        mes_release_message_buf(msg);
        return;
    }
    LOG_DEBUG_INF("The dss server receive msg from remote node, src node:%u, dst node:%u.", srcid, dstid);
    errno_t errcode = memcpy_s(session->recv_pack.buf, size, (msg->buffer + sizeof(mes_message_head_t)), size);
    mes_release_message_buf(msg);
    if (errcode != EOK) {
        LOG_DEBUG_ERR("The dss server memcpy msg failed, src node:%u, dst node:%u.", srcid, dstid);
        return;
    }
    status_t ret = dss_proc_standby_req(session);
    mes_message_head_t ack;
    status_t status = dss_prepare_ack_msg(session, ret);
    if (status != CM_SUCCESS) {
        LOG_DEBUG_ERR("The dss server prepare ack msg failed, src node:%u, dst node:%u.", srcid, dstid);
        return;
    }
    ack.size = (uint16)(session->send_pack.head->size - sizeof(dss_packet_head_t) + sizeof(mes_message_head_t));
    LOG_DEBUG_INF(
        "The dss server send msg to the remote node, src node:%u, dst node:%u, cmd:%u, ack size is %lu.",
        (uint32)(head.src_inst), (uint32)(head.dst_inst), session->send_pack.head->cmd,
        session->send_pack.head->size - sizeof(dss_packet_head_t));

    mes_init_ack_head(&head, &ack, DSS_CMD_ACK_SYB2ACTIVE, ack.size, session->id);
    ret = mes_send_data2(&ack, session->send_pack.buf + sizeof(dss_packet_head_t));
    if (ret != CM_SUCCESS) {
        LOG_DEBUG_ERR("The dss server fails to send messages to the remote node, src node:%u, dst node:%u.",
            (uint32)(head.src_inst), (uint32)(head.dst_inst));
        return;
    }
    LOG_DEBUG_INF("The dss server send messages to the remote node success, src node:%u, dst node:%u.",
        (uint32)(head.src_inst), (uint32)(head.dst_inst));
}

status_t dss_send2standby(
    dss_session_t *session, mes_message_head_t *reqhead, big_packets_ctrl_t *ctrl, const char *buf, uint16 size)
{
    mes_message_head_t ack;
    ack.size = (uint16)(size + sizeof(mes_message_head_t) + sizeof(big_packets_ctrl_t));
    mes_init_ack_head(reqhead, &ack, DSS_CMD_ACK_LOAD_DISK, ack.size, session->id);
    status_t ret = mes_send_data4(&ack, sizeof(mes_message_head_t), ctrl, sizeof(big_packets_ctrl_t), buf, size);
    if (ret != CM_SUCCESS) {
        LOG_RUN_ERR("The dssserver fails to send messages to the remote node, src node:%u, dst node:%u.",
            (uint32)(reqhead->src_inst), (uint32)(reqhead->dst_inst));
        return ret;
    }

    LOG_DEBUG_INF("The dssserver send messages to the remote node success, src node:%u, dst node:%u."
                 "src sid:%u, dst sid:%u, rsn:%llu",
        (uint32)(reqhead->src_inst), (uint32)(reqhead->dst_inst), (uint32)(reqhead->src_sid),
        (uint32)(reqhead->dst_sid), reqhead->rsn);
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

int32 dss_batch_load(dss_session_t *session, dss_loaddisk_req_t *req, mes_message_head_t *reqhead)
{
#ifndef WIN32
    char readbuff[DSS_LOADDISK_BUFFER_SIZE] __attribute__((__aligned__(DSS_ALIGN_SIZE))) = {0};
#else
    char readbuff[DSS_LOADDISK_BUFFER_SIZE] = {0};
#endif
    int32 remain = (int32)req->size;
    int32 readsize = 0;
    int32 readtotal = 0;
    big_packets_ctrl_t ctrl;
    errno_t errcode = memset_s(&ctrl, sizeof(big_packets_ctrl_t), 0, sizeof(big_packets_ctrl_t));
    securec_check_ret(errcode);
    ctrl.totalsize = req->size;
    dss_loaddisk_lock(req->vg_name);
    while (remain > 0) {
        if (session && session->is_closed) {
            LOG_RUN_ERR("session:%u is closed.", session->id);
            return CM_ERROR;
        }
        int64 roffset = (int64)((int64)req->offset + (int64)readtotal);
        readsize = (remain <= (int32)(DSS_LOADDISK_BUFFER_SIZE)) ? remain : (int32)(DSS_LOADDISK_BUFFER_SIZE);
        if (dss_read_volume_4standby(req->vg_name, req->volumeid, roffset, readbuff, readsize) != CM_SUCCESS) {
            LOG_RUN_ERR("read volume for standby failed, vg name[%s], volume id[%u].", req->vg_name, req->volumeid);
            dss_loaddisk_unlock(req->vg_name);
            return DSS_READ4STANDBY_ERR;
        }
        readtotal += readsize;
        remain -= readsize;

        ctrl.cursize = (uint32)readsize;
        ctrl.endflag = (remain == 0) ? CM_TRUE : CM_FALSE;
        if (dss_send2standby(session, reqhead, &ctrl, readbuff, (uint16)readsize) != CM_SUCCESS) {
            LOG_RUN_ERR("read volume for standby send msg failed, vg name[%s], volume id[%u].", req->vg_name, req->volumeid);
            dss_loaddisk_unlock(req->vg_name);
            return CM_ERROR;
        }

        LOG_DEBUG_INF("load disk from active info vg name(%s) volume id(%u) msg seq(%u) msg len(%u).", req->vg_name,
            req->volumeid, (uint32)ctrl.seq, ctrl.cursize);
        
        ctrl.offset += (uint32)readsize;
        ctrl.seq++;
    }

    dss_loaddisk_unlock(req->vg_name);
    return CM_SUCCESS;
}

void dss_proc_loaddisk_req(dss_session_t *session, mes_message_t *msg)
{
    mes_message_head_t head = *(msg->head);
    uint32 size = msg->head->size - sizeof(mes_message_head_t);
    uint32 dstid = (uint32)(head.dst_inst);
    int32 ret = CM_ERROR;

    if (dss_is_readonly() == CM_TRUE) {
        dss_config_t *cfg = dss_get_inst_cfg();
        LOG_RUN_ERR("The local node:%u is in readonly state and connot execute remote loaddisk request.",
            (uint32)(cfg->params.inst_id));
        dss_proc_remote_req_err(session, &head, DSS_CMD_ACK_LOAD_DISK, ret);
        mes_release_message_buf(msg);
        return;
    }

    if (size != sizeof(dss_loaddisk_req_t)) {
        LOG_RUN_ERR("The dssserver reveive msg from remote failed, src node:%u, dst node:%u.",
            (uint32)(head.src_inst), dstid);
        dss_proc_remote_req_err(session, &head, DSS_CMD_ACK_LOAD_DISK, ret);
        mes_release_message_buf(msg);
        return;
    }
    dss_loaddisk_req_t req = *(dss_loaddisk_req_t *)(msg->buffer + sizeof(mes_message_head_t));
    LOG_DEBUG_INF("Exec load disk req, src node:%u, volume id:%u, offset:%llu, size:%u.", (uint32)(head.src_inst),
        req.volumeid, req.offset, req.size);
    if (dss_check_srv_status(msg) != CM_TRUE) {
        dss_proc_remote_req_err(session, &head, DSS_CMD_ACK_LOAD_DISK, ret);
        mes_release_message_buf(msg);
        return;
    }
    ret = dss_batch_load(session, &req, &head);
    if (ret != CM_SUCCESS) {
        LOG_RUN_ERR("Exec load disk req failed, src node:%u, volume id:%u, offset:%llu, size:%u.", (uint32)(head.src_inst),
            req.volumeid, req.offset, req.size);
        dss_proc_remote_req_err(session, &head, DSS_CMD_ACK_LOAD_DISK, ret);
    }
    mes_release_message_buf(msg);
    return;
}

static status_t dss_init_readvlm_remote_params(
    dss_loaddisk_req_t *req, const char *entry, uint32 *currid, uint32 *remoteid, dss_session_t *session)
{
    error_t errcode = memset_s(req, sizeof(dss_loaddisk_req_t), 0, sizeof(dss_loaddisk_req_t));
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

static bool32 dss_packets_verify(bool32 bfirst, big_packets_ctrl_t *lastctrl, big_packets_ctrl_t *ctrl)
{
    if ((ctrl->endflag != CM_TRUE) || (ctrl->cursize + ctrl->offset != ctrl->totalsize)) {
        return CM_FALSE;
    }

    *lastctrl = *ctrl;
    return CM_TRUE;
}

static status_t dss_rec_msgs(dss_session_t *session, void *buf, int32 size)
{
    bool32 bfirst = CM_TRUE;
    mes_message_t msg;
    big_packets_ctrl_t lastctrl;
    lastctrl.offset = 0;
    lastctrl.totalsize = 0;
    lastctrl.seq = 0;
    lastctrl.cursize = 0;
    big_packets_ctrl_t ctrl;
    do {
        if (session && session->is_closed) {
            LOG_RUN_ERR("session:%u is closed.", session->id);
            return CM_ERROR;
        }
        status_t ret = mes_allocbuf_and_recv_data((uint16)session->id, &msg, DSS_MES_WAIT_TIMEOUT);
        if (ret != CM_SUCCESS) {
            LOG_RUN_ERR("dss server receive msg from remote node failed, result:%d.", ret);
            return ret;
        }

        if (msg.head->size < (sizeof(mes_message_head_t) + sizeof(big_packets_ctrl_t))) {
            ret = CM_ERROR;
            LOG_RUN_ERR("dss server load disk from remote node failed, msg len(%d) error.", msg.head->size);
            if (msg.head->size == (sizeof(mes_message_head_t) + sizeof(int32))) {
                ret = *(int32*)(msg.buffer + sizeof(mes_message_head_t));
            }
            mes_release_message_buf(&msg);
            return ret;
        }
        ctrl = *(big_packets_ctrl_t *)(msg.buffer + sizeof(mes_message_head_t));
        if (dss_packets_verify(bfirst, &lastctrl, &ctrl) == CM_FALSE) {
            mes_release_message_buf(&msg);
            LOG_RUN_ERR("dss server receive msg verify failed.");
            return CM_ERROR;
        }
        errno_t errcode = memcpy_s((char *)buf + ctrl.offset, ctrl.cursize,
            msg.buffer + sizeof(mes_message_head_t) + sizeof(big_packets_ctrl_t), ctrl.cursize);
        mes_release_message_buf(&msg);
        securec_check_ret(errcode);
        bfirst = CM_FALSE;
    } while (ctrl.endflag != CM_TRUE);

    return CM_SUCCESS;
}

status_t dss_read_volume_remote(const char *vg_name, dss_volume_t *volume, int64 offset, void *buf, int32 size)
{
    status_t ret = CM_ERROR;
    mes_message_head_t head;
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
        "instance %u start to load %d data of dist(%s) from th primary node:%u", currid, size, vg_name, remoteid);
    req.volumeid = volumeid;
    req.offset= (uint64)offset;
    req.size = (uint32)size;
    // 1. init msg head
    MES_INIT_MESSAGE_HEAD(&head, DSS_CMD_REQ_LOAD_DISK, 0, currid, remoteid, session->id, CM_INVALID_ID16);
    head.size = (uint16)(sizeof(dss_loaddisk_req_t) + sizeof(mes_message_head_t));
    head.rsn = mes_get_rsn(session->id);
    LOG_DEBUG_INF("Ready mes cmd:%u, src node:%u, dst node:%u, src sid:%u, dst sid:%u, rsn:%llu end",
        (uint32)(head.cmd), (uint32)(head.src_inst), (uint32)(head.dst_inst), (uint32)(head.src_sid),
        (uint32)(head.dst_sid), head.rsn);

    // 2. send request to remote
    ret = mes_send_data2(&head, &req);
    if (ret != CM_SUCCESS) {
        LOG_RUN_ERR(
            "The dssserver fails to send messages to the remote node, src node:%u, dst node:%u.", currid, remoteid);
        dss_destroy_session(session);
        return ret;
    }
    // 3. receive msg from remote
    ret = dss_rec_msgs(session, buf ,size);
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

void dss_proc_join_cluster_req(dss_session_t *session, mes_message_t *msg)
{
    uint32 size = msg->head->size - sizeof(mes_message_head_t);
    if (size != sizeof(dss_join_cluster_req_t)) {
        LOG_RUN_ERR("Porc join cluster from remote node:%u check req msg fail.", (uint32)(msg->head->src_inst));
        dss_proc_remote_req_err(session, msg->head, DSS_CMD_ACK_JOIN_CLUSTER, CM_ERROR);
        mes_release_message_buf(msg);
        return;
    }

    dss_join_cluster_req_t *join_cluster_req = (dss_join_cluster_req_t *)(msg->buffer + sizeof(mes_message_head_t));
    LOG_DEBUG_INF("Proc join cluster from remote node:%u reg node:%u begin.", (uint32)(msg->head->src_inst),
        join_cluster_req->reg_id);
    
    // only in the work_status map can join the cluster
    dss_join_cluster_ack_t join_cluster_ack = {CM_FALSE};
    uint64 work_status = dss_get_inst_work_status();
    uint64 inst_mask = ((uint64)0x1 << join_cluster_req->reg_id);
    if (work_status & inst_mask) {
        join_cluster_ack.is_reg = CM_TRUE;
    }

    LOG_DEBUG_INF("Proc join cluster from remote node:%u, reg node:%u, is_reg:%u.", (uint32)(msg->head->src_inst),
        join_cluster_req->reg_id, (uint32)join_cluster_ack.is_reg);

    text_t data = {(char *)&join_cluster_ack, sizeof(dss_join_cluster_ack_t)};
    if (dss_put_text(&session->send_pack, &data) != CM_SUCCESS) {
        LOG_RUN_ERR("Proc join cluster from remote node:%u, reg node:%u, is_reg:%u ready ack fail.",
            (uint32)(msg->head->src_inst), join_cluster_req->reg_id, (uint32)join_cluster_ack.is_reg);
        dss_proc_remote_req_err(session, msg->head, DSS_CMD_ACK_JOIN_CLUSTER, CM_ERROR);
        mes_release_message_buf(msg);
        return;
    }

    mes_message_head_t ack;
    ack.size = (uint16)((session->send_pack.head->size - sizeof(dss_packet_head_t)) +sizeof(mes_message_head_t));
    mes_init_ack_head(msg->head, &ack, DSS_CMD_ACK_JOIN_CLUSTER, ack.size, session->id);
    int send_ret = mes_send_data2(&ack, session->send_pack.buf + sizeof(dss_packet_head_t));
    if (send_ret != CM_SUCCESS) {
        LOG_RUN_ERR("Proc join cluster from remote node:%u, reg node:%u send ack fail.", (uint32)(msg->head->src_inst),
            join_cluster_req->reg_id);
        mes_release_message_buf(msg);
        return;
    }

    LOG_DEBUG_INF("Proc join cluster from remote node:%u, reg node:%u send ack end.", (uint32)(msg->head->src_inst),
        join_cluster_req->reg_id);
    mes_release_message_buf(msg);
}

status_t dss_refresh_ft_by_primary(dss_block_id_t blockid, uint32 vgid, char *vg_name)
{
    LOG_DEBUG_INF("Try refresh ft by primary begin");

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

void dss_proc_refresh_ft_by_primary_req(dss_session_t *session, mes_message_t *msg)
{
    uint32 size = msg->head->size - sizeof(mes_message_head_t);
    if (size != sizeof(dss_refresh_ft_req_t)) {
        LOG_RUN_ERR("Refresh ft by primary from remote node:%u check req msg fail.", (uint32)(msg->head->src_inst));
        dss_proc_remote_req_err(session, msg->head, DSS_CMD_ACK_REFRESH_FT, CM_ERROR);
        mes_release_message_buf(msg);
        return;
    }

    dss_refresh_ft_req_t *refresh_ft_req = (dss_refresh_ft_req_t *)(msg->buffer + sizeof(mes_message_head_t));
    LOG_DEBUG_INF("Refresh ft by primary from remote node:%u, blockid:%llu, vgid:%u, vg_name:%s begin.",
        (uint32)(msg->head->src_inst), DSS_ID_TO_U64(refresh_ft_req->blockid), refresh_ft_req->vgid,
        refresh_ft_req->vg_name);
    if (dss_refresh_ft_block(
        session, refresh_ft_req->vg_name, refresh_ft_req->vgid, refresh_ft_req->blockid) != CM_SUCCESS) {
        LOG_RUN_ERR("Refresh ft by primary from remote node:%u, blockid:%llu, vgid:%u, vg_name:%s refresh fail",
            (uint32)(msg->head->src_inst), DSS_ID_TO_U64(refresh_ft_req->blockid), refresh_ft_req->vgid,
            refresh_ft_req->vg_name);
        dss_proc_remote_req_err(session, msg->head, DSS_CMD_ACK_REFRESH_FT, CM_ERROR);
        mes_release_message_buf(msg);
        return;
    }

    dss_refresh_ft_ack_t refresh_ft_ack = {CM_TRUE};
    text_t data = {(char *)&refresh_ft_ack, sizeof(dss_refresh_ft_ack_t)};
    if (dss_put_text(&session->send_pack, &data) != CM_SUCCESS) {
        LOG_RUN_ERR("Proc refresh ft by primary from remote node:%u, is_ok:%u ready ack fail.",
            (uint32)(msg->head->src_inst), (uint32)refresh_ft_ack.is_ok);
        dss_proc_remote_req_err(session, msg->head, DSS_CMD_ACK_REFRESH_FT, CM_ERROR);
        mes_release_message_buf(msg);
        return;
    }

    mes_message_head_t ack;
    ack.size = (uint16)((session->send_pack.head->size - sizeof(dss_packet_head_t)) +sizeof(mes_message_head_t));
    mes_init_ack_head(msg->head, &ack, DSS_CMD_ACK_REFRESH_FT, ack.size, session->id);
    int send_ret = mes_send_data2(&ack, session->send_pack.buf + sizeof(dss_packet_head_t));
    if (send_ret != CM_SUCCESS) {
        LOG_RUN_ERR("Refresh ft by primary from remote node:%u, blockid:%llu, vgid:%u, vg_name:%s send ack fail",
            (uint32)(msg->head->src_inst), DSS_ID_TO_U64(refresh_ft_req->blockid), refresh_ft_req->vgid,
            refresh_ft_req->vg_name);
        mes_release_message_buf(msg);
        return;
    }

    LOG_DEBUG_INF("Refresh ft by primary from remote node:%u, blockid:%llu, vgid:%u, vg_name:%s refresh end",
        (uint32)(msg->head->src_inst), DSS_ID_TO_U64(refresh_ft_req->blockid), refresh_ft_req->vgid,
        refresh_ft_req->vg_name);
    mes_release_message_buf(msg);
}