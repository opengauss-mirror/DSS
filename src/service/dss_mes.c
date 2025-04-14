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
#include "cm_error.h"
#include "dss_malloc.h"
#include "dss_session.h"
#include "dss_file.h"
#include "dss_service.h"
#include "dss_instance.h"
#include "dss_api.h"
#include "dss_mes.h"
#include "dss_syn_meta.h"
#include "dss_thv.h"
#include "dss_fault_injection.h"
#include "dss_param_verify.h"

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
    LOG_DEBUG_INF("[MES] Receive ack(%u),src inst(%u), dst inst(%u).", (uint32)(dss_head->dss_cmd),
        (uint32)(dss_head->src_inst), (uint32)(dss_head->dst_inst));
}

dss_processor_t g_dss_processors[DSS_CMD_CEIL] = {
    [DSS_CMD_REQ_BROADCAST] = {dss_proc_broadcast_req, CM_TRUE, CM_TRUE, MES_PRIORITY_ONE, "dss broadcast"},
    [DSS_CMD_ACK_BROADCAST_WITH_MSG] = {dss_proc_normal_ack, CM_FALSE, CM_FALSE, MES_PRIORITY_ONE,
        "dss broadcast ack with data"},
    [DSS_CMD_REQ_SYB2ACTIVE] = {dss_proc_syb2active_req, CM_TRUE, CM_TRUE, MES_PRIORITY_ONE,
        "dss standby to active req"},
    [DSS_CMD_ACK_SYB2ACTIVE] = {dss_proc_normal_ack, CM_FALSE, CM_FALSE, MES_PRIORITY_ONE, "dss active to standby ack"},
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
        "dss active proc refresh ft to standby ack"},
    [DSS_CMD_REQ_GET_FT_BLOCK] = {dss_proc_get_ft_block_req, CM_TRUE, CM_TRUE, MES_PRIORITY_ZERO,
        "dss standby get ft block req"},
    [DSS_CMD_ACK_GET_FT_BLOCK] = {dss_proc_normal_ack, CM_FALSE, CM_FALSE, MES_PRIORITY_ZERO,
        "dss active proc get ft block ack"},
};

static inline mes_priority_t dss_get_cmd_prio_id(dss_mes_command_t cmd)
{
    return g_dss_processors[cmd].prio_id;
}

typedef void (*dss_remote_ack_proc)(dss_session_t *session, dss_remote_exec_succ_ack_t *remote_ack);
typedef struct st_dss_remote_ack_hdl {
    dss_remote_ack_proc proc;
} dss_remote_ack_hdl_t;
void dss_process_remote_ack_for_get_ftid_by_path(dss_session_t *session, dss_remote_exec_succ_ack_t *remote_ack)
{
    dss_find_node_t *ft_node = (dss_find_node_t *)(remote_ack->body_buf + sizeof(uint32));
    dss_vg_info_item_t *vg_item = dss_find_vg_item(ft_node->vg_name);
    (void)dss_get_ft_node_by_ftid(session, vg_item, ft_node->ftid, CM_TRUE, CM_FALSE);
}
static dss_remote_ack_hdl_t g_dss_remote_ack_handle[DSS_CMD_TYPE_OFFSET(DSS_CMD_END)] = {
    [DSS_CMD_TYPE_OFFSET(DSS_CMD_GET_FTID_BY_PATH)] = {dss_process_remote_ack_for_get_ftid_by_path},
};

static inline dss_remote_ack_hdl_t *dss_get_remote_ack_handle(int32 cmd)
{
    if (cmd >= DSS_CMD_BEGIN && cmd < DSS_CMD_END) {
        return &g_dss_remote_ack_handle[DSS_CMD_TYPE_OFFSET(cmd)];
    }
    return NULL;
}
// bcast processers
static inline void dss_set_ack_common(dss_bcast_context_t *bcast_ctx, bool32 ret_val)
{
    bcast_ctx->ack_len = sizeof(dss_ack_common_t);
    dss_ack_common_t *ack = (dss_ack_common_t *)bcast_ctx->ack_msg;
    ack->cmd_ack = ret_val;
}

status_t dss_process_check_open_file(dss_session_t *session, dss_bcast_context_t *bcast_ctx)
{
    if (bcast_ctx->req_len < sizeof(dss_req_check_open_file_t)) {
        LOG_RUN_ERR("[MES] invalid message req size %u", bcast_ctx->req_len);
        return CM_ERROR;
    }
    dss_req_check_open_file_t *req = (dss_req_check_open_file_t *)bcast_ctx->req_msg;
    bool32 check_ret = CM_FALSE;
    status_t ret = dss_check_open_file_remote(session, req->vg_name, req->ftid, &check_ret);
    if (ret != CM_SUCCESS) {
        return ret;
    }
    dss_set_ack_common(bcast_ctx, check_ret);
    return CM_SUCCESS;
}

status_t dss_process_invalidate_meta(dss_session_t *session, dss_bcast_context_t *bcast_ctx)
{
    dss_req_meta_data_t *req_ex = (dss_req_meta_data_t *)bcast_ctx->req_msg;
    bool32 invalidate_ret = CM_FALSE;
    status_t ret = dss_invalidate_meta_remote(
        session, (dss_invalidate_meta_msg_t *)req_ex->data, req_ex->data_size, &invalidate_ret);
    if (ret != CM_SUCCESS) {
        return ret;
    }
    dss_set_ack_common(bcast_ctx, invalidate_ret);
    return CM_SUCCESS;
}

status_t dss_process_sync_meta(dss_session_t *session, dss_bcast_context_t *bcast_ctx)
{
    dss_req_meta_data_t *req_ex = (dss_req_meta_data_t *)bcast_ctx->req_msg;
    bool32 sync_ret = CM_FALSE;
    status_t ret = dss_meta_syn_remote(session, (dss_meta_syn_t *)req_ex->data, req_ex->data_size, &sync_ret);
    if (ret != CM_SUCCESS) {
        return ret;
    }
    dss_set_ack_common(bcast_ctx, sync_ret);
    return CM_SUCCESS;
}
typedef status_t (*dss_bcast_proc_func)(dss_session_t *session, dss_bcast_context_t *bcast_ctx);
typedef struct st_dss_bcast_hdl {
    dss_bcast_proc_func boc_proc;
    bool32 need_ack;
    dss_bcast_ack_cmd_t ack_cmd;
} dss_bcast_hdl_t;

// warning: if add new broadcast req, please consider the impact of expired broadcast messages on the standby server
static dss_bcast_hdl_t g_dss_bcast_handle[BCAST_REQ_END] = {
    [BCAST_REQ_DEL_DIR_FILE] = {dss_process_check_open_file, DSS_TRUE, BCAST_ACK_DEL_FILE},
    [BCAST_REQ_INVALIDATE_META] = {dss_process_invalidate_meta, DSS_TRUE, BCAST_ACK_INVALIDATE_META},
    [BCAST_REQ_META_SYN] = {dss_process_sync_meta, DSS_FALSE, BCAST_ACK_END},
};

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
    head->flags = flags | dss_get_cmd_prio_id(cmd);
}

static inline dss_bcast_ack_cmd_t dss_get_bcast_ack_cmd(dss_bcast_req_cmd_t bcast_op)
{
    if (bcast_op >= ELEMENT_COUNT(g_dss_bcast_handle)) {
        LOG_RUN_ERR("Invalid broadcast request type");
        return BCAST_ACK_END;
    }
    return g_dss_bcast_handle[bcast_op].ack_cmd;
}

static inline bool32 dss_bcast_need_ack(dss_bcast_req_cmd_t bcast_op)
{
    DSS_ASSERT_LOG(bcast_op < ELEMENT_COUNT(g_dss_bcast_handle), "invalid bcast cmd %u", bcast_op);
    return g_dss_bcast_handle[bcast_op].need_ack;
}

static void dss_send_bcast_ack(dss_bcast_context_t *bcast_ctx, status_t result)
{
    dss_bcast_req_head_t *req_head = (dss_bcast_req_head_t *)bcast_ctx->req_msg;
    uint16 dst_inst = req_head->dss_head.src_inst;
    uint16 src_inst = req_head->dss_head.dst_inst;
    uint32 version = req_head->dss_head.msg_proto_ver;
    ruid_type ruid = req_head->dss_head.ruid;

    dss_bcast_ack_head_t *ack_head = (dss_bcast_ack_head_t *)bcast_ctx->ack_msg;
    dss_init_mes_head(
        &ack_head->dss_head, DSS_CMD_ACK_BROADCAST_WITH_MSG, 0, src_inst, dst_inst, bcast_ctx->ack_len, version, ruid);
    ack_head->type = dss_get_bcast_ack_cmd(req_head->type);
    ack_head->dss_head.result = result;
    int ret = mes_send_response(dst_inst, ack_head->dss_head.flags, ruid, bcast_ctx->ack_msg, bcast_ctx->ack_len);
    if (ret != CM_SUCCESS) {
        LOG_DEBUG_ERR("[MES] send message failed, src inst(%hhu), dst inst(%hhu) ret(%d) ", src_inst, dst_inst, ret);
        return;
    }
    DSS_LOG_DEBUG_OP("[MES] Succeed to send message, result: %u. cmd=%u, src_inst=%hhu, dst_inst=%hhu.", result,
        ack_head->type, ack_head->dss_head.src_inst, ack_head->dss_head.dst_inst);
}

static void dss_send_bcast_ack_common(dss_bcast_context_t *bcast_ctx, status_t ret)
{
    bcast_ctx->ack_len = sizeof(dss_ack_common_t);
    dss_send_bcast_ack(bcast_ctx, ret);
}

int32 dss_proc_broadcast_ack_single(dss_bcast_ack_head_t *ack_head, void *ack_msg_output)
{
    int32 ret = ERR_DSS_MES_ILL;
    switch (ack_head->type) {
        case BCAST_ACK_DEL_FILE:
        case BCAST_ACK_INVALIDATE_META:
            if (ack_head->dss_head.size < sizeof(dss_ack_common_t)) {
                DSS_THROW_ERROR(ERR_DSS_MES_ILL, "msg len is invalid");
                return ERR_DSS_MES_ILL;
            }
            dss_ack_common_t *ack = (dss_ack_common_t *)ack_head;
            dss_bcast_ack_bool_t *ack_bool = (dss_bcast_ack_bool_t *)ack_msg_output;
            ret = ack->result;
            // ack_bool->cmd_ack init-ed with the deault, if some node not the same with the default, let's cover
            // the default value
            if (ret == CM_SUCCESS && ack_bool->default_ack != ack->cmd_ack) {
                ack_bool->cmd_ack = ack->cmd_ack;
            }
            if (ret != CM_SUCCESS) {
                DSS_THROW_ERROR(ERR_DSS_FILE_OPENING_REMOTE, ack_head->dss_head.src_inst, ack_head->dss_head.dss_cmd);
            }
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
        LOG_DEBUG_ERR(
            "send version not match message failed, src inst(%hhu), dst inst(%hhu) ret(%d)", src_inst, dst_inst, ret);
        return;
    }
    LOG_RUN_INF("send version not match message succeed, src inst(%hhu), dst inst(%hhu), ack msg version (%hhu)",
        src_inst, dst_inst, version);
}

#define DSS_BOC_ACK_MSG_LEN ((int)128)
void dss_proc_broadcast_req(dss_session_t *session, mes_msg_t *msg)
{
    if (dss_need_exec_local()) {
        LOG_RUN_WAR("No need to solve broadcast msg when the current node is master.");
        return;
    }
    if (msg->size < sizeof(dss_bcast_req_head_t)) {
        LOG_RUN_ERR("[MES] invalid message req size %u", msg->size);
        return;
    }
    dss_bcast_req_head_t *req_head = (dss_bcast_req_head_t *)msg->buffer;
    char ack_msg[DSS_BOC_ACK_MSG_LEN] = {0};
    dss_bcast_context_t bcast_ctx = {.req_msg = msg->buffer, .req_len = msg->size, .ack_msg = ack_msg, .ack_len = 0};
    if (req_head->type >= ELEMENT_COUNT(g_dss_bcast_handle)) {
        dss_send_bcast_ack_common(&bcast_ctx, ERR_DSS_UNSUPPORTED_CMD);
        return;
    }
    dss_bcast_hdl_t *boc_handler = &g_dss_bcast_handle[req_head->type];
    if (boc_handler->boc_proc == NULL) {
        dss_send_bcast_ack_common(&bcast_ctx, ERR_DSS_UNSUPPORTED_CMD);
        return;
    }
    status_t ret = boc_handler->boc_proc(session, &bcast_ctx);
    if (boc_handler->need_ack) {
        dss_send_bcast_ack(&bcast_ctx, ret);
    }
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

static int dss_proc_broadcast_ack_inner(
    mes_msg_list_t *responses, dss_bcast_community_t *community, void *ack_msg_output)
{
    int ret;
    dss_bcast_ack_head_t *ack_head;
    uint32 src_inst;
    for (uint32 i = 0; i < responses->count; i++) {
        mes_msg_t *msg = &responses->messages[i];
        ack_head = (dss_bcast_ack_head_t *)msg->buffer;
        src_inst = responses->messages[i].src_inst;
        dss_set_cluster_proto_vers((uint8)src_inst, ack_head->dss_head.sw_proto_ver);
        if (ack_head->dss_head.result == ERR_DSS_VERSION_NOT_MATCH) {
            community->version_not_match_inst |= ((uint64)0x1 << src_inst);
            continue;
        }
        if (ack_head->dss_head.size < sizeof(dss_bcast_ack_head_t)) {
            DSS_THROW_ERROR(ERR_DSS_MES_ILL, "msg len is invalid");
            return ERR_DSS_MES_ILL;
        }
        ret = dss_proc_broadcast_ack_single(ack_head, ack_msg_output);
        DSS_RETURN_IF_ERROR(ret);
    }
    return DSS_SUCCESS;
}

static void dss_release_broadcast_msg(mes_msg_list_t *responses)
{
    for (uint32 i = 0; i < responses->count; i++) {
        mes_release_msg(&responses->messages[i]);
    }
}

static int dss_proc_broadcast_ack(
    ruid_type ruid, dss_bcast_community_t *community, uint64 *succ_ack_inst, void *ack_msg_output)
{
    mes_msg_list_t responses;
    int ret = mes_broadcast_get_response(ruid, &responses, community->timeout);
    if (ret != DSS_SUCCESS) {
        LOG_DEBUG_INF("[MES] Try broadcast get response failed, ret is %d, ruid is %llu.", ret, ruid);
        return ret;
    }
    ret = dss_proc_broadcast_ack_inner(&responses, community, ack_msg_output);
    if (ret != DSS_SUCCESS) {
        dss_release_broadcast_msg(&responses);
        LOG_DEBUG_INF("[MES] Try broadcast get response failed, ret is %d, ruid is %llu.", ret, ruid);
        return ret;
    }
    // do not care ret, just check get ack msg
    for (uint32 i = 0; i < responses.count; i++) {
        uint32 src_inst = responses.messages[i].src_inst;
        *succ_ack_inst |= ((uint64)0x1 << src_inst);
    }
    *succ_ack_inst = *succ_ack_inst & (~community->version_not_match_inst);
    dss_release_broadcast_msg(&responses);
    return ret;
}

static void dss_handle_discard_recv_broadcast_msg(ruid_type ruid)
{
    mes_msg_list_t responses;
    int ret = mes_broadcast_get_response(ruid, &responses, 0);
    if (ret == CM_SUCCESS) {
        dss_release_broadcast_msg(&responses);
    }
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
static status_t dss_broadcast_msg(dss_bcast_req_head_t *req, dss_bcast_community_t *community, void *ack_msg_output)
{
    int32 ret = DSS_SUCCESS;

    dss_config_t *inst_cfg = dss_get_inst_cfg();
    dss_params_t *param = &inst_cfg->params;
    uint64 succ_req_inst = 0;
    uint64 succ_ack_inst = 0;
    uint32 i = 0;
    // init last send err with all
    uint64 cur_work_inst_map = dss_get_inst_work_status();
    uint64 snd_err_inst_map = (~community->succ_inst & cur_work_inst_map);
    uint64 last_inst_inst_map = 0;
    uint64 new_added_inst_map = 0;
    uint64 valid_inst = 0;
    uint64 valid_inst_mask = 0;
    do {
        // only send the last-send-failed and new added
        cm_reset_error();
        valid_inst_mask = ((cur_work_inst_map & snd_err_inst_map) | new_added_inst_map);
        valid_inst = (param->nodes_list.inst_map) & (~((uint64)0x1 << (uint64)(param->inst_id))) & valid_inst_mask;
        valid_inst = (~community->version_not_match_inst & valid_inst);
        if (valid_inst == 0) {
            if (community->version_not_match_inst != 0) {
                community->version_not_match_inst = 0;
                return ERR_DSS_VERSION_NOT_MATCH;
            }
            LOG_DEBUG_INF("[MES] No inst need to broadcast.");
            return CM_SUCCESS;
        }
        LOG_DEBUG_INF("[MES] Try broadcast num is %u, head cmd is %u.", i, req->type);
        uint32 count = cm_bitmap64_count(valid_inst);
        uint32 valid_inst_arr[DSS_MAX_INSTANCES] = {0};
        dss_get_valid_inst(valid_inst, valid_inst_arr, count);
        (void)mes_broadcast_request_sp((inst_type *)valid_inst_arr, count, req->dss_head.flags, &req->dss_head.ruid,
            (char *)req, req->dss_head.size);
        succ_req_inst = valid_inst;
        if (dss_bcast_need_ack(req->type)) {
            ret = dss_proc_broadcast_ack(req->dss_head.ruid, community, &succ_ack_inst, ack_msg_output);
        } else {
            dss_handle_discard_recv_broadcast_msg(req->dss_head.ruid);
            ret = CM_SUCCESS;
            succ_ack_inst = succ_req_inst;
        }

        uint64 succ_inst = valid_inst & succ_ack_inst;
        LOG_DEBUG_INF(
            "[MES] Try broadcast num is %u, valid_inst is %llu, succ_inst is %llu.", i, valid_inst, succ_inst);
        if (succ_inst != 0) {
            community->succ_inst = community->succ_inst | succ_inst;
        }
        if (ret == CM_SUCCESS && succ_req_inst == succ_ack_inst) {
            if (community->version_not_match_inst != 0) {
                community->version_not_match_inst = 0;
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

static bool32 dss_check_srv_status(mes_msg_t *msg)
{
    dss_message_head_t *dss_head = (dss_message_head_t *)(msg->buffer);
    if (g_dss_instance.status != DSS_STATUS_OPEN && dss_head->dss_cmd != DSS_CMD_ACK_JOIN_CLUSTER) {
        LOG_DEBUG_INF("[MES] Could not exec remote req for the dssserver is not open or msg not join cluster, src "
                      "node:%u, wait try again.",
            (uint32)(dss_head->src_inst));
        return CM_FALSE;
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
    dss_init_mes_head(&ack, cmd, 0, src_inst, dst_inst, ack_size + DSS_MES_MSG_HEAD_SIZE, version, ruid);
    ack.result = ret;
    (void)mes_send_response_x(dst_inst, ack.flags, ruid, 2, &ack, DSS_MES_MSG_HEAD_SIZE, ack_buf, ack_size);
}

static status_t dss_process_remote_req_prepare(dss_session_t *session, mes_msg_t *msg, dss_processor_t *processor)
{
    dss_message_head_t *dss_head = (dss_message_head_t *)msg->buffer;
    // ready the ack connection
    dss_check_peer_by_inst(&g_dss_instance, dss_head->src_inst);
    if (dss_head->dss_cmd != DSS_CMD_REQ_BROADCAST &&
        (!dss_need_exec_local() || get_instance_status_proc() != DSS_STATUS_OPEN)) {
        LOG_RUN_ERR("Proc msg cmd:%u from remote node:%u fail, can NOT exec here.", (uint32)dss_head->dss_cmd,
            dss_head->src_inst);
        return CM_ERROR;
    }

    if (dss_check_srv_status(msg) != CM_TRUE) {
        LOG_RUN_WAR("Proc msg cmd:%u from remote node:%u fail, local status %u not open, wait try again.",
            (uint32)dss_head->dss_cmd, dss_head->src_inst, g_dss_instance.status);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static status_t dss_process_remote_ack_prepare(dss_session_t *session, mes_msg_t *msg, dss_processor_t *processor)
{
    if (dss_check_srv_status(msg) != CM_TRUE) {
        dss_message_head_t *dss_head = (dss_message_head_t *)msg->buffer;
        LOG_RUN_WAR("Proc msg cmd:%u from remote node:%u fail, local status %u not open, wait try again.",
            (uint32)dss_head->dss_cmd, dss_head->src_inst, g_dss_instance.status);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static void dss_process_message(uint32 work_idx, ruid_type ruid, mes_msg_t *msg)
{
    cm_reset_error();

    DDES_FAULT_INJECTION_ACTION_TRIGGER_CUSTOM(
        DSS_FI_MES_PROC_ENTER, cm_sleep(ddes_fi_get_entry_value(DDES_FI_TYPE_CUSTOM_FAULT)));

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
    LOG_DEBUG_INF("[MES] Proc msg cmd:%u, src node:%u, dst node:%u begin.", (uint32)(dss_head->dss_cmd),
        (uint32)(dss_head->src_inst), (uint32)(dss_head->dst_inst));

    dss_session_ctrl_t *session_ctrl = dss_get_session_ctrl();
    dss_session_t *session = session_ctrl->sessions[work_idx];
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
    LOG_DEBUG_INF(
        "[MES] dss process message, cmd is %u, proto_version is %u.", dss_head->dss_cmd, dss_head->msg_proto_ver);
    dss_processor_t *processor = &g_dss_processors[dss_head->dss_cmd];
    const char *error_message = NULL;
    int32 error_code;
    // from here, the proc need to give the ack and release message buf
    while (CM_TRUE) {
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
        cm_get_error(&error_code, &error_message);
        if (error_code == ERR_DSS_SHM_LOCK_TIMEOUT) {
            cm_unlatch(&g_dss_instance.switch_latch, LATCH_STAT(LATCH_SWITCH));
            LOG_RUN_INF("Try again if error is shm lock timeout.");
            cm_reset_error();
            continue;
        }
        cm_unlatch(&g_dss_instance.switch_latch, LATCH_STAT(LATCH_SWITCH));
        break;
    }
    LOG_DEBUG_INF("[MES] Proc msg cmd:%u, src node:%u, dst node:%u end.", (uint32)(dss_head->dss_cmd),
        (uint32)(dss_head->src_inst), (uint32)(dss_head->dst_inst));
}

// add function
static status_t dss_register_proc(void)
{
    mes_register_proc_func(dss_process_message);
    return CM_SUCCESS;
}

#define DSS_MES_PRIO_CNT 2
static status_t dss_set_mes_message_pool(unsigned long long recv_msg_buf_size, mes_profile_t *profile)
{
    LOG_DEBUG_INF("mes message pool size:%llu", recv_msg_buf_size);
    int ret = CM_SUCCESS;
    mes_msg_pool_attr_t *mpa = &profile->msg_pool_attr;
    mpa->total_size = recv_msg_buf_size;
    mpa->enable_inst_dimension = CM_FALSE;
    mpa->buf_pool_count = DSS_MSG_BUFFER_NO_CEIL;

    mpa->buf_pool_attr[DSS_MSG_BUFFER_NO_0].buf_size = DSS_FIRST_BUFFER_LENGTH;
    mpa->buf_pool_attr[DSS_MSG_BUFFER_NO_1].buf_size = DSS_SECOND_BUFFER_LENGTH;
    mpa->buf_pool_attr[DSS_MSG_BUFFER_NO_2].buf_size = DSS_THIRD_BUFFER_LENGTH;
    mpa->buf_pool_attr[DSS_MSG_BUFFER_NO_3].buf_size = DSS_FOURTH_BUFFER_LENGTH;

    mes_msg_buffer_pool_attr_t *buf_pool_attr;
    buf_pool_attr = &mpa->buf_pool_attr[DSS_MSG_BUFFER_NO_3];
    buf_pool_attr->shared_pool_attr.queue_num = DSS_MSG_FOURTH_BUFFER_QUEUE_NUM;
    for (uint32 prio = 0; prio < profile->priority_cnt; prio++) {
        buf_pool_attr->priority_pool_attr[prio].queue_num = DSS_MSG_FOURTH_BUFFER_QUEUE_NUM;
    }

    for (uint8 buf_pool_no = 0; buf_pool_no < mpa->buf_pool_count; buf_pool_no++) {
        buf_pool_attr = &mpa->buf_pool_attr[buf_pool_no];
        buf_pool_attr->shared_pool_attr.queue_num = DSS_MSG_BUFFER_QUEUE_NUM;
        for (uint32 prio = 0; prio < profile->priority_cnt; prio++) {
            buf_pool_attr->priority_pool_attr[prio].queue_num = DSS_MSG_BUFFER_QUEUE_NUM;
        }
    }

    for (uint32 prio = 0; prio < profile->priority_cnt; prio++) {
        mpa->max_buf_size[prio] = mpa->buf_pool_attr[DSS_MSG_BUFFER_NO_3].buf_size;
    }

    mes_msg_pool_minimum_info_t minimum_info = {0};
    ret = mes_get_message_pool_minimum_info(profile, CM_FALSE, &minimum_info);
    if (ret != CM_SUCCESS) {
        LOG_RUN_ERR("[DSS] set mes message pool, get message pool minimum info failed");
        return ret;
    }
    // want fourth buf_pool smallest
    double fourth_ratio = ((double)(minimum_info.buf_pool_minimum_size[DSS_MSG_BUFFER_NO_3]) /
                              (mpa->total_size - minimum_info.metadata_size)) +
                          DBL_EPSILON;
    mpa->buf_pool_attr[DSS_MSG_BUFFER_NO_3].proportion = fourth_ratio;

    double left_ratio = 1 - fourth_ratio;
    mpa->buf_pool_attr[DSS_MSG_BUFFER_NO_0].proportion = DSS_FIRST_BUFFER_RATIO * left_ratio;
    mpa->buf_pool_attr[DSS_MSG_BUFFER_NO_1].proportion = DSS_SECOND_BUFFER_RATIO * left_ratio;
    mpa->buf_pool_attr[DSS_MSG_BUFFER_NO_2].proportion =
        1 - (mpa->buf_pool_attr[DSS_MSG_BUFFER_NO_0].proportion + mpa->buf_pool_attr[DSS_MSG_BUFFER_NO_1].proportion +
                mpa->buf_pool_attr[DSS_MSG_BUFFER_NO_3].proportion);
    return CM_SUCCESS;
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
    mes_profile->recv_task_count[MES_PRIORITY_ZERO] =
        MAX(1, (uint32)(work_thread_cnt_load_meta * DSS_RECV_WORK_THREAD_RATIO));

    mes_profile->send_task_count[MES_PRIORITY_ONE] = 0;
    mes_profile->work_task_count[MES_PRIORITY_ONE] = work_thread_cnt_comm;
    mes_profile->recv_task_count[MES_PRIORITY_ONE] =
        MAX(1, (uint32)(work_thread_cnt_comm * DSS_RECV_WORK_THREAD_RATIO));
}

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
    profile->mes_with_ip = inst_cfg->params.mes_with_ip;
    profile->ip_white_list_on = inst_cfg->params.ip_white_list_on;
    profile->inst_cnt = inst_cfg->params.nodes_list.inst_cnt;
    uint32 inst_cnt = 0;
    for (uint32 i = 0; i < DSS_MAX_INSTANCES; i++) {
        uint64_t inst_mask = ((uint64)0x1 << i);
        if ((inst_cfg->params.nodes_list.inst_map & inst_mask) == 0) {
            continue;
        }
        errcode = strncpy_s(profile->inst_net_addr[inst_cnt].ip, CM_MAX_IP_LEN, inst_cfg->params.nodes_list.nodes[i],
            strlen(inst_cfg->params.nodes_list.nodes[i]));
        if (errcode != EOK) {
            DSS_RETURN_IFERR2(CM_ERROR, DSS_THROW_ERROR(ERR_SYSTEM_CALL, (errcode)));
        }
        profile->inst_net_addr[inst_cnt].port = inst_cfg->params.nodes_list.ports[i];
        profile->inst_net_addr[inst_cnt].need_connect = CM_TRUE;
        profile->inst_net_addr[inst_cnt].inst_id = i;
        inst_cnt++;
        if (inst_cnt == inst_cfg->params.nodes_list.inst_cnt) {
            break;
        }
    }
    profile->priority_cnt = DSS_MES_PRIO_CNT;
    profile->frag_size = DSS_FOURTH_BUFFER_LENGTH;
    profile->max_wait_time = inst_cfg->params.mes_wait_timeout;
    profile->connect_timeout = (int)CM_CONNECT_TIMEOUT;
    profile->socket_timeout = (int)CM_NETWORK_IO_TIMEOUT;

    dss_set_group_task_num(inst_cfg, profile);
    status_t status = dss_set_mes_message_pool(inst_cfg->params.mes_pool_size, profile);
    if (status != CM_SUCCESS) {
        return status;
    }
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
        dss_session_t *session = session_ctrl->sessions[i];
        session->is_direct = CM_TRUE;
        session->is_closed = CM_FALSE;
        session->is_used = CM_FALSE;
    }
    session_ctrl->used_count = mes_sess_cnt;
    cm_spin_unlock(&session_ctrl->lock);
    return CM_SUCCESS;
}

void dss_mes_regist_other_proc()
{
    dss_config_t *inst_cfg = dss_get_inst_cfg();
    if (!g_dss_instance.is_maintain && inst_cfg->params.nodes_list.inst_cnt > 1) {
        regist_remote_read_proc(dss_read_volume_remote);
        regist_invalidate_other_nodes_proc(dss_invalidate_other_nodes);
        regist_broadcast_check_file_open_proc(dss_broadcast_check_file_open);
        regist_refresh_ft_by_primary_proc(dss_refresh_ft_by_primary);
        regist_get_node_by_path_remote_proc(dss_get_node_by_path_remote);
        regist_meta_syn2other_nodes_proc(dss_syn_data2other_nodes);
    }
}

status_t dss_startup_mes(void)
{
    status_t status = dss_register_proc();
    DSS_RETURN_IFERR2(status, LOG_RUN_ERR("dss_register_proc failed."));

    status = dss_create_mes_session();
    DSS_RETURN_IFERR2(status, LOG_RUN_ERR("dss_set_mes_profile failed."));

    mes_profile_t profile;
    status = dss_set_mes_profile(&profile);
    DSS_RETURN_IFERR2(status, LOG_RUN_ERR("dss_set_mes_profile failed."));

    dss_notify_regist_mes_func((dss_regist_mes_func_t)dss_mes_regist_other_proc);

    dss_mes_regist_other_proc();
    return mes_init(&profile);
}

void dss_stop_mes(void)
{
    mes_uninit();
}

status_t dss_sync_boc(dss_bcast_req_head_t *req, uint32 req_size, void *ack_msg_output)
{
    if (g_dss_instance.is_maintain) {
        return CM_SUCCESS;
    }
    dss_config_t *inst_cfg = dss_get_inst_cfg();
    dss_params_t *param = &inst_cfg->params;
    dss_bcast_community_t community = {0};
    community.broadcast_proto_ver = dss_get_broadcast_proto_ver(0);
    community.timeout = param->mes_wait_timeout;
    status_t ret;
    do {
        LOG_DEBUG_INF("[MES] notify other dss instance to do cmd %u.", req->type);
        dss_init_mes_head(&req->dss_head, DSS_CMD_REQ_BROADCAST, 0, (uint16)param->inst_id, CM_INVALID_ID16, req_size,
            community.broadcast_proto_ver, 0);
        ret = dss_broadcast_msg(req, &community, ack_msg_output);
        if (ret == ERR_DSS_VERSION_NOT_MATCH) {
            uint32 new_proto_ver = dss_get_broadcast_proto_ver(community.succ_inst);
            LOG_RUN_INF("[CHECK_PROTO]broadcast msg proto version has changed, old is %hhu, new is %hhu",
                community.broadcast_proto_ver, new_proto_ver);
            community.broadcast_proto_ver = new_proto_ver;
            community.version_not_match_inst = 0;
            // if msg has been changed, need rewrite req
            continue;
        } else {
            break;
        }
    } while (CM_TRUE);
    if (ret != CM_SUCCESS) {
        LOG_RUN_ERR("[DSS]: Failed to notify other dss instance, cmd: %u, errcode:%d, "
                    "OS errno:%d, OS errmsg:%s.",
            req->type, cm_get_error_code(), errno, strerror(errno));
        return CM_ERROR;
    }
    return ret;
}

status_t dss_bcast_ask_file_open(dss_vg_info_item_t *vg_item, uint64 ftid, bool32 *cmd_ack)
{
    dss_req_check_open_file_t req;
    req.ftid = ftid;
    req.bcast_head.type = BCAST_REQ_DEL_DIR_FILE;
    errno_t err = strncpy_s(req.vg_name, DSS_MAX_NAME_LEN, vg_item->vg_name, strlen(vg_item->vg_name));
    if (err != EOK) {
        DSS_THROW_ERROR(ERR_SYSTEM_CALL, err);
        return CM_ERROR;
    }
    LOG_DEBUG_INF("[MES] notify other dss instance to do cmd %u, ftid:%llu in vg:%s.", req.bcast_head.type, ftid,
        vg_item->vg_name);
    dss_bcast_ack_bool_t recv_msg = {.default_ack = DSS_FALSE, .cmd_ack = DSS_FALSE};
    DSS_RETURN_IF_ERROR(dss_sync_boc((dss_bcast_req_head_t *)&req, sizeof(dss_req_check_open_file_t), &recv_msg));
    if (cmd_ack != NULL) {
        *cmd_ack = recv_msg.cmd_ack;
    }
    return CM_SUCCESS;
}

status_t dss_bcast_meta_data(dss_bcast_req_cmd_t cmd, char *data, uint32 size, bool32 *cmd_ack)
{
    dss_req_meta_data_t req;
    req.bcast_head.type = cmd;
    req.data_size = size;
    errno_t err = memcpy_s(req.data, sizeof(req.data), data, size);
    if (err != EOK) {
        DSS_THROW_ERROR(ERR_SYSTEM_CALL, err);
        return CM_ERROR;
    }
    dss_bcast_ack_bool_t recv_msg = {.default_ack = DSS_TRUE, .cmd_ack = DSS_TRUE};
    DSS_RETURN_IF_ERROR(
        dss_sync_boc((dss_bcast_req_head_t *)&req, OFFSET_OF(dss_req_meta_data_t, data) + size, &recv_msg));
    if (cmd_ack != NULL) {
        *cmd_ack = recv_msg.cmd_ack;
    }
    return CM_SUCCESS;
}

status_t dss_invalidate_other_nodes(
    dss_vg_info_item_t *vg_item, char *meta_info, uint32 meta_info_size, bool32 *cmd_ack)
{
    return dss_bcast_meta_data(BCAST_REQ_INVALIDATE_META, meta_info, meta_info_size, cmd_ack);
}

status_t dss_broadcast_check_file_open(dss_vg_info_item_t *vg_item, uint64 ftid, bool32 *cmd_ack)
{
    return dss_bcast_ask_file_open(vg_item, ftid, cmd_ack);
}

status_t dss_syn_data2other_nodes(dss_vg_info_item_t *vg_item, char *meta_syn, uint32 meta_syn_size, bool32 *cmd_ack)
{
    return dss_bcast_meta_data(BCAST_REQ_META_SYN, meta_syn, meta_syn_size, cmd_ack);
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
        if ((inst_cfg->params.nodes_list.inst_map & inst_mask) == 0) {
            continue;
        }
        dss_check_inst_conn(id, (old_inst_map & inst_mask), (cur_inst_map & inst_mask));
        inst_cnt++;
        if (inst_cnt == inst_cfg->params.nodes_list.inst_cnt) {
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
        ret = mes_send_request_x(dss_head.dst_inst, dss_head.flags, &dss_head.ruid, 2, &dss_head, DSS_MES_MSG_HEAD_SIZE,
            session->recv_pack.buf, session->recv_pack.head->size);
        char *err_msg = "The dss server fails to send messages to the remote node";
        DSS_RETURN_IFERR2(ret, LOG_RUN_ERR("%s, src node(%u), dst node(%u).", err_msg, currtid, remoteid));
        // 3. receive msg from remote
        ret = dss_get_mes_response(dss_head.ruid, &msg, timeout);
        DSS_RETURN_IFERR2(
            ret, LOG_RUN_ERR("dss server receive msg from remote failed, src node:%u, dst node:%u, cmd:%u.", currtid,
                     remoteid, session->recv_pack.head->cmd));
        // 4. attach remote execution result
        ack_head = (dss_message_head_t *)msg.buffer;
        if (ack_head->result == ERR_DSS_VERSION_NOT_MATCH) {
            session->client_version = dss_get_client_version(&session->recv_pack);
            new_proto_ver = MIN(ack_head->sw_proto_ver, DSS_PROTO_VERSION);
            new_proto_ver = MIN(new_proto_ver, session->client_version);
            session->proto_version = new_proto_ver;
            if (session->proto_version != dss_get_version(&session->recv_pack)) {
                LOG_RUN_INF("[CHECK_PROTO]The client protocol version need be changed, old protocol version is %u, new "
                            "protocol version is %u",
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
            DSS_RETURN_IFERR3(CM_ERROR, DSS_THROW_ERROR(ERR_DSS_MES_ILL, "msg len is invalid"), mes_release_msg(&msg));
        }
        dss_remote_exec_fail_ack_t *fail_ack = (dss_remote_exec_fail_ack_t *)msg.buffer;
        DSS_THROW_ERROR(ERR_DSS_PROCESS_REMOTE, fail_ack->err_code, fail_ack->err_msg);
    } else if (body_size > 0) {
        dss_remote_exec_succ_ack_t *succ_ack = (dss_remote_exec_succ_ack_t *)msg.buffer;
        LOG_DEBUG_INF("[MES] dss server receive msg from remote node, cmd:%u, ack to cli data size:%u.",
            session->recv_pack.head->cmd, body_size);
        dss_remote_ack_hdl_t *handle = dss_get_remote_ack_handle(session->recv_pack.head->cmd);
        if (handle != NULL) {
            handle->proc(session, succ_ack);
        }
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

    DSS_RETURN_IF_ERROR(dss_get_exec_nodeid(session, &currid, &remoteid));

    LOG_DEBUG_INF("[MES] Exec cmd:%u on remote node:%u begin.", (uint32)cmd, remoteid);
    do {
        uint32 proto_ver = dss_get_remote_proto_ver(remoteid);
        // 1. init msg head
        dss_init_mes_head(dss_head, cmd, 0, (uint16)currid, (uint16)remoteid, req_size, proto_ver, 0);
        // 2. send request to remote
        ret = mes_send_request(remoteid, dss_head->flags, &dss_head->ruid, req, dss_head->size);
        if (ret != CM_SUCCESS) {
            LOG_RUN_ERR("Exec cmd:%u on remote node:%u send msg fail.", (uint32)cmd, remoteid);
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
            // if msg version has changed, please motify your change
            mes_release_msg(&msg);
            continue;
        }
        break;
    } while (CM_TRUE);
    // 4. attach remote execution result
    *remote_result = ack_head->result;
    LOG_DEBUG_INF("[MES] dss server receive msg from remote node, cmd:%u, ack to cli data size:%hu, remote_result:%u.",
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
    LOG_DEBUG_INF("[MES] Exec cmd:%u on remote node:%u end.", (uint32)cmd, remoteid);
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
    LOG_DEBUG_INF("[MES] The dss server receive messages from remote node, src node:%u, dst node:%u.", srcid, dstid);
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
    LOG_DEBUG_INF(
        "[MES] The dss server send messages to the remote node, src node:%u, dst node:%u, cmd:%u,ack size:%u.", srcid,
        dstid, session->send_pack.head->cmd, body_size);
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
    LOG_DEBUG_INF("[MES] The dss server send messages to the remote node success, src node:%u, dst node:%u.",
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

    LOG_DEBUG_INF("[MES] The dss server send messages to the remote node success, src node:%u, dst node:%u.",
        (uint32)(dss_head->src_inst), (uint32)(dss_head->dst_inst));
    return ret;
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

        LOG_DEBUG_INF("[MES] load disk from active info vg name(%s) volume id(%u) msg seq(%hu) msg len(%u).",
            req->vg_name, req->volumeid, ctrl.seq, ctrl.cursize);

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
    dss_lock_vg_mem_and_shm_ex_s(session, req->vg_name);
    int32 ret = dss_batch_load_core(session, req, g_thv_read_buf, version);
    dss_unlock_vg_mem_and_shm_ex(session, req->vg_name);
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
    LOG_DEBUG_INF("[MES] Exec load disk req, src node(%hu), volume id:%u, offset:%llu, size:%u.",
        req_dss_head->src_inst, req->volumeid, req->offset, req->size);
    ret = dss_batch_load(session, req, req_dss_head->msg_proto_ver);
    if (ret != CM_SUCCESS) {
        LOG_RUN_ERR("Exec load disk req failed, src node:%u, volume id:%u, offset:%llu, size:%u.",
            (uint32)(req_dss_head->src_inst), req->volumeid, req->offset, req->size);
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
    DSS_RETURN_IF_ERROR(dss_get_exec_nodeid(session, currid, remoteid));
    if (*currid == *remoteid) {
        LOG_DEBUG_ERR("read from current node %u no need to send message.", *currid);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static bool32 dss_packets_verify(big_packets_ctrl_t *lastctrl, big_packets_ctrl_t *ctrl, uint32 size)
{
    if (ctrl->endflag != CM_TRUE && size != ctrl->totalsize) {
        LOG_RUN_ERR("[MES] end flag is not CM_TRUE.");
        return CM_FALSE;
    }
    if (ctrl->endflag == CM_TRUE && ctrl->cursize + ctrl->offset != ctrl->totalsize) {
        LOG_RUN_ERR("[MES]size is not true, cursize is %u, offset is %u, total size is %u.", ctrl->cursize,
            ctrl->offset, ctrl->totalsize);
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
        if (dss_packets_verify(&lastctrl, ctrl, size) == CM_FALSE) {
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
        LOG_DEBUG_INF("[MES] Ready msg cmd:%u, src node:%u, dst node:%u end", dss_head->dss_cmd,
            (uint32)(dss_head->src_inst), (uint32)(dss_head->dst_inst));
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
    req.offset = (uint64)offset;
    req.size = (uint32)size;
    // 1. init msg head
    uint32 remote_proto_ver = dss_get_remote_proto_ver(remoteid);
    dss_init_mes_head(&req.dss_head, DSS_CMD_REQ_LOAD_DISK, 0, (uint16)currid, (uint16)remoteid,
        sizeof(dss_loaddisk_req_t), remote_proto_ver, 0);
    ret = dss_read_volume_remote_core(session, &req, buf);
    dss_destroy_session(session);
    if (ret != CM_SUCCESS) {
        LOG_RUN_ERR(
            "The dssserver receive messages from remote node failed, src node:%u, dst node:%u.", currid, remoteid);
        return ret;
    }

    LOG_DEBUG_INF("[MES] load disk(%s) data from the active node success.", vg_name);
    return CM_SUCCESS;
}

status_t dss_join_cluster(bool32 *join_succ)
{
    *join_succ = CM_FALSE;

    LOG_DEBUG_INF("[MES] Try join cluster begin.");

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

    LOG_DEBUG_INF("[MES] Try join cluster exec result:%u.", (uint32)*join_succ);
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
        "[MES] Proc join cluster from remote node:%u reg node:%u begin.", (uint32)(req_head->src_inst), req->reg_id);

    // only in the work_status map can join the cluster

    dss_join_cluster_ack_t ack;
    dss_init_mes_head(
        &ack.ack_head, DSS_CMD_ACK_JOIN_CLUSTER, 0, src_inst, dst_inst, sizeof(dss_join_cluster_ack_t), version, ruid);
    ack.is_reg = CM_FALSE;
    ack.ack_head.result = CM_SUCCESS;
    uint64 work_status = dss_get_inst_work_status();
    uint64 inst_mask = ((uint64)0x1 << req->reg_id);
    if (work_status & inst_mask) {
        ack.is_reg = CM_TRUE;
    }

    LOG_DEBUG_INF("[MES] Proc join cluster from remote node:%u, reg node:%u, is_reg:%u.", (uint32)(req_head->src_inst),
        req->reg_id, (uint32)ack.is_reg);
    int send_ret = mes_send_response(dst_inst, ack.ack_head.flags, ruid, (char *)&ack, ack.ack_head.size);
    if (send_ret != CM_SUCCESS) {
        LOG_RUN_ERR("Proc join cluster from remote node:%u, reg node:%u send ack fail.", (uint32)dst_inst, req->reg_id);
        return;
    }

    LOG_DEBUG_INF("[MES] Proc join cluster from remote node:%u, reg node:%u send ack size:%u end.", (uint32)dst_inst,
        req->reg_id, ack.ack_head.size);
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
        *output_info->parent_node = dss_get_node_by_ft(*shm_block, ack->parent_node_id.item);
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
        DSS_THROW_ERROR(ERR_DSS_MES_ILL, "Invalid get ft node id ack msg error.");
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
            *output_info->out_node = dss_get_node_by_ft(shm_block, ack.node_id.item);
        }
    }
    return dss_get_node_by_path_inner(session, output_info, &ack, ack_vg_item, &shm_block);
}

status_t dss_refresh_ft_by_primary(dss_block_id_t blockid, uint32 vgid, char *vg_name)
{
    LOG_DEBUG_INF("[MES] Try refresh ft by primary begin.");

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

    LOG_DEBUG_INF("[MES] Try refresh ft by primary result:%u.", ack.is_ok);
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
        dss_unlock_vg_mem_and_shm(session, *vg_item);
        *vg_item = file_vg_item;
        dss_lock_vg_mem_and_shm_s_force(session, *vg_item);
    }
    ack->node_id = out_node->id;
    DSS_LOG_DEBUG_OP("[MES] Req out node, v:%u,au:%llu,block:%u,item:%u,type:%d,path:%s.", out_node->id.volume,
        (uint64)out_node->id.au, out_node->id.block, out_node->id.item, req->type, req->path);
    dss_ft_block_t *block = dss_get_ft_by_node(out_node);

    // may updt written size updating the info
    if (out_node->type != GFT_PATH) {
        dss_latch_s_node(session, out_node, NULL);
    }
    errno_t errcode = memcpy_s(ack->block, DSS_BLOCK_SIZE, block, DSS_BLOCK_SIZE);
    if (out_node->type != GFT_PATH) {
        dss_unlatch_node(out_node);
    }

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
        DSS_LOG_DEBUG_OP(
            "[MES] Req parent node: %s,type:%d,path:%s.", dss_display_metaid(parent_node->id), req->type, req->path);
        block = dss_get_ft_by_node(parent_node);
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
        LOG_RUN_ERR("Get ft block from remote node:%u check req msg type:%d fail.", (uint32)dst_inst, req->type);
        dss_proc_remote_req_err(session, &req->dss_head, DSS_CMD_ACK_GET_FT_BLOCK, CM_ERROR);
        return;
    }
    status_t status = dss_check_device_path(req->path);
    if (status != CM_SUCCESS) {
        dss_proc_remote_req_err(session, &req->dss_head, DSS_CMD_ACK_GET_FT_BLOCK, status);
        return;
    }
    LOG_DEBUG_INF("[MES] Get ft block from remote node:%u, path:%s begin.", (uint32)dst_inst, req->path);
    uint32 beg_pos = 0;
    char vg_name[DSS_MAX_NAME_LEN];
    status = dss_get_name_from_path(req->path, &beg_pos, vg_name);
    if (status != CM_SUCCESS) {
        dss_proc_remote_req_err(session, &req->dss_head, DSS_CMD_ACK_GET_FT_BLOCK, status);
    }
    dss_get_ft_block_ack_t ack;
    dss_init_mes_head(&ack.ack_head, DSS_CMD_ACK_GET_FT_BLOCK, 0, src_inst, dst_inst, sizeof(dss_get_ft_block_ack_t),
        proto_ver, ruid);
    dss_vg_info_item_t *vg_item = dss_find_vg_item(vg_name);
    if (vg_item == NULL) {
        LOG_RUN_ERR("invalid vg name: %s ,Get vg item fail.", vg_name);
        DSS_THROW_ERROR(ERR_DSS_VG_NOT_EXIST, vg_name);
        return;
    }
    dss_lock_vg_mem_and_shm_s_force(session, vg_item);
    status = dss_proc_get_ft_block_req_core(session, req, &ack, &vg_item);
    dss_unlock_vg_mem_and_shm(session, vg_item);
    if (status != CM_SUCCESS) {
        dss_proc_remote_req_err(session, &req->dss_head, DSS_CMD_ACK_GET_FT_BLOCK, status);
        return;
    }
    ack.ack_head.result = CM_SUCCESS;
    int send_ret = mes_send_response(dst_inst, ack.ack_head.flags, ruid, (char *)&ack, ack.ack_head.size);
    if (send_ret != CM_SUCCESS) {
        LOG_RUN_ERR("Get ft block from remote node:%u, path:%s send ack fail.", (uint32)(dst_inst), req->path);
    } else {
        LOG_DEBUG_INF("[MES] Get ft block from remote node:%u, path:%s end.", (uint32)(dst_inst), req->path);
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
    LOG_DEBUG_INF("[MES] Refresh ft by primary from remote node:%u, blockid:%s, vgid:%u, vg_name:%s begin.",
        (uint32)(req_head->src_inst), dss_display_metaid(refresh_ft_req->blockid), refresh_ft_req->vgid,
        refresh_ft_req->vg_name);
    if (dss_refresh_ft_block(session, refresh_ft_req->vg_name, refresh_ft_req->vgid, refresh_ft_req->blockid) !=
        CM_SUCCESS) {
        LOG_RUN_ERR("Refresh ft by primary from remote node:%u, blockid:%s, vgid:%u, vg_name:%s refresh fail.",
            (uint32)(req_head->src_inst), dss_display_metaid(refresh_ft_req->blockid), refresh_ft_req->vgid,
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
        LOG_RUN_ERR("Refresh ft by primary from remote node:%u, blockid:%s, vgid:%u, vg_name:%s send ack fail.",
            (uint32)dst_inst, dss_display_metaid(refresh_ft_req->blockid), refresh_ft_req->vgid,
            refresh_ft_req->vg_name);
        return;
    }

    LOG_DEBUG_INF("[MES] Refresh ft by primary from remote node:%u, blockid:%s, vgid:%u, vg_name:%s refresh end.",
        (uint32)dst_inst, dss_display_metaid(refresh_ft_req->blockid), refresh_ft_req->vgid, refresh_ft_req->vg_name);
}