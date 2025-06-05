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
 * dss_mes.h
 *
 *
 * IDENTIFICATION
 *    src/service/dss_mes.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __DSS_MES_H__
#define __DSS_MES_H__

#include "mes_interface.h"
#include "dss_file_def.h"
#include "dss_session.h"
#include "dss_bcast_def.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum en_dss_mes_command {
    DSS_CMD_REQ_BROADCAST = 0,
    DSS_CMD_ACK_BROADCAST_WITH_MSG,
    DSS_CMD_REQ_SYB2ACTIVE, /* Request command from the standby node to the active node */
    DSS_CMD_ACK_SYB2ACTIVE,
    DSS_CMD_REQ_LOAD_DISK,
    DSS_CMD_ACK_LOAD_DISK,
    DSS_CMD_REQ_JOIN_CLUSTER,
    DSS_CMD_ACK_JOIN_CLUSTER,
    DSS_CMD_REQ_REFRESH_FT,
    DSS_CMD_ACK_REFRESH_FT,
    DSS_CMD_REQ_GET_FT_BLOCK,
    DSS_CMD_ACK_GET_FT_BLOCK,
    DSS_CMD_CEIL,
} dss_mes_command_t;

typedef enum en_dss_msg_buffer_number {
    DSS_MSG_BUFFER_NO_0 = 0,
    DSS_MSG_BUFFER_NO_1,
    DSS_MSG_BUFFER_NO_2,
    DSS_MSG_BUFFER_NO_3,
    DSS_MSG_BUFFER_NO_CEIL
} dss_msg_buffer_number_e;

#define DSS_MES_PRIO_CNT 2
#define DSS_MES_THREAD_NUM 2
#define DSS_MES_TRY_TIMES 100
#define DSS_BROADCAST_WAIT_INFINITE (0xFFFFFFFF)
#define DSS_IS_INST_SEND(bits, id) (((bits) >> (id)) & 0x1)
#define DSS_MSG_BUFFER_QUEUE_NUM (8)
#define DSS_MSG_FOURTH_BUFFER_QUEUE_NUM (1)
#define DSS_FIRST_BUFFER_LENGTH (256)
#define DSS_SECOND_BUFFER_LENGTH (SIZE_K(1) + 256)
#define DSS_THIRD_BUFFER_LENGTH (SIZE_K(32) + 256)
#define DSS_FOURTH_BUFFER_LENGTH (DSS_LOADDISK_BUFFER_SIZE + 256)
#define DSS_CKPT_NOTIFY_TASK_RATIO (1.0f / 4)
#define DSS_CLEAN_EDP_TASK_RATIO (1.0f / 4)
#define DSS_TXN_INFO_TASK_RATIO (1.0f / 16)
#define DSS_RECV_WORK_THREAD_RATIO (1.0f / 4)
#define DSS_FIRST_BUFFER_RATIO ((double)1.0 / 8)
#define DSS_SECOND_BUFFER_RATIO ((double)3.0 / 8)
#define DSS_THIRDLY_BUFFER_RATIO ((double)1.0 / 2)

typedef void (*dss_message_proc_t)(dss_session_t *session, mes_msg_t *msg);
typedef struct st_processor_func {
    dss_mes_command_t cmd_type;
    dss_message_proc_t proc;
    bool32 is_enqueue_work_thread;  // Whether to let the worker thread process
    const char *func_name;
} processor_func_t;

typedef struct st_dss_processor {
    dss_message_proc_t proc;
    bool32 is_enqueue;
    bool32 is_req;
    mes_priority_t prio_id;
    char *name;
} dss_processor_t;

typedef struct st_dss_mes_actnode {
    bool8 is_active;
    uint8 node_id;
    uint16 rsvd;
    uint32 node_rsn;
} dss_mes_actnode_t;

typedef struct st_dss_mes_actlist {
    uint32 count;
    dss_mes_actnode_t node[0];
} dss_mes_actlist_t;

typedef struct st_dss_bcast_community {
    uint32 broadcast_proto_ver;
    uint64 succ_inst;
    uint64 version_not_match_inst;
    uint32 timeout;
} dss_bcast_community_t;

typedef struct st_dss_bcast_ack_bool {
    bool32 default_ack;
    bool32 cmd_ack;
} dss_bcast_ack_bool_t;

typedef struct st_dss_get_version_output {
    bool32 all_same;
    uint32 min_version;
} dss_get_version_output_t;

/*--------------------The following structures involve protocols and cannot be modified-------------------------------*/
typedef struct st_dss_req_common {
    dss_bcast_req_head_t bcast_head;
} dss_req_common_t;

typedef struct st_dss_req_check_open_file {
    dss_bcast_req_head_t bcast_head;
    uint64 ftid;
    char vg_name[DSS_MAX_NAME_LEN];
} dss_req_check_open_file_t;

typedef struct st_dss_req_invalid_meta {
    dss_bcast_req_head_t bcast_head;
    uint32 data_size;  // just for compatibility,fixed value:sizeof(dss_invalidate_meta_msg_t)
    dss_invalidate_meta_msg_t data;
} dss_req_invalid_meta_t;

typedef struct st_dss_ack_common {
    dss_bcast_ack_head_t bcast_head;
    int32 result;
    bool32 cmd_ack;
} dss_ack_common_t;

typedef struct st_dss_ack_get_version {
    dss_bcast_ack_head_t bcast_head;
    uint32 version;
} dss_ack_get_version_t;

typedef struct st_dss_remote_exec_succ_ack {
    dss_message_head_t ack_head;
    char body_buf[4];
} dss_remote_exec_succ_ack_t;

typedef struct st_dss_remote_exec_fail_ack {
    dss_message_head_t ack_head;
    int32 err_code;
    char err_msg[4];
} dss_remote_exec_fail_ack_t;

typedef struct st_big_packets_ctrl {
    dss_message_head_t dss_head;
    uint32 offset;
    uint32 cursize;
    uint32 totalsize;
    uint16 seq;
    uint8 endflag;
    uint8 reseved;
} big_packets_ctrl_t;

typedef struct st_loaddisk_req {
    dss_message_head_t dss_head;
    uint32 volumeid;
    uint32 size;
    uint64 offset;
    char vg_name[DSS_MAX_NAME_LEN];
} dss_loaddisk_req_t;

typedef struct st_join_cluster_req {
    dss_message_head_t dss_head;
    uint32 reg_id;
} dss_join_cluster_req_t;

typedef struct st_join_cluster_ack {
    dss_message_head_t ack_head;
    bool32 is_reg;
} dss_join_cluster_ack_t;

typedef struct st_refresh_ft_req {
    dss_message_head_t dss_head;
    dss_block_id_t blockid;
    uint32 vgid;
    char vg_name[DSS_MAX_NAME_LEN];
} dss_refresh_ft_req_t;

typedef struct st_refresh_ft_ack {
    dss_message_head_t ack_head;
    bool32 is_ok;
} dss_refresh_ft_ack_t;

typedef struct st_get_ft_block_req {
    dss_message_head_t dss_head;
    char path[DSS_FILE_PATH_MAX_LENGTH];
    gft_item_type_t type;
    // add flag after DSS_VERSION_2
    int32 flag;
} dss_get_ft_block_req_t;

typedef struct st_get_ft_block_ack {
    dss_message_head_t ack_head;
    dss_block_id_t node_id;
    dss_block_id_t parent_node_id;
    char vg_name[DSS_MAX_NAME_LEN];
    char block[DSS_BLOCK_SIZE];
    char parent_block[DSS_BLOCK_SIZE];
} dss_get_ft_block_ack_t;

typedef struct st_dss_bcast_context {
    char *req_msg;
    unsigned int req_len;
    char *ack_msg;
    unsigned int ack_len;
} dss_bcast_context_t;

#define DSS_MES_MSG_HEAD_SIZE (sizeof(dss_message_head_t))
uint32 dss_get_broadcast_proto_ver(uint64 succ_inst);

status_t dss_exec_sync(dss_session_t *session, uint32 remoteid, uint32 currtid, status_t *remote_result);
status_t dss_invalidate_other_nodes(
    dss_session_t *session, dss_vg_info_item_t *vg_item, dss_invalidate_meta_msg_t *meta_info, bool32 *cmd_ack);
status_t dss_broadcast_check_file_open(
    dss_session_t *session, dss_vg_info_item_t *vg_item, uint64 ftid, bool32 *cmd_ack);
status_t dss_syn_data2other_nodes(dss_session_t *session, dss_req_meta_data_t *req, bool32 *cmd_ack);
status_t dss_bcast_get_protocol_version(dss_session_t *session, dss_get_version_output_t *get_version_output);

void dss_check_mes_conn(uint64 cur_inst_map);
void dss_mes_regist_other_proc();
status_t dss_startup_mes(void);
void dss_stop_mes(void);
int32 dss_proc_broadcast_ack_single(dss_bcast_ack_head_t *ack_head, void *ack_buf);
void dss_proc_broadcast_req(dss_session_t *session, mes_msg_t *msg);
void dss_proc_syb2active_req(dss_session_t *session, mes_msg_t *msg);
void dss_proc_loaddisk_req(dss_session_t *session, mes_msg_t *msg);
void dss_proc_join_cluster_req(dss_session_t *session, mes_msg_t *msg);
void dss_proc_refresh_ft_by_primary_req(dss_session_t *session, mes_msg_t *msg);
void dss_proc_get_ft_block_req(dss_session_t *session, mes_msg_t *msg);

status_t dss_read_volume_remote(const char *vg_name, dss_volume_t *volume, int64 offset, void *buf, int32 size);
status_t dss_send2standby(big_packets_ctrl_t *ack, const char *buf);
int32 dss_batch_load(dss_session_t *session, dss_loaddisk_req_t *req, uint32 version);
status_t dss_join_cluster(dss_session_t *session, bool32 *join_succ);
status_t dss_refresh_ft_by_primary(dss_session_t *session, dss_block_id_t blockid, uint32 vgid, char *vg_name);
status_t dss_get_node_by_path_remote(dss_session_t *session, const char *dir_path, gft_item_type_t type,
    dss_check_dir_output_t *output_info, int32 flag, bool32 is_throw_err);

#ifdef __cplusplus
}
#endif

#endif
