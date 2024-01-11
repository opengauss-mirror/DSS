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

#define DSS_MES_THREAD_NUM 2
#define DSS_MES_TRY_TIMES 100
#define DSS_BROADCAST_WAIT_INFINITE (0xFFFFFFFF)
#define DSS_IS_INST_SEND(bits, id) (((bits) >> (id)) & 0x1)
#define DSS_BUFFER_POOL_NUM (3)
#define DSS_MSG_BUFFER_QUEUE_NUM (8)
#define DSS_FIRST_BUFFER_LENGTH (128)
#define DSS_SECOND_BUFFER_LENGTH (256)
#define DSS_THIRD_BUFFER_LENGTH (SIZE_K(32) + 256)
#define DSS_CKPT_NOTIFY_TASK_RATIO (1.0f / 4)
#define DSS_CLEAN_EDP_TASK_RATIO (1.0f / 4)
#define DSS_TXN_INFO_TASK_RATIO (1.0f / 16)
#define DSS_RECV_WORK_THREAD_RATIO (1.0f / 4)
#define DSS_FIRST_BUFFER_RATIO (1.0f / 4)
#define DSS_SECOND_BUFFER_RATIO (1.0f / 4)
#define DSS_THIRDLY_BUFFER_RATIO (1.0f / 2)

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
// clang-format off
typedef enum st_dss_bcast_req_cmd {
    BCAST_REQ_DEL_DIR_FILE = 0,
    BCAST_REQ_INVALIDATE_FS_META,
    BCAST_REQ_END
} dss_bcast_req_cmd_t;

typedef enum st_dss_bcast_ack_cmd {
    BCAST_ACK_DEL_FILE = 0,
    BCAST_ACK_INVALIDATE_FS_META,
    BCAST_ACK_END
} dss_bcast_ack_cmd_t;

// clang-format on
typedef struct st_dss_bcast_req {
    dss_bcast_req_cmd_t type;
    char buffer[4];
} dss_bcast_req_t;

typedef struct st_dss_recv_msg {
    bool32 handle_recv_msg;
    bool32 cmd_ack;
    uint32 broadcast_proto_ver;
    uint64 version_not_match_inst;
    uint64 succ_inst;
} dss_recv_msg_t;

typedef struct st_dss_message_head {
    uint32 msg_proto_ver;
    uint32 sw_proto_ver;
    uint16 src_inst;
    uint16 dst_inst;
    uint32 dss_cmd;
    uint32 size;
    uint32 flags;
    ruid_type ruid;
    int32 result;
    uint8 reserve[64];
} dss_message_head_t;

typedef struct st_dss_notify_req_msg {
    dss_message_head_t dss_head;
    dss_bcast_req_cmd_t type;
    uint64 ftid;
    char vg_name[DSS_MAX_NAME_LEN];
} dss_notify_req_msg_t;

typedef struct st_dss_notify_ack_msg {
    dss_message_head_t dss_head;
    dss_bcast_ack_cmd_t type;
    int32 result;
    bool32 cmd_ack;
} dss_notify_ack_msg_t;

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
} dss_get_ft_block_req_t;

typedef struct st_get_ft_block_ack {
    dss_message_head_t ack_head;
    dss_block_id_t node_id;
    dss_block_id_t parent_node_id;
    char vg_name[DSS_MAX_NAME_LEN];
    char block[DSS_BLOCK_SIZE];
    char parent_block[DSS_BLOCK_SIZE];
} dss_get_ft_block_ack_t;

#define DSS_MES_MSG_HEAD_SIZE (sizeof(dss_message_head_t))
uint32 dss_get_broadcast_proto_ver(uint64 succ_inst);
status_t dss_notify_sync(char *buffer, uint32 size, dss_recv_msg_t *recv_msg);
status_t dss_exec_sync(dss_session_t *session, uint32 remoteid, uint32 currtid, status_t *remote_result);
status_t dss_notify_expect_bool_ack(
    dss_vg_info_item_t *vg_item, dss_bcast_req_cmd_t cmd, uint64 ftid, bool32 *cmd_ack);
status_t dss_invalidate_other_nodes(dss_vg_info_item_t *vg_item, uint64 ftid, bool32 *cmd_ack);
status_t dss_broadcast_check_file_open(dss_vg_info_item_t *vg_item, uint64 ftid, bool32 *cmd_ack);

void dss_check_mes_conn(uint64 cur_inst_map);
status_t dss_startup_mes(void);
void dss_stop_mes(void);
int32 dss_process_broadcast_ack(dss_notify_ack_msg_t *ack, dss_recv_msg_t *recv_msg_output);
void dss_proc_broadcast_req(dss_session_t *session, mes_msg_t *msg);
status_t dss_read_volume_remote(const char *vg_name, dss_volume_t *volume, int64 offset, void *buf, int32 size);
status_t dss_send2standby(big_packets_ctrl_t *ack, const char *buf);
int32 dss_batch_load(dss_session_t *session, dss_loaddisk_req_t *req, uint32 version);
status_t dss_join_cluster(bool32 *join_succ);
status_t dss_refresh_ft_by_primary(dss_block_id_t blockid, uint32 vgid, char *vg_name);
status_t dss_get_node_by_path_remote(dss_session_t *session, const char *dir_path, gft_item_type_t type,
    dss_check_dir_output_t *output_info, bool32 is_throw_err);

#ifdef __cplusplus
}
#endif

#endif
