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

#include "mes.h"
#include "dss_file_def.h"
#include "dss_session.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum en_dss_mes_command {
    DSS_CMD_REQ_BROADCAST = 0,
    DSS_CMD_ACK_BROADCAST_WITH_MSG,
    DSS_CMD_ACK_BROADCAST,
    DSS_CMD_REQ_SYB2ACTIVE, /* Request command from the standby node to the active node */
    DSS_CMD_ACK_SYB2ACTIVE,
    DSS_CMD_REQ_LOCKS, /* Request command from the standby node to the active node */
    DSS_CMD_ACK_LOCKS,
    DSS_CMD_CEIL,
} dss_mes_command_t;

#define DSS_MES_THREAD_NUM 2
#define DSS_MES_WAIT_TIMEOUT 5000  // 5s
#define DSS_MES_TRY_TIMES 100
#define DSS_BROADCAST_WAIT_INFINITE (0xFFFFFFFF)
#define DSS_IS_INST_SEND(bits, id) (((bits) >> (id)) & 0x1)
#define DSS_BUFFER_POOL_NUM (3)
#define DSS_MSG_BUFFER_QUEUE_NUM (8)
#define DSS_FIRST_BUFFER_LENGTH (64)
#define DSS_SECOND_BUFFER_LENGTH (128)
#define DSS_THIRD_BUFFER_LENGTH (SIZE_K(32) + 64)
#define DSS_CKPT_NOTIFY_TASK_RATIO (1.0f / 4)
#define DSS_CLEAN_EDP_TASK_RATIO (1.0f / 4)
#define DSS_TXN_INFO_TASK_RATIO (1.0f / 16)
#define DSS_FIRST_BUFFER_RATIO (1.0f / 4)
#define DSS_SECOND_BUFFER_RATIO (1.0f / 4)
#define DSS_THIRDLY_BUFFER_RATIO (1.0f / 2)

typedef void (*dss_message_proc_t)(dss_session_t *session, mes_message_t *msg);
typedef struct st_processor_func {
    dss_mes_command_t cmd_type;
    dss_message_proc_t proc;
    bool32 is_enqueue_work_thread;  // Whether to let the worker thread process
    const char *func_name;
} processor_func_t;

typedef struct st_dss_processor {
    dss_message_proc_t proc;
    bool32 is_enqueue;
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

typedef enum st_dss_bcast_req_cmd {
    BCAST_REQ_RENAME = 0,
    BCAST_REQ_DEL_DIR_FILE,
    BCAST_REQ_TRUNCATE_FILE,
    BCAST_REQ_ASK_STATUS,
    BCAST_REQ_END
} dss_bcast_req_cmd_t;

typedef enum st_dss_bcast_ack_cmd {
    BCAST_ACK_RENAME = 0,
    BCAST_ACK_DEL_FILE,
    BCAST_ACK_TRUNCATE_FILE,
    BCAST_ACK_ASK_STATUS,
    BCAST_ACK_END
} dss_bcast_ack_cmd_t;

typedef struct st_dss_bcast_req {
    dss_bcast_req_cmd_t type;
    char buffer[4];
} dss_bcast_req_t;

typedef struct st_dss_recv_msg {
    bool32 handle_recv_msg;
    bool32 open_flag;
} dss_recv_msg_t;

typedef struct st_dss_mes_ack_with_data {
    mes_message_head_t head;
    dss_bcast_ack_cmd_t type;
    char data[4];
} dss_mes_ack_with_data_t;

typedef struct st_dss_check_file_open_param {
    uint64 ftid;
    char vg_name[DSS_MAX_NAME_LEN];
} dss_check_file_open_param;

typedef enum st_dss_distribute_locks_flag {
    DSS_DISTRIBUTE_LOCK_X = 0,
    DSS_DISTRIBUTE_LOCK_S,
    DSS_DISTRIBUTE_UN_LOCK
} dss_distribute_locks_flag;

typedef struct st_dss_distribute_locks_param {
    dss_distribute_locks_flag locks_flag;
    char vg_name[DSS_MAX_NAME_LEN];
} dss_distribute_locks_param;

status_t dss_notify_sync(
    dss_session_t *session, dss_bcast_req_cmd_t cmd, const char *buffer, uint32 size, dss_recv_msg_t *recv_msg);
status_t dss_polling_master_id(dss_session_t *session);
status_t dss_exec_sync(dss_session_t *session, uint32 remoteid, uint32 currtid);
void dss_check_mes_conn(uint64 cur_inst_map);
status_t dss_startup_mes(void);
void dss_stop_mes(void);

#ifdef __cplusplus
}
#endif

#endif
