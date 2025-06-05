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
 * dss_bcast_def.h
 *
 *
 * IDENTIFICATION
 *    src/common/dss_bcast_def.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __DSS_BCAST_DEF_H_
#define __DSS_BCAST_DEF_H_

#ifdef __cplusplus
extern "C" {
#endif

typedef enum st_dss_bcast_req_cmd {
    BCAST_REQ_DEL_DIR_FILE = 0,
    BCAST_REQ_INVALIDATE_META,
    BCAST_REQ_META_SYN,
    BCAST_REQ_GET_VERSION,
    BCAST_REQ_END
} dss_bcast_req_cmd_t;

typedef enum st_dss_bcast_ack_cmd {
    BCAST_ACK_DEL_FILE = 0,
    BCAST_ACK_INVALIDATE_META,
    BCAST_ACK_GET_VERSION,
    BCAST_ACK_END
} dss_bcast_ack_cmd_t;

typedef struct st_dss_bcast_req {
    dss_bcast_req_cmd_t type;
    char buffer[4];
} dss_bcast_req_t;

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

typedef struct st_dss_bcast_req_head {
    dss_message_head_t dss_head;
    dss_bcast_req_cmd_t type;
} dss_bcast_req_head_t;

typedef struct st_dss_bcast_ack_head {
    dss_message_head_t dss_head;
    dss_bcast_ack_cmd_t type;
} dss_bcast_ack_head_t;

typedef struct st_dss_meta_syn_msg {
    uint64 ftid;
    uint64 fid;       // it's the owner's gft_node_t.fid
    uint64 file_ver;  // it's the owner's gft_node_t.file_ver
    uint64 syn_meta_version;
    uint64 meta_block_id;
    uint32 vg_id;
    uint32 meta_type;
    uint32 meta_len;
    char meta[DSS_FILE_SPACE_BLOCK_SIZE];
} dss_meta_syn_t;

typedef struct st_dss_invalidate_meta_msg {
    uint32 vg_id;
    uint32 meta_type;
    uint64 meta_block_id;
} dss_invalidate_meta_msg_t;

typedef struct st_dss_req_meta_data {
    dss_bcast_req_head_t bcast_head;
    uint32 data_size;
    dss_meta_syn_t data;
} dss_req_meta_data_t;

#ifdef __cplusplus
}
#endif
#endif
