/*
 * Copyright (c) 2024 Huawei Technologies Co.,Ltd.
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
 * dss_syn_meta.h
 *
 *
 * IDENTIFICATION
 *    src/common/dss_syn_meta.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __DSS_SYN_META_H__
#define __DSS_SYN_META_H__

#include "dss_defs.h"
#include "dss_file_def.h"
#include "dss_session.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct st_dss_meta_syn_msg {
    uint64 ftid;
    uint64 fid;       // it's the owner's gft_node_t.fid
    uint64 file_ver;  // it's the owner's gft_node_t.file_ver
    uint64 syn_meta_version;
    uint64 meta_block_id;
    uint32 vg_id;
    uint32 meta_type;
    uint32 meta_len;
    char meta[DSS_MAX_META_BLOCK_SIZE];
} dss_meta_syn_t;

typedef struct st_dss_invalidate_meta_msg {
    uint32 vg_id;
    uint32 meta_type;
    uint64 meta_block_id;
} dss_invalidate_meta_msg_t;

bool32 dss_is_syn_meta_enable();
void dss_set_syn_meta_enable(bool32 is_enable_syn_meta);

void dss_add_syn_meta(dss_vg_info_item_t *vg_item, dss_block_ctrl_t *block_ctrl, uint64 version);
void dss_del_syn_meta(dss_vg_info_item_t *vg_item, dss_block_ctrl_t *block_ctrl, int64 syn_meta_ref_cnt);
bool32 dss_syn_buffer_cache(dss_session_t *session, dss_vg_info_item_t *vg_item);
status_t dss_meta_syn_remote(dss_session_t *session, dss_meta_syn_t *meta_syn, uint32 size, bool32 *ack);
status_t dss_invalidate_meta_remote(
    dss_session_t *session, dss_invalidate_meta_msg_t *invalidate_meta_msg, uint32 size, bool32 *invalid_ack);

typedef status_t (*dss_meta_syn2other_nodes_proc_t)(
    dss_vg_info_item_t *vg_item, char *meta_syn, uint32 meta_syn_size, bool32 *cmd_ack);
void regist_meta_syn2other_nodes_proc(dss_meta_syn2other_nodes_proc_t proc);

#ifdef __cplusplus
}
#endif

#endif