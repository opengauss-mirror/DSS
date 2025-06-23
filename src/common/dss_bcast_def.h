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

#ifdef __cplusplus
}
#endif
#endif
