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
 * dss_fs_aux.h
 *
 *
 * IDENTIFICATION
 *    src/common/persist/dss_fs_aux.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __DSS_FS_AUX_H__
#define __DSS_FS_AUX_H__

#include "dss_file_def.h"
#include "dss_file.h"
#include "dss_redo.h"
#include "dss_latch.h"

#ifdef __cplusplus
extern "C" {
#endif

#pragma pack(8)
typedef struct st_dss_fs_aux_root_t {
    uint64 version;
    dss_fs_block_list_t free;
} dss_fs_aux_root_t;

typedef struct st_dss_fs_aux_header_t {
    dss_common_block_t common;
    dss_block_id_t next;
    dss_block_id_t ftid;
    dss_block_id_t data_id;  // when data_id.item & 0x1 is 1, means the au is parted write
                             // when data_id.item & 0x1 is 0, means the au is fully write
    uint32 bitmap_num;
    uint16_t index;
    uint16_t resv;
} dss_fs_aux_header_t;

typedef struct st_dss_fs_aux_t {
    dss_fs_aux_header_t head;
    uchar bitmap[0];
} dss_fs_aux_t;

typedef struct st_dss_fs_aux_pos_desc_t {
    uint32 byte_index;
    uint8 bit_index;
    uint8 rsv[3];
} dss_fs_aux_pos_desc_t;

typedef struct st_dss_fs_aux_range_desc_t {
    dss_fs_aux_pos_desc_t beg;
    dss_fs_aux_pos_desc_t end;
} dss_fs_aux_range_desc_t;

typedef struct st_dss_fs_pos_desc {
    bool32 is_valid;
    bool32 is_exist_aux;
    dss_fs_block_t *entry_fs_block;
    dss_fs_block_t *second_fs_block;
    dss_fs_aux_t *fs_aux;
    uint32 block_count;
    uint32 block_au_count;
    uint32 au_offset;
    dss_block_id_t data_auid;
} dss_fs_pos_desc_t;

// for redo ------------------------------
typedef struct st_dss_redo_format_fs_aux_t {
    auid_t auid;
    uint32 obj_id;
    uint32 count;
    dss_fs_block_list_t old_free_list;
} dss_redo_format_fs_aux_t;

typedef struct st_dss_redo_free_fs_aux_t {
    dss_block_id_t id;
    dss_block_id_t next;
    dss_fs_aux_root_t root;
} dss_redo_free_fs_aux_t;

typedef struct st_dss_redo_alloc_fs_aux_t {
    dss_block_id_t id;
    dss_block_id_t ftid;
    uint16 index;
    dss_fs_aux_root_t root;
} dss_redo_alloc_fs_aux_t;

typedef struct st_dss_redo_init_fs_aux_t {
    dss_block_id_t id;
    dss_block_id_t data_id;
    dss_block_id_t ftid;
    dss_block_id_t parent_id;
    uint16 reserve[2];
} dss_redo_init_fs_aux_t;

typedef struct st_dss_redo_updt_fs_block_t {
    dss_block_id_t id;
    dss_block_id_t data_id;
    uint16 index;
    uint16 reserve;
} dss_redo_updt_fs_block_t;

#pragma pack()
// end for redo<-----------------

void dss_check_fs_aux_affiliation(dss_fs_aux_header_t *block, ftid_t id, uint16_t index);

static inline dss_block_ctrl_t *dss_get_fs_aux_ctrl(dss_fs_aux_t *fs_aux)
{
    return (dss_block_ctrl_t *)((char *)fs_aux + DSS_FS_AUX_SIZE);
}

static inline bool32 dss_is_fs_aux_valid(gft_node_t *node, dss_fs_aux_t *fs_aux)
{
    dss_block_ctrl_t *block_ctrl = dss_get_fs_aux_ctrl(fs_aux);
    return ((node->fid == block_ctrl->fid) && (node->file_ver == block_ctrl->file_ver) &&
            (block_ctrl->ftid == DSS_ID_TO_U64(node->id)));
}

static inline bool32 dss_is_fs_aux_valid_all(gft_node_t *node, dss_fs_aux_t *fs_aux, uint16_t index)
{
    bool32 is_valid_shm = dss_is_fs_aux_valid(node, fs_aux);
    if (is_valid_shm) {
        dss_check_fs_aux_affiliation(&fs_aux->head, node->id, index);
    }
    return is_valid_shm;
}

static inline void dss_updt_fs_aux_file_ver(gft_node_t *node, dss_fs_aux_t *fs_aux)
{
    dss_block_ctrl_t *block_ctrl = dss_get_fs_aux_ctrl(fs_aux);
    block_ctrl->fid = node->fid;
    block_ctrl->file_ver = node->file_ver;
    block_ctrl->ftid = DSS_ID_TO_U64(node->id);
    block_ctrl->node = (char *)node;
}

static inline uint64 dss_get_fs_aux_fid(dss_fs_aux_t *fs_aux)
{
    dss_block_ctrl_t *block_ctrl = dss_get_fs_aux_ctrl(fs_aux);
    return block_ctrl->fid;
}

static inline uint64 dss_get_fs_aux_file_ver(dss_fs_aux_t *fs_aux)
{
    dss_block_ctrl_t *block_ctrl = dss_get_fs_aux_ctrl(fs_aux);
    return block_ctrl->file_ver;
}

static inline void dss_latch_fs_aux_init(dss_fs_aux_t *fs_aux)
{
    dss_block_ctrl_t *block_ctrl = dss_get_fs_aux_ctrl(fs_aux);
    cm_latch_init(&block_ctrl->latch);
}

static inline void dss_latch_s_fs_aux(dss_session_t *session, dss_fs_aux_t *fs_aux, latch_statis_t *stat)
{
    dss_block_ctrl_t *block_ctrl = dss_get_fs_aux_ctrl(fs_aux);
    dss_latch_s2(&block_ctrl->latch, DSS_SESSIONID_IN_LOCK(session->id), CM_FALSE, stat);
}

static inline void dss_latch_x_fs_aux(dss_session_t *session, dss_fs_aux_t *fs_aux, latch_statis_t *stat)
{
    dss_block_ctrl_t *block_ctrl = dss_get_fs_aux_ctrl(fs_aux);
    cm_latch_x(&block_ctrl->latch, DSS_SESSIONID_IN_LOCK(session->id), stat);
}

static inline void dss_unlatch_fs_aux(dss_fs_aux_t *fs_aux)
{
    dss_block_ctrl_t *block_ctrl = dss_get_fs_aux_ctrl(fs_aux);
    dss_unlatch(&block_ctrl->latch);
}

void dss_calc_fs_aux_pos(uint64 au_size, int64 offset, dss_fs_aux_pos_desc_t *pos, bool32 is_end);
void dss_calc_fs_aux_range(dss_vg_info_item_t *vg_item, int64 offset, int64 size, dss_fs_aux_range_desc_t *range);
void dss_calc_fs_aux_bitmap_value(uint8 bit_beg, uint8 bit_end, uint8 *value);

status_t dss_format_fs_aux(dss_session_t *session, dss_vg_info_item_t *vg_item, auid_t auid);
status_t dss_alloc_fs_aux(dss_session_t *session, dss_vg_info_item_t *vg_item, gft_node_t *node,
    dss_alloc_fs_block_info_t *info, dss_fs_aux_t **block);
void dss_free_fs_aux(dss_session_t *session, dss_vg_info_item_t *vg_item, dss_fs_aux_t *block, dss_fs_aux_root_t *root);

void dss_init_fs_aux(dss_session_t *session, dss_vg_info_item_t *vg_item, dss_fs_aux_t *block, dss_block_id_t data_id,
    dss_block_id_t ftid);
dss_fs_aux_t *dss_find_fs_aux(dss_session_t *session, dss_vg_info_item_t *vg_item, gft_node_t *node,
    dss_block_id_t block_id, bool32 check_version, ga_obj_id_t *out_obj_id, uint16 index);
status_t dss_updt_fs_aux(dss_session_t *session, dss_vg_info_item_t *vg_item, gft_node_t *node, int64 offset,
    int64 size, bool32 is_init_tail);

bool32 dss_check_fs_aux_inited(dss_vg_info_item_t *vg_item, dss_fs_aux_t *fs_aux, int64 offset, int64 size);

void dss_get_inited_size_with_fs_aux(
    dss_vg_info_item_t *vg_item, dss_fs_aux_t *fs_aux, int64 offset, int32 size, int32 *inited_size);

status_t dss_try_find_data_au_batch(dss_session_t *session, dss_vg_info_item_t *vg_item, gft_node_t *node,
    dss_fs_block_t *second_block, uint32 block_au_count_beg);
status_t dss_find_data_au_by_offset(
    dss_session_t *session, dss_vg_info_item_t *vg_item, gft_node_t *node, int64 offset, dss_fs_pos_desc_t *fs_pos);
status_t dss_read_volume_with_fs_aux(dss_vg_info_item_t *vg_item, gft_node_t *node, dss_fs_aux_t *fs_aux,
    dss_volume_t *volume, int64 vol_offset, int64 offset, void *buf, int32 size);

status_t dss_get_gft_node_with_cache(
    dss_session_t *session, dss_vg_info_item_t *vg_item, uint64 fid, dss_block_id_t ftid, gft_node_t **node_out);
status_t dss_get_entry_block_with_cache(
    dss_session_t *session, dss_vg_info_item_t *vg_item, gft_node_t *node, dss_fs_block_t **fs_block_out);
status_t dss_get_second_block_with_cache(dss_session_t *session, dss_vg_info_item_t *vg_item, gft_node_t *node,
    dss_block_id_t block_id, uint32 block_count, dss_fs_block_t **fs_block_out);
status_t dss_get_fs_aux_with_cache(dss_session_t *session, dss_vg_info_item_t *vg_item, gft_node_t *node,
    dss_block_id_t block_id, uint32 block_au_count, dss_fs_aux_t **fs_aux_out);
void dss_check_fs_aux_free(dss_fs_aux_header_t *block);
void dss_init_fs_aux_head(dss_fs_aux_t *fs_aux, dss_block_id_t ftid, uint16 index);
// for redo
status_t rp_redo_format_fs_aux(dss_vg_info_item_t *vg_item, dss_redo_entry_t *entry);
status_t rb_redo_format_fs_aux(dss_vg_info_item_t *vg_item, dss_redo_entry_t *entry);
status_t rp_redo_alloc_fs_aux(dss_vg_info_item_t *vg_item, dss_redo_entry_t *entry);
status_t rb_redo_alloc_fs_aux(dss_vg_info_item_t *vg_item, dss_redo_entry_t *entry);
status_t rp_redo_free_fs_aux(dss_vg_info_item_t *vg_item, dss_redo_entry_t *entry);
status_t rb_redo_free_fs_aux(dss_vg_info_item_t *vg_item, dss_redo_entry_t *entry);
status_t rp_redo_init_fs_aux(dss_vg_info_item_t *vg_item, dss_redo_entry_t *entry);
status_t rb_redo_init_fs_aux(dss_vg_info_item_t *vg_item, dss_redo_entry_t *entry);
status_t rb_reload_fs_aux_root(dss_vg_info_item_t *vg_item);
status_t dss_update_fs_aux_bitmap2disk(dss_vg_info_item_t *item, dss_fs_aux_t *block, uint32 size, bool32 had_checksum);
#ifdef __cplusplus
}
#endif

#endif