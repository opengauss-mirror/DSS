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
 * dss_alloc_unit.h
 *
 *
 * IDENTIFICATION
 *    src/common/dss_alloc_unit.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __DSS_ALLOC_UNIT_H__
#define __DSS_ALLOC_UNIT_H__

#include "cm_defs.h"
#include "dss_defs.h"
#include "dss_diskgroup.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DSS_GET_AU_ROOT(dss_ctrl_p) ((dss_au_root_t *)((dss_ctrl_p)->core.au_root))
#define DSS_MIN_FILE_NUM_IN_RECYCLE 32

typedef enum en_dss_au_type {
    DSS_AU_TYPE_FILE,
    DSS_AU_TYPE_META_FT,
    DSS_AU_TYPE_META_BITMAP,
    DSS_AU_TYPE_META_FREE,
} dss_au_type_t;

typedef struct st_dss_au_t {
    uint32_t checksum;
    uint32_t type : 4;  // au type:file,meta
    uint32_t size : 28;
    auid_t id;
    auid_t next;        // next free au
    char reserve[488];  // 512 align
} dss_au_head_t;

typedef struct st_dss_au_list_t {
    uint32 count;
    auid_t first;
    auid_t last;
} dss_au_list_t;

typedef struct st_dss_au_root_t {
    uint64 version;
    uint64 free_root;  // .recycle ftid;
    uint64 count;
    uint32 free_vol_id;  // the first volume that has free space.
    uint32 reserve;
    dss_au_list_t free_list;
} dss_au_root_t;

bool32 dss_can_alloc_from_recycle(const gft_node_t *root_node, bool32 is_before);
void dss_init_au_root(dss_ctrl_t *dss_ctrl);
status_t dss_alloc_au(dss_session_t *session, dss_vg_info_item_t *vg_item, auid_t *auid, bool8 latch_ft_root);

status_t dss_get_core_version(dss_vg_info_item_t *item, uint64 *version);
status_t dss_load_core_ctrl(dss_vg_info_item_t *item, dss_core_ctrl_t *core);
void dss_update_core_ctrl(
    dss_session_t *session, dss_vg_info_item_t *item, dss_core_ctrl_t *core, uint32 volume_id, bool32 is_only_root);
status_t dss_get_au_head(dss_vg_info_item_t *item, auid_t auid, dss_au_head_t *au_head);
status_t dss_get_au(dss_vg_info_item_t *item, auid_t auid, char *buf, int32 size);
bool32 dss_cmp_auid(auid_t auid, uint64 id);
void dss_set_auid(auid_t *auid, uint64 id);
int64 dss_get_au_offset(dss_vg_info_item_t *item, auid_t auid);
uint64 dss_get_au_id(dss_vg_info_item_t *item, uint64 offset);
void dss_set_blockid(dss_block_id_t *blockid, uint64 id);
bool32 dss_cmp_blockid(dss_block_id_t blockid, uint64 id);
status_t dss_get_volume_version(dss_vg_info_item_t *item, uint64 *version);

#ifdef __cplusplus
}
#endif

#endif
