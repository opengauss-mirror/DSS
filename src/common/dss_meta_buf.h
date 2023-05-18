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
 * dss_meta_buf.h
 *
 *
 * IDENTIFICATION
 *    src/common/dss_meta_buf.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __DSS_META_BUF_H__
#define __DSS_META_BUF_H__

#include "dss_ga.h"
#include "dss_diskgroup.h"

#ifdef __cplusplus
extern "C" {
#endif

status_t dss_register_buffer_cache(
    dss_vg_info_item_t *vg_item, const dss_block_id_t *block_id, ga_obj_id_t obj_id, dss_block_ctrl_t *block_ctrl);
void dss_unregister_buffer_cache(dss_vg_info_item_t *vg_item, dss_block_id_t block_id);
status_t dss_find_block_objid_in_shm(
    dss_vg_info_item_t *vg_item, dss_block_id_t block_id, dss_block_type_t type, ga_obj_id_t *objid);
char *dss_find_block_in_shm(dss_vg_info_item_t *vg_item, dss_block_id_t block_id, dss_block_type_t type,
    bool32 check_version, ga_obj_id_t *out_obj_id, bool32 active_refresh);
char *dss_find_block_in_shm_no_refresh(dss_session_t *session, dss_vg_info_item_t *vg_item, dss_block_id_t block_id,
    dss_block_type_t type, ga_obj_id_t *out_obj_id);
status_t dss_refresh_buffer_cache(dss_vg_info_item_t *vg_item, shm_hashmap_t *map);
status_t dss_get_block_from_disk(
    dss_vg_info_item_t *vg_item, dss_block_id_t block_id, char *buf, int64_t offset, int32 size, bool32 calc_checksum);
status_t dss_check_block_version(
    dss_vg_info_item_t *vg_item, dss_block_id_t blockid, dss_block_type_t type, char *addr, bool32 *is_changed);

static inline int64 dss_get_block_offset(dss_vg_info_item_t *vg_item, uint64 block_size, uint64 blockid, uint64 auid)
{
    return (int64)(block_size * blockid + dss_get_vg_au_size(vg_item->dss_ctrl) * auid);
}
#ifdef __cplusplus
}
#endif
#endif
