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
#include "dss_session.h"

#ifdef __cplusplus
extern "C" {
#endif

// this meta_addr should be formated as: block_ctrl(512) | meta(ft/fs/fs-aux)
#define DSS_GET_META_FROM_BLOCK_CTRL(meta_type, block_ctrl) ((meta_type *)((char *)(block_ctrl) + DSS_BLOCK_CTRL_SIZE))
#define DSS_GET_BLOCK_CTRL_FROM_META(meta_addr) ((dss_block_ctrl_t *)((char *)(meta_addr)-DSS_BLOCK_CTRL_SIZE))

#define DSS_LOCK_SHM_META_TIMEOUT 200
#define DSS_BUFFER_CACHE_HASH(block_id) cm_hash_int64((int64)DSS_BLOCK_ID_IGNORE_UNINITED((block_id)))
void dss_enter_shm_x(dss_session_t *session, dss_vg_info_item_t *vg_item);
bool32 dss_enter_shm_time_x(dss_session_t *session, dss_vg_info_item_t *vg_item, uint32 wait_ticks);
void dss_enter_shm_s(dss_session_t *session, dss_vg_info_item_t *vg_item, bool32 is_force, int32 timeout);
void dss_leave_shm(dss_session_t *session, dss_vg_info_item_t *vg_item);

dss_block_ctrl_t *dss_buffer_get_block_ctrl_addr(ga_pool_id_e pool_id, uint32 object_id);
char *dss_buffer_get_meta_addr(ga_pool_id_e pool_id, uint32 object_id);

uint32 dss_buffer_cache_get_block_size(uint32_t block_type);
bool32 dss_buffer_cache_key_compare(void *key, void *key2);

status_t dss_register_buffer_cache(dss_session_t *session, dss_vg_info_item_t *vg_item, const dss_block_id_t block_id,
    ga_obj_id_t obj_id, char *meta_addr, dss_block_type_t type);
void dss_unregister_buffer_cache(dss_session_t *session, dss_vg_info_item_t *vg_item, dss_block_id_t block_id);
status_t dss_find_block_objid_in_shm(dss_session_t *session, dss_vg_info_item_t *vg_item, dss_block_id_t block_id,
    dss_block_type_t type, ga_obj_id_t *objid);
char *dss_find_block_in_shm(dss_session_t *session, dss_vg_info_item_t *vg_item, dss_block_id_t block_id,
    dss_block_type_t type, bool32 check_version, ga_obj_id_t *out_obj_id, bool32 active_refresh);
char *dss_find_block_from_disk_and_refresh_shm(dss_session_t *session, dss_vg_info_item_t *vg_item,
    dss_block_id_t block_id, dss_block_type_t type, ga_obj_id_t *out_obj_id);
char *dss_find_block_in_shm_no_refresh(
    dss_session_t *session, dss_vg_info_item_t *vg_item, dss_block_id_t block_id, ga_obj_id_t *out_obj_id);
// do not care content change, just care about exist
char *dss_find_block_in_shm_no_refresh_ex(
    dss_session_t *session, dss_vg_info_item_t *vg_item, dss_block_id_t block_id, ga_obj_id_t *out_obj_id);

status_t dss_refresh_buffer_cache(dss_session_t *session, dss_vg_info_item_t *vg_item, shm_hashmap_t *map);
status_t dss_get_block_from_disk(
    dss_vg_info_item_t *vg_item, dss_block_id_t block_id, char *buf, int64_t offset, int32 size, bool32 calc_checksum);
status_t dss_check_block_version(dss_vg_info_item_t *vg_item, dss_block_id_t block_id, dss_block_type_t type,
    char *meta_addr, bool32 *is_changed, bool32 force_refresh);
status_t dss_refresh_block_in_shm(dss_session_t *session, dss_vg_info_item_t *vg_item, dss_block_id_t block_id,
    dss_block_type_t type, char *buf, char **shm_buf);
static inline int64 dss_get_block_offset(dss_vg_info_item_t *vg_item, uint64 block_size, uint64 blockid, uint64 auid)
{
    return (int64)(block_size * blockid + dss_get_vg_au_size(vg_item->dss_ctrl) * auid);
}

void dss_init_dss_fs_block_cache_info(dss_fs_block_cache_info_t *fs_block_cache_info);
void dss_init_vg_cache_node_info(dss_vg_info_item_t *vg_item);
status_t dss_hashmap_extend_and_redistribute(dss_session_t *session, shm_hash_ctrl_t *hash_ctrl);
status_t dss_hashmap_extend_and_redistribute_batch(
    dss_session_t *session, shm_hash_ctrl_t *hash_ctrl, uint32 extend_num);
void dss_hashmap_dynamic_extend_and_redistribute_per_vg(dss_vg_info_item_t *vg_item, dss_session_t *session);

#ifdef __cplusplus
}
#endif
#endif
