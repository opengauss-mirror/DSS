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
#include "dss_au.h"
#include "dss_diskgroup.h"
#include "dss_session.h"

#ifdef __cplusplus
extern "C" {
#endif

// this meta_addr should be formated as: block_ctrl(512) | meta(ft/fs/fs-aux)
#define DSS_GET_META_FROM_BLOCK_CTRL(meta_type, block_ctrl) ((meta_type *)((char *)(block_ctrl) + DSS_BLOCK_CTRL_SIZE))
#define DSS_GET_BLOCK_CTRL_FROM_META(meta_addr) ((dss_block_ctrl_t *)((char *)(meta_addr)-DSS_BLOCK_CTRL_SIZE))

#if defined(_DEBUG) || defined(DEBUG) || defined(DB_DEBUG_VERSION)
#define DSS_RECYCLE_META_RECYCLE_RATE_HWM 8000  // unit is 0.01%
#define DSS_RECYCLE_META_RECYCLE_RATE_LWM 6000  // unit is 0.01%
#else
#define DSS_RECYCLE_META_RECYCLE_RATE_HWM 80  // unit is 1%
#define DSS_RECYCLE_META_RECYCLE_RATE_LWM 60  // unit is 1%
#endif

#define DSS_RECYCLE_META_HOT_INC_STEP 3
#define DSS_RECYCLE_META_TIME_CLEAN_BATCH_NUM 8
#define DSS_RECYCLE_META_TRIGGER_CLEAN_BATCH_NUM 1
#define DSS_RECYCLE_META_TRIGGER_WAIT_TIME 200  // ms

typedef struct st_dss_recycle_meta_args {
    dss_recycle_meta_pos_t *recyle_meta_pos;
    uint32 time_clean_wait_time;     // ms
    uint32 trigger_clean_wait_time;  // ms
    cm_thread_cond_t trigger_cond;   // for tigger recycle meta by other task
    bool32 trigger_enable;
    uint32 last_bucket_id[DSS_MAX_VOLUME_GROUP_NUM];  // for re-start from last recycle stop point
} dss_recycle_meta_args_t;

typedef struct st_dss_recycle_meta {
    dss_recycle_meta_args_t recycle_meta_args;
    dss_bg_task_info_t recycle_meta_task[DSS_RECYLE_META_TASK_NUM_MAX];
} dss_recycle_meta_t;

#define DSS_LOCK_SHM_META_TIMEOUT 200
#define DSS_BUFFER_CACHE_HASH(block_id) cm_hash_int64((int64)DSS_BLOCK_ID_IGNORE_UNINITED((block_id)))
void dss_enter_shm_x(dss_session_t *session, dss_vg_info_item_t *vg_item);
bool32 dss_enter_shm_time_x(dss_session_t *session, dss_vg_info_item_t *vg_item, uint32 wait_ticks);
void dss_enter_shm_s(dss_session_t *session, dss_vg_info_item_t *vg_item, bool32 is_force, int32 timeout);
void dss_leave_shm(dss_session_t *session, dss_vg_info_item_t *vg_item);
bool32 dss_enter_shm_timed_s(dss_session_t *session, dss_vg_info_item_t *vg_item, bool32 is_force, int32 timeout);
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

// do not need control concurrence
void dss_inc_meta_ref_hot(dss_block_ctrl_t *block_ctrl);
// do not need control concurrence
void dss_desc_meta_ref_hot(dss_block_ctrl_t *block_ctrl);

void dss_buffer_recycle_disable(dss_block_ctrl_t *block_ctrl, bool8 recycle_disable);
void dss_set_recycle_meta_args_to_vg(dss_bg_task_info_t *bg_task_info);
void dss_recycle_meta(dss_session_t *session, dss_bg_task_info_t *bg_task_info, date_t *clean_time);
void dss_trigger_recycle_meta(dss_vg_info_item_t *vg_item);

#ifdef __cplusplus
}
#endif
#endif
