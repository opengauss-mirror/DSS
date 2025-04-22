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
 * dss_meta_buf.c
 *
 *
 * IDENTIFICATION
 *    src/common/dss_meta_buf.c
 *
 * -------------------------------------------------------------------------
 */

#include "dss_meta_buf.h"
#include "dss_alloc_unit.h"
#include "dss_file.h"
#include "cm_bilist.h"
#include "dss_fs_aux.h"
#include "dss_syn_meta.h"

#ifdef __cplusplus
extern "C" {
#endif

void dss_enter_shm_x(dss_session_t *session, dss_vg_info_item_t *vg_item)
{
    dss_lock_shm_meta_x(session, vg_item->vg_latch);
}

bool32 dss_enter_shm_time_x(dss_session_t *session, dss_vg_info_item_t *vg_item, uint32 wait_ticks)
{
    if (!dss_lock_shm_meta_timed_x(session, vg_item->vg_latch, DSS_LOCK_SHM_META_TIMEOUT)) {
        return CM_FALSE;
    }
    return CM_TRUE;
}

void dss_enter_shm_s(dss_session_t *session, dss_vg_info_item_t *vg_item, bool32 is_force, int32 timeout)
{
    CM_ASSERT(session != NULL);
    if (dss_is_server()) {
        (void)dss_lock_shm_meta_s_without_stack(session, vg_item->vg_latch, is_force, timeout);
        return;
    }

    dss_latch_offset_t latch_offset;
    latch_offset.type = DSS_LATCH_OFFSET_SHMOFFSET;
    latch_offset.offset.shm_offset = dss_get_vg_latch_shm_offset(vg_item);
    (void)dss_lock_shm_meta_s_with_stack(session, &latch_offset, vg_item->vg_latch, timeout);
}

bool32 dss_enter_shm_timed_s(dss_session_t *session, dss_vg_info_item_t *vg_item, bool32 is_force, int32 timeout)
{
    CM_ASSERT(session != NULL);
    if (dss_is_server()) {
        if (dss_lock_shm_meta_s_without_stack(session, vg_item->vg_latch, is_force, timeout) != CM_SUCCESS) {
            return CM_FALSE;
        }
        return CM_TRUE;
    }
    dss_latch_offset_t latch_offset;
    latch_offset.type = DSS_LATCH_OFFSET_SHMOFFSET;
    latch_offset.offset.shm_offset = dss_get_vg_latch_shm_offset(vg_item);
    if (dss_lock_shm_meta_s_with_stack(session, &latch_offset, vg_item->vg_latch, timeout) != CM_SUCCESS) {
        return CM_FALSE;
    }
    return CM_TRUE;
}

void dss_leave_shm(dss_session_t *session, dss_vg_info_item_t *vg_item)
{
    CM_ASSERT(session != NULL);
    if (dss_is_server()) {
        dss_unlock_shm_meta_without_stack(session, vg_item->vg_latch);
    } else {
        (void)dss_unlock_shm_meta_s_with_stack(session, vg_item->vg_latch, CM_FALSE);
    }
}

dss_block_ctrl_t *dss_buffer_get_block_ctrl_addr(ga_pool_id_e pool_id, uint32 object_id)
{
    return (dss_block_ctrl_t *)ga_object_addr(pool_id, object_id);
}

char *dss_buffer_get_meta_addr(ga_pool_id_e pool_id, uint32 object_id)
{
    dss_block_ctrl_t *block_ctrl = dss_buffer_get_block_ctrl_addr(pool_id, object_id);
    if (block_ctrl != NULL) {
        return DSS_GET_META_FROM_BLOCK_CTRL(char, block_ctrl);
    }
    return NULL;
}

static void dss_remove_recycle_meta(dss_session_t *session, dss_vg_info_item_t *vg_item, dss_block_ctrl_t *block_ctrl);

bool32 dss_buffer_cache_key_compare(void *key, void *key2)
{
    uint64 id = DSS_BLOCK_ID_IGNORE_UNINITED(*(uint64 *)key);
    uint64 id2 = DSS_BLOCK_ID_IGNORE_UNINITED(*(uint64 *)key2);
    return cm_oamap_uint64_compare(&id, &id2);
}

static inline ga_pool_id_e dss_buffer_cache_get_pool_id(uint32_t block_type)
{
    CM_ASSERT(block_type < DSS_BLOCK_TYPE_MAX);
    if (block_type == DSS_BLOCK_TYPE_FT) {
        return GA_8K_POOL;
    } else if (block_type == DSS_BLOCK_TYPE_FS) {
        return GA_16K_POOL;
    } else {
        return GA_FS_AUX_POOL;
    }
}

uint32 dss_buffer_cache_get_block_size(uint32_t block_type)
{
    CM_ASSERT(block_type < DSS_BLOCK_TYPE_MAX);
    if (block_type == DSS_BLOCK_TYPE_FT) {
        return DSS_BLOCK_SIZE;
    } else if (block_type == DSS_BLOCK_TYPE_FS) {
        return DSS_FILE_SPACE_BLOCK_SIZE;
    } else {
        return DSS_FS_AUX_SIZE;
    }
}

static void dss_register_buffer_cache_inner(dss_session_t *session, shm_hash_ctrl_t *hash_ctrl,
    shm_hashmap_bucket_t *bucket, ga_obj_id_t obj_id, char *meta_addr, uint32 hash)
{
    CM_ASSERT(bucket != NULL);
    CM_ASSERT(meta_addr != NULL);

    dss_block_ctrl_t *first_block_ctrl = NULL;
    dss_block_ctrl_t *block_ctrl = DSS_GET_BLOCK_CTRL_FROM_META(meta_addr);
    if (bucket->has_next) {
        ga_obj_id_t first_obj_id = *(ga_obj_id_t *)&bucket->first;
        first_block_ctrl = dss_buffer_get_block_ctrl_addr(first_obj_id.pool_id, first_obj_id.obj_id);
        DSS_ASSERT_LOG(first_block_ctrl != NULL, "obj meta_addr is NULL when register buffer cache");
    } else {
        block_ctrl->has_next = CM_FALSE;
    }
    block_ctrl->hash = hash;
    block_ctrl->my_obj_id = obj_id;
    SHM_HASH_BUCKET_INSERT(bucket, *(sh_mem_p *)&obj_id, block_ctrl, first_block_ctrl);
}

static void dss_unregister_buffer_cache_inner(
    shm_hash_ctrl_t *hash_ctrl, shm_hashmap_bucket_t *bucket, ga_obj_id_t next_id, char *meta_addr)
{
    dss_block_ctrl_t *prev_block_ctrl = NULL;
    dss_block_ctrl_t *next_block_ctrl = NULL;
    dss_block_ctrl_t *block_ctrl = DSS_GET_BLOCK_CTRL_FROM_META(meta_addr);
    if (block_ctrl->has_prev) {
        ga_obj_id_t obj_id = *(ga_obj_id_t *)&block_ctrl->hash_prev;
        prev_block_ctrl = dss_buffer_get_block_ctrl_addr(obj_id.pool_id, obj_id.obj_id);
    }
    if (block_ctrl->has_next) {
        ga_obj_id_t obj_id = *(ga_obj_id_t *)&block_ctrl->hash_next;
        next_block_ctrl = dss_buffer_get_block_ctrl_addr(obj_id.pool_id, obj_id.obj_id);
    }
    SHM_HASH_BUCKET_REMOVE(bucket, *(sh_mem_p *)&next_id, block_ctrl, prev_block_ctrl, next_block_ctrl);
}

status_t shm_hashmap_move_bucket_node(
    dss_session_t *session, shm_hash_ctrl_t *hash_ctrl, uint32 old_bucket_idx, uint32 new_bucket_idx)
{
    LOG_DEBUG_INF("[HASHMAP]Begin to move some entry from bucket %u to bucket %u.", old_bucket_idx, new_bucket_idx);
    shm_hashmap_bucket_t *old_bucket = shm_hashmap_get_bucket(hash_ctrl, old_bucket_idx, NULL);
    shm_hashmap_bucket_t *new_bucket = shm_hashmap_get_bucket(hash_ctrl, new_bucket_idx, NULL);
    DSS_ASSERT_LOG(old_bucket != NULL, "[HASHMAP]Expect bucket %u is not null.", old_bucket_idx);
    DSS_ASSERT_LOG(new_bucket != NULL, "[HASHMAP]Expect bucket %u is not null.", new_bucket_idx);
    ga_obj_id_t tmp_id = *(ga_obj_id_t *)&old_bucket->first;
    ga_obj_id_t next_id = *(ga_obj_id_t *)&old_bucket->first;
    bool32 has_next = old_bucket->has_next;
    char *meta_addr = NULL;
    dss_block_ctrl_t *block_ctrl = NULL;
    dss_common_block_t *block = NULL;
    auid_t block_id_tmp = {0};
    uint32 hash;
    uint32 bucket_idx;
    while (has_next) {
        meta_addr = dss_buffer_get_meta_addr(next_id.pool_id, next_id.obj_id);
        DSS_ASSERT_LOG(meta_addr != NULL, "[HASHMAP]Expect meta_addr is not null, pool id is %u, object id is %u.",
            next_id.pool_id, next_id.obj_id);
        block = DSS_GET_COMMON_BLOCK_HEAD(meta_addr);
        block_ctrl = DSS_GET_BLOCK_CTRL_FROM_META(meta_addr);
        block_id_tmp = ((dss_common_block_t *)meta_addr)->id;
        hash = DSS_BUFFER_CACHE_HASH(block_id_tmp);
        has_next = block_ctrl->has_next;
        tmp_id = next_id;
        next_id = *(ga_obj_id_t *)&block_ctrl->hash_next;
        bucket_idx = shm_hashmap_calc_bucket_idx(hash_ctrl, hash);
        if (bucket_idx != old_bucket_idx) {
            dss_lock_shm_meta_bucket_x(session, &old_bucket->enque_lock);
            dss_lock_shm_meta_bucket_x(session, &new_bucket->enque_lock);
            dss_unregister_buffer_cache_inner(hash_ctrl, old_bucket, tmp_id, meta_addr);
            LOG_DEBUG_INF("[HASHMAP]Move block id %s from bucket %u, hash:%u, type:%u, num:%u.",
                dss_display_metaid(block_id_tmp), old_bucket_idx, hash, block->type, old_bucket->entry_num);
            DSS_ASSERT_LOG(bucket_idx == new_bucket_idx, "Expect bucket idx is %u, but bucket idx is %u.",
                new_bucket_idx, bucket_idx);
            dss_register_buffer_cache_inner(session, hash_ctrl, new_bucket, tmp_id, meta_addr, hash);
            LOG_DEBUG_INF(
                "[HASHMAP]Succeed to register buffer cache, bucket %u, num %u.", new_bucket_idx, new_bucket->entry_num);
            dss_unlock_shm_meta_bucket(session, &old_bucket->enque_lock);
            dss_unlock_shm_meta_bucket(session, &new_bucket->enque_lock);
            LOG_DEBUG_INF("[HASHMAP]Move block id %s from bucket %u to bucket %u, object id:{%u,%u}, hash:%u, type:%u.",
                dss_display_metaid(block_id_tmp), old_bucket_idx, new_bucket_idx, tmp_id.pool_id, tmp_id.obj_id, hash,
                block->type);
            ga_obj_id_t new_id = *(ga_obj_id_t *)&new_bucket->first;
            DSS_ASSERT_LOG(new_id.pool_id == tmp_id.pool_id && new_id.obj_id == tmp_id.obj_id,
                "[HASHMAP]new id is {%u,%u}, tmp id is {%u,%u}.", new_id.pool_id, new_id.obj_id, tmp_id.pool_id,
                tmp_id.obj_id);
        }
    }
    return CM_SUCCESS;
}

status_t dss_hashmap_extend_and_redistribute_batch(
    dss_session_t *session, shm_hash_ctrl_t *hash_ctrl, uint32 extend_num)
{
    uint32 i = 0;
    while (i < extend_num) {
        if (hash_ctrl->bucket_num == hash_ctrl->bucket_limits && hash_ctrl->max_bucket == hash_ctrl->high_mask) {
            LOG_DEBUG_WAR("[HASHMAP]No need to extend hashmap for it has reached the upper limit.");
            return CM_SUCCESS;
        }
        status_t status = dss_hashmap_extend_and_redistribute(session, hash_ctrl);
        if (status != CM_SUCCESS) {
            LOG_DEBUG_ERR("[HASHMAP]Failed to extend hashmap, extend_num is %u, i is %u.", extend_num, i);
            return status;
        }
        i++;
    }
    return CM_SUCCESS;
}

void dss_hashmap_dynamic_extend_and_redistribute_per_vg(dss_vg_info_item_t *vg_item, dss_session_t *session)
{
    shm_hash_ctrl_t *hash_ctrl = &vg_item->buffer_cache->hash_ctrl;
    if (shm_hashmap_need_extend_and_redistribute(hash_ctrl)) {
        dss_enter_shm_x(session, vg_item);
        LOG_DEBUG_INF("[HASHMAP]Begin to extend hashmap of vg %s.", vg_item->vg_name);
        status_t status = dss_hashmap_extend_and_redistribute_batch(session, hash_ctrl, DSS_EXTEND_BATCH);
        if (status != CM_SUCCESS) {
            LOG_DEBUG_ERR(
                "[HASHMAP]Failed to extend hashmap of vg %s, nsegments is %u, max_bucket is %u, bucket_num is %u.",
                vg_item->vg_name, hash_ctrl->nsegments, hash_ctrl->max_bucket, hash_ctrl->bucket_num);
            dss_leave_shm(session, vg_item);
            return;
        }
        LOG_DEBUG_INF(
            "[HASHMAP]Succeed to extend hashmap of vg %s, nsegments is %u, max_bucket is %u, bucket_num is %u.",
            vg_item->vg_name, hash_ctrl->nsegments, hash_ctrl->max_bucket, hash_ctrl->bucket_num);
        dss_leave_shm(session, vg_item);
    }
}

status_t dss_hashmap_redistribute(dss_session_t *session, shm_hash_ctrl_t *hash_ctrl, uint32 old_bucket)
{
    hash_ctrl->max_bucket++;
    uint32 new_bucket = shm_hashmap_calc_bucket_idx(hash_ctrl, hash_ctrl->max_bucket);
    return shm_hashmap_move_bucket_node(session, hash_ctrl, old_bucket, new_bucket);
}

void dss_hashmap_extend_bucket_num(shm_hash_ctrl_t *hash_ctrl)
{
    if (hash_ctrl->max_bucket >= hash_ctrl->high_mask) {
        LOG_RUN_INF("[HASHMAP]Before update hash ctrl, max_bucket %u, bucket_num:%u, low mask:%u, high mask:%u.",
            hash_ctrl->max_bucket, hash_ctrl->bucket_num, hash_ctrl->low_mask, hash_ctrl->high_mask);
        hash_ctrl->bucket_num <<= 1;
        hash_ctrl->low_mask = hash_ctrl->high_mask;
        hash_ctrl->high_mask = (hash_ctrl->max_bucket + 1) | hash_ctrl->low_mask;
        LOG_RUN_INF("[HASHMAP]Update hash ctrl, max_bucket %u, bucket_num:%u, low mask:%u, high mask:%u.",
            hash_ctrl->max_bucket, hash_ctrl->bucket_num, hash_ctrl->low_mask, hash_ctrl->high_mask);
    }
}

status_t dss_hashmap_extend_segment(shm_hash_ctrl_t *hash_ctrl)
{
    uint32 segment = (hash_ctrl->max_bucket + 1) / DSS_BUCKETS_PER_SEGMENT;
    if (segment >= hash_ctrl->nsegments) {
        DSS_RETURN_IF_ERROR(shm_hashmap_extend_segment(hash_ctrl));
    }
    return CM_SUCCESS;
}

status_t dss_hashmap_extend_and_redistribute(dss_session_t *session, shm_hash_ctrl_t *hash_ctrl)
{
    uint32 old_bucket = shm_hashmap_calc_bucket_idx(hash_ctrl, hash_ctrl->max_bucket + 1);
    DSS_RETURN_IF_ERROR(dss_hashmap_extend_segment(hash_ctrl));
    dss_hashmap_extend_bucket_num(hash_ctrl);
    return dss_hashmap_redistribute(session, hash_ctrl, old_bucket);
}

status_t dss_register_buffer_cache(dss_session_t *session, dss_vg_info_item_t *vg_item, const dss_block_id_t block_id,
    ga_obj_id_t obj_id, char *meta_addr, dss_block_type_t type)
{
    dss_block_ctrl_t *block_ctrl = DSS_GET_BLOCK_CTRL_FROM_META(meta_addr);
    shm_hash_ctrl_t *hash_ctrl = &vg_item->buffer_cache->hash_ctrl;
    uint32 hash = DSS_BUFFER_CACHE_HASH(block_id);
    uint32 bucket_idx = shm_hashmap_calc_bucket_idx(hash_ctrl, hash);
    shm_hashmap_bucket_t *bucket = shm_hashmap_get_bucket(hash_ctrl, bucket_idx, NULL);
    if (bucket == NULL) {
        return CM_ERROR;
    }
    errno_t errcode = memset_s(block_ctrl, sizeof(dss_block_ctrl_t), 0, sizeof(dss_block_ctrl_t));
    if (errcode) {
        LOG_DEBUG_ERR("Failed to memset block ctrl, block id %s.", dss_display_metaid(block_id));
        return CM_ERROR;
    }
    dss_lock_shm_meta_bucket_x(session, &bucket->enque_lock);
    DSS_LOG_DEBUG_OP("Register block id %s, hash:%u, type:%u, bucket_idx is %u.", dss_display_metaid(block_id), hash,
        type, bucket_idx);
    cm_latch_init(&block_ctrl->latch);
    block_ctrl->type = type;
    block_ctrl->block_id = block_id;
    dss_register_buffer_cache_inner(session, hash_ctrl, bucket, obj_id, meta_addr, hash);
    LOG_DEBUG_INF("Succeed to register buffer cache, bucket %u, num %u.", bucket_idx, bucket->entry_num);
    dss_unlock_shm_meta_bucket(session, &bucket->enque_lock);
    return CM_SUCCESS;
}

void dss_unregister_buffer_cache(dss_session_t *session, dss_vg_info_item_t *vg_item, dss_block_id_t block_id)
{
    char *meta_addr = NULL;
    dss_block_ctrl_t *block_ctrl = NULL;
    dss_common_block_t *block = NULL;
    auid_t block_id_tmp = {0};
    uint32 hash = DSS_BUFFER_CACHE_HASH(block_id);
    shm_hash_ctrl_t *hash_ctrl = &vg_item->buffer_cache->hash_ctrl;
    uint32 bucket_idx = shm_hashmap_calc_bucket_idx(hash_ctrl, hash);
    shm_hashmap_bucket_t *bucket = shm_hashmap_get_bucket(hash_ctrl, bucket_idx, NULL);
    cm_panic(bucket != NULL);
    dss_lock_shm_meta_bucket_x(session, &bucket->enque_lock);
    ga_obj_id_t next_id = *(ga_obj_id_t *)&bucket->first;
    bool32 has_next = bucket->has_next;
    while (has_next) {
        meta_addr = dss_buffer_get_meta_addr(next_id.pool_id, next_id.obj_id);
        cm_panic(meta_addr != NULL);
        block = DSS_GET_COMMON_BLOCK_HEAD(meta_addr);
        block_ctrl = DSS_GET_BLOCK_CTRL_FROM_META(meta_addr);
        block_id_tmp = ((dss_common_block_t *)meta_addr)->id;
        if ((block_ctrl->hash == hash) && (dss_buffer_cache_key_compare(&block_id_tmp, &block_id) == CM_TRUE)) {
            // may has been linked to recycle meta list
            dss_remove_recycle_meta(session, vg_item, block_ctrl);
            dss_unregister_buffer_cache_inner(hash_ctrl, bucket, next_id, meta_addr);
            LOG_DEBUG_INF("Move block id %s from bucket %u, hash:%u, type:%u, num:%u.",
                dss_display_metaid(block_id_tmp), bucket_idx, hash, block->type, bucket->entry_num);
            dss_unlock_shm_meta_bucket(session, &bucket->enque_lock);
            return;
        }
        has_next = block_ctrl->has_next;
        next_id = *(ga_obj_id_t *)&block_ctrl->hash_next;
    }
    dss_unlock_shm_meta_bucket(session, &bucket->enque_lock);
    LOG_DEBUG_ERR("Key to remove not found");
}

status_t dss_get_block_from_disk(
    dss_vg_info_item_t *vg_item, dss_block_id_t block_id, char *buf, int64_t offset, int32 size, bool32 calc_checksum)
{
    bool32 remote = calc_checksum;
    CM_ASSERT(block_id.volume < DSS_MAX_VOLUMES);
    status_t status = dss_check_read_volume(vg_item, (uint32)block_id.volume, offset, buf, size, &remote);
    if (status != CM_SUCCESS) {
        return status;
    }

    // check the checksum when read the file table block and file space block.
    if ((calc_checksum) && (remote == CM_FALSE)) {
        cm_panic((uint32)size == DSS_BLOCK_SIZE || (uint32)size == DSS_FILE_SPACE_BLOCK_SIZE ||
                 (uint32)size == DSS_FS_AUX_SIZE);
        uint32 checksum = dss_get_checksum(buf, (uint32)size);
        dss_common_block_t *block = (dss_common_block_t *)buf;
        dss_check_checksum(checksum, block->checksum);
    }

    return CM_SUCCESS;
}

status_t dss_check_block_version(dss_vg_info_item_t *vg_item, dss_block_id_t block_id, dss_block_type_t type,
    char *meta_addr, bool32 *is_changed, bool32 force_refresh)
{
#ifndef WIN32
    char buf[DSS_DISK_UNIT_SIZE] __attribute__((__aligned__(DSS_DISK_UNIT_SIZE)));
#else
    char buf[DSS_DISK_UNIT_SIZE];
#endif

    if (is_changed) {
        *is_changed = CM_FALSE;
    }

    uint64 version = ((dss_common_block_t *)meta_addr)->version;
    uint32 size = dss_buffer_cache_get_block_size(type);
    int64 offset = dss_get_block_offset(vg_item, (uint64)size, block_id.block, block_id.au);
    // just read block header
    status_t status = dss_get_block_from_disk(vg_item, block_id, buf, offset, DSS_DISK_UNIT_SIZE, CM_FALSE);
    if (status != CM_SUCCESS) {
        LOG_DEBUG_ERR("Failed to get block: %s from disk, meta_addr:%p, offset:%lld, size:%d.",
            dss_display_metaid(block_id), buf, offset, DSS_DISK_UNIT_SIZE);
        return status;
    }
    uint64 disk_version = ((dss_common_block_t *)buf)->version;
    if (dss_compare_version(disk_version, version) || force_refresh) {
        DSS_LOG_DEBUG_OP(
            "dss_check_block_version, version:%llu, disk_version:%llu, block_id: %s, type:%u, force_refresh:%u.",
            version, disk_version, dss_display_metaid(block_id), type, (uint32)force_refresh);
        // if size == DSS_DISK_UNIT_SIZE, the buf has been changed all, not need load again
        if (size == DSS_DISK_UNIT_SIZE) {
            securec_check_ret(memcpy_s(meta_addr, DSS_DISK_UNIT_SIZE, buf, DSS_DISK_UNIT_SIZE));
        } else {
            if (force_refresh && version == 0) {
                status = dss_get_block_from_disk(vg_item, block_id, meta_addr, offset, (int32)size, CM_FALSE);
            } else {
                status = dss_get_block_from_disk(vg_item, block_id, meta_addr, offset, (int32)size, CM_TRUE);
            }
            if (status != CM_SUCCESS) {
                LOG_DEBUG_ERR("Failed to get block: %s from disk, meta_addr:%p, offset:%lld, size:%u.",
                    dss_display_metaid(block_id), meta_addr, offset, size);
                return status;
            }
        }
        if (is_changed) {
            *is_changed = CM_TRUE;
        }
    }

    return CM_SUCCESS;
}

static status_t dss_load_buffer_cache(dss_session_t *session, dss_vg_info_item_t *vg_item, auid_t block_id,
    dss_block_type_t type, char **block_addr, ga_obj_id_t *out_obj_id)
{
    char *meta_addr = NULL;
    dss_block_ctrl_t *block_ctrl = NULL;
    dss_common_block_t *block = NULL;
    auid_t block_id_tmp = {0};
    shm_hash_ctrl_t *hash_ctrl = &vg_item->buffer_cache->hash_ctrl;
    uint32 hash = DSS_BUFFER_CACHE_HASH(block_id);
    uint32 bucket_idx = shm_hashmap_calc_bucket_idx(hash_ctrl, hash);
    shm_hashmap_bucket_t *bucket = shm_hashmap_get_bucket(hash_ctrl, bucket_idx, NULL);
    if (bucket == NULL) {
        LOG_RUN_ERR("Failed to find bucket %u.", bucket_idx);
        return CM_ERROR;
    }
    dss_lock_shm_meta_bucket_x(session, &bucket->enque_lock);
    ga_obj_id_t next_id = *(ga_obj_id_t *)&bucket->first;
    bool32 has_next = bucket->has_next;
    while (has_next) {
        meta_addr = dss_buffer_get_meta_addr(next_id.pool_id, next_id.obj_id);
        cm_panic(meta_addr != NULL);
        block = DSS_GET_COMMON_BLOCK_HEAD(meta_addr);
        block_ctrl = DSS_GET_BLOCK_CTRL_FROM_META(meta_addr);
        block_id_tmp = ((dss_common_block_t *)meta_addr)->id;
        if ((block_ctrl->hash == hash) && (dss_buffer_cache_key_compare(&block_id_tmp, &block_id) == CM_TRUE)) {
            dss_unlock_shm_meta_bucket(session, &bucket->enque_lock);
            status_t status = dss_check_block_version(vg_item, block_id, type, meta_addr, NULL, CM_FALSE);
            if (status != CM_SUCCESS) {
                return status;
            }
            *block_addr = meta_addr;
            if (out_obj_id) {
                *out_obj_id = next_id;
            }
            block_ctrl->type = type;
            dss_inc_meta_ref_hot(block_ctrl);
            return CM_SUCCESS;
        }
        has_next = block_ctrl->has_next;
        next_id = *(ga_obj_id_t *)&block_ctrl->hash_next;
    }

    ga_pool_id_e pool_id = dss_buffer_cache_get_pool_id(type);
    uint32 size = dss_buffer_cache_get_block_size(type);
    int64_t offset = dss_get_block_offset(vg_item, (uint64)size, block_id.block, block_id.au);
    uint32 obj_id = ga_alloc_object(pool_id, CM_INVALID_ID32);
    if (obj_id == CM_INVALID_ID32) {
        dss_unlock_shm_meta_bucket(session, &bucket->enque_lock);
        return CM_ERROR;
    }
    meta_addr = dss_buffer_get_meta_addr(pool_id, obj_id);

    status_t status = dss_get_block_from_disk(vg_item, block_id, meta_addr, offset, (int32)size, CM_TRUE);
    if (status != CM_SUCCESS) {
        dss_unlock_shm_meta_bucket(session, &bucket->enque_lock);
        ga_free_object(pool_id, obj_id);
        LOG_DEBUG_ERR("Failed to get block from disk, v:%u,au:%llu,block:%u,item:%u,type:%d.", block_id.volume,
            (uint64)block_id.au, block_id.block, block_id.item, type);
        return status;
    }
    block = DSS_GET_COMMON_BLOCK_HEAD(meta_addr);
    DSS_LOG_DEBUG_OP("DSS load buffer cache, v:%u,au:%llu,block:%u,item:%u,type:%d.", block->id.volume,
        (uint64)block->id.au, block->id.block, block->id.item, block->type);
    block_ctrl = DSS_GET_BLOCK_CTRL_FROM_META(meta_addr);
    errno_t errcode = memset_s(block_ctrl, sizeof(dss_block_ctrl_t), 0, sizeof(dss_block_ctrl_t));
    if (errcode != EOK) {
        dss_unlock_shm_meta_bucket(session, &bucket->enque_lock);
        ga_free_object(pool_id, obj_id);
        LOG_DEBUG_ERR("Failed to memset block ctrl, v:%u,au:%llu,block:%u,item:%u,type:%d.", block_id.volume,
            (uint64)block_id.au, block_id.block, block_id.item, type);
        return CM_ERROR;
    }
    cm_latch_init(&block_ctrl->latch);
    block_ctrl->type = type;
    block_ctrl->block_id = block_id;

    ga_obj_id_t ga_obj_id;
    ga_obj_id.pool_id = pool_id;
    ga_obj_id.obj_id = obj_id;
    dss_register_buffer_cache_inner(session, hash_ctrl, bucket, ga_obj_id, meta_addr, hash);
    LOG_DEBUG_INF("Succeed to register buffer cache, bucket %u, num %u.", bucket_idx, bucket->entry_num);
    dss_unlock_shm_meta_bucket(session, &bucket->enque_lock);
    if (out_obj_id) {
        *out_obj_id = ga_obj_id;
    }
    *block_addr = meta_addr;
    dss_inc_meta_ref_hot(block_ctrl);
    DSS_LOG_DEBUG_OP("Succeed to load meta block, v:%u,au:%llu,block:%u,item:%u,type:%d.", block_id.volume,
        (uint64)block_id.au, block_id.block, block_id.item, type);
    return CM_SUCCESS;
}

void *dss_find_block_in_bucket(dss_session_t *session, dss_vg_info_item_t *vg_item, uint32 hash, uint64 *key,
    bool32 is_print_error_log, ga_obj_id_t *out_obj_id)
{
    CM_ASSERT(key != NULL);
    shm_hashmap_t *hashmap = vg_item->buffer_cache;
    if (hashmap == NULL) {
        if (is_print_error_log) {
            LOG_DEBUG_ERR("Pointer to map or compare_func is NULL");
        }
        return NULL;
    }
    shm_hash_ctrl_t *hash_ctrl = &vg_item->buffer_cache->hash_ctrl;
    char *meta_addr = NULL;
    dss_block_ctrl_t *block_ctrl = NULL;
    auid_t block_id_tmp = {0};
    uint32 bucket_idx = shm_hashmap_calc_bucket_idx(hash_ctrl, hash);
    uint32 segment_objid = DSS_INVALID_ID32;
    shm_hashmap_bucket_t *bucket = shm_hashmap_get_bucket(hash_ctrl, bucket_idx, &segment_objid);
    if (bucket == NULL) {
        if (is_print_error_log) {
            LOG_DEBUG_ERR("Pointer to bucket %u is NULL.", bucket_idx);
        }
        return NULL;
    }
    if (vg_item->from_type == FROM_SHM) {
        dss_lock_shm_meta_bucket_s(session, segment_objid, &bucket->enque_lock);
    }
    ga_obj_id_t next_id = *(ga_obj_id_t *)&bucket->first;
    bool32 has_next = bucket->has_next;
    while (has_next) {
        meta_addr = dss_buffer_get_meta_addr(next_id.pool_id, next_id.obj_id);
        cm_panic(meta_addr != NULL);
        block_ctrl = DSS_GET_BLOCK_CTRL_FROM_META(meta_addr);
        block_id_tmp = ((dss_common_block_t *)meta_addr)->id;
        if ((block_ctrl->hash == hash) && (dss_buffer_cache_key_compare(&block_id_tmp, key) == CM_TRUE)) {
            if (vg_item->from_type == FROM_SHM) {
                dss_unlock_shm_meta_bucket(session, &bucket->enque_lock);
            }
            if (out_obj_id != NULL) {
                *out_obj_id = next_id;
            }

            dss_inc_meta_ref_hot(block_ctrl);
            return meta_addr;
        }
        has_next = block_ctrl->has_next;
        next_id = *(ga_obj_id_t *)&block_ctrl->hash_next;
    }
    if (vg_item->from_type == FROM_SHM) {
        dss_unlock_shm_meta_bucket(session, &bucket->enque_lock);
    }
    return NULL;
}

// do not care content change
static void *dss_find_block_in_bucket_ex(dss_session_t *session, dss_vg_info_item_t *vg_item, uint32 hash, uint64 *key,
    bool32 is_print_error_log, ga_obj_id_t *out_obj_id)
{
    shm_hashmap_t *map = vg_item->buffer_cache;
    CM_ASSERT(key != NULL);
    if (map == NULL) {
        if (is_print_error_log) {
            LOG_DEBUG_ERR("Pointer to map or compare_func is NULL");
        }
        return NULL;
    }
    char *meta_addr = NULL;
    dss_block_ctrl_t *block_ctrl = NULL;
    dss_block_ctrl_t *next_block_ctrl = NULL;
    auid_t block_id_tmp = {0};
    shm_hash_ctrl_t *hash_ctrl = &vg_item->buffer_cache->hash_ctrl;
    uint32 bucket_idx = shm_hashmap_calc_bucket_idx(hash_ctrl, hash);
    uint32 segment_objid = DSS_INVALID_ID32;
    shm_hashmap_bucket_t *bucket = shm_hashmap_get_bucket(hash_ctrl, bucket_idx, &segment_objid);
    if (bucket == NULL) {
        if (is_print_error_log) {
            LOG_DEBUG_ERR("Pointer to bucket %u is NULL.", bucket_idx);
        }
        return NULL;
    }
    (void)dss_lock_shm_meta_bucket_s(session, segment_objid, &bucket->enque_lock);
    ga_obj_id_t next_id = *(ga_obj_id_t *)&bucket->first;
    bool32 has_next = bucket->has_next;
    if (has_next) {
        meta_addr = dss_buffer_get_meta_addr(next_id.pool_id, next_id.obj_id);
        cm_panic(meta_addr != NULL);
        block_ctrl = DSS_GET_BLOCK_CTRL_FROM_META(meta_addr);
        block_id_tmp = ((dss_common_block_t *)meta_addr)->id;
        dss_latch_s(&block_ctrl->latch);
    }
    dss_unlock_shm_meta_bucket(session, &bucket->enque_lock);

    while (has_next) {
        if ((block_ctrl->hash == hash) && (dss_buffer_cache_key_compare(&block_id_tmp, key) == CM_TRUE)) {
            if (out_obj_id != NULL) {
                *out_obj_id = next_id;
            }
            dss_inc_meta_ref_hot(block_ctrl);
            dss_unlatch(&block_ctrl->latch);
            return meta_addr;
        }
        has_next = block_ctrl->has_next;
        next_id = *(ga_obj_id_t *)&block_ctrl->hash_next;
        if (has_next) {
            meta_addr = dss_buffer_get_meta_addr(next_id.pool_id, next_id.obj_id);
            cm_panic(meta_addr != NULL);
            next_block_ctrl = DSS_GET_BLOCK_CTRL_FROM_META(meta_addr);
            block_id_tmp = ((dss_common_block_t *)meta_addr)->id;
            dss_latch_s(&next_block_ctrl->latch);
        }
        dss_unlatch(&block_ctrl->latch);
        block_ctrl = next_block_ctrl;
        next_block_ctrl = NULL;
    }

    return NULL;
}

status_t dss_find_block_objid_in_shm(dss_session_t *session, dss_vg_info_item_t *vg_item, dss_block_id_t block_id,
    dss_block_type_t type, ga_obj_id_t *objid)
{
    char *meta_addr = NULL;
    uint32 hash = DSS_BUFFER_CACHE_HASH(block_id);
    meta_addr = dss_find_block_in_bucket(session, vg_item, hash, (uint64 *)&block_id, CM_FALSE, objid);
    if (meta_addr != NULL) {
        return CM_SUCCESS;
    }
    return CM_ERROR;
}

static status_t dss_add_buffer_cache_inner(dss_session_t *session, shm_hash_ctrl_t *hash_ctrl,
    shm_hashmap_bucket_t *bucket, auid_t add_block_id, dss_block_type_t type, char *refresh_buf, char **shm_buf)
{
    ga_pool_id_e pool_id = dss_buffer_cache_get_pool_id(type);
    uint32 size = dss_buffer_cache_get_block_size(type);
    dss_block_ctrl_t *block_ctrl = NULL;
    uint32 hash = DSS_BUFFER_CACHE_HASH(add_block_id);
    uint32 obj_id = ga_alloc_object(pool_id, CM_INVALID_ID32);
    if (obj_id == CM_INVALID_ID32) {
        DSS_THROW_ERROR(ERR_DSS_GA_ALLOC_OBJECT, pool_id);
        return CM_ERROR;
    }
    char *meta_addr = dss_buffer_get_meta_addr(pool_id, obj_id);
    if (meta_addr == NULL) {
        ga_free_object(pool_id, obj_id);
        DSS_THROW_ERROR(ERR_DSS_GA_GET_ADDR, pool_id, obj_id);
        return CM_ERROR;
    }
    errno_t errcode = memcpy_s(meta_addr, size, refresh_buf, size);
    if (errcode != EOK) {
        ga_free_object(pool_id, obj_id);
        LOG_DEBUG_ERR("Failed to memcpy block, v:%u,au:%llu,block:%u,item:%u,type:%d.", add_block_id.volume,
            (uint64)add_block_id.au, add_block_id.block, add_block_id.item, type);
        CM_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
        return CM_ERROR;
    }
    dss_common_block_t *block = DSS_GET_COMMON_BLOCK_HEAD(meta_addr);
    DSS_LOG_DEBUG_OP("Dss add buffer cache, v:%u,au:%llu,block:%u,item:%u,type:%d.", block->id.volume,
        (uint64)block->id.au, block->id.block, block->id.item, block->type);
    block_ctrl = DSS_GET_BLOCK_CTRL_FROM_META(meta_addr);
    errcode = memset_s(block_ctrl, sizeof(dss_block_ctrl_t), 0, sizeof(dss_block_ctrl_t));
    if (errcode != EOK) {
        ga_free_object(pool_id, obj_id);
        LOG_DEBUG_ERR("Failed to memset block ctrl, v:%u,au:%llu,block:%u,item:%u,type:%d.", add_block_id.volume,
            (uint64)add_block_id.au, add_block_id.block, add_block_id.item, type);
        CM_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
        return CM_ERROR;
    }
    cm_latch_init(&block_ctrl->latch);
    block_ctrl->type = type;
    block_ctrl->block_id = add_block_id;

    ga_obj_id_t ga_obj_id;
    ga_obj_id.pool_id = pool_id;
    ga_obj_id.obj_id = obj_id;
    dss_register_buffer_cache_inner(session, hash_ctrl, bucket, ga_obj_id, meta_addr, hash);
    dss_inc_meta_ref_hot(block_ctrl);
    DSS_LOG_DEBUG_OP("Succeed to load meta_addr block, v:%u,au:%llu,block:%u,item:%u,type:%d.", add_block_id.volume,
        (uint64)add_block_id.au, add_block_id.block, add_block_id.item, type);
    *shm_buf = meta_addr;
    return CM_SUCCESS;
}

static status_t dss_add_buffer_cache(dss_session_t *session, dss_vg_info_item_t *vg_item, auid_t add_block_id,
    dss_block_type_t type, char *refresh_buf, char **shm_buf)
{
    char *meta_addr = NULL;
    dss_block_ctrl_t *block_ctrl = NULL;
    auid_t block_id_tmp = {0};
    uint32 hash = DSS_BUFFER_CACHE_HASH(add_block_id);
    shm_hash_ctrl_t *hash_ctrl = &vg_item->buffer_cache->hash_ctrl;
    uint32 bucket_idx = shm_hashmap_calc_bucket_idx(hash_ctrl, hash);
    shm_hashmap_bucket_t *bucket = shm_hashmap_get_bucket(hash_ctrl, bucket_idx, NULL);
    if (bucket == NULL) {
        return CM_ERROR;
    }
    dss_lock_shm_meta_bucket_x(session, &bucket->enque_lock);
    ga_obj_id_t next_id = *(ga_obj_id_t *)&bucket->first;
    bool32 has_next = bucket->has_next;
    while (has_next) {
        meta_addr = dss_buffer_get_meta_addr(next_id.pool_id, next_id.obj_id);
        if (meta_addr == NULL) {
            dss_unlock_shm_meta_bucket(session, &bucket->enque_lock);
            DSS_THROW_ERROR(ERR_DSS_GA_GET_ADDR, next_id.pool_id, next_id.obj_id);
            return CM_ERROR;
        }

        block_ctrl = DSS_GET_BLOCK_CTRL_FROM_META(meta_addr);
        block_id_tmp = ((dss_common_block_t *)meta_addr)->id;
        if ((block_ctrl->hash == hash) && (dss_buffer_cache_key_compare(&block_id_tmp, &add_block_id) == CM_TRUE)) {
            dss_unlock_shm_meta_bucket(session, &bucket->enque_lock);
            if (((dss_common_block_t *)meta_addr)->type != type) {
                DSS_THROW_ERROR(ERR_DSS_INVALID_BLOCK_TYPE, type, ((dss_common_block_t *)meta_addr)->type);
                return ERR_DSS_INVALID_BLOCK_TYPE;
            }
            uint32 size = dss_buffer_cache_get_block_size(type);
            securec_check_ret(memcpy_s(meta_addr, size, refresh_buf, size));
            dss_common_block_t *ref_block = DSS_GET_COMMON_BLOCK_HEAD(meta_addr);
            dss_inc_meta_ref_hot(block_ctrl);
            DSS_LOG_DEBUG_OP("Dss refresh block in shm, v:%u,au:%llu,block:%u,item:%u,type:%d.", ref_block->id.volume,
                (uint64)ref_block->id.au, ref_block->id.block, ref_block->id.item, ref_block->type);
            *shm_buf = meta_addr;
            return CM_SUCCESS;
        }
        has_next = block_ctrl->has_next;
        next_id = *(ga_obj_id_t *)&block_ctrl->hash_next;
    }
    status_t ret = dss_add_buffer_cache_inner(session, hash_ctrl, bucket, add_block_id, type, refresh_buf, shm_buf);
    if (ret == CM_SUCCESS) {
        LOG_DEBUG_INF("Succeed to register buffer cache, bucket %u, num %u.", bucket_idx, bucket->entry_num);
    }
    dss_unlock_shm_meta_bucket(session, &bucket->enque_lock);
    return ret;
}

status_t dss_refresh_block_in_shm(dss_session_t *session, dss_vg_info_item_t *vg_item, dss_block_id_t block_id,
    dss_block_type_t type, char *buf, char **shm_buf)
{
    char *meta_addr = NULL;
    uint32 hash = DSS_BUFFER_CACHE_HASH(block_id);
    meta_addr = dss_find_block_in_bucket(session, vg_item, hash, (uint64 *)&block_id, CM_FALSE, NULL);
    if (meta_addr != NULL) {
        if (((dss_common_block_t *)meta_addr)->type != type) {
            DSS_THROW_ERROR(ERR_DSS_INVALID_BLOCK_TYPE, type, ((dss_common_block_t *)meta_addr)->type);
            return ERR_DSS_INVALID_BLOCK_TYPE;
        }
        uint32 size = dss_buffer_cache_get_block_size(type);
        securec_check_ret(memcpy_s(meta_addr, size, buf, size));
        dss_common_block_t *block = DSS_GET_COMMON_BLOCK_HEAD(meta_addr);
        DSS_LOG_DEBUG_OP("Dss refresh block in shm, v:%u,au:%llu,block:%u,item:%u,type:%d.", block->id.volume,
            (uint64)block->id.au, block->id.block, block->id.item, block->type);
        *shm_buf = meta_addr;
        return CM_SUCCESS;
    }
    return dss_add_buffer_cache(session, vg_item, block_id, type, buf, shm_buf);
}

char *dss_find_block_in_shm(dss_session_t *session, dss_vg_info_item_t *vg_item, dss_block_id_t block_id,
    dss_block_type_t type, bool32 check_version, ga_obj_id_t *out_obj_id, bool32 active_refresh)
{
    status_t status;
    char *meta_addr = NULL;
    uint32 hash = DSS_BUFFER_CACHE_HASH(block_id);
    meta_addr = dss_find_block_in_bucket(session, vg_item, hash, (uint64 *)&block_id, CM_FALSE, out_obj_id);
    if (!dss_is_server()) {
        return meta_addr;
    }
    if (meta_addr != NULL) {
        if (check_version && (DSS_STANDBY_CLUSTER || !dss_is_readwrite() || active_refresh)) {
            status = dss_check_block_version(vg_item, block_id, type, meta_addr, NULL, CM_FALSE);
            if (status != CM_SUCCESS) {
                return NULL;
            }
        }
        if (dss_is_readwrite()) {
            DSS_ASSERT_LOG(dss_need_exec_local(), "only masterid %u can be readwrite.", dss_get_master_id());
        }
        return meta_addr;
    }

    status = dss_load_buffer_cache(session, vg_item, block_id, type, &meta_addr, out_obj_id);
    if (status != CM_SUCCESS) {
        LOG_DEBUG_ERR("Failed to load meta_addr block, block_id: %s.", dss_display_metaid(block_id));
        return NULL;
    }
    return meta_addr;
}

char *dss_find_block_from_disk_and_refresh_shm(dss_session_t *session, dss_vg_info_item_t *vg_item,
    dss_block_id_t block_id, dss_block_type_t type, ga_obj_id_t *out_obj_id)
{
    status_t status;
    char *meta_addr = NULL;
    uint32 hash = DSS_BUFFER_CACHE_HASH(block_id);
    meta_addr = dss_find_block_in_bucket(session, vg_item, hash, (uint64 *)&block_id, CM_FALSE, out_obj_id);
    if (meta_addr != NULL) {
        if (((dss_common_block_t *)meta_addr)->version != 0) {
            status = dss_check_block_version(vg_item, block_id, type, meta_addr, NULL, CM_TRUE);
            if (status != CM_SUCCESS) {
                return NULL;
            }
        }
        return meta_addr;
    }

    if (!dss_is_server()) {
        return NULL;
    }
    if (dss_load_buffer_cache(session, vg_item, block_id, type, &meta_addr, out_obj_id) != CM_SUCCESS) {
        LOG_DEBUG_ERR("Failed to load meta_addr block, block_id: %s.", dss_display_metaid(block_id));
        return NULL;
    }
    return meta_addr;
}

char *dss_find_block_in_shm_no_refresh(
    dss_session_t *session, dss_vg_info_item_t *vg_item, dss_block_id_t block_id, ga_obj_id_t *out_obj_id)
{
    uint32 hash = DSS_BUFFER_CACHE_HASH(block_id);
    return dss_find_block_in_bucket(session, vg_item, hash, (uint64 *)&block_id, CM_FALSE, out_obj_id);
}

// do not care content change
char *dss_find_block_in_shm_no_refresh_ex(
    dss_session_t *session, dss_vg_info_item_t *vg_item, dss_block_id_t block_id, ga_obj_id_t *out_obj_id)
{
    uint32 hash = DSS_BUFFER_CACHE_HASH(block_id);
    return dss_find_block_in_bucket_ex(session, vg_item, hash, (uint64 *)&block_id, CM_FALSE, out_obj_id);
}

static status_t dss_refresh_buffer_cache_inner(dss_session_t *session, dss_vg_info_item_t *vg_item, uint32 bucket_idx,
    ga_queue_t *obj_que, ga_pool_id_e *obj_pool_id)
{
    shm_hash_ctrl_t *hash_ctrl = &vg_item->buffer_cache->hash_ctrl;
    shm_hashmap_bucket_t *bucket = shm_hashmap_get_bucket(hash_ctrl, bucket_idx, NULL);
    CM_ASSERT(bucket != NULL);

    dss_block_ctrl_t *block_ctrl = NULL;
    dss_block_ctrl_t *block_ctrl_prev = NULL;
    dss_block_ctrl_t *block_ctrl_next = NULL;

    ga_obj_id_t obj_id = {0};
    ga_obj_id_t obj_id_next = {0};

    bool32 has_next = CM_FALSE;
    bool32 need_remove = CM_FALSE;

    dss_lock_shm_meta_bucket_x(session, &bucket->enque_lock);
    if (!bucket->has_next) {
        dss_unlock_shm_meta_bucket(session, &bucket->enque_lock);
        return CM_SUCCESS;
    }

    status_t status = CM_SUCCESS;
    obj_id = *(ga_obj_id_t *)&bucket->first;
    block_ctrl = dss_buffer_get_block_ctrl_addr(obj_id.pool_id, obj_id.obj_id);
    do {
        // no recycle mem for ft block because api cache the meta_addr
        if (block_ctrl->type == DSS_BLOCK_TYPE_FT) {
            dss_init_dss_fs_block_cache_info(&block_ctrl->fs_block_cache_info);
            char *meta_addr = DSS_GET_META_FROM_BLOCK_CTRL(char, block_ctrl);
            status = dss_check_block_version(
                vg_item, ((dss_common_block_t *)meta_addr)->id, block_ctrl->type, meta_addr, NULL, CM_FALSE);
            DSS_BREAK_IF_ERROR(status);

            // no need remove ft block, so make it to the lastest prev block ctrl for remove every time
            block_ctrl_prev = block_ctrl;
        } else {
            // cache the pool info and obj info
            ga_append_into_queue_by_pool_id(obj_id.pool_id, &obj_que[block_ctrl->type], obj_id.obj_id);
            obj_pool_id[block_ctrl->type] = obj_id.pool_id;

            need_remove = CM_TRUE;
        }

        has_next = block_ctrl->has_next;
        obj_id_next = *(ga_obj_id_t *)&block_ctrl->hash_next;
        if (has_next) {
            block_ctrl_next = dss_buffer_get_block_ctrl_addr(obj_id_next.pool_id, obj_id_next.obj_id);
        } else {
            block_ctrl_next = NULL;
        }

        if (need_remove) {
            // may has been linked to recycle meta list
            dss_remove_recycle_meta(session, vg_item, block_ctrl);
            SHM_HASH_BUCKET_REMOVE(bucket, *(sh_mem_p *)&obj_id, block_ctrl, block_ctrl_prev, block_ctrl_next);
            need_remove = CM_FALSE;
        }

        obj_id = obj_id_next;
        block_ctrl = block_ctrl_next;
    } while (has_next);

    dss_unlock_shm_meta_bucket(session, &bucket->enque_lock);
    return status;
}

status_t dss_refresh_buffer_cache(dss_session_t *session, dss_vg_info_item_t *vg_item, shm_hashmap_t *map)
{
    ga_queue_t obj_que[DSS_BLOCK_TYPE_MAX] = {0};
    ga_pool_id_e obj_pool_id[DSS_BLOCK_TYPE_MAX] = {0};
    shm_hash_ctrl_t *hash_ctrl = &vg_item->buffer_cache->hash_ctrl;
    for (uint32_t i = 0; i <= hash_ctrl->max_bucket; i++) {
        status_t status = dss_refresh_buffer_cache_inner(session, vg_item, i, obj_que, obj_pool_id);
        if (status != CM_SUCCESS) {
            return status;
        }
    }
    // free all the obj as batch
    for (uint32 i = 0; i < DSS_BLOCK_TYPE_MAX; i++) {
        if (obj_que[i].count > 0) {
            ga_free_object_list(obj_pool_id[i], &obj_que[i]);
        }
    }
    return CM_SUCCESS;
}

void dss_init_dss_fs_block_cache_info(dss_fs_block_cache_info_t *fs_block_cache_info)
{
    (void)memset_s(fs_block_cache_info, sizeof(dss_fs_block_cache_info_t), 0x00, sizeof(dss_fs_block_cache_info_t));
}

void dss_init_vg_cache_node_info(dss_vg_info_item_t *vg_item)
{
    (void)memset_s(vg_item->vg_cache_node, sizeof(vg_item->vg_cache_node), 0x00, sizeof(vg_item->vg_cache_node));
}

// do not need control concurrence
void dss_inc_meta_ref_hot(dss_block_ctrl_t *block_ctrl)
{
    (void)cm_atomic_add((atomic_t *)&block_ctrl->ref_hot, DSS_RECYCLE_META_HOT_INC_STEP);
}

// do not need control concurrence
void dss_desc_meta_ref_hot(dss_block_ctrl_t *block_ctrl)
{
    if (block_ctrl->ref_hot > 0) {
        int64 ref_hot = block_ctrl->ref_hot;
        int64 new_ref_hot = (int64)((uint64)ref_hot >> 1);
        (void)cm_atomic_cas((atomic_t *)&block_ctrl->ref_hot, ref_hot, new_ref_hot);
    }
}

static void dss_append_recycle_meta(dss_session_t *session, dss_vg_info_item_t *vg_item, dss_block_ctrl_t *block_ctrl)
{
    CM_ASSERT(block_ctrl->recycle_meta_node.next == NULL);
    CM_ASSERT(block_ctrl->recycle_meta_node.prev == NULL);
    uint32 sid = (session == NULL) ? DSS_DEFAULT_SESSIONID : DSS_SESSIONID_IN_LOCK(session->id);
    dss_latch_x2(&vg_item->recycle_meta_desc.latch, sid);
    cm_bilist_add_tail(&block_ctrl->recycle_meta_node, &vg_item->recycle_meta_desc.bilist);
    dss_unlatch(&vg_item->recycle_meta_desc.latch);
}

static bilist_node_t *dss_pop_recycle_meta(dss_session_t *session, dss_vg_info_item_t *vg_item)
{
    uint32 sid = (session == NULL) ? DSS_DEFAULT_SESSIONID : DSS_SESSIONID_IN_LOCK(session->id);
    dss_latch_x2(&vg_item->recycle_meta_desc.latch, sid);
    bilist_node_t *recycle_meta_node = cm_bilist_pop_first(&vg_item->recycle_meta_desc.bilist);
    dss_unlatch(&vg_item->recycle_meta_desc.latch);
    if (recycle_meta_node != NULL) {
        CM_ASSERT(recycle_meta_node->next == NULL);
        CM_ASSERT(recycle_meta_node->prev == NULL);
    }
    return recycle_meta_node;
}

static void dss_remove_recycle_meta(dss_session_t *session, dss_vg_info_item_t *vg_item, dss_block_ctrl_t *block_ctrl)
{
    uint32 sid = (session == NULL) ? DSS_DEFAULT_SESSIONID : DSS_SESSIONID_IN_LOCK(session->id);
    dss_latch_x2(&vg_item->recycle_meta_desc.latch, sid);
    cm_bilist_del(&block_ctrl->recycle_meta_node, &vg_item->recycle_meta_desc.bilist);
    dss_unlatch(&vg_item->recycle_meta_desc.latch);
    CM_ASSERT(block_ctrl->recycle_meta_node.next == NULL);
    CM_ASSERT(block_ctrl->recycle_meta_node.prev == NULL);
}

static uint32 dss_try_find_recycle_meta_by_bucket(dss_session_t *session, dss_vg_info_item_t *vg_item,
    shm_hashmap_bucket_t *bucket, dss_recycle_meta_args_t *recycle_meta_args)
{
    bool32 has_next = CM_FALSE;
    ga_obj_id_t next_id = {0};
    dss_block_ctrl_t *block_ctrl = NULL;

    status_t status = dss_lock_shm_meta_bucket_s(session, vg_item->id, &bucket->enque_lock);
    if (status != CM_SUCCESS) {
        return 0;
    }

    uint32 found_num = 0;
    uint32 fs_usage = ga_get_pool_usage(GA_16K_POOL);
    uint32 fs_aux_usage = ga_get_pool_usage(GA_FS_AUX_POOL);

    next_id = *(ga_obj_id_t *)&bucket->first;
    has_next = bucket->has_next;
    while (has_next) {
        block_ctrl = dss_buffer_get_block_ctrl_addr(next_id.pool_id, next_id.obj_id);
        if (!block_ctrl->recycle_disable &&
            ((fs_usage >= recycle_meta_args->recyle_meta_pos->hwm && block_ctrl->type == DSS_BLOCK_TYPE_FS) ||
                (fs_aux_usage >= recycle_meta_args->recyle_meta_pos->hwm &&
                    block_ctrl->type == DSS_BLOCK_TYPE_FS_AUX))) {
            dss_desc_meta_ref_hot(block_ctrl);
            if (block_ctrl->ref_hot == 0) {
                dss_append_recycle_meta(session, vg_item, block_ctrl);
                found_num++;
            }
        }

        has_next = block_ctrl->has_next;
        next_id = *(ga_obj_id_t *)&block_ctrl->hash_next;
    }
    dss_unlock_shm_meta_bucket(session, &bucket->enque_lock);
    return found_num;
}

static void dss_meta_init_owner_fs_block_cache(dss_block_ctrl_t *owner_block_ctrl)
{
    owner_block_ctrl->fs_block_cache_info.entry_block_addr = NULL;
    owner_block_ctrl->fs_block_cache_info.entry_block_id = 0;
    owner_block_ctrl->fs_block_cache_info.fs_block_addr = NULL;
    owner_block_ctrl->fs_block_cache_info.fs_block_id = 0;
    owner_block_ctrl->fs_block_cache_info.fs_aux_addr = NULL;
    owner_block_ctrl->fs_block_cache_info.fs_aux_block_id = 0;
}

static bool32 dss_try_clean_cache_meta(dss_session_t *session, dss_block_ctrl_t *block_ctrl)
{
    if (block_ctrl->type != DSS_BLOCK_TYPE_FS && block_ctrl->type != DSS_BLOCK_TYPE_FS_AUX) {
        return CM_FALSE;
    }

    gft_node_t *owner_node = (gft_node_t *)block_ctrl->fs_block_cache_info.owner_node_addr;
    if (owner_node == NULL) {
        return CM_TRUE;
    }

    bool32 need_clean = CM_FALSE;
    dss_latch_x_node(session, owner_node, NULL);
    // not cached, clean the owner info
    if (DSS_ID_TO_U64(owner_node->id) != block_ctrl->fs_block_cache_info.owner_node_id) {
        need_clean = CM_TRUE;
    } else {
        // cached
        dss_block_ctrl_t *owner_block_ctrl = dss_get_block_ctrl_by_node(owner_node);
        // the owner has been deleted, clean the owner's cache info, and then clean the owner info
        if (dss_is_node_deleted(owner_node)) {
            dss_meta_init_owner_fs_block_cache(owner_block_ctrl);
            need_clean = CM_TRUE;
            // the onwer is ok, but not cache this block, clean the onwer info
        } else if (owner_block_ctrl->fs_block_cache_info.entry_block_id != DSS_ID_TO_U64(block_ctrl->block_id) &&
                   owner_block_ctrl->fs_block_cache_info.fs_block_id != DSS_ID_TO_U64(block_ctrl->block_id) &&
                   owner_block_ctrl->fs_block_cache_info.fs_aux_block_id != DSS_ID_TO_U64(block_ctrl->block_id)) {
            need_clean = CM_TRUE;
        }
    }
    dss_unlatch_node(owner_node);

    if (need_clean) {
        block_ctrl->fs_block_cache_info.owner_node_addr = NULL;
        block_ctrl->fs_block_cache_info.owner_node_id = 0;
    }
    return need_clean;
}

static void dss_try_recycle_meta_batch(dss_session_t *session, dss_vg_info_item_t *vg_item, bool32 trigger_enable)
{
    dss_block_ctrl_t *block_ctrl = NULL;
    uint32 fs_recyle_cnt = 0;
    uint32 fs_aux_recyle_cnt = 0;

    if (vg_item->recycle_meta_desc.bilist.count == 0) {
        return;
    }

    dss_enter_shm_x(session, vg_item);
    bilist_node_t *recycle_meta_node = dss_pop_recycle_meta(session, vg_item);
    while (recycle_meta_node) {
        block_ctrl = BILIST_NODE_OF(dss_block_ctrl_t, recycle_meta_node, recycle_meta_node);
        // only the ref_hot is 0, and not in syn meta, and clean the invalid cache info
        if (!block_ctrl->recycle_disable && block_ctrl->ref_hot == 0 && dss_try_clean_cache_meta(session, block_ctrl)) {
            if (block_ctrl->type == DSS_BLOCK_TYPE_FS) {
                fs_recyle_cnt++;
                LOG_DEBUG_INF("recycle fs meta pool item id:%s", dss_display_metaid(block_ctrl->block_id));
            } else {
                fs_aux_recyle_cnt++;
                LOG_DEBUG_INF("recycle fs aux meta pool item id:%s", dss_display_metaid(block_ctrl->block_id));
            }

            dss_unregister_buffer_cache(session, vg_item, block_ctrl->block_id);
            ga_free_object(block_ctrl->my_obj_id.pool_id, block_ctrl->my_obj_id.obj_id);
        }
        recycle_meta_node = dss_pop_recycle_meta(session, vg_item);
    }
    dss_leave_shm(session, vg_item);

    LOG_DEBUG_INF("recycle fs meta pool item count:%u", fs_recyle_cnt);
    LOG_DEBUG_INF("recycle fs aux meta pool item count:%u", fs_aux_recyle_cnt);
}

static inline uint32 dss_recycle_meta_batch_num(bool32 trigger_enable)
{
    return trigger_enable ? DSS_RECYCLE_META_TRIGGER_CLEAN_BATCH_NUM : DSS_RECYCLE_META_TIME_CLEAN_BATCH_NUM;
}

static void dss_recycle_meta_by_vg(dss_session_t *session, dss_vg_info_item_t *vg_item,
    dss_recycle_meta_args_t *recycle_meta_args, bool32 trigger_enable)
{
    shm_hashmap_t *map = vg_item->buffer_cache;
    if (map == NULL) {
        return;
    }

    shm_hash_ctrl_t *hash_ctrl = &map->hash_ctrl;
    // hash_ctrl->max_bucket may change
    uint32 cur_map_num = hash_ctrl->max_bucket;
    if (cur_map_num == 0) {
        return;
    }

    shm_hashmap_bucket_t *bucket = NULL;
    uint32 found_num = 0;
    uint32 bucket_id = recycle_meta_args->last_bucket_id[vg_item->id];
    if (bucket_id >= cur_map_num || bucket_id >= hash_ctrl->max_bucket) {
        bucket_id = 0;
    }

    for (; (bucket_id < cur_map_num && bucket_id < hash_ctrl->max_bucket); bucket_id++) {
        bucket = shm_hashmap_get_bucket(hash_ctrl, bucket_id, NULL);
        if (bucket == NULL || !bucket->has_next) {
            continue;
        }

        found_num += dss_try_find_recycle_meta_by_bucket(session, vg_item, bucket, recycle_meta_args);
        uint32 batch_num = dss_recycle_meta_batch_num(trigger_enable);
        if ((found_num >= batch_num) || ((bucket_id + 1) == cur_map_num)) {
            dss_try_recycle_meta_batch(session, vg_item, trigger_enable);
            found_num = 0;
        }

        // check the recycle end
        uint32 fs_usage = ga_get_pool_usage(GA_16K_POOL);
        uint32 fs_aux_usage = ga_get_pool_usage(GA_FS_AUX_POOL);
        if (fs_usage <= recycle_meta_args->recyle_meta_pos->lwm &&
            fs_aux_usage <= recycle_meta_args->recyle_meta_pos->lwm) {
            break;
        }
    }
    recycle_meta_args->last_bucket_id[vg_item->id] = bucket_id;

    if (found_num > 0) {
        dss_try_recycle_meta_batch(session, vg_item, trigger_enable);
    }
}

void dss_recycle_meta(dss_session_t *session, dss_bg_task_info_t *bg_task_info, date_t *clean_time)
{
    dss_recycle_meta_args_t *recycle_meta_args = (dss_recycle_meta_args_t *)bg_task_info->task_args;

    (void)cm_wait_cond(&recycle_meta_args->trigger_cond, recycle_meta_args->trigger_clean_wait_time);
    bool32 trigger_enable = recycle_meta_args->trigger_enable;
    if (!trigger_enable) {
        uint64 time_now = (uint64)cm_now();
        if ((time_now - (*clean_time)) < (recycle_meta_args->time_clean_wait_time * MICROSECS_PER_SECOND)) {
            return;
        }
    } else {
        recycle_meta_args->trigger_enable = CM_FALSE;
    }

    // check wheather need to recycle meta first
    uint32 fs_usage = ga_get_pool_usage(GA_16K_POOL);
    uint32 fs_aux_usage = ga_get_pool_usage(GA_FS_AUX_POOL);
    if ((fs_usage <= recycle_meta_args->recyle_meta_pos->hwm) &&
        (fs_aux_usage <= recycle_meta_args->recyle_meta_pos->hwm)) {
        return;
    }

    LOG_DEBUG_INF("try recycle meta, trigger_enable:%u", (uint32)trigger_enable);
    // do recycle meta for vg one by one
    for (uint32_t i = bg_task_info->my_task_id; i < g_vgs_info->group_num; i += bg_task_info->task_num_max) {
        dss_recycle_meta_by_vg(session, &g_vgs_info->volume_group[i], recycle_meta_args, trigger_enable);
    }

    if (!trigger_enable) {
        *clean_time = cm_now();
    }

    (void)cm_wait_cond(&recycle_meta_args->trigger_cond, recycle_meta_args->trigger_clean_wait_time);
}

void dss_buffer_recycle_disable(dss_block_ctrl_t *block_ctrl, bool8 recycle_disable)
{
    block_ctrl->recycle_disable = recycle_disable;
}

void dss_set_recycle_meta_args_to_vg(dss_bg_task_info_t *bg_task_info)
{
    // do recycle meta for vg one by one
    for (uint32_t i = bg_task_info->my_task_id; i < g_vgs_info->group_num; i += bg_task_info->task_num_max) {
        g_vgs_info->volume_group[i].recycle_meta_desc.task_args = bg_task_info->task_args;
    }
}

void dss_trigger_recycle_meta(dss_vg_info_item_t *vg_item)
{
    dss_recycle_meta_args_t *recycle_meta_args = (dss_recycle_meta_args_t *)vg_item->recycle_meta_desc.task_args;
    recycle_meta_args->trigger_enable = CM_TRUE;
    cm_release_cond(&recycle_meta_args->trigger_cond);
}

#ifdef __cplusplus
}
#endif
