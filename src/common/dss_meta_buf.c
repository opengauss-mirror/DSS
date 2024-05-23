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

#ifdef __cplusplus
extern "C" {
#endif

#define DSS_BUFFER_CACHE_HASH(block_id) cm_hash_int64((int64)DSS_BLOCK_ID_IGNORE_UNINITED((block_id)))

bool32 dss_buffer_cache_key_compare(void *key, void *key2)
{
    uint64 id = DSS_BLOCK_ID_IGNORE_UNINITED(*(uint64 *)key);
    uint64 id2 = DSS_BLOCK_ID_IGNORE_UNINITED(*(uint64 *)key2);
    return cm_oamap_uint64_compare(&id, &id2);
}

static inline ga_pool_id_e dss_buffer_cache_get_pool_id(uint32_t block_type)
{
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
    if (block_type == DSS_BLOCK_TYPE_FT) {
        return DSS_BLOCK_SIZE;
    } else if (block_type == DSS_BLOCK_TYPE_FS) {
        return DSS_FILE_SPACE_BLOCK_SIZE;
    } else {
        return DSS_FS_AUX_SIZE;
    }
}

dss_block_ctrl_t *dss_buffer_cache_get_block_ctrl(uint32_t block_type, char *addr)
{
    if (block_type == DSS_BLOCK_TYPE_FT) {
        return (dss_block_ctrl_t *)(addr + DSS_BLOCK_SIZE);
    } else if (block_type == DSS_BLOCK_TYPE_FS) {
        return (dss_block_ctrl_t *)(addr + DSS_FILE_SPACE_BLOCK_SIZE);
    } else {
        return (dss_block_ctrl_t *)(addr + DSS_FS_AUX_SIZE);
    }
}

static void dss_register_buffer_cache_inner(
    shm_hashmap_bucket_t *bucket, ga_obj_id_t obj_id, dss_block_ctrl_t *block_ctrl, uint32 hash)
{
    CM_ASSERT(bucket != NULL);
    CM_ASSERT(block_ctrl != NULL);
    dss_block_ctrl_t *first_block_ctrl = NULL;
    if (bucket->has_next) {
        ga_obj_id_t first_obj_id = *(ga_obj_id_t *)&bucket->first;
        char *addr = ga_object_addr(first_obj_id.pool_id, first_obj_id.obj_id);
        dss_common_block_t *block = DSS_GET_COMMON_BLOCK_HEAD(addr);
        first_block_ctrl = dss_buffer_cache_get_block_ctrl(block->type, addr);
    } else {
        block_ctrl->has_next = CM_FALSE;
    }
    block_ctrl->hash = hash;
    SHM_HASH_BUCKET_INSERT(bucket, *(sh_mem_p *)&obj_id, block_ctrl, first_block_ctrl);
}

status_t dss_register_buffer_cache(dss_vg_info_item_t *vg_item, const dss_block_id_t block_id, ga_obj_id_t obj_id,
    dss_block_ctrl_t *block_ctrl, dss_block_type_t type)
{
    uint32 hash = DSS_BUFFER_CACHE_HASH(block_id);
    shm_hashmap_bucket_t *buckets = (shm_hashmap_bucket_t *)OFFSET_TO_ADDR(vg_item->buffer_cache->buckets);
    shm_hashmap_bucket_t *bucket = &buckets[hash % vg_item->buffer_cache->num];
    errno_t errcode = memset_s(block_ctrl, sizeof(dss_block_ctrl_t), 0, sizeof(dss_block_ctrl_t));
    if (errcode) {
        LOG_DEBUG_ERR("Failed to memset block ctrl, v:%u,au:%llu,block:%u,item:%u.", block_id.volume,
            (uint64)block_id.au, block_id.block, block_id.item);
        return CM_ERROR;
    }
    dss_lock_shm_meta_bucket_x(&bucket->enque_lock);
    DSS_LOG_DEBUG_OP("Register block id, v:%u,au:%llu,block:%u,item:%u.", block_id.volume, (uint64)block_id.au,
        block_id.block, block_id.item);
    cm_latch_init(&block_ctrl->latch);
    block_ctrl->type = type;
    block_ctrl->block_id = block_id;
    dss_register_buffer_cache_inner(bucket, obj_id, block_ctrl, hash);
    dss_unlock_shm_meta_bucket(NULL, &bucket->enque_lock);
    return CM_SUCCESS;
}

void dss_unregister_buffer_cache(dss_vg_info_item_t *vg_item, dss_block_id_t block_id)
{
    char *addr = NULL;
    dss_block_ctrl_t *block_ctrl = NULL;
    dss_block_ctrl_t *prev_block_ctrl = NULL;
    dss_block_ctrl_t *next_block_ctrl = NULL;
    dss_common_block_t *block = NULL;
    auid_t block_id_tmp = {0};
    uint32 hash = DSS_BUFFER_CACHE_HASH(block_id);
    shm_hashmap_bucket_t *buckets = (shm_hashmap_bucket_t *)OFFSET_TO_ADDR(vg_item->buffer_cache->buckets);
    shm_hashmap_bucket_t *bucket = &buckets[hash % vg_item->buffer_cache->num];
    dss_lock_shm_meta_bucket_x(&bucket->enque_lock);
    ga_obj_id_t next_id = *(ga_obj_id_t *)&bucket->first;
    bool32 has_next = bucket->has_next;
    while (has_next) {
        addr = ga_object_addr(next_id.pool_id, next_id.obj_id);
        cm_panic(addr != NULL);
        block = DSS_GET_COMMON_BLOCK_HEAD(addr);
        block_ctrl = dss_buffer_cache_get_block_ctrl(block->type, addr);
        block_id_tmp = ((dss_common_block_t *)addr)->id;
        if ((block_ctrl->hash == hash) && (dss_buffer_cache_key_compare(&block_id_tmp, &block_id) == CM_TRUE)) {
            if (block_ctrl->has_prev) {
                ga_obj_id_t obj_id = *(ga_obj_id_t *)&block_ctrl->hash_prev;
                addr = ga_object_addr(obj_id.pool_id, obj_id.obj_id);
                block = DSS_GET_COMMON_BLOCK_HEAD(addr);
                prev_block_ctrl = dss_buffer_cache_get_block_ctrl(block->type, addr);
            }
            if (block_ctrl->has_next) {
                ga_obj_id_t obj_id = *(ga_obj_id_t *)&block_ctrl->hash_next;
                addr = ga_object_addr(obj_id.pool_id, obj_id.obj_id);
                block = DSS_GET_COMMON_BLOCK_HEAD(addr);
                next_block_ctrl = dss_buffer_cache_get_block_ctrl(block->type, addr);
            }
            SHM_HASH_BUCKET_REMOVE(bucket, *(sh_mem_p *)&next_id, block_ctrl, prev_block_ctrl, next_block_ctrl);
            dss_unlock_shm_meta_bucket(NULL, &bucket->enque_lock);
            return;
        }
        has_next = block_ctrl->has_next;
        next_id = *(ga_obj_id_t *)&block_ctrl->hash_next;
    }
    dss_unlock_shm_meta_bucket(NULL, &bucket->enque_lock);
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

status_t dss_check_block_version(
    dss_vg_info_item_t *vg_item, dss_block_id_t block_id, dss_block_type_t type, char *addr, bool32 *is_changed, bool32 force_refresh)
{
#ifndef WIN32
    char buf[DSS_DISK_UNIT_SIZE] __attribute__((__aligned__(DSS_DISK_UNIT_SIZE)));
#else
    char buf[DSS_DISK_UNIT_SIZE];
#endif

    if (is_changed) {
        *is_changed = CM_FALSE;
    }

    uint64 version = ((dss_common_block_t *)addr)->version;
    uint32 size = dss_buffer_cache_get_block_size(type);
    int64 offset = dss_get_block_offset(vg_item, (uint64)size, block_id.block, block_id.au);
    // just read block header
    status_t status = dss_get_block_from_disk(vg_item, block_id, buf, offset, DSS_DISK_UNIT_SIZE, CM_FALSE);
    if (status != CM_SUCCESS) {
        LOG_DEBUG_ERR("Failed to get block: %s from disk, addr:%p, offset:%lld, size:%d.", dss_display_metaid(block_id),
            buf, offset, DSS_DISK_UNIT_SIZE);
        return status;
    }
    uint64 disk_version = ((dss_common_block_t *)buf)->version;
    if (dss_compare_version(disk_version, version) || force_refresh) {
        DSS_LOG_DEBUG_OP("dss_check_block_version, version:%llu, disk_version:%llu, blockid: %s, type:%u, force_refresh:%u.", version,
            disk_version, dss_display_metaid(block_id), type, (uint32)force_refresh);
        // if size == DSS_DISK_UNIT_SIZE, the buf has been changed all, not need load again
        if (size == DSS_DISK_UNIT_SIZE) {
            securec_check_ret(memcpy_s(addr, DSS_DISK_UNIT_SIZE, buf, DSS_DISK_UNIT_SIZE));
        } else {
            if (force_refresh && version == 0) {
                status = dss_get_block_from_disk(vg_item, block_id, addr, offset, (int32)size, CM_FALSE);
            } else {
                status = dss_get_block_from_disk(vg_item, block_id, addr, offset, (int32)size, CM_TRUE);
            }
            if (status != CM_SUCCESS) {
                LOG_DEBUG_ERR("Failed to get block: %s from disk, addr:%p, offset:%lld, size:%u.",
                    dss_display_metaid(block_id), addr, offset, size);
                return status;
            }
        }
        if (is_changed) {
            *is_changed = CM_TRUE;
        }
    }

    return CM_SUCCESS;
}

static status_t dss_load_buffer_cache(
    dss_vg_info_item_t *vg_item, auid_t block_id, dss_block_type_t type, char **block_addr, ga_obj_id_t *out_obj_id)
{
    char *addr = NULL;
    dss_block_ctrl_t *block_ctrl = NULL;
    dss_common_block_t *block = NULL;
    auid_t block_id_tmp = {0};
    uint32 hash = DSS_BUFFER_CACHE_HASH(block_id);
    shm_hashmap_t *map = vg_item->buffer_cache;
    shm_hashmap_bucket_t *buckets = (shm_hashmap_bucket_t *)OFFSET_TO_ADDR(map->buckets);
    shm_hashmap_bucket_t *bucket = &buckets[hash % map->num];
    dss_lock_shm_meta_bucket_x(&bucket->enque_lock);
    ga_obj_id_t next_id = *(ga_obj_id_t *)&bucket->first;
    bool32 has_next = bucket->has_next;
    while (has_next) {
        addr = ga_object_addr(next_id.pool_id, next_id.obj_id);
        cm_panic(addr != NULL);
        block = DSS_GET_COMMON_BLOCK_HEAD(addr);
        block_ctrl = dss_buffer_cache_get_block_ctrl(block->type, addr);
        block_id_tmp = ((dss_common_block_t *)addr)->id;
        if ((block_ctrl->hash == hash) && (dss_buffer_cache_key_compare(&block_id_tmp, &block_id) == CM_TRUE)) {
            dss_unlock_shm_meta_bucket(NULL, &bucket->enque_lock);
            status_t status = dss_check_block_version(vg_item, block_id, type, addr, NULL, CM_FALSE);
            if (status != CM_SUCCESS) {
                return status;
            }
            *block_addr = addr;
            if (out_obj_id) {
                *out_obj_id = next_id;
            }
            block_ctrl->type = type;
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
        dss_unlock_shm_meta_bucket(NULL, &bucket->enque_lock);
        return CM_ERROR;
    }
    addr = ga_object_addr(pool_id, obj_id);

    status_t status = dss_get_block_from_disk(vg_item, block_id, addr, offset, (int32)size, CM_TRUE);
    if (status != CM_SUCCESS) {
        dss_unlock_shm_meta_bucket(NULL, &bucket->enque_lock);
        ga_free_object(pool_id, obj_id);
        LOG_DEBUG_ERR("Failed to get block from disk, v:%u,au:%llu,block:%u,item:%u,type:%d.", block_id.volume,
            (uint64)block_id.au, block_id.block, block_id.item, type);
        return status;
    }
    block = DSS_GET_COMMON_BLOCK_HEAD(addr);
    DSS_LOG_DEBUG_OP("DSS load buffer cache, v:%u,au:%llu,block:%u,item:%u,type:%d.", block->id.volume,
        (uint64)block->id.au, block->id.block, block->id.item, block->type);
    block_ctrl = dss_buffer_cache_get_block_ctrl(block->type, addr);
    errno_t errcode = memset_s(block_ctrl, sizeof(dss_block_ctrl_t), 0, sizeof(dss_block_ctrl_t));
    if (errcode != EOK) {
        dss_unlock_shm_meta_bucket(NULL, &bucket->enque_lock);
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
    dss_register_buffer_cache_inner(bucket, ga_obj_id, block_ctrl, hash);
    dss_unlock_shm_meta_bucket(NULL, &bucket->enque_lock);
    if (out_obj_id) {
        *out_obj_id = ga_obj_id;
    }
    *block_addr = addr;
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
    if (hashmap->num == 0) {
        if (is_print_error_log) {
            LOG_DEBUG_ERR("The map is not initialized.");
        }
        return NULL;
    }

    char *addr = NULL;
    dss_block_ctrl_t *block_ctrl = NULL;
    dss_common_block_t *block = NULL;
    auid_t block_id_tmp = {0};
    shm_hashmap_bucket_t *buckets = (shm_hashmap_bucket_t *)OFFSET_TO_ADDR(hashmap->buckets);
    shm_hashmap_bucket_t *bucket = &buckets[hash % hashmap->num];
    if (vg_item->from_type == FROM_SHM) {
        dss_lock_shm_meta_bucket_s(session, vg_item->id, &bucket->enque_lock);
    }
    ga_obj_id_t next_id = *(ga_obj_id_t *)&bucket->first;
    bool32 has_next = bucket->has_next;
    while (has_next) {
        addr = ga_object_addr(next_id.pool_id, next_id.obj_id);
        cm_panic(addr != NULL);
        block = DSS_GET_COMMON_BLOCK_HEAD(addr);
        block_ctrl = dss_buffer_cache_get_block_ctrl(block->type, addr);
        block_id_tmp = ((dss_common_block_t *)addr)->id;
        if ((block_ctrl->hash == hash) && (dss_buffer_cache_key_compare(&block_id_tmp, key) == CM_TRUE)) {
            if (vg_item->from_type == FROM_SHM) {
                dss_unlock_shm_meta_bucket(session, &bucket->enque_lock);
            }
            if (out_obj_id != NULL) {
                *out_obj_id = next_id;
            }
            return addr;
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
    if (map->num == 0) {
        if (is_print_error_log) {
            LOG_DEBUG_ERR("The map is not initialized.");
        }
        return NULL;
    }

    char *addr = NULL;
    dss_block_ctrl_t *block_ctrl = NULL;
    dss_block_ctrl_t *next_block_ctrl = NULL;
    dss_common_block_t *block = NULL;
    auid_t block_id_tmp = {0};
    shm_hashmap_bucket_t *buckets = (shm_hashmap_bucket_t *)OFFSET_TO_ADDR(map->buckets);
    shm_hashmap_bucket_t *bucket = &buckets[hash % map->num];

    (void)dss_lock_shm_meta_bucket_s(session, vg_item->id, &bucket->enque_lock);
    ga_obj_id_t next_id = *(ga_obj_id_t *)&bucket->first;
    bool32 has_next = bucket->has_next;
    if (has_next) {
        addr = ga_object_addr(next_id.pool_id, next_id.obj_id);
        cm_panic(addr != NULL);
        block = DSS_GET_COMMON_BLOCK_HEAD(addr);
        block_ctrl = dss_buffer_cache_get_block_ctrl(block->type, addr);
        block_id_tmp = ((dss_common_block_t *)addr)->id;
        dss_latch_s(&block_ctrl->latch);
    }
    dss_unlock_shm_meta_bucket(session, &bucket->enque_lock);

    while (has_next) {
        if ((block_ctrl->hash == hash) && (dss_buffer_cache_key_compare(&block_id_tmp, key) == CM_TRUE)) {
            if (out_obj_id != NULL) {
                *out_obj_id = next_id;
            }
            dss_unlatch(&block_ctrl->latch);
            return addr;
        }
        has_next = block_ctrl->has_next;
        next_id = *(ga_obj_id_t *)&block_ctrl->hash_next;
        if (has_next) {
            addr = ga_object_addr(next_id.pool_id, next_id.obj_id);
            cm_panic(addr != NULL);
            block = DSS_GET_COMMON_BLOCK_HEAD(addr);
            next_block_ctrl = dss_buffer_cache_get_block_ctrl(block->type, addr);
            block_id_tmp = ((dss_common_block_t *)addr)->id;
            dss_latch_s(&next_block_ctrl->latch);
        }
        dss_unlatch(&block_ctrl->latch);
        block_ctrl = next_block_ctrl;
        next_block_ctrl = NULL;
    }

    return NULL;
}

status_t dss_find_block_objid_in_shm(
    dss_vg_info_item_t *vg_item, dss_block_id_t block_id, dss_block_type_t type, ga_obj_id_t *objid)
{
    char *addr = NULL;
    uint32 hash = DSS_BUFFER_CACHE_HASH(block_id);
    addr = dss_find_block_in_bucket(NULL, vg_item, hash, (uint64 *)&block_id, CM_FALSE, objid);
    if (addr != NULL) {
        return CM_SUCCESS;
    }
    return CM_ERROR;
}

static status_t dss_add_buffer_cache_inner(
    shm_hashmap_bucket_t *bucket, auid_t add_block_id, dss_block_type_t type, char *refresh_buf, char **shm_buf)
{
    ga_pool_id_e pool_id = dss_buffer_cache_get_pool_id(type);
    uint32 size = dss_buffer_cache_get_block_size(type);
    dss_block_ctrl_t *block_ctrl = NULL;
    uint32 hash = DSS_BUFFER_CACHE_HASH(add_block_id);
    uint32 obj_id = ga_alloc_object(pool_id, CM_INVALID_ID32);
    if (obj_id == CM_INVALID_ID32) {
        return CM_ERROR;
    }
    char *addr = ga_object_addr(pool_id, obj_id);
    if (addr == NULL) {
        ga_free_object(pool_id, obj_id);
        DSS_THROW_ERROR(ERR_DSS_GA_GET_ADDR, pool_id, obj_id);
        return CM_ERROR;
    }
    errno_t errcode = memcpy_s(addr, size, refresh_buf, size);
    if (errcode != EOK) {
        ga_free_object(pool_id, obj_id);
        LOG_DEBUG_ERR("Failed to memcpy block, v:%u,au:%llu,block:%u,item:%u,type:%d.", add_block_id.volume,
            (uint64)add_block_id.au, add_block_id.block, add_block_id.item, type);
        CM_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
        return CM_ERROR;
    }
    dss_common_block_t *block = DSS_GET_COMMON_BLOCK_HEAD(addr);
    DSS_LOG_DEBUG_OP("Dss add buffer cache, v:%u,au:%llu,block:%u,item:%u,type:%d.", block->id.volume,
        (uint64)block->id.au, block->id.block, block->id.item, block->type);
    block_ctrl = dss_buffer_cache_get_block_ctrl(block->type, addr);
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
    dss_register_buffer_cache_inner(bucket, ga_obj_id, block_ctrl, hash);

    DSS_LOG_DEBUG_OP("Succeed to load meta block, v:%u,au:%llu,block:%u,item:%u,type:%d.", add_block_id.volume,
        (uint64)add_block_id.au, add_block_id.block, add_block_id.item, type);
    *shm_buf = addr;
    return CM_SUCCESS;
}

static status_t dss_add_buffer_cache(
    dss_vg_info_item_t *vg_item, auid_t add_block_id, dss_block_type_t type, char *refresh_buf, char **shm_buf)
{
    char *addr = NULL;
    dss_block_ctrl_t *block_ctrl = NULL;
    dss_common_block_t *block = NULL;
    auid_t block_id_tmp = {0};
    uint32 hash = DSS_BUFFER_CACHE_HASH(add_block_id);
    shm_hashmap_t *map = vg_item->buffer_cache;
    shm_hashmap_bucket_t *buckets = (shm_hashmap_bucket_t *)OFFSET_TO_ADDR(map->buckets);
    shm_hashmap_bucket_t *bucket = &buckets[hash % map->num];
    dss_lock_shm_meta_bucket_x(&bucket->enque_lock);
    ga_obj_id_t next_id = *(ga_obj_id_t *)&bucket->first;
    bool32 has_next = bucket->has_next;
    while (has_next) {
        addr = ga_object_addr(next_id.pool_id, next_id.obj_id);
        if (addr == NULL) {
            dss_unlock_shm_meta_bucket(NULL, &bucket->enque_lock);
            DSS_THROW_ERROR(ERR_DSS_GA_GET_ADDR, next_id.pool_id, next_id.obj_id);
            return CM_ERROR;
        }
        block = DSS_GET_COMMON_BLOCK_HEAD(addr);
        block_ctrl = dss_buffer_cache_get_block_ctrl(block->type, addr);
        block_id_tmp = ((dss_common_block_t *)addr)->id;
        block_ctrl->type = type;
        if ((block_ctrl->hash == hash) && (dss_buffer_cache_key_compare(&block_id_tmp, &add_block_id) == CM_TRUE)) {
            dss_unlock_shm_meta_bucket(NULL, &bucket->enque_lock);
            if (((dss_common_block_t *)addr)->type != type) {
                DSS_THROW_ERROR(ERR_DSS_INVALID_BLOCK_TYPE, type, ((dss_common_block_t *)addr)->type);
                return ERR_DSS_INVALID_BLOCK_TYPE;
            }
            uint32 size = dss_buffer_cache_get_block_size(type);
            securec_check_ret(memcpy_s(addr, size, refresh_buf, size));
            dss_common_block_t *ref_block = DSS_GET_COMMON_BLOCK_HEAD(addr);
            DSS_LOG_DEBUG_OP("Dss refresh block in shm, v:%u,au:%llu,block:%u,item:%u,type:%d.", ref_block->id.volume,
                (uint64)ref_block->id.au, ref_block->id.block, ref_block->id.item, ref_block->type);
            *shm_buf = addr;
            return CM_SUCCESS;
        }
        has_next = block_ctrl->has_next;
        next_id = *(ga_obj_id_t *)&block_ctrl->hash_next;
    }
    status_t ret = dss_add_buffer_cache_inner(bucket, add_block_id, type, refresh_buf, shm_buf);
    dss_unlock_shm_meta_bucket(NULL, &bucket->enque_lock);
    return ret;
}

status_t dss_refresh_block_in_shm(dss_session_t *session, dss_vg_info_item_t *vg_item, dss_block_id_t block_id,
    dss_block_type_t type, char *buf, char **shm_buf)
{
    char *addr = NULL;
    uint32 hash = DSS_BUFFER_CACHE_HASH(block_id);
    addr = dss_find_block_in_bucket(session, vg_item, hash, (uint64 *)&block_id, CM_FALSE, NULL);
    if (addr != NULL) {
        if (((dss_common_block_t *)addr)->type != type) {
            DSS_THROW_ERROR(ERR_DSS_INVALID_BLOCK_TYPE, type, ((dss_common_block_t *)addr)->type);
            return ERR_DSS_INVALID_BLOCK_TYPE;
        }
        uint32 size = dss_buffer_cache_get_block_size(type);
        securec_check_ret(memcpy_s(addr, size, buf, size));
        dss_common_block_t *block = DSS_GET_COMMON_BLOCK_HEAD(addr);
        DSS_LOG_DEBUG_OP("Dss refresh block in shm, v:%u,au:%llu,block:%u,item:%u,type:%d.", block->id.volume,
            (uint64)block->id.au, block->id.block, block->id.item, block->type);
        *shm_buf = addr;
        return CM_SUCCESS;
    }
    return dss_add_buffer_cache(vg_item, block_id, type, buf, shm_buf);
}

char *dss_find_block_in_shm(dss_session_t *session, dss_vg_info_item_t *vg_item, dss_block_id_t block_id,
    dss_block_type_t type, bool32 check_version, ga_obj_id_t *out_obj_id, bool32 active_refresh)
{
    status_t status;
    char *addr = NULL;
    uint32 hash = DSS_BUFFER_CACHE_HASH(block_id);
    addr = dss_find_block_in_bucket(session, vg_item, hash, (uint64 *)&block_id, CM_FALSE, out_obj_id);
    if (!dss_is_server()) {
        return addr;
    }
    if (addr != NULL) {
        if (check_version && (DSS_STANDBY_CLUSTER || !dss_is_readwrite() || active_refresh)) {
            status = dss_check_block_version(vg_item, block_id, type, addr, NULL, CM_FALSE);
            if (status != CM_SUCCESS) {
                return NULL;
            }
        }
        if (dss_is_readwrite()) {
            DSS_ASSERT_LOG(dss_need_exec_local(), "only masterid %u can be readwrite.", dss_get_master_id());
        }
        return addr;
    }

    status = dss_load_buffer_cache(vg_item, block_id, type, &addr, out_obj_id);
    if (status != CM_SUCCESS) {
        LOG_DEBUG_ERR("Failed to load meta block, block_id: %s.", dss_display_metaid(block_id));
        return NULL;
    }
    return addr;
}

char *dss_find_block_from_disk_and_refresh_shm(dss_session_t *session, dss_vg_info_item_t *vg_item, dss_block_id_t block_id,
    dss_block_type_t type, ga_obj_id_t *out_obj_id)
{
    status_t status;
    char *addr = NULL;
    uint32 hash = DSS_BUFFER_CACHE_HASH(block_id);
    addr = dss_find_block_in_bucket(session, vg_item, hash, (uint64 *)&block_id, CM_FALSE, out_obj_id);
    if (addr != NULL) {
            status = dss_check_block_version(vg_item, block_id, type, addr, NULL, CM_TRUE);
            if (status != CM_SUCCESS) {
                return NULL;
            }
        return addr;
    }

    if (!dss_is_server()) {
        return NULL;
    }
    if (dss_load_buffer_cache(vg_item, block_id, type, &addr, out_obj_id) != CM_SUCCESS) {
        LOG_DEBUG_ERR("Failed to load meta block, block_id: %s.", dss_display_metaid(block_id));
        return NULL;
    }
    return addr;
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

static status_t dss_refresh_buffer_cache_inner(
    dss_vg_info_item_t *vg_item, shm_hashmap_bucket_t *bucket, ga_queue_t *obj_que, ga_pool_id_e *obj_pool_id)
{
    bool32 has_next = CM_FALSE;
    ga_obj_id_t next_id = {0};

    dss_block_ctrl_t *block_ctrl = NULL;
    dss_block_ctrl_t *block_ctrl_prev = NULL;
    dss_common_block_t *block = NULL;
    char *addr = NULL;

    ga_obj_id_t id_curr = {0};
    dss_block_ctrl_t *block_ctrl_curr = NULL;
    bool32 need_remove = CM_FALSE;

    dss_lock_shm_meta_bucket_s(NULL, vg_item->id, &bucket->enque_lock);
    next_id = *(ga_obj_id_t *)&bucket->first;
    has_next = bucket->has_next;
    while (has_next) {
        if (addr == NULL) {
            addr = ga_object_addr(next_id.pool_id, next_id.obj_id);
            block = DSS_GET_COMMON_BLOCK_HEAD(addr);
            block_ctrl = dss_buffer_cache_get_block_ctrl(block->type, addr);
        }

        // no recycle mem for ft block because api cache the addr
        if (block->type == DSS_BLOCK_TYPE_FT) {
            dss_init_dss_fs_block_cache_info(&block_ctrl->fs_block_cache_info);
            status_t status =
                dss_check_block_version(vg_item, ((dss_common_block_t *)addr)->id, block->type, addr, NULL, CM_FALSE);
            if (status != CM_SUCCESS) {
                dss_unlock_shm_meta_bucket(NULL, &bucket->enque_lock);
                return status;
            }

            // next may NOT be ft, need remove from the link and need the prev point info
            block_ctrl_prev = block_ctrl;
            need_remove = CM_FALSE;
        } else {
            // cache the pool info and obj info
            ga_append_into_queue_by_pool_id(next_id.pool_id, &obj_que[block->type], next_id.obj_id);
            obj_pool_id[block->type] = next_id.pool_id;

            // need remove from the link, and need cur point info
            id_curr = next_id;
            block_ctrl_curr = block_ctrl;
            need_remove = CM_TRUE;
        }

        has_next = block_ctrl->has_next;
        next_id = *(ga_obj_id_t *)&block_ctrl->hash_next;

        if (has_next) {
            addr = ga_object_addr(next_id.pool_id, next_id.obj_id);
            block = DSS_GET_COMMON_BLOCK_HEAD(addr);
            block_ctrl = dss_buffer_cache_get_block_ctrl(block->type, addr);
        } else {
            addr = NULL;
            block = NULL;
            block_ctrl = NULL;
        }

        if (need_remove) {
            SHM_HASH_BUCKET_REMOVE(bucket, *(sh_mem_p *)&id_curr, block_ctrl_curr, block_ctrl_prev, block_ctrl);
        }
    }
    dss_unlock_shm_meta_bucket(NULL, &bucket->enque_lock);

    return CM_SUCCESS;
}

status_t dss_refresh_buffer_cache(dss_vg_info_item_t *vg_item, shm_hashmap_t *map)
{
    shm_hashmap_bucket_t *buckets = (shm_hashmap_bucket_t *)OFFSET_TO_ADDR(map->buckets);
    shm_hashmap_bucket_t *bucket = NULL;

    ga_queue_t obj_que[DSS_BLOCK_TYPE_MAX] = {0};
    ga_pool_id_e obj_pool_id[DSS_BLOCK_TYPE_MAX] = {0};

    for (uint32_t i = 0; i < map->num; i++) {
        bucket = &buckets[i];
        status_t status = dss_refresh_buffer_cache_inner(vg_item, bucket, obj_que, obj_pool_id);
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

#ifdef __cplusplus
}
#endif
