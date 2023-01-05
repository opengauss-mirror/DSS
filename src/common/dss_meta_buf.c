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
#include "dss_syncpoint.h"

#ifdef __cplusplus
extern "C" {
#endif

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
        if (block->type == DSS_BLOCK_TYPE_FT) {
            first_block_ctrl = (dss_block_ctrl_t *)(addr + DSS_BLOCK_SIZE);
        } else {
            first_block_ctrl = (dss_block_ctrl_t *)(addr + DSS_FILE_SPACE_BLOCK_SIZE);
        }
    } else {
        block_ctrl->has_next = CM_FALSE;
    }
    block_ctrl->hash = hash;
    SHM_HASH_BUCKET_INSERT(bucket, *(sh_mem_p *)&obj_id, block_ctrl, first_block_ctrl);
}

status_t dss_register_buffer_cache(
    dss_vg_info_item_t *vg_item, const dss_block_id_t *block_id, ga_obj_id_t obj_id, dss_block_ctrl_t *block_ctrl)
{
    uint32 hash = cm_hash_int64(*(int64 *)block_id);
    shm_hashmap_bucket_t *buckets = (shm_hashmap_bucket_t *)OFFSET_TO_ADDR(vg_item->buffer_cache->buckets);
    shm_hashmap_bucket_t *bucket = &buckets[hash % vg_item->buffer_cache->num];
    errno_t errcode = memset_s(block_ctrl, sizeof(dss_block_ctrl_t), 0, sizeof(dss_block_ctrl_t));
    if (errcode) {
        LOG_DEBUG_ERR("Failed to memset block ctrl, v:%u,au:%llu,block:%u,item:%u.", block_id->volume,
            (uint64)block_id->au, block_id->block, block_id->item);
        return CM_ERROR;
    }
    dss_latch_x(&bucket->enque_lock);
    dss_register_buffer_cache_inner(bucket, obj_id, block_ctrl, hash);
    dss_unlatch(&bucket->enque_lock);
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
    uint32 hash = cm_hash_int64(*(int64 *)&block_id);
    shm_hashmap_bucket_t *buckets = (shm_hashmap_bucket_t *)OFFSET_TO_ADDR(vg_item->buffer_cache->buckets);
    shm_hashmap_bucket_t *bucket = &buckets[hash % vg_item->buffer_cache->num];
    dss_latch_x(&bucket->enque_lock);
    ga_obj_id_t next_id = *(ga_obj_id_t *)&bucket->first;
    bool32 has_next = bucket->has_next;
    while (has_next) {
        addr = ga_object_addr(next_id.pool_id, next_id.obj_id);
        cm_panic(addr != NULL);
        block = DSS_GET_COMMON_BLOCK_HEAD(addr);
        if (block->type == DSS_BLOCK_TYPE_FT) {
            block_ctrl = (dss_block_ctrl_t *)(addr + DSS_BLOCK_SIZE);
            block_id_tmp = ((dss_ft_block_t *)addr)->id;
        } else {
            block_ctrl = (dss_block_ctrl_t *)(addr + DSS_FILE_SPACE_BLOCK_SIZE);
            block_id_tmp = ((dss_fs_block_t *)addr)->head.id;
        }
        if ((block_ctrl->hash == hash) && (vg_item->buffer_cache->func(&block_id_tmp, &block_id) == CM_TRUE)) {
            if (block_ctrl->has_prev) {
                ga_obj_id_t obj_id = *(ga_obj_id_t *)&block_ctrl->hash_prev;
                addr = ga_object_addr(obj_id.pool_id, obj_id.obj_id);
                block = DSS_GET_COMMON_BLOCK_HEAD(addr);
                prev_block_ctrl = (block->type == DSS_BLOCK_TYPE_FT) ?
                                      (dss_block_ctrl_t *)(addr + DSS_BLOCK_SIZE) :
                                      (dss_block_ctrl_t *)(addr + DSS_FILE_SPACE_BLOCK_SIZE);
            }
            if (block_ctrl->has_next) {
                ga_obj_id_t obj_id = *(ga_obj_id_t *)&block_ctrl->hash_next;
                addr = ga_object_addr(obj_id.pool_id, obj_id.obj_id);
                block = DSS_GET_COMMON_BLOCK_HEAD(addr);
                next_block_ctrl = (block->type == DSS_BLOCK_TYPE_FT) ?
                                      (dss_block_ctrl_t *)(addr + DSS_BLOCK_SIZE) :
                                      (dss_block_ctrl_t *)(addr + DSS_FILE_SPACE_BLOCK_SIZE);
            }
            SHM_HASH_BUCKET_REMOVE(bucket, *(sh_mem_p *)&next_id, block_ctrl, prev_block_ctrl, next_block_ctrl);
            dss_unlatch(&bucket->enque_lock);
            return;
        }
        has_next = block_ctrl->has_next;
        next_id = *(ga_obj_id_t *)&block_ctrl->hash_next;
    }
    dss_unlatch(&bucket->enque_lock);
    LOG_DEBUG_ERR("Key to remove not found");
}

status_t dss_get_block_from_disk(
    dss_vg_info_item_t *vg_item, dss_block_id_t block_id, char *buf, int64_t offset, int32 size, bool32 calc_checksum)
{
    CM_ASSERT(block_id.volume < DSS_MAX_VOLUMES);
    status_t status = dss_check_read_volume(vg_item, (uint32)block_id.volume, offset, buf, size);
    if (status != CM_SUCCESS) {
        return status;
    }

    // check the checksum when read the file table block and file space block.
    if (calc_checksum) {
        cm_panic((uint32)size == DSS_BLOCK_SIZE || (uint32)size == DSS_FILE_SPACE_BLOCK_SIZE);
        uint32 checksum = dss_get_checksum(buf, (uint32)size);
        dss_common_block_t *block = (dss_common_block_t *)buf;
        dss_check_checksum(checksum, block->checksum);
    }

    return CM_SUCCESS;
}

status_t dss_check_block_version(
    dss_vg_info_item_t *vg_item, dss_block_id_t blockid, dss_block_type_t type, char *addr, bool32 *is_changed)
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
    uint32 size = (type == DSS_BLOCK_TYPE_FT) ? DSS_BLOCK_SIZE : DSS_FILE_SPACE_BLOCK_SIZE;
    int64 offset = dss_get_block_offset(vg_item, (uint64)size, blockid.block, blockid.au);
    // just read block header
    status_t status = dss_get_block_from_disk(vg_item, blockid, buf, offset, DSS_DISK_UNIT_SIZE, CM_FALSE);
    if (status != CM_SUCCESS) {
        LOG_DEBUG_ERR("Failed to get block:%llu from disk, addr:%p, offset:%lld, size:%d.", DSS_ID_TO_U64(blockid), buf,
            offset, DSS_DISK_UNIT_SIZE);
        return status;
    }
    uint64 disk_version = ((dss_common_block_t *)buf)->version;
    if (dss_compare_version(disk_version, version)) {
        DSS_LOG_DEBUG_OP("dss_check_block_version, version:%llu, disk_version:%llu, blockid:%llu, type:%u.", version,
            disk_version, DSS_ID_TO_U64(blockid), type);
        status = dss_get_block_from_disk(vg_item, blockid, addr, offset, (int32)size, CM_TRUE);
        if (status != CM_SUCCESS) {
            LOG_DEBUG_ERR("Failed to get block:%llu from disk, addr:%p, offset:%lld, size:%u.", DSS_ID_TO_U64(blockid),
                addr, offset, size);
            return status;
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
    uint32 hash = cm_hash_int64(*(int64 *)&block_id);
    shm_hashmap_t *map = vg_item->buffer_cache;
    shm_hashmap_bucket_t *buckets = (shm_hashmap_bucket_t *)OFFSET_TO_ADDR(map->buckets);
    shm_hashmap_bucket_t *bucket = &buckets[hash % map->num];
    dss_latch_x(&bucket->enque_lock);
    ga_obj_id_t next_id = *(ga_obj_id_t *)&bucket->first;
    bool32 has_next = bucket->has_next;
    while (has_next) {
        addr = ga_object_addr(next_id.pool_id, next_id.obj_id);
        cm_panic(addr != NULL);
        block = DSS_GET_COMMON_BLOCK_HEAD(addr);
        if (block->type == DSS_BLOCK_TYPE_FT) {
            block_ctrl = (dss_block_ctrl_t *)(addr + DSS_BLOCK_SIZE);
            block_id_tmp = ((dss_ft_block_t *)addr)->id;
        } else {
            block_ctrl = (dss_block_ctrl_t *)(addr + DSS_FILE_SPACE_BLOCK_SIZE);
            block_id_tmp = ((dss_fs_block_t *)addr)->head.id;
        }
        if ((block_ctrl->hash == hash) && (cm_oamap_uint64_compare(&block_id_tmp, &block_id) == CM_TRUE)) {
            dss_unlatch(&bucket->enque_lock);
            status_t status = dss_check_block_version(vg_item, block_id, type, addr, NULL);
            if (status != CM_SUCCESS) {
                return status;
            }
            *block_addr = addr;
            if (out_obj_id) {
                *out_obj_id = next_id;
            }
            return CM_SUCCESS;
        }
        has_next = block_ctrl->has_next;
        next_id = *(ga_obj_id_t *)&block_ctrl->hash_next;
    }

    ga_pool_id_e pool_id;
    uint32 size;
    if (type == DSS_BLOCK_TYPE_FT) {
        pool_id = GA_8K_POOL;
        size = DSS_BLOCK_SIZE;
    } else {
        pool_id = GA_16K_POOL;
        size = DSS_FILE_SPACE_BLOCK_SIZE;
    }
    int64_t offset = dss_get_block_offset(vg_item, (uint64)size, block_id.block, block_id.au);
    uint32 obj_id = ga_alloc_object(pool_id, CM_INVALID_ID32);
    if (obj_id == CM_INVALID_ID32) {
        dss_unlatch(&bucket->enque_lock);
        return ERR_ALLOC_MEMORY;
    }
    char *buf = ga_object_addr(pool_id, obj_id);

    status_t status = dss_get_block_from_disk(vg_item, block_id, buf, offset, (int32)size, CM_TRUE);
    if (status != CM_SUCCESS) {
        dss_unlatch(&bucket->enque_lock);
        ga_free_object(pool_id, obj_id);
        LOG_DEBUG_ERR("Failed to get block from disk, v:%u,au:%llu,block:%u,item:%u,type:%d.", block_id.volume,
            (uint64)block_id.au, block_id.block, block_id.item, type);
        return status;
    }
    block = DSS_GET_COMMON_BLOCK_HEAD(buf);
    if (block->type == DSS_BLOCK_TYPE_FT) {
        block_ctrl = (dss_block_ctrl_t *)(buf + DSS_BLOCK_SIZE);
    } else {
        block_ctrl = (dss_block_ctrl_t *)(buf + DSS_FILE_SPACE_BLOCK_SIZE);
    }
    errno_t errcode = memset_s(block_ctrl, sizeof(dss_block_ctrl_t), 0, sizeof(dss_block_ctrl_t));
    if (errcode != EOK) {
        dss_unlatch(&bucket->enque_lock);
        ga_free_object(pool_id, obj_id);
        LOG_DEBUG_ERR("Failed to memset block ctrl, v:%u,au:%llu,block:%u,item:%u,type:%d.", block_id.volume,
            (uint64)block_id.au, block_id.block, block_id.item, type);
        return CM_ERROR;
    }
    ga_obj_id_t ga_obj_id;
    ga_obj_id.pool_id = pool_id;
    ga_obj_id.obj_id = obj_id;
    dss_register_buffer_cache_inner(bucket, ga_obj_id, block_ctrl, hash);
    dss_unlatch(&bucket->enque_lock);
    if (out_obj_id) {
        *out_obj_id = ga_obj_id;
    }
    *block_addr = buf;
    DSS_LOG_DEBUG_OP("Succeed to load meta block, v:%u,au:%llu,block:%u,item:%u,type:%d.", block_id.volume,
        (uint64)block_id.au, block_id.block, block_id.item, type);
    return CM_SUCCESS;
}

void *dss_find_block_in_bucket(
    shm_hashmap_t *map, uint32 hash, uint64 *key, bool32 is_print_error_log, ga_obj_id_t *out_obj_id)
{
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
    dss_common_block_t *block = NULL;
    auid_t block_id_tmp = {0};
    shm_hashmap_bucket_t *buckets = (shm_hashmap_bucket_t *)OFFSET_TO_ADDR(map->buckets);
    shm_hashmap_bucket_t *bucket = &buckets[hash % map->num];
    dss_latch_s(&bucket->enque_lock);
    ga_obj_id_t next_id = *(ga_obj_id_t *)&bucket->first;
    bool32 has_next = bucket->has_next;
    while (has_next) {
        addr = ga_object_addr(next_id.pool_id, next_id.obj_id);
        cm_panic(addr != NULL);
        block = DSS_GET_COMMON_BLOCK_HEAD(addr);
        if (block->type == DSS_BLOCK_TYPE_FT) {
            block_ctrl = (dss_block_ctrl_t *)(addr + DSS_BLOCK_SIZE);
            block_id_tmp = ((dss_ft_block_t *)addr)->id;
        } else {
            block_ctrl = (dss_block_ctrl_t *)(addr + DSS_FILE_SPACE_BLOCK_SIZE);
            block_id_tmp = ((dss_fs_block_t *)addr)->head.id;
        }
        if ((block_ctrl->hash == hash) && (cm_oamap_uint64_compare(&block_id_tmp, key) == CM_TRUE)) {
            dss_unlatch(&bucket->enque_lock);
            if (out_obj_id != NULL) {
                *out_obj_id = next_id;
            }
            return addr;
        }
        has_next = block_ctrl->has_next;
        next_id = *(ga_obj_id_t *)&block_ctrl->hash_next;
    }
    dss_unlatch(&bucket->enque_lock);
    return NULL;
}

status_t dss_find_block_objid_in_shm(
    dss_vg_info_item_t *vg_item, dss_block_id_t block_id, dss_block_type_t type, ga_obj_id_t *objid)
{
    char *addr = NULL;
    uint32 hash = cm_hash_int64(*(int64 *)&block_id);
    addr = dss_find_block_in_bucket(vg_item->buffer_cache, hash, (uint64 *)&block_id, CM_FALSE, objid);
    if (addr != NULL) {
        return CM_SUCCESS;
    }
    return CM_ERROR;
}

char *dss_find_block_in_shm(dss_vg_info_item_t *vg_item, dss_block_id_t block_id, dss_block_type_t type,
    bool32 check_version, ga_obj_id_t *out_obj_id, bool32 active_refresh)
{
    status_t status;
    char *addr = NULL;
    uint32 hash = cm_hash_int64(*(int64 *)&block_id);
    addr = dss_find_block_in_bucket(vg_item->buffer_cache, hash, (uint64 *)&block_id, CM_FALSE, out_obj_id);
    if (addr != NULL) {
        if (check_version && dss_is_server() && (!dss_is_readwrite() || active_refresh)) {
            status = dss_check_block_version(vg_item, block_id, type, addr, NULL);
            if (status != CM_SUCCESS) {
                return NULL;
            }
        }
        return addr;
    }

    if (!dss_is_server()) {
        return NULL;
    }

    status = dss_load_buffer_cache(vg_item, block_id, type, &addr, out_obj_id);
    if (status != CM_SUCCESS) {
        LOG_DEBUG_ERR("Failed to load meta block, block_id:%llu.", DSS_ID_TO_U64(block_id));
        return NULL;
    }
    return addr;
}

status_t dss_refresh_buffer_cache(dss_vg_info_item_t *vg_item, shm_hashmap_t *map)
{
    shm_hashmap_bucket_t *buckets = (shm_hashmap_bucket_t *)OFFSET_TO_ADDR(map->buckets);
    shm_hashmap_bucket_t *bucket = NULL;
    dss_block_ctrl_t *block_ctrl = NULL;
    dss_common_block_t *block = NULL;
    bool32 has_next = CM_FALSE;
    auid_t block_id_tmp = {0};
    ga_obj_id_t next_id = {0};
    status_t status;
    char *addr = NULL;
    for (uint32_t i = 0; i < map->num; i++) {
        bucket = &buckets[i];
        dss_latch_s(&bucket->enque_lock);
        next_id = *(ga_obj_id_t *)&bucket->first;
        has_next = bucket->has_next;
        while (has_next) {
            addr = ga_object_addr(next_id.pool_id, next_id.obj_id);
            block = DSS_GET_COMMON_BLOCK_HEAD(addr);
            if (block->type == DSS_BLOCK_TYPE_FT) {
                block_ctrl = (dss_block_ctrl_t *)(addr + DSS_BLOCK_SIZE);
                block_id_tmp = ((dss_ft_block_t *)addr)->id;
            } else {
                block_ctrl = (dss_block_ctrl_t *)(addr + DSS_FILE_SPACE_BLOCK_SIZE);
                block_id_tmp = ((dss_fs_block_t *)addr)->head.id;
            }
            status = dss_check_block_version(vg_item, block_id_tmp, block->type, addr, NULL);
            if (status != CM_SUCCESS) {
                dss_unlatch(&bucket->enque_lock);
                return status;
            }
            has_next = block_ctrl->has_next;
            next_id = *(ga_obj_id_t *)&block_ctrl->hash_next;
        }
        dss_unlatch(&bucket->enque_lock);
    }
    return CM_SUCCESS;
}

#ifdef __cplusplus
}
#endif
