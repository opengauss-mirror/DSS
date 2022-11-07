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
 * cm_hashmap.c
 *
 *
 * IDENTIFICATION
 *    src/common/cm_hashmap.c
 *
 * -------------------------------------------------------------------------
 */

#include "cm_error.h"
#include "cm_hash.h"
#include "cm_log.h"
#include "dss_errno.h"
#include "dss_malloc.h"
#include "dss_hashmap.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define HASH_MASK 0x3fffffff

// clang-format off
static uint32 const cm_primes[] = {
    7,
    13,
    31,
    61,
    127,
    251,
    509,
    1021,
    1297,
    2039,
    4093,
    8191,
    16381,
    32749,
    65521,
    131071,
    262139,
    524287,
    1048573,
    2097143,
    4194301,
    8388593,
    16777213,
    33554393,
    67108859,
    134217689,
    268435399,
    536870909,
    1073741789,
    2147483647,
    0xfffffffb
};

// clang-format on
uint32 cm_hash_int64(int64 i64)
{
    uint32 u32l = (uint32)i64;
    uint32 u32h = (uint32)((uint64)i64 >> 32);

    u32l ^= (i64 >= 0) ? u32h : ~u32h;

    return cm_hash_uint32_shard(u32l);
}

uint32 cm_hash_text(const text_t *text, uint32 range)
{
    return cm_hash_bytes((uint8 *)text->str, text->len, range);
}

uint32 cm_hash_string(const char *str, uint32 range)
{
    return cm_hash_bytes((uint8 *)str, (uint32)strlen(str), range);
}

bool32 cm_oamap_ptr_compare(void *key1, void *key2)
{
    CM_ASSERT(key1 != NULL && key2 != NULL);
    return (key1 == key2);
}

bool32 cm_oamap_uint64_compare(void *key1, void *key2)
{
    CM_ASSERT(key1 != NULL && key2 != NULL);
    return (*(uint64 *)key1 == *(uint64 *)key2);
}

bool32 cm_oamap_uint32_compare(void *key1, void *key2)
{
    CM_ASSERT(key1 != NULL);
    CM_ASSERT(key2 != NULL);
    return (*(uint32 *)key1 == *(uint32 *)key2);
}

bool32 cm_oamap_string_compare(void *key1, void *key2)
{
    CM_ASSERT(key1 != NULL);
    CM_ASSERT(key2 != NULL);
    return (strcmp((char *)key1, (char *)key2) == 0);
}

static uint32 oamap_get_near_prime(unsigned long n)
{
    uint32 low = 0;
    uint32 cnt = (uint32)(sizeof(cm_primes) / sizeof(uint32));
    uint32 high = cnt;

    while (low != high) {
        unsigned int mid = low + (high - low) / 2;
        if (n > cm_primes[mid]) {
            low = mid + 1;
        } else {
            high = mid;
        }
    }
    if (low < cnt) {
        return cm_primes[low];
    } else {
        return (uint32)n;
    }
}

static void oamap_rehash_core(cm_oamap_t *map, uint32 new_capacity, cm_oamap_bucket_t *new_buckets, uint32 *used)
{
    bool32 found;
    uint32 i, j, start;
    cm_oamap_bucket_t *src_bucket, *dst_bucket;

    if (new_capacity == 0) {
        cm_panic(0);
    }
    void **new_key = (void **)(new_buckets + new_capacity);
    void **new_value = (void **)(new_key + new_capacity);
    for (i = 0; i < map->num; i++) {
        src_bucket = &(map->buckets[i]);
        if (src_bucket->state != (uint32)USED) {
            continue;
        }
        start = src_bucket->hash % new_capacity;
        found = CM_FALSE;
        for (j = start; j < new_capacity; j++) {
            dst_bucket = &new_buckets[j];
            if (dst_bucket->state != (uint32)USED) {
                *dst_bucket = *src_bucket;
                new_key[j] = map->key[i];
                new_value[j] = map->value[i];
                found = CM_TRUE;
                (*used)++;
                break;
            }
        }
        if (found) {
            continue;
        }
        while (start > 0) {
            start--;
            dst_bucket = &new_buckets[start];
            if (dst_bucket->state != (uint32)USED) {
                *dst_bucket = *src_bucket;
                new_key[start] = map->key[i];
                new_value[start] = map->value[i];
                found = CM_TRUE;
                (*used)++;
                break;
            }
        }
    }
}

static int32 oamap_rehash(cm_oamap_t *map, uint32 new_capacity)
{
    CM_ASSERT(map != NULL);
    uint32 used = 0;
    if (new_capacity == 0) {
        return ERR_DSS_INVALID_PARAM;
    }

    uint64 size = new_capacity * (uint64)(sizeof(cm_oamap_bucket_t) + sizeof(void *) + sizeof(void *));
    if (size >= CM_INVALID_ID32) {
        LOG_DEBUG_ERR("Invalid capacity value specified for rehashing map.");
        return ERR_DSS_INVALID_PARAM;
    }

    cm_oamap_bucket_t *new_buckets = (cm_oamap_bucket_t *)cm_malloc((uint32)size);
    if (new_buckets == NULL) {
        LOG_DEBUG_ERR("Malloc failed");
        return ERR_ALLOC_MEMORY;
    }
    void **new_key = (void **)(new_buckets + new_capacity);
    void **new_value = (void **)(new_key + new_capacity);

    for (uint32 i = 0; i < new_capacity; i++) {
        new_buckets[i].state = (uint32)FREE;
        new_key[i] = NULL;
        new_value[i] = NULL;
    }
    oamap_rehash_core(map, new_capacity, new_buckets, &used);

    cm_free(map->buckets);
    map->buckets = new_buckets;
    map->key = new_key;
    map->value = new_value;
    map->num = new_capacity;
    map->deleted = 0;
    map->used = used;
    return CM_SUCCESS;
}

void cm_oamap_init_mem(cm_oamap_t *map)
{
    if (map == NULL) {
        LOG_DEBUG_ERR("Null pointer specified");
        return;
    }

    map->buckets = NULL;
    map->key = NULL;
    map->value = NULL;
    map->num = 0;
    map->used = 0;
    map->deleted = 0;
    map->compare_func = NULL;
}

int32 cm_oamap_init(
    cm_oamap_t *map, uint32 init_capacity, cm_oamap_compare_t compare_func /* , memory_context_t *mem_ctx */)
{
    uint64 size;
    uint32 i;
    if (map == NULL || compare_func == NULL) {
        LOG_DEBUG_ERR("Null pointer specified");
        return ERR_DSS_INVALID_PARAM;
    }
    // The max oamap
    map->num = oamap_get_near_prime(init_capacity);
    if (map->num >= MAX_OAMAP_BUCKET_NUM) {
        LOG_DEBUG_ERR("Invalid bucket num specified");
        return ERR_DSS_INVALID_PARAM;
    }
    map->used = 0;
    size = map->num * (uint32)(sizeof(cm_oamap_bucket_t) + sizeof(void *) + sizeof(void *));
    if (size >= CM_INVALID_ID32) {
        LOG_DEBUG_ERR("Invalid map size");
        return ERR_DSS_INVALID_PARAM;
    }
    map->compare_func = compare_func;
    map->buckets = (cm_oamap_bucket_t *)cm_malloc((uint32)size);
    if (map->buckets == NULL) {
        LOG_DEBUG_ERR("Malloc failed");
        return ERR_ALLOC_MEMORY;
    }
    map->key = (void **)(map->buckets + map->num);
    map->value = (void **)(map->key + map->num);

    for (i = 0; i < map->num; i++) {
        map->buckets[i].state = (uint32)FREE;
        map->key[i] = NULL;
        map->value[i] = NULL;
    }
    map->deleted = 0;
    return CM_SUCCESS;
}

void cm_oamap_destroy(cm_oamap_t *map)
{
    CM_ASSERT(map != NULL);
    map->num = 0;
    map->deleted = 0;
    map->used = 0;

    if (map->buckets != NULL) {
        cm_free(map->buckets);
        map->buckets = NULL;
    }

    map->compare_func = NULL;
}

static int32 cm_oamap_find_pos_forward(cm_oamap_t *map, uint32 hash, void *key, bool32 *found_pos, uint32 *insert_pos)
{
    cm_oamap_bucket_t *cm_oamap_bucket;
    uint32 start = hash % map->num;
    while (start > 0) {
        start--;
        cm_oamap_bucket = &(map->buckets[start]);
        if (cm_oamap_bucket->state == (uint32)FREE) {
            if (!(*found_pos)) {
                // find a new free pos to insert. so need to update the used counter
                map->used++;
                *found_pos = CM_TRUE;
                *insert_pos = start;
            }
            break;
        } else if (cm_oamap_bucket->state == (uint32)DELETED) {
            if (!(*found_pos)) {
                // find a deleted pos to reuse for insert. so need to update the deleted counter
                map->deleted--;
                *found_pos = CM_TRUE;
                *insert_pos = start;
            }
        } else {
            if (cm_oamap_bucket->hash == hash && map->compare_func(map->key[start], key) == CM_TRUE) {
                LOG_DEBUG_ERR("Duplicate key being inserted");
                return ERR_DSS_OAMAP_INSERT_DUP_KEY;
            }
        }
    }
    return CM_SUCCESS;
}

static int32 cm_oamap_insert_core(cm_oamap_t *map, uint32 hash, void *key, void *value)
{
    uint32 i;
    cm_oamap_bucket_t *cm_oamap_bucket;
    bool32 found_free = CM_FALSE;
    bool32 found_pos = CM_FALSE;
    uint32 insert_pos = 0;
    uint32 start = hash % map->num;
    for (i = start; i < map->num; i++) {
        cm_oamap_bucket = &(map->buckets[i]);
        if (cm_oamap_bucket->state == (uint32)FREE) {
            found_free = CM_TRUE;
            if (!found_pos) {
                // find a new free pos to insert. so need to update the used counter
                map->used++;
                found_pos = CM_TRUE;
                insert_pos = i;
            }
            break;
        } else if (cm_oamap_bucket->state == (uint32)DELETED) {
            if (!found_pos) {
                // find a deleted pos to reuse for insert. so need to udpate the deleted counter
                map->deleted--;
                found_pos = CM_TRUE;
                insert_pos = i;
            }
        } else {
            if (cm_oamap_bucket->hash == hash && map->compare_func(map->key[i], key)) {
                LOG_DEBUG_ERR("Duplicate key being inserted, i:%u, hash:%u", i, hash);
                return ERR_DSS_OAMAP_INSERT_DUP_KEY;
            }
        }
    }
    if (!found_free) {
        CM_RETURN_IFERR(cm_oamap_find_pos_forward(map, hash, key, &found_pos, &insert_pos));
    }

    if (found_pos) {
        cm_oamap_bucket = &(map->buckets[insert_pos]);
        cm_oamap_bucket->hash = hash;
        cm_oamap_bucket->state = (uint32)USED;
        map->key[insert_pos] = key;
        map->value[insert_pos] = value;
        return CM_SUCCESS;
    }
    LOG_DEBUG_ERR("Insertion failed");
    return ERR_DSS_OAMAP_INSERT;
}

int32 cm_oamap_insert(cm_oamap_t *map, uint32 hash, void *key, void *value)
{
    int32 ret;
    uint32 new_size;
    if (map == NULL) {
        LOG_DEBUG_ERR("Pointer to map is NULL");
        return ERR_DSS_INVALID_PARAM;
    }
    if ((map->used - map->deleted) * 3 > map->num * 2) {
        new_size = oamap_get_near_prime(map->num + 1);
        if (new_size > MAX_OAMAP_BUCKET_NUM) {
            LOG_DEBUG_ERR("Invalid bucket num specified");
            return ERR_DSS_INVALID_PARAM;
        }
        ret = oamap_rehash(map, new_size);
        if (ret != CM_SUCCESS) {
            LOG_DEBUG_ERR("OAMAP rehash failed,%d.", ret);
            return ret;
        }
    }
    hash = hash & HASH_MASK;
    return cm_oamap_insert_core(map, hash, key, value);
}

void *cm_oamap_lookup(cm_oamap_t *map, uint32 hash, void *key)
{
    uint32 i, start;
    cm_oamap_bucket_t *bucket;

    if (map == NULL) {
        LOG_DEBUG_ERR("Pointer to map is NULL");
        return NULL;
    }

    if (map->num == 0) {
        LOG_DEBUG_ERR("The map is not initialized.");
        return NULL;
    }

    hash = hash & HASH_MASK;
    start = hash % map->num;

    for (i = start; i < map->num; i++) {
        bucket = &(map->buckets[i]);
        if (bucket->state == (uint32)FREE) {
            return NULL;
        } else if (bucket->state == (uint32)USED) {
            if (bucket->hash == hash && map->compare_func(map->key[i], key) == CM_TRUE) {
                return map->value[i];
            }
        } else {
            // for lint
        }
    }

    while (start > 0) {
        start--;
        bucket = &(map->buckets[start]);
        if (bucket->state == (uint32)FREE) {
            return NULL;
        } else if (bucket->state == (uint32)USED) {
            if (bucket->hash == hash && map->compare_func(map->key[start], key) == CM_TRUE) {
                return map->value[start];
            }
        } else {
            // for lint
        }
    }
    return NULL;
}

void *cm_oamap_remove(cm_oamap_t *map, uint32 hash, void *key)
{
    uint32 i, start;
    cm_oamap_bucket_t *bucket;
    void *value = NULL;
    if (map == NULL) {
        LOG_DEBUG_ERR("Pointer to map is NULL");
        return NULL;
    }

    hash = hash & HASH_MASK;
    start = hash % map->num;
    for (i = start; i < map->num; i++) {
        bucket = &(map->buckets[i]);
        if (bucket->state == (uint32)FREE) {
            return NULL;
        } else if (bucket->state == (uint32)USED) {
            if (bucket->hash == hash && map->compare_func(map->key[i], key) == CM_TRUE) {
                bucket->hash = 0;
                bucket->state = (uint32)DELETED;
                map->deleted++;
                value = map->value[i];
                map->key[i] = NULL;
                map->value[i] = NULL;
                return value;
            }
        } else {
            // for lint
        }
    }

    while (start > 0) {
        start--;
        bucket = &(map->buckets[start]);
        if (bucket->state == (uint32)FREE) {
            return NULL;
        } else if (bucket->state == (uint32)USED) {
            if (bucket->hash == hash && map->compare_func(map->key[start], key) == CM_TRUE) {
                bucket->hash = 0;
                bucket->state = (uint32)DELETED;
                map->deleted++;
                value = map->value[start];
                map->key[start] = NULL;
                map->value[start] = NULL;
                return value;
            }
        } else {
            // for lint
        }
    }
    LOG_DEBUG_ERR("Key to remove not found");
    return value;
}

void cm_oamap_reset_iterator(cm_oamap_iterator_t *iter)
{
    CM_ASSERT(iter != NULL);
    *iter = 0;
}

int32 cm_oamap_fetch(cm_oamap_t *map, cm_oamap_iterator_t *iter, void **key, void **value)
{
    uint32 i;
    cm_oamap_bucket_t *bucket;

    CM_ASSERT(map != NULL);
    CM_ASSERT(iter != NULL);
    CM_ASSERT(key != NULL);
    CM_ASSERT(value != NULL);

    for (i = *iter; i < map->num; i++) {
        bucket = &(map->buckets[i]);
        if (bucket->state == (uint32)USED) {
            *key = map->key[i];
            *value = map->value[i];
            *iter = i + 1;
            return CM_SUCCESS;
        }
    }

    *key = NULL;
    *value = NULL;
    *iter = map->num;
    return ERR_DSS_OAMAP_FETCH;
}

uint32 cm_oamap_size(cm_oamap_t *map)
{
    CM_ASSERT(map != NULL);
    return map->num;
}

#ifdef __cplusplus
}
#endif /* __cplusplus */
