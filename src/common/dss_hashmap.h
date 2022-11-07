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
 * dss_hashmap.h
 *
 *
 * IDENTIFICATION
 *    src/common/dss_hashmap.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __DSS_HASHMAP_H__
#define __DSS_HASHMAP_H__

#include "cm_types.h"
#include "cm_text.h"

#ifdef __cplusplus
extern "C" {
#endif

// should not too big.it will allow to insert max node in oa map is MAX_OAMAP_NUM
#define MAX_OAMAP_BUCKET_NUM (1024 * 1024 * 2)
typedef uint32 (*cm_oamap_hash_t)(void *key);
typedef bool32 (*cm_oamap_compare_t)(void *key1, void *key2);
typedef uint32 cm_oamap_iterator_t;

typedef enum tag_cm_oamap_bucket_state {
    FREE,
    USED,
    DELETED,
} cm_oamap_bucket_state_e;

// open address map is use for small numbers of key map
typedef struct tag_cm_oamap_bucket {
    uint32 hash : 30;
    uint32 state : 2;
} cm_oamap_bucket_t;

typedef struct tag_cm_oamap {
    cm_oamap_bucket_t *buckets;
    void **key;
    void **value;
    uint32 num;
    uint32 used;
    uint32 deleted;
    cm_oamap_compare_t compare_func;
} cm_oamap_t;

// mem_ctx == NULL will use the standard malloc and free
void cm_oamap_init_mem(cm_oamap_t *map);

int32 cm_oamap_init(
    cm_oamap_t *map, uint32 init_capacity, cm_oamap_compare_t compare_func /* , memory_context_t *mem_ctx */);

void cm_oamap_destroy(cm_oamap_t *map);

int32 cm_oamap_insert(cm_oamap_t *map, uint32 hash, void *key, void *value);

void *cm_oamap_lookup(cm_oamap_t *map, uint32 hash, void *key);

void *cm_oamap_remove(cm_oamap_t *map, uint32 hash, void *key);

void cm_oamap_reset_iterator(cm_oamap_iterator_t *iter);

int32 cm_oamap_fetch(cm_oamap_t *map, cm_oamap_iterator_t *iter, void **key, void **value);

bool32 cm_oamap_ptr_compare(void *key1, void *key2);

bool32 cm_oamap_uint64_compare(void *key1, void *key2);

bool32 cm_oamap_uint32_compare(void *key1, void *key2);

bool32 cm_oamap_string_compare(void *key1, void *key2);

uint32 cm_oamap_size(cm_oamap_t *map);

uint32 cm_hash_uint32_shard(uint32 val);
uint32 cm_hash_int64(int64 i64);
uint32 cm_hash_text(const text_t *text, uint32 range);
uint32 cm_hash_string(const char *str, uint32 range);

#ifdef __cplusplus
}
#endif

#endif /* __DSS_HASHMAP_H__ */
