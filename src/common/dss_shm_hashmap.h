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
 * dss_shm_hashmap.h
 *
 *
 * IDENTIFICATION
 *    src/common/dss_shm_hashmap.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __DSS_SHM_HASHMAP_H_
#define __DSS_SHM_HASHMAP_H_

#include "cm_defs.h"
#include "cm_types.h"
#include "dss_hashmap.h"
#include "dss_shm.h"
#include "cm_latch.h"
#include "dss_latch.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DSS_MAX_SEGMENT_NUM (1024)
#define DSS_MAX_BUCKET_NUM (2097152)
#ifdef ENABLE_DSSTEST
#define DSS_INIT_BUCKET_NUM (2048)
#else
#define DSS_INIT_BUCKET_NUM (32768)
#endif

#define DSS_BUCKETS_PER_SEGMENT (DSS_MAX_BUCKET_NUM / DSS_MAX_SEGMENT_NUM)
#define DSS_BUCKETS_SIZE_PER_SEGMENT (DSS_BUCKETS_PER_SEGMENT * sizeof(shm_hashmap_bucket_t))
#define DSS_EXTEND_BATCH (128)
#define DSS_HASH_FILL_FACTOR ((float)0.75)
typedef struct st_shm_oamap_bucket {
    uint32 hash : 30;
    uint32 state : 2;
} shm_oamap_bucket_t;

typedef struct st_shm_oamap {
    sh_mem_p buckets_offset; /* ptr offset */
    sh_mem_p key_offset;     /* ptr offset */
    sh_mem_p value_offset;   /* ptr offset */
    uint32 num;
    uint32 used;
    uint32 deleted;
    uint32 not_extend : 1;
    uint32 shm_id : 31;
    uint64 reserve;
} shm_oamap_t;

typedef struct st_shm_hashmap_bucket {
    dss_shared_latch_t enque_lock;
    sh_mem_p first;
    bool32 has_next;
    uint32 entry_num;
} shm_hashmap_bucket_t;

typedef shm_hashmap_bucket_t *shm_hashmap_segment;
typedef struct st_shm_hash_ctrl {
    sh_mem_p dirs;
    uint32 bucket_limits;
    uint32 bucket_num;
    uint32 max_bucket;
    uint32 low_mask;
    uint32 high_mask;
    uint32 nsegments;
    cm_oamap_compare_t func;
} shm_hash_ctrl_t;
typedef struct st_shm_hashmap {
    shm_hash_ctrl_t hash_ctrl;
    uint32 not_extend : 1;
    uint32 shm_id : 31;
} shm_hashmap_t;

typedef struct st_shm_oamap_param {
    uint32 hash;
    shm_oamap_t *map;
    void *key_acl;
    cm_oamap_compare_t compare_func;
} shm_oamap_param_t;

int32 shm_hashmap_init(shm_hashmap_t *map, uint32 id, cm_oamap_compare_t compare_func);
void shm_hashmap_destroy(shm_hashmap_t *map, uint32 id);
shm_hashmap_bucket_t *shm_hashmap_get_bucket(shm_hash_ctrl_t *hash_ctrl, uint32 bucket_idx, uint32 *segment_objid);
status_t shm_hashmap_extend_segment(shm_hash_ctrl_t *hash_ctrl);
bool32 shm_hashmap_need_extend_and_redistribute(shm_hash_ctrl_t *hash_ctrl);
uint32 shm_hashmap_calc_bucket_idx(shm_hash_ctrl_t *hash_ctrl, uint32 hash);

#define SHM_HASH_BUCKET_INSERT(bucket, item, item_ctrl, first_ctrl) \
    do {                                                            \
        if ((bucket)->has_next) {                                   \
            (item_ctrl)->hash_next = (bucket)->first;               \
            (item_ctrl)->has_next = CM_TRUE;                        \
            (first_ctrl)->hash_prev = (item);                       \
            (first_ctrl)->has_prev = CM_TRUE;                       \
        } else {                                                    \
            (bucket)->has_next = CM_TRUE;                           \
        }                                                           \
        (bucket)->first = (item);                                   \
        (bucket)->entry_num++;                                      \
    } while (0)

#define SHM_HASH_BUCKET_REMOVE(bucket, item, item_ctrl, prev_ctrl, next_ctrl) \
    do {                                                                      \
        if ((prev_ctrl) != NULL) {                                            \
            (prev_ctrl)->hash_next = (item_ctrl)->hash_next;                  \
            (prev_ctrl)->has_next = (item_ctrl)->has_next;                    \
        }                                                                     \
        if ((next_ctrl) != NULL) {                                            \
            (next_ctrl)->hash_prev = (item_ctrl)->hash_prev;                  \
            (next_ctrl)->has_prev = (item_ctrl)->has_prev;                    \
        }                                                                     \
        if ((item) == (bucket)->first) {                                      \
            (bucket)->first = (item_ctrl)->hash_next;                         \
            (bucket)->has_next = (item_ctrl)->has_next;                       \
        }                                                                     \
        (item_ctrl)->has_next = CM_FALSE;                                     \
        (item_ctrl)->has_prev = CM_FALSE;                                     \
        (bucket)->entry_num--;                                                \
    } while (0)

#ifdef __cplusplus
}
#endif

#endif /* _CM_SHM_HASHMAP_H_ */
