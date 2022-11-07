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
 * dss_skiplist.h
 *
 *
 * IDENTIFICATION
 *    src/common/dss_skiplist.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __DSS_SKIP_LIST_H__
#define __DSS_SKIP_LIST_H__

#include "cm_atomic.h"
#include "dss_skiplist_mem.h"

#ifdef __cplusplus
extern "C" {
#endif

/* the skiplist struct implement here original reference REDIS's implement. But Do some enhancement on:
    1.thread safe for multi thread when insert/delete/find
    2.user defined compare function for more case
    3.memory management
    4.lazy clean and range scan optimize
    5.remove span of node
*/
#define SKIP_LIST_MAX_LEVEL 32

#define SKIP_LIST_FOUND 0

#define SKLIST_FETCH_END 1

typedef int32 (*sklist_key_cmp_func)(void *arg, void *left, void *right);
typedef int32 (*sklist_value_cmp_func)(void *left, void *right);
typedef void (*sklist_free_func)(void *arg, void *key);
typedef int32 (*sklist_value_get_func)(void *arg, void *data_buf, uint16 buf_len, void **out_data);

#define STATUS_IDLE 0
#define STATUS_DELETED 0x01000000
#define STATUS_CLEANING 0x02000000
#define STATUS_WAIT 0x04000000

// was typedef volatile uint32 reference; "reference" is too common and caused 20 pclint warnings!
#define sklist_ref_t atomic32_t

typedef struct tagskip_list_node {
    void *value;
    void *key;
    struct tagskip_list_node *backward;
    volatile uint32 ver;
    sklist_ref_t ref;
    struct skip_level {
        struct tagskip_list_node *forward;
    } level[1];
} skip_list_node_t;

typedef struct tagskip_list_usage {
    uint64 memory;
    uint64 insert_ok;
    uint64 delete_ok;
    uint64 clean_pending;
    uint64 find_ok;
    uint64 insert_retry;
    uint64 delete_retry;
    uint64 lazy_clean;
    uint64 insert_nok;
    uint64 delete_nok;
    uint64 find_nok;
    uint32 node_num;
    uint32 level_node_num[SKIP_LIST_MAX_LEVEL];
} skip_list_usage_t;

typedef struct tagskip_list_callback {
    sklist_key_cmp_func key_cmp_func;
    sklist_value_cmp_func value_cmp_func;
    sklist_free_func key_free_func;
    sklist_free_func value_free_func;
    sklist_value_get_func value_get_func;
    void *callback_func_arg;
} skip_list_callback_t;

typedef struct tagskip_list {
    latch_t lock;
    skip_list_node_t *head;
    skip_list_node_t *tail;
    uint32 length;
    int32 level;
    skip_list_usage_t usage;
    mem_ctx_t mem;
    skip_list_callback_t callback;
} skip_list_t;

typedef struct tagskip_list_range {
    bool32 is_left_include;
    bool32 is_right_include;
    void *left_key;
    void *left_value;
    void *right_key;
    void *right_value;
} skip_list_range_t;

typedef struct tagskip_list_iterator {
    skip_list_node_t *node;
    bool32 is_include;
    skip_list_range_t cond;
    skip_list_t *list;
} skip_list_iterator_t;

void sklist_lazy_clean(skip_list_t *list, skip_list_node_t *node);

uint32 sklist_init(skip_list_t *list, skip_list_callback_t *callback);

void sklist_destroy(skip_list_t *list);

uint32 sklist_insert(skip_list_t *list, void *key, void *value);

uint32 sklist_delete(skip_list_t *list, void *key, void *value);

int32 sklist_get_value(
    skip_list_t *list, void *key, bool32 match_value, void *value, uint16 value_len, void **out_data);

void sklist_create_iterator(skip_list_t *list, skip_list_range_t *range, skip_list_iterator_t *itr);

int32 sklist_fetch_next(skip_list_iterator_t *itr, void **key, void *value, uint16 value_len);

void sklist_close_iterator(skip_list_iterator_t *itr);

#ifdef __cplusplus
}
#endif

#endif
