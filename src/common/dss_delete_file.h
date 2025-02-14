/*
 * Copyright (c) 2025 Huawei Technologies Co.,Ltd.
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
 * dss_delete_file.h
 *
 *
 * IDENTIFICATION
 *    src/common/dss_delete_file.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __DSS_DELETE_FILE_H__
#define __DSS_DELETE_FILE_H__

#include "cm_stack.h"
#include "dss_diskgroup.h"
#include "dss_file_def.h"
#include "dss_malloc.h"
#include "dss_session.h"

#define DSS_MAX_DELETE_DEPTH ((DSS_FILE_PATH_MAX_LENGTH - 1) / 2)
#define DSS_LOCK_TIMEOUT_FOR_DELETE 50
typedef struct st_dss_delete_queue_t {
    ftid_t items[DSS_MAX_DELETE_DEPTH];
    uint32 front;
    uint32 rear;
} dss_delete_queue_t;

static inline void dss_init_delete_queue(dss_delete_queue_t *queue)
{
    queue->front = DSS_INVALID_ID32;
    queue->rear = DSS_INVALID_ID32;
}

static inline bool8 dss_delete_queue_is_empty(dss_delete_queue_t *queue)
{
    return queue->front == DSS_INVALID_ID32;
}

static inline bool8 dss_delete_queue_is_full(dss_delete_queue_t *queue)
{
    return queue->rear - queue->front == DSS_MAX_DELETE_DEPTH;
}

typedef struct st_dss_search_node_t {
    ftid_t ftid;
    bool8 path_isvisited;
    char reserve[7];
} dss_search_node_t;

static inline uint32 dss_get_search_stack_size()
{
    return sizeof(cm_stack_t) + CM_ALIGN8(sizeof(dss_search_node_t) * DSS_MAX_DELETE_DEPTH) + GS_PUSH_RESERVE_SIZE;
}

static inline bool8 dss_search_stack_is_empty(cm_stack_t *stack)
{
    return (stack->push_offset == stack->size && stack->heap_offset == 0);
}

static inline dss_search_node_t *dss_top_search_stack(cm_stack_t *stack)
{
    if (dss_search_stack_is_empty(stack)) {
        LOG_DEBUG_INF("search stack is empty.");
        return NULL;
    }
    return (dss_search_node_t *)(stack->buf + stack->push_offset + GS_PUSH_RESERVE_SIZE);
}

static inline void dss_pop_search_stack(cm_stack_t *stack)
{
    cm_pop(stack);
}

static inline bool8 dss_is_master_and_open()
{
    return (dss_need_exec_local() && dss_is_readwrite() && get_instance_status_proc() == DSS_STATUS_OPEN);
}
void dss_delay_clean_all_vg(dss_session_t *session, cm_stack_t *stack, dss_delete_queue_t *queue);
#endif
