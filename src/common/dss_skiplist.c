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
 * dss_skiplist.c
 *
 *
 * IDENTIFICATION
 *    src/common/dss_skiplist.c
 *
 * -------------------------------------------------------------------------
 */

#include "cm_atomic.h"
#include "cm_debug.h"
#include "dss_errno.h"
#include "dss_latch.h"
#include "dss_skiplist.h"

#define PARITY_CHECK 2

static inline sklist_ref_t sklist_cmp_xchg(sklist_ref_t *volatile val, sklist_ref_t oldval, sklist_ref_t newval)
{
    CM_ASSERT(val != NULL);

    sklist_ref_t ret_val = 0;

#ifdef WIN32
    sklist_ref_t *addr = (sklist_ref_t *)val;
    sklist_ref_t compareval = oldval;
    sklist_ref_t value = newval;
    ret_val = InterlockedCompareExchange(val, newval, oldval);

#elif defined(__linux)
    ret_val = __sync_val_compare_and_swap(val, oldval, newval);
#else
    ret_val = *val;
#endif
    return ret_val;
}
/* try to increase the reference if it is not CLEANING */
static inline void try_inc_reference(sklist_ref_t *volatile ref)
{
    CM_ASSERT(ref != NULL);
    (void)cm_atomic32_inc(ref);
}

/* try to dec the reference */
static inline void try_dec_reference(sklist_ref_t *volatile ref)
{
    CM_ASSERT(ref != NULL);
    cm_atomic32_dec(ref);
}

static inline void try_clear_flag(sklist_ref_t *volatile ref, sklist_ref_t mask)
{
    CM_ASSERT(ref != NULL);

    sklist_ref_t new_val, old_val, ret_val;
    for (;;) {
        old_val = *ref;
        new_val = old_val & (~mask);
        ret_val = sklist_cmp_xchg(ref, old_val, new_val);
        if (old_val == ret_val) {
            return;
        }
    }
}

static inline void try_set_flag(sklist_ref_t *volatile ref, sklist_ref_t mask)
{
    CM_ASSERT(ref != NULL);

    sklist_ref_t new_val, old_val, ret_val;
    for (;;) {
        old_val = *ref;
        new_val = old_val | mask;
        ret_val = sklist_cmp_xchg(ref, old_val, new_val);
        if (old_val == ret_val) {
            return;
        }
    }
}

static skip_list_node_t *sklist_create_node(skip_list_t *list, int *level, void *key, void *value)
{
    CM_ASSERT(list != NULL);
    CM_ASSERT(level != NULL);
    skip_list_node_t *node;
    int32 new_level;
    uint16 size = (uint16)(sizeof(skip_list_node_t) + (uint16)(*level - 1) * sizeof(struct skip_level));
    uint16 actual_size;
    uint32 ret = sklist_mem_alloc(&list->mem, size, (void **)&node);
    if (ret != CM_SUCCESS) {
        return NULL;
    }
    actual_size = sklist_mem_size(node);
    if ((actual_size - sizeof(skip_list_node_t)) % sizeof(struct skip_level) != 0) {
        return NULL;
    }

    new_level = (int32)((actual_size - sizeof(skip_list_node_t)) / sizeof(struct skip_level)) + 1;
    *level = new_level;
    node->key = key;
    node->value = value;
    node->ref = 0;
    return node;
}

static uint32 sklist_get_link_node(skip_list_t *list, skip_list_node_t *node, skip_list_node_t **update)
{
    if (!list || !node) {
        return ERR_DSS_SKLIST_ERR;
    }
    CM_ASSERT(update != NULL);

    skip_list_node_t *cur;
    int32 cmp = 1;
    if (list->head == NULL) {
        return ERR_DSS_SKLIST_NOT_INIT;
    }
    cur = list->head;

    for (int32 i = list->level - 1; i >= 0; i--) {
        while (cur->level[i].forward) {
            cmp = list->callback.key_cmp_func(list->callback.callback_func_arg, cur->level[i].forward->key, node->key);
            if (cmp > 0) {  // (cur->level[i].forward->key > key)
                break;
            }
            if (cmp < 0) {
                cur = cur->level[i].forward;
                continue;
            }
            // was trying to get the node by (cur->level[i].forward == node), but when keys are all the same, cur
            // will run to the tail.
            cmp = list->callback.value_cmp_func(cur->level[i].forward->value, node->value);
            if (cmp < 0) {
                cur = cur->level[i].forward;
                continue;
            }
            if (cmp == 0 && cur->level[i].forward != node) {
                LOG_DEBUG_ERR("[Skip list] Node address mismatch");
                return ERR_DSS_SKLIST_NOT_EXIST;
            }
            break;
        }
        update[i] = cur;
    }
    return CM_SUCCESS;
}

static void skilist_free_key_and_value(skip_list_t *list, skip_list_node_t *node)
{
    CM_ASSERT(list != NULL);
    CM_ASSERT(node != NULL);

    if (list->callback.key_free_func) {
        list->callback.key_free_func(list->callback.callback_func_arg, node->key);
    }
    if (list->callback.value_free_func) {
        list->callback.value_free_func(list->callback.callback_func_arg, node->value);
    }
}

static void sklist_delete_node(skip_list_t *list, skip_list_node_t **update, skip_list_node_t *delete_node)
{
    CM_ASSERT(list != NULL);
    CM_ASSERT(update != NULL);
    CM_ASSERT(delete_node != NULL);

    uint32 level = 0;
    if ((delete_node->ref & 0x00ffffff) != 0) {
        /* some one still refer the node. set the status to deleted. we just return here */
        try_set_flag(&delete_node->ref, STATUS_DELETED);
        list->usage.clean_pending++;
        return;
    }
    // do the really remove node from the list
    for (int32 i = 0; i < list->level; i++) {
        if (update[i]->level[i].forward == delete_node) {
            /* the update node point to the delete node */
            update[i]->level[i].forward = delete_node->level[i].forward;
            // change the version of node
            update[i]->ver++;

            level++;
        } else {
            /* the update node cross the delete node */
        }
    }
    if (delete_node->level[0].forward) {
        /* if the delete node is not in the tail */
        delete_node->level[0].forward->backward = delete_node->backward;
        // change the version of node
        delete_node->level[0].forward->ver++;
    } else {
        /* update the tail */
        list->tail = delete_node->backward;
    }
    /* try to reduce the level of the skip list */
    while (list->level > 1 && list->head->level[list->level - 1].forward == NULL) {
        list->level--;
    }
    list->length--;
    skilist_free_key_and_value(list, delete_node);
    sklist_mem_free(delete_node);
    /* TBD: do we need judge here */
    if (level == 0) {
        LOG_DEBUG_ERR("[Skip list] Freed a node without updating list.");
        return;
    }
    list->usage.memory -= ((uint32)sizeof(skip_list_node_t) + (level - 1) * (uint32)sizeof(struct skip_level));
    list->usage.node_num--;
    list->usage.level_node_num[level - 1]--;
    list->usage.delete_ok++;
}

void sklist_lazy_clean(skip_list_t *list, skip_list_node_t *node)
{
    CM_ASSERT(list != NULL);

    uint32 ret;
    skip_list_node_t *update[SKIP_LIST_MAX_LEVEL];
    ret = sklist_get_link_node(list, node, update);
    if (ret == CM_SUCCESS) {
        list->usage.lazy_clean++;
        sklist_delete_node(list, update, node);
    }
}

static inline void sklist_try_lazy_clean(skip_list_t *list, skip_list_node_t *node)
{
    CM_ASSERT(list != NULL);
    CM_ASSERT(node != NULL);

    if (node->ref == STATUS_DELETED) {
        sklist_lazy_clean(list, node);
    }
}

static int sklist_get_rand_level(void)
{
    int32 level = 1;
    while (rand() % PARITY_CHECK) {
        level += 1;
    }
    return (level < SKIP_LIST_MAX_LEVEL) ? level : SKIP_LIST_MAX_LEVEL;
}

uint32 sklist_init(skip_list_t *list, skip_list_callback_t *callback)
{
    CM_ASSERT(list != NULL);
    CM_ASSERT(callback != NULL);

    if (memset_s(&list->lock, sizeof(latch_t), 0, sizeof(latch_t)) != EOK) {
        cm_panic(0);
    }
    list->length = 0;
    list->level = 1;
    list->tail = NULL;
    uint32 ret = sklist_mem_init(&list->mem);
    if (ret != CM_SUCCESS) {
        return ret;
    }
    int32 level = SKIP_LIST_MAX_LEVEL;
    list->head = sklist_create_node(list, &level, 0, NULL);
    if (list->head == NULL || level != SKIP_LIST_MAX_LEVEL) {
        return ERR_ALLOC_MEMORY;
    }

    if (memset_s(&list->usage, sizeof(skip_list_usage_t), 0, sizeof(skip_list_usage_t)) != EOK) {
        cm_panic(0);
    }
    list->usage.memory = (uint32)(
        sizeof(skip_list_t) + sizeof(skip_list_node_t) + (SKIP_LIST_MAX_LEVEL - 1) * sizeof(struct skip_level));

    for (int32 i = 0; i < SKIP_LIST_MAX_LEVEL; i++) {
        list->head->level[i].forward = NULL;
    }
    list->head->backward = NULL;

    list->callback.callback_func_arg = callback->callback_func_arg;
    list->callback.key_cmp_func = callback->key_cmp_func;
    list->callback.value_cmp_func = callback->value_cmp_func;
    list->callback.key_free_func = callback->key_free_func;
    list->callback.value_get_func = callback->value_get_func;
    list->callback.value_free_func = callback->value_free_func;

    return CM_SUCCESS;
}

void sklist_destroy(skip_list_t *list)
{
    CM_ASSERT(list != NULL);

    dss_latch_x(&list->lock);
    skip_list_node_t *node, *next;
    if (list->head == NULL) {
        dss_unlatch(&list->lock);
        return;
    }
    node = list->head->level[0].forward;
    // NOTICE, resource will be recycle in function 'lidx_del' in dn_localindex.c
    sklist_mem_free(list->head);
    list->head = NULL;
    while (node) {
        next = node->level[0].forward;
        sklist_mem_free(node);
        node = next;
    }
    if (memset_s(&list->usage, sizeof(skip_list_usage_t), 0, sizeof(skip_list_usage_t)) != EOK) {
        cm_panic(0);
    }
    list->usage.memory = (uint64)sizeof(skip_list_t);
    list->length = 0;
    list->level = 0;
    dss_unlatch(&list->lock);
}

static void sklist_create_node_fail(skip_list_t *list, int32 save_level, skip_list_node_t **update)
{
    // check if need to do lazy clean
    int32 loop = save_level - 1;
    sklist_try_lazy_clean(list, update[loop]);
    loop--;
    for (; loop >= 0; loop--) {
        if (update[loop] != update[(int32)(loop + 1)]) {
            sklist_try_lazy_clean(list, update[loop]);
        }
    }
}

static uint32 sklist_update_insert_info(
    skip_list_t *list, skip_list_node_t *cur, int32 save_level, int32 level, skip_list_node_t **update)
{
    if (level > list->level) {
        /* init the new level of the skiplist. */
        for (int32 i = list->level; i < level; i++) {
            update[i] = list->head;
        }
        list->level = level;
    }
    list->usage.memory += (uint32)(sizeof(skip_list_node_t) + (uint16)(level - 1) * sizeof(struct skip_level));
    list->usage.node_num++;
    list->usage.level_node_num[level - 1]++;
    for (int32 i = 0; i < level; i++) {
        if (!(GET_BLOCK_HEADER(cur)->next == (void *)0x12345678)) {
            return ERR_DSS_SKLIST_ERR;
        }
        /* update each level's point who point to the new node */
        cur->level[i].forward = update[i]->level[i].forward;
        update[i]->level[i].forward = cur;
        // change the version of node
        update[i]->ver++;
    }

    cur->backward = (update[0] == list->head) ? NULL : update[0];
    if (cur->level[0].forward) {
        cur->level[0].forward->backward = cur;
        // change the version of node
        cur->level[0].forward->ver++;
    } else {
        list->tail = cur;
    }
    list->length++;
    list->usage.insert_ok++;
    // check if need to do lazy clean
    sklist_create_node_fail(list, save_level, update);
    return CM_SUCCESS;
}

static uint32 sklist_insert_same_value(
    skip_list_t *list, int32 save_level, int32 begin, skip_list_node_t *cur, skip_list_node_t **update)
{
    for (int32 loop = save_level - 1; loop > begin; loop--) {
        try_dec_reference(&update[loop]->ref);
    }
    skip_list_node_t *forward = cur->level[begin].forward;
    uint32 mask = STATUS_DELETED | STATUS_CLEANING;
    if (forward->ref & mask) {
        try_clear_flag(&forward->ref, (sklist_ref_t)mask);
        return CM_SUCCESS;
    }
    list->usage.insert_nok++;
    return ERR_DSS_SKLIST_EXIST;
}

static void sklist_insert_update_retry_info(
    skip_list_t *list, int32 save_level, int32 *retry, skip_list_node_t **update, uint32 *ver)
{
    // we need to make sure the node we record do not change
    for (int32 loop = list->level - 1; loop >= 0; loop--) {
        try_dec_reference(&update[loop]->ref);
        if (ver[loop] != update[loop]->ver) {
            *retry = 1;
        }
    }
    // if related nodes version changed or level of list changed. Need to retry the scan again
    if (*retry == 1 || save_level != list->level) {
        // change in between. need to restart the scan
        *retry = 1;
        list->usage.insert_retry++;
    }
}

uint32 sklist_insert(skip_list_t *list, void *key, void *value)
{
    skip_list_node_t *update[SKIP_LIST_MAX_LEVEL] = {NULL};
    uint32 ver[SKIP_LIST_MAX_LEVEL] = {0};
    skip_list_node_t *cur;
    int32 level;
    int32 cmp = 1;
    int32 retry = 0;
    int32 save_level;
    if (!list || !value) {
        return ERR_DSS_SKLIST_ERR;
    }
    dss_latch_s(&list->lock);
    for (;;) {
        if (list->head == NULL) {
            dss_unlatch(&list->lock);
            return ERR_DSS_SKLIST_NOT_INIT;
        }
        cur = list->head;
        save_level = list->level;
        for (int32 i = list->level - 1; i >= 0; i--) {
            while (cur->level[i].forward) {
                if (!(GET_BLOCK_HEADER(cur)->next == (void *)0x12345678)) {
                    dss_unlatch(&list->lock);
                    return ERR_DSS_SKLIST_ERR;
                }
                cmp = list->callback.key_cmp_func(list->callback.callback_func_arg, cur->level[i].forward->key, key);
                if (cmp > 0) {  // (cur->level[i].forward->key > key)
                    break;
                } else if (cmp < 0) {
                    cur = cur->level[i].forward;
                    continue;
                }
                // (cur->level[i].forward->key == key && cur->level[i].forward->value == value)
                /* We may have multiple elements with the same key, what we need
                 * is to find the element with both the right key and object. */
                cmp = list->callback.value_cmp_func(cur->level[i].forward->value, value);
                if (cmp > 0) {
                    break;
                } else if (cmp < 0) {
                    cur = cur->level[i].forward;
                    continue;
                }
                // to release the ref count which add previously
                uint32 ret = sklist_insert_same_value(list, save_level, i, cur, update);
                dss_unlatch(&list->lock);
                return ret;
            }
            update[i] = cur;
            ver[i] = cur->ver;
            // increase the ref count to make sure it will not remove in between
            try_inc_reference(&cur->ref);
        }
        level = sklist_get_rand_level();
        if (retry == 0) {
            // switch the lock to exclusive to protect the following critical change
            dss_unlatch(&list->lock);
            dss_latch_x(&list->lock);
            sklist_insert_update_retry_info(list, save_level, &retry, update, ver);
            if (retry == 1) {
                continue;
            }
        }
        // create node and update list info
        cur = sklist_create_node(list, &level, key, value);
        if (cur == NULL) {
            list->usage.insert_nok++;
            sklist_create_node_fail(list, save_level, update);
            dss_unlatch(&list->lock);
            return ERR_ALLOC_MEMORY;
        }
        uint32 ret = sklist_update_insert_info(list, cur, save_level, level, update);
        dss_unlatch(&list->lock);
        return ret;
    }
}

bool32 sklist_retry(skip_list_t *list, skip_list_node_t **update, uint32 *ver, int32 *retry)
{
    int32 save_level = list->level;
    if (*retry == 0) {
        // switch the lock to exclusive to protect the following critical change
        dss_unlatch(&list->lock);
        dss_latch_x(&list->lock);
        // we need to make sure the node we record do not change
        for (int32 loop = save_level - 1; loop >= 0; loop--) {
            try_dec_reference(&update[loop]->ref);
            if (ver[loop] != update[loop]->ver) {
                *retry = 1;
            }
        }
        // if related nodes version changed or level of list changed. Need to retry the scan again
        if (*retry == 1 || save_level != list->level) {
            *retry = 1;
            // change in between. need to restart the scan
            list->usage.delete_retry++;
            return CM_TRUE;
        }
    }
    return CM_FALSE;
}

uint32 sklist_delete(skip_list_t *list, void *key, void *value)
{
    if (!list || !value) {
        return ERR_DSS_SKLIST_ERR;
    }
    skip_list_node_t *update[SKIP_LIST_MAX_LEVEL] = {NULL};
    uint32 ver[SKIP_LIST_MAX_LEVEL] = {0};
    skip_list_node_t *cur;
    int32 cmp = 1;
    int32 retry = 0;
    int32 loop;
    dss_latch_s(&list->lock);
    for (;;) {
        if (list->head == NULL) {
            dss_unlatch(&list->lock);
            return ERR_DSS_SKLIST_NOT_INIT;
        }
        cur = list->head;
        for (int32 i = list->level - 1; i >= 0; i--) {
            while (cur->level[i].forward) {
                cmp = list->callback.key_cmp_func(list->callback.callback_func_arg, cur->level[i].forward->key, key);
                if (cmp > 0) {  // (cur->level[i].forward->key > key)
                    break;
                }
                if (cmp == 0) {  // (cur->level[i].forward->key == key && cur->level[i].forward->value == value)
                    /* We may have multiple elements with the same key, what we need
                     * is to find the element with both the right key and object. */
                    cmp = list->callback.value_cmp_func(cur->level[i].forward->value, value);
                    if (cmp >= 0) {
                        break;
                    }
                }
                cur = cur->level[i].forward;
            }
            update[i] = cur;
            ver[i] = cur->ver;
            // increase the ref count to make sure it will not remove in between
            try_inc_reference(&cur->ref);
        }
        cur = cur->level[0].forward;
        if (cur == NULL || (cmp != 0) || ((cur->ref & STATUS_DELETED) != 0)) {
            list->usage.delete_nok++;
            for (loop = list->level - 1; loop >= 0; loop--) {
                try_dec_reference(&update[loop]->ref);
            }
            dss_unlatch(&list->lock);
            return ERR_DSS_SKLIST_NOT_EXIST;
        }
        if (sklist_retry(list, update, ver, &retry)) {
            continue;
        }
        sklist_delete_node(list, update, cur);
        dss_unlatch(&list->lock);
        return CM_SUCCESS;
    }
}

int32 sklist_get_value(skip_list_t *list, void *key, bool32 match_value, void *value, uint16 value_len, void **out_data)
{
    int32 ret;
    skip_list_node_t *cur;
    int32 cmp = 1;
    if (!list) {
        return ERR_DSS_SKLIST_ERR;
    }
    dss_latch_s(&list->lock);
    if (list->head == NULL) {
        dss_unlatch(&list->lock);
        return ERR_DSS_SKLIST_NOT_INIT;
    }
    cur = list->head;

    for (int32 i = list->level - 1; i >= 0; i--) {
        while (cur->level[i].forward) {
            cmp = list->callback.key_cmp_func(list->callback.callback_func_arg, cur->level[i].forward->key, key);
            if (cmp < 0) {
                cur = cur->level[i].forward;
                continue;
            }
            if (cmp > 0) {  // (cur->level[i].forward->key > key)
                break;
            }
            // (cur->level[i].forward->key == key && cur->level[i].forward->value == value)
            /* We may have multiple elements with the same key, what we need
             * is to find the element with both the right key and object. */
            if (cur->level[i].forward->ref & STATUS_DELETED) {
                cur = cur->level[i].forward;
                continue;
            }

            if (match_value != CM_TRUE) {
                cmp = 0;
            } else {
                cmp = list->callback.value_cmp_func(cur->level[i].forward->value, value);
            }

            if (cmp > 0) {
                break;
            }
            if (cmp == 0) {
                ret = list->callback.value_get_func(cur->level[i].forward->value, value, value_len, out_data);
                list->usage.find_ok++;
                dss_unlatch(&list->lock);
                return ret;
            }
            cur = cur->level[i].forward;
        }
    }
    list->usage.find_nok++;
    dss_unlatch(&list->lock);
    return ERR_DSS_SKLIST_NOT_EXIST;
}

/* find the biggest node which match < itr->next_key&itr->next_value.
The return value is the compare result of the return node's next node and the input key& value */
static int32 sklist_get_node(skip_list_t *list, void *key, void *value, skip_list_node_t **node)
{
    CM_ASSERT(list != NULL);
    CM_ASSERT(node != NULL);

    skip_list_node_t *cur;
    int32 cmp = 1;
    cur = list->head;
    int32 i;
    for (i = list->level - 1; i >= 0 && cmp != 0; i--) {
        while (cur->level[i].forward) {
            cmp = list->callback.key_cmp_func(list->callback.callback_func_arg, cur->level[i].forward->key, key);
            if (cmp < 0) {
                cur = cur->level[i].forward;
                continue;
            }
            if (cmp > 0) {  // (cur->level[i].forward->key > key)
                break;
            }
            /* We may have multiple elements with the same key, what we need
             * is to find the element with both the right key and object. */
            if (value == NULL) {
                cmp = 1;
                break;
            }
            cmp = list->callback.value_cmp_func(cur->level[i].forward->value, value);
            if (cmp == 0) {
                break;
            }
            cur = cur->level[i].forward;
        }
    }

    while (cur->level[0].forward) {
        cmp = list->callback.key_cmp_func(list->callback.callback_func_arg, cur->level[0].forward->key, key);
        if (cmp >= 0) {
            break;
        }
        cur = cur->level[0].forward;
    }
    *node = cur;
    return cmp;
}

void sklist_create_iterator_with_left_key(skip_list_t *list, skip_list_range_t *range, skip_list_iterator_t *itr)
{
    int32 cmp;
    cmp = sklist_get_node(itr->list, range->left_key, range->left_value, &itr->node);
    if (cmp != 0) {
        itr->is_include = CM_FALSE;
        return;
    }
    itr->is_include = range->is_left_include;
    // We need to filter the multiple same key when is_include flag is false
    if (!itr->is_include) {
        while (itr->node->level[0].forward != NULL) {
            cmp = list->callback.key_cmp_func(
                list->callback.callback_func_arg, itr->node->level[0].forward->key, range->left_key);
            if (cmp > 0) {
                break;
            }
            itr->node = itr->node->level[0].forward;
        }
    } else {
        itr->node = itr->node->level[0].forward;
    }
}

void sklist_create_iterator(skip_list_t *list, skip_list_range_t *range, skip_list_iterator_t *itr)
{
    CM_ASSERT(list != NULL);
    CM_ASSERT(range != NULL);
    CM_ASSERT(itr != NULL);

    itr->list = list;
    dss_latch_s(&list->lock);

    if (range->left_key) {
        sklist_create_iterator_with_left_key(list, range, itr);
    } else {
        itr->node = list->head->level[0].forward;
        itr->is_include = CM_TRUE;
    }

    if (itr->node) {
        try_inc_reference(&itr->node->ref);
        if ((itr->node->ref & STATUS_DELETED) != 0) {
            itr->is_include = CM_FALSE;
        }
    }

    itr->cond = *range;
    dss_unlatch(&list->lock);
}

static int32 sklist_fetch_next_inner(
    skip_list_iterator_t *itr, skip_list_node_t *cur, void **key, void *value, uint16 value_len)
{
    int32 cmp;
    if (!itr->cond.right_key) {
        cmp = -1;
    } else {
        cmp = itr->list->callback.key_cmp_func(itr->list->callback.callback_func_arg, cur->key, itr->cond.right_key);
    }
    if (cmp > 0) {
        try_dec_reference(&itr->node->ref);
        if (itr->node->ref == STATUS_DELETED) {
            dss_unlatch(&itr->list->lock);
            dss_latch_x(&itr->list->lock);
            sklist_try_lazy_clean(itr->list, itr->node);
        }
        dss_unlatch(&itr->list->lock);
        itr->node = NULL;
        return SKLIST_FETCH_END;
    } else if (cmp == 0) {
        /* We may have multiple elements with the same key, what we need
         * is to find the element with both the right key and object. */
        if (!itr->cond.right_value) {
            cmp = 0;
        } else {
            cmp = itr->list->callback.value_cmp_func(cur->value, itr->cond.right_value);
        }
        if (cmp > 0 || (cmp == 0 && !itr->cond.is_right_include)) {
            try_dec_reference(&itr->node->ref);
            if (itr->node->ref == STATUS_DELETED) {
                dss_unlatch(&itr->list->lock);
                dss_latch_x(&itr->list->lock);
                sklist_try_lazy_clean(itr->list, itr->node);
            }
            dss_unlatch(&itr->list->lock);
            itr->node = NULL;
            return SKLIST_FETCH_END;
        }
    }
    try_dec_reference(&itr->node->ref);
    try_inc_reference(&cur->ref);
    if (itr->node->ref == STATUS_DELETED) {
        dss_unlatch(&itr->list->lock);
        dss_latch_x(&itr->list->lock);
        sklist_try_lazy_clean(itr->list, itr->node);
    }
    int32 ret = itr->list->callback.value_get_func(cur->value, value, value_len, NULL);
    dss_unlatch(&itr->list->lock);
    itr->node = cur;
    *key = cur->key;
    itr->list->usage.find_ok++;
    return ret;
}

static int32 sklist_get_list_node(skip_list_node_t **cur, skip_list_iterator_t *itr)
{
    *cur = itr->node->level[0].forward;
    for (;;) {
        if (!(*cur)) {
            try_dec_reference(&itr->node->ref);
            if (itr->node->ref == STATUS_DELETED) {
                dss_unlatch(&itr->list->lock);
                dss_latch_x(&itr->list->lock);
                sklist_try_lazy_clean(itr->list, itr->node);
            }
            dss_unlatch(&itr->list->lock);
            itr->node = NULL;
            return SKLIST_FETCH_END;
        }
        // if the node is delete.just ignore it.
        if ((itr->node->ref & STATUS_DELETED) == 0) {
            break;
        }
        *cur = (*cur)->level[0].forward;
    }
    return CM_SUCCESS;
}

int32 sklist_fetch_next(skip_list_iterator_t *itr, void **key, void *value, uint16 value_len)
{
    CM_ASSERT(itr != NULL);

    skip_list_node_t *cur;
    if (!itr->list || !key) {
        return ERR_DSS_SKLIST_ERR;
    }
    if (!itr->node) {
        return SKLIST_FETCH_END;
    }

    dss_latch_s(&itr->list->lock);

    if (itr->is_include) {
        cur = itr->node;
        itr->is_include = CM_FALSE;
    } else {
        CM_RETURN_IFERR(sklist_get_list_node(&cur, itr));
    }
    return sklist_fetch_next_inner(itr, cur, key, value, value_len);
}

void sklist_close_iterator(skip_list_iterator_t *itr)
{
    CM_ASSERT(itr != NULL);

    if (itr->node) {
        dss_latch_s(&itr->list->lock);
        try_dec_reference(&itr->node->ref);
        if (itr->node->ref == STATUS_DELETED) {
            dss_unlatch(&itr->list->lock);
            dss_latch_x(&itr->list->lock);
            sklist_try_lazy_clean(itr->list, itr->node);
        }
        dss_unlatch(&itr->list->lock);
        itr->node = NULL;
    }
}
