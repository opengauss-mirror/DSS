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
 * dss_delete_file.c
 *
 *
 * IDENTIFICATION
 *    src/common/dss_delete_file.c
 *
 * -------------------------------------------------------------------------
 */

#include "cm_system.h"
#include "cm_stack.h"
#include "dss_delete_file.h"
#include "dss_open_file.h"
#include "dss_file.h"
#include "dss_redo.h"
#include "dss_thv.h"

status_t dss_en_delete_queue(dss_delete_queue_t *queue, ftid_t ftid)
{
    if (dss_delete_queue_is_full(queue)) {
        LOG_DEBUG_ERR("[DELAY_CLEAN]Failed to enqueue because the queue is full.");
        DSS_THROW_ERROR(ERR_DSS_DELETE_QUEUE_IS_FULL);
        return CM_ERROR;
    }
    if (dss_delete_queue_is_empty(queue)) {
        queue->front = 0;
        queue->rear = 0;
    }
    queue->items[queue->rear] = ftid;
    queue->rear++;
    return CM_SUCCESS;
}

status_t dss_de_delete_queue(dss_delete_queue_t *queue, ftid_t *ftid)
{
    *ftid = queue->items[queue->front];
    queue->front++;
    if (queue->front == queue->rear) {
        dss_init_delete_queue(queue);
    }
    return CM_SUCCESS;
}

status_t dss_push_search_stack(cm_stack_t *stack, ftid_t ftid, bool8 path_isvisited)
{
    dss_search_node_t *node = (dss_search_node_t *)cm_push(stack, sizeof(dss_search_node_t));
    if (node == NULL) {
        LOG_DEBUG_ERR("[DELAY_CLEAN]Failed to push stack.");
        DSS_THROW_ERROR(ERR_DSS_SEARCH_STACK_IS_FULL);
        return CM_ERROR;
    }
    node->ftid = ftid;
    node->path_isvisited = path_isvisited;
    LOG_DEBUG_INF("[DELAY_CLEAN]push search node to stack, ftid %s, path_isvisited %d.", dss_display_metaid(ftid),
        node->path_isvisited);
    return CM_SUCCESS;
}

status_t dss_fragment_scan(
    dss_session_t *session, dss_vg_info_item_t *vg_item, cm_stack_t *stack, dss_delete_queue_t *queue, bool8 *not_ready)
{
    dss_config_t *inst_cfg = dss_get_inst_cfg();
    uint32 i = 0;
    uint32 fragment = inst_cfg->params.delay_clean_search_fragment;
    dss_search_node_t *serach_node = NULL;
    gft_node_t *node = NULL;
    *not_ready = CM_FALSE;
    while (!dss_search_stack_is_empty(stack) && (i < fragment || fragment == 0)) {
        if (!dss_is_master_and_open()) {
            *not_ready = CM_TRUE;
            break;
        }
        serach_node = dss_top_search_stack(stack);
        node = dss_get_ft_node_by_ftid(session, vg_item, serach_node->ftid, CM_TRUE, CM_FALSE);
        if (node == NULL) {
            LOG_RUN_WAR("[DELAY_CLEAN]Failed to get node, ftid is %s.", dss_display_metaid(node->id));
            return CM_ERROR;
        }
        LOG_DEBUG_INF("[DELAY_CLEAN]top node %s from stack, type is %d, ftid is %s, path_isvisited is %d.", node->name,
            node->type, dss_display_metaid(node->id), serach_node->path_isvisited);
        if (!serach_node->path_isvisited && !dss_is_last_tree_node(node) &&
            ((node->flags & DSS_FT_NODE_FLAG_SYSTEM) == 0)) {
            serach_node->path_isvisited = CM_TRUE;
            if (node->type == GFT_PATH && node->items.count != 0) {
                DSS_RETURN_IF_ERROR(dss_push_search_stack(stack, node->items.first, CM_FALSE));
                i++;
                continue;
            }
        }
        dss_pop_search_stack(stack);
        LOG_DEBUG_INF("[DELAY_CLEAN]pop node %s from stack, ftid is %s.", node->name, dss_display_metaid(node->id));
        if ((node->flags & DSS_FT_NODE_FLAG_DEL) != 0) {
            if (dss_en_delete_queue(queue, serach_node->ftid) != CM_SUCCESS) {
                if (cm_get_error_code() == ERR_DSS_DELETE_QUEUE_IS_FULL) {
                    LOG_DEBUG_INF("[DELAY_CLEAN]delete queue is full, try to real delete.");
                    cm_reset_error();
                    break;
                }
                return CM_ERROR;
            }
        }
        if (!dss_cmp_blockid(node->next, CM_INVALID_ID64)) {
            DSS_RETURN_IF_ERROR(dss_push_search_stack(stack, node->next, CM_FALSE));
        }
        i++;
    }
    return CM_SUCCESS;
}

static status_t dss_clean_delay_file_node(
    dss_session_t *session, dss_vg_info_item_t *vg_item, gft_node_t *parent_node, gft_node_t *node)
{
    if (node->size > 0) {
        // first remove node from old dir but not real delete, just mv to recycle
        dss_au_root_t *dss_au_root = DSS_GET_AU_ROOT(vg_item->dss_ctrl);
        ftid_t recycle_ftid = *(ftid_t *)(&dss_au_root->free_root);
        gft_node_t *recycle_node = dss_get_ft_node_by_ftid(session, vg_item, recycle_ftid, CM_TRUE, CM_FALSE);
        dss_free_ft_node(session, vg_item, parent_node, node, CM_FALSE);
        dss_mv_to_specific_dir(session, vg_item, node, recycle_node);
    } else {
        status_t status = dss_recycle_empty_file(session, vg_item, parent_node, node);
        if (status != CM_SUCCESS) {
            dss_rollback_mem_update(session, vg_item);
            LOG_RUN_WAR("[DELAY_CLEAN]Failed to recycle empty file(fid:%llu).", node->fid);
            return status;
        }
    }
    return CM_SUCCESS;
}

static status_t dss_clean_delay_node(
    dss_session_t *session, dss_vg_info_item_t *vg_item, gft_node_t *parent_node, gft_node_t *node)
{
    LOG_DEBUG_INF("[DELAY_CLEAN]Delay File begin to clean name %s ftid:%s.", node->name, dss_display_metaid(node->id));
    if (node->type == GFT_PATH) {
        // clean delay path only when they have no children node
        LOG_DEBUG_INF("[DELAY_CLEAN]Delay File %s ftid:%s is path, children node count %u .", node->name,
            dss_display_metaid(node->id), node->items.count);
        if (node->items.count != 0) {
            LOG_DEBUG_WAR("[DELAY_CLEAN]Delay File dir %s ftid:%s has children node, no need to delete.", node->name,
                dss_display_metaid(node->id));
            return CM_SUCCESS;
        }
        dss_free_ft_node(session, vg_item, parent_node, node, CM_TRUE);
    } else {
        status_t status = dss_clean_delay_file_node(session, vg_item, parent_node, node);
        DSS_RETURN_IF_ERROR(status);
    }
    if (dss_process_redo_log(session, vg_item) != CM_SUCCESS) {
        LOG_RUN_ERR("[DSS] ABORT INFO: redo log process failed, errcode:%d, OS errno:%d, OS errmsg:%s.",
            cm_get_error_code(), errno, strerror(errno));
        cm_fync_logfile();
        dss_exit(1);
    }
    LOG_DEBUG_INF("[DELAY_CLEAN]Delay File clean success.");
    return CM_SUCCESS;
}

status_t dss_clean_delete_queue(
    dss_session_t *session, dss_vg_info_item_t *vg_item, dss_delete_queue_t *queue, bool8 *not_ready)
{
    ftid_t ftid;
    bool32 check_file_open = CM_FALSE;
    gft_node_t *node = NULL;
    gft_node_t *parent_node = NULL;
    while (!dss_delete_queue_is_empty(queue)) {
        if (!dss_is_master_and_open()) {
            *not_ready = CM_TRUE;
            break;
        }
        DSS_RETURN_IF_ERROR(dss_de_delete_queue(queue, &ftid));
        DSS_RETURN_IF_ERROR(dss_check_open_file_local_and_remote(session, vg_item, ftid, &check_file_open));
        if (check_file_open) {
            check_file_open = CM_FALSE;
            continue;
        }
        if (!dss_lock_vg_mem_and_shm_timed_x(session, vg_item, DSS_LOCK_TIMEOUT_FOR_DELETE)) {
            LOG_RUN_WAR("[DELAY_CLEAN]Lock vg %s x failed, exit the clean, wait next time.", vg_item->vg_name);
            return CM_ERROR;
        }
        node = dss_get_ft_node_by_ftid(session, vg_item, ftid, CM_TRUE, CM_FALSE);
        if (node == NULL) {
            dss_unlock_vg_mem_and_shm(session, vg_item);
            LOG_RUN_WAR("[DELAY_CLEAN]Failed to get node id:%s.", dss_display_metaid(ftid));
            return CM_ERROR;
        }
        parent_node = dss_get_ft_node_by_ftid(session, vg_item, node->parent, CM_TRUE, CM_FALSE);
        if (parent_node == NULL) {
            dss_unlock_vg_mem_and_shm(session, vg_item);
            LOG_RUN_WAR("[DELAY_CLEAN]Failed to get parent node id:%s, child_node name %s.",
                dss_display_metaid(node->parent), node->name);
            return CM_ERROR;
        }
        if (dss_clean_delay_node(session, vg_item, parent_node, node) != CM_SUCCESS) {
            dss_unlock_vg_mem_and_shm(session, vg_item);
            return CM_ERROR;
        }
        dss_unlock_vg_mem_and_shm(session, vg_item);
    }
    return CM_SUCCESS;
}

static void dss_clean_vg_root_tree(
    dss_session_t *session, dss_vg_info_item_t *vg_item, cm_stack_t *stack, dss_delete_queue_t *queue)
{
    LOG_DEBUG_INF("[DELAY_CLEAN]Begin to clean the root tree %s.", vg_item->vg_name);
    if (!dss_is_master_and_open()) {
        LOG_RUN_WAR("[DELAY_CLEAN]Instance status is not ready, exit the clean, wait next time.");
        return;
    }
    dss_init_delete_queue(queue);
    cm_stack_reset(stack);
    cm_reset_error();
    if (!dss_lock_vg_mem_and_shm_timed_s(session, vg_item, DSS_LOCK_TIMEOUT_FOR_DELETE)) {
        LOG_RUN_WAR("[DELAY_CLEAN]Lock vg %s s failed, exit the clean, wait next time.", vg_item->vg_name);
        return;
    }
    ftid_t id = {0};
    if (dss_push_search_stack(stack, id, CM_FALSE) != CM_SUCCESS) {
        dss_unlock_vg_mem_and_shm(session, vg_item);
        return;
    }
    bool8 not_ready = CM_FALSE;
    dss_unlock_vg_mem_and_shm(session, vg_item);
    status_t status;
    while (!dss_search_stack_is_empty(stack)) {
        if (!dss_lock_vg_mem_and_shm_timed_s(session, vg_item, DSS_LOCK_TIMEOUT_FOR_DELETE)) {
            LOG_RUN_WAR("[DELAY_CLEAN]Lock vg %s s failed, exit the clean, wait next time.", vg_item->vg_name);
            return;
        }
        status = dss_fragment_scan(session, vg_item, stack, queue, &not_ready);
        if (status != CM_SUCCESS) {
            dss_unlock_vg_mem_and_shm(session, vg_item);
            LOG_RUN_WAR(
                "[DELAY_CLEAN]Failed to fragment scan vg %s, exit the clean, wait next time.", vg_item->vg_name);
            return;
        }
        if (not_ready) {
            dss_unlock_vg_mem_and_shm(session, vg_item);
            LOG_RUN_WAR("[DELAY_CLEAN]Instance status is not ready, exit the clean, wait next time.");
            return;
        }
        dss_unlock_vg_mem_and_shm(session, vg_item);
        status = dss_clean_delete_queue(session, vg_item, queue, &not_ready);
        if (status != CM_SUCCESS) {
            LOG_RUN_WAR("[DELAY_CLEAN]Failed to clean delete queue of vg %s, exit the clean, wait next time.",
                vg_item->vg_name);
            return;
        }
        if (not_ready) {
            LOG_RUN_WAR("[DELAY_CLEAN]Instance status is not ready, exit the clean, wait next time.");
            return;
        }
    }
    if (dss_search_stack_is_empty(stack)) {
        LOG_DEBUG_INF("[DELAY_CLEAN]Succeed to clean the root tree %s.", vg_item->vg_name);
    }
}

void dss_delay_clean_all_vg(dss_session_t *session, cm_stack_t *stack, dss_delete_queue_t *queue)
{
    for (uint32_t i = 0; i < g_vgs_info->group_num; i++) {
        dss_clean_vg_root_tree(session, &g_vgs_info->volume_group[i], stack, queue);
    }
}