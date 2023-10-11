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
 * dss_open_file.c
 *
 *
 * IDENTIFICATION
 *    src/common/dss_open_file.c
 *
 * -------------------------------------------------------------------------
 */

#include "dss_open_file.h"
#include "cm_system.h"

bilist_node_t *dss_find_open_file_node(bilist_t *open_file_list, uint64 ftid, uint64 pid, int64 start_time)
{
    dss_open_file_info_t *open_file = NULL;

    bilist_node_t *node = cm_bilist_head(open_file_list);
    for (; node != NULL; node = BINODE_NEXT(node)) {
        open_file = BILIST_NODE_OF(dss_open_file_info_t, node, link);
        if (open_file->ftid == ftid && open_file->pid == pid && open_file->start_time == start_time) {
            return node;
        }
    }
    return NULL;
}

status_t dss_insert_open_file_index(
    dss_session_t *session, dss_vg_info_item_t *vg_item, uint64 ftid, uint64 pid, int64 start_time)
{
    dss_open_file_info_t *open_file = NULL;

    dss_latch_x2(&vg_item->open_file_latch, session->id);
    bilist_node_t *node = dss_find_open_file_node(&vg_item->open_file_list, ftid, pid, start_time);
    if (node != NULL) {
        open_file = BILIST_NODE_OF(dss_open_file_info_t, node, link);
        open_file->ref++;
        LOG_DEBUG_INF("Succeed to insert open file index, ftid:%llu, pid:%llu, ref:%llu.", ftid, pid, open_file->ref);
        dss_unlatch(&vg_item->open_file_latch);
        return CM_SUCCESS;
    }

    open_file = (dss_open_file_info_t *)cm_malloc(sizeof(dss_open_file_info_t));
    if (open_file == NULL) {
        dss_unlatch(&vg_item->open_file_latch);
        DSS_THROW_ERROR(ERR_DSS_OUT_OF_MEM);
        return CM_ERROR;
    }
    errno_t ret = memset_s(open_file, sizeof(dss_open_file_info_t), 0, sizeof(dss_open_file_info_t));
    if (ret != EOK) {
        dss_unlatch(&vg_item->open_file_latch);
        CM_FREE_PTR(open_file);
        DSS_THROW_ERROR(ERR_SYSTEM_CALL, ret);
        return CM_ERROR;
    }
    open_file->ftid = ftid;
    open_file->pid = pid;
    open_file->start_time = start_time;
    open_file->ref = 1;
    cm_bilist_add_tail(&open_file->link, &vg_item->open_file_list);
    LOG_DEBUG_INF("Succeed to insert open file index, ftid:%llu, pid:%llu, ref:%llu.", ftid, pid, open_file->ref);
    dss_unlatch(&vg_item->open_file_latch);
    return CM_SUCCESS;
}

status_t dss_delete_open_file_index(
    dss_session_t *session, dss_vg_info_item_t *vg_item, uint64 ftid, uint64 pid, int64 start_time)
{
    dss_latch_x(&vg_item->open_file_latch);
    bilist_node_t *node = dss_find_open_file_node(&vg_item->open_file_list, ftid, pid, start_time);
    if (node == NULL) {
        dss_unlatch(&vg_item->open_file_latch);
        DSS_THROW_ERROR_EX(ERR_DSS_FILE_CLOSE, "Failed to delete open file index, ftid:%llu, pid:%llu.", ftid, pid);
        return CM_ERROR;
    }
    dss_open_file_info_t *open_file = BILIST_NODE_OF(dss_open_file_info_t, node, link);
    LOG_DEBUG_INF("Succeed to delete open file index, ftid:%llu, pid:%llu, old ref is %llu.", ftid, pid, open_file->ref);
    if (open_file->ref > 1) {
        open_file->ref--;
    } else {
        dss_free_open_file_node(node, &vg_item->open_file_list);
    }
    dss_unlatch(&vg_item->open_file_latch);
    return CM_SUCCESS;
}

status_t dss_check_open_file(dss_session_t *session, dss_vg_info_item_t *vg_item, uint64 ftid, bool32 *is_open)
{
    *is_open = CM_FALSE;
    dss_open_file_info_t *open_file = NULL;

    dss_latch_x2(&vg_item->open_file_latch, session->id);
    bilist_node_t *curr_node = cm_bilist_head(&vg_item->open_file_list);
    bilist_node_t *next_node = NULL;
    while (curr_node != NULL) {
        open_file = BILIST_NODE_OF(dss_open_file_info_t, curr_node, link);
        next_node = curr_node->next;
        if (!cm_sys_process_alived(open_file->pid, open_file->start_time)) {
            dss_free_open_file_node(curr_node, &vg_item->open_file_list);
            curr_node = next_node;
            continue;
        }
        if (open_file->ftid == ftid) {
            *is_open = CM_TRUE;
            break;
        }
        curr_node = next_node;
    }
    
    dss_unlatch(&vg_item->open_file_latch);
    return CM_SUCCESS;
}
