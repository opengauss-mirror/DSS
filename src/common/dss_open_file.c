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
#include "dss_malloc.h"
#include "dss_system.h"

static int32 of_sklist_file_key_cmp_proc(void *arg, void *left, void *right)
{
    CM_ASSERT(arg != NULL);
    CM_ASSERT(left != NULL);
    CM_ASSERT(right != NULL);
    dss_open_file_info_t *left_key = (dss_open_file_info_t *)left;
    dss_open_file_info_t *right_key = (dss_open_file_info_t *)right;
    if (left_key->ftid == right_key->ftid) {
        if (left_key->pid == right_key->pid) {
            return 0;
        } else if (left_key->pid > right_key->pid) {
            return 1;
        } else {
            return -1;
        }
    }

    if (left_key->ftid > right_key->ftid) {
        return 1;
    } else {
        return -1;
    }
}

static int32 of_sklist_pid_key_cmp_proc(void *arg, void *left, void *right)
{
    CM_ASSERT(arg != NULL);
    CM_ASSERT(left != NULL);
    CM_ASSERT(right != NULL);

    dss_open_file_info_t *left_key = (dss_open_file_info_t *)left;
    dss_open_file_info_t *right_key = (dss_open_file_info_t *)right;
    if (left_key->pid == right_key->pid) {
        if (left_key->ftid == right_key->ftid) {
            return 0;
        } else if (left_key->ftid > right_key->ftid) {
            return 1;
        } else {
            return -1;
        }
    }

    if (left_key->pid > right_key->pid) {
        return 1;
    } else {
        return -1;
    }
}

static int32 of_sklist_value_cmp_proc(void *left, void *right)
{
    CM_ASSERT(left != NULL);
    CM_ASSERT(right != NULL);

    return 0;
}

static int32 of_sklist_value_get_proc(void *data, void *buf, uint16 len, void **out_data)
{
    CM_ASSERT(data != NULL);

    if (buf) {
        errno_t errcode = memcpy_s(buf, len, data, len);
        securec_check_ret(errcode);
    }

    if (out_data) {
        *out_data = data;
    }

    return CM_SUCCESS;
}

static void of_sklist_free_proc(void *arg, void *key)
{
    CM_ASSERT(arg != NULL);
    CM_ASSERT(key != NULL);

    DSS_FREE_POINT(key);
}

status_t dss_init_open_file_index(dss_vg_info_item_t *vg_item)
{
    skip_list_callback_t callback;
    callback.callback_func_arg = vg_item;
    callback.key_cmp_func = of_sklist_file_key_cmp_proc;
    callback.value_cmp_func = of_sklist_value_cmp_proc;
    callback.key_free_func = of_sklist_free_proc;
    callback.value_get_func = of_sklist_value_get_proc;
    callback.value_free_func = NULL;
    uint32 ret = sklist_init(&vg_item->open_file_list, &callback);
    if (ret != CM_SUCCESS) {
        LOG_DEBUG_ERR("Failed to initialize skip list file index.");
        return CM_ERROR;
    }

    callback.key_cmp_func = of_sklist_pid_key_cmp_proc;
    ret = sklist_init(&vg_item->open_pid_list, &callback);
    if (ret != CM_SUCCESS) {
        LOG_DEBUG_ERR("Failed to initialize skip list pid index.");
        return CM_ERROR;
    }
    LOG_RUN_INF("Succeed to initialize to open file index for vg:%s.", vg_item->vg_name);
    return CM_SUCCESS;
}

void dss_destroy_open_file_index(dss_vg_info_item_t *vg_item)
{
    sklist_destroy(&vg_item->open_file_list);
    sklist_destroy(&vg_item->open_pid_list);
}

static status_t dss_insert_skiplist_index(skip_list_t *list, uint64 ftid, uint64 pid)
{
    dss_open_file_info_t key;
    key.ftid = ftid;
    key.pid = pid;
    key.ref = 1;

    dss_open_file_info_t *out_data;
    int32 ret = sklist_get_value(list, &key, CM_FALSE, NULL, 0, (void **)&out_data);
    if (ret == ERR_DSS_SKLIST_NOT_EXIST) {
        dss_open_file_info_t *key_ins = (dss_open_file_info_t *)cm_malloc(sizeof(dss_open_file_info_t));
        if (key_ins == NULL) {
            DSS_THROW_ERROR(ERR_ALLOC_MEMORY, sizeof(dss_open_file_info_t), "dss_insert_skiplist_index");
            return CM_ERROR;
        }
        key_ins->ftid = ftid;
        key_ins->pid = pid;
        key_ins->ref = 1;
        uint32 err = sklist_insert(list, key_ins, key_ins);
        if (err != 0) {
            LOG_DEBUG_ERR("Failed to insert open file index,ftid:%llu, pid:%llu.", key_ins->ftid, key_ins->pid);
            DSS_THROW_ERROR(err);
            return CM_ERROR;
        }
    } else if (ret == 0) {
        out_data->ref++;
    } else {
        DSS_THROW_ERROR(ret, "Failed to insert open file, ftid:%llu, pid:%llu.", ftid, pid);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static status_t dss_delete_skiplist_index(skip_list_t *list, uint64 ftid, uint64 pid)
{
    dss_open_file_info_t key;
    key.ftid = ftid;
    key.pid = pid;
    key.ref = 1;

    dss_open_file_info_t *out_data;
    int32 ret = sklist_get_value(list, &key, CM_FALSE, NULL, 0, (void **)&out_data);
    if (ret == 0) {  // found
        if (out_data->ref > 1) {
            out_data->ref--;
        } else {
            uint32 err = sklist_delete(list, &key, &key);
            if (err != CM_SUCCESS) {
                DSS_THROW_ERROR(ret, "Failed to delete open file info, ftid:%llu, pid:%llu.", ftid, pid);
                return CM_ERROR;
            }
        }
    } else {
        DSS_THROW_ERROR(ret, "Failed to delete open file info, ftid:%llu, pid:%llu.", ftid, pid);
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

status_t dss_insert_open_file_index(dss_vg_info_item_t *vg_item, uint64 ftid, uint64 pid)
{
    dss_latch_x(&vg_item->open_file_latch);
    status_t status = dss_insert_skiplist_index(&vg_item->open_file_list, ftid, pid);
    DSS_RETURN_IFERR3(status, dss_unlatch(&vg_item->open_file_latch),
        LOG_DEBUG_ERR("Failed to insert open file index,ftid:%llu, pid:%llu.", ftid, pid));

    status = dss_insert_skiplist_index(&vg_item->open_pid_list, ftid, pid);
    if (status != CM_SUCCESS) {
        (void)dss_delete_skiplist_index(&vg_item->open_file_list, ftid, pid);
        dss_unlatch(&vg_item->open_file_latch);
        LOG_DEBUG_ERR("Failed to insert open pid index,ftid:%llu, pid:%llu.", ftid, pid);
        return status;
    }
    dss_unlatch(&vg_item->open_file_latch);
    LOG_DEBUG_INF("Succeed to insert open file index, ftid:%llu, pid:%llu.", ftid, pid);
    return CM_SUCCESS;
}

status_t dss_delete_open_file_index(dss_vg_info_item_t *vg_item, uint64 ftid, uint64 pid)
{
    dss_latch_x(&vg_item->open_file_latch);
    status_t status = dss_delete_skiplist_index(&vg_item->open_file_list, ftid, pid);
    DSS_RETURN_IFERR3(status, dss_unlatch(&vg_item->open_file_latch),
        LOG_DEBUG_ERR("Failed to delete open file index,ftid:%llu, pid:%llu.", ftid, pid));

    status = dss_delete_skiplist_index(&vg_item->open_pid_list, ftid, pid);
    if (status != CM_SUCCESS) {
        (void)dss_insert_skiplist_index(&vg_item->open_file_list, ftid, pid);
        dss_unlatch(&vg_item->open_file_latch);
        LOG_DEBUG_ERR("Failed to delete open pid index,ftid:%llu, pid:%llu.", ftid, pid);
        return status;
    }
    dss_unlatch(&vg_item->open_file_latch);
    LOG_DEBUG_INF("Succeed to delete open file index, ftid:%llu, pid:%llu.", ftid, pid);
    return CM_SUCCESS;
}

status_t dss_check_open_file(dss_vg_info_item_t *vg_item, uint64 ftid, bool32 *is_open)
{
    skip_list_t *list = &vg_item->open_file_list;
    skip_list_iterator_t itr;
    skip_list_range_t range;
    dss_open_file_info_t left_key;
    left_key.ftid = ftid;
    left_key.pid = 0;
    left_key.ref = 1;

    dss_open_file_info_t right_key;
    right_key.ftid = ftid;
    right_key.pid = CM_INVALID_ID64;
    right_key.ref = 1;

    range.is_left_include = CM_FALSE;
    range.is_right_include = CM_FALSE;
    range.left_key = &left_key;
    range.left_value = NULL;
    range.right_key = &right_key;
    range.right_value = NULL;
    sklist_create_iterator(list, &range, &itr);

    dss_open_file_info_t *next_key;
    int32 ret = sklist_fetch_next(&itr, (void **)&next_key, NULL, 0);
    if (ret == SKLIST_FETCH_END) {
        *is_open = CM_FALSE;
    } else if (ret == SKIP_LIST_FOUND) {
        LOG_DEBUG_INF("Succeed to find open file index, ftid:%llu, pid:%llu.", ftid, next_key->pid);
        *is_open = CM_TRUE;
    } else {
        sklist_close_iterator(&itr);
        return CM_ERROR;
    }
    sklist_close_iterator(&itr);

    return CM_SUCCESS;
}
