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
 * dss_srv_proc.c
 *
 *
 * IDENTIFICATION
 *    src/service/dss_srv_proc.c
 *
 * -------------------------------------------------------------------------
 */
#include "dss_errno.h"
#include "dss_redo.h"
#include "dss_open_file.h"
#include "dss_file.h"
#include "dss_mes.h"
#include "dss_srv_proc.h"
#include "dss_instance.h"

#ifdef __cplusplus
extern "C" {
#endif

static status_t dss_notify_check_file_open(
    dss_vg_info_item_t *vg_item, dss_session_t *session, dss_bcast_req_cmd_t cmd, uint64 ftid, bool32 *is_open)
{
    if (g_dss_instance.is_maintain) {
        return CM_SUCCESS;
    }
    dss_check_file_open_param check;
    check.ftid = ftid;
    *is_open = CM_FALSE;
    errno_t err = strncpy_sp(check.vg_name, DSS_MAX_NAME_LEN, vg_item->vg_name, DSS_MAX_NAME_LEN);
    if (err != EOK) {
        DSS_THROW_ERROR(ERR_SYSTEM_CALL, err);
        return CM_ERROR;
    }
    LOG_DEBUG_INF("notify other dss instance to check file open, ftid:%llu in vg:%s.", ftid, vg_item->vg_name);
    dss_recv_msg_t recv_msg = {CM_TRUE, CM_FALSE};
    status_t status = dss_notify_sync(session, cmd, (char *)&check, sizeof(dss_check_file_open_param), &recv_msg);
    if (status != CM_SUCCESS) {
        LOG_RUN_ERR("[DSS] ABORT INFO: Failed to notify other dss instance, cmd: %u, file: %llu, vg: %s, errcode:%d, "
                    "OS errno:%d, OS errmsg:%s.",
            cmd, ftid, vg_item->vg_name, cm_get_error_code(), errno, strerror(errno));
        cm_fync_logfile();
        _exit(1);
    }
    if (recv_msg.open_flag) {
        *is_open = CM_TRUE;
    }
    return status;
}

static status_t dss_check_two_path_in_same_vg(const char *path1, const char *path2, char *vg_name)
{
    uint32 beg_pos1 = 0;
    uint32 beg_pos2 = 0;
    char vg_name1[DSS_MAX_NAME_LEN] = {0};

    status_t ret = dss_get_name_from_path(path1, &beg_pos1, vg_name1);
    DSS_RETURN_IFERR2(ret, LOG_DEBUG_ERR("Failed to get name from path %s,%d.", path1, ret));

    ret = dss_get_name_from_path(path2, &beg_pos2, vg_name);
    DSS_RETURN_IFERR2(ret, LOG_DEBUG_ERR("Failed to get name from path %s,%d.", path2, ret));

    if ((beg_pos1 != beg_pos2) || (cm_strcmpni(vg_name1, vg_name, strlen(vg_name1)) != 0)) {
        DSS_THROW_ERROR(ERR_DSS_FILE_RENAME_DIFF_VG, vg_name1, vg_name);
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

static status_t dss_rename_file_check(
    dss_session_t *session, const char *file, const char *dst, dss_vg_info_item_t **vg_item, gft_node_t **out_node)
{
    status_t status = dss_check_file(*vg_item);
    DSS_RETURN_IFERR2(status, LOG_DEBUG_ERR("Failed to check file,errcode:%d.", cm_get_error_code()));

    dss_check_dir_output_t output_info = {out_node, NULL, NULL};
    if (dss_check_dir(dst, GFT_FILE, &output_info, CM_TRUE) != CM_SUCCESS) {
        int32 errcode = cm_get_error_code();
        if (errcode != ERR_DSS_FILE_NOT_EXIST) {
            return CM_ERROR;
        }
        cm_reset_error();
    } else {
        DSS_THROW_ERROR(ERR_DSS_FILE_RENAME_EXIST, "cannot rename a existed file.");
        return CM_ERROR;
    }
    dss_vg_info_item_t *file_vg_item;
    output_info.item = &file_vg_item;
    status = dss_check_dir(file, GFT_FILE, &output_info, CM_TRUE);
    DSS_RETURN_IFERR2(status, LOG_DEBUG_ERR("Failed to check dir,errcode:%d.", cm_get_error_code()));

    if (file_vg_item->id != (*vg_item)->id) {
        dss_unlock_vg_mem_and_shm(session, *vg_item);
        *vg_item = file_vg_item;
        dss_lock_vg_mem_and_shm_x(session, *vg_item);
    }
    return CM_SUCCESS;
}

status_t dss_rename_file_put_redo_log(dss_session_t *session, gft_node_t *out_node, const char *dst_name,
    dss_vg_info_item_t *vg_item, dss_config_t *inst_cfg)
{
    dss_redo_rename_t redo;
    redo.node = *out_node;
    errno_t err = snprintf_s(redo.name, DSS_MAX_NAME_LEN, strlen(dst_name), "%s", dst_name);
    bool32 result = (bool32)(err != -1);
    DSS_RETURN_IF_FALSE2(result, DSS_THROW_ERROR(ERR_SYSTEM_CALL, err));

    err = snprintf_s(redo.old_name, DSS_MAX_NAME_LEN, strlen(out_node->name), "%s", out_node->name);
    result = (bool32)(err != -1);
    DSS_RETURN_IF_FALSE2(result, DSS_THROW_ERROR(ERR_SYSTEM_CALL, err));

    err = snprintf_s(out_node->name, DSS_MAX_NAME_LEN, strlen(dst_name), "%s", dst_name);
    result = (bool32)(err != -1);
    DSS_RETURN_IF_FALSE2(result, DSS_THROW_ERROR(ERR_SYSTEM_CALL, err));

    dss_put_log(session, vg_item, DSS_RT_RENAME_FILE, &redo, sizeof(redo));

    if (dss_process_redo_log(session, vg_item) != CM_SUCCESS) {
        dss_unlock_vg_mem_and_shm(session, vg_item);
        LOG_RUN_ERR("[DSS] ABORT INFO: redo log process failed, errcode:%d, OS errno:%d, OS errmsg:%s.",
            cm_get_error_code(), errno, strerror(errno));
        cm_fync_logfile();
        _exit(1);
    }
    return CM_SUCCESS;
}

status_t dss_rename_file_check_path_and_name(
    dss_session_t *session, const char *src_path, const char *dst_path, char *vg_name, char *dst_name)
{
    CM_RETURN_IFERR(dss_check_two_path_in_same_vg(src_path, dst_path, vg_name));
    text_t dst_name_text;
    CM_RETURN_IFERR(dss_check_rename_path(session, src_path, dst_path, &dst_name_text));
    CM_RETURN_IFERR(cm_text2str(&dst_name_text, dst_name, DSS_MAX_NAME_LEN));
    status_t status = dss_check_name(dst_name);
    DSS_RETURN_IFERR2(status, LOG_DEBUG_ERR("The name %s is invalid.", dst_path));

    return CM_SUCCESS;
}

status_t dss_rename_file(dss_session_t *session, const char *file, const char *dst)
{
    if (cm_strcmpi(file, dst) == 0) {
        // nothing to do
        return CM_SUCCESS;
    }
    char vg_name[DSS_MAX_NAME_LEN];
    char dst_name[DSS_MAX_NAME_LEN];
    CM_RETURN_IFERR(dss_rename_file_check_path_and_name(session, file, dst, vg_name, dst_name));
    dss_vg_info_item_t *vg_item = dss_find_vg_item(vg_name);
    if (vg_item == NULL) {
        DSS_THROW_ERROR(ERR_DSS_VG_NOT_EXIST, vg_name);
        return CM_ERROR;
    }
    dss_config_t *inst_cfg = dss_get_inst_cfg();
    dss_lock_vg_mem_and_shm_x(session, vg_item);
    status_t ret = CM_ERROR;
    do {
        gft_node_t *out_node = NULL;
        DSS_BREAK_IF_ERROR(dss_rename_file_check(session, file, dst, &vg_item, &out_node));
        if (out_node == NULL) {
            LOG_DEBUG_ERR("Failed to rename file %s.", file);
            break;
        }
        bool32 is_open = CM_FALSE;
        DSS_BREAK_IF_ERROR(
            dss_notify_check_file_open(vg_item, session, BCAST_REQ_RENAME, *(uint64 *)&out_node->id, &is_open));
        if (is_open) {
            // logic same as before
            DSS_THROW_ERROR(ERR_DSS_FILE_RENAME_OPENING_REMOTE, file, dst);
            break;
        }
        DSS_BREAK_IF_ERROR(dss_rename_file_put_redo_log(session, out_node, dst_name, vg_item, inst_cfg));
        ret = CM_SUCCESS;
    } while (0);
    if (ret != CM_SUCCESS) {
        // error_handle: rollback memory
        dss_rollback_mem_update(session->log_split, vg_item);
    }
    dss_unlock_vg_mem_and_shm(session, vg_item);
    return ret;
}

static status_t dss_rm_dir_file_r(
    dss_session_t *session, dss_vg_info_item_t *vg_item, gft_node_t *node, gft_node_t *parent_node)
{
    if (node->type == GFT_PATH) {
        if (node->flags & DSS_FT_NODE_FLAG_SYSTEM) {
            LOG_DEBUG_WAR("Failed to rm dir %s, can not rm system dir.", node->name);
            return CM_ERROR;
        }
        // delete empty dir
        if (node->items.count == 0) {
            dss_free_ft_node_inner(session, vg_item, parent_node, node, CM_TRUE);
            return CM_SUCCESS;
        }
        // delete files or folders in dir, then delete empty dir
        gft_node_t *sub_node = dss_get_ft_node_by_ftid(vg_item, node->items.first, CM_TRUE, CM_FALSE);
        while (!dss_cmp_auid(sub_node->next, DSS_INVALID_ID64)) {
            gft_node_t *cur_sub_node = sub_node;
            bool32 is_open;
            status_t status = dss_check_open_file(vg_item, *(uint64 *)&cur_sub_node->id, &is_open);
            if (status != CM_SUCCESS) {
                LOG_DEBUG_ERR(
                    "Failed to check open file, file %s, ftid:%llu.", cur_sub_node->name, *(uint64 *)&cur_sub_node->id);
                return CM_ERROR;
            }
            if (is_open) {
                LOG_DEBUG_ERR("Path %s is open, ftid:%llu.", cur_sub_node->name, *(uint64 *)&cur_sub_node->id);
                DSS_THROW_ERROR(ERR_DSS_FILE_REMOVE_OPENING);
                return CM_ERROR;
            }
            sub_node = dss_get_ft_node_by_ftid(vg_item, sub_node->next, CM_TRUE, CM_FALSE);
            CM_RETURN_IFERR(dss_rm_dir_file_r(session, vg_item, cur_sub_node, node));
        }
        CM_RETURN_IFERR(dss_rm_dir_file_r(session, vg_item, sub_node, node));
        dss_free_ft_node(session, vg_item, parent_node, node, CM_TRUE, CM_FALSE);
    } else {
        if (node->size > 0) {
            // first remove node from old dir
            dss_free_ft_node(session, vg_item, parent_node, node, CM_FALSE, CM_FALSE);
            dss_mv_to_recycle_dir(session, vg_item, node);
        } else {
            status_t status = dss_recycle_empty_file(session, vg_item, parent_node, node);
            if (status != CM_SUCCESS) {
                dss_rollback_mem_update(session->log_split, vg_item);
                LOG_DEBUG_ERR("Failed to recycle empty file(fid:%llu).", node->fid);
                return status;
            }
        }
    }
    return CM_SUCCESS;
}

status_t dss_rm_dir_by_path(
    dss_session_t *session, gft_node_t **node_array, const char *dir_name, bool recursive, dss_vg_info_item_t *vg_item)
{
    gft_node_t *node = node_array[0];
    gft_node_t *parent_node = node_array[1];
    if (!parent_node) {
        DSS_THROW_ERROR(ERR_DSS_INVALID_PARAM, dir_name);
        LOG_DEBUG_ERR("Failed to rm dir %s, can not rm root dir.", dir_name);
        return CM_ERROR;
    }
    if ((node->flags & DSS_FT_NODE_FLAG_SYSTEM) != 0) {
        DSS_THROW_ERROR(ERR_DSS_INVALID_PARAM, dir_name);
        LOG_DEBUG_ERR("Failed to rm dir %s, can not rm system dir.", dir_name);
        return CM_ERROR;
    }
    if (node->items.count != 0) {
        if (recursive) {
            return dss_rm_dir_file_r(session, vg_item, node, parent_node);
        }
        gft_node_t *sub_node = dss_get_ft_node_by_ftid(vg_item, node->items.first, CM_TRUE, CM_FALSE);
        while (sub_node) {
            if (sub_node->flags != DSS_FT_NODE_FLAG_DEL) {
                DSS_THROW_ERROR_EX(ERR_DSS_DIR_REMOVE_NOT_EMPTY, "Failed to rm dir %s, which has sub node %s.",
                    dir_name, sub_node->name);
                return CM_ERROR;
            }
            if (dss_cmp_auid(sub_node->next, DSS_INVALID_ID64)) {
                break;
            }
            sub_node = dss_get_ft_node_by_ftid(vg_item, sub_node->next, CM_TRUE, CM_FALSE);
        }
        if (node->flags & DSS_FT_NODE_FLAG_NORMAL) {
            node->flags = DSS_FT_NODE_FLAG_DEL;
            dss_ft_block_t *cur_block = dss_get_ft_block_by_node(node);
            status_t status = dss_update_ft_block_disk(vg_item, cur_block, node->id);
            if (status != CM_SUCCESS) {
                LOG_DEBUG_ERR("Failed to update ft block:%llu to disk.", DSS_ID_TO_U64(node->id));
                return status;
            }
            LOG_DEBUG_INF("Dir: %s successfully marked for deletion", node->name);
        }
    } else {
        dss_free_ft_node(session, vg_item, parent_node, node, CM_TRUE, CM_FALSE);
    }
    return CM_SUCCESS;
}

status_t dss_check_vg_ft_dir(dss_session_t *session, dss_vg_info_item_t **vg_item, const char *path,
    gft_item_type_t type, gft_node_t **node, gft_node_t **parent_node)
{
    CM_RETURN_IFERR(dss_check_file(*vg_item));

    dss_vg_info_item_t *tmp_vg_item;
    dss_check_dir_output_t output_info = {node, &tmp_vg_item, parent_node};
    status_t status = dss_check_dir(path, type, &output_info, CM_TRUE);
    if (status != CM_SUCCESS) {
        LOG_DEBUG_ERR("Failed to check dir, errcode: %d.", status);
        return status;
    }
    if (tmp_vg_item->id != (*vg_item)->id) {
        dss_unlock_vg_mem_and_shm(session, *vg_item);
        *vg_item = tmp_vg_item;
        dss_lock_vg_mem_and_shm_x(session, *vg_item);
    }

    bool32 is_open;
    status = dss_check_open_file(*vg_item, *(uint64 *)&(*node)->id, &is_open);
    if (status != CM_SUCCESS) {
        LOG_DEBUG_ERR("Failed to check open file, path %s, ftid:%llu.", path, *(uint64 *)&(*node)->id);
        return CM_ERROR;
    }

    if (is_open) {
        LOG_DEBUG_ERR("Path %s is open, ftid:%llu.", path, *(uint64 *)&(*node)->id);
        if (((*node)->type == GFT_FILE) && ((*node)->flags & DSS_FT_NODE_FLAG_NORMAL)) {
            (*node)->flags = DSS_FT_NODE_FLAG_DEL;
            dss_ft_block_t *cur_block = dss_get_ft_block_by_node(*node);
            status = dss_update_ft_block_disk(*vg_item, cur_block, (*node)->id);
            if (status != CM_SUCCESS) {
                LOG_DEBUG_ERR("Failed to update ft block:%llu to disk.", DSS_ID_TO_U64((*node)->id));
                return status;
            }
            LOG_DEBUG_INF("File: %s successfully marked for deletion", (*node)->name);
        }
        DSS_THROW_ERROR(ERR_DSS_FILE_REMOVE_OPENING);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static status_t dss_check_and_mark_file(dss_vg_info_item_t *vg_item, gft_node_t *node, const char *dir_name)
{
    LOG_DEBUG_INF("Path %s is opened, ftid:%llu.", dir_name, *(uint64 *)&node->id);
    if ((node->type == GFT_FILE) && (node->flags & DSS_FT_NODE_FLAG_NORMAL)) {
        node->flags = DSS_FT_NODE_FLAG_DEL;
        dss_ft_block_t *ft_block = dss_get_ft_block_by_node(node);
        status_t status = dss_update_ft_block_disk(vg_item, ft_block, node->id);
        if (status != CM_SUCCESS) {
            LOG_DEBUG_ERR("Failed to update ft block:%llu to disk.", DSS_ID_TO_U64(node->id));
            return status;
        }
        LOG_DEBUG_INF("File: %s successfully marked for deletion", node->name);
        return CM_SUCCESS;
    }
    DSS_THROW_ERROR(ERR_DSS_FILE_REMOVE_OPENING);
    return CM_ERROR;
}

static status_t dss_rm_dir_file(dss_session_t *session, const char *dir_name, gft_item_type_t type, bool recursive)
{
    CM_ASSERT(dir_name != NULL);
    gft_node_t *node;
    gft_node_t *parent_node = NULL;
    bool32 need_abort = DSS_FALSE;
    status_t status = CM_ERROR;

    dss_vg_info_item_t *vg_item = NULL;
    char name[DSS_MAX_NAME_LEN];
    CM_RETURN_IFERR(dss_find_vg_by_dir(dir_name, name, &vg_item));
    dss_lock_vg_mem_and_shm_x(session, vg_item);

    do {
        if (dss_check_vg_ft_dir(session, &vg_item, dir_name, type, &node, &parent_node) != CM_SUCCESS) {
            if ((cm_get_error_code() == ERR_DSS_FILE_REMOVE_OPENING) && (node->flags & DSS_FT_NODE_FLAG_DEL)) {
                cm_reset_error();
                status = CM_SUCCESS;
                break;
            }
            break;
        }
        bool32 is_open = CM_FALSE;
        DSS_BREAK_IF_ERROR(
            dss_notify_check_file_open(vg_item, session, BCAST_REQ_DEL_DIR_FILE, *(uint64 *)&node->id, &is_open));
        if (is_open) {
            status = dss_check_and_mark_file(vg_item, node, dir_name);
            if (status != CM_SUCCESS && (cm_get_error_code() == ERR_DSS_FILE_REMOVE_OPENING) &&
                (node->flags & DSS_FT_NODE_FLAG_DEL)) {
                cm_reset_error();
                status = CM_SUCCESS;
                break;
            }
            break;
        }

        LOG_RUN_INF("Begin to rm dir or file:%s in vg:%s.", dir_name, vg_item->vg_name);
        if (type == GFT_PATH) {
            gft_node_t *node_array[DSS_REMOVE_DIR_NEED_NODE_NUM] = {node, parent_node};
            DSS_BREAK_IF_ERROR(dss_rm_dir_by_path(session, node_array, dir_name, recursive, vg_item));
        } else {
            DSS_BREAK_IF_ERROR(dss_rm_dir_file_r(session, vg_item, node, parent_node));
        }

        if (dss_process_redo_log(session, vg_item) != CM_SUCCESS) {
            LOG_RUN_ERR("[DSS] ABORT INFO: redo log process failed, errcode:%d, OS errno:%d, OS errmsg:%s.",
                cm_get_error_code(), errno, strerror(errno));
            need_abort = DSS_TRUE;
            break;
        }
        LOG_RUN_INF("Succeed to rm dir or file:%s in vg:%s.", dir_name, vg_item->vg_name);
        status = CM_SUCCESS;
    } while (0);

    dss_unlock_vg_mem_and_shm(session, vg_item);
    if (need_abort) {
        cm_fync_logfile();
        _exit(1);
    }
    return status;
}

status_t dss_remove_dir(dss_session_t *session, const char *dir, bool recursive)
{
    return dss_rm_dir_file(session, dir, GFT_PATH, recursive);
}

status_t dss_remove_file(dss_session_t *session, const char *file)
{
    return dss_rm_dir_file(session, file, GFT_FILE, false);
}

status_t dss_remove_link(dss_session_t *session, const char *file)
{
    return dss_rm_dir_file(session, file, GFT_LINK, false);
}

static status_t dss_remove_dir_file_by_node_inner(
    dss_session_t *session, dss_vg_info_item_t *vg_item, gft_node_t *node, gft_node_t **parent_node)
{
    DSS_RETURN_IF_ERROR(dss_check_file(vg_item));

    LOG_RUN_INF("Begin to get parent node of node: %s", node->name);
    *parent_node = dss_find_parent_node_by_node(vg_item, node);
    if (*parent_node == NULL) {
        LOG_DEBUG_ERR("Failed to find parent node by node name%s.", node->name);
        return CM_ERROR;
    }
    LOG_RUN_INF("Success to get parent node: %s of node: %s", (*parent_node)->name, node->name);
    bool32 is_open = CM_FALSE;
    DSS_RETURN_IF_ERROR(
        dss_notify_check_file_open(vg_item, session, BCAST_REQ_DEL_DIR_FILE, *(uint64 *)&node->id, &is_open));
    if (is_open) {
        LOG_DEBUG_INF("Failed to remove delay file when close file, because file is opened in other instance ftid: "
                      "%llu, name: %s, v:%u, au:%llu, block:%u, item:%u.",
            *(uint64 *)&node->id, node->name, node->id.volume, (uint64)node->id.au, node->id.block, node->id.item);
        return CM_ERROR;
    }
    DSS_LOG_DEBUG_OP("Begin to rm %s, ftid: %llu", node->name, DSS_ID_TO_U64(node->id));
    if (node->type == GFT_PATH) {
        gft_node_t *node_array[DSS_REMOVE_DIR_NEED_NODE_NUM] = {node, *parent_node};
        DSS_RETURN_IF_ERROR(dss_rm_dir_by_path(session, node_array, node->name, DSS_FALSE, vg_item));
    } else {
        DSS_RETURN_IF_ERROR(dss_rm_dir_file_r(session, vg_item, node, *parent_node));
    }

    if (dss_process_redo_log(session, vg_item) != CM_SUCCESS) {
        LOG_RUN_ERR("[DSS] ABORT INFO: redo log process failed, errcode:%d, OS errno:%d, OS errmsg:%s.",
            cm_get_error_code(), errno, strerror(errno));
        cm_fync_logfile();
        _exit(1);
    }
    DSS_LOG_DEBUG_OP("Succeed to rm %s in vg:%s.", node->name, vg_item->vg_name);
    return CM_SUCCESS;
}

status_t dss_remove_dir_file_by_node(dss_session_t *session, dss_vg_info_item_t *vg_item, gft_node_t *node)
{
    cm_assert(node != NULL);
    cm_assert(node->flags == DSS_FT_NODE_FLAG_DEL);
    gft_node_t *parent_node;
    dss_lock_vg_mem_and_shm_x(session, vg_item);

    status_t status = dss_remove_dir_file_by_node_inner(session, vg_item, node, &parent_node);
    dss_unlock_vg_mem_and_shm(session, vg_item);
    if (status != CM_SUCCESS) {
        return CM_ERROR;
    }
    if (parent_node->flags & DSS_FT_NODE_FLAG_DEL) {
        return dss_remove_dir_file_by_node(session, vg_item, parent_node);
    }
    return CM_SUCCESS;
}

static status_t dss_make_dir_file_core(dss_session_t *session, const char *parent, dss_vg_info_item_t **vg_item,
    const char *dir_name, gft_item_type_t type)
{
    gft_node_t *out_node = NULL;
    status_t status = dss_open_file_check(session, parent, vg_item, GFT_PATH, &out_node);
    if (status != CM_SUCCESS) {
        DSS_THROW_ERROR(ERR_DSS_VG_CHECK, (*vg_item)->dss_ctrl->volume.defs[0].name, "failed to open file check");
        return status;
    }
    // check if file/dir to create is duplicated
    gft_node_t *check_node = dss_find_ft_node(*vg_item, out_node, dir_name, CM_TRUE);
    if (check_node != NULL) {
        if (check_node->flags & DSS_FT_NODE_FLAG_DEL) {
            LOG_DEBUG_INF(
                "Create file with same name file relay delete, ftid:%llu, fid:%llu, vg:%s, session pid:%llu, v:%u, "
                "au:%llu, block:%u, item:%u.",
                *(int64 *)&check_node->id, check_node->fid, (*vg_item)->vg_name, session->cli_info.cli_pid,
                check_node->id.volume, (uint64)check_node->id.au, check_node->id.block, check_node->id.item);
        } else {
            DSS_THROW_ERROR(ERR_DSS_DIR_CREATE_DUPLICATED, dir_name);
            LOG_DEBUG_ERR("Repeated file creation.");
            return CM_ERROR;
        }
    }
    out_node = dss_alloc_ft_node(session, *vg_item, out_node, dir_name, type);  // actual FTN creation
    bool32 result = (bool32)(out_node != NULL);
    DSS_RETURN_IF_FALSE3(result, dss_rollback_mem_update(session->log_split, *vg_item),
        LOG_DEBUG_ERR("Failed to alloc ft node %s.", dir_name));

    status = dss_process_redo_log(session, *vg_item);
    if (status != CM_SUCCESS) {
        dss_unlock_vg_mem_and_shm(session, *vg_item);
        LOG_RUN_ERR("[DSS] ABORT INFO: redo log process failed, errcode:%d, OS errno:%d, OS errmsg:%s.",
            cm_get_error_code(), errno, strerror(errno));
        cm_fync_logfile();
        _exit(1);
    }
    return CM_SUCCESS;
}

static status_t dss_make_dir_file(
    dss_session_t *session, const char *parent, const char *dir_name, gft_item_type_t type)
{
    CM_ASSERT(parent != NULL);
    CM_ASSERT(dir_name != NULL);
    status_t status;
    char name[DSS_MAX_NAME_LEN];
    uint32_t beg_pos = 0;
    if (dss_get_name_from_path(parent, &beg_pos, name) != CM_SUCCESS) {
        LOG_DEBUG_ERR("Failed to get name from path %s.", parent);
        return CM_ERROR;
    }

    if (dss_check_name(dir_name) != CM_SUCCESS) {
        LOG_DEBUG_ERR("The name %s is invalid.", dir_name);
        return CM_ERROR;
    }
    DSS_LOG_DEBUG_OP("Begin to make dir or file:%s in vg:%s.", dir_name, name);
    dss_vg_info_item_t *vg_item = dss_find_vg_item(name);
    if (vg_item == NULL) {
        DSS_THROW_ERROR(ERR_DSS_VG_NOT_EXIST, name);
        LOG_DEBUG_ERR("get vg item failed, vg name:%s.", name);
        return CM_ERROR;
    }
    dss_lock_vg_mem_and_shm_x(session, vg_item);
    status = dss_make_dir_file_core(session, parent, &vg_item, dir_name, type);

    dss_unlock_vg_mem_and_shm(session, vg_item);
    if (status == CM_SUCCESS) {
        LOG_RUN_INF("Succeed to mk dir or file:%s in vg:%s.", dir_name, name);
    }
    return status;
}

status_t dss_make_dir(dss_session_t *session, const char *parent, const char *dir_name)
{
    return dss_make_dir_file(session, parent, dir_name, GFT_PATH);
}

status_t dss_create_file(dss_session_t *session, const char *parent, const char *name, int32_t flag)
{
    return dss_make_dir_file(session, parent, name, GFT_FILE);
}

status_t dss_create_link(dss_session_t *session, const char *parent, const char *name)
{
    DSS_LOG_DEBUG_OP("Begin to set link:%s.", name);
    CM_RETURN_IFERR_EX(dss_make_dir_file(session, parent, name, GFT_LINK), LOG_DEBUG_ERR("Failed to make link."));
    LOG_RUN_INF("Succeed to set link:%s in path:%s.", name, parent);
    return CM_SUCCESS;
}

static void dss_close_handle(dss_session_t *session, dss_vg_info_item_t *vg_item, ftid_t ftid)
{
    gft_node_t *node = dss_get_ft_node_by_ftid(vg_item, ftid, CM_TRUE, CM_FALSE);
    if (node == NULL || node->type != GFT_FILE) {
        return;
    }
    if ((node->flags & DSS_FT_NODE_FLAG_DEL) != 0) {
        dss_unlatch(&vg_item->open_file_latch);
        status_t status = dss_remove_dir_file_by_node(session, vg_item, node);
        dss_latch_x(&vg_item->open_file_latch);
        if (status != CM_SUCCESS) {
            LOG_DEBUG_INF(
                "Failed to remove delay file when close file, ftid%llu, fid:%llu, vg: %s, session pid:%llu, v:%u, "
                "au:%llu, block:%u, item:%u.",
                *(int64 *)&ftid, node->fid, vg_item->vg_name, session->cli_info.cli_pid, ftid.volume, (uint64)ftid.au,
                ftid.block, ftid.item);
            return;
        }
        LOG_DEBUG_INF(
            "Succeed to remove delay file when close file, ftid:%llu, fid:%llu, vg: %s, session pid:%llu, v:%u, "
            "au:%llu, block:%u, item:%u.",
            *(uint64 *)&ftid, node->fid, vg_item->vg_name, session->cli_info.cli_pid, ftid.volume, (uint64)ftid.au,
            ftid.block, ftid.item);
        if (status != CM_SUCCESS) {
            LOG_DEBUG_INF("Failed to check remove delay file when session disconn close file, vg: %s.", vg_item->vg_name);
        }
    }
}

void dss_clean_open_files_in_vg(dss_session_t *session, dss_vg_info_item_t *vg_item, uint64 pid)
{
    skip_list_t *list = &vg_item->open_pid_list;
    skip_list_iterator_t itr;
    skip_list_range_t range;
    dss_open_file_info_t left_key;
    left_key.ftid = 0;
    left_key.pid = pid;
    left_key.ref = 1;

    dss_open_file_info_t right_key;
    right_key.ftid = CM_INVALID_ID64;
    right_key.pid = pid;
    right_key.ref = 1;

    range.is_left_include = CM_TRUE;
    range.is_right_include = CM_FALSE;
    range.left_key = &left_key;
    range.left_value = NULL;
    range.right_key = &right_key;
    range.right_value = NULL;

    uint32 count = 0;
    uint32 count_fail = 0;
    dss_open_file_info_t *next_key;
    int32 ret = SKLIST_FETCH_END;
    dss_latch_x(&vg_item->open_file_latch);

    do {
        sklist_create_iterator(list, &range, &itr);
        ret = sklist_fetch_next(&itr, (void **)&next_key, NULL, 0);
        if (ret != SKIP_LIST_FOUND) {
            sklist_close_iterator(&itr);
            LOG_DEBUG_INF("Not find skiplist index, ret:%d.", ret);
            break;
        }
        sklist_close_iterator(&itr);
        ftid_t ftid = *(ftid_t *)&next_key->ftid;
        uint32 err = sklist_delete(&vg_item->open_file_list, next_key, next_key);
        if (err != CM_SUCCESS) {
            count_fail++;
            LOG_DEBUG_INF("Failed to delete file skiplist index, ftid:%llu, pid:%llu.", next_key->ftid, next_key->pid);
        }

        err = sklist_delete(list, next_key, next_key);
        if (err != CM_SUCCESS) {
            count_fail++;
            LOG_DEBUG_INF("Failed to delete pid skiplist index, ftid:%llu, pid:%llu.", next_key->ftid, next_key->pid);
        }
        if (dss_is_readwrite()) {
            dss_close_handle(session, vg_item, ftid);
        }
        DSS_LOG_DEBUG_OP(
            "Succeed to close file, ftid:%llu, vg: %s, session pid:%llu, v:%u, au:%llu, block:%u, item:%u.",
            *(uint64 *)&ftid, vg_item->vg_name, session->cli_info.cli_pid, ftid.volume, (uint64)ftid.au, ftid.block,
            ftid.item);
        count++;
    } while (ret == SKIP_LIST_FOUND);
    dss_unlatch(&vg_item->open_file_latch);

    LOG_RUN_INF("Succeed to clean open files, count:%u, fail count:%u.", count, count_fail);
}

#ifdef __cplusplus
}
#endif
