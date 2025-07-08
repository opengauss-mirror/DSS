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
#include "dss_thv.h"

#ifdef __cplusplus
extern "C" {
#endif

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

static bool32 dss_get_dst_directory(char *dir, const char *dst)
{
    text_t dst_dir;
    text_t dst_name;
    cm_str2text((char *)dst, &dst_name);
    if (!cm_fetch_rtext(&dst_name, '/', '\0', &dst_dir)) {
        DSS_THROW_ERROR_EX(
            ERR_DSS_FILE_RENAME, "Not a complete absolute path name(%s %s)", T2S(&dst_dir), T2S(&dst_name));
        LOG_DEBUG_ERR("Not a complete absolute path name(%s %s)", T2S(&dst_dir), dst);
        return CM_FALSE;
    }

    if (cm_text2str(&dst_dir, dir, DSS_MAX_NAME_LEN) != CM_SUCCESS) {
        return CM_FALSE;
    }

    return CM_TRUE;
}

static status_t dss_rename_file_check(
    dss_session_t *session, dss_rename_info_t *rename_info, dss_vg_info_item_t **vg_item)
{
    status_t status = dss_check_file(*vg_item);
    DSS_RETURN_IFERR2(status, LOG_DEBUG_ERR("Failed to check file,errcode:%d.", cm_get_error_code()));

    dss_check_dir_output_t output_info = {&(rename_info->src_node), NULL, NULL, CM_TRUE};
    dss_vg_info_item_t *file_vg_item = *vg_item;
    output_info.item = &file_vg_item;
    status = dss_check_dir(session, rename_info->src_path, GFT_FILE, &output_info, O_WRONLY, CM_TRUE);
    DSS_RETURN_IFERR2(status, LOG_DEBUG_ERR("Failed to check src dir,errcode:%d.", cm_get_error_code()));

    dss_check_dir_output_t output_info_tmp = {&(rename_info->dst_node), NULL, NULL, CM_TRUE};
    if (dss_check_dir(session, rename_info->dst_path, GFT_FILE, &output_info_tmp, O_WRONLY, CM_TRUE) != CM_SUCCESS) {
        int32 errcode = cm_get_error_code();
        if (errcode != ERR_DSS_FILE_NOT_EXIST) {
            return CM_ERROR;
        }
        cm_reset_error();

        char dst_dir[DSS_FILE_PATH_MAX_LENGTH];
        DSS_RETURN_VALUE_IF_HOOK(!dss_get_dst_directory(dst_dir, rename_info->dst_path), CM_ERROR,
            LOG_DEBUG_ERR("Failed to obtain the directory of the path(%s).", rename_info->dst_path));
        status = dss_check_dir(session, dst_dir, GFT_PATH, &output_info_tmp, O_WRONLY, CM_TRUE);
        DSS_RETURN_IFERR2(status, LOG_DEBUG_ERR("Failed to check dst dir,errcode:%d.", cm_get_error_code()));
    } else {
        DSS_THROW_ERROR(ERR_DSS_FILE_RENAME_EXIST, "cannot rename a existed file.");
        return CM_ERROR;
    }

    if (file_vg_item->id != (*vg_item)->id) {
        dss_unlock_vg_mem_and_shm(session, *vg_item);
        *vg_item = file_vg_item;
        dss_lock_vg_mem_and_shm_x(session, *vg_item);
    }
    return CM_SUCCESS;
}

status_t dss_rename_file_put_redo_log(
    dss_session_t *session, dss_rename_info_t *rename_info, dss_vg_info_item_t *vg_item, dss_config_t *inst_cfg)
{
    dss_redo_rename_t redo;
    redo.node = *(rename_info->src_node);
    errno_t err = snprintf_s(redo.name, DSS_MAX_NAME_LEN, strlen(rename_info->dst_name), "%s", rename_info->dst_name);
    bool32 result = (bool32)(err != -1);
    DSS_RETURN_IF_FALSE2(result, DSS_THROW_ERROR(ERR_SYSTEM_CALL, err));

    err = snprintf_s(
        redo.old_name, DSS_MAX_NAME_LEN, strlen(rename_info->src_node->name), "%s", rename_info->src_node->name);
    result = (bool32)(err != -1);
    DSS_RETURN_IF_FALSE2(result, DSS_THROW_ERROR(ERR_SYSTEM_CALL, err));

    err = snprintf_s(
        rename_info->src_node->name, DSS_MAX_NAME_LEN, strlen(rename_info->dst_name), "%s", rename_info->dst_name);
    result = (bool32)(err != -1);
    DSS_RETURN_IF_FALSE2(result, DSS_THROW_ERROR(ERR_SYSTEM_CALL, err));

    dss_put_log(session, vg_item, DSS_RT_RENAME_FILE, &redo, sizeof(redo));

    if (rename_info->is_cross_dir) {
        gft_node_t *parent_node =
            dss_get_ft_node_by_ftid(session, vg_item, rename_info->src_node->parent, CM_TRUE, CM_FALSE);
        dss_remove_ft_node(session, vg_item, parent_node, rename_info->src_node);
        dss_mv_to_specific_dir(session, vg_item, rename_info->src_node, rename_info->dst_node);
    }

    if (dss_process_redo_log(session, vg_item) != CM_SUCCESS) {
        dss_unlock_vg_mem_and_shm(session, vg_item);
        LOG_RUN_ERR("[DSS] ABORT INFO: redo log process failed, errcode:%d, OS errno:%d, OS errmsg:%s.",
            cm_get_error_code(), errno, strerror(errno));
        cm_fync_logfile();
        dss_exit(1);
    }
    return CM_SUCCESS;
}

status_t dss_rename_file_check_path_and_name(
    const char *src_path, const char *dst_path, char *vg_name, char *dst_name, bool32 *is_cross_dir)
{
    CM_RETURN_IFERR(dss_check_two_path_in_same_vg(src_path, dst_path, vg_name));
    text_t dst_name_text;
    CM_RETURN_IFERR(dss_check_rename_path(src_path, dst_path, &dst_name_text, is_cross_dir));
    CM_RETURN_IFERR(cm_text2str(&dst_name_text, dst_name, DSS_MAX_NAME_LEN));
    status_t status = dss_check_name(dst_name);
    DSS_RETURN_IFERR2(status, LOG_DEBUG_ERR("The name %s is invalid.", dst_path));

    return CM_SUCCESS;
}
status_t dss_check_vg_ft_dir(dss_session_t *session, dss_vg_info_item_t **vg_item, const char *path,
    gft_item_type_t type, gft_node_t **node, gft_node_t **parent_node)
{
    CM_RETURN_IFERR(dss_check_file(*vg_item));

    dss_vg_info_item_t *tmp_vg_item = *vg_item;
    dss_check_dir_output_t output_info = {node, &tmp_vg_item, parent_node, CM_TRUE};
    status_t status = dss_check_dir(session, path, type, &output_info, O_WRONLY, CM_TRUE);
    if (status != CM_SUCCESS) {
        LOG_DEBUG_ERR("Failed to check dir, errcode: %d.", status);
        return status;
    }
    if (tmp_vg_item->id != (*vg_item)->id) {
        dss_unlock_vg_mem_and_shm(session, *vg_item);
        *vg_item = tmp_vg_item;
        dss_lock_vg_mem_and_shm_x(session, *vg_item);
    }
    return CM_SUCCESS;
}

static bool32 dss_has_children_nodes(dss_session_t *session, dss_vg_info_item_t *vg_item, gft_node_t *node)
{
    if (node->items.count == 0) {
        return CM_FALSE;
    }
    gft_node_t *sub_node = dss_get_ft_node_by_ftid(session, vg_item, node->items.first, CM_TRUE, CM_FALSE);
    while (sub_node != NULL) {
        if ((sub_node->flags & DSS_FT_NODE_FLAG_DEL) == 0) {
            return CM_TRUE;
        }
        if (dss_cmp_auid(sub_node->next, DSS_INVALID_ID64)) {
            break;
        }
        sub_node = dss_get_ft_node_by_ftid(session, vg_item, sub_node->next, CM_TRUE, CM_FALSE);
    }
    return CM_FALSE;
}

static inline status_t dss_mark_delete_flag_core(dss_session_t *session, dss_vg_info_item_t *vg_item, gft_node_t *node)
{
    dss_set_node_flag(session, vg_item, node, CM_TRUE, DSS_FT_NODE_FLAG_DEL);
    LOG_DEBUG_INF("File : %s successfully marked for deletion", node->name);
    return CM_SUCCESS;
}

static status_t dss_mark_delete_flag_r(dss_session_t *session, dss_vg_info_item_t *vg_item, gft_node_t *node)
{
    if ((node->flags & DSS_FT_NODE_FLAG_SYSTEM) != 0) {
        DSS_THROW_ERROR(ERR_DSS_FILE_REMOVE_SYSTEM, node->name);
        LOG_DEBUG_ERR("Failed to rm dir %s, can not rm system dir.", node->name);
        return CM_ERROR;
    }
    if (!dss_is_last_tree_node(node)) {
        gft_node_t *sub_node = dss_get_ft_node_by_ftid(session, vg_item, node->items.first, CM_TRUE, CM_FALSE);
        while (sub_node != NULL) {
            if ((sub_node->flags & DSS_FT_NODE_FLAG_DEL) == 0) {
                CM_RETURN_IFERR(dss_mark_delete_flag_r(session, vg_item, sub_node));
            }
            sub_node = dss_get_next_node(session, vg_item, sub_node);
        }
    }
    if ((node->flags & DSS_FT_NODE_FLAG_DEL) != 0) {
        LOG_DEBUG_INF("File: %s has been marked for deletion, nothing need to do.", node->name);
        return CM_SUCCESS;
    }
    return dss_mark_delete_flag_core(session, vg_item, node);
}

static status_t dss_mark_delete_flag(
    dss_session_t *session, dss_vg_info_item_t *vg_item, gft_node_t *node, const char *dir_name, bool recursive)
{
    LOG_DEBUG_INF(
        "Mark delete flag for file or dir %s, fid:%llu, ftid: %s.", dir_name, node->fid, dss_display_metaid(node->id));
    if ((node->flags & DSS_FT_NODE_FLAG_DEL) != 0) {
        LOG_DEBUG_INF("File: %s has been marked for deletion, nothing need to do.", node->name);
        return CM_SUCCESS;
    }
    bool32 has_sub_file = CM_FALSE;
    status_t status = CM_ERROR;
    if (node->type == GFT_PATH) {
        has_sub_file = dss_has_children_nodes(session, vg_item, node);
    }

    if (has_sub_file) {
        if (!recursive) {
            DSS_THROW_ERROR_EX(ERR_DSS_DIR_REMOVE_NOT_EMPTY, "Failed to rm dir %s, which has sub node.", dir_name);
            return CM_ERROR;
        }
        status = dss_mark_delete_flag_r(session, vg_item, node);
    } else {
        return dss_mark_delete_flag_core(session, vg_item, node);
    }
    return status;
}

static status_t dss_rm_dir_file_inner(
    dss_session_t *session, dss_vg_info_item_t **vg_item, const char *dir_name, gft_item_type_t type, bool32 recursive)
{
    gft_node_t *parent_node = NULL;
    gft_node_t *node = NULL;
    status_t status = dss_check_vg_ft_dir(session, vg_item, dir_name, type, &node, &parent_node);
    DSS_RETURN_IF_ERROR(status);

    return dss_mark_delete_flag(session, *vg_item, node, dir_name, recursive);
}

static status_t dss_rm_dir_file(dss_session_t *session, const char *dir_name, gft_item_type_t type, bool32 recursive)
{
    CM_ASSERT(dir_name != NULL);

    char name[DSS_MAX_NAME_LEN];
    dss_vg_info_item_t *vg_item = NULL;
    CM_RETURN_IFERR(dss_find_vg_by_dir(dir_name, name, &vg_item));

    dss_lock_vg_mem_and_shm_x(session, vg_item);
    dss_init_vg_cache_node_info(vg_item);
    status_t status = dss_rm_dir_file_inner(session, &vg_item, dir_name, type, recursive);
    if (status != CM_SUCCESS) {
        dss_rollback_mem_update(session, vg_item);
        dss_unlock_vg_mem_and_shm(session, vg_item);
        LOG_RUN_ERR("Failed to remove dir or file, name : %s.", dir_name);
        return status;
    }

    if (dss_process_redo_log(session, vg_item) != CM_SUCCESS) {
        dss_unlock_vg_mem_and_shm(session, vg_item);
        LOG_RUN_ERR("[DSS] ABORT INFO: redo log process failed, errcode:%d, OS errno:%d, OS errmsg:%s.",
            cm_get_error_code(), errno, strerror(errno));
        cm_fync_logfile();
        dss_exit(1);
    }

    LOG_RUN_INF("Succeed to rm dir or file:%s in vg:%s.", dir_name, vg_item->vg_name);
    dss_unlock_vg_mem_and_shm(session, vg_item);
    return CM_SUCCESS;
}

static status_t dss_rm_dir_file_in_rename(
    dss_session_t *session, dss_vg_info_item_t **vg_item, const char *dir_name, gft_item_type_t type, bool32 recursive)
{
    CM_ASSERT(dir_name != NULL);

    status_t status = dss_rm_dir_file_inner(session, vg_item, dir_name, type, recursive);
    if (status != CM_SUCCESS) {
        LOG_RUN_ERR("Failed to remove dir or file, name : %s.", dir_name);
        return status;
    }
    LOG_RUN_INF("Succeed to rm dir or file:%s in vg:%s in rename.", dir_name, (*vg_item)->vg_name);
    return CM_SUCCESS;
}

static status_t dss_rename_file_inner(
    dss_session_t *session, dss_vg_info_item_t **vg_item, dss_config_t *inst_cfg, dss_rename_info_t *rename_info)
{
    status_t ret = dss_rename_file_check(session, rename_info, vg_item);
    if (ret != CM_SUCCESS) {
        return ret;
    }

    return dss_rename_file_put_redo_log(session, rename_info, *vg_item, inst_cfg);
}

status_t dss_rename_file(dss_session_t *session, const char *src, const char *dst)
{
    char vg_name[DSS_MAX_NAME_LEN];
    char dst_name[DSS_MAX_NAME_LEN];
    bool32 is_cross_dir = CM_FALSE;
    CM_RETURN_IFERR(dss_rename_file_check_path_and_name(src, dst, vg_name, dst_name, &is_cross_dir));
    if (is_cross_dir && DSS_GET_PROTOCOL_VER < DSS_VERSION_3) {
        DSS_THROW_ERROR(
            ERR_DSS_FILE_RENAME, "To rename across directory, version of dssserver must be no less than 3.");
        LOG_DEBUG_ERR("Maybe version of dssserver in the cluster are less than 3, rename across directory "
                      "are not support");
        return CM_ERROR;
    }
    dss_vg_info_item_t *vg_item = dss_find_vg_item(vg_name);
    if (vg_item == NULL) {
        DSS_THROW_ERROR(ERR_DSS_VG_NOT_EXIST, vg_name);
        return CM_ERROR;
    }
    if (cm_str_equal(src, dst)) {
        DSS_THROW_ERROR(ERR_DSS_FILE_RENAME, "src name is the same as dst.");
        return CM_ERROR;
    }
    dss_config_t *inst_cfg = dss_get_inst_cfg();
    dss_lock_vg_mem_and_shm_x(session, vg_item);

    dss_rename_info_t rename_info;
    rename_info.src_path = src;
    rename_info.dst_path = dst;
    rename_info.dst_name = dst_name;
    rename_info.is_cross_dir = is_cross_dir;
    status_t ret = dss_rename_file_inner(session, &vg_item, inst_cfg, &rename_info);
    if (ret == CM_SUCCESS) {
        dss_unlock_vg_mem_and_shm(session, vg_item);
        return ret;
    }
    dss_init_vg_cache_node_info(vg_item);

    // error_handle: rollback memory
    dss_rollback_mem_update(session, vg_item);
    int32 err_code = cm_get_error_code();
    if (err_code != ERR_DSS_FILE_RENAME_EXIST) {
        dss_unlock_vg_mem_and_shm(session, vg_item);
        return ret;
    }

    cm_reset_error();
    ret = dss_rm_dir_file_in_rename(session, &vg_item, dst, GFT_FILE, CM_FALSE);
    if (ret != CM_SUCCESS) {
        dss_rollback_mem_update(session, vg_item);
        dss_unlock_vg_mem_and_shm(session, vg_item);
        return ret;
    }
    dss_init_vg_cache_node_info(vg_item);

    ret = dss_rename_file_inner(session, &vg_item, inst_cfg, &rename_info);
    if (ret != CM_SUCCESS) {
        dss_rollback_mem_update(session, vg_item);
    }
    dss_init_vg_cache_node_info(vg_item);

    dss_unlock_vg_mem_and_shm(session, vg_item);
    return ret;
}

status_t dss_remove_dir(dss_session_t *session, const char *dir, bool32 recursive)
{
    return dss_rm_dir_file(session, dir, GFT_PATH, recursive);
}

status_t dss_remove_file(dss_session_t *session, const char *file)
{
    return dss_rm_dir_file(session, file, GFT_FILE, CM_FALSE);
}

status_t dss_remove_link(dss_session_t *session, const char *file)
{
    return dss_rm_dir_file(session, file, GFT_LINK, CM_FALSE);
}

static status_t dss_make_dir_file_core(dss_session_t *session, const char *parent, dss_vg_info_item_t **vg_item,
    const char *dir_name, gft_item_type_t type, int32_t flag)
{
    gft_node_t *out_node = NULL;
    status_t status = dss_open_file_check(session, parent, vg_item, GFT_PATH, &out_node);
    if (status != CM_SUCCESS) {
        LOG_DEBUG_ERR("Failed to open file check:%s when mkdir of file:%s", parent, dir_name);
        DSS_THROW_ERROR(ERR_DSS_VG_CHECK, (*vg_item)->dss_ctrl->volume.defs[0].name, "failed to open file check");
        return status;
    }
    // check if file/dir to create is duplicated
    gft_node_t *check_node = dss_find_ft_node(session, *vg_item, out_node, dir_name, CM_TRUE);
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
    out_node = dss_alloc_ft_node(session, *vg_item, out_node, dir_name, type, flag);  // actual FTN creation
    bool32 result = (bool32)(out_node != NULL);
    DSS_RETURN_IF_FALSE3(
        result, dss_rollback_mem_update(session, *vg_item), LOG_DEBUG_ERR("Failed to alloc ft node %s.", dir_name));

    status = dss_process_redo_log(session, *vg_item);
    if (status != CM_SUCCESS) {
        dss_unlock_vg_mem_and_shm(session, *vg_item);
        LOG_RUN_ERR("[DSS] ABORT INFO: redo log process failed, errcode:%d, OS errno:%d, OS errmsg:%s.",
            cm_get_error_code(), errno, strerror(errno));
        cm_fync_logfile();
        dss_exit(1);
    }
    LOG_DEBUG_ERR("[FT][ALLOC] Succeed to mkdir or file, fid:%llu, ftid: %s for file:%s.", out_node->fid,
        dss_display_metaid(out_node->id), dir_name);
    return CM_SUCCESS;
}

static status_t dss_make_dir_file(
    dss_session_t *session, const char *parent, const char *dir_name, gft_item_type_t type, int32 flag)
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
        LOG_DEBUG_ERR("Failed to mkdir or file:%s in path:%s, cant get vg item, vg name:%s.", dir_name, parent, name);
        return CM_ERROR;
    }
    dss_lock_vg_mem_and_shm_x(session, vg_item);
    status = dss_make_dir_file_core(session, parent, &vg_item, dir_name, type, flag);

    dss_unlock_vg_mem_and_shm(session, vg_item);
    if (status == CM_SUCCESS) {
        LOG_RUN_INF("Succeed to mk dir or file:%s in path:%s in vg:%s.", dir_name, parent, name);
    }
    return status;
}

status_t dss_make_dir(dss_session_t *session, const char *parent, const char *dir_name)
{
    return dss_make_dir_file(session, parent, dir_name, GFT_PATH, 0);
}

status_t dss_create_file(dss_session_t *session, const char *parent, const char *name, int32 flag)
{
    return dss_make_dir_file(session, parent, name, GFT_FILE, flag);
}

status_t dss_create_link(dss_session_t *session, const char *parent, const char *name)
{
    DSS_LOG_DEBUG_OP("Begin to set link:%s.", name);
    CM_RETURN_IFERR_EX(dss_make_dir_file(session, parent, name, GFT_LINK, 0), LOG_DEBUG_ERR("Failed to make link."));
    LOG_RUN_INF("Succeed to set link:%s in path:%s.", name, parent);
    return CM_SUCCESS;
}

void dss_clean_open_files_in_vg(dss_session_t *session, dss_vg_info_item_t *vg_item, uint64 pid)
{
    dss_open_file_info_t *open_file = NULL;
    dss_latch_x2(&vg_item->open_file_latch, session->id);
    bilist_node_t *curr_node = cm_bilist_head(&vg_item->open_file_list);
    bilist_node_t *next_node = NULL;
    while (curr_node != NULL) {
        next_node = curr_node->next;
        open_file = BILIST_NODE_OF(dss_open_file_info_t, curr_node, link);
        if (open_file->pid == pid) {
            dss_free_open_file_node(curr_node, &vg_item->open_file_list);
        }
        curr_node = next_node;
    }
    dss_unlatch(&vg_item->open_file_latch);
}

#ifdef __cplusplus
}
#endif
