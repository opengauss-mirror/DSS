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
 * dss_file.c
 *
 *
 * IDENTIFICATION
 *    src/common/dss_file.c
 *
 * -------------------------------------------------------------------------
 */

#include "cm_date.h"
#include "dss_ga.h"
#include "cm_hash.h"
#include "dss_defs.h"
#include "dss_hashmap.h"
#include "dss_shm.h"
#include "dss_alloc_unit.h"
#include "dss_io_fence.h"
#include "dss_malloc.h"
#include "dss_open_file.h"
#include "dss_redo.h"
#include "dss_syncpoint.h"

dss_env_t g_dss_env;
dss_env_t *dss_get_env(void)
{
    return &g_dss_env;
}
// CAUTION: dss_admin manager command just like dss_create_vg,cannot call it,
dss_config_t *dss_get_inst_cfg(void)
{
    if (dss_is_server()) {
        return g_inst_cfg;
    } else {
        dss_env_t *dss_env = dss_get_env();
        return &dss_env->inst_cfg;
    }
}
//    return 1 is letter
//    return 0 is not letter
int is_letter(char c)
{
    return ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'));
}

//    return 1 is number
//    return 0 is not number
int is_number(char c)
{
    return (c >= '0' && c <= '9');
}

static inline bool32 is_ft_root_block(ftid_t ftid)
{
    return ftid.au == 0 && ftid.block == 0;
}

static inline bool32 compare_auid(auid_t a, auid_t b)
{
    return ((a.volume == b.volume) && (a.au == b.au) && (a.block == b.block) && (a.item == b.item));
}

static status_t dss_is_valid_name_char(char name)
{
    if (!is_number(name) && !is_letter(name) && name != '_' && name != '.' && name != '-') {
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

static status_t dss_is_valid_path_char(char name)
{
    if (name != '/' && dss_is_valid_name_char(name) != CM_SUCCESS) {
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static status_t dss_check_name_is_valid(const char *name, uint32 path_max_size)
{
    if (strlen(name) >= path_max_size) {
        DSS_THROW_ERROR(ERR_DSS_FILE_PATH_ILL, name, ", name is too long");
        return CM_ERROR;
    }

    for (uint32 i = 0; i < strlen(name); i++) {
        if (dss_is_valid_name_char(name[i]) != CM_SUCCESS) {
            DSS_THROW_ERROR(ERR_DSS_FILE_PATH_ILL, name, ", name should be [0~9,a~z,A~Z,-,_,.]");
            return CM_ERROR;
        }
    }
    return CM_SUCCESS;
}

static status_t dss_check_path_is_valid(const char *path, uint32 path_max_size)
{
    if (strlen(path) >= path_max_size) {
        DSS_THROW_ERROR(ERR_DSS_FILE_PATH_ILL, path, ", path is too long\n");
        return CM_ERROR;
    }

    for (uint32 i = 0; i < strlen(path); i++) {
        if (dss_is_valid_path_char(path[i]) != CM_SUCCESS) {
            DSS_THROW_ERROR(ERR_DSS_FILE_PATH_ILL, path, ", path should be [0~9,a~z,A~Z,-,_,/,.]");
            return CM_ERROR;
        }
    }
    return CM_SUCCESS;
}

status_t dss_check_name(const char *name)
{
    if (name == NULL) {
        DSS_THROW_ERROR(ERR_DSS_FILE_PATH_ILL, "[null]", ", name cannot be a null string.");
        return CM_ERROR;
    }

    return dss_check_name_is_valid(name, DSS_MAX_NAME_LEN);
}

status_t dss_check_path(const char *path)
{
    if (path == NULL) {
        DSS_THROW_ERROR(ERR_DSS_FILE_PATH_ILL, "[null]", ", path cannot be a null string.");
        return CM_ERROR;
    }

    return dss_check_path_is_valid(path, DSS_FILE_PATH_MAX_LENGTH);
}

status_t dss_check_device_path(const char *path)
{
    if (path == NULL) {
        DSS_THROW_ERROR(ERR_DSS_FILE_PATH_ILL, "[null]", ", path cannot be a null string.");
        return CM_ERROR;
    }

    if (path[0] != '+') {
        DSS_THROW_ERROR(ERR_DSS_FILE_PATH_ILL, path, ", path should start with +");
        return CM_ERROR;
    }

    return dss_check_path_is_valid(path + 1, (DSS_FILE_PATH_MAX_LENGTH - 1));
}

status_t dss_check_path_both(const char *path)
{
    if (path == NULL) {
        DSS_THROW_ERROR(ERR_DSS_FILE_PATH_ILL, "[null]", "path cannot be a null string.");
        return CM_ERROR;
    }

    if (path[0] == '+') {
        return dss_check_path_is_valid(path + 1, DSS_FILE_PATH_MAX_LENGTH - 1);
    } else {
        return dss_check_path_is_valid(path, DSS_FILE_PATH_MAX_LENGTH);
    }
}

status_t dss_get_name_from_path(const char *path, uint32_t *beg_pos, char *name)
{
    CM_ASSERT(path != NULL);
    CM_ASSERT(beg_pos != NULL);
    CM_ASSERT(name != NULL);
    uint32_t name_len = 0;
    size_t len = strlen(path);
    if (len == 0) {
        DSS_THROW_ERROR(ERR_DSS_FILE_PATH_ILL, "[null]", "path cannot be a null string.");
        return CM_ERROR;
    }
    if (*beg_pos > len) {
        DSS_THROW_ERROR(ERR_DSS_FILE_PATH_ILL, path, "begin pos is larger than string length.");
        return CM_ERROR;
    }

    if (path[*beg_pos] == '/' || (*beg_pos == 0 && path[*beg_pos] == '+')) {
        (*beg_pos)++;
        while (path[*beg_pos] != '/' && path[*beg_pos] != 0) {
            name[name_len] = path[*beg_pos];
            if (dss_is_valid_name_char(name[name_len]) != CM_SUCCESS) {
                DSS_THROW_ERROR(ERR_DSS_FILE_PATH_ILL, path, ", name should be [0~9,a~z,A~Z,-,_,.]");
                return CM_ERROR;
            }
            (*beg_pos)++;
            name_len++;
            if (name_len >= DSS_MAX_NAME_LEN) {
                DSS_THROW_ERROR(ERR_DSS_FILE_PATH_ILL, (char *)path + *beg_pos, "name length should less than 64.");
                return CM_ERROR;
            }
        }
        name[name_len] = 0;
    } else if (path[*beg_pos] == 0) {
        name[0] = 0;
    } else {
        DSS_THROW_ERROR(ERR_DSS_FILE_PATH_ILL, path, ", name should be [0~9,a~z,A~Z,-,_,.]");
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

status_t dss_find_vg_by_dir(const char *dir_path, char *name, dss_vg_info_item_t **vg_item)
{
    status_t status;
    uint32_t beg_pos = 0;

    status = dss_get_name_from_path(dir_path, &beg_pos, name);
    if (status != CM_SUCCESS) {
        LOG_DEBUG_ERR("Failed to get name from path %s,%d.", dir_path, status);
        return status;
    }

    if (name[0] == 0) {
        LOG_DEBUG_ERR("Failed to get name from path %s.", dir_path);
        return CM_ERROR;
    }

    *vg_item = dss_find_vg_item(name);
    if (*vg_item == NULL) {
        DSS_THROW_ERROR(ERR_DSS_VG_NOT_EXIST, name);
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

void dss_lock_vg_mem_and_shm_x(dss_session_t *session, dss_vg_info_item_t *vg_item)
{
    dss_lock_vg_mem_x(vg_item);
    dss_lock_shm_meta_x(session, vg_item->vg_latch);
}

void dss_lock_vg_mem_and_shm_s(dss_session_t *session, dss_vg_info_item_t *vg_item)
{
    dss_lock_vg_mem_s(vg_item);
    dss_latch_offset_t latch_offset;
    latch_offset.type = DSS_LATCH_OFFSET_SHMOFFSET;
    latch_offset.offset.shm_offset = dss_get_vg_latch_shm_offset(vg_item);
    dss_lock_shm_meta_s(session, &latch_offset, vg_item->vg_latch, SPIN_WAIT_FOREVER);
}

void dss_unlock_vg_mem_and_shm(dss_session_t *session, dss_vg_info_item_t *vg_item)
{
    dss_unlock_shm_meta(session, vg_item->vg_latch);
    dss_unlock_vg_mem(vg_item);
}

void dss_mv_to_recycle_dir(dss_session_t *session, dss_vg_info_item_t *vg_item, gft_node_t *node)
{
    CM_ASSERT(vg_item != NULL);
    CM_ASSERT(node != NULL);
    gft_node_t *last_node = NULL;
    dss_au_root_t *dss_au_root = DSS_GET_AU_ROOT(vg_item->dss_ctrl);
    ftid_t free_root = *(ftid_t *)(&dss_au_root->free_root);
    gft_node_t *root_node = dss_get_ft_node_by_ftid(vg_item, free_root, CM_TRUE, CM_FALSE);
    CM_ASSERT(root_node != NULL);

    root_node->items.count++;
    node->prev = root_node->items.last;
    dss_set_blockid(&node->next, DSS_INVALID_64);

    bool32 cmp = dss_cmp_blockid(root_node->items.last, DSS_INVALID_64);
    if (cmp) {
        root_node->items.first = node->id;
    } else {
        last_node = (gft_node_t *)dss_get_ft_node_by_ftid(vg_item, root_node->items.last, CM_TRUE, CM_FALSE);
        CM_ASSERT(last_node != NULL);
        last_node->next = node->id;
    }
    root_node->items.last = node->id;

    dss_redo_recycle_ft_node_t redo;
    uint16 i = 0;
    redo.node[i] = *node;
    i++;
    if (last_node) {
        redo.node[i] = *last_node;
    } else {
        dss_set_auid(&redo.node[i].id, CM_INVALID_ID64);
    }
    i++;
    redo.node[i] = *root_node;

    dss_put_log(session, vg_item, DSS_RT_RECYCLE_FILE_TABLE_NODE, &redo, sizeof(dss_redo_recycle_ft_node_t));
    DSS_LOG_DEBUG_OP("Mv to recycle dir, name:%s, node id:%llu.", node->name, DSS_ID_TO_U64(node->id));
}

status_t dss_recycle_empty_file(
    dss_session_t *session, dss_vg_info_item_t *vg_item, gft_node_t *parent_node, gft_node_t *node)
{
    ga_obj_id_t entry_objid;
    bool32 cmp = dss_cmp_blockid(node->entry, CM_INVALID_ID64);
    if (cmp) {
        dss_free_ft_node(session, vg_item, parent_node, node, CM_TRUE, CM_FALSE);
        DSS_LOG_DEBUG_OP("Succeed to free empty file(fid:%llu), just free node.", node->fid);
        return CM_SUCCESS;
    }
    dss_fs_block_header *entry_block = (dss_fs_block_header *)dss_find_block_in_shm(
        vg_item, node->entry, DSS_BLOCK_TYPE_FS, CM_TRUE, &entry_objid, CM_FALSE);
    if (!entry_block) {
        LOG_DEBUG_ERR("Failed to get fs block %llu,%llu,%llu, maybe no memory.", (uint64)node->entry.au,
            (uint64)node->entry.volume, (uint64)node->entry.block);
        return ERR_ALLOC_MEMORY;
    }

    uint16 index;
    ga_obj_id_t sec_objid;
    dss_fs_block_t *entry_fs_block = (dss_fs_block_t *)entry_block;
    CM_ASSERT(entry_block->used_num == 1);

    index = (uint16)(entry_block->used_num - 1);
    dss_fs_block_t *block = (dss_fs_block_t *)dss_find_block_in_shm(
        vg_item, entry_fs_block->bitmap[index], DSS_BLOCK_TYPE_FS, CM_TRUE, &sec_objid, CM_FALSE);
    if (!block) {
        LOG_DEBUG_ERR("Failed to get fs block %llu,%llu,%llu, maybe no memory.", (uint64)node->entry.au,
            (uint64)node->entry.volume, (uint64)node->entry.block);
        return ERR_ALLOC_MEMORY;
    }
    CM_ASSERT(block->head.used_num == 0);

    dss_free_fs_block_addr(session, vg_item, (char *)block, sec_objid);
    // do not set the entry block ,let allocate block to do it;

    dss_free_fs_block_addr(session, vg_item, (char *)entry_block, entry_objid);
    dss_free_ft_node(session, vg_item, parent_node, node, CM_TRUE, CM_FALSE);

    DSS_LOG_DEBUG_OP("Succeed to free empty file(fid:%llu).", node->fid);
    return CM_SUCCESS;
}

static status_t dss_get_link_auid(dss_vg_info_item_t *vg_item, gft_node_t *node, auid_t *auid, bool32 is_read)
{
    dss_fs_block_header *entry_block =
        (dss_fs_block_header *)dss_find_block_in_shm(vg_item, node->entry, DSS_BLOCK_TYPE_FS, CM_TRUE, NULL, CM_FALSE);
    if (!entry_block) {
        LOG_DEBUG_ERR("Can not find entry block in memory, entry blockid:%llu, nodeid:%llu.",
            DSS_ID_TO_U64(node->entry), DSS_ID_TO_U64(node->id));
        return CM_ERROR;
    }

    uint16 index = (uint16)(entry_block->used_num - 1);
    dss_fs_block_t *entry_fs_block = (dss_fs_block_t *)entry_block;

    dss_block_id_t second_block_id = entry_fs_block->bitmap[index];
    dss_fs_block_header *second_block = (dss_fs_block_header *)dss_find_block_in_shm(
        vg_item, second_block_id, DSS_BLOCK_TYPE_FS, CM_TRUE, NULL, CM_FALSE);
    if (!second_block) {
        LOG_DEBUG_ERR("Failed to find the second block:%llu.", DSS_ID_TO_U64(second_block_id));
        return CM_ERROR;
    }
    index = (uint16)(second_block->used_num - 1);
    dss_fs_block_t *second_fs_block = (dss_fs_block_t *)second_block;
    *auid = second_fs_block->bitmap[index];
    if (dss_cmp_auid(*auid, DSS_INVALID_ID64)) {
        char *log_buf = (is_read ? (char *)"Read" : (char *)"Write");
        LOG_DEBUG_ERR("[%s link] get link au failed", log_buf);
        CM_ASSERT(0);
    }
    return CM_SUCCESS;
}

static status_t dss_read_link_file(dss_vg_info_item_t *vg_item, gft_node_t *node, char *out_filename, size_t out_len)
{
    CM_ASSERT(vg_item != NULL);
    CM_ASSERT(node != NULL);
    CM_RETURN_IF_FALSE(node->type == GFT_LINK);
    status_t status = CM_ERROR;
    auid_t auid;
    CM_RETURN_IFERR(dss_get_link_auid(vg_item, node, &auid, DSS_TRUE));

    dss_volume_t volume = vg_item->volume_handle[auid.volume];
    if (volume.handle == DSS_INVALID_HANDLE) {
        status =
            dss_open_volume(vg_item->dss_ctrl->volume.defs[auid.volume].name, NULL, DSS_INSTANCE_OPEN_FLAG, &volume);
        if (status != CM_SUCCESS) {
            LOG_DEBUG_ERR("open volume %s failed.", vg_item->dss_ctrl->volume.defs[auid.volume].name);
            return status;
        }
        vg_item->volume_handle[auid.volume] = volume;
    }

    int64 vol_offset = dss_get_au_offset(vg_item, auid);
    status = dss_read_volume(&volume, vol_offset, out_filename, (int32)out_len);
    if (status != CM_SUCCESS) {
        LOG_RUN_ERR("Read volume failed, volume: %s, vol_offset: %lld, node name: %s, node type: %u", volume.name,
            vol_offset, node->name, node->type);
        return CM_ERROR;
    }
    DSS_LOG_DEBUG_OP("Read link, volume: %s, vol_offset: %lld, auid: %llu, buff: %s, buf_size: %lu", volume.name,
        vol_offset, DSS_ID_TO_U64(auid), out_filename, strlen(out_filename));
    return CM_SUCCESS;
}

static status_t dss_check_dir_core(
    const char *dir_path, gft_item_type_t type, char *name, uint32_t *beg_pos, dss_check_dir_param_t *output_param);
static status_t dss_open_link(
    dss_session_t *session, const char *link_path, dss_vg_info_item_t **vg_item, gft_node_t **out_node);

status_t dss_read_link(dss_session_t *session, char *link_path, char *out_filepath, uint32 *out_len)
{
    gft_node_t *node = NULL;
    dss_vg_info_item_t *vg_item = NULL;
    char name[DSS_MAX_NAME_LEN];
    CM_RETURN_IFERR(dss_find_vg_by_dir(link_path, name, &vg_item));
    dss_lock_vg_mem_and_shm_s(session, vg_item);
    status_t status = dss_open_link(session, link_path, &vg_item, &node);
    if (status != CM_SUCCESS) {
        dss_unlock_vg_mem_and_shm(session, vg_item);
        return status;
    }
#ifndef WIN32
    char dst_path[DSS_FILE_PATH_MAX_LENGTH] __attribute__((__aligned__(DSS_DISK_UNIT_SIZE))) = {0};
#else
    char dst_path[DSS_FILE_PATH_MAX_LENGTH] = {0};
#endif
    status = dss_read_link_file(vg_item, node, dst_path, sizeof(dst_path) - 1);
    dss_unlock_vg_mem_and_shm(session, vg_item);
    if (status != CM_SUCCESS) {
        status = dss_delete_open_file_index(
            vg_item, *(uint64 *)&node->id, session->cli_info.cli_pid, session->cli_info.start_time);
        if (status == CM_SUCCESS) {
            LOG_RUN_INF("Success to delete open file index, ftid:%llu.", *(uint64 *)&node->id);
        }
        return CM_ERROR;
    }
    *out_len = (uint32)strlen(dst_path);
    errno_t errcode = strcpy_s(out_filepath, DSS_FILE_PATH_MAX_LENGTH, dst_path);
    securec_check_ret(errcode);

    status = dss_delete_open_file_index(
        vg_item, *(uint64 *)&node->id, session->cli_info.cli_pid, session->cli_info.start_time);
    if (status != CM_SUCCESS) {
        LOG_DEBUG_ERR("Failed to delete open file index.");
        return CM_ERROR;
    }
    DSS_LOG_DEBUG_OP("Succeed to close link, ftid:%llu, session id:%u.", *(uint64 *)&node->id, session->id);
    return CM_SUCCESS;
}

static status_t dss_write_link_file_content(
    dss_session_t *session, dss_vg_info_item_t *vg_item, auid_t auid, char *dst_path)
{
    CM_ASSERT(vg_item != NULL);
#ifndef WIN32
    char dst_path_buf[DSS_FILE_PATH_MAX_LENGTH] __attribute__((__aligned__(DSS_DISK_UNIT_SIZE))) = {0};
#else
    char dst_path_buf[DSS_FILE_PATH_MAX_LENGTH] = {0};
#endif
    errno_t errcode = strcpy_s(dst_path_buf, sizeof(dst_path_buf), dst_path);
    securec_check_ret(errcode);

    status_t status;
    dss_volume_t volume = vg_item->volume_handle[auid.volume];
    if (volume.handle == DSS_INVALID_HANDLE) {
        status =
            dss_open_volume(vg_item->dss_ctrl->volume.defs[auid.volume].name, NULL, DSS_INSTANCE_OPEN_FLAG, &volume);
        if (status != CM_SUCCESS) {
            LOG_DEBUG_ERR("open volume %s failed.", vg_item->dss_ctrl->volume.defs[auid.volume].name);
            return status;
        }
        vg_item->volume_handle[auid.volume] = volume;
    }

    int64 vol_offset = dss_get_au_offset(vg_item, auid);
    status = dss_write_volume(&volume, vol_offset, dst_path_buf, sizeof(dst_path_buf) - 1);
    if (status != CM_SUCCESS) {
        LOG_RUN_ERR("Write volume failed, volume: %s, vol_offset: %lld, buff: %s, buf_size: %lu", volume.name,
            vol_offset, dst_path_buf, sizeof(dst_path_buf) - 1);
        return CM_ERROR;
    }
    DSS_LOG_DEBUG_OP("Write link, volume: %s, vol_offset: %lld, auid: %llu, buff: %s, buf_size: %lu", volume.name,
        vol_offset, DSS_ID_TO_U64(auid), dst_path_buf, sizeof(dst_path_buf) - 1);
    return CM_SUCCESS;
}

status_t dss_write_link_file(dss_session_t *session, char *link_path, char *dst_path)
{
    CM_ASSERT(dst_path != NULL);
    dss_vg_info_item_t *vg_item;
    gft_node_t *node = NULL;
    status_t status = CM_ERROR;
    char name[DSS_MAX_NAME_LEN];
    CM_RETURN_IFERR(dss_find_vg_by_dir(link_path, name, &vg_item));
    dss_lock_vg_mem_and_shm_s(session, vg_item);
    status = dss_open_link(session, link_path, &vg_item, &node);
    dss_unlock_vg_mem_and_shm(session, vg_item);
    CM_RETURN_IFERR(status);
    CM_RETURN_IF_FALSE(node->type == GFT_LINK);
    status = dss_extend(session, node->fid, node->id, 0, vg_item->vg_name, vg_item->id, DSS_FALSE);
    if (status != CM_SUCCESS) {
        status = dss_delete_open_file_index(
            vg_item, *(uint64 *)&node->id, session->cli_info.cli_pid, session->cli_info.start_time);
        if (status == CM_SUCCESS) {
            LOG_RUN_INF("Success to delete open file index, ftid:%llu.", *(uint64 *)&node->id);
        }
        return CM_ERROR;
    }
    auid_t auid;
    status = dss_get_link_auid(vg_item, node, &auid, DSS_FALSE);
    if (status != CM_SUCCESS) {
        CM_RETURN_IFERR(dss_delete_open_file_index(
            vg_item, *(uint64 *)&node->id, session->cli_info.cli_pid, session->cli_info.start_time));
        return CM_ERROR;
    }
    status = dss_write_link_file_content(session, vg_item, auid, dst_path);
    if (status != CM_SUCCESS) {
        CM_RETURN_IFERR(dss_delete_open_file_index(
            vg_item, *(uint64 *)&node->id, session->cli_info.cli_pid, session->cli_info.start_time));
        if (status == CM_SUCCESS) {
            LOG_RUN_INF("Success to delete open file index, ftid:%llu.", *(uint64 *)&node->id);
        }
        return CM_ERROR;
    }

    status = dss_delete_open_file_index(
        vg_item, *(uint64 *)&node->id, session->cli_info.cli_pid, session->cli_info.start_time);
    if (status != CM_SUCCESS) {
        LOG_DEBUG_ERR("Failed to delete open file index.");
        return CM_ERROR;
    }
    DSS_LOG_DEBUG_OP("Succeed to close link, ftid:%llu, session id:%u.", *(uint64 *)&node->id, session->id);
    return CM_SUCCESS;
}

static status_t dss_check_link(
    const char *dir_path, gft_item_type_t type, uint32_t *beg_pos, dss_check_dir_param_t *output_param)
{
    // last node is a link
    if (type == GFT_LINK && dir_path[*beg_pos] == 0) {
        return CM_SUCCESS;
    }

#ifndef WIN32
    char link_path[DSS_FILE_PATH_MAX_LENGTH] __attribute__((__aligned__(DSS_DISK_UNIT_SIZE))) = {0};
#else
    char link_path[DSS_FILE_PATH_MAX_LENGTH] = {0};
#endif

    LOG_DEBUG_INF("Read link file: %s", output_param->last_node->name);
    status_t status =
        dss_read_link_file(output_param->vg_item, output_param->last_node, link_path, sizeof(link_path) - 1);
    if (status != CM_SUCCESS) {
        LOG_DEBUG_ERR("Read link file: %s failed.\n", output_param->last_node->name);
        return CM_ERROR;
    }

    size_t path_len = strlen(link_path);
    errno_t errcode = strcpy_s(link_path + path_len, DSS_FILE_PATH_MAX_LENGTH - path_len, dir_path + *beg_pos);
    securec_check_ret(errcode);

    char name[DSS_MAX_NAME_LEN];
    *beg_pos = 0;
    status = dss_get_name_from_path(link_path, beg_pos, name);
    if (status != CM_SUCCESS) {
        LOG_DEBUG_ERR("Failed to get name from path %s,%d.", link_path, status);
        return status;
    }

    if (name[0] == 0) {
        LOG_DEBUG_ERR("Failed to get name from path %s.", link_path);
        return status;
    }
    return dss_check_dir_core(link_path, type, name, beg_pos, output_param);
}

static status_t dss_check_dir_core(
    const char *dir_path, gft_item_type_t type, char *name, uint32_t *beg_pos, dss_check_dir_param_t *output_param)
{
    uint32_t next_pos;
    status_t status;
    output_param->vg_item = dss_find_vg_item(name);
    if (output_param->vg_item == NULL) {
        DSS_THROW_ERROR(ERR_DSS_VG_NOT_EXIST, name);
        LOG_DEBUG_ERR("Failed to find vg, %s.", name);
        return CM_ERROR;
    }
    gft_node_t *node = dss_find_ft_node(output_param->vg_item, NULL, name, CM_TRUE);
    if (node == NULL) {
        LOG_DEBUG_ERR("Failed to get the root node %s.", name);
        return CM_ERROR;
    }
    output_param->last_node = node;
    do {
        status = dss_get_name_from_path(dir_path, beg_pos, name);
        if (status != CM_SUCCESS) {
            LOG_DEBUG_ERR("Failed to get name from path %s,%d.", dir_path, status);
            return status;
        }
        if (name[0] == 0) {
            continue;
        }
        output_param->last_node =
            dss_find_ft_node(output_param->vg_item, output_param->last_node, name, output_param->is_skip_delay_file);
        if (output_param->last_node == NULL && type == GFT_PATH) {
            if (output_param->is_throw_err) {
                DSS_THROW_ERROR(ERR_DSS_DIR_NOT_EXIST, name, dir_path);
            }
            return ERR_DSS_DIR_NOT_EXIST;
        } else if (output_param->last_node == NULL && type == GFT_FILE) {
            if (output_param->is_throw_err) {
                DSS_THROW_ERROR(ERR_DSS_FILE_NOT_EXIST, name, dir_path);
            }
            return ERR_DSS_FILE_NOT_EXIST;
        } else if (output_param->last_node == NULL && type == GFT_LINK) {
            if (output_param->is_throw_err) {
                DSS_THROW_ERROR(ERR_DSS_LINK_NOT_EXIST, name, dir_path);
            }
            return ERR_DSS_LINK_NOT_EXIST;
        }

        output_param->p_node = node;
        next_pos = *beg_pos;
        status = dss_get_name_from_path(dir_path, &next_pos, name);
        if (status != CM_SUCCESS) {
            LOG_DEBUG_ERR("Failed to get name from path %s,%d.", dir_path, status);
            return status;
        }
        if (name[0] != 0) {
            node = output_param->last_node;
        }

        if (output_param->last_node->type == GFT_LINK) {
            LOG_DEBUG_INF("get dir is link name:%s.", output_param->last_node->name);
            return dss_check_link(dir_path, type, beg_pos, output_param);
        }
    } while (name[0] != 0);
    return CM_SUCCESS;
}

static char *dss_file_type_to_str(gft_item_type_t type)
{
    switch (type) {
        case GFT_PATH:
            return DSS_GFT_PATH_STR;
        case GFT_FILE:
            return DSS_GFT_FILE_STR;
        case GFT_LINK:
            return DSS_GFT_LINK_STR;
        default:
            return DSS_GFT_INVALID_STR;
    }
}

status_t dss_check_dir(
    const char *dir_path, gft_item_type_t type, dss_check_dir_output_t *output_info, bool32 is_throw_err)
{
    CM_ASSERT(dir_path != NULL);
    char name[DSS_MAX_NAME_LEN];
    uint32_t beg_pos = 0;
    status_t status = dss_get_name_from_path(dir_path, &beg_pos, name);
    if (status != CM_SUCCESS) {
        LOG_DEBUG_ERR("Failed to get name from path %s,%d.", dir_path, status);
        return status;
    }

    if (name[0] == 0) {
        LOG_DEBUG_ERR("Failed to get name from path %s.", dir_path);
        return status;
    }
    dss_check_dir_param_t output_param = {0};
    output_param.is_throw_err = is_throw_err;
    output_param.is_skip_delay_file = CM_TRUE;
    DSS_RETURN_IF_ERROR(dss_check_dir_core(dir_path, type, name, &beg_pos, &output_param));
    if (output_param.last_node->type != type) {
        if (is_throw_err) {
            DSS_THROW_ERROR(ERR_DSS_FILE_TYPE_MISMATCH, output_param.last_node->name);
            LOG_DEBUG_ERR("The type %s of node %s is not matched type %s, dir path is %s",
                dss_file_type_to_str(output_param.last_node->type), output_param.last_node->name,
                dss_file_type_to_str(type), dir_path);
        }
        LOG_DEBUG_INF("The type %s of node %s is not matched type %s, dir path is %s",
            dss_file_type_to_str(output_param.last_node->type), output_param.last_node->name,
            dss_file_type_to_str(type), dir_path);
        return ERR_DSS_FILE_TYPE_MISMATCH;
    }

    if (output_info->out_node) {
        *output_info->out_node = output_param.last_node;
    }

    if (output_info->item) {
        *output_info->item = output_param.vg_item;
    }

    if (output_info->parent_node) {
        *output_info->parent_node = output_param.p_node;
    }

    return CM_SUCCESS;
}

static status_t dss_refresh_dir_r(dss_vg_info_item_t *vg_item, gft_node_t *parent_node, bool8 is_refresh_all_node)
{
    status_t status = CM_SUCCESS;
    ftid_t id = parent_node->items.first;
    for (uint32 i = 0; i < parent_node->items.count; i++) {
#ifdef OPENGAUSS
        if (dss_cmp_blockid(id, CM_INVALID_ID64)) {
            // openGauss may be find uncommitted node when standby
            LOG_DEBUG_INF("Get invalid id in parent name:%s, id:%llu, count:%u, when refresh dir, index:%u.",
                parent_node->name, *(uint64 *)&parent_node->id, parent_node->items.count, i);
            break;
        }
#endif
        gft_node_t *node = dss_get_ft_node_by_ftid(vg_item, id, CM_TRUE, CM_TRUE);
        if (node == NULL) {
            LOG_DEBUG_ERR("Can not get node:%llu, parent node name:%s.", *(uint64 *)&id, parent_node->name);
            return CM_ERROR;
        }
        if (node->type == GFT_PATH && is_refresh_all_node) {
            status = dss_refresh_dir_r(vg_item, node, is_refresh_all_node);
            if (status != CM_SUCCESS) {
                LOG_DEBUG_ERR("Failed to refesh dir vg:%s, ftid:%llu, dir name:%s.", vg_item->vg_name,
                    *(uint64 *)&node->id, node->name);
                break;
            }
        }
        id = node->next;
    }
    return status;
}

status_t dss_open_dir(dss_session_t *session, const char *dir_path, bool32 is_refresh)
{
    if (!dir_path) {
        return CM_ERROR;
    }
    dss_vg_info_item_t *vg_item = NULL;
    char name[DSS_MAX_NAME_LEN];
    CM_RETURN_IFERR(dss_find_vg_by_dir(dir_path, name, &vg_item));
    dss_lock_vg_mem_and_shm_s(session, vg_item);
    gft_node_t *node = NULL;
    status_t status;

    do {
        dss_vg_info_item_t *dir_vg_item;
        dss_check_dir_output_t output_info = {&node, &dir_vg_item, NULL};
        status = dss_check_dir(dir_path, GFT_PATH, &output_info, CM_TRUE);
        if (status != CM_SUCCESS) {
            LOG_DEBUG_ERR("Failed to check dir:%s.", dir_path);
            break;
        }
        if (dir_vg_item->id != vg_item->id) {
            dss_unlock_vg_mem_and_shm(session, vg_item);
            vg_item = dir_vg_item;
            dss_lock_vg_mem_and_shm_s(session, vg_item);
        }
        if (node->flags & DSS_FT_NODE_FLAG_DEL) {
            DSS_THROW_ERROR(ERR_DSS_DIR_NOT_EXIST, node->name, dir_path);
            status = CM_ERROR;
            break;
        }
        if (is_refresh) {
            node = dss_get_ft_node_by_ftid(vg_item, node->id, CM_TRUE, CM_TRUE);
            cm_panic(node != NULL);
            status = dss_refresh_dir_r(vg_item, node, CM_TRUE);
            if (status != CM_SUCCESS) {
                LOG_DEBUG_ERR("Failed to refesh dir vg:%s, dir name:%s, ftid:%llu, pid:%llu.", vg_item->vg_name,
                    node->name, *(uint64 *)&node->id, session->cli_info.cli_pid);
                break;
            }
        }
        status = dss_insert_open_file_index(
            vg_item, *(uint64 *)&node->id, session->cli_info.cli_pid, session->cli_info.start_time);
        if (status != CM_SUCCESS) {
            LOG_DEBUG_ERR("Failed to insert open file index vg:%s, ftid:%llu, pid:%llu.", vg_item->vg_name,
                *(uint64 *)&node->id, session->cli_info.cli_pid);
            break;
        }
        DSS_LOG_DEBUG_OP("Succeed to open dir:%s, fid:%llu.", dir_path, node->fid);
    } while (0);

    dss_unlock_vg_mem_and_shm(session, vg_item);
    return status;
}

void dss_close_dir(dss_session_t *session, char *vg_name, uint64 ftid)
{
    dss_vg_info_item_t *vg_item = dss_find_vg_item(vg_name);
    if (vg_item == NULL) {
        LOG_DEBUG_ERR("Failed to find vg, %s.", vg_name);
        return;
    }

    status_t status =
        dss_delete_open_file_index(vg_item, ftid, session->cli_info.cli_pid, session->cli_info.start_time);
    if (status != CM_SUCCESS) {
        LOG_DEBUG_ERR("Failed to delete open file index.");
        return;
    }
    DSS_LOG_DEBUG_OP("Succeed to close dir, ftid:%llu, session id:%u.", ftid, session->id);
}

int64 dss_get_fs_block_offset(dss_vg_info_item_t *vg_item, dss_block_id_t blockid)
{
    return dss_get_block_offset(vg_item, DSS_FILE_SPACE_BLOCK_SIZE, blockid.block, blockid.au);
}

void dss_init_fs_block_head(dss_fs_block_t *fs_block)
{
    CM_ASSERT(fs_block != NULL);
    dss_set_blockid(&fs_block->head.next, CM_INVALID_ID64);
    fs_block->head.used_num = 0;
    dss_set_blockid(&fs_block->bitmap[0], CM_INVALID_ID64);
}

status_t dss_alloc_fs_block_inter(
    dss_session_t *session, dss_vg_info_item_t *vg_item, bool32 check_version, char **block, ga_obj_id_t *out_obj_id)
{
    dss_fs_block_t *fs_block;

    // refresh core by caller for performance.
    dss_fs_block_root_t *root = DSS_GET_FS_BLOCK_ROOT(vg_item->dss_ctrl);
    dss_block_id_t block_id;
    block_id = root->free.first;
    fs_block = (dss_fs_block_t *)dss_find_block_in_shm(
        vg_item, block_id, DSS_BLOCK_TYPE_FS, check_version, out_obj_id, CM_FALSE);
    if (fs_block == NULL) {
        return CM_ERROR;
    }

    root->free.count--;
    root->free.first = fs_block->head.next;
    if (dss_cmp_blockid(root->free.first, CM_INVALID_ID64)) {
        CM_ASSERT(root->free.count == 0);
        dss_set_blockid(&root->free.last, CM_INVALID_ID64);
    }

    dss_init_fs_block_head(fs_block);

    *block = (char *)fs_block;

    dss_redo_alloc_fs_block_t redo;
    redo.id = block_id;
    redo.root = *root;
    dss_put_log(session, vg_item, DSS_RT_ALLOC_FS_BLOCK, &redo, sizeof(redo));
    DSS_LOG_DEBUG_OP("Alloc file space meta block,v:%u,au:%llu,block:%u,item:%u,free count:%llu, free first:%llu. ",
        block_id.volume, (uint64)block_id.au, block_id.block, block_id.item, root->free.count,
        DSS_ID_TO_U64(root->free.first));
    return CM_SUCCESS;
}

status_t dss_alloc_fs_block(dss_session_t *session, dss_vg_info_item_t *vg_item, char **block, ga_obj_id_t *out_obj_id,
    dss_alloc_fs_block_judge *judge)
{
    CM_ASSERT(vg_item != NULL);
    CM_ASSERT(block != NULL);
    status_t status;
    auid_t auid;
    // refresh core by caller for performance.
    dss_fs_block_root_t *root = DSS_GET_FS_BLOCK_ROOT(vg_item->dss_ctrl);

    if (root->free.count > 0) {
        bool32 check_version = CM_TRUE;
        if (!judge->is_extend) {
            if (judge->is_new_au) {  // new au do not check version.
                check_version = CM_FALSE;
            }
            judge->is_new_au = CM_FALSE;
        }
        status = dss_alloc_fs_block_inter(session, vg_item, check_version, block, out_obj_id);
    } else {
        status = dss_alloc_au(session, vg_item, &auid, judge->latch_ft_root);
        if (status != CM_SUCCESS) {
            LOG_DEBUG_ERR("Failed to allocate au from vg %s,%d.", vg_item->vg_name, status);
            return status;
        }

        status = dss_format_bitmap_node(session, vg_item, auid);
        if (status != CM_SUCCESS) {
            LOG_DEBUG_ERR(
                "Failed to format bitmap meta from vg %s,%u, %llu.", vg_item->vg_name, auid.volume, (uint64)auid.au);
            return status;
        }

        DSS_LOG_DEBUG_OP("Allocate au:%llu for file space.", DSS_ID_TO_U64(auid));
        // check version must be CM_FALSE, because the au is new.
        if (!judge->is_extend) {
            judge->is_new_au = CM_TRUE;
        }
        status = dss_alloc_fs_block_inter(session, vg_item, CM_FALSE, block, out_obj_id);
    }

    return status;
}

void dss_free_fs_block_addr(dss_session_t *session, dss_vg_info_item_t *vg_item, char *block, ga_obj_id_t obj_id)
{
    CM_ASSERT(vg_item != NULL);
    CM_ASSERT(block != NULL);

    dss_fs_block_t *fs_block;
    dss_fs_block_root_t *root = DSS_GET_FS_BLOCK_ROOT(vg_item->dss_ctrl);

    dss_block_id_t block_id;

    block_id = root->free.first;
    fs_block = (dss_fs_block_t *)block;
    fs_block->head.next = block_id;
    fs_block->head.common.version++;
    fs_block->head.common.checksum = dss_get_checksum(block, DSS_FILE_SPACE_BLOCK_SIZE);
    root->free.first = fs_block->head.id;
    if (dss_cmp_blockid(block_id, CM_INVALID_ID64)) {
        root->free.last = fs_block->head.id;
        CM_ASSERT(root->free.count == 0);
    }
    root->free.count++;
    CM_ASSERT(dss_cmp_blockid(root->free.first, CM_INVALID_ID64) == 0);

    dss_redo_free_fs_block_t redo;
    if (memcpy_s(redo.head, sizeof(redo.head), block, sizeof(redo.head)) != EOK) {
        cm_panic(0);
    }
    dss_put_log(session, vg_item, DSS_RT_FREE_FS_BLOCK, &redo, sizeof(redo));

    dss_update_core_ctrl(session, vg_item, &vg_item->dss_ctrl->core, 0, CM_TRUE);
    DSS_LOG_DEBUG_OP("Free file space meta block,v:%u,au:%llu,block:%u,item:%u, next:%llu,count:%llu. ",
        fs_block->head.id.volume, (uint64)fs_block->head.id.au, fs_block->head.id.block, fs_block->head.id.item,
        *(uint64 *)&fs_block->head.next, root->free.count);
}

status_t dss_init_file_fs_block(dss_session_t *session, dss_vg_info_item_t *vg_item, dss_block_id_t *block_id)
{
    char *block;
    dss_fs_block_t *fs_entry_block;
    dss_fs_block_header *block_header;
    ga_obj_id_t objid;

    status_t status = dss_check_refresh_core(vg_item);
    if (status != CM_SUCCESS) {
        LOG_DEBUG_ERR("Failed to check and refresh core, vg %s.", vg_item->vg_name);
        return CM_ERROR;
    }
    dss_alloc_fs_block_judge judge = {CM_FALSE, CM_FALSE, CM_FALSE};
    // allocate the first level bitmap block
    status = dss_alloc_fs_block(session, vg_item, &block, &objid, &judge);
    if (status != CM_SUCCESS) {
        return status;
    }
    fs_entry_block = (dss_fs_block_t *)block;

    status = dss_alloc_fs_block(session, vg_item, &block, NULL, &judge);
    if (status != CM_SUCCESS) {
        // NOTE:can not free fs block, let rollback do it.
        return status;
    }

    block_header = (dss_fs_block_header *)block;
    fs_entry_block->bitmap[0] = block_header->id;
    *block_id = ((dss_fs_block_header *)fs_entry_block)->id;
    fs_entry_block->head.used_num = 1;

    dss_redo_init_fs_block_t redo;
    redo.id = fs_entry_block->head.id;
    redo.index = 0;
    redo.second_id = block_header->id;
    redo.used_num = 1;
    dss_put_log(session, vg_item, DSS_RT_INIT_FILE_FS_BLOCK, &redo, sizeof(redo));

    DSS_LOG_DEBUG_OP(
        "dss_init_file_fs_block, id:%llu, id2:%llu.", DSS_ID_TO_U64(redo.id), DSS_ID_TO_U64(redo.second_id));
    return CM_SUCCESS;
}

status_t dss_exist_item(dss_session_t *session, const char *item, gft_item_type_t type, bool32 *result)
{
    CM_ASSERT(item != NULL);
    status_t status;
    gft_node_t *out_node = NULL;
    *result = CM_FALSE;
    dss_vg_info_item_t *vg_item = NULL;
    char name[DSS_MAX_NAME_LEN];
    CM_RETURN_IFERR(dss_find_vg_by_dir(item, name, &vg_item));
    dss_lock_vg_mem_and_shm_s(session, vg_item);

    status = CM_ERROR;
    do {
        DSS_BREAK_IF_ERROR(dss_check_file(vg_item));
        dss_check_dir_output_t output_info = {&out_node, NULL, NULL};
        status = dss_check_dir(item, type, &output_info, CM_FALSE);
        if (status != CM_SUCCESS) {
            if ((type == GFT_FILE && status == ERR_DSS_FILE_NOT_EXIST) ||
                (type == GFT_PATH && status == ERR_DSS_DIR_NOT_EXIST) ||
                (type == GFT_LINK && status == ERR_DSS_LINK_NOT_EXIST) || (status == ERR_DSS_FILE_TYPE_MISMATCH)) {
                LOG_DEBUG_INF("Reset error %d when check dir failed.", status);
                cm_reset_error();
            } else {
                LOG_DEBUG_ERR("Failed to check file dir or link,errcode:%d.", status);
                break;
            }
        }
        status = CM_SUCCESS;
    } while (0);

    *result = ((out_node == NULL) || (out_node->flags & DSS_FT_NODE_FLAG_DEL)) ? CM_FALSE : CM_TRUE;
    dss_unlock_vg_mem_and_shm(session, vg_item);
    return status;
}

static void dss_get_dir_path(char *dir_path, uint32 buf_size, const char *full_path)
{
    char *p = NULL;
    size_t path_len = strlen(full_path);
    errno_t ret = strncpy_s(dir_path, buf_size, full_path, path_len);
    if (ret != EOK) {
        DSS_THROW_ERROR(ERR_SYSTEM_CALL, (ret));
        return;
    }
    p = strrchr(dir_path, '/');
    if (p == NULL) {
        return;
    }
    *p = '\0';
}

static uint32_t dss_get_last_delimiter(const char *path, char delimiter)
{
    uint32_t len = (uint32_t)strlen(path);
    for (uint32_t i = len - 1; i > 0; i--) {
        if (path[i] == delimiter) {
            return i;
        }
    }
    return len;
}

static status_t dss_check_node_delete(gft_node_t *node)
{
    if (node->flags != DSS_FT_NODE_FLAG_DEL) {
        return CM_SUCCESS;
    }
    if (node->type == GFT_PATH) {
        DSS_THROW_ERROR(ERR_DSS_DIR_NOT_EXIST, node->name, "dss");
        LOG_DEBUG_ERR("dir: %s is deleted", node->name);
    } else if (node->type == GFT_FILE) {
        DSS_THROW_ERROR(ERR_DSS_FILE_NOT_EXIST, node->name, "dss");
        LOG_DEBUG_ERR("file: %s is deleted", node->name);
    } else {
        DSS_THROW_ERROR(ERR_DSS_LINK_NOT_EXIST, node->name, "dss");
        LOG_DEBUG_ERR("link: %s is deleted", node->name);
    }
    return CM_ERROR;
}

status_t dss_get_ftid_by_path(dss_session_t *session, const char *path, ftid_t *ftid, dss_vg_info_item_t **dir_vg_item)
{
    CM_ASSERT(path != NULL);
    dss_vg_info_item_t *vg_item = NULL;
    char name[DSS_MAX_NAME_LEN];
    CM_RETURN_IFERR(dss_find_vg_by_dir(path, name, &vg_item));
    dss_lock_vg_mem_and_shm_s(session, vg_item);
    gft_node_t *parent_node;
    gft_node_t *node;
    status_t status = CM_ERROR;
    char dir_path[DSS_FILE_PATH_MAX_LENGTH];

    do {
        DSS_BREAK_IF_ERROR(dss_check_file(vg_item));

        dss_get_dir_path(dir_path, DSS_FILE_PATH_MAX_LENGTH, path);
        dss_check_dir_output_t output_info = {&parent_node, dir_vg_item, NULL};
        if (dss_check_dir(dir_path, GFT_PATH, &output_info, CM_TRUE) != CM_SUCCESS) {
            if (cm_get_error_code() == ERR_DSS_DIR_NOT_EXIST) {
                LOG_DEBUG_ERR("dir path: %s not exist", dir_path);
                break;
            }
        }

        uint32_t pos = dss_get_last_delimiter(path, '/');
        DSS_BREAK_IF_ERROR(dss_get_name_from_path(path, &pos, name));
        if (name[0] == 0) {
            LOG_DEBUG_INF("get root node ftid");
            *ftid = parent_node->id;
            status = CM_SUCCESS;
            break;
        }

        node = dss_find_ft_node(*dir_vg_item, parent_node, name, CM_TRUE);
        if (node == NULL) {
            DSS_THROW_ERROR(ERR_DSS_FILE_NOT_EXIST, name, path);
            LOG_DEBUG_ERR("path: %s not exist", path);
            break;
        }
        DSS_BREAK_IF_ERROR(dss_check_node_delete(node));
        *ftid = node->id;
        LOG_DEBUG_INF("Success to get ftid[%llu] by path: %s", DSS_ID_TO_U64(*ftid), path);
        status = CM_SUCCESS;
    } while (0);

    dss_unlock_vg_mem_and_shm(session, vg_item);
    return status;
}

status_t dss_check_file(dss_vg_info_item_t *vg_item)
{
    status_t status = dss_check_refresh_ft(vg_item);
    if (status != CM_SUCCESS) {
        LOG_DEBUG_ERR("Failed to check and update file table %s.", vg_item->dss_ctrl->vg_info.vg_name);
        return status;
    }
    return CM_SUCCESS;
}

status_t dss_open_file_check_s(
    dss_session_t *session, const char *file, dss_vg_info_item_t **vg_item, gft_item_type_t type, gft_node_t **out_node)
{
    status_t status = dss_check_file(*vg_item);
    if (status != CM_SUCCESS) {
        LOG_DEBUG_ERR("Failed to check file, errcode:%d.", cm_get_error_code());
        return status;
    }
    dss_vg_info_item_t *file_vg_item;
    dss_check_dir_output_t output_info = {out_node, &file_vg_item, NULL};
    status = dss_check_dir(file, type, &output_info, CM_TRUE);
    if (status != CM_SUCCESS) {
        LOG_DEBUG_ERR("Failed to check dir when open file read, errcode: %d.", cm_get_error_code());
        return status;
    }
    if (file_vg_item->id != (*vg_item)->id) {
        dss_unlock_vg_mem_and_shm(session, *vg_item);
        *vg_item = file_vg_item;
        dss_lock_vg_mem_and_shm_s(session, *vg_item);
    }
    return CM_SUCCESS;
}

status_t dss_open_file_check(
    dss_session_t *session, const char *file, dss_vg_info_item_t **vg_item, gft_item_type_t type, gft_node_t **out_node)
{
    status_t status = dss_check_file(*vg_item);
    if (status != CM_SUCCESS) {
        LOG_DEBUG_ERR("Failed to check file,errcode:%d.", cm_get_error_code());
        return status;
    }
    dss_vg_info_item_t *file_vg_item;
    dss_check_dir_output_t output_info = {out_node, &file_vg_item, NULL};
    status = dss_check_dir(file, type, &output_info, CM_TRUE);
    if (status != CM_SUCCESS) {
        LOG_DEBUG_ERR("Failed to check dir when open file, errcode:%d.", cm_get_error_code());
        return status;
    }
    if (file_vg_item->id != (*vg_item)->id) {
        dss_unlock_vg_mem_and_shm(session, *vg_item);
        *vg_item = file_vg_item;
        dss_lock_vg_mem_and_shm_x(session, *vg_item);
    }
    return CM_SUCCESS;
}

static status_t dss_open_file_find_block_and_insert_index(
    dss_session_t *session, dss_vg_info_item_t *vg_item, gft_node_t *out_node)
{
    status_t status;
    if (dss_cmp_blockid(out_node->entry, CM_INVALID_ID64)) {
        LOG_DEBUG_ERR("Failed to open fs block,errcode:%d.", cm_get_error_code());
        cm_panic(0);
    }
    // check the entry and load
    char *entry_block = dss_find_block_in_shm(vg_item, out_node->entry, DSS_BLOCK_TYPE_FS, CM_TRUE, NULL, CM_FALSE);
    if (entry_block == NULL) {
        LOG_DEBUG_ERR("Failed to find block:%llu in cache.", DSS_ID_TO_U64(out_node->entry));
        return CM_ERROR;
    }

    status = dss_insert_open_file_index(
        vg_item, *(uint64 *)&out_node->id, session->cli_info.cli_pid, session->cli_info.start_time);
    if (status != CM_SUCCESS) {
        LOG_DEBUG_ERR("Failed to insert open file index.");
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

status_t dss_open_file_core(dss_session_t *session, const char *path, uint32 type, gft_node_t **out_node)
{
    CM_ASSERT(path != NULL);
    dss_vg_info_item_t *vg_item = NULL;
    char name[DSS_MAX_NAME_LEN];
    CM_RETURN_IFERR(dss_find_vg_by_dir(path, name, &vg_item));
    dss_lock_vg_mem_and_shm_s(session, vg_item);
    status_t status = dss_open_file_check_s(session, path, &vg_item, type, out_node);
    if (status != CM_SUCCESS) {
        dss_unlock_vg_mem_and_shm(session, vg_item);
        return CM_ERROR;
    }
    if (*out_node == NULL) {
        dss_unlock_vg_mem_and_shm(session, vg_item);
        cm_panic(0);
    }

    if (((*out_node)->flags & DSS_FT_NODE_FLAG_DEL) && ((*out_node)->type == GFT_FILE)) {
        DSS_THROW_ERROR(ERR_DSS_FILE_NOT_EXIST, path, "dss");
        dss_unlock_vg_mem_and_shm(session, vg_item);
        return CM_ERROR;
    }

    status = dss_open_file_find_block_and_insert_index(session, vg_item, *out_node);
    if (status != CM_SUCCESS) {
        dss_rollback_mem_update(session->log_split, vg_item);
        dss_unlock_vg_mem_and_shm(session, vg_item);
        return CM_ERROR;
    }

    status = dss_process_redo_log(session, vg_item);
    if (status != CM_SUCCESS) {
        dss_unlock_vg_mem_and_shm(session, vg_item);
        LOG_RUN_ERR("[DSS API] ABORT INFO : redo log process failed, errcode:%d, OS errno:%d, OS errmsg:%s.",
            cm_get_error_code(), errno, strerror(errno));
        cm_fync_logfile();
        _exit(1);
    }
    dss_unlock_vg_mem_and_shm(session, vg_item);
    return CM_SUCCESS;
}

status_t dss_open_file(dss_session_t *session, const char *file, int32_t flag)
{
    DSS_LOG_DEBUG_OP("Begin to open file:%s, session id:%u.", file, session->id);
    gft_node_t *out_node = NULL;
    CM_RETURN_IFERR(dss_open_file_core(session, file, GFT_FILE, &out_node));
    uint64 fid = out_node->fid;
    DSS_LOG_DEBUG_OP("Succeed to open file:%s, fid:%llu, session id:%u.", file, fid, session->id);
    return CM_SUCCESS;
}

static status_t dss_open_link_core(
    dss_session_t *session, dss_vg_info_item_t **vg_item, const char *path, uint32 type, gft_node_t **out_node)
{
    CM_ASSERT(path != NULL);
    status_t status = dss_open_file_check_s(session, path, vg_item, type, out_node);
    if (status != CM_SUCCESS) {
        return CM_ERROR;
    }
    if (*out_node == NULL) {
        cm_panic(0);
    }
    return dss_open_file_find_block_and_insert_index(session, *vg_item, *out_node);
}

static status_t dss_open_link(
    dss_session_t *session, const char *link_path, dss_vg_info_item_t **vg_item, gft_node_t **out_node)
{
    char name[DSS_MAX_NAME_LEN];

    DSS_RETURN_IF_ERROR(dss_find_vg_by_dir(link_path, name, vg_item));
    DSS_RETURN_IF_ERROR(dss_open_link_core(session, vg_item, link_path, GFT_LINK, out_node));
    DSS_LOG_DEBUG_OP("Succeed to open link: %s, fid: %llu, session id: %u, entry: %llu.", link_path, (*out_node)->fid,
        session->id, DSS_ID_TO_U64((*out_node)->entry));
    return CM_SUCCESS;
}

gft_node_t *dss_find_parent_node_r(dss_vg_info_item_t *vg_item, gft_node_t *parent_node, gft_node_t *find_node)
{
    ftid_t id = parent_node->items.first;
    if (dss_cmp_auid(id, DSS_INVALID_ID64)) {
        LOG_DEBUG_INF("dir: %s is empty", parent_node->name);
        return NULL;
    }
    LOG_DEBUG_INF("dir: %s has %u items", parent_node->name, parent_node->items.count);
    for (uint32 i = 0; i < parent_node->items.count; i++) {
#ifdef OPENGAUSS
        if (dss_cmp_blockid(id, CM_INVALID_ID64)) {
            // openGauss may be find uncommitted node when standby
            LOG_DEBUG_INF("Get invalid id in parent name:%s, id:%llu, count:%u, when find parent node, children "
                          "name:%s, index:%u.",
                parent_node->name, *(uint64 *)&parent_node->id, parent_node->items.count, find_node->name, i);
            return NULL;
        }
#endif
        gft_node_t *cur_node = dss_get_ft_node_by_ftid(vg_item, id, CM_FALSE, CM_FALSE);
        if (cur_node == NULL) {
            LOG_DEBUG_ERR("Can not get node:%llu.", *(uint64 *)&id);
            return NULL;
        }
        if (cur_node->type == GFT_PATH) {
            if (cur_node->flags & DSS_FT_NODE_FLAG_SYSTEM) {
                id = cur_node->next;
                continue;
            }
            gft_node_t *tmp = dss_find_parent_node_r(vg_item, cur_node, find_node);
            if (tmp != NULL) {
                return tmp;
            }
        }
        if (compare_auid(id, find_node->id)) {
            DSS_LOG_DEBUG_OP("node[%s]: %llu find parent node[%s]: %llu", find_node->name, DSS_ID_TO_U64(find_node->id),
                parent_node->name, DSS_ID_TO_U64(parent_node->id));
            return parent_node;
        }
        id = cur_node->next;
        if (dss_cmp_auid(id, DSS_INVALID_ID64)) {
            return NULL;
        }
    }
    return NULL;
}

gft_node_t *dss_find_parent_node_by_node(dss_vg_info_item_t *vg_item, gft_node_t *node)
{
    CM_ASSERT(node != NULL);

    gft_node_t *root_node = dss_find_ft_node(vg_item, NULL, vg_item->vg_name, CM_TRUE);
    if (root_node == NULL) {
        LOG_DEBUG_ERR("Failed to get the root node %s.", vg_item->vg_name);
        cm_panic(0);
    }
    gft_node_t *parent_node = dss_find_parent_node_r(vg_item, root_node, node);
    return parent_node;
}

status_t dss_close_file(dss_session_t *session, dss_vg_info_item_t *vg_item, uint64 ftid)
{
    status_t status =
        dss_delete_open_file_index(vg_item, ftid, session->cli_info.cli_pid, session->cli_info.start_time);
    if (status != CM_SUCCESS) {
        LOG_DEBUG_ERR("Failed to delete open file index.");
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

status_t dss_check_rm_file(dss_vg_info_item_t *vg_item, ftid_t ftid, bool32 *should_rm_file, gft_node_t **file_node)
{
    CM_ASSERT(should_rm_file != NULL);

    *file_node = dss_get_ft_node_by_ftid(vg_item, ftid, CM_TRUE, CM_FALSE);
    if (*file_node == NULL) {
        *should_rm_file = DSS_FALSE;
        DSS_LOG_DEBUG_OP("Nothing need to remove when close file ftid%llu, vg: %s, v:%u, au:%llu, block:%u, item:%u.",
            *(uint64 *)&ftid, vg_item->vg_name, ftid.volume, (uint64)ftid.au, ftid.block, ftid.item);
        return CM_SUCCESS;
    }
    if (((*file_node)->flags & DSS_FT_NODE_FLAG_DEL) == 0) {
        *should_rm_file = DSS_FALSE;
        DSS_LOG_DEBUG_OP("file: %s is not deleted", (*file_node)->name);
        return CM_SUCCESS;
    }

    bool32 is_open;
    status_t status = dss_check_open_file(vg_item, *(uint64 *)&(*file_node)->id, &is_open);
    if (status != CM_SUCCESS) {
        LOG_DEBUG_ERR(
            "Failed to check open file, file: %s ftid:%llu.", (*file_node)->name, *(uint64 *)&(*file_node)->id);
        return CM_ERROR;
    }
    if (is_open) {
        *should_rm_file = DSS_FALSE;
        LOG_DEBUG_ERR("file %s is open, ftid:%llu.", (*file_node)->name, *(uint64 *)&(*file_node)->id);
        return CM_SUCCESS;
    }
    DSS_LOG_DEBUG_OP("The file: %s has been deleted and is not opened locally.", (*file_node)->name);
    *should_rm_file = DSS_TRUE;
    return CM_SUCCESS;
}

static void dss_init_ft_node(
    dss_ft_block_t *ft_block, gft_node_t *first_node, gft_root_t *gft, uint32_t block_id, auid_t auid)
{
    gft_node_t *node;
    for (uint32 i = 0; i < ft_block->node_num; i++) {
        node = &first_node[i];
        if (i != 0) {
            node->prev = auid;
            node->prev.block = block_id;
            node->prev.item = (uint16)i - 1;
        }
        node->id = auid;
        node->id.block = block_id;
        node->id.item = i;

        if (i == ft_block->node_num - 1) {
            gft->free_list.last = auid;
            gft->free_list.last.block = block_id;
            gft->free_list.last.item = i;
            dss_set_auid(&node->next, DSS_INVALID_64);
        } else {
            node->next = auid;
            node->next.block = block_id;
            node->next.item = (uint16)i + 1;
        }
    }
}

status_t dss_init_ft_block(dss_vg_info_item_t *vg_item, char *block, uint32_t block_id, auid_t auid)
{
    char *root = vg_item->dss_ctrl->root;
    gft_root_t *gft = &((dss_root_ft_block_t *)(root))->ft_root;

    dss_ft_block_t *ft_block = (dss_ft_block_t *)block;
    ft_block->node_num = (DSS_BLOCK_SIZE - sizeof(dss_ft_block_t)) / sizeof(gft_node_t);
    ft_block->id = auid;
    ft_block->id.block = block_id;
    ft_block->common.type = DSS_BLOCK_TYPE_FT;

    gft_node_t *first_node = (gft_node_t *)(block + sizeof(dss_ft_block_t));
    gft_node_t *node;
    gft_node_t *last_node = NULL;
    if (ft_block->node_num > 0) {
        node = &first_node[0];
        node->prev = gft->free_list.last;
        bool32 cmp = dss_cmp_auid(gft->free_list.last, DSS_INVALID_64);
        if (!cmp) {
            last_node = dss_get_ft_node_by_ftid(vg_item, gft->free_list.last, CM_FALSE, CM_FALSE);
            if (last_node == NULL) {
                LOG_DEBUG_ERR("Failed to get file table node:%llu.", DSS_ID_TO_U64(gft->free_list.last));
                return CM_ERROR;
            }

            last_node->next = auid;
            last_node->next.block = block_id;
            last_node->next.item = 0;
        }
    }
    dss_init_ft_node(ft_block, first_node, gft, block_id, auid);
    gft->free_list.count = gft->free_list.count + ft_block->node_num;
    if (dss_cmp_auid(gft->free_list.first, DSS_INVALID_64)) {
        gft->free_list.first = auid;
        gft->free_list.first.block = block_id;
        gft->free_list.first.item = 0;
    }
    DSS_LOG_DEBUG_OP("dss_init_ft_block blockid:%llu.", DSS_ID_TO_U64(ft_block->id));
    return CM_SUCCESS;
}

void dss_init_bitmap_block(dss_ctrl_t *dss_ctrl, char *block, uint32_t block_id, auid_t auid)
{
    dss_fs_block_root_t *block_root = DSS_GET_FS_BLOCK_ROOT(dss_ctrl);
    dss_fs_block_header *fs_block = (dss_fs_block_header *)block;
    if (memset_s(fs_block, DSS_FILE_SPACE_BLOCK_SIZE, -1, DSS_FILE_SPACE_BLOCK_SIZE) != EOK) {
        cm_panic(0);
    }
    fs_block->common.type = DSS_BLOCK_TYPE_FS;
    fs_block->common.version = 0;
    fs_block->used_num = 0;
    fs_block->total_num = (DSS_FILE_SPACE_BLOCK_SIZE - sizeof(dss_fs_block_header)) / sizeof(uint64);
    fs_block->id.au = auid.au;
    fs_block->id.volume = auid.volume;
    fs_block->id.block = block_id;
    fs_block->id.item = 0;

    block_root->free.count++;
    dss_block_id_t first = block_root->free.first;
    block_root->free.first = fs_block->id;
    fs_block->next = first;

    bool32 cmp = dss_cmp_auid(block_root->free.last, DSS_INVALID_64);
    if (cmp) {
        block_root->free.last = fs_block->id;
    }
    LOG_DEBUG_INF("Init bitmap block, free count:%llu, first:%llu, id:%llu.", block_root->free.count,
        DSS_ID_TO_U64(first), DSS_ID_TO_U64(fs_block->id));
}

status_t dss_update_au_disk(
    dss_vg_info_item_t *vg_item, auid_t auid, ga_pool_id_e pool_id, uint32 first, uint32 count, uint32 size)
{
    CM_ASSERT(vg_item != NULL);
    status_t status;
    char *buf;
    CM_ASSERT(vg_item->volume_handle[auid.volume].handle != DSS_INVALID_HANDLE);
    int64_t offset = dss_get_au_offset(vg_item, auid);
    int64_t block_offset = offset;
    uint32 obj_id = first;
    for (uint32 i = 0; i < count; i++) {
        buf = ga_object_addr(pool_id, obj_id);

        dss_common_block_t *block = (dss_common_block_t *)buf;
        block->checksum = dss_get_checksum(buf, size);
        LOG_DEBUG_INF("dss_update_au_disk checksum:%u,%llu,%u.", block->checksum, DSS_ID_TO_U64(auid), i);

        block_offset = offset + i * size;
        status = dss_write_volume_inst(vg_item, &vg_item->volume_handle[auid.volume], block_offset, buf, size);
        if (status != CM_SUCCESS) {
            return status;
        }
        obj_id = ga_next_object(pool_id, obj_id);
    }
    return CM_SUCCESS;
}

status_t dss_format_ft_node_core(dss_vg_info_item_t *vg_item, ga_queue_t queue, auid_t auid, gft_root_t *gft)
{
    status_t status = CM_SUCCESS;
    uint32 rollback_count = 0;
    uint32 block_num = (uint32)DSS_GET_FT_BLOCK_NUM_IN_AU(vg_item->dss_ctrl);
    uint32 obj_id = queue.first;
    ga_obj_id_t ga_obj_id = {.pool_id = GA_8K_POOL, .obj_id = 0};
    gft_list_t bk_list = gft->free_list;
    dss_ft_block_t *block = (dss_ft_block_t *)dss_get_ft_block_by_ftid(vg_item, gft->last);
    block->next = auid;
    for (uint32 i = 0; i < block_num; i++) {
        block = (dss_ft_block_t *)ga_object_addr(GA_8K_POOL, obj_id);
        errno_t err = memset_sp((char *)block, DSS_BLOCK_SIZE, 0, DSS_BLOCK_SIZE);
        cm_panic(err == EOK);
        block->id = auid;
        block->id.block = i;
        if (i != block_num - 1) {
            block->next = auid;
            block->next.block = i + 1;

            gft->last = block->id;
        } else {
            dss_set_blockid(&block->next, CM_INVALID_ID64);
        }

        ga_obj_id.obj_id = obj_id;
        do {
            status = dss_register_buffer_cache(
                vg_item, &block->id, ga_obj_id, (dss_block_ctrl_t *)((char *)block + DSS_BLOCK_SIZE));
            if (status != CM_SUCCESS) {
                rollback_count = i;
                LOG_DEBUG_ERR("Failed to register block:%llu.", DSS_ID_TO_U64(block->id));
                break;
            }

            status = dss_init_ft_block(vg_item, (char *)block, i, auid);
            if (status != CM_SUCCESS) {
                rollback_count = i + 1;
                LOG_DEBUG_ERR("Failed to initialize block:%llu.", DSS_ID_TO_U64(block->id));
                break;
            }
        } while (0);
        if (status != CM_SUCCESS) {
            for (uint32 j = 0; j < rollback_count; ++j) {
                dss_block_id_t block_id = auid;
                block_id.block = j;
                dss_unregister_buffer_cache(vg_item, block_id);
            }
            ga_free_object_list(GA_8K_POOL, &queue);
            gft->free_list = bk_list;  // rollback free_list
            LOG_DEBUG_ERR("Rollback the format ft node when fail, i:%u.", i);
            return status;
        }

        obj_id = ga_next_object(GA_8K_POOL, obj_id);
    }
    return CM_SUCCESS;
}

status_t dss_format_ft_node(dss_session_t *session, dss_vg_info_item_t *vg_item, auid_t auid)
{
    CM_ASSERT(vg_item != NULL);
    dss_ctrl_t *dss_ctrl = vg_item->dss_ctrl;
    char *root = dss_ctrl->root;
    dss_root_ft_block_t *ft_block = (dss_root_ft_block_t *)(root);
    gft_root_t *gft = &ft_block->ft_root;
    status_t status = CM_SUCCESS;

    gft_list_t bk_list = gft->free_list;
    uint32 block_num = (uint32)DSS_GET_FT_BLOCK_NUM_IN_AU(dss_ctrl);
    ga_queue_t queue;
    status = ga_alloc_object_list(GA_8K_POOL, block_num, &queue);
    if (status != CM_SUCCESS) {
        LOG_DEBUG_ERR("Failed to alloc object list, block_num:%u.", block_num);
        return status;
    }

    dss_block_id_t old_last = gft->last;
    status = dss_format_ft_node_core(vg_item, queue, auid, gft);
    if (status != CM_SUCCESS) {
        return status;
    }

    dss_redo_format_ft_t redo;
    redo.auid = auid;
    redo.obj_id = queue.first;
    redo.count = block_num;
    redo.old_last_block = old_last;
    redo.old_free_list = bk_list;
    dss_put_log(session, vg_item, DSS_RT_FORMAT_AU_FILE_TABLE, &redo, sizeof(dss_redo_format_ft_t));

#ifdef DB_DEBUG_VERSION
    DSS_TEST_ROLLBACK2(ERR_DSS_NO_SPACE);
#endif
    return CM_SUCCESS;
}

status_t dss_format_bitmap_node(dss_session_t *session, dss_vg_info_item_t *vg_item, auid_t auid)
{
    dss_ctrl_t *dss_ctrl = vg_item->dss_ctrl;
    status_t status;

    dss_fs_block_root_t *block_root = DSS_GET_FS_BLOCK_ROOT(dss_ctrl);
    dss_fs_block_list_t bk_list = block_root->free;
    dss_fs_block_header *block;
    uint32 block_num = (uint32)DSS_GET_FS_BLOCK_NUM_IN_AU(dss_ctrl);
    ga_queue_t queue;
    status = ga_alloc_object_list(GA_16K_POOL, block_num, &queue);
    if (status != CM_SUCCESS) {
        LOG_DEBUG_ERR("Failed to alloc object list, block num is %u.", block_num);
        return status;
    }
    uint32 obj_id = queue.first;
    ga_obj_id_t ga_obj_id;
    ga_obj_id.pool_id = GA_16K_POOL;
    for (uint32 i = 0; i < block_num; i++) {
        block = (dss_fs_block_header *)ga_object_addr(GA_16K_POOL, obj_id);
        block->id = auid;
        block->id.block = i;
        block->id.item = 0;
        ga_obj_id.obj_id = obj_id;

        status = dss_register_buffer_cache(
            vg_item, &block->id, ga_obj_id, (dss_block_ctrl_t *)((char *)block + DSS_FILE_SPACE_BLOCK_SIZE));
        if (status != CM_SUCCESS) {
            LOG_DEBUG_ERR("Failed to register block, block id is %llu, obj is is %u.", *(uint64 *)&block->id, obj_id);
            return status;
        }

        dss_init_bitmap_block(dss_ctrl, (char *)block, i, auid);
        obj_id = ga_next_object(GA_16K_POOL, obj_id);
    }

    dss_redo_format_fs_t redo;
    redo.auid = auid;
    redo.count = block_num;
    redo.old_free_list = bk_list;
    dss_put_log(session, vg_item, DSS_RT_FORMAT_AU_FILE_SPACE, &redo, sizeof(dss_redo_format_fs_t));

    return CM_SUCCESS;
}

static void format_ft_block_when_create_vg(
    dss_vg_info_item_t *vg_item, gft_list_t *plist, dss_ft_block_t *block, uint32 index, auid_t auid)
{
    uint32 blk_count = (uint32)DSS_GET_FT_BLOCK_NUM_IN_AU(vg_item->dss_ctrl);
    uint32 item_count = (DSS_BLOCK_SIZE - sizeof(dss_ft_block_t)) / sizeof(gft_node_t);
    gft_node_t *node = NULL;

    block->common.type = DSS_BLOCK_TYPE_FT;
    block->node_num = item_count;

    for (uint32 j = 0; j < item_count; j++) {
        node = (gft_node_t *)((char *)block + sizeof(dss_ft_block_t) + sizeof(gft_node_t) * j);
        node->id = auid;
        node->id.block = index;
        node->id.item = j;

        // set the prev ftid_t
        if (j == 0) {
            if (index == 0) {
                *(uint64 *)(&node->prev) = DSS_INVALID_64;
            } else {
                // the prev ft block
                node->prev = auid;
                node->prev.block = index - 1;
                node->prev.item = item_count - 1;
            }
        } else {
            // the same ft block
            node->prev = auid;
            node->prev.block = index;
            node->prev.item = j - 1;
        }

        // set the next ftid_t
        if (j == item_count - 1) {
            if (index == blk_count - 1) {
                *(uint64 *)(&node->next) = DSS_INVALID_64;
            } else {
                // the next ft block
                node->next = auid;
                node->next.block = index + 1;
                node->next.item = 0;
            }
        } else {
            // the same ft block
            node->next = auid;
            node->next.block = index;
            node->next.item = j + 1;
        }

        // add to gft node free list
        if (*(uint64 *)(&plist->first) == DSS_INVALID_64) {
            plist->first = node->id;
        }
        plist->last = node->id;
        plist->count++;
    }
}

/*
 * NOTE: this function is used only in creating vg.
 * you can't use block memory cache and must flush block to disk manually.
 */
static status_t format_ft_au_when_create_vg(dss_vg_info_item_t *vg_item, auid_t auid)
{
    status_t status;
    dss_ctrl_t *dss_ctrl = vg_item->dss_ctrl;
    uint64 au_size = dss_get_vg_au_size(dss_ctrl);
    char *au_buf = (char *)cm_malloc_align(DSS_DISK_UNIT_SIZE, (uint32)au_size);
    if (au_buf == NULL) {
        LOG_DEBUG_ERR("Failed to alloc %d memory", (int32)au_size);
        return CM_ERROR;
    }
    int64 offset;
    dss_ft_block_t *block = NULL;
    errno_t err = memset_sp(au_buf, au_size, 0, au_size);
    if (err != EOK) {
        free(au_buf);
        LOG_DEBUG_ERR("Failed to memset: %d", err);
        return CM_ERROR;
    }

    uint32 blk_count = (uint32)DSS_GET_FT_BLOCK_NUM_IN_AU(dss_ctrl);

    gft_list_t new_list;
    new_list.count = 0;
    *(uint64 *)&new_list.first = DSS_INVALID_64;
    *(uint64 *)&new_list.last = DSS_INVALID_64;

    for (uint32 i = 0; i < blk_count; i++) {
        block = (dss_ft_block_t *)(au_buf + (i * DSS_BLOCK_SIZE));
        block->id = auid;
        block->id.block = i;

        // set ft block next
        if (i == blk_count - 1) {
            *(uint64 *)(&block->next) = DSS_INVALID_64;
        } else {
            block->next = auid;
            block->next.block = i + 1;
        }
        format_ft_block_when_create_vg(vg_item, &new_list, block, i, auid);
        block->common.version++;
        block->common.checksum = dss_get_checksum(block, DSS_BLOCK_SIZE);
    }

    dss_root_ft_block_t *root_ft = DSS_GET_ROOT_BLOCK(dss_ctrl);
    gft_root_t *root_gft = &root_ft->ft_root;
    root_ft->ft_block.next = ((dss_ft_block_t *)au_buf)->id;                       // first block
    root_gft->last = ((dss_ft_block_t *)(au_buf + au_size - DSS_BLOCK_SIZE))->id;  // last block

    // link the gft_node and free_list
    if (root_gft->free_list.count == 0) {
        root_gft->free_list = new_list;
    } else {
        ftid_t last_id = root_gft->free_list.last;
        CM_ASSERT(last_id.volume == 0 && last_id.au == 0 && last_id.block == 0);

        // skip dss_root_ft_block_t header
        gft_node_t *last_node =
            (gft_node_t *)((char *)root_ft + sizeof(dss_root_ft_block_t) + sizeof(gft_node_t) * last_id.item);
        gft_node_t *new_list_first_node = (gft_node_t *)au_buf;

        last_node->next = new_list_first_node->id;
        new_list_first_node->prev = last_node->id;
        root_gft->free_list.last = new_list.last;
        root_gft->free_list.count += new_list.count;
    }
    // flush ft block to disk manually
    block = (dss_ft_block_t *)(au_buf);
    offset = dss_get_ft_block_offset(vg_item, block->id);
    status = dss_check_write_volume(vg_item, block->id.volume, offset, au_buf, (uint32)au_size);
    if (status != CM_SUCCESS) {
        free(au_buf);
        return status;
    }
    status = dss_update_ft_root(vg_item);
    free(au_buf);
    return status;
}

status_t dss_alloc_ft_au(dss_session_t *session, dss_vg_info_item_t *vg_item, ftid_t *id)
{
    CM_ASSERT(vg_item != NULL);
    CM_ASSERT(id != NULL);
    status_t status;

    status = dss_alloc_au(session, vg_item, id, CM_TRUE);
    if (status != CM_SUCCESS) {
        LOG_DEBUG_ERR("Failed allocate au for file table from vg:%s.", vg_item->vg_name);
        return status;
    }

    dss_au_root_t *au_root = DSS_GET_AU_ROOT(vg_item->dss_ctrl);
    if (au_root->free_root == DSS_INVALID_64) {
        /* when we are creating vg, .recycle directory hasn't been initialized yet! */
        status = format_ft_au_when_create_vg(vg_item, *(auid_t *)id);
    } else {
        CM_ASSERT(session != NULL);
        status = dss_format_ft_node(session, vg_item, *id);
    }

    if (status != CM_SUCCESS) {
        LOG_DEBUG_ERR("Failed format au:%llu file table from vg:%s.", DSS_ID_TO_U64(*id), vg_item->vg_name);
    }
    return status;
}

void dss_init_alloc_ft_node(gft_root_t *gft, gft_node_t *node, uint32 flags, gft_node_t *parent_node)
{
    node->create_time = cm_current_time();
    node->update_time = node->create_time;
    node->size = 0;
    node->written_size = 0;
    node->prev = parent_node->items.last;
    node->fid = gft->fid++;
    node->flags = flags;
    dss_set_auid(&node->next, CM_INVALID_ID64);
}

void dss_set_ft_node(dss_session_t *session, dss_vg_info_item_t *vg_item, gft_node_t *parent_node, gft_node_t *node,
    gft_root_t *gft, gft_node_t *prev_node)
{
    dss_redo_alloc_ft_node_t redo_node;
    uint16 i = 0;
    redo_node.node[i++] = *node;
    if (prev_node != NULL) {
        redo_node.node[i] = *prev_node;
    } else {
        dss_set_auid(&redo_node.node[i].id, CM_INVALID_ID64);
    }
    i++;
    redo_node.node[i] = *parent_node;

    redo_node.ft_root = *gft;
    dss_put_log(session, vg_item, DSS_RT_ALLOC_FILE_TABLE_NODE, &redo_node, sizeof(dss_redo_alloc_ft_node_t));
    char *prev_name;
    if (prev_node) {
        prev_name = prev_node->name;
    } else {
        prev_name = "NULL";
    }
    DSS_LOG_DEBUG_OP(
        "Alloc ft node, type:%u, name:%s, prev name:%s, volume:%u, au:%llu, block:%u, item:%u, free count:%u.",
        node->type, node->name, prev_name, node->id.volume, (uint64)node->id.au, node->id.block, node->id.item,
        gft->free_list.count);
}

void dss_ft_node_link_list(dss_session_t *session, dss_vg_info_item_t *vg_item, gft_node_t *parent_node, ftid_t id,
    gft_node_t *node, gft_root_t *gft)
{
    gft_node_t *prev_node = NULL;
    bool32 cmp = dss_cmp_auid(parent_node->items.last, CM_INVALID_ID64);
    if (!cmp) {
        /*
         * when current thread modify prev_node's next pointer,
         * another thread may be modify prev_node's size by extend space
         * so here we need file lock to avoid concurrency scenario.
         */
        prev_node = dss_get_ft_node_by_ftid(vg_item, parent_node->items.last, CM_TRUE, CM_FALSE);
        if (prev_node != NULL) {
            prev_node->next = id;
        }
    }

    parent_node->items.count++;
    parent_node->items.last = id;
    cmp = dss_cmp_auid(parent_node->items.first, CM_INVALID_ID64);
    if (cmp) {
        parent_node->items.first = id;
    }

    dss_set_ft_node(session, vg_item, parent_node, node, gft, prev_node);
}

/*
 * NOTE: this function is called only in creating vg.
 * because there is no block buffer for use, you can't call dss_find_block_in_mem
 * or ga_alloc_object_list, redo log etc. You must flush buffer to disk manually.
 */
gft_node_t *dss_alloc_ft_node_when_create_vg(
    dss_vg_info_item_t *vg_item, gft_node_t *parent_node, const char *name, gft_item_type_t type, uint32 flags)
{
    CM_ASSERT(vg_item != NULL);
    CM_ASSERT(parent_node != NULL);
    CM_ASSERT(name != NULL);
    /* parent_node must be the root directory */
    CM_ASSERT(parent_node->id.au == 0 && parent_node->id.block == 0 && parent_node->id.item == 0);

    status_t status;
    ftid_t id;
    dss_ctrl_t *dss_ctrl = vg_item->dss_ctrl;
    char *root = dss_ctrl->root;
    dss_root_ft_block_t *ft_block = (dss_root_ft_block_t *)(root);
    gft_root_t *gft = &ft_block->ft_root;
    if (gft->free_list.count == 0) {
        status = dss_alloc_ft_au(NULL, vg_item, &id);
        if (status != CM_SUCCESS) {
            LOG_DEBUG_ERR("Failed to allocate au when allocating file table node.");
            return NULL;
        }
        DSS_LOG_DEBUG_OP("Succeed to allocate au:%llu when allocating file table node.", DSS_ID_TO_U64(id));
    }

    id = gft->free_list.first;
    char *buf = (char *)cm_malloc_align(DSS_DISK_UNIT_SIZE, DSS_BLOCK_SIZE);
    if (buf == NULL) {
        return NULL;
    }

    /* read ft block from disk, because there's no cache in hands */
    dss_block_id_t block_id = id;
    block_id.item = 0;
    int64 offset = dss_get_block_offset(vg_item, DSS_BLOCK_SIZE, block_id.block, block_id.au);
    if (dss_get_block_from_disk(vg_item, block_id, buf, offset, DSS_BLOCK_SIZE, CM_TRUE) != CM_SUCCESS) {
        free(buf);
        LOG_DEBUG_ERR("Failed to load ft block volume:%llu, au:%llu, block:%llu.", (uint64)block_id.volume,
            (uint64)block_id.au, (uint64)block_id.block);
        return NULL;
    }
    gft_node_t *node = (gft_node_t *)(buf + sizeof(dss_ft_block_t) + sizeof(gft_node_t) * id.item);

    gft->free_list.first = node->next;
    bool32 cmp = dss_cmp_auid(gft->free_list.first, CM_INVALID_ID64);
    if (cmp) {
        gft->free_list.last = gft->free_list.first;
    }
    gft->free_list.count--;

    node->type = type;
    if (type == GFT_PATH) {
        node->items.count = 0;
        dss_set_auid(&node->items.first, CM_INVALID_ID64);
        dss_set_auid(&node->items.last, CM_INVALID_ID64);
    } else {
        /* file or link */
        dss_set_blockid(&node->entry, CM_INVALID_ID64);
    }
    if (strcpy_s(node->name, sizeof(node->name), name) != EOK) {
        cm_panic(0);
    }
    dss_init_alloc_ft_node(gft, node, flags, parent_node);

    parent_node->items.first = node->id;
    parent_node->items.last = node->id;
    parent_node->items.count = 1;

    do {
        /* flush ft block to disk manually */
        status = dss_update_ft_block_disk(vg_item, (dss_ft_block_t *)buf, id);
        DSS_BREAK_IF_ERROR(status);
        status = dss_update_ft_root(vg_item);  // parent_node must be root directory like `+data`
    } while (0);

    free(buf);
    return (status == CM_SUCCESS) ? node : NULL;
}

status_t dss_init_ft_node_entry(dss_session_t *session, dss_vg_info_item_t *vg_item, gft_node_t *node)
{
    dss_block_id_t block_id = {0};
    status_t status = dss_init_file_fs_block(session, vg_item, &block_id);
    if (status != CM_SUCCESS) {
        LOG_DEBUG_ERR("Failed to initialize the file space bitmap.");
        return status;
    }
    node->entry = block_id;
    return CM_SUCCESS;
}

status_t dss_alloc_ft_au_when_no_free(
    dss_session_t *session, dss_vg_info_item_t *vg_item, gft_root_t *gft, bool32 *check_version)
{
    if (gft->free_list.count == 0) {
        ftid_t id;
        status_t status = dss_alloc_ft_au(session, vg_item, &id);
        DSS_RETURN_IFERR2(status, LOG_DEBUG_ERR("Failed to allocate au when allocating file table node."));
        *check_version = CM_FALSE;
        DSS_LOG_DEBUG_OP("Succeed to allocate au:%llu when allocating file table node.", DSS_ID_TO_U64(id));
    }
    return CM_SUCCESS;
}

gft_node_t *dss_alloc_ft_node(dss_session_t *session, dss_vg_info_item_t *vg_item, gft_node_t *parent_node,
    const char *name, gft_item_type_t type)
{
    CM_ASSERT(vg_item != NULL);
    CM_ASSERT(parent_node != NULL);
    CM_ASSERT(name != NULL);
    status_t status;
    ftid_t id;
    dss_ctrl_t *dss_ctrl = vg_item->dss_ctrl;
    char *root = dss_ctrl->root;
    dss_root_ft_block_t *ft_block = (dss_root_ft_block_t *)(root);
    gft_root_t *gft = &ft_block->ft_root;
    bool32 check_version = CM_TRUE;

    status = dss_alloc_ft_au_when_no_free(session, vg_item, gft, &check_version);
    if (status != CM_SUCCESS) {
        return NULL;
    }
    id = gft->free_list.first;
    gft_node_t *node = dss_get_ft_node_by_ftid(vg_item, id, check_version, CM_FALSE);
    if (node == NULL) {
        LOG_DEBUG_ERR("Failed to get file table node when allocating file table node.");
        return NULL;
    }
    node->type = type;
    if (strcpy_s(node->name, sizeof(node->name), name) != EOK) {
        cm_panic(0);
    }
    if (type == GFT_PATH) {
        node->items.count = 0;
        dss_set_auid(&node->items.first, CM_INVALID_ID64);
        dss_set_auid(&node->items.last, CM_INVALID_ID64);
    } else {  // FILE or LINK
        if (dss_init_ft_node_entry(session, vg_item, node) != CM_SUCCESS) {
            dss_rollback_mem_update(session->log_split, vg_item);
            LOG_DEBUG_ERR("Failed to get alloc fs block when allocating file table node %s.", node->name);
            return NULL;
        }
    }
    gft->free_list.first = node->next;
    gft->free_list.count--;
    bool32 cmp = dss_cmp_auid(gft->free_list.first, CM_INVALID_ID64);
    if (cmp) {
        LOG_DEBUG_INF("File table node free list will be empty, count: %u.", gft->free_list.count);
        cm_panic(gft->free_list.count == 0);
        gft->free_list.last = gft->free_list.first;
    }
    dss_init_alloc_ft_node(gft, node, DSS_FT_NODE_FLAG_NORMAL, parent_node);
    dss_ft_node_link_list(session, vg_item, parent_node, id, node, gft);
    /*
     * release lock after we flush the ft block to disk, to avoid this concurrency scenario:
     * thread 1: a) calculate ft block checksum, and then b) flush the block to disk,
     * thread 2: modify ft block after thread 1's operation a, and before operation b.
     * NOTE: this place needs file lock to avoid one thread modify gft_node_t's size,
     * and another thread modify the gft_node_t's prev/next pointer.
     */
    return node;
}

static void dss_get_prev_and_next_node(dss_vg_info_item_t *vg_item, gft_node_t *parent_node, gft_node_t *node,
    gft_block_info_t *prev_info, gft_block_info_t *next_info)
{
    node->update_time = cm_current_time();
    if (*(uint64 *)(&parent_node->items.first) == *(uint64 *)(&node->id)) {
        parent_node->items.first = node->next;
        bool32 cmp = dss_cmp_blockid(parent_node->items.first, CM_INVALID_ID64);
        if (cmp) {
            CM_ASSERT(parent_node->items.count == 1);
            parent_node->items.last = parent_node->items.first;
        } else {
            next_info->ft_node = dss_get_ft_node_by_ftid(vg_item, parent_node->items.first, CM_TRUE, CM_FALSE);
            CM_ASSERT(next_info->ft_node != NULL);
            dss_set_blockid(&next_info->ft_node->prev, CM_INVALID_ID64);
        }
    } else if (*(uint64 *)(&parent_node->items.last) == *(uint64 *)(&node->id)) {
        parent_node->items.last = node->prev;
        prev_info->ft_node = dss_get_ft_node_by_ftid(vg_item, parent_node->items.last, CM_TRUE, CM_FALSE);
        CM_ASSERT(prev_info->ft_node != NULL);
        dss_set_blockid(&prev_info->ft_node->next, CM_INVALID_ID64);
    } else {
        prev_info->ft_node = dss_get_ft_node_by_ftid(vg_item, node->prev, CM_TRUE, CM_FALSE);
        CM_ASSERT(prev_info->ft_node != NULL);
        prev_info->ft_node->next = node->next;
        next_info->ft_node = dss_get_ft_node_by_ftid(vg_item, node->next, CM_TRUE, CM_FALSE);
        CM_ASSERT(next_info->ft_node != NULL);
        next_info->ft_node->prev = node->prev;
    }
    parent_node->items.count--;
}

void dss_free_ft_node_inner(
    dss_session_t *session, dss_vg_info_item_t *vg_item, gft_node_t *parent_node, gft_node_t *node, bool32 real_del)
{
    CM_ASSERT(vg_item != NULL);
    CM_ASSERT(parent_node != NULL);
    CM_ASSERT(node != NULL);
    gft_block_info_t prev_info = {0};
    gft_block_info_t next_info = {0};
    node->update_time = cm_current_time();
    dss_get_prev_and_next_node(vg_item, parent_node, node, &prev_info, &next_info);

    dss_ctrl_t *dss_ctrl = vg_item->dss_ctrl;
    char *root = dss_ctrl->root;
    dss_root_ft_block_t *ft_block = (dss_root_ft_block_t *)(root);
    gft_root_t *gft = &ft_block->ft_root;
    if (real_del) {
        node->next = gft->free_list.first;
        dss_set_blockid(&node->prev, DSS_INVALID_64);
        dss_set_blockid(&node->entry, DSS_INVALID_64);
        gft->free_list.first = node->id;
    }

    dss_redo_free_ft_node_t redo_node;
    uint16 i = 0;
    redo_node.node[i] = *parent_node;
    i++;
    if (prev_info.ft_node != NULL) {
        redo_node.node[i] = *prev_info.ft_node;
        DSS_LOG_DEBUG_OP("Free ft node, prev_node name:%s, prev_node id:%llu.", prev_info.ft_node->name,
            DSS_ID_TO_U64(prev_info.ft_node->id));
    } else {
        dss_set_auid(&redo_node.node[i].id, CM_INVALID_ID64);
    }
    i++;
    if (next_info.ft_node != NULL) {
        redo_node.node[i] = *next_info.ft_node;
        DSS_LOG_DEBUG_OP("Free ft node, next_node name:%s, next_node id:%llu.", next_info.ft_node->name,
            DSS_ID_TO_U64(next_info.ft_node->id));
    } else {
        dss_set_auid(&redo_node.node[i].id, CM_INVALID_ID64);
    }
    i++;
    redo_node.node[i] = *node;
    redo_node.ft_root = *gft;
    dss_put_log(session, vg_item, DSS_RT_FREE_FILE_TABLE_NODE, &redo_node, sizeof(dss_redo_free_ft_node_t));
    DSS_LOG_DEBUG_OP(
        "Free ft node, name:%s, volume:%u, au:%llu, block:%u, item:%u, id:%llu, free count:%u, real delete:%u",
        node->name, node->id.volume, (uint64)node->id.au, node->id.block, node->id.item, DSS_ID_TO_U64(node->id),
        gft->free_list.count, real_del);
}

// remove ftn from parent
void dss_free_ft_node(dss_session_t *session, dss_vg_info_item_t *vg_item, gft_node_t *parent_node, gft_node_t *node,
    bool32 real_del, bool32 latch_safe)
{
    CM_ASSERT(vg_item != NULL);
    CM_ASSERT(parent_node != NULL);
    CM_ASSERT(node != NULL);
    dss_free_ft_node_inner(session, vg_item, parent_node, node, real_del);
}

bool32 dss_oamap_blockid_compare(void *key1, void *key2)
{
    CM_ASSERT(key1 != NULL);
    CM_ASSERT(key2 != NULL);

    dss_block_id_t *blockid1 = (dss_block_id_t *)key1;
    dss_block_id_t *blockid2 = (dss_block_id_t *)key2;

    if (blockid1->volume == blockid2->volume && blockid1->au == blockid2->au && blockid1->block == blockid2->block) {
        return CM_TRUE;
    } else {
        return CM_FALSE;
    }
}

gft_node_t *dss_find_ft_node_core(
    dss_vg_info_item_t *vg_item, gft_node_t *parent_node, const char *name, bool32 skip_del)
{
    bool32 check_version = dss_is_server();
    ftid_t id = parent_node->items.first;

    cm_oamap_t map;
    if (dss_is_server()) {
        int32 ret = cm_oamap_init(&map, DSS_FILE_HASH_SIZE, dss_oamap_blockid_compare);
        if (ret != CM_SUCCESS) {
            LOG_DEBUG_ERR("Initialize the hash map failed, hash size:%u.", DSS_FILE_HASH_SIZE);
            return NULL;
        }
    }

    for (uint32 i = 0; i < parent_node->items.count; i++) {
#ifdef OPENGAUSS
        if (dss_cmp_blockid(id, CM_INVALID_ID64)) {
            // openGauss may be find uncommitted node when standby
            LOG_DEBUG_INF("Get invalid id in parent name:%s, id:%llu, count:%u, when find node name:%s, index:%u.",
                parent_node->name, *(uint64 *)&parent_node->id, parent_node->items.count, name, i);
            return NULL;
        }
#endif
        gft_node_t *node = dss_get_ft_node_by_ftid(vg_item, id, check_version, CM_FALSE);
        if (node == NULL) {
            if (dss_is_server()) {
                cm_oamap_destroy(&map);
            }
            LOG_DEBUG_ERR("Can not get node:%llu,File name %s type:%u.", *(uint64 *)&id, name, parent_node->type);
            return NULL;
        }
        if (skip_del && (node->flags & DSS_FT_NODE_FLAG_DEL)) {
            id = node->next;
            continue;
        }
        if (strcmp(node->name, name) == 0) {
            if (dss_is_server()) {
                cm_oamap_destroy(&map);
            }
            return node;
        }

        id = node->next;
        if (!dss_is_server()) {
            continue;
        }

        dss_block_id_t blockid = id;
        blockid.item = 0;
        uint32 hash = cm_hash_int64(*(int64 *)&blockid);
        void *res = cm_oamap_lookup(&map, hash, &blockid);
        if (res) {
            check_version = CM_FALSE;  // Have checked, no need checked again.
            continue;
        }
        check_version = CM_TRUE;
        int32 ret = cm_oamap_insert(&map, hash, &node->next, &node->next);
        if (ret != CM_SUCCESS) {
            cm_oamap_destroy(&map);
            LOG_DEBUG_ERR("Insert the hash map failed, blockid:%llu.", DSS_ID_TO_U64(node->next));
            return NULL;
        }
    }

    if (dss_is_server()) {
        cm_oamap_destroy(&map);
    }
    return NULL;
}

gft_node_t *dss_find_ft_node(dss_vg_info_item_t *vg_item, gft_node_t *parent_node, const char *name, bool32 skip_del)
{
    CM_ASSERT(name != NULL);
    ftid_t id;
    if (parent_node == NULL) {
        memset_s(&id, sizeof(id), 0, sizeof(id));
        return dss_get_ft_node_by_ftid(vg_item, id, dss_is_server(), CM_FALSE);
    }

    if (parent_node->type != GFT_PATH) {
        LOG_DEBUG_ERR("File name %s type:%u is invalid.", name, parent_node->type);
        return NULL;
    }

    if (parent_node->items.count == 0) {
        LOG_DEBUG_INF("File name %s count:%u.", name, parent_node->items.count);
        return NULL;
    }

    gft_node_t *node = dss_find_ft_node_core(vg_item, parent_node, name, skip_del);
    if (node != NULL) {
        return node;
    }

    LOG_DEBUG_INF("File name %s, its parent node count:%u.", name, parent_node->items.count);
    return NULL;
}

status_t dss_refresh_root_ft(dss_vg_info_item_t *vg_item, bool32 check_version, bool32 active_refresh)
{
#ifdef OPENGAUSS
    if (dss_is_readwrite() && !active_refresh) {
        return CM_SUCCESS;
    }
#endif
    dss_ctrl_t *dss_ctrl = vg_item->dss_ctrl;
    char *root = dss_ctrl->root;
    dss_root_ft_block_t *ft_block = (dss_root_ft_block_t *)(root);
    if (check_version && dss_is_server()) {
        uint64 version = ft_block->ft_block.common.version;
        uint64 disk_version;
        status_t status = dss_get_root_version(vg_item, &disk_version);
        if (status != CM_SUCCESS) {
            LOG_DEBUG_ERR("Failed to get the root version.");
            return status;
        }

        if (dss_compare_version(disk_version, version)) {
            status = dss_load_vg_ctrl_part(vg_item, (int64)DSS_CTRL_ROOT_OFFSET, root, (int32)DSS_BLOCK_SIZE);
            if (status != CM_SUCCESS) {
                LOG_DEBUG_ERR("Failed to get the whole root.");
                return status;
            }
            DSS_LOG_DEBUG_OP(
                "The root version is changed, refresh it, version:%llu, new version:%llu.", version, disk_version);

            uint32 checksum = dss_get_checksum(root, DSS_BLOCK_SIZE);
            dss_common_block_t *block = (dss_common_block_t *)root;
            dss_check_checksum(checksum, block->checksum);
        }
    }
    return CM_SUCCESS;
}

char *dss_find_ft_block_latch(dss_vg_info_item_t *vg_item, ftid_t ftid, ga_obj_id_t *out_obj_id)
{
#ifndef OPENGAUSS
    return (char *)1;
#else
    gft_node_t *node = (gft_node_t *)dss_get_ft_node_by_ftid(vg_item, ftid, CM_FALSE, CM_FALSE);
    dss_ft_block_t *block = dss_get_ft_block_by_node(node);
    return ((char *)block) + DSS_BLOCK_SIZE;
#endif
}

gft_node_t *dss_get_ft_node_by_ftid(dss_vg_info_item_t *vg_item, ftid_t id, bool32 check_version, bool32 active_refresh)
{
    dss_ctrl_t *dss_ctrl = vg_item->dss_ctrl;
    if (is_ft_root_block(id)) {
        char *root = dss_ctrl->root;
        dss_root_ft_block_t *ft_block = (dss_root_ft_block_t *)(root);
        if (dss_refresh_root_ft(vg_item, check_version, active_refresh) != CM_SUCCESS) {
            return NULL;
        }

        if (id.item < ft_block->ft_block.node_num) {
            return (gft_node_t *)((root + sizeof(dss_root_ft_block_t)) + id.item * sizeof(gft_node_t));
        }
    } else {
        dss_block_id_t block_id = id;
        block_id.item = 0;
        dss_ft_block_t *block = (dss_ft_block_t *)dss_find_block_in_shm(
            vg_item, block_id, DSS_BLOCK_TYPE_FT, check_version, NULL, active_refresh);
        if (block == NULL) {
            LOG_DEBUG_ERR("Failed to find block:%llu in mem.", *(uint64 *)&block_id);
            return NULL;
        }

        if (block->node_num <= id.item) {
            LOG_DEBUG_ERR("The block is wrong, node_num:%u, item:%u.", block->node_num, (uint32)id.item);
            return NULL;
        }

        return (gft_node_t *)(((char *)block + sizeof(dss_ft_block_t)) + id.item * sizeof(gft_node_t));
    }
    return NULL;
}

char *dss_get_ft_block_by_ftid(dss_vg_info_item_t *vg_item, ftid_t id)
{
    dss_ctrl_t *dss_ctrl = vg_item->dss_ctrl;
    if (is_ft_root_block(id)) {
        char *root = dss_ctrl->root;
        // NOTE:when recover just return root, must not be load from disk.Because format ft node is logic recovery,
        // its gft info only use redo log info.
        if (vg_item->status == DSS_STATUS_RECOVERY) {
            return root;
        }

        if (dss_refresh_root_ft(vg_item, CM_TRUE, CM_FALSE) != CM_SUCCESS) {
            return NULL;
        }
        return root;
    }
    return dss_find_block_in_shm(vg_item, id, DSS_BLOCK_TYPE_FT, CM_TRUE, NULL, CM_FALSE);
}

dss_ft_block_t *dss_get_ft_block_by_node(gft_node_t *node)
{
    CM_ASSERT(node != NULL);

    if ((node->id.au) == 0 && node->id.block == 0) {
        return (dss_ft_block_t *)(((char *)node - sizeof(dss_root_ft_block_t)) - (node->id.item * sizeof(gft_node_t)));
    }

    return (dss_ft_block_t *)(((char *)node - sizeof(dss_ft_block_t)) - (node->id.item * sizeof(gft_node_t)));
}

static void dss_init_ft_root_core(char *root, dss_root_ft_block_t *ft_block, gft_root_t *gft)
{
    dss_set_blockid(&ft_block->ft_block.next, DSS_INVALID_64);
    dss_set_blockid(&gft->first, 0);
    dss_set_blockid(&gft->last, 0);

    gft->items.count = 0;
    *(uint64_t *)(&gft->items.first) = DSS_INVALID_64;
    *(uint64_t *)(&gft->items.last) = DSS_INVALID_64;
    gft->free_list.count = 0;
    *(uint64 *)(&gft->free_list.first) = DSS_INVALID_64;
    *(uint64 *)(&gft->free_list.last) = DSS_INVALID_64;
    // item_count is always 1
    uint32 item_count = (DSS_BLOCK_SIZE - sizeof(dss_root_ft_block_t)) / sizeof(gft_node_t);
    ft_block->ft_block.node_num = item_count;
    gft_node_t *first_free_node = (gft_node_t *)(root + sizeof(dss_root_ft_block_t));
    gft_node_t *node = NULL;

    // the first gft_node_t is used for vg name (like: `/`)
    for (uint32 i = 1; i < item_count; i++) {
        node = first_free_node + i;
        dss_set_auid(&node->id, 0);
        node->id.block = 0;
        node->id.item = i;

        if (i == 1) {
            *(uint64_t *)(&node->prev) = DSS_INVALID_64;
            gft->free_list.first = node->id;
        } else {
            *(uint64_t *)(&node->prev) = 0;
            node->prev.block = 0;
            node->prev.item = (uint16)i - 1;
        }

        if (i == item_count - 1) {
            *(uint64_t *)(&node->next) = DSS_INVALID_64;
            gft->free_list.last = node->id;
        } else {
            *(uint64_t *)(&node->next) = 0;
            node->next.block = 0;
            node->next.item = (uint16)i + 1;
        }

        gft->free_list.count++;
    }
}

static void dss_init_first_node(dss_ctrl_t *dss_ctrl, gft_node_t *first_node)
{
    first_node->type = GFT_PATH;
    if (strcpy_s(first_node->name, DSS_MAX_NAME_LEN, dss_ctrl->vg_info.vg_name) != EOK) {
        cm_panic(0);
    }
    first_node->create_time = cm_current_time();
    first_node->size = 0;
    first_node->written_size = 0;
    first_node->items.count = 0;
    dss_set_auid(&first_node->items.first, DSS_INVALID_64);
    dss_set_auid(&first_node->items.last, DSS_INVALID_64);
    dss_set_auid(&first_node->prev, DSS_INVALID_64);
    dss_set_auid(&first_node->next, DSS_INVALID_64);
    dss_set_auid(&first_node->id, 0);
    first_node->id.block = 0;
    first_node->id.item = 0;
}

void dss_init_ft_root(dss_ctrl_t *dss_ctrl, gft_node_t **out_node)
{
    CM_ASSERT(dss_ctrl != NULL);
    char *root = dss_ctrl->root;
    dss_root_ft_block_t *ft_block = (dss_root_ft_block_t *)(root);
    gft_root_t *gft = &ft_block->ft_root;
    dss_init_ft_root_core(root, ft_block, gft);

    gft_node_t *first_node = (gft_node_t *)(root + sizeof(dss_root_ft_block_t));
    dss_init_first_node(dss_ctrl, first_node);

    gft->items.count = 1;
    gft->items.first = first_node->id;
    gft->items.last = first_node->id;
    if (out_node) {
        *out_node = first_node;
    }
    return;
}

status_t dss_update_ft_root(dss_vg_info_item_t *vg_item)
{
    status_t status;
    dss_ctrl_t *dss_ctrl = vg_item->dss_ctrl;
    dss_root_ft_block_t *block = DSS_GET_ROOT_BLOCK(dss_ctrl);
    block->ft_block.common.version++;
    block->ft_block.common.checksum = dss_get_checksum(block, DSS_BLOCK_SIZE);
    CM_ASSERT(vg_item->volume_handle[0].handle != DSS_INVALID_HANDLE);
    DSS_LOG_DEBUG_OP("Update node table root, version:%llu.", block->ft_block.common.version);
    status = dss_write_volume_inst(
        vg_item, &vg_item->volume_handle[0], (int64)DSS_CTRL_ROOT_OFFSET, dss_ctrl->root, DSS_BLOCK_SIZE);
    if (status == CM_SUCCESS) {
        // write to backup area
        status = dss_write_volume_inst(
            vg_item, &vg_item->volume_handle[0], (int64)DSS_CTRL_BAK_ROOT_OFFSET, dss_ctrl->root, DSS_BLOCK_SIZE);
    }
    return status;
}

status_t dss_check_refresh_fs_block(
    dss_vg_info_item_t *vg_item, dss_block_id_t blockid, char *block, bool32 *is_changed)
{
#ifdef OPENGAUSS
    if (dss_is_readwrite()) {
        return CM_SUCCESS;
    }
#endif
    status_t status = dss_check_refresh_core(vg_item);
    if (status != CM_SUCCESS) {
        LOG_DEBUG_ERR("Failed to check and refresh core, %s.", vg_item->entry_path);
        return CM_ERROR;
    }

    return dss_check_block_version(vg_item, blockid, DSS_BLOCK_TYPE_FS, block, is_changed);
}

// refresh file table
status_t dss_refresh_ft(dss_vg_info_item_t *vg_item)
{
#ifdef OPENGAUSS
    if (dss_is_readwrite()) {
        return CM_SUCCESS;
    }
#endif
    status_t status =
        dss_load_vg_ctrl_part(vg_item, (int64)DSS_CTRL_ROOT_OFFSET, vg_item->dss_ctrl->root, (int32)DSS_BLOCK_SIZE);
    if (status != CM_SUCCESS) {
        LOG_DEBUG_ERR("Failed to load vg core part %s.", vg_item->entry_path);
        return status;
    }

    uint64 count = 0;
    char *root = vg_item->dss_ctrl->root;
    dss_root_ft_block_t *ft_block = (dss_root_ft_block_t *)(root);
    dss_block_id_t block_id = ft_block->ft_block.next;
    bool32 cmp = dss_cmp_blockid(block_id, CM_INVALID_ID64);
    while (!cmp) {
        ft_block = (dss_root_ft_block_t *)dss_get_ft_block_by_ftid(vg_item, block_id);
        if (ft_block) {
            block_id = ft_block->ft_block.next;
            cmp = dss_cmp_blockid(block_id, CM_INVALID_ID64);
        } else {
            LOG_DEBUG_ERR("Failed to get file table block when refresh ft %s.", vg_item->entry_path);
            return CM_ERROR;
        }
        count++;
    }
    DSS_LOG_DEBUG_OP("Succeed to refresh ft %s, count:%llu.", vg_item->entry_path, count);
    return CM_SUCCESS;
}

status_t dss_get_root_version(dss_vg_info_item_t *vg_item, uint64 *version)
{
    CM_ASSERT(vg_item != NULL);
    CM_ASSERT(version != NULL);

#ifndef WIN32
    char temp[DSS_DISK_UNIT_SIZE] __attribute__((__aligned__(DSS_DISK_UNIT_SIZE)));
#else
    char temp[DSS_DISK_UNIT_SIZE];
#endif

    status_t status = dss_load_vg_ctrl_part(vg_item, (int64)DSS_CTRL_ROOT_OFFSET, temp, DSS_DISK_UNIT_SIZE);
    if (status != CM_SUCCESS) {
        LOG_DEBUG_ERR("Failed to load vg core version %s.", vg_item->entry_path);
        return status;
    }
    *version = ((dss_common_block_t *)temp)->version;
    return CM_SUCCESS;
}

status_t dss_check_refresh_ft(dss_vg_info_item_t *vg_item)
{
#ifdef OPENGAUSS
    if (dss_is_readwrite()) {
        return CM_SUCCESS;
    }
#endif
    uint64 disk_version;
    status_t status = dss_get_root_version(vg_item, &disk_version);
    if (status != CM_SUCCESS) {
        LOG_DEBUG_ERR("Failed to get root version %s.", vg_item->entry_path);
        return status;
    }

    dss_root_ft_block_t *ft_block_m = DSS_GET_ROOT_BLOCK(vg_item->dss_ctrl);
    if (dss_compare_version(disk_version, ft_block_m->ft_block.common.version)) {
        status =
            dss_load_vg_ctrl_part(vg_item, (int64)DSS_CTRL_ROOT_OFFSET, vg_item->dss_ctrl->root, (int32)DSS_BLOCK_SIZE);
        if (status != CM_SUCCESS) {
            LOG_DEBUG_ERR("Failed to load vg core part %s.", vg_item->entry_path);
            return status;
        }
    }
    DSS_LOG_DEBUG_OP(
        "dss_check_refresh_ft version:%llu, disk version:%llu.", ft_block_m->ft_block.common.version, disk_version);
    return CM_SUCCESS;
}

status_t dss_update_ft_block_disk(dss_vg_info_item_t *vg_item, dss_ft_block_t *block, ftid_t id)
{
    uint32 volume_id = (uint32)id.volume;
    int64 offset = dss_get_ft_block_offset(vg_item, id);

    block->common.version++;
    block->common.checksum = dss_get_checksum(block, DSS_BLOCK_SIZE);
    CM_ASSERT(vg_item->volume_handle[volume_id].handle != DSS_INVALID_HANDLE);
    return dss_check_write_volume(vg_item, volume_id, offset, block, DSS_BLOCK_SIZE);
}

int64 dss_get_ft_block_offset(dss_vg_info_item_t *vg_item, ftid_t id)
{
    if ((id.au) == 0) {
        return (int64)DSS_CTRL_ROOT_OFFSET;
    }
    return dss_get_block_offset(vg_item, DSS_BLOCK_SIZE, id.block, id.au);
}

status_t dss_update_fs_bitmap_block_disk(
    dss_vg_info_item_t *item, dss_fs_block_t *block, uint32 size, bool32 had_checksum)
{
    CM_ASSERT(item != NULL);
    CM_ASSERT(block != NULL);
    uint32 volume_id = (uint32)block->head.id.volume;
    int64 offset = dss_get_fs_block_offset(item, block->head.id);

    if (!had_checksum) {
        block->head.common.version++;
        block->head.common.checksum = dss_get_checksum(block, DSS_FILE_SPACE_BLOCK_SIZE);
    }

    DSS_LOG_DEBUG_OP("update_fs_bitmap_block_disk checksum:%u,%llu, version:%llu, size:%u.",
        block->head.common.checksum, DSS_ID_TO_U64(block->head.id), block->head.common.version, size);

    CM_ASSERT(item->volume_handle[volume_id].handle != DSS_INVALID_HANDLE);
    status_t status = dss_check_write_volume(item, volume_id, offset, block, size);
    if (status != CM_SUCCESS) {
        return status;
    }
    return CM_SUCCESS;
}

status_t dss_get_second_block(
    dss_vg_info_item_t *vg_item, dss_block_id_t second_block_id, dss_fs_block_t **second_block)
{
    *second_block =
        (dss_fs_block_t *)dss_find_block_in_shm(vg_item, second_block_id, DSS_BLOCK_TYPE_FS, CM_TRUE, NULL, CM_FALSE);
    if (!*second_block) {
        LOG_DEBUG_ERR("Failed to find the second block:%llu.", DSS_ID_TO_U64(second_block_id));
        return CM_ERROR;
    }
    bool32 is_changed;
    status_t status = dss_check_refresh_fs_block(vg_item, second_block_id, (char *)(*second_block), &is_changed);
    if (status != CM_SUCCESS) {
        LOG_DEBUG_ERR("Failed to alloc au,vg name %s.", vg_item->dss_ctrl->vg_info.vg_name);
        return status;
    }
    return CM_SUCCESS;
}

static status_t dss_get_block_entry(dss_session_t *session, dss_vg_info_item_t *vg_item, dss_config_t *inst_cfg,
    uint64 fid, ftid_t ftid, gft_node_t **node_out, dss_fs_block_header **entry_out)
{
    gft_node_t *node = dss_get_ft_node_by_ftid(vg_item, ftid, CM_TRUE, CM_FALSE);
    if (!node) {
        dss_unlock_vg_mem_and_shm(session, vg_item);
        LOG_DEBUG_ERR("Failed to find ftid,ftid: %llu.", *(uint64 *)&ftid);
        return CM_ERROR;
    }

    if (node->fid != fid) {
        dss_unlock_vg_mem_and_shm(session, vg_item);
        LOG_DEBUG_ERR("Fid is not match,(%llu,%llu).", node->fid, fid);
        return CM_ERROR;
    }
    // next will check disk version, so here not check
    dss_fs_block_header *entry_block =
        (dss_fs_block_header *)dss_find_block_in_shm(vg_item, node->entry, DSS_BLOCK_TYPE_FS, CM_TRUE, NULL, CM_FALSE);
    if (!entry_block) {
        dss_unlock_vg_mem_and_shm(session, vg_item);
        LOG_DEBUG_ERR("Failed to find entry block:%llu.", *(uint64 *)&node->entry);
        return CM_ERROR;
    }
    *node_out = node;
    *entry_out = entry_block;
    return CM_SUCCESS;
}

status_t dss_get_fs_block_info_by_offset(
    int64 offset, uint64 au_size, uint32 *block_count, uint32 *block_au_count, uint32 *au_offset)
{
    if (au_size == 0) {
        LOG_DEBUG_ERR("The au size cannot be zero.");
        return CM_ERROR;
    }

    // two level bitmap, ~2k block ids per entry FSB
    uint64 au_count = (DSS_FILE_SPACE_BLOCK_SIZE - sizeof(dss_fs_block_header)) / sizeof(auid_t);  // 2043 2nd FSBs
    uint64 block_len = au_count * au_size;  // [4G, 128G] per 2nd-level FSB, with AU range [2MB, 64MB]
    int64 temp = (offset / (int64)block_len);
    if (temp > (int64)au_count) {  // Total [8T, 256T] per file, to be verified
        LOG_DEBUG_ERR(
            "Invalid offset, offset:%lld, real block count:%lld, max block count:%llu.", offset, temp, au_count);
        return CM_ERROR;
    }
    *block_count = (uint32)(temp);                              // index of secondary FSB(id) in entry FSB's bitmap
    int64 block_offset = offset % (int64)block_len;             // offset within FSB
    *block_au_count = (uint32)(block_offset / (int64)au_size);  // index of AU within FSB
    if (au_offset != NULL) {
        *au_offset = (uint32)(block_offset % (int64)au_size);  // offset within AU
    }

    return CM_SUCCESS;
}

status_t dss_extend(
    dss_session_t *session, uint64 fid, ftid_t ftid, int64 offset, char *vg_name, uint32 vgid, bool32 is_read)
{
    status_t status;
    dss_vg_info_item_t *vg_item = dss_find_vg_item(vg_name);
    if (!vg_item) {
        LOG_DEBUG_ERR("Failed to find vg,vg name %s.", vg_name);
        DSS_THROW_ERROR(ERR_DSS_VG_NOT_EXIST, vg_name);
        return CM_ERROR;
    }

    dss_lock_vg_mem_and_shm_x(session, vg_item);
    status = dss_extend_inner(session, fid, ftid, offset, vg_name, vgid, is_read);
    dss_unlock_vg_mem_and_shm(session, vg_item);
    return status;
}

status_t dss_extend_inner(
    dss_session_t *session, uint64 fid, ftid_t ftid, int64 offset, char *vg_name, uint32 vgid, bool32 is_read)
{
    dss_vg_info_item_t *vg_item = dss_find_vg_item(vg_name);
    dss_config_t *inst_cfg = dss_get_inst_cfg();
    if (vg_item == NULL) {
        LOG_DEBUG_ERR("Failed to find vg,vg name %s.", vg_name);
        DSS_THROW_ERROR(ERR_DSS_VG_NOT_EXIST, vg_name);
        return CM_ERROR;
    }

    gft_node_t *node = NULL;
    dss_fs_block_header *entry_block = NULL;
    CM_RETURN_IFERR(dss_get_block_entry(session, vg_item, inst_cfg, fid, ftid, &node, &entry_block));

    dss_fs_block_t *entry_fs_block = (dss_fs_block_t *)entry_block;
    // two level bitmap
    uint32 block_count = 0;
    uint32 block_au_count = 0;
    uint64 au_size = dss_get_vg_au_size(vg_item->dss_ctrl);
    status_t status = dss_get_fs_block_info_by_offset(offset, au_size, &block_count, &block_au_count, NULL);
    if (status != CM_SUCCESS) {
        LOG_DEBUG_ERR("The offset(%lld) is not correct,real block count:%u.", offset, block_count);
        return CM_ERROR;
    }
    bool32 need_get_second = CM_FALSE;
    ga_obj_id_t sec_obj_id;
    dss_fs_block_t *second_block = NULL;
    dss_block_id_t second_block_id = entry_fs_block->bitmap[block_count];
    if (dss_cmp_blockid(second_block_id, CM_INVALID_ID64)) {
        bool32 is_changed;
        status = dss_check_refresh_fs_block(vg_item, node->entry, (char *)entry_fs_block, &is_changed);
        if (status != CM_SUCCESS) {
            LOG_DEBUG_ERR("Failed to alloc au,vg name %s.", vg_item->dss_ctrl->vg_info.vg_name);
            return status;
        }

        second_block_id = entry_fs_block->bitmap[block_count];
        if (dss_cmp_blockid(second_block_id, CM_INVALID_ID64)) {
            if (is_read) {
                LOG_DEBUG_INF("Read invalid offset in %s.", node->name);
                return CM_SUCCESS;
            }
            dss_alloc_fs_block_judge judge = {CM_TRUE, CM_FALSE, CM_TRUE};
            // allocate block
            status = dss_alloc_fs_block(session, vg_item, (char **)&second_block, &sec_obj_id, &judge);
            if (!second_block) {
                dss_rollback_mem_update(session->log_split, vg_item);
                LOG_DEBUG_ERR("Failed to alloc file space meta block,vg name %s.", vg_item->dss_ctrl->vg_info.vg_name);
                return CM_ERROR;
            }
            second_block_id = second_block->head.id;
            DSS_LOG_DEBUG_OP("Allocate second level block:%llu.", DSS_ID_TO_U64(second_block_id));
            uint16 old_used_num = entry_fs_block->head.used_num;
            dss_block_id_t old_id = entry_fs_block->bitmap[block_count];
            entry_fs_block->bitmap[block_count] = second_block->head.id;
            entry_fs_block->head.used_num++;
            dss_redo_set_fs_block_t redo;
            redo.id = node->entry;
            redo.index = (uint16)block_count;
            redo.value = second_block->head.id;
            redo.used_num = entry_fs_block->head.used_num;
            redo.old_used_num = old_used_num;
            redo.old_value = old_id;
            dss_put_log(session, vg_item, DSS_RT_SET_FILE_FS_BLOCK, &redo, sizeof(redo));
        } else {
            need_get_second = CM_TRUE;
        }
    } else {
        need_get_second = CM_TRUE;
    }

    if (need_get_second) {
        status = dss_get_second_block(vg_item, second_block_id, &second_block);
        if (status != CM_SUCCESS) {
            dss_rollback_mem_update(session->log_split, vg_item);
            LOG_DEBUG_ERR("Failed to alloc au,vg name %s.", vg_item->dss_ctrl->vg_info.vg_name);
            return status;
        }
    }

    auid_t auid = second_block->bitmap[block_au_count];
    if (dss_cmp_auid(auid, CM_INVALID_ID64)) {
        if (is_read) {
            LOG_DEBUG_INF("Read invalid offset in %s.", node->name);
            return CM_SUCCESS;
        }
        // allocate au
        status = dss_alloc_au(session, vg_item, &auid, CM_TRUE);
        if (status != CM_SUCCESS) {
            dss_rollback_mem_update(session->log_split, vg_item);
            LOG_DEBUG_ERR("Failed to alloc au,vg name %s.", vg_item->dss_ctrl->vg_info.vg_name);
            DSS_THROW_ERROR(ERR_DSS_NO_SPACE);
            return status;
        }
        CM_ASSERT(auid.volume < DSS_MAX_VOLUMES);
        uint16 old_used_num = second_block->head.used_num;
        dss_block_id_t old_id = second_block->bitmap[block_au_count];
        second_block->bitmap[block_au_count] = auid;
        second_block->head.used_num++;
        uint64 old_size = node->size;
        dss_redo_set_fs_block_t redo;
        redo.id = second_block_id;
        redo.index = (uint16)block_au_count;
        redo.value = auid;
        redo.used_num = second_block->head.used_num;
        redo.old_value = old_id;
        redo.old_used_num = old_used_num;
        dss_put_log(session, vg_item, DSS_RT_SET_FILE_FS_BLOCK, &redo, sizeof(redo));

        node->size += dss_get_vg_au_size(vg_item->dss_ctrl);
        dss_redo_set_file_size_t redo_size;
        redo_size.ftid = node->id;
        redo_size.size = node->size;
        redo_size.oldsize = old_size;
        dss_put_log(session, vg_item, DSS_RT_SET_FILE_SIZE, &redo_size, sizeof(redo_size));
    }

    status = dss_process_redo_log(session, vg_item);
    if (status != CM_SUCCESS) {
        LOG_RUN_ERR("[DSS] ABORT INFO: redo log process failed, errcode:%d, OS errno:%d, OS errmsg:%s.",
            cm_get_error_code(), errno, strerror(errno));
        cm_fync_logfile();
        _exit(1);
    }

    return CM_SUCCESS;
}

static bool32 dss_is_truncate_necessary(gft_node_t *node, uint64 aligned_length, uint64 au_size)
{
    if (aligned_length >= node->size) {
        LOG_DEBUG_INF("Aligned target length %llu >= current file size %llu; curr AU size is %llu. No Truncation.",
            aligned_length, node->size, au_size);
        return CM_FALSE;
    }
    return CM_TRUE;
}

/* transfer non-intact FSB's AUs after truncate point to recycle FSB's last secondary FSB */
static void dss_transfer_remaining_au(dss_session_t *session, dss_fs_block_t *src_partial_sfsb,
    dss_fs_block_t *dst_first_sfsb, dss_fs_block_t *dst_second_sfsb, uint32 src_au_idx, uint32 dst_au_idx,
    dss_vg_info_item_t *vg_item)
{
    uint32 au_idx_limit = (DSS_FILE_SPACE_BLOCK_SIZE - sizeof(dss_fs_block_header)) / sizeof(auid_t);
    auid_t auid = src_partial_sfsb->bitmap[src_au_idx];
    dss_fs_block_t *dst_sfsb = dst_first_sfsb;
    CM_ASSERT(dst_au_idx <= au_idx_limit);

    LOG_DEBUG_INF("Begin to transfer the partial FSB, src_au_idx:%u, %u AUs to xfer, dst_au_idx:%u, au_idx_limit:%u, "
                  "dst SFSB:%llu, used num:%hu, src SFSB:%llu, used num:%hu.",
        src_au_idx, ((au_idx_limit - src_au_idx) + 1), dst_au_idx, au_idx_limit, DSS_ID_TO_U64(dst_sfsb->head.id),
        dst_sfsb->head.used_num, DSS_ID_TO_U64(src_partial_sfsb->head.id), src_partial_sfsb->head.used_num);

    // after whole FSB transfer, dst SFSB's remaning space might < src SFSB's AUs that need transfer
    // dst_second_sfsb should've been prepped in caller dss_build_truncated_ftn
    while (src_au_idx < au_idx_limit && !dss_cmp_auid(auid, DSS_INVALID_ID64) && dst_au_idx <= au_idx_limit) {
        if (dst_au_idx == au_idx_limit && !dss_cmp_auid(auid, DSS_INVALID_ID64)) {
            CM_ASSERT(dst_second_sfsb != NULL);
            dst_sfsb = dst_second_sfsb;
            dst_au_idx = 0;
            LOG_DEBUG_INF("Utilizing the second SFSB:%llu during xferring partial SFSB.",
                DSS_ID_TO_U64(dst_second_sfsb->head.id));
        }

        CM_ASSERT(src_partial_sfsb->head.used_num > 0);
        uint16 dst_old_used_num = dst_sfsb->head.used_num;
        dss_block_id_t dst_old_id = dst_sfsb->bitmap[dst_au_idx];
        uint16 src_old_used_num = src_partial_sfsb->head.used_num;
        dss_block_id_t src_old_id = src_partial_sfsb->bitmap[src_au_idx];

        dst_sfsb->bitmap[dst_au_idx] = auid;
        dss_set_auid(&src_partial_sfsb->bitmap[src_au_idx], DSS_INVALID_ID64);
        dst_sfsb->head.used_num++;
        src_partial_sfsb->head.used_num--;

        dss_redo_set_fs_block_t redo;
        redo.id = dst_sfsb->head.id;
        CM_ASSERT(!dss_cmp_blockid(redo.id, DSS_INVALID_64));
        redo.index = (uint16)dst_au_idx;
        redo.value = auid;
        redo.used_num = dst_sfsb->head.used_num;
        redo.old_value = dst_old_id;
        redo.old_used_num = dst_old_used_num;
        dss_put_log(session, vg_item, DSS_RT_SET_FILE_FS_BLOCK, &redo, sizeof(redo));

        redo.id = src_partial_sfsb->head.id;
        CM_ASSERT(!dss_cmp_blockid(redo.id, DSS_INVALID_64));
        redo.index = (uint16)src_au_idx;
        redo.value = src_partial_sfsb->bitmap[src_au_idx];
        redo.used_num = src_partial_sfsb->head.used_num;
        redo.old_value = src_old_id;
        redo.old_used_num = src_old_used_num;
        dss_put_log(session, vg_item, DSS_RT_SET_FILE_FS_BLOCK, &redo, sizeof(redo));
        // log buffer size 512kb / size of dss_redo_set_fs_block_t 32bytes ~ 16000, capable of holding above logs

        src_au_idx++;
        dst_au_idx++;
        auid = src_partial_sfsb->bitmap[src_au_idx];
    };
    // dst_second_fsb->head.used_num = curr_dst_au_idx;.
    LOG_DEBUG_INF("Success to transfer the partial FSB, curr src_au_idx:%u, curr dst_au_idx:%u, dst SFSB used num:%d, "
                  "src SFSB used num:%d.",
        src_au_idx, dst_au_idx, dst_sfsb->head.used_num, src_partial_sfsb->head.used_num);
}

static void dss_transfer_second_level_fsb(dss_session_t *session, dss_vg_info_item_t *vg_item,
    dss_fs_block_t *src_entry_fsb, dss_fs_block_t *dst_entry_fsb, uint32 curr_src_idx, int32 *dst_sfsb_idx)
{
    uint32 au_idx_limit = (DSS_FILE_SPACE_BLOCK_SIZE - sizeof(dss_fs_block_header)) / sizeof(auid_t);

    while (!dss_cmp_blockid(src_entry_fsb->bitmap[curr_src_idx], DSS_INVALID_64) && curr_src_idx < au_idx_limit) {
        dss_block_id_t dst_old_id = dst_entry_fsb->bitmap[*dst_sfsb_idx];
        dss_block_id_t src_old_id = src_entry_fsb->bitmap[curr_src_idx];
        uint16 dst_old_used_num = dst_entry_fsb->head.used_num;
        uint16 src_old_used_num = src_entry_fsb->head.used_num;
        CM_ASSERT(dss_cmp_blockid(dst_old_id, DSS_INVALID_64));

        dst_entry_fsb->bitmap[*dst_sfsb_idx] = src_entry_fsb->bitmap[curr_src_idx];
        dss_set_blockid(&src_entry_fsb->bitmap[curr_src_idx], DSS_INVALID_64);
        // '++' would cause overcnt by 1 err. Compensate 1 in caller.
        dst_entry_fsb->head.used_num = (uint16_t)(*dst_sfsb_idx + 1);
        src_entry_fsb->head.used_num--;
        CM_ASSERT(!dss_cmp_blockid(dst_entry_fsb->bitmap[*dst_sfsb_idx], DSS_INVALID_64));

        DSS_LOG_DEBUG_OP("Transferring second level fs block:%llu.", DSS_ID_TO_U64(src_old_id));

        dss_redo_set_fs_block_t redo;
        redo.id = dst_entry_fsb->head.id;
        CM_ASSERT(!dss_cmp_blockid(redo.id, DSS_INVALID_64));
        redo.index = (uint16)(*dst_sfsb_idx);
        redo.value = dst_entry_fsb->bitmap[*dst_sfsb_idx];
        redo.used_num = dst_entry_fsb->head.used_num;
        redo.old_used_num = dst_old_used_num;
        redo.old_value = dst_old_id;
        dss_put_log(session, vg_item, DSS_RT_SET_FILE_FS_BLOCK, &redo, sizeof(redo));

        redo.id = src_entry_fsb->head.id;
        CM_ASSERT(!dss_cmp_blockid(redo.id, DSS_INVALID_64));
        redo.index = (uint16)curr_src_idx;
        redo.value = src_entry_fsb->bitmap[curr_src_idx];
        redo.used_num = src_entry_fsb->head.used_num;
        redo.old_used_num = src_old_used_num;
        redo.old_value = src_old_id;
        dss_put_log(session, vg_item, DSS_RT_SET_FILE_FS_BLOCK, &redo, sizeof(redo));
        // 512KB of redo size in total, capable of holding all these logs

        LOG_DEBUG_INF("Success to transfer intact SFSB:%llu, from src EFSB:%llu[%u], to dst EFSB:%llu[%d], "
                      "curr src EFSB used num:%d, curr dst EFSB used num:%d.",
            DSS_ID_TO_U64(dst_entry_fsb->bitmap[*dst_sfsb_idx]), DSS_ID_TO_U64(src_entry_fsb->head.id), curr_src_idx,
            DSS_ID_TO_U64(dst_entry_fsb->head.id), *dst_sfsb_idx, src_entry_fsb->head.used_num,
            dst_entry_fsb->head.used_num);

        curr_src_idx++;
        (*dst_sfsb_idx)++;
    }
}

/* This function entails the essence of file truncation. Given a file table node that is already put in .recycle,
 * we perform:
 * 1. if truncation point==first AU in FSB, then simply transfer all 2-level FSBs and return. Else do:
 * 2. transfer trailing 2-level FSBs(might be none, or [0, n] whole FSBs + [0, 1] extant partial FSB) to recycled FSB;
 * 3. maintain last AUID idx from step 2, then transfer remaining AUs in FSB containing the truncation point.
 */
static void dss_build_truncated_ftn(dss_session_t *session, dss_vg_info_item_t *vg_item, dss_fs_block_t *src_entry_fsb,
    dss_fs_block_t *dst_entry_fsb, uint32 src_partial_sfsb_idx, uint32 src_au_idx)
{
    int32 dst_sfsb_idx = 0;
    uint32 curr_src_idx = src_partial_sfsb_idx + 1;  // src 2nd idx indicates FSB containing fraction of AUs to trunc
    uint32 au_idx_limit = (DSS_FILE_SPACE_BLOCK_SIZE - sizeof(dss_fs_block_header)) / sizeof(auid_t);

    cm_assert(!dss_cmp_blockid(dst_entry_fsb->bitmap[0], DSS_INVALID_64));
    dss_block_id_t cache_first_sfsb = dst_entry_fsb->bitmap[0];  // cache 1st sfsb for partial txfer
    dss_set_blockid(&dst_entry_fsb->bitmap[0], DSS_INVALID_64);

    /*
     * Only happens when file size exceeds 2k*AU size.
     * transfer all *intact* secondary file space blocks to recycle efsb
     * note free FSB meta happens during alloc au from recycle, not here
     */
    dss_transfer_second_level_fsb(session, vg_item, src_entry_fsb, dst_entry_fsb, curr_src_idx, &dst_sfsb_idx);

    // Prep to transfer partial-FSB AUs. src_au is the first AU to trunc
    dst_sfsb_idx--;  // geq 0 means has trunc intact sfsb; -1 otherwise

    if (src_au_idx < au_idx_limit) {
        dss_fs_block_t *src_partial_sfsb = NULL;
        dss_block_id_t src_partial_sfsb_id = src_entry_fsb->bitmap[src_partial_sfsb_idx];
        (void)dss_get_second_block(vg_item, src_partial_sfsb_id, &src_partial_sfsb);
        CM_ASSERT(src_partial_sfsb != NULL);

        dss_fs_block_t *dst_sfsb = NULL;
        dss_block_id_t dst_sfsb_id = dst_entry_fsb->bitmap[dst_sfsb_idx < 0 ? 0 : dst_sfsb_idx];
        dst_sfsb_id = dss_cmp_blockid(dst_sfsb_id, DSS_INVALID_64) ? cache_first_sfsb : dst_sfsb_id;
        (void)dss_get_second_block(vg_item, dst_sfsb_id, &dst_sfsb);

        uint32 dst_au_idx = 0;
        while (dst_au_idx < au_idx_limit && !dss_cmp_auid(dst_sfsb->bitmap[dst_au_idx], DSS_INVALID_64)) {
            dst_au_idx++;
        }  // found dst 2-level FSB's first available AU

        // If curr dst sfsb won't hold all AUs, or no intact trunc, we need cached sfsb.
        if (src_au_idx < dst_au_idx || dst_sfsb_idx < 0) {
            uint16 idx_for_cached_sfsb = dst_sfsb_idx < 0 ? 0 : (uint16)dst_sfsb_idx + 1;
            cm_assert(dss_cmp_blockid(dst_entry_fsb->bitmap[idx_for_cached_sfsb], DSS_INVALID_64));

            uint16 dst_old_used_num = dst_entry_fsb->head.used_num;
            dss_block_id_t dst_old_id = dst_entry_fsb->bitmap[idx_for_cached_sfsb];
            dst_entry_fsb->head.used_num = dst_sfsb_idx < 0 ? 1 : dst_old_used_num + 1;  // +1 cuz normed in txfr intact
            dst_entry_fsb->bitmap[idx_for_cached_sfsb] = cache_first_sfsb;
            cm_assert(!dss_cmp_blockid(cache_first_sfsb, DSS_INVALID_64));

            dss_redo_set_fs_block_t redo;
            redo.id = dst_entry_fsb->head.id;
            redo.index = idx_for_cached_sfsb;
            redo.value = dst_entry_fsb->bitmap[idx_for_cached_sfsb];
            redo.used_num = dst_entry_fsb->head.used_num;
            redo.old_used_num = dst_old_used_num;
            redo.old_value = dst_old_id;
            dss_put_log(session, vg_item, DSS_RT_SET_FILE_FS_BLOCK, &redo, sizeof(redo));
        } else {
            ga_obj_id_t cached_objid;
            dss_fs_block_t *cached_block = (dss_fs_block_t *)dss_find_block_in_shm(
                vg_item, cache_first_sfsb, DSS_BLOCK_TYPE_FS, CM_TRUE, &cached_objid, CM_FALSE);
            if (!cached_block) {
                LOG_DEBUG_ERR("Failed to get cached fs block %llu, maybe no memory.", DSS_ID_TO_U64(cache_first_sfsb));
                DSS_THROW_ERROR(ERR_ALLOC_MEMORY, sizeof(dss_fs_block_t), "cached_block");
                cm_panic(0);
            }
            dss_free_fs_block_addr(session, vg_item, (char *)cached_block, cached_objid);
        }

        dss_fs_block_t *dst_second_sfsb = NULL;
        dss_get_second_block(vg_item, cache_first_sfsb, &dst_second_sfsb);
        dst_second_sfsb = dst_sfsb_idx < 0 ? NULL : dst_second_sfsb;
        dss_transfer_remaining_au(
            session, src_partial_sfsb, dst_sfsb, dst_second_sfsb, src_au_idx, dst_au_idx, vg_item);
    }
}

/* validate params, lock VG and process recovery for truncate */
static status_t dss_prepare_truncate(dss_session_t *session, char *vg_name, uint64 length)
{
    dss_vg_info_item_t *vg_item = dss_find_vg_item(vg_name);
    if (vg_item == NULL) {
        LOG_DEBUG_ERR("Failed to find vg with name %s.", vg_name);
        DSS_THROW_ERROR(ERR_DSS_VG_NOT_EXIST, vg_name);
        return CM_ERROR;
    }
    dss_lock_vg_mem_and_shm_x(session, vg_item);

    status_t status = dss_check_file(vg_item);
    if (status != CM_SUCCESS) {
        dss_unlock_vg_mem_and_shm(session, vg_item);
        LOG_DEBUG_ERR("Failed to check file,errcode:%d.", cm_get_error_code());
        return status;
    }
    return CM_SUCCESS;
}

static status_t dss_init_trunc_ftn(dss_session_t *session, dss_vg_info_item_t *vg_item, const gft_node_t *node,
    gft_node_t **truncated_ftn, uint64 length)
{
    dss_au_root_t *dss_au_root = DSS_GET_AU_ROOT(vg_item->dss_ctrl);
    ftid_t free_root = *(ftid_t *)(&dss_au_root->free_root);
    gft_node_t *recycle_dir = dss_get_ft_node_by_ftid(vg_item, free_root, CM_TRUE, CM_FALSE);

    char trunc_name[DSS_MAX_NAME_LEN];
    date_detail_t detail = g_timer()->detail;
    int iret_snprintf = snprintf_s(trunc_name, sizeof(trunc_name), sizeof(trunc_name) - 1, "%s_sz%llu_%02u%02u%02u%03u",
        node->name, node->size - length, detail.hour, detail.min, detail.sec, detail.millisec);
    DSS_SECUREC_SS_RETURN_IF_ERROR(iret_snprintf, CM_ERROR);
    *truncated_ftn = dss_alloc_ft_node(session, vg_item, recycle_dir, trunc_name, GFT_FILE);
    status_t status = dss_process_redo_log(session, vg_item);
    if (status != CM_SUCCESS) {
        LOG_RUN_ERR("[DSS] ABORT INFO: redo log process failed, errcode:%d, OS errno:%d, OS errmsg:%s.",
            cm_get_error_code(), errno, strerror(errno));
        cm_fync_logfile();
        _exit(1);
    }
    if (*truncated_ftn == NULL) {
        LOG_DEBUG_ERR("Failed to alloc_ft_node.");
        cm_panic(0);
    }
    return CM_SUCCESS;
}

static void dss_truncate_set_sizes(
    dss_session_t *session, dss_vg_info_item_t *vg_item, gft_node_t *node, gft_node_t *trunc_ftn, uint64 length)
{
    uint64 au_size = dss_get_vg_au_size(vg_item->dss_ctrl);
    uint64 align_length = CM_CALC_ALIGN(length, au_size);
    dss_redo_set_file_size_t redo_size;
    uint64 old_size = trunc_ftn->size;
    trunc_ftn->size = node->size - align_length;
    trunc_ftn->written_size = 0;
    redo_size.ftid = trunc_ftn->id;
    redo_size.size = trunc_ftn->size;
    redo_size.oldsize = old_size;
    dss_put_log(session, vg_item, DSS_RT_SET_FILE_SIZE, &redo_size, sizeof(redo_size));

    old_size = node->size;
    node->size = align_length;
    node->written_size = length < node->written_size ? length : node->written_size;
    redo_size.ftid = node->id;
    redo_size.size = node->size;
    redo_size.oldsize = old_size;
    dss_put_log(session, vg_item, DSS_RT_SET_FILE_SIZE, &redo_size, sizeof(redo_size));
}

status_t truncate_to_extend(dss_session_t *session, dss_vg_info_item_t *vg_item, gft_node_t *node, uint64 size)
{
    status_t status = CM_SUCCESS;
    uint64 au_size = dss_get_vg_au_size(vg_item->dss_ctrl);
    uint64 align_size = CM_CALC_ALIGN(size, au_size);

    /* ready to extend file size to `align_size`, but its written_size is `size` */
    int64 offset;
    for (offset = (int64)node->size; offset < (int64)align_size; offset += (int64)au_size) {
        status = dss_extend_inner(session, node->fid, node->id, offset, vg_item->vg_name, vg_item->id, CM_FALSE);
        if (status != CM_SUCCESS) {
            return status;
        }
    }
    node->written_size = size;
    /* we need to add written_size redo future, now flush ft block to disk directly. */
    dss_ft_block_t *block = dss_get_ft_block_by_node(node);
    status = dss_update_ft_block_disk(vg_item, block, node->id);
    return status;
}

status_t dss_truncate(dss_session_t *session, uint64 fid, ftid_t ftid, int64 offset, uint64 length, char *vg_name)
{
    CM_RETURN_IFERR(dss_prepare_truncate(session, vg_name, length));

    // update props on FT, generate new FT node in recycle with props, check v3 usage on truncate
    status_t status = CM_SUCCESS;
    gft_node_t *node = NULL;
    dss_fs_block_header *entry_block = NULL;
    dss_config_t *inst_cfg = dss_get_inst_cfg();
    dss_vg_info_item_t *vg_item = dss_find_vg_item(vg_name);
    CM_RETURN_IFERR(dss_get_block_entry(session, vg_item, inst_cfg, fid, ftid, &node, &entry_block));
    uint64 au_size = dss_get_vg_au_size(vg_item->dss_ctrl);
    uint64 align_length = CM_CALC_ALIGN(length, au_size);
#ifdef OPENGAUSS
    if (node->written_size < length) {
#else
    if (node->size < align_length) {
#endif
        /* to extend the file */
        status = truncate_to_extend(session, vg_item, node, length);
        dss_unlock_vg_mem_and_shm(session, vg_item);
        return status;
    }

    if (!dss_is_truncate_necessary(node, align_length, au_size)) {
        dss_unlock_vg_mem_and_shm(session, vg_item);
        return CM_SUCCESS;
    }
    /*
     * Key idea: what to check when determining that we've reached EOF during R/W? we must make sure no out-of-bound
     * R/W on truncated file. Answer is the second file space block id at the truncate point should be invalid64.
     * More importantly, truncated space must be recycled for re-use, meaning the metadata in .recycle must be
     * generated accordingly, associated with the file space block(s) taken from the truncated file.
     */

    // find truncate point(FSB index: &block_count, and AU index: &block_au_count) in 2-level bitmap
    dss_fs_block_t *entry_fs_block = (dss_fs_block_t *)entry_block;
    uint32 block_count = 0;
    uint32 block_au_count = 0;
    uint32 au_offset = 0;
    status = dss_get_fs_block_info_by_offset((int64)align_length, au_size, &block_count, &block_au_count, &au_offset);
    if (status != CM_SUCCESS) {
        dss_unlock_vg_mem_and_shm(session, vg_item);
        LOG_DEBUG_ERR("The offset(%llu) is not correct, real block count:%u.", align_length, block_count);
        return CM_ERROR;
    }
    /* Perform truncating file space blocks. */
    gft_node_t *trunc_ftn;
    DSS_RETURN_IFERR3(dss_init_trunc_ftn(session, vg_item, node, &trunc_ftn, align_length),
        dss_unlock_shm_meta(session, vg_item->vg_latch), dss_unlock_vg_mem(vg_item));

    LOG_DEBUG_INF("Begin to truncate file:%s, length:%llu, align_length:%llu, SFSB idx:%u, AU idx:%u", node->name,
        length, align_length, block_count, block_au_count);

    dss_fs_block_t *dst_entry_fsb =
        (dss_fs_block_t *)dss_find_block_in_shm(vg_item, trunc_ftn->entry, DSS_BLOCK_TYPE_FS, CM_TRUE, NULL, CM_FALSE);
    uint32 au_trunc_idx = au_offset == 0 ? block_au_count : block_au_count + 1;
    dss_build_truncated_ftn(session, vg_item, entry_fs_block, dst_entry_fsb, block_count, au_trunc_idx);
    dss_truncate_set_sizes(session, vg_item, node, trunc_ftn, length);
    /* Truncating file space block completed. */
    status = dss_process_redo_log(session, vg_item);
    if (status != CM_SUCCESS) {
        dss_unlock_vg_mem_and_shm(session, vg_item);
        LOG_RUN_ERR("[DSS] ABORT INFO: redo log process failed, errcode:%d, OS errno:%d, OS errmsg:%s.",
            cm_get_error_code(), errno, strerror(errno));
        cm_fync_logfile();
        _exit(1);
    }

    // release resources
    dss_unlock_vg_mem_and_shm(session, vg_item);
    LOG_DEBUG_INF(
        "Succeed to truncate file:%s, size:%llu, written_size:%llu", node->name, node->size, node->written_size);
    return CM_SUCCESS;
}

static status_t dss_refresh_file_core(dss_vg_info_item_t *vg_item, uint64 fid, ftid_t ftid, dss_block_id_t blockid)
{
    gft_node_t *node = dss_get_ft_node_by_ftid(vg_item, ftid, CM_TRUE, CM_FALSE);
    if (!node) {
        LOG_DEBUG_ERR("Failed to find ftid,ftid: %llu.", *(uint64 *)&ftid);
        return CM_ERROR;
    }

    if (node->fid != fid) {
        LOG_DEBUG_ERR("Fid is not match,(%llu,%llu).", node->fid, fid);
        return CM_ERROR;
    }
    // check the entry and load
    char *block = dss_find_block_in_shm(vg_item, node->entry, DSS_BLOCK_TYPE_FS, CM_TRUE, NULL, CM_FALSE);
    if (!block) {
        LOG_DEBUG_ERR("Failed to find block:%llu.", *(uint64 *)&node->entry);
        return CM_ERROR;
    }

    bool32 cmp = dss_cmp_blockid(blockid, CM_INVALID_ID64);
    if (cmp == 0) {
        block = dss_find_block_in_shm(vg_item, blockid, DSS_BLOCK_TYPE_FS, CM_TRUE, NULL, CM_FALSE);
        if (!block) {
            LOG_DEBUG_ERR("Failed to find block:%llu.", DSS_ID_TO_U64(blockid));
            return CM_ERROR;
        }
    }
    return CM_SUCCESS;
}

status_t dss_refresh_file(dss_session_t *session, uint64 fid, ftid_t ftid, char *vg_name, dss_block_id_t blockid)
{
    dss_vg_info_item_t *vg_item = dss_find_vg_item(vg_name);
    if (vg_item == NULL) {
        LOG_DEBUG_ERR("Failed to find vg,vg name %s.", vg_name);
        DSS_THROW_ERROR(ERR_DSS_VG_NOT_EXIST, vg_name);
        return CM_ERROR;
    }

    dss_lock_vg_mem_and_shm_x(session, vg_item);
    status_t ret = dss_refresh_file_core(vg_item, fid, ftid, blockid);
    dss_unlock_vg_mem_and_shm(session, vg_item);
    return ret;
}

void dss_init_root_fs_block(dss_ctrl_t *dss_ctrl)
{
    CM_ASSERT(dss_ctrl != NULL);
    dss_fs_block_root_t *block_root = DSS_GET_FS_BLOCK_ROOT(dss_ctrl);
    block_root->version = 0;
    block_root->free.count = 0;
    dss_set_auid(&block_root->free.first, CM_INVALID_ID64);
    dss_set_auid(&block_root->free.last, CM_INVALID_ID64);
}

status_t dss_refresh_volume(dss_session_t *session, const char *name_str, uint32 vgid, uint32 volumeid)
{
#ifdef OPENGAUSS
    if (dss_is_readwrite()) {
        return CM_SUCCESS;
    }
#endif
    dss_vg_info_item_t *vg_item = dss_find_vg_item(name_str);
    if (!vg_item) {
        DSS_THROW_ERROR(ERR_DSS_VG_NOT_EXIST, name_str);
        return CM_ERROR;
    }
    status_t status;
    dss_lock_shm_meta_x(session, vg_item->vg_latch);
    status = dss_check_volume(vg_item, volumeid);
    dss_unlock_shm_meta(session, vg_item->vg_latch);
    return status;
}

status_t dss_refresh_vginfo(dss_vg_info_item_t *vg_item)
{
#ifdef OPENGAUSS
    if (dss_is_readwrite()) {
        return CM_SUCCESS;
    }
#endif
    uint64 version;
    if (dss_get_core_version(vg_item, &version) != CM_SUCCESS) {
        LOG_DEBUG_ERR("Failed to get core version, vg %s.", vg_item->entry_path);
        return CM_ERROR;
    }
    DSS_LOG_DEBUG_OP(
        "dss_refresh_vginfo get core version:%llu, cmp version:%llu.", version, vg_item->dss_ctrl->core.version);
    if (dss_compare_version(version, vg_item->dss_ctrl->core.version)) {
        if (dss_check_volume(vg_item, CM_INVALID_ID32) != CM_SUCCESS) {
            LOG_DEBUG_ERR("Failed to check volume, vg %s.", vg_item->entry_path);
            DSS_THROW_ERROR(ERR_DSS_VG_CHECK, vg_item->vg_name, "refresh volume group info before add volume failed.");
            return CM_ERROR;
        }
        if (dss_load_core_ctrl(vg_item, &vg_item->dss_ctrl->core) != CM_SUCCESS) {
            LOG_DEBUG_ERR("Failed to get core ctrl, vg %s.", vg_item->entry_path);
            DSS_THROW_ERROR(ERR_DSS_VG_CHECK, vg_item->vg_name, "refresh volume group info before add volume failed.");
            return CM_ERROR;
        }
    }
    return CM_SUCCESS;
}

status_t dss_load_fs_block_by_blockid(dss_vg_info_item_t *vg_item, dss_block_id_t blockid, int32 size)
{
    char *block = dss_find_block_in_shm(vg_item, blockid, DSS_BLOCK_TYPE_FS, CM_FALSE, NULL, CM_FALSE);
    CM_ASSERT(block != NULL);
    int64 offset = dss_get_fs_block_offset(vg_item, blockid);
    status_t status = dss_get_block_from_disk(vg_item, blockid, block, offset, size, CM_TRUE);
    if (status != CM_SUCCESS) {
        LOG_DEBUG_ERR("Failed to get block %s.", vg_item->entry_path);
        return status;
    }

    return CM_SUCCESS;
}
status_t dss_check_rename_path(dss_session_t *session, const char *src_path, const char *dst_path, text_t *dst_name)
{
    text_t src_dir;
    text_t src_name;
    cm_str2text((char *)src_path, &src_name);
    if (!cm_fetch_rtext(&src_name, '/', '\0', &src_dir)) {
        LOG_DEBUG_ERR("not a complete absolute path name(%s %s)", T2S(&src_dir), src_path);
        DSS_THROW_ERROR(ERR_DSS_FILE_RENAME, "can not change path.");
        return CM_ERROR;
    }

    text_t dst_dir;
    cm_str2text((char *)dst_path, dst_name);
    if (!cm_fetch_rtext(dst_name, '/', '\0', &dst_dir)) {
        LOG_DEBUG_ERR("not a complete absolute path name(%s %s)", T2S(&dst_dir), dst_path);
        return CM_ERROR;
    }

    if (cm_text_equal(&src_dir, &dst_dir) == CM_FALSE) {
        DSS_THROW_ERROR(ERR_DSS_FILE_RENAME, "can not change path.");
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

status_t dss_check_open_file_remote(const char *vg_name, uint64 ftid, bool32 *is_open)
{
    *is_open = CM_FALSE;

    DSS_LOG_DEBUG_OP("[DSS-MES-CB]Begin to check file-open %llu.", ftid);
    dss_vg_info_item_t *vg_item = dss_find_vg_item(vg_name);
    if (vg_item == NULL) {
        DSS_THROW_ERROR(ERR_DSS_VG_NOT_EXIST, vg_name);
        LOG_DEBUG_ERR("Failed to find vg, %s.", vg_name);
        return CM_ERROR;
    }

    if (dss_check_open_file(vg_item, ftid, is_open) != CM_SUCCESS) {
        LOG_DEBUG_ERR("Failed to check open file, vg: %s, ftid:%llu.", vg_name, ftid);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

status_t dss_refresh_ft_block(dss_session_t *session, char *vg_name, uint32 vgid, dss_block_id_t blockid)
{
    status_t status;
    dss_vg_info_item_t *vg_item = dss_find_vg_item(vg_name);
    if (!vg_item) {
        LOG_DEBUG_ERR("Failed to find vg,vg name %s.", vg_name);
        DSS_THROW_ERROR(ERR_DSS_VG_NOT_EXIST, vg_name);
        return CM_ERROR;
    }
    dss_lock_vg_mem_and_shm_x(session, vg_item);
    gft_node_t *node = dss_get_ft_node_by_ftid(vg_item, blockid, CM_TRUE, CM_TRUE);
    if (!node) {
        dss_unlock_vg_mem_and_shm(session, vg_item);
        LOG_DEBUG_ERR("Failed to find ftid,ftid: %llu.", *(uint64 *)&blockid);
        return CM_ERROR;
    }

    if (node->type == GFT_PATH) {
        status = dss_refresh_dir_r(vg_item, node, CM_FALSE);
        if (status != CM_SUCCESS) {
            LOG_DEBUG_ERR("Failed to refesh dir vg:%s, dir name:%s, ftid:%llu, pid:%llu.", vg_item->vg_name, node->name,
                *(uint64 *)&node->id, session->cli_info.cli_pid);
            dss_unlock_vg_mem_and_shm(session, vg_item);
            return CM_ERROR;
        }
    }
    dss_unlock_vg_mem_and_shm(session, vg_item);
    return CM_SUCCESS;
}

status_t dss_update_file_written_size(
    dss_session_t *session, char *vg_name, uint64 written_size, dss_block_id_t blockid)
{
    dss_vg_info_item_t *vg_item = dss_find_vg_item(vg_name);
    if (!vg_item) {
        LOG_DEBUG_ERR("Failed to find vg,vg name %s.", vg_name);
        DSS_THROW_ERROR(ERR_DSS_VG_NOT_EXIST, vg_name);
        return CM_ERROR;
    }
    dss_lock_vg_mem_x(vg_item);
    LOG_DEBUG_INF("Begin to update file written_size:%llu.", written_size);

    gft_node_t *node = dss_get_ft_node_by_ftid(vg_item, blockid, CM_TRUE, CM_FALSE);
    if (!node) {
        dss_unlock_vg_mem(vg_item);
        LOG_DEBUG_ERR("Failed to find FTN, ftid: %llu.", *(uint64 *)&blockid);
        return CM_ERROR;
    }

    node->written_size = node->written_size > written_size ? node->written_size : written_size;
    cm_assert((bool32)node->written_size <= node->size);
    dss_ft_block_t *cur_block = dss_get_ft_block_by_node(node);
    status_t status = dss_update_ft_block_disk(vg_item, cur_block, node->id);
    LOG_DEBUG_INF(
        "Success to update written_size:%llu of file:%s, node size:%llu.", node->written_size, node->name, node->size);
    dss_unlock_vg_mem(vg_item);
    return status;
}
