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
 * dsscmd_create_vg.c
 *
 *
 * IDENTIFICATION
 *    src/cmd/dsscmd_create_vg.c
 *
 * -------------------------------------------------------------------------
 */

#include "dsscmd_create_vg.h"
#include "dss_file.h"
#include "dss_redo.h"
#include "dss_malloc.h"

static void dss_get_vg_time(timeval_t *tv_begin)
{
    (void)cm_gettimeofday(tv_begin);
}

static void dss_set_ctrl_checksum(dss_ctrl_t *ctrl)
{
    ctrl->vg_info.checksum = dss_get_checksum(ctrl->vg_data, DSS_VG_DATA_SIZE);
    ctrl->core.checksum = dss_get_checksum(ctrl->core_data, DSS_CORE_CTRL_SIZE);
    ctrl->volume.checksum = dss_get_checksum(ctrl->volume_data, DSS_VOLUME_CTRL_SIZE);
    dss_root_ft_block_t *ft_root = DSS_GET_ROOT_BLOCK(ctrl);
    ft_root->ft_block.common.checksum = dss_get_checksum(ctrl->root, DSS_BLOCK_SIZE);
}

// NOTE:only called by create vg, no need to record redo log
static status_t vg_initialize_resource(dss_vg_info_item_t *vg_item, gft_node_t *parent_node)
{
    gft_node_t *node;
    /* create `.recycle` directory */
    node =
        dss_alloc_ft_node_when_create_vg(vg_item, parent_node, DSS_RECYLE_DIR_NAME, GFT_PATH, DSS_FT_NODE_FLAG_SYSTEM);
    CM_ASSERT(node != NULL);
    if (node == NULL) {
        LOG_DEBUG_ERR("Failed to allocate file table node.");
        return CM_ERROR;
    }

    dss_au_root_t *dss_au_root = DSS_GET_AU_ROOT(vg_item->dss_ctrl);
    dss_au_root->free_root = *(uint64 *)(&parent_node->items.first);
    return dss_update_core_ctrl_disk(vg_item);
}

static void dss_static_assert_info(void)
{
    DSS_STATIC_ASSERT(sizeof(dss_ctrl_t) == SIZE_M(1));
    DSS_STATIC_ASSERT(sizeof(dss_ctrl_t) <= DSS_CTRL_SIZE);
    DSS_STATIC_ASSERT(sizeof(auid_t) == LENGTH_EIGHT_BYTE);
    DSS_STATIC_ASSERT(sizeof(dss_redo_batch_t) % LENGTH_EIGHT_BYTE == 0);
    DSS_STATIC_ASSERT(DSS_VG_DATA_SIZE == DSS_DISK_UNIT_SIZE);
    DSS_STATIC_ASSERT(DSS_MAX_AU_SIZE / DSS_BLOCK_SIZE <= (1 << DSS_MAX_BIT_NUM_BLOCK));
    DSS_STATIC_ASSERT(sizeof(ga_obj_id_t) == LENGTH_EIGHT_BYTE);
    DSS_STATIC_ASSERT(sizeof(dss_fs_block_header) + sizeof(dss_block_id_t) < DSS_DISK_UNIT_SIZE);
    DSS_STATIC_ASSERT(sizeof(dss_share_vg_item_t) % DSS_DISK_UNIT_SIZE == 0);
    DSS_STATIC_ASSERT(DSS_DISK_UNIT_SIZE == DSS_ALIGN_SIZE);
    DSS_STATIC_ASSERT(sizeof(dss_core_ctrl_t) <= DSS_CORE_CTRL_SIZE);
    DSS_STATIC_ASSERT(sizeof(dss_vg_header_t) <= DSS_VG_DATA_SIZE);
    DSS_STATIC_ASSERT(sizeof(dss_volume_attr_t) <= DSS_DISK_UNIT_SIZE);
    DSS_STATIC_ASSERT(sizeof(dss_volume_def_t) <= DSS_DISK_UNIT_SIZE);
    DSS_STATIC_ASSERT(sizeof(dss_fs_block_root_t) <= DSS_FS_BLOCK_ROOT_SIZE);
    DSS_STATIC_ASSERT(OFFSET_OF(dss_core_ctrl_t, volume_attrs) == DSS_DISK_UNIT_SIZE);
    DSS_STATIC_ASSERT(sizeof(dss_au_root_t) <= DSS_AU_ROOT_SIZE);
    DSS_STATIC_ASSERT(sizeof(dss_core_ctrl_t) % DSS_DISK_UNIT_SIZE == 0);
}

static status_t dss_check_volume_invalid(const char *volume_name)
{
    if (strlen(volume_name) >= DSS_FILE_PATH_MAX_LENGTH) {
        DSS_THROW_ERROR_EX(
            ERR_DSS_VG_CREATE, "volume name %s is too long, cannot exceed %u.", volume_name, DSS_FILE_PATH_MAX_LENGTH);
        return CM_ERROR;
    }
    dss_volume_t volume;
    status_t ret = dss_open_volume(volume_name, NULL, DSS_INSTANCE_OPEN_FLAG, &volume);
    DSS_RETURN_IFERR2(ret, LOG_DEBUG_ERR("open volume %s failed.", volume_name));

    // check if the volume is used
    dss_volume_header_t *vol_cmp_head = (dss_volume_header_t *)cm_malloc_align(DSS_ALIGN_SIZE, DSS_ALIGN_SIZE);
    if (vol_cmp_head == NULL) {
        dss_close_volume(&volume);
        DSS_THROW_ERROR(ERR_ALLOC_MEMORY, DSS_ALIGN_SIZE, "dss_create_vg");
        return CM_ERROR;
    }

    status_t status = CM_ERROR;
    do {
        DSS_BREAK_IF_ERROR(dss_read_volume(&volume, 0, vol_cmp_head, (int32)DSS_ALIGN_SIZE));
        if (vol_cmp_head->valid_flag == DSS_CTRL_VALID_FLAG) {
            // cannot add a exists volume
            DSS_THROW_ERROR(ERR_DSS_VOLUME_ADD_EXISTED, volume_name, vol_cmp_head->vg_name);
            break;
        }
        status = CM_SUCCESS;
    } while (0);

    dss_close_volume(&volume);
    DSS_FREE_POINT(vol_cmp_head);
    return status;
}

static status_t dss_check_parameter(const char *vg_name, const char *volume_name, const dss_config_t *inst_cfg)
{
    status_t status = dss_check_name(vg_name);
    DSS_RETURN_IFERR2(status, DSS_THROW_ERROR(ERR_DSS_VG_CREATE, vg_name, "volume group name is invalid"));
    if ((volume_name == NULL) || (inst_cfg == NULL)) {
        DSS_THROW_ERROR(ERR_DSS_VG_CREATE, vg_name, "volume name or config is invalid.");
        return CM_ERROR;
    }
    status = dss_check_volume_invalid(volume_name);
    DSS_RETURN_IFERR2(status, LOG_DEBUG_ERR("volume:%s is invalid.", volume_name));
    return CM_SUCCESS;
}

static status_t dss_initial_vg_ctrl(
    const char *vg_name, const char *volume_name, dss_volume_t *volume, dss_ctrl_t *vg_ctrl, uint32 size)
{
    uint32 au_size = 0;
    errno_t errcode;
    errcode = memset_s(vg_ctrl, sizeof(dss_ctrl_t), 0, sizeof(dss_ctrl_t));
    if (errcode != EOK) {
        DSS_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
        return CM_ERROR;
    }
    vg_ctrl->vg_info.vol_type.id = 0;
    vg_ctrl->vg_info.vol_type.type = DSS_VOLUME_TYPE_MANAGER;
    errcode = strncpy_s(
        vg_ctrl->vg_info.vol_type.entry_volume_name, DSS_MAX_VOLUME_PATH_LEN, volume_name, strlen(volume_name));
    if (errcode != EOK) {
        DSS_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
        return CM_ERROR;
    }
    errcode = strncpy_s(vg_ctrl->vg_info.vg_name, DSS_MAX_NAME_LEN, vg_name, strlen(vg_name));
    if (errcode != EOK) {
        DSS_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
        return CM_ERROR;
    }
    dss_get_vg_time(&vg_ctrl->vg_info.create_time);

    au_size = (size == 0 ? DSS_DEFAULT_AU_SIZE : SIZE_K(size));
    dss_set_vg_au_size(vg_ctrl, au_size);

    errcode = strncpy_s(vg_ctrl->volume.defs[0].name, DSS_MAX_VOLUME_PATH_LEN, volume_name, strlen(volume_name));
    if (errcode != EOK) {
        DSS_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
        return CM_ERROR;
    }
    vg_ctrl->volume.defs[0].flag = 1;
    vg_ctrl->volume.defs[0].id = 0;

    vg_ctrl->core.volume_count = 1;
    vg_ctrl->core.volume_attrs[0].flag = 1;
    vg_ctrl->core.volume_attrs[0].id = 0;

    vg_ctrl->core.volume_attrs[0].hwm = dss_get_vg_au_size(vg_ctrl);
    vg_ctrl->core.volume_attrs[0].size = dss_get_volume_size(volume);
    if (vg_ctrl->core.volume_attrs[0].size == DSS_INVALID_64) {
        LOG_DEBUG_ERR("Failed to get volume size when create vg %s.", vg_name);
        return CM_ERROR;
    }
    vg_ctrl->core.volume_attrs[0].free = vg_ctrl->core.volume_attrs[0].size - dss_get_vg_au_size(vg_ctrl);
    return CM_SUCCESS;
}

static status_t dss_write_volume_ctrl_info(
    const char *volume_name, dss_volume_t *volume, dss_ctrl_t *vg_ctrl, dss_vg_info_item_t *vg_item)
{
    status_t status;
    dss_init_au_root(vg_ctrl);
    dss_init_root_fs_block(vg_ctrl);

    gft_node_t *node;
    dss_init_ft_root(vg_ctrl, &node);
    dss_set_ctrl_checksum(vg_ctrl);

    status = dss_write_volume(volume, 0, vg_ctrl, sizeof(dss_ctrl_t));
    if (status == CM_SUCCESS) {
        // write to backup area
        status = dss_write_volume(volume, DSS_CTRL_BAK_ADDR, vg_ctrl, sizeof(dss_ctrl_t));
    }
    DSS_RETURN_IFERR2(status, LOG_DEBUG_ERR("Failed write volume,errcode:%d.", status));

    status = vg_initialize_resource(vg_item, node);
    DSS_RETURN_IFERR2(status, LOG_DEBUG_ERR("Failed to initialize resource,errcode:%d.", status));

    // set the vg valid flag. avoid that write disk array failed.
    vg_ctrl->vg_info.valid_flag = DSS_CTRL_VALID_FLAG;
    dss_set_ctrl_checksum(vg_ctrl);
    status = dss_write_volume(volume, (int64)DSS_CTRL_VG_DATA_OFFSET, vg_ctrl, DSS_VG_DATA_SIZE);
    if (status == CM_SUCCESS) {
        // write to backup area
        status = dss_write_volume(volume, (int64)DSS_CTRL_BAK_VG_DATA_OFFSET, vg_ctrl, DSS_VG_DATA_SIZE);
    }
    DSS_RETURN_IFERR2(status, LOG_DEBUG_ERR("write volume %s failed.", volume_name));
    return CM_SUCCESS;
}

static status_t dss_set_vg_ctrl(
    const char *vg_name, const char *volume_name, dss_vg_info_item_t *vg_item, dss_config_t *inst_cfg, uint32 size)
{
    status_t status;
    dss_ctrl_t *vg_ctrl = (dss_ctrl_t *)cm_malloc_align(DSS_ALIGN_SIZE, sizeof(dss_ctrl_t));
    if (vg_ctrl == NULL) {
        dss_free_vg_info(g_vgs_info);
        LOG_DEBUG_ERR("Failed to alloc memory, vg name is %s, volume name is %s.\n", vg_name, volume_name);
        DSS_THROW_ERROR(ERR_ALLOC_MEMORY, sizeof(dss_ctrl_t), "vg_ctrl");
        return CM_ERROR;
    }
    vg_item->dss_ctrl = vg_ctrl;
    do {
        status = dss_lock_vg_storage(vg_item, volume_name, inst_cfg);
        DSS_BREAK_IFERR2(status, LOG_DEBUG_ERR("Failed to lock vg %s.", volume_name));
        dss_volume_t volume;
        status = dss_open_volume(volume_name, NULL, DSS_INSTANCE_OPEN_FLAG, &volume);
        DSS_BREAK_IFERR3(status, dss_unlock_vg_storage(vg_item, volume_name, inst_cfg),
            LOG_DEBUG_ERR("open volume %s failed.", volume_name));

        status = dss_initial_vg_ctrl(vg_name, volume_name, &volume, vg_ctrl, size);
        if (status != CM_SUCCESS) {
            dss_close_volume(&volume);
            dss_unlock_vg_storage(vg_item, volume_name, inst_cfg);
            LOG_DEBUG_ERR("initial_vg_ctrl failed.vg %s,vm %s.", vg_name, volume_name);
            break;
        }
        status = dss_set_log_buf(vg_name, vg_item, &volume);
        if (status != CM_SUCCESS) {
            dss_close_volume(&volume);
            dss_unlock_vg_storage(vg_item, volume_name, inst_cfg);
            LOG_DEBUG_ERR("initial global log buffer failed.vg %s,vm %s.", vg_name, volume_name);
            break;
        }
        status = dss_write_volume_ctrl_info(volume_name, &volume, vg_ctrl, vg_item);
        if (status != CM_SUCCESS) {
            dss_close_volume(&volume);
            dss_unlock_vg_storage(vg_item, volume_name, inst_cfg);
            LOG_DEBUG_ERR("dss write volume ctrl info failed.vm %s.", volume_name);
            break;
        }
        dss_close_volume(&volume);
        dss_unlock_vg_storage(vg_item, volume_name, inst_cfg);
    } while (0);
    DSS_FREE_POINT(vg_ctrl);
    dss_free_vg_info(g_vgs_info);
    return status;
}

status_t dss_create_vg(const char *vg_name, const char *volume_name, dss_config_t *inst_cfg, uint32 size)
{
    status_t status = dss_check_parameter(vg_name, volume_name, inst_cfg);
    DSS_RETURN_IFERR2(status, LOG_DEBUG_ERR("parameter is invalid."));

    dss_static_assert_info();

    LOG_RUN_INF("Begin to create vg %s.", vg_name);
    LOG_DEBUG_INF("Begin to create vg %s.", vg_name);
    status = dss_load_vg_conf_info(&g_vgs_info, inst_cfg);
    if (status != CM_SUCCESS) {
        LOG_DEBUG_ERR("Failed to load vg info from config, vg name is %s, volume name is %s, errcode is %d.\n", vg_name,
            volume_name, status);
        return status;
    }

    dss_vg_info_item_t *vg_item = dss_find_vg_item(vg_name);
    if (vg_item == NULL) {
        dss_free_vg_info(g_vgs_info);
        LOG_DEBUG_ERR("Failed to find vg info from config, vg name is %s, volume name is %s, errcode is %d.\n", vg_name,
            volume_name, status);
        DSS_THROW_ERROR(ERR_DSS_VG_CREATE, vg_name, "Failed to find vg info from config");
        return CM_ERROR;
    }

    if (vg_item->entry_path[0] == '\0' || cm_strcmpi(vg_item->entry_path, volume_name) != 0) {
        dss_free_vg_info(g_vgs_info);
        DSS_THROW_ERROR(
            ERR_DSS_VG_CREATE, vg_name, "Failed to cmp super-block name with entry_path config in dss_vg_conf.\n");
        return CM_ERROR;
    }

    status = dss_set_vg_ctrl(vg_name, volume_name, vg_item, inst_cfg, size);
    DSS_RETURN_IFERR2(status, LOG_DEBUG_ERR("dss set vg ctrl failed."));
    LOG_RUN_INF("End to create vg %s.", vg_name);
    LOG_DEBUG_INF("End to create vg %s.", vg_name);

    return CM_SUCCESS;
}
