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
 * dsscmd_volume.c
 *
 *
 * IDENTIFICATION
 *    src/cmd/dsscmd_volume.c
 *
 * -------------------------------------------------------------------------
 */

#include "dsscmd_volume.h"
#include "dss_file.h"
#include "dss_redo_recovery.h"
#include "dss_malloc.h"
#include "dsscmd_inq.h"
#include "dsscmd_encrypt.h"

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
    status_t status = 
        dss_alloc_ft_node_when_create_vg(vg_item, parent_node, DSS_RECYLE_DIR_NAME, GFT_PATH, DSS_FT_NODE_FLAG_SYSTEM);
    if (status != CM_SUCCESS) {
        LOG_RUN_ERR("Failed to allocate .recycle file when create vg %s.", vg_item->vg_name);
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
    if (strlen(volume_name) >= DSS_MAX_VOLUME_PATH_LEN) {
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
            DSS_THROW_ERROR(
                ERR_DSS_VOLUME_ADD, volume_name, "please check volume is used in cluster, if not need to dd manually");
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
    dss_set_software_version(&vg_ctrl->vg_info, (uint32)DSS_SOFTWARE_VERSION);
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
    vg_ctrl->core.volume_attrs[0].id = 0;

    vg_ctrl->core.volume_attrs[0].hwm = CM_CALC_ALIGN(DSS_VOLUME_HEAD_SIZE, au_size);
    vg_ctrl->core.volume_attrs[0].size = dss_get_volume_size(volume);
    if (vg_ctrl->core.volume_attrs[0].size == DSS_INVALID_64) {
        DSS_THROW_ERROR(ERR_DSS_VG_CREATE, vg_name, "failed to get volume size");
        return CM_ERROR;
    }
    if (vg_ctrl->core.volume_attrs[0].size <= vg_ctrl->core.volume_attrs[0].hwm) {
        DSS_THROW_ERROR(ERR_DSS_VG_CREATE, vg_name, "volume size is too small.");
        return CM_ERROR;
    }
    vg_ctrl->core.volume_attrs[0].free = vg_ctrl->core.volume_attrs[0].size - vg_ctrl->core.volume_attrs[0].hwm;
    LOG_RUN_INF("After initial vg ctrl, au_size is %u, hwm is %llu, free is %llu, size is %llu", au_size,
        vg_ctrl->core.volume_attrs[0].hwm, vg_ctrl->core.volume_attrs[0].free, vg_ctrl->core.volume_attrs[0].size);
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
    DSS_RETURN_IFERR2(status, LOG_DEBUG_ERR("[VOL][CV] Failed write volume,errcode:%d.", status));

    status = vg_initialize_resource(vg_item, node);
    DSS_RETURN_IFERR2(status, LOG_DEBUG_ERR("[VOL][CV] Failed to initialize resource,errcode:%d.", status));

    // set the vg valid flag. avoid that write disk array failed.
    vg_ctrl->vg_info.valid_flag = DSS_CTRL_VALID_FLAG;
    dss_set_ctrl_checksum(vg_ctrl);
    status = dss_write_volume(volume, (int64)DSS_CTRL_VG_DATA_OFFSET, vg_ctrl, DSS_VG_DATA_SIZE);
    if (status == CM_SUCCESS) {
        // write to backup area
        status = dss_write_volume(volume, (int64)DSS_CTRL_BAK_VG_DATA_OFFSET, vg_ctrl, DSS_VG_DATA_SIZE);
    }
    DSS_RETURN_IFERR2(status, LOG_DEBUG_ERR("[VOL][CV] write volume %s failed.", volume_name));
    return CM_SUCCESS;
}

static status_t dss_set_vg_ctrl(
    const char *vg_name, const char *volume_name, dss_vg_info_item_t *vg_item, dss_config_t *inst_cfg, uint32 size)
{
    status_t status;
    dss_ctrl_t *vg_ctrl = (dss_ctrl_t *)cm_malloc_align(DSS_ALIGN_SIZE, sizeof(dss_ctrl_t));
    if (vg_ctrl == NULL) {
        dss_free_vg_info();
        LOG_DEBUG_ERR("[VOL][CV] Failed to alloc memory, vg name is %s, volume name is %s.\n", vg_name, volume_name);
        DSS_THROW_ERROR(ERR_ALLOC_MEMORY, sizeof(dss_ctrl_t), "vg_ctrl");
        return CM_ERROR;
    }
    (void)memset_s(vg_ctrl, sizeof(dss_ctrl_t), 0 , sizeof(dss_ctrl_t));
    vg_item->dss_ctrl = vg_ctrl;
    do {
        dss_volume_t volume;
        status = dss_open_volume(volume_name, NULL, DSS_INSTANCE_OPEN_FLAG, &volume);
        DSS_BREAK_IFERR2(status, LOG_DEBUG_ERR("[VOL][CV] Open volume %s failed.", volume_name));

        status = dss_initial_vg_ctrl(vg_name, volume_name, &volume, vg_ctrl, size);
        if (status != CM_SUCCESS) {
            dss_close_volume(&volume);
            LOG_DEBUG_ERR("[VOL][CV] initial_vg_ctrl failed.vg %s,vm %s.", vg_name, volume_name);
            break;
        }
        status = dss_set_log_buf(vg_name, vg_item);
        if (status != CM_SUCCESS) {
            dss_close_volume(&volume);
            LOG_DEBUG_ERR("[VOL][CV] initial global log buffer failed.vg %s,vm %s.", vg_name, volume_name);
            break;
        }
        status = dss_write_volume_ctrl_info(volume_name, &volume, vg_ctrl, vg_item);
        if (status != CM_SUCCESS) {
            dss_close_volume(&volume);
            LOG_DEBUG_ERR("[VOL][CV] dss write volume ctrl info failed.vm %s.", volume_name);
            break;
        }
        dss_close_volume(&volume);
    } while (0);
    DSS_FREE_POINT(vg_ctrl);
    dss_free_vg_info();
    return status;
}

status_t dss_create_vg(const char *vg_name, const char *volume_name, dss_config_t *inst_cfg, uint32 size)
{
    status_t status = dss_check_parameter(vg_name, volume_name, inst_cfg);
    DSS_RETURN_IFERR2(status, LOG_DEBUG_ERR("[VOL][CV] parameter is invalid."));

    dss_static_assert_info();

    LOG_RUN_INF("[VOL][CV] Begin to create vg %s.", vg_name);
    status = dss_load_vg_conf_info(&g_vgs_info, inst_cfg);
    if (status != CM_SUCCESS) {
        LOG_DEBUG_ERR(
            "[VOL][CV] Failed to load vg info from config, vg name is %s, volume name is %s, errcode is %d.\n",
            vg_name, volume_name, status);
        return status;
    }

    dss_vg_info_item_t *vg_item = dss_find_vg_item(vg_name);
    if (vg_item == NULL) {
        dss_free_vg_info();
        LOG_DEBUG_ERR(
            "[VOL][CV] Failed to find vg info from config, vg name is %s, volume name is %s, errcode is %d.\n",
            vg_name, volume_name, status);
        DSS_THROW_ERROR(ERR_DSS_VG_CREATE, vg_name, "Failed to find vg info from config");
        return CM_ERROR;
    }

    if (vg_item->entry_path[0] == '\0' || cm_strcmpi(vg_item->entry_path, volume_name) != 0) {
        dss_free_vg_info();
        DSS_THROW_ERROR(
            ERR_DSS_VG_CREATE, vg_name, "Failed to cmp super-block name with entry_path config in dss_vg_conf.\n");
        return CM_ERROR;
    }

    status = dss_set_vg_ctrl(vg_name, volume_name, vg_item, inst_cfg, size);
    DSS_RETURN_IFERR2(status, LOG_DEBUG_ERR("[VOL][CV] dss set vg ctrl failed."));
    LOG_RUN_INF("End to create vg %s.", vg_name);

    return CM_SUCCESS;
}

static dss_vg_info_item_t* dss_find_vg_item_inner(dss_vg_info_t *vg_info, const char *vg_name, bool32 *is_first_vg)
{
    *is_first_vg = CM_FALSE;
    for (uint32_t i = 0; i < vg_info->group_num; i++) {
        if (strcmp(vg_info->volume_group[i].vg_name, vg_name) == 0) {
            if (i == 0) {
                *is_first_vg = CM_TRUE;
            }
            return &vg_info->volume_group[i];
        }
    }
    return NULL;
}

static status_t dss_modify_volume_head(
    dss_vg_info_item_t* vg_item, const char *vol_path, uint32 id, volume_modify_type_e type)
{
#ifndef WIN32
    char buf[DSS_DISK_UNIT_SIZE] __attribute__((__aligned__(DSS_ALIGN_SIZE)));
#else
    char buf[DSS_DISK_UNIT_SIZE];
#endif
    dss_volume_header_t *vol_head = (dss_volume_header_t *)buf;
    CM_RETURN_IFERR(dss_open_volume(vol_path, NULL, DSS_CLI_OPEN_FLAG, &vg_item->volume_handle[id]));
    status_t ret = dss_read_volume(&vg_item->volume_handle[id], 0, vol_head, DSS_DISK_UNIT_SIZE);
    if (ret != CM_SUCCESS) {
        dss_close_volume(&vg_item->volume_handle[id]);
        return ret;
    }

    switch (type) {
        case VOLUME_MODIFY_ADD:
            ret = dss_gen_volume_head(vol_head, vg_item, vol_path, id);
            break;
        case VOLUME_MODIFY_REMOVE:
            vol_head->valid_flag = 0;
            vol_head->software_version = 0;
            break;
        case VOLUME_MODIFY_REPLACE:
        case VOLUME_MODIFY_ROLLBACK:         
            break;
        default:
            LOG_DEBUG_ERR("Invalid volume modify type: %u.", type);
            ret = CM_ERROR;
            break;
    }

    if (ret != CM_SUCCESS) {
        dss_close_volume(&vg_item->volume_handle[id]);
        return ret;
    }
    ret = dss_write_volume(&vg_item->volume_handle[id], 0, vol_head, DSS_DISK_UNIT_SIZE);
    dss_close_volume(&vg_item->volume_handle[id]);
    return ret;
}

static status_t dss_check_volume_flag(dss_vg_info_item_t *vg_item)
{
    for (uint32_t i = 0; i < DSS_MAX_VOLUMES; i++) {
        if (vg_item->dss_ctrl->volume.defs[i].flag == VOLUME_ADD ||
            vg_item->dss_ctrl->volume.defs[i].flag == VOLUME_REMOVE ||
            vg_item->dss_ctrl->volume.defs[i].flag == VOLUME_REPLACE) {
            DSS_THROW_ERROR(ERR_DSS_VG_CHECK, vg_item->vg_name, "invalid volume flag, please execute dsscmd rollback.");
            return CM_ERROR;
        }
    }
    return CM_SUCCESS;
}

static status_t dss_add_volume_inner(dss_vg_info_item_t *vg_item, const char *vol_path)
{
    LOG_RUN_INF("Begin to add volume, vg_name is %s, vol_path is %s.", vg_item->vg_name, vol_path);
    CM_RETURN_IFERR(dss_check_volume_flag(vg_item));
    if (dss_find_volume(vg_item, vol_path) != CM_INVALID_ID32) {
        DSS_THROW_ERROR(ERR_DSS_VOLUME_EXISTED, vol_path, vg_item->vg_name);
        return CM_ERROR;
    }

    uint32 id = dss_find_free_volume_id(vg_item);
    if (id >= DSS_MAX_VOLUMES) {
        LOG_DEBUG_ERR("Failed to add volume, exceed max volumes %d.", DSS_MAX_VOLUMES);
        return CM_ERROR;
    }

    CM_RETURN_IFERR(dss_open_volume(vol_path, NULL, DSS_CLI_OPEN_FLAG, &vg_item->volume_handle[id]));
    CM_RETURN_IFERR_EX(dss_cmp_volume_head(vg_item, vol_path, id), dss_close_volume(&vg_item->volume_handle[id]));
    uint64 vol_size = dss_get_volume_size(&vg_item->volume_handle[id]);
    dss_close_volume(&vg_item->volume_handle[id]);
    if (vol_size  == DSS_INVALID_64) {
        LOG_DEBUG_ERR("Failed to get volume size when add volume:%s.", vol_path);
        return CM_ERROR;
    }
    CM_RETURN_IFERR(dss_add_volume_vg_ctrl(vg_item->dss_ctrl, id, vol_size, vol_path, VOLUME_ADD));

    /*
     * The client does not record redo log. Therefore, the two-phase method is used.
     * Firstly, write the volume_ctrl to disk, where the status is free.
     * Secondly, write the core_ctrl and volume_head to disk.
     * Finally, update the status of volume_ctrl to disk, where the status is occupy.
     */
    LOG_RUN_INF(
        "Update volume_ctrl, core_ctrl and volume_head, vg_name is %s, vol_path is %s.", vg_item->vg_name, vol_path);
    if (dss_update_volume_ctrl(vg_item) != CM_SUCCESS) {
        LOG_RUN_ERR("Failed to update volume_ctrl, vg_name is %s, vol_path is %s.", vg_item->vg_name, vol_path);
        return CM_ERROR;
    }
    if (dss_update_core_ctrl_disk(vg_item) != CM_SUCCESS) {
        LOG_RUN_ERR("Failed to update core_ctrl, vg_name is %s, vol_path is %s.", vg_item->vg_name, vol_path);
        return CM_ERROR;
    }
    if (dss_modify_volume_head(vg_item, vol_path, id, VOLUME_MODIFY_ADD) != CM_SUCCESS) {
        LOG_RUN_ERR("Failed to update volume_head, vg_name is %s, vol_path is %s.", vg_item->vg_name, vol_path);
        return CM_ERROR;
    }
    vg_item->dss_ctrl->volume.defs[id].flag = VOLUME_OCCUPY;
    if (dss_update_volume_ctrl(vg_item) != CM_SUCCESS) {
        LOG_RUN_ERR("Failed to update volume_ctrl flag, vg_name is %s, vol_path is %s.", vg_item->vg_name, vol_path);
        return CM_ERROR;
    }
    LOG_RUN_INF("End to add volume, vg_name is %s, vol_path is %s.", vg_item->vg_name, vol_path);
    return CM_SUCCESS;
}

static status_t dss_remove_volume_inner(dss_vg_info_item_t* vg_item, const char *vol_path)
{
    LOG_RUN_INF("Begin to remove volume, vg_name is %s, vol_path is %s.", vg_item->vg_name, vol_path);
    uint32 id;
    CM_RETURN_IFERR(dss_check_volume_flag(vg_item));
    CM_RETURN_IFERR(dss_check_remove_volume(vg_item, vol_path, &id));

    if (vg_item->volume_handle[id].handle != DSS_INVALID_HANDLE) {
        dss_close_volume(&vg_item->volume_handle[id]);
    }

    vg_item->dss_ctrl->volume.defs[id].flag = VOLUME_REMOVE;
    if (dss_update_volume_ctrl(vg_item) != CM_SUCCESS) {
        LOG_RUN_ERR("Failed to update volume_ctrl flag, vg_name is %s, vol_path is %s.", vg_item->vg_name, vol_path);
        return CM_ERROR;
    }
    dss_remove_volume_vg_ctrl(vg_item->dss_ctrl, id);
    if (dss_update_core_ctrl_disk(vg_item) != CM_SUCCESS) {
        LOG_RUN_ERR("Failed to update core_ctrl, vg_name is %s, vol_path is %s.", vg_item->vg_name, vol_path);
        return CM_ERROR;
    }
    if (dss_update_volume_ctrl(vg_item) != CM_SUCCESS) {
        LOG_RUN_ERR("Failed to update volume_ctrl, vg_name is %s, vol_path is %s.", vg_item->vg_name, vol_path);
        return CM_ERROR;
    }
    if (dss_modify_volume_head(vg_item, vol_path, id, VOLUME_MODIFY_REMOVE) != CM_SUCCESS) {
        LOG_RUN_ERR("Failed to update volume_head, vg_name is %s, vol_path is %s.", vg_item->vg_name, vol_path);
        return CM_ERROR;
    }
    LOG_RUN_INF("End to remove volume, vg_name is %s, vol_path is %s.", vg_item->vg_name, vol_path);
    return CM_SUCCESS;
}

static status_t dss_replace_prepare_new_volume(
    dss_vg_info_item_t *vg_item, dss_volume_t *new_volume, uint32 id, uint64 *new_size)
{
#ifndef WIN32
    char buf[DSS_DISK_UNIT_SIZE] __attribute__((__aligned__(DSS_ALIGN_SIZE)));
#else
    char buf[DSS_DISK_UNIT_SIZE];
#endif
    dss_volume_header_t *vol_head = (dss_volume_header_t *)buf;

    CM_RETURN_IFERR(dss_read_volume(new_volume, 0, vol_head, DSS_DISK_UNIT_SIZE));
    if (vol_head->vol_type.id != id || strcmp(vol_head->vg_name, vg_item->dss_ctrl->vg_info.vg_name) != 0) {
        DSS_THROW_ERROR(ERR_DSS_VOLUME_REPLACE, new_volume->name, "new volume copy wrong");
        return CM_ERROR;
    }

    *new_size = dss_get_volume_size(new_volume);
    if (*new_size == DSS_INVALID_64) {
        LOG_DEBUG_ERR("Failed to get new volume size when check volume:%s.", new_volume->name);
        return CM_ERROR;
    }
    if (*new_size < vg_item->dss_ctrl->core.volume_attrs[id].hwm) {
        DSS_THROW_ERROR(ERR_DSS_VOLUME_REPLACE, new_volume->name, "new volume size is too small");
        return CM_ERROR;
    }

    MEMS_RETURN_IFERR(strcpy_s(vol_head->vol_type.entry_volume_name, DSS_MAX_VOLUME_PATH_LEN, new_volume->name));
    vol_head->checksum = dss_get_checksum((char *)vol_head, DSS_DISK_UNIT_SIZE);
    CM_RETURN_IFERR(dss_write_volume(new_volume, 0, vol_head, DSS_DISK_UNIT_SIZE));

    CM_RETURN_IFERR(
        dss_open_volume(vg_item->dss_ctrl->volume.defs[id].name, NULL, DSS_CLI_OPEN_FLAG, &vg_item->volume_handle[id]));
    status_t ret = dss_read_volume(&vg_item->volume_handle[id], 0, vol_head, DSS_DISK_UNIT_SIZE);
    if (ret != CM_SUCCESS) {
        dss_close_volume(&vg_item->volume_handle[id]);
        return ret;
    }
    if (strcmp(vg_item->dss_ctrl->volume.defs[id].name, vol_head->vol_type.entry_volume_name) != 0) {
        dss_close_volume(&vg_item->volume_handle[id]);
        DSS_THROW_ERROR(ERR_DSS_VOLUME_EXISTED, vol_head->vol_type.entry_volume_name, vol_head->vg_name);
        return CM_ERROR;
    }
    dss_close_volume(&vg_item->volume_handle[id]);
    return CM_SUCCESS;
}

static status_t dss_replace_volume_to_disk(dss_vg_info_item_t* vg_item, const char *old_vol, const char *new_vol,
    uint32 id, uint64 new_size, dss_config_t *inst_cfg)
{
    /*
     * The client does not record redo log. Therefore, the two-phase method is used.
     * Firstly, write the volume_ctrl to disk, where the status is replace.
     * Secondly, modify the vol_header of old_vol and new_vol.
     * Thirdly, write the core_ctrl to disk, modify volume size.
     * Finally, update the flag and new name of volume_ctrl to disk, where the flag is occupy.
     */
    dss_ctrl_t *vg_ctrl = vg_item->dss_ctrl;
    vg_ctrl->volume.defs[id].flag = VOLUME_REPLACE;
    vg_ctrl->volume.defs[id].version++;
    if (dss_update_volume_ctrl(vg_item) != CM_SUCCESS) {
        LOG_RUN_ERR("Failed to update volume_ctrl flag, vg_name is %s, vol_path is %s.", vg_item->vg_name, old_vol);
        return CM_ERROR;
    }

    status_t ret;
    vg_ctrl->core.volume_attrs[id].size = new_size;
    vg_ctrl->core.volume_attrs[id].free = new_size - vg_ctrl->core.volume_attrs[id].hwm;
    vg_ctrl->volume.defs[id].flag = VOLUME_OCCUPY;
    MEMS_RETURN_IFERR(strcpy_s(vg_ctrl->volume.defs[id].name, DSS_MAX_VOLUME_PATH_LEN, new_vol));

    if (id == 0) {
        LOG_RUN_INF("Replace entry volume, close old volume %s, open new volume %s.", old_vol, new_vol);
        dss_close_volume(&vg_item->volume_handle[0]);
        CM_RETURN_IFERR(dss_open_volume(new_vol, NULL, DSS_CLI_OPEN_FLAG, &vg_item->volume_handle[0]));
        CM_RETURN_IFERR_EX(
            dss_lock_vg_storage_core(vg_item, new_vol, inst_cfg), dss_close_volume(&vg_item->volume_handle[0]));
    }

    do {
        ret = dss_update_core_ctrl_disk(vg_item);
        if (ret != CM_SUCCESS) {
            LOG_RUN_ERR("Failed to update core_ctrl, vg_name is %s, vol_path is %s.", vg_item->vg_name, new_vol);
            break;
        }
        ret = dss_update_volume_ctrl(vg_item);
        if (ret != CM_SUCCESS) {
            LOG_RUN_ERR("Failed to update volume_ctrl, vg_name is %s, vol_path is %s.", vg_item->vg_name, new_vol);
        }
    } while (0);

    if (ret != CM_SUCCESS) {
        if (id == 0) {
            (void)dss_unlock_vg_storage_core(vg_item, new_vol, inst_cfg);
            dss_close_volume(&vg_item->volume_handle[0]);
        }
        return ret;
    } else {
        if (id == 0) {
            if (dss_unlock_vg_storage_core(vg_item, new_vol, inst_cfg) != CM_SUCCESS) {
                dss_close_volume(&vg_item->volume_handle[0]);
                return CM_ERROR;
            }
            dss_close_volume(&vg_item->volume_handle[0]);
        }
    }
    ret = dss_modify_volume_head(vg_item, old_vol, id, VOLUME_MODIFY_REMOVE);
    if (ret != CM_SUCCESS) {
        LOG_RUN_ERR("Failed to update volume_head, vg_name is %s, vol_path is %s.", vg_item->vg_name, old_vol);
    }
    return ret;
}

static status_t dss_replace_volume_inner(
    dss_vg_info_item_t *vg_item, const char *old_vol, const char *new_vol, dss_config_t *inst_cfg)
{
    LOG_RUN_INF(
        "Begin to replace volume, vg_name is %s, old_vol is %s, new_vol is %s.", vg_item->vg_name, old_vol, new_vol);
    CM_RETURN_IFERR(dss_check_volume_flag(vg_item));
    uint32 id = dss_find_volume(vg_item, old_vol);
    if (id == CM_INVALID_ID32) {
        DSS_THROW_ERROR(ERR_DSS_VOLUME_NOEXIST, old_vol, vg_item->vg_name);
        return CM_ERROR;
    }

    if (vg_item->volume_handle[id].handle != DSS_INVALID_HANDLE) {
        dss_close_volume(&vg_item->volume_handle[id]);
    }

    uint64 new_size;
    dss_volume_t new_volume;
    status_t ret = dss_open_volume(new_vol, NULL, DSS_CLI_OPEN_FLAG, &new_volume);
    DSS_RETURN_IFERR2(ret, LOG_DEBUG_ERR("Open volume %s failed.", new_vol));
    ret =  dss_replace_prepare_new_volume(vg_item, &new_volume, id, &new_size);
    dss_close_volume(&new_volume);
    if (ret != CM_SUCCESS) {
        LOG_RUN_ERR("Failed to prepare new volume, vg_name is %s, new_vol is %s.", vg_item->vg_name, new_vol);
        return ret;
    }

    ret = dss_replace_volume_to_disk(vg_item, old_vol, new_vol, id, new_size, inst_cfg);
    if (ret != CM_SUCCESS) {
        LOG_RUN_ERR("Failed to replace volume to disk, vg_name is %s, old_vol is %s, new_vol is %s.", vg_item->vg_name,
            old_vol, new_vol);
        return ret;
    }
    LOG_RUN_INF(
        "End to replace volume, vg_name is %s, old_vol is %s, new_vol is %s.", vg_item->vg_name, old_vol, new_vol);
    return CM_SUCCESS;
}

static status_t dss_modify_volume_offline_inner(dss_vg_info_item_t *vg_item, const char *old_vol, const char *new_vol,
    volume_modify_type_e type, dss_config_t *inst_cfg)
{
    status_t ret;

    switch (type) {
        case VOLUME_MODIFY_ADD:
            ret = dss_add_volume_inner(vg_item, old_vol);
            break;
        case VOLUME_MODIFY_REMOVE:
            ret = dss_remove_volume_inner(vg_item, old_vol);
            break;
        case VOLUME_MODIFY_REPLACE:
            ret = dss_replace_volume_inner(vg_item, old_vol, new_vol, inst_cfg);
            break;
        case VOLUME_MODIFY_ROLLBACK:
            ret = dss_recover_ctrlinfo(vg_item);
            if (ret != CM_SUCCESS) {
                LOG_DEBUG_ERR("The dss ctrl of %s is invalid when rollback.", vg_item->vg_name);
            }
            break;
        default:
            DSS_PRINT_ERROR("Invalid volume modify type: %u.\n", type);
            ret = CM_ERROR;
            break;
    }

    return ret;
}

status_t dss_modify_volume_offline(
    const char *home, const char *vg_name, const char *old_vol, const char *new_vol, volume_modify_type_e type)
{
    char buff[LENGTH_EIGHT_BYTE];
    (void)printf("Please ensure that the cluster is stopped, enter yes!\n");
    CM_RETURN_IFERR(dss_receive_info_from_terminal(buff, LENGTH_EIGHT_BYTE, CM_TRUE));

    if (cm_strcmpi(buff, "yes") != 0) {
        (void)printf("Please ensure that the cluster is stopped, enter yes!\n");
        CM_RETURN_IFERR(dss_receive_info_from_terminal(buff, LENGTH_EIGHT_BYTE, CM_TRUE));
    }

    if (cm_strcmpi(buff, "yes") != 0) {
        DSS_PRINT_ERROR("Failed to modify volume offline, the cluster must be stopped.\n");
        return CM_ERROR;
    }

    dss_config_t *inst_cfg = dss_get_g_inst_cfg();
    dss_vg_info_t *vg_info = NULL;
    bool32 is_first_vg = CM_FALSE;
    CM_RETURN_IFERR(dss_inq_alloc_vg_info(home, inst_cfg, &vg_info));
    dss_vg_info_item_t *vg_item = dss_find_vg_item_inner(vg_info, vg_name, &is_first_vg);
    if (vg_item == NULL) {
        dss_inq_free_vg_info(vg_info);
        DSS_THROW_ERROR(ERR_DSS_VG_NOT_EXIST, vg_name);
        return CM_ERROR;
    }
    status_t ret;
    if (!is_first_vg) {
        ret = dss_get_vg_non_entry_info(inst_cfg, &vg_info->volume_group[0], CM_TRUE, CM_TRUE);
        if (ret != CM_SUCCESS) {
            dss_inq_free_vg_info(vg_info);
            DSS_PRINT_ERROR("Failed to get first vg non entry info when modify volume offline.\n");
            return ret;
        }
    }
    ret = dss_get_vg_non_entry_info(inst_cfg, vg_item, CM_TRUE, CM_TRUE);
    if (ret != CM_SUCCESS) {
        dss_inq_free_vg_info(vg_info);
        DSS_PRINT_ERROR("Failed to get vg non entry info when modify volume offline.\n");
        return ret;
    }
    if (dss_lock_vg_storage_w(vg_item, vg_item->entry_path, inst_cfg) != CM_SUCCESS) {
        dss_inq_free_vg_info(vg_info);
        DSS_PRINT_ERROR("Failed to lock vg:%s.\n", vg_name);
        return CM_ERROR;
    }
    ret = dss_modify_volume_offline_inner(vg_item, old_vol, new_vol, type, inst_cfg);
    if (ret != CM_SUCCESS) {
        DSS_PRINT_ERROR("Failed to execute modify volume inner.\n");
        (void)dss_unlock_vg_storage(vg_item, vg_item->entry_path, inst_cfg);
        dss_inq_free_vg_info(vg_info);
        return ret;
    }
    ret = dss_unlock_vg_storage(vg_item, vg_item->entry_path, inst_cfg);
    dss_inq_free_vg_info(vg_info);
    return ret;
}
