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
 * dss_io_fence.c
 *
 *
 * IDENTIFICATION
 *    src/common/dss_io_fence.c
 *
 * -------------------------------------------------------------------------
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "dss_log.h"
#include "dss_io_fence.h"

void dss_destroy_ptlist(ptlist_t *ptlist)
{
    if (ptlist == NULL) {
        return;
    }
    for (uint32 i = 0; i < ptlist->count; i++) {
        DSS_FREE_POINT(ptlist->items[i]);
    }
    cm_destroy_ptlist(ptlist);
}

bool32 dss_iof_is_register(char *dev, int64 rk, ptlist_t *regs)
{
#ifdef WIN32
#else
    uint32 i;
    int32 j;
    iof_reg_in_t *reg_info = NULL;
    int64 out_rk = rk + 1;

    for (i = 0; i < regs->count; i++) {
        reg_info = (iof_reg_in_t *)cm_ptlist_get(regs, i);
        if (reg_info == NULL) {
            continue;
        }
        if (strcmp(dev, reg_info->dev) != 0) {
            continue;
        }

        for (j = 0; j < reg_info->key_count; j++) {
            if (reg_info->reg_keys[j] == out_rk) {
                return CM_TRUE;
            }
        }
    }
#endif
    return CM_FALSE;
}

status_t dss_iof_kick_one_volume(char *dev, int64 rk, int64 rk_kick, ptlist_t *regs)
{
#ifdef WIN32
#else
    status_t status = CM_SUCCESS;
    iof_reg_out_t reg_info;
    bool32 is_reg = CM_FALSE;
    int32 ret = 0;

    reg_info.rk = rk;
    reg_info.rk_kick = rk_kick;
    reg_info.dev = dev;

    is_reg = dss_iof_is_register(dev, rk, regs);
    if (!is_reg) {
        LOG_DEBUG_INF(
            "Need to register node to dev before kick other nodes, dev %s, org rk %lld.", reg_info.dev, reg_info.rk);
        ret = cm_iof_register(&reg_info);
        if (ret != CM_SUCCESS) {
            if (ret == CM_IOF_ERR_DUP_OP) {
                LOG_DEBUG_INF("The current host has been registered for dev %s.", reg_info.dev);
            } else {
                LOG_DEBUG_ERR("Register dev failed, org rk %lld, dev %s.", reg_info.rk, reg_info.dev);
                return CM_ERROR;
            }
        }
    }

    is_reg = dss_iof_is_register(dev, rk_kick, regs);
    if (!is_reg) {
        LOG_DEBUG_INF(
            "The node to be kicked is not registered on the target volume, dev %s, rk_kick %lld.", dev, rk_kick);
        return CM_SUCCESS;
    }

    status = cm_iof_kick(&reg_info);
    if (status != CM_SUCCESS) {
        LOG_DEBUG_ERR(
            "kick dev failed, org rk %lld, org sark %lld, dev %s.", reg_info.rk, reg_info.rk_kick, reg_info.dev);
        return status;
    }
#endif
    return CM_SUCCESS;
}

status_t dss_iof_kick_all_volumes(dss_vg_info_t *dss_vg_info, int64 rk, int64 rk_kick, ptlist_t *reg_list)
{
#ifdef WIN32
#else
    int32 j = 0;
    status_t status = CM_SUCCESS;

    for (uint32 i = 0; i < dss_vg_info->group_num; i++) {
        dss_vg_info_item_t *item = &dss_vg_info->volume_group[i];
        status = dss_iof_kick_one_volume(item->entry_path, rk, rk_kick, reg_list);
        if (status != CM_SUCCESS) {
            // continue to kick next volume
            LOG_DEBUG_ERR("kick entry dev failed, dev %s.", item->entry_path);
        }

        // volume_attrs[0] is the sys dev
        for (j = 1; j < DSS_MAX_VOLUMES; j++) {
            if (item->dss_ctrl->core.volume_attrs[j].flag == VOLUME_FREE) {
                continue;
            }

            status = dss_iof_kick_one_volume(item->dss_ctrl->volume.defs[j].name, rk, rk_kick, reg_list);
            if (status != CM_SUCCESS) {
                // continue to kick next volume
                LOG_DEBUG_ERR("kick data dev failed, dev %s.", item->entry_path);
            }
        }
    }
#endif
    return CM_SUCCESS;
}

status_t dss_iof_sync_vginfo(dss_session_t *session, dss_vg_info_item_t *vg_item)
{
#ifdef WIN32
#else
    uint64 version;

    dss_config_t *inst_cfg = dss_get_inst_cfg();

    if (dss_lock_vg_storage(vg_item, vg_item->entry_path, inst_cfg) != CM_SUCCESS) {
        LOG_DEBUG_ERR("Failed to lock vg entry %s.", vg_item->entry_path);
        return CM_ERROR;
    }

    dss_lock_shm_meta_x(session, vg_item->vg_latch);

    if (dss_get_core_version(vg_item, &version) != CM_SUCCESS) {
        dss_unlock_shm_meta(session, vg_item->vg_latch);
        dss_unlock_vg_storage(vg_item, vg_item->entry_path, inst_cfg);
        LOG_DEBUG_ERR("Failed to get core version, vg %s.", vg_item->entry_path);
        return CM_ERROR;
    }

    if (dss_compare_version(version, vg_item->dss_ctrl->core.version)) {
        if (dss_check_volume(vg_item, CM_INVALID_ID32) != CM_SUCCESS) {
            dss_unlock_shm_meta(session, vg_item->vg_latch);
            dss_unlock_vg_storage(vg_item, vg_item->entry_path, inst_cfg);
            LOG_DEBUG_ERR("Failed to check volume, vg %s.", vg_item->entry_path);
            return CM_ERROR;
        }

        if (dss_load_core_ctrl(vg_item, &vg_item->dss_ctrl->core) != CM_SUCCESS) {
            dss_unlock_shm_meta(session, vg_item->vg_latch);
            dss_unlock_vg_storage(vg_item, vg_item->entry_path, inst_cfg);
            LOG_DEBUG_ERR("Failed to get core ctrl, vg %s.", vg_item->entry_path);
            return CM_ERROR;
        }
    }
    dss_unlock_shm_meta(session, vg_item->vg_latch);
    dss_unlock_vg_storage(vg_item, vg_item->entry_path, inst_cfg);
#endif
    return CM_SUCCESS;
}

status_t dss_iof_sync_all_vginfo(dss_session_t *session, dss_vg_info_t *dss_vg_info)
{
#ifdef WIN32
#else
    status_t status = CM_SUCCESS;

    for (uint32 i = 0; i < dss_vg_info->group_num; i++) {
        dss_vg_info_item_t *item = &dss_vg_info->volume_group[i];
        status = dss_iof_sync_vginfo(session, item);
        if (status != CM_SUCCESS) {
            LOG_DEBUG_ERR("sync vginfo failed, vg name %s.", item->vg_name);
            return CM_ERROR;
        }
    }
#endif
    return CM_SUCCESS;
}

status_t dss_iof_kick_all(dss_vg_info_t *vg_info, dss_config_t *inst_cfg, int64 rk, int64 rk_kick)
{
#ifdef WIN32
#else
    status_t status;
    ptlist_t reg_list;

    if (rk_kick == inst_cfg->params.inst_id) {
        LOG_DEBUG_ERR("Can't kick current node, rk_kick %lld, inst id %lld.", rk_kick, inst_cfg->params.inst_id);
        return CM_ERROR;
    }

    bool32 result = (bool32)(rk == inst_cfg->params.inst_id);
    DSS_RETURN_IF_FALSE2(result,
        LOG_DEBUG_ERR("Must use inst id of current node as rk, rk %lld, inst id %lld.", rk, inst_cfg->params.inst_id));

    cm_ptlist_init(&reg_list);
    status = dss_iof_inql_regs(vg_info, &reg_list);
    DSS_RETURN_IFERR3(status, dss_destroy_ptlist(&reg_list), LOG_DEBUG_ERR("Inquiry regs info failed."));

    status = dss_iof_kick_all_volumes(vg_info, rk, rk_kick, &reg_list);
    DSS_RETURN_IFERR2(status, dss_destroy_ptlist(&reg_list));

    dss_destroy_ptlist(&reg_list);
#endif
    LOG_RUN_INF("IOfence kick all succ.");

    return CM_SUCCESS;
}

status_t dss_iof_register_single(int64 rk, char *dev)
{
    iof_reg_out_t reg_info;
    reg_info.rk = rk;
    reg_info.dev = dev;
    status_t ret = cm_iof_register(&reg_info);
    if (ret != CM_SUCCESS) {
        if (ret != CM_IOF_ERR_DUP_OP) {
            LOG_RUN_ERR("Failed to register, rk: %lld, dev: %s, ret: %d.", rk, dev, ret);
            return CM_ERROR;
        }
        LOG_RUN_INF("Register conflict, rk: %lld, dev: %s", rk, dev);
    }
    LOG_RUN_INF("Register success, rk: %lld, dev: %s.", rk, dev);
    return CM_SUCCESS;
}

status_t dss_iof_unregister_single(int64 rk, char *dev)
{
    iof_reg_out_t reg_info;
    reg_info.rk = rk;
    reg_info.dev = dev;
    status_t ret = cm_iof_unregister(&reg_info);
    if (ret != CM_SUCCESS) {
        if (ret != CM_IOF_ERR_DUP_OP) {
            LOG_RUN_ERR("Failed to unregister, rk: %lld, dev: %s, ret: %d.", rk, dev, ret);
            return CM_ERROR;
        }
        LOG_RUN_INF("Unregister conflict, rk: %lld, dev: %s", rk, dev);
    }
    LOG_RUN_INF("Unregister success, rk: %lld, dev: %s.", rk, dev);
    return CM_SUCCESS;
}

static void dss_get_vg_info_is_server(bool32 is_server, dss_vg_info_t **dss_vg_info)
{
    if (is_server) {
        *dss_vg_info = VGS_INFO;
    } else {
        dss_env_t *dss_env = dss_get_env();
        *dss_vg_info = dss_env->dss_vg_info;
    }
}

status_t dss_iof_register_core(int64 rk, dss_vg_info_t *dss_vg_info)
{
    status_t ret;
    for (uint32 i = 0; i < (uint32)dss_vg_info->group_num; i++) {
        dss_vg_info_item_t *item = &dss_vg_info->volume_group[i];
        ret = dss_iof_register_single(rk, item->entry_path);
        if (ret != CM_SUCCESS) {
            return ret;
        }
        // volume_attrs[0] is the sys dev
        for (uint32 j = 1; j < DSS_MAX_VOLUMES; j++) {
            if (item->dss_ctrl->core.volume_attrs[j].flag == VOLUME_FREE) {
                continue;
            }
            DSS_RETURN_IF_ERROR(dss_iof_register_single(rk, item->dss_ctrl->volume.defs[j].name));
        }
    }
    return CM_SUCCESS;
}

status_t dss_iof_register_all(int64 rk, bool32 is_server)
{
#ifdef WIN32
#else
    dss_vg_info_t *dss_vg_info = NULL;

    LOG_DEBUG_INF("Begin register all, rk %lld, is server %u.", rk + 1, (uint32)is_server);
    dss_get_vg_info_is_server(is_server, &dss_vg_info);
    bool32 result = (bool32)(dss_vg_info != NULL);
    DSS_RETURN_IF_FALSE2(result, LOG_DEBUG_ERR("Can't get vgs info, is_server %u.", (uint32)is_server));
    status_t ret = dss_iof_register_core(rk, dss_vg_info);
    if (ret != CM_SUCCESS) {
        return ret;
    }
#endif
    LOG_RUN_INF("IOfence register all succ.");
    return CM_SUCCESS;
}

status_t dss_iof_unregister_core(int64 rk, dss_vg_info_t *dss_vg_info)
{
    status_t ret;
    for (uint32 i = 0; i < (uint32)dss_vg_info->group_num; i++) {
        dss_vg_info_item_t *item = &dss_vg_info->volume_group[i];
        ret = dss_iof_unregister_single(rk, item->entry_path);
        if (ret != CM_SUCCESS) {
            return ret;
        }
        // volume_attrs[0] is the sys dev
        for (uint32 j = 1; j < DSS_MAX_VOLUMES; j++) {
            if (item->dss_ctrl->core.volume_attrs[j].flag == VOLUME_FREE) {
                continue;
            }
            DSS_RETURN_IF_ERROR(dss_iof_unregister_single(rk, item->dss_ctrl->volume.defs[j].name));
        }
    }
    LOG_DEBUG_INF("Unregister all succ.");
    return CM_SUCCESS;
}

status_t dss_iof_unregister_all(int64 rk, bool32 is_server)
{
#ifdef WIN32
#else
    dss_vg_info_t *dss_vg_info = NULL;

    LOG_DEBUG_INF("Begin Unregister all, rk %lld, is server %u.", rk + 1, (uint32)is_server);
    dss_get_vg_info_is_server(is_server, &dss_vg_info);
    bool32 result = (bool32)(dss_vg_info != NULL);
    DSS_RETURN_IF_FALSE2(result, LOG_DEBUG_ERR("Can't get vgs info, is_server %u.", (uint32)is_server));
    status_t ret = dss_iof_unregister_core(rk, dss_vg_info);
    if (ret != CM_SUCCESS) {
        return ret;
    }
#endif
    LOG_RUN_INF("IOfence unregister all succ.");
    return CM_SUCCESS;
}

status_t dss_inquiry_lun(dev_info_t *dev_info)
{
#ifdef WIN32
#else
    status_t status = CM_SUCCESS;

    if (dev_info == NULL || dev_info->dev == NULL) {
        return CM_ERROR;
    }

    status = perctrl_scsi3_inql(dev_info->dev, &dev_info->data);
    if (status != CM_SUCCESS) {
        LOG_DEBUG_ERR("Failed to inquiry lun info, status %d.", status);
        return CM_ERROR;
    }

#endif

    return CM_SUCCESS;
}

status_t dss_inquiry_luns_from_ctrl(dss_vg_info_item_t *item, ptlist_t *lunlist)
{
    status_t status;
    for (uint32 j = 1; j < DSS_MAX_VOLUMES; j++) {
        if (item->dss_ctrl->core.volume_attrs[j].flag == VOLUME_FREE) {
            continue;
        }

        dev_info_t *dev_info = (dev_info_t *)malloc(sizeof(dev_info_t));
        bool32 result = (bool32)(dev_info != NULL);
        DSS_RETURN_IF_FALSE2(result, LOG_DEBUG_ERR("Malloc failed."));

        errno_t ret = memset_sp(dev_info, sizeof(dev_info_t), 0, sizeof(dev_info_t));
        result = (bool32)(ret == EOK);
        DSS_RETURN_IF_FALSE3(result, DSS_FREE_POINT(dev_info), DSS_THROW_ERROR(ERR_SYSTEM_CALL, ret));

        dev_info->dev = item->dss_ctrl->volume.defs[j].name;
        status = dss_inquiry_lun(dev_info);
        DSS_RETURN_IFERR3(status, DSS_FREE_POINT(dev_info),
            LOG_DEBUG_ERR("Inquiry dev failed, dev %s.", item->dss_ctrl->volume.defs[j].name));

        status = cm_ptlist_add(lunlist, dev_info);
        DSS_RETURN_IFERR2(status, DSS_FREE_POINT(dev_info));
    }
    return CM_SUCCESS;
}

status_t dss_inquiry_luns(ptlist_t *lunlist, bool32 is_server)
{
#ifdef WIN32
#else
    status_t status = CM_SUCCESS;
    dss_vg_info_t *dss_vg_info = NULL;
    dev_info_t *dev_info = NULL;
    errno_t ret;

    LOG_DEBUG_INF("Begin inquiry luns, is server %u.", (uint32)is_server);
    dss_get_vg_info_is_server(is_server, &dss_vg_info);

    if (dss_vg_info == NULL) {
        return CM_SUCCESS;
    }

    for (uint32 i = 0; i < (uint32)dss_vg_info->group_num; i++) {
        dss_vg_info_item_t *item = &dss_vg_info->volume_group[i];

        dev_info = (dev_info_t *)malloc(sizeof(dev_info_t));
        bool32 result = (bool32)(dev_info != NULL);
        DSS_RETURN_IF_FALSE2(result, LOG_DEBUG_ERR("Malloc failed."));

        ret = memset_sp(dev_info, sizeof(dev_info_t), 0, sizeof(dev_info_t));
        result = (bool32)(ret == EOK);
        DSS_RETURN_IF_FALSE3(result, DSS_FREE_POINT(dev_info), DSS_THROW_ERROR(ERR_SYSTEM_CALL, ret));

        dev_info->dev = item->entry_path;
        status = dss_inquiry_lun(dev_info);
        if (status != CM_SUCCESS) {
            LOG_DEBUG_ERR("Inquiry entry path dev failed, dev %s.", item->entry_path);
            DSS_FREE_POINT(dev_info);
            return CM_ERROR;
        }

        status = cm_ptlist_add(lunlist, dev_info);
        DSS_RETURN_IFERR2(status, DSS_FREE_POINT(dev_info));

        // volume_attrs[0] is the sys dev
        DSS_RETURN_IF_ERROR(dss_inquiry_luns_from_ctrl(item, lunlist));
    }
#endif

    LOG_RUN_INF("Inquiry luns succ.");
    return CM_SUCCESS;
}

status_t dss_iof_inql_regs_core(ptlist_t *reglist, dss_vg_info_item_t *item)
{
    iof_reg_in_t *reg_info = NULL;
    status_t status = CM_SUCCESS;
    errno_t ret;
    // volume_attrs[0] is the sys dev
    for (uint32 j = 1; j < DSS_MAX_VOLUMES; j++) {
        if (item->dss_ctrl->core.volume_attrs[j].flag == VOLUME_FREE) {
            continue;
        }

        reg_info = (iof_reg_in_t *)malloc(sizeof(iof_reg_in_t));
        bool32 result = (bool32)(reg_info != NULL);
        DSS_RETURN_IF_FALSE2(result, LOG_DEBUG_ERR("Malloc failed."));

        ret = memset_sp(reg_info, sizeof(iof_reg_in_t), 0, sizeof(iof_reg_in_t));
        result = (bool32)(ret == EOK);
        DSS_RETURN_IF_FALSE3(result, DSS_FREE_POINT(reg_info), DSS_THROW_ERROR(ERR_SYSTEM_CALL, ret));

        reg_info->dev = item->dss_ctrl->volume.defs[j].name;
        status = cm_iof_inql(reg_info);
        if (status != CM_SUCCESS) {
            LOG_DEBUG_ERR("Inquiry reg info for dev failed, dev %s.", item->dss_ctrl->volume.defs[j].name);
            DSS_FREE_POINT(reg_info);
            return CM_ERROR;
        }

        status = cm_ptlist_add(reglist, reg_info);
        DSS_RETURN_IFERR2(status, DSS_FREE_POINT(reg_info));
    }
    return CM_SUCCESS;
}

status_t dss_iof_inql_regs(dss_vg_info_t *vg_info, ptlist_t *reglist)
{
#ifdef WIN32
#else
    status_t status = CM_SUCCESS;
    iof_reg_in_t *reg_info = NULL;
    errno_t ret;

    for (uint32 i = 0; i < (uint32)vg_info->group_num; i++) {
        dss_vg_info_item_t *item = &vg_info->volume_group[i];
        reg_info = (iof_reg_in_t *)malloc(sizeof(iof_reg_in_t));
        bool32 result = (bool32)(reg_info != NULL);
        DSS_RETURN_IF_FALSE2(result, LOG_DEBUG_ERR("Malloc failed."));

        ret = memset_sp(reg_info, sizeof(iof_reg_in_t), 0, sizeof(iof_reg_in_t));
        result = (bool32)(ret == EOK);
        DSS_RETURN_IF_FALSE3(result, DSS_FREE_POINT(reg_info), DSS_THROW_ERROR(ERR_SYSTEM_CALL, ret));

        reg_info->dev = item->entry_path;
        status = cm_iof_inql(reg_info);
        if (status != CM_SUCCESS) {
            LOG_DEBUG_ERR("Inquiry reg info for entry path dev failed, dev %s.", item->entry_path);
            DSS_FREE_POINT(reg_info);
            return CM_ERROR;
        }

        status = cm_ptlist_add(reglist, reg_info);
        DSS_RETURN_IFERR2(status, DSS_FREE_POINT(reg_info));
        // volume_attrs[0] is the sys dev
        DSS_RETURN_IF_ERROR(dss_iof_inql_regs_core(reglist, item));
    }
#endif
    return CM_SUCCESS;
}
