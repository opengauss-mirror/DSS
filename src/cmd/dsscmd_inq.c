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
 * dsscmd_inq.c
 *
 *
 * IDENTIFICATION
 *    src/cmd/dsscmd_inq.c
 *
 * -------------------------------------------------------------------------
 */

#include "dss_malloc.h"
#include "dss_latch.h"
#include "dss_redo.h"
#include "dsscmd_inq.h"

#ifdef __cplusplus
extern "C" {
#endif

static void print_dev_info(ptlist_t *devs)
{
    (void)printf("%-20s %-20s %-20s %-20s %-15s %-20s\n", "Dev", "Vendor", "Model", "ArraySN", "LUNID", "LUNWWN");

    uint32 i;
    dev_info_t *dev_info = NULL;
    text_t text;
    for (i = 0; i < devs->count; i++) {
        dev_info = (dev_info_t *)cm_ptlist_get(devs, i);
        if (dev_info != NULL) {
            // trim vendor
            cm_str2text(dev_info->data.vendor_info.vendor, &text);
            cm_trim_text(&text);
            DSS_RETURN_DRIECT_IFERR(cm_text2str(&text, dev_info->data.vendor_info.vendor, CM_MAX_VENDOR_LEN));
            // trim product
            cm_str2text(dev_info->data.vendor_info.product, &text);
            cm_trim_text(&text);
            DSS_RETURN_DRIECT_IFERR(cm_text2str(&text, dev_info->data.vendor_info.product, CM_MAX_PRODUCT_LEN));
            (void)printf("%-20s %-20s %-20s %-20s %-15d %-20s\n", dev_info->dev, dev_info->data.vendor_info.vendor,
                dev_info->data.vendor_info.product, dev_info->data.array_info.array_sn, dev_info->data.lun_info.lun_id,
                dev_info->data.lun_info.lun_wwn);
        }
    }
}

#define DSS_MAX_REKEY_BUFF (DSS_MAX_INSTANCES * 4)
static void print_reg_info_rely_resk(int64 resk)
{
    if (resk > 0) {
        (void)printf("%-20lld ", resk - 1);
    } else {
        (void)printf("%-20c ", '-');
    }
}

static void print_reg_info_rely_key_count(iof_reg_in_t *reg_info)
{
    char buff[DSS_MAX_REKEY_BUFF];
    text_t text;
    text.str = buff;
    text.len = 0;
    if (reg_info->key_count > 0) {
        (void)memset_s(buff, sizeof(buff), 0, sizeof(buff));
        text.len = 0;
        for (int32 j = 0; j < reg_info->key_count; j++) {
            cm_concat_int32(&text, DSS_MAX_REKEY_BUFF, (int32)(reg_info->reg_keys[j] - 1));
            if (j + 1 < reg_info->key_count) {
                (void)cm_concat_string(&text, DSS_MAX_REKEY_BUFF, ",");
            }
        }
        (void)printf("%-20s\n", text.str);
    } else {
        (void)printf("%-20c\n", '-');
    }
}

static void print_reg_info(ptlist_t *regs)
{
    (void)printf("%-20s %-20s %-20s %-20s\n", "Dev", "Generation", "RESKEY", "REGKEY");

    uint32 i;
    iof_reg_in_t *reg_info = NULL;

    for (i = 0; i < regs->count; i++) {
        reg_info = (iof_reg_in_t *)cm_ptlist_get(regs, i);
        if (reg_info != NULL) {
            (void)printf("%-20s %-20u ", reg_info->dev, reg_info->generation);
            print_reg_info_rely_resk(reg_info->resk);
            print_reg_info_rely_key_count(reg_info);
        }
    }
}

static status_t dss_modify_cluster_node_info(
    dss_vg_info_item_t *vg_item, dss_config_t *inst_cfg, dss_inq_status_e inq_status, int64 host_id)
{
    if (dss_lock_vg_storage_w(vg_item, vg_item->entry_path, inst_cfg) != CM_SUCCESS) {
        LOG_DEBUG_ERR("[FENCE] Failed to lock vg:%s.", vg_item->entry_path);
        return CM_ERROR;
    }

    bool32 remote = CM_FALSE;
    dss_group_global_ctrl_t *global_ctrl  = &vg_item->dss_ctrl->global_ctrl;
    status_t status = dss_load_vg_ctrl_part(
        vg_item, (int64)(DSS_VOLUME_HEAD_SIZE - DSS_DISK_UNIT_SIZE), global_ctrl, DSS_DISK_UNIT_SIZE, &remote);
    if (status != CM_SUCCESS) {
        dss_unlock_vg_storage(vg_item, vg_item->entry_path, inst_cfg);
        LOG_DEBUG_ERR("[FENCE] Failed to load global ctrl part %s, errno:%d, errmsg:%s.", vg_item->entry_path,
            cm_get_os_error(), strerror(cm_get_os_error()));
        return status;
    }

    bool32 is_reg = cm_bitmap64_exist(&global_ctrl->cluster_node_info, (uint8)host_id);
    if (is_reg && inq_status == DSS_INQ_STATUS_REG) {
        dss_unlock_vg_storage(vg_item, vg_item->entry_path, inst_cfg);
        return CM_SUCCESS;
    }
    if (!is_reg && inq_status == DSS_INQ_STATUS_UNREG) {
        dss_unlock_vg_storage(vg_item, vg_item->entry_path, inst_cfg);
        return CM_SUCCESS;
    }

    if (inq_status == DSS_INQ_STATUS_REG) {
        cm_bitmap64_set(&global_ctrl->cluster_node_info, (uint8)host_id);
    } else {
        cm_bitmap64_clear(&global_ctrl->cluster_node_info, (uint8)host_id);
    }

    status = dss_write_ctrl_to_disk(
        vg_item, (int64)(DSS_VOLUME_HEAD_SIZE - DSS_DISK_UNIT_SIZE), global_ctrl, DSS_DISK_UNIT_SIZE);
    dss_unlock_vg_storage(vg_item, vg_item->entry_path, inst_cfg);
    return status;
}

// get the non-entry disk information of vg.
status_t dss_get_vg_non_entry_info(
    dss_config_t *inst_cfg, dss_vg_info_item_t *vg_item, bool32 is_lock, bool32 check_redo)
{
    if (vg_item->vg_name[0] == '\0' || vg_item->entry_path[0] == '\0') {
        LOG_DEBUG_ERR("Failed to load vg ctrl, input parameter is invalid.");
        return CM_ERROR;
    }

    LOG_DEBUG_INF("Begin to load vg ctrl when get non entry info, is_lock is %d.", is_lock);
    if (is_lock) {
        if (dss_lock_vg_storage_r(vg_item, vg_item->entry_path, inst_cfg) != CM_SUCCESS) {
          LOG_DEBUG_ERR("Failed to lock vg:%s.", vg_item->entry_path);
           return CM_ERROR;
        }
    }

    bool32 remote = CM_FALSE;
    status_t status = CM_ERROR;
    bool32 recover_redo = CM_FALSE;
    do {
        status = dss_load_vg_ctrl_part(vg_item, 0, vg_item->dss_ctrl, (int32)sizeof(dss_ctrl_t), &remote);
        if (status != CM_SUCCESS) {
            LOG_DEBUG_ERR("Failed to load vg ctrl part %s.", vg_item->entry_path);
            break;
        }

        if (!DSS_VG_IS_VALID(vg_item->dss_ctrl)) {
            DSS_THROW_ERROR(ERR_DSS_VG_CHECK_NOT_INIT);
            break;
        }
        
        if (check_redo) {
            status = dss_check_recover_redo_log(vg_item, &recover_redo);
            if (status != CM_SUCCESS) {
                LOG_DEBUG_ERR("Failed to check recover redo log.");
            }
        }        
    } while (CM_FALSE);

    if (is_lock) {
        dss_unlock_vg_storage(vg_item, vg_item->entry_path, inst_cfg);
    }
    if (status != CM_SUCCESS) {
        return status;
    }
    if (check_redo && recover_redo) {
        DSS_THROW_ERROR(ERR_DSS_REDO_ILL, "residual redo log exists on the server.");
        LOG_RUN_ERR("Please start dssserver to recover redo log, then execute this command again.");
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

static status_t dss_alloc_volume_group(dss_vg_info_t *vg_info)
{
    uint32 len = DSS_MAX_STACK_BUF_SIZE + DSS_MAX_STACK_BUF_SIZE + DSS_MAX_STACK_BUF_SIZE + sizeof(dss_ctrl_t);
    char *buf = (char *)cm_malloc_align(DSS_ALIGN_SIZE, vg_info->group_num * len);
    bool32 result = (bool32)(buf != NULL);
    DSS_RETURN_IF_FALSE2(
        result, LOG_DEBUG_ERR("cm_malloc_align stack failed, align size:%u, size:%u.", DSS_ALIGN_SIZE, len));
    for (uint32 i = 0; i < vg_info->group_num; i++) {
        vg_info->volume_group[i].buffer_cache = (shm_hashmap_t *)(buf + i * len);
        vg_info->volume_group[i].vg_latch = (dss_shared_latch_t *)(buf + i * len + DSS_MAX_STACK_BUF_SIZE);
        vg_info->volume_group[i].stack.buff = (char *)(buf + i * len + DSS_MAX_STACK_BUF_SIZE + DSS_MAX_STACK_BUF_SIZE);
        vg_info->volume_group[i].dss_ctrl =
            (dss_ctrl_t *)(buf + i * len + DSS_MAX_STACK_BUF_SIZE + DSS_MAX_STACK_BUF_SIZE + DSS_MAX_STACK_BUF_SIZE);
        for (uint32 j = 0; j < DSS_MAX_VOLUMES; j++) {
            vg_info->volume_group[i].id = i;
            vg_info->volume_group[i].volume_handle[j].handle = DSS_INVALID_HANDLE;
            vg_info->volume_group[i].volume_handle[j].handle = DSS_INVALID_HANDLE;
        }
    }
    return CM_SUCCESS;
}

static void dss_free_volume_group(dss_vg_info_t *vg_info)
{
    // This memory is applied for together, only hthe header needs to be released.
    DSS_FREE_POINT(vg_info->volume_group[0].buffer_cache);
}

// get the entry disk information of vg from config.
static status_t dss_get_vg_entry_info(const char *home, dss_config_t *inst_cfg, dss_vg_info_t *vg_info)
{
    status_t status = dss_set_cfg_dir(home, inst_cfg);
    DSS_RETURN_IFERR2(status, LOG_DEBUG_ERR("Environment variant DSS_HOME not found."));
    status = dss_load_config(inst_cfg);
    DSS_RETURN_IFERR2(status, LOG_DEBUG_ERR("Failed to load parameters."));
    status = dss_load_vg_conf_inner(vg_info, inst_cfg);
    DSS_RETURN_IFERR2(status, LOG_DEBUG_ERR("Failed to load vg conf inner."));
    return CM_SUCCESS;
}

status_t dss_inq_alloc_vg_info(const char *home, dss_config_t *inst_cfg, dss_vg_info_t **vg_info)
{
    *vg_info = (dss_vg_info_t *)cm_malloc(sizeof(dss_vg_info_t));
    if (*vg_info == NULL) {
        DSS_PRINT_ERROR("Failed to malloc vg_info when alloc vg info.\n");
        return CM_ERROR;
    }
    errno_t errcode = memset_s(*vg_info, sizeof(dss_vg_info_t), 0, sizeof(dss_vg_info_t));
    if (errcode != EOK) {
        DSS_FREE_POINT(*vg_info);
        DSS_PRINT_ERROR("Failed to memset vg_info when alloc vg info.\n");
        return CM_ERROR;
    }

    status_t status = dss_get_vg_entry_info(home, inst_cfg, *vg_info);
    if (status != CM_SUCCESS) {
        DSS_FREE_POINT(*vg_info);
        DSS_PRINT_ERROR("Failed to get vg entry info when alloc vg info.\n");
        return CM_ERROR;
    }

    status = dss_alloc_volume_group(*vg_info);
    if (status != CM_SUCCESS) {
        DSS_FREE_POINT(*vg_info);
        DSS_PRINT_ERROR("Failed to alloc volume group when alloc vg info.\n");
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

void dss_inq_free_vg_info(dss_vg_info_t *vg_info)
{
    dss_free_volume_group(vg_info);
    DSS_FREE_POINT(vg_info);
}

status_t dss_inq_lun(const char *home)
{
#ifndef WIN32
    status_t status;
    dss_config_t inst_cfg;
    dss_vg_info_t *vg_info = NULL;
    DSS_RETURN_IF_ERROR(dss_inq_alloc_vg_info(home, &inst_cfg, &vg_info));

    for (uint32 i = 0; i < vg_info->group_num; i++) {
        status = dss_get_vg_non_entry_info(&inst_cfg, &vg_info->volume_group[i], CM_TRUE, CM_FALSE);
        if (status != CM_SUCCESS) {
            dss_inq_free_vg_info(vg_info);
            DSS_PRINT_ERROR("Failed to get vg non entry info when inq lun.\n");
            return status;
        }
    }
    ptlist_t devlist;
    cm_ptlist_init(&devlist);
    status = dss_inquiry_luns(vg_info, &devlist);
    if (status != CM_SUCCESS) {
        dss_destroy_ptlist(&devlist);
        dss_inq_free_vg_info(vg_info);
        return status;
    }
    print_dev_info(&devlist);
    dss_destroy_ptlist(&devlist);
    dss_inq_free_vg_info(vg_info);
#endif
    return CM_SUCCESS;
}

status_t dss_inq_reg(const char *home)
{
#ifndef WIN32
    status_t status;
    dss_config_t inst_cfg;
    dss_vg_info_t *vg_info = NULL;
    DSS_RETURN_IF_ERROR(dss_inq_alloc_vg_info(home, &inst_cfg, &vg_info));

    for (uint32 i = 0; i < vg_info->group_num; i++) {
        status = dss_get_vg_non_entry_info(&inst_cfg, &vg_info->volume_group[i], CM_TRUE, CM_FALSE);
        if (status != CM_SUCCESS) {
            dss_inq_free_vg_info(vg_info);
            DSS_PRINT_ERROR("Failed to get vg non entry info when inq reg.\n");
            return status;
        }
    }

    ptlist_t reg_info;
    cm_ptlist_init(&reg_info);
    status = dss_iof_inql_regs(vg_info, &reg_info);
    if (status != CM_SUCCESS) {
        dss_destroy_ptlist(&reg_info);
        dss_inq_free_vg_info(vg_info);
        return status;
    }

    print_reg_info(&reg_info);
    dss_destroy_ptlist(&reg_info);
    dss_inq_free_vg_info(vg_info);
#endif
    return CM_SUCCESS;
}

bool32 is_register(iof_reg_in_t *reg, int64 host_id, int64 *iofence_key)
{
    for (int32 i = 0; i < reg->key_count; i++) {
        if (reg->reg_keys[i] < 1 || reg->reg_keys[i] > DSS_MAX_INSTANCES) {
            continue;
        }
        iofence_key[reg->reg_keys[i] - 1]++;
    }
    for (int32 i = 0; i < reg->key_count; i++) {
        if (reg->reg_keys[i] == host_id + 1) {
            return DSS_TRUE;
        }
    }
    return DSS_FALSE;
}

status_t dss_check_volume_register(char *entry_path, int64 host_id, bool32 *is_reg, int64 *iofence_key)
{
    *is_reg = DSS_TRUE;
    iof_reg_in_t reg_info;
    errno_t errcode = memset_s(&reg_info, sizeof(reg_info), 0, sizeof(reg_info));
    securec_check_ret(errcode);

    reg_info.dev = entry_path;
    status_t status = cm_iof_inql(&reg_info);
    if (status != CM_SUCCESS) {
        LOG_DEBUG_ERR("[FENCE] Inquiry reg info for entry path dev failed, dev %s.", reg_info.dev);
        return CM_ERROR;
    }
    if (!is_register(&reg_info, host_id, iofence_key)) {
        *is_reg = DSS_FALSE;
    }

    LOG_RUN_INF("Succeed to check volume register, vol_path is %s, result is %d.", entry_path, *is_reg);
    return CM_SUCCESS;
}

static status_t dss_reghl_inner(dss_vg_info_item_t *item, int64 host_id)
{
    for (uint32 j = 1; j < DSS_MAX_VOLUMES; j++) {
        if (item->dss_ctrl->volume.defs[j].flag == VOLUME_FREE) {
            continue;
        }
        CM_RETURN_IFERR(dss_iof_register_single(host_id, item->dss_ctrl->volume.defs[j].name));
    }
    return CM_SUCCESS;
}

static void dss_printf_iofence_key(int64 *iofence_key)
{
    char buff[DSS_MAX_REKEY_BUFF];
    text_t text;
    text.str = buff;
    text.len = 0;
    (void)memset_s(buff, sizeof(buff), 0, sizeof(buff));
    for (int32 j = 0; j < DSS_MAX_INSTANCES; j++) {
        if (iofence_key[j] == 0) {
            continue;
        }
        cm_concat_int32(&text, DSS_MAX_REKEY_BUFF, j);
        if (j + 1 < DSS_MAX_INSTANCES) {
            (void)cm_concat_string(&text, DSS_MAX_REKEY_BUFF, ",");
        }
    }
    if (text.len == 0) {
        (void)printf("iofence_key=-1\n");
        LOG_RUN_INF("iofence_key=-1.");
    } else {
        (void)printf("iofence_key=%-20s\n", text.str);
        LOG_RUN_INF("iofence_key=%-20s.", text.str);
    }
}

/*
 * 1. get vg entry info
 * 2. register vg entry disk
 * 3. get vg non entry info
 * 4. register vg non entry disk
 */
status_t dss_reghl_core(const char *home)
{
#ifndef WIN32
    status_t status;
    dss_config_t inst_cfg;
    dss_vg_info_t *vg_info = NULL;
    DSS_RETURN_IF_ERROR(dss_inq_alloc_vg_info(home, &inst_cfg, &vg_info));

    for (uint32 i = 0; i < vg_info->group_num; i++) {
        status = dss_iof_register_single(inst_cfg.params.inst_id, vg_info->volume_group[i].entry_path);
        if (status != CM_SUCCESS) {
            dss_inq_free_vg_info(vg_info);
            DSS_PRINT_ERROR("Failed to register vg entry disk when reghl, errcode is %d.\n", status);
            return status;
        }
        status = dss_get_vg_non_entry_info(&inst_cfg, &vg_info->volume_group[i], CM_TRUE, CM_FALSE);
        if (status != CM_SUCCESS) {
            dss_inq_free_vg_info(vg_info);
            DSS_PRINT_ERROR("Failed to get vg non entry info when reghl, errcode is %d.\n", status);
            return status;
        }
        if (i == 0) {
            status = dss_modify_cluster_node_info(
                &vg_info->volume_group[i], &inst_cfg, DSS_INQ_STATUS_REG, inst_cfg.params.inst_id);
            if (status != CM_SUCCESS) {
                dss_inq_free_vg_info(vg_info);
                DSS_PRINT_ERROR("Failed to modify node cluster info, errcode is %d.\n", status);
                return status;
            }
        }
        status = dss_reghl_inner(&vg_info->volume_group[i], inst_cfg.params.inst_id);
        if (status != CM_SUCCESS) {
            dss_inq_free_vg_info(vg_info);
            DSS_PRINT_ERROR("Failed to reghl, errcode is %d.\n", status);
            return status;
        }
    }
    dss_inq_free_vg_info(vg_info);
    LOG_RUN_INF("Succeed to register instance %llu.", inst_cfg.params.inst_id);
#endif
    return CM_SUCCESS;
}

static status_t dss_unreghl_inner(dss_vg_info_item_t *item, int64 host_id)
{
    for (uint32 j = 1; j < DSS_MAX_VOLUMES; j++) {
        if (item->dss_ctrl->volume.defs[j].flag == VOLUME_FREE) {
            continue;
        }
        CM_RETURN_IFERR(dss_iof_unregister_single(host_id, item->dss_ctrl->volume.defs[j].name));
    }
    return dss_iof_unregister_single(host_id, item->entry_path);
}

/*
 * 1. get vg entry info
 * 2. check vg entry disk is register
 * 3. get vg non entry info
 * 4. unregister vg non entry disk
 * 5. unregister vg entry disk
 */
status_t dss_unreghl_core(const char *home, bool32 is_lock)
{
#ifndef WIN32
    bool32 is_reg;
    status_t status;
    dss_config_t inst_cfg;
    dss_vg_info_t *vg_info = NULL;
    int64 iofence_key[DSS_MAX_INSTANCES] = {0};
    DSS_RETURN_IF_ERROR(dss_inq_alloc_vg_info(home, &inst_cfg, &vg_info));

    for (uint32 i = 0; i < vg_info->group_num; i++) {
        status = dss_check_volume_register(
            vg_info->volume_group[i].entry_path, inst_cfg.params.inst_id, &is_reg, iofence_key);
        if (status != CM_SUCCESS) {
            dss_inq_free_vg_info(vg_info);
            DSS_PRINT_ERROR("Failed to check volume register when unreghl, errcode is %d.\n", status);
            return CM_ERROR;
        }
        if (!is_reg) {
            continue;
        }
        status = dss_get_vg_non_entry_info(&inst_cfg, &vg_info->volume_group[i], is_lock, CM_FALSE);
        if (status != CM_SUCCESS) {
            dss_inq_free_vg_info(vg_info);
            DSS_PRINT_ERROR("Failed to get vg entry info when unreghl, errcode is %d.\n", status);
            return status;
        }
        if (i == 0 && is_lock) {
            status = dss_modify_cluster_node_info(
                &vg_info->volume_group[i], &inst_cfg, DSS_INQ_STATUS_UNREG, inst_cfg.params.inst_id);
            if (status != CM_SUCCESS) {
                dss_inq_free_vg_info(vg_info);
                DSS_PRINT_ERROR("Failed to modify node cluster info, errcode is %d.\n", status);
                return status;
            }
        }
        status = dss_unreghl_inner(&vg_info->volume_group[i], inst_cfg.params.inst_id);
        if (status != CM_SUCCESS) {
            dss_inq_free_vg_info(vg_info);
            DSS_PRINT_ERROR("Failed to unreghl, errcode is %d.\n", status);
            return status;
        }
    }
    dss_inq_free_vg_info(vg_info);
    LOG_RUN_INF("Succeed to unregister instance %llu.", inst_cfg.params.inst_id);
#endif
    return CM_SUCCESS;
}

static status_t dss_inq_reg_inner(dss_vg_info_t *vg_info, dss_config_t *inst_cfg, int64 host_id, int64 *iofence_key)
{
    bool32 is_reg;
    dss_vg_info_item_t *item = NULL;
    for (uint32 i = 0; i < vg_info->group_num; i++) {
        CM_RETURN_IFERR(dss_get_vg_non_entry_info(inst_cfg, &vg_info->volume_group[i], CM_TRUE, CM_FALSE));
        item = &vg_info->volume_group[i];
        for (uint32 j = 1; j < DSS_MAX_VOLUMES; j++) {
            if (item->dss_ctrl->volume.defs[j].flag == VOLUME_FREE) {
                continue;
            }
            CM_RETURN_IFERR(
                dss_check_volume_register(item->dss_ctrl->volume.defs[j].name, host_id, &is_reg, iofence_key));
            if (!is_reg) {
                DSS_PRINT_INF("The node %lld is registered partially, inq_result = 1.\n", host_id);
                LOG_RUN_INF("The node %lld is registered partially, inq_result = 1.", host_id);
                return CM_TIMEDOUT;
            }
        }
    }
    DSS_PRINT_INF("The node %lld is registered, inq_result = 2.\n", host_id);
    LOG_RUN_INF("The node %lld is registered, inq_result = 2.", host_id);
    return CM_PIPECLOSED;
}

/*
 * 1. get vg entry info
 * 2. check vg entry disk is register. If neither is registered, return 0, else if partially registered, return 1.
 * 3. get vg non entry info
 * 4. check vg non entry disk is register. If all are registered, return 2, else return 1.
 */
status_t dss_inq_reg_core(const char *home, int64 host_id)
{
#ifndef WIN32
    bool32 is_reg;
    uint32 count = 0;
    status_t status;
    dss_config_t inst_cfg;
    dss_vg_info_t *vg_info = NULL;
    int64 iofence_key[DSS_MAX_INSTANCES] = {0};
    DSS_RETURN_IF_ERROR(dss_inq_alloc_vg_info(home, &inst_cfg, &vg_info));

    for (uint32 i = 0; i < vg_info->group_num; i++) {
        status = dss_check_volume_register(vg_info->volume_group[i].entry_path, host_id, &is_reg, iofence_key);
        if (status != CM_SUCCESS) {
            dss_inq_free_vg_info(vg_info);
            DSS_PRINT_ERROR("Failed to check vg entry info when inq reg, errcode is %d.\n", status);
            return CM_ERROR;
        }
        if (!is_reg) {
            count++;
        }
    }
    if (count == vg_info->group_num) {
        dss_printf_iofence_key(iofence_key);
        dss_inq_free_vg_info(vg_info);
        DSS_PRINT_INF("The node %lld is not registered, inq_result = 0.\n", host_id);
        LOG_RUN_INF("The node %lld is not registered, inq_result = 0.", host_id);
        return CM_SUCCESS;
    }
    if (count != 0 && count != vg_info->group_num) {
        dss_printf_iofence_key(iofence_key);
        dss_inq_free_vg_info(vg_info);
        DSS_PRINT_INF("The node %lld is registered partially, inq_result = 1.\n", host_id);
        LOG_RUN_INF("The node %lld is registered partially, inq_result = 1.", host_id);
        return CM_TIMEDOUT;
    }
    status = dss_inq_reg_inner(vg_info, &inst_cfg, host_id, iofence_key);
    dss_inq_free_vg_info(vg_info);
    if (status == CM_ERROR) {
        DSS_PRINT_ERROR("Failed to check vg entry info when inq reg, errcode is %d.\n", status);
        return CM_ERROR;
    }
    dss_printf_iofence_key(iofence_key);
    return status;
#endif
    return CM_PIPECLOSED;
}

static status_t dss_clean_inner(dss_vg_info_t *vg_info, dss_config_t *inst_cfg, int64 inst_id)
{
    bool32 is_lock = CM_FALSE;
    dss_vg_info_item_t *vg_item;
    int64 tmp_inst_id = (inst_id == DSS_MAX_INST_ID) ? inst_cfg->params.inst_id : inst_id;
    for (uint32 i = 0; i < vg_info->group_num; i++) {
        vg_item = &vg_info->volume_group[i];
        if (vg_item->vg_name[0] == '\0' || vg_item->entry_path[0] == '\0') {
            return CM_ERROR;
        }
        if (dss_check_lock_instid(vg_item, vg_item->entry_path, tmp_inst_id, &is_lock) != CM_SUCCESS) {
            return CM_ERROR;
        }
        if (!is_lock) {
            continue;
        }
        if (inst_id != DSS_MAX_INST_ID) {
            dss_unlock_vg_raid(vg_item, vg_item->entry_path, tmp_inst_id);
            continue;
        }
        if (dss_file_lock_vg_w(inst_cfg) != CM_SUCCESS) {
            return CM_ERROR;
        }
        dss_unlock_vg_raid(vg_item, vg_item->entry_path, tmp_inst_id);
        dss_file_unlock_vg();
    }
    return CM_SUCCESS;
}

status_t dss_clean_vg_lock(const char *home, int64 inst_id)
{
#ifndef WIN32
    dss_config_t inst_cfg;
    dss_vg_info_t *vg_info = NULL;
    DSS_RETURN_IF_ERROR(dss_inq_alloc_vg_info(home, &inst_cfg, &vg_info));

    int32 dss_mode = dss_storage_mode(&inst_cfg);
    if (dss_mode == DSS_MODE_DISK) {
        dss_inq_free_vg_info(vg_info);
        return CM_SUCCESS;
    }

    status_t status = dss_clean_inner(vg_info, &inst_cfg, inst_id);
    dss_inq_free_vg_info(vg_info);
    return status;
#endif
    return CM_SUCCESS;
}

static status_t dss_kickh_inner(dss_vg_info_t *vg_info, dss_config_t *inst_cfg, int64 host_id, bool32 is_lock)
{
    status_t status;
    for (uint32 i = 0; i < vg_info->group_num; i++) {
        status = dss_get_vg_non_entry_info(inst_cfg, &vg_info->volume_group[i], is_lock, CM_FALSE);
        if (status != CM_SUCCESS) {
            DSS_PRINT_ERROR("Failed to get vg non entry info when kickh.\n");
            return CM_ERROR;
        }
    }

    if (is_lock) {
        status = dss_modify_cluster_node_info(&vg_info->volume_group[0], inst_cfg, DSS_INQ_STATUS_UNREG, host_id);
        if (status != CM_SUCCESS) {
            DSS_PRINT_ERROR("Failed to modify node cluster info, errcode is %d.\n", status);
            return status;
        }
    }
    status = dss_iof_kick_all(vg_info, inst_cfg, inst_cfg->params.inst_id, host_id);
    if (status != CM_SUCCESS) {
        DSS_PRINT_ERROR(
            "Failed to kick host, curr hostid %lld, kick hostid %lld.\n", inst_cfg->params.inst_id, host_id);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

/*
 * 1. get vg entry info
 * 2. get vg non entry info without lock, then kick
 * 3. get vg non entry info with lock, then kick
 */
status_t dss_kickh_core(const char *home, int64 host_id)
{
#ifndef WIN32
    dss_config_t inst_cfg;
    dss_vg_info_t *vg_info = NULL;
    DSS_RETURN_IF_ERROR(dss_inq_alloc_vg_info(home, &inst_cfg, &vg_info));

    status_t status = dss_kickh_inner(vg_info, &inst_cfg, host_id, CM_FALSE);
    if (status != CM_SUCCESS) {
        dss_inq_free_vg_info(vg_info);
        DSS_PRINT_ERROR("Failed to kickh without lock.\n");
        return CM_ERROR;
    }

    status = dss_clean_vg_lock(home, host_id);
    if (status != CM_SUCCESS) {
        dss_inq_free_vg_info(vg_info);
        DSS_PRINT_ERROR("Failed to clean when kickh.\n");
        return CM_ERROR;
    }

    status = dss_kickh_inner(vg_info, &inst_cfg, host_id, CM_TRUE);
    dss_inq_free_vg_info(vg_info);
    if (status != CM_SUCCESS) {
        DSS_PRINT_ERROR("Failed to kickh with lock.\n");
        return status;
    }
    LOG_RUN_INF("Succeed to kick host, kickid %lld.", host_id);
#endif
    return CM_SUCCESS;
}

#ifdef __cplusplus
}
#endif
