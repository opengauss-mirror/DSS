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
#include "dss_io_fence.h"
#include "dsscmd_inq.h"

#ifdef __cplusplus
extern "C" {
#endif

static void print_dev_info(ptlist_t *devs)
{
    printf("%-20s%-20s%-20s%-20s%-15s%-20s\n", "Dev", "Vendor", "Model", "ArraySN", "LUNID", "LUNWWN");

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
            printf("%-20s%-20s%-20s%-20s%-15d%-20s\n", dev_info->dev, dev_info->data.vendor_info.vendor,
                dev_info->data.vendor_info.product, dev_info->data.array_info.array_sn, dev_info->data.lun_info.lun_id,
                dev_info->data.lun_info.lun_wwn);
        }
    }
}

#define DSS_MAX_REKEY_BUFF (DSS_MAX_INSTANCES * 4)
static void print_reg_info_rely_resk(int64 resk)
{
    if (resk > 0) {
        printf("%-20lld", resk - 1);
    } else {
        printf("%-20c", '-');
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
            cm_concat_int32(&text, DSS_MAX_REKEY_BUFF, (uint32)(reg_info->reg_keys[j] - 1));
            if (j + 1 < reg_info->key_count) {
                (void)cm_concat_string(&text, DSS_MAX_REKEY_BUFF, ",");
            }
        }
        printf("%-20s\n", text.str);
    } else {
        printf("%-20c\n", '-');
    }
}

static void print_reg_info(ptlist_t *regs)
{
    printf("%-20s%-20s%-20s%-20s\n", "Dev", "Generation", "RESKEY", "REGKEY");

    uint32 i;
    iof_reg_in_t *reg_info = NULL;

    for (i = 0; i < regs->count; i++) {
        reg_info = (iof_reg_in_t *)cm_ptlist_get(regs, i);
        if (reg_info != NULL) {
            printf("%-20s%-20u", reg_info->dev, reg_info->generation);
            print_reg_info_rely_resk(reg_info->resk);
            print_reg_info_rely_key_count(reg_info);
        }
    }
}

status_t inq_lun(void)
{
    status_t status;
    ptlist_t devlist;

    cm_ptlist_init(&devlist);
    status = dss_inquiry_luns(&devlist, DSS_FALSE);
    if (status != CM_SUCCESS) {
        cm_destroy_ptlist(&devlist);
        return status;
    }
    print_dev_info(&devlist);
    cm_destroy_ptlist(&devlist);

    return CM_SUCCESS;
}

status_t inq_regs(void)
{
    status_t status;
    ptlist_t reg_info;

    cm_ptlist_init(&reg_info);
    status = dss_iof_inql_regs(&reg_info, DSS_FALSE);
    if (status != CM_SUCCESS) {
        cm_destroy_ptlist(&reg_info);
        return status;
    }

    print_reg_info(&reg_info);
    cm_destroy_ptlist(&reg_info);

    return CM_SUCCESS;
}

bool32 is_register(iof_reg_in_t *reg, int64 host_id, int64 *iofence_key)
{
    for (int32 i = 0; i < reg->key_count; i++) {
        iofence_key[reg->reg_keys[i] - 1]++;
    }
    for (int32 i = 0; i < reg->key_count; i++) {
        if (reg->reg_keys[i] == host_id + 1) {
            return DSS_TRUE;
        }
    }
    return DSS_FALSE;
}

// get the non-entry disk information of vg.
static status_t dss_get_vg_non_entry_info(dss_config_t *inst_cfg, dss_vg_info_item_t *vg_item)
{
    if (vg_item->vg_name[0] == '0' || vg_item->entry_path[0] == '0') {
        LOG_DEBUG_ERR("Failed to load vg ctrl, input parameter is invalid.");
        return CM_ERROR;
    }

    if (dss_lock_vg_storage(vg_item, vg_item->entry_path, inst_cfg) != CM_SUCCESS) {
        LOG_DEBUG_ERR("Failed to lock vg:%s.", vg_item->entry_path);
        return CM_ERROR;
    }

    bool32 remote = CM_FALSE;
    status_t status = dss_load_vg_ctrl_part(vg_item, 0, vg_item->dss_ctrl, (int32)sizeof(dss_ctrl_t), &remote);
    if (status != CM_SUCCESS) {
        dss_unlock_vg_storage(vg_item, vg_item->entry_path, inst_cfg);
        LOG_DEBUG_ERR("Failed to load vg ctrl part %s.", vg_item->entry_path);
        return status;
    }

    dss_unlock_vg_storage(vg_item, vg_item->entry_path, inst_cfg);

    if (!DSS_VG_IS_VALID(vg_item->dss_ctrl)) {
        DSS_THROW_ERROR(ERR_DSS_VG_CHECK_NOT_INIT);
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

static status_t dss_init_vg_info(dss_vg_info_t *vg_info)
{
    uint32 len = DSS_MAX_STACK_BUF_SIZE + DSS_MAX_STACK_BUF_SIZE + DSS_MAX_STACK_BUF_SIZE + sizeof(dss_ctrl_t);
    char *buf = (char *)cm_malloc_align(DSS_ALIGN_SIZE, vg_info->group_num * len);
    bool32 result = (bool32)(buf != NULL);
    DSS_RETURN_IF_FALSE2(
        result, LOG_DEBUG_ERR("cm_malloc_align stack failed, align size:%u, size:%u.", DSS_ALIGN_SIZE, len));

    for (uint32 i = 0; i < vg_info->group_num; i++) {
        vg_info->volume_group[i].buffer_cache = (shm_hashmap_t *)(buf + i * len);
        vg_info->volume_group[i].vg_latch = (latch_t *)(buf + i * len + DSS_MAX_STACK_BUF_SIZE);
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

// get the entry disk information of vg from config.
static status_t dss_get_vg_entry_info(const char *home, dss_config_t *inst_cfg, dss_vg_info_t *vg_info)
{
    status_t status = dss_set_cfg_dir(home, inst_cfg);
    DSS_RETURN_IFERR2(status, LOG_DEBUG_ERR("Environment variant DSS_HOME not found."));
    status = dss_load_vg_conf_inner(vg_info, inst_cfg);
    DSS_RETURN_IFERR2(status, LOG_DEBUG_ERR("Failed to load vg conf inner."));
    return dss_init_vg_info(vg_info);
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
        LOG_DEBUG_ERR("Inquiry reg info for entry path dev failed, dev %s.", reg_info.dev);
        return CM_ERROR;
    }
    if (!is_register(&reg_info, host_id, iofence_key)) {
        *is_reg = DSS_FALSE;
    }

    return CM_SUCCESS;
}

static status_t dss_reghl_inner(dss_vg_info_item_t *item, int64 host_id)
{
    for (uint32 j = 1; j < DSS_MAX_VOLUMES; j++) {
        if (item->dss_ctrl->core.volume_attrs[j].flag == VOLUME_FREE) {
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
    } else {
        (void)printf("iofence_key=%-20s\n", text.str);
    }
}

/*
 * 1. get vg entry info
 * 2. register vg entry disk
 * 3. get vg non entry info
 * 4. register vg non entry disk
 */
status_t dss_reghl_core(const char *home, int64 host_id, dss_vg_info_t *vg_info)
{
#ifndef WIN32
    dss_config_t inst_cfg;
    status_t status = dss_get_vg_entry_info(home, &inst_cfg, vg_info);
    DSS_RETURN_IFERR2(status, DSS_PRINT_ERROR("Failed to get vg entry info when reghl, errcode is %d.\n", status));

    for (uint32 i = 0; i < vg_info->group_num; i++) {
        status = dss_iof_register_single(host_id, vg_info->volume_group[i].entry_path);
        if (status != CM_SUCCESS) {
            DSS_FREE_POINT(vg_info->volume_group[0].buffer_cache);
            DSS_PRINT_ERROR("Failed to register vg entry disk when reghl, errcode is %d.\n", status);
            return status;
        }
        status = dss_get_vg_non_entry_info(&inst_cfg, &vg_info->volume_group[i]);
        if (status != CM_SUCCESS) {
            DSS_FREE_POINT(vg_info->volume_group[0].buffer_cache);
            DSS_PRINT_ERROR("Failed to get vg non entry info when reghl, errcode is %d.\n", status);
            return status;
        }
        status = dss_reghl_inner(&vg_info->volume_group[i], host_id);
        if (status != CM_SUCCESS) {
            DSS_FREE_POINT(vg_info->volume_group[0].buffer_cache);
            DSS_PRINT_ERROR("Failed to reghl, errcode is %d.\n", status);
            return status;
        }
    }
    DSS_FREE_POINT(vg_info->volume_group[0].buffer_cache);
#endif
    return CM_SUCCESS;
}

static status_t dss_unreghl_inner(dss_vg_info_item_t *item, int64 host_id)
{
    for (uint32 j = 1; j < DSS_MAX_VOLUMES; j++) {
        if (item->dss_ctrl->core.volume_attrs[j].flag == VOLUME_FREE) {
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
status_t dss_unreghl_core(const char *home, int64 host_id, dss_vg_info_t *vg_info)
{
#ifndef WIN32
    bool32 is_reg;
    dss_config_t inst_cfg;
    int64 iofence_key[DSS_MAX_INSTANCES] = {0};
    status_t status = dss_get_vg_entry_info(home, &inst_cfg, vg_info);
    DSS_RETURN_IFERR2(status, DSS_PRINT_ERROR("Failed to get vg entry info, errcode is %d.\n", status));

    for (uint32 i = 0; i < vg_info->group_num; i++) {
        status = dss_check_volume_register(vg_info->volume_group[i].entry_path, host_id, &is_reg, iofence_key);
        if (status != CM_SUCCESS) {
            DSS_FREE_POINT(vg_info->volume_group[0].buffer_cache);
            DSS_PRINT_ERROR("Failed to check volume register when unreghl, errcode is %d.\n", status);
            return CM_ERROR;
        }
        if (!is_reg) {
            continue;
        }
        status = dss_get_vg_non_entry_info(&inst_cfg, &vg_info->volume_group[i]);
        if (status != CM_SUCCESS) {
            DSS_FREE_POINT(vg_info->volume_group[0].buffer_cache);
            DSS_PRINT_ERROR("Failed to get vg entry info when unreghl, errcode is %d.\n", status);
            return status;
        }
        status = dss_unreghl_inner(&vg_info->volume_group[i], host_id);
        if (status != CM_SUCCESS) {
            DSS_FREE_POINT(vg_info->volume_group[0].buffer_cache);
            DSS_PRINT_ERROR("Failed to unreghl, errcode is %d.\n", status);
            return status;
        }
    }
    DSS_FREE_POINT(vg_info->volume_group[0].buffer_cache);
#endif
    return CM_SUCCESS;
}

static status_t dss_inq_reg_inner(dss_vg_info_t *vg_info, dss_config_t *inst_cfg, int64 host_id, int64 *iofence_key)
{
    bool32 is_reg;
    dss_vg_info_item_t *item = NULL;
    for (uint32 i = 0; i < vg_info->group_num; i++) {
        CM_RETURN_IFERR(dss_get_vg_non_entry_info(inst_cfg, &vg_info->volume_group[i]));
        item = &vg_info->volume_group[i];
        for (uint32 j = 1; j < DSS_MAX_VOLUMES; j++) {
            if (item->dss_ctrl->core.volume_attrs[j].flag == VOLUME_FREE) {
                continue;
            }
            CM_RETURN_IFERR(dss_check_volume_register(item->dss_ctrl->volume.defs[j].name, host_id, &is_reg, iofence_key));
            if (!is_reg) {
                DSS_PRINT_INF("The node %lld is registered partially, inq_result = 1.\n", host_id);
                return CM_TIMEDOUT;
            }
        }
    }
    DSS_PRINT_INF("The node %lld is registered, inq_result = 2.\n", host_id);
    return CM_SUCCESS;
}

/*
 * 1. get vg entry info
 * 2. check vg entry disk is register. If neither is registered, return 0, else if partially registered, return 1.
 * 3. get vg non entry info
 * 4. check vg non entry disk is register. If all are registered, return 2, else return 1.
 */
status_t dss_inq_reg_core(const char *home, int64 host_id, dss_vg_info_t *vg_info)
{
#ifndef WIN32
    bool32 is_reg;
    uint32 count = 0;
    dss_config_t inst_cfg;
    int64 iofence_key[DSS_MAX_INSTANCES] = {0};
    status_t status = dss_get_vg_entry_info(home, &inst_cfg, vg_info);
    DSS_RETURN_IFERR2(status, DSS_PRINT_ERROR("Failed to get vg entry info when inq reg, errcode is %d.\n", status));

    for (uint32 i = 0; i < vg_info->group_num; i++) {
        status = dss_check_volume_register(vg_info->volume_group[i].entry_path, host_id, &is_reg, iofence_key);
        if (status != CM_SUCCESS) {
            DSS_FREE_POINT(vg_info->volume_group[0].buffer_cache);
            DSS_PRINT_ERROR("Failed to check vg entry info when inq reg, errcode is %d.\n", status);
            return CM_ERROR;
        }
        if (!is_reg) {
            count++;
        }
    }
    if (count == vg_info->group_num) {
        dss_printf_iofence_key(iofence_key);
        DSS_FREE_POINT(vg_info->volume_group[0].buffer_cache);
        DSS_PRINT_INF("The node %lld is not registered, inq_result = 0.\n", host_id);
        return CM_SUCCESS;
    }
    if (count != 0 && count != vg_info->group_num) {
        dss_printf_iofence_key(iofence_key);
        DSS_FREE_POINT(vg_info->volume_group[0].buffer_cache);
        DSS_PRINT_INF("The node %lld is registered partially, inq_result = 1.\n", host_id);
        return CM_TIMEDOUT;
    }
    status = dss_inq_reg_inner(vg_info, &inst_cfg, host_id, iofence_key);
    if (status != CM_SUCCESS) {
        DSS_FREE_POINT(vg_info->volume_group[0].buffer_cache);
        DSS_PRINT_ERROR("Failed to check vg entry info when inq reg, errcode is %d.\n", status);
        return CM_ERROR;
    }
    dss_printf_iofence_key(iofence_key);
    DSS_FREE_POINT(vg_info->volume_group[0].buffer_cache);
#endif
    return CM_PIPECLOSED;
}

#ifdef __cplusplus
}
#endif
