/*
 * Copyright (c) 2024 Huawei Technologies Co.,Ltd.
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
 * dss_redo_recovery.c
 *
 *
 * IDENTIFICATION
 *    src/common/persist/dss_redo_recovery.c
 *
 * -------------------------------------------------------------------------
 */

#include "cm_debug.h"
#include "dss_ga.h"
#include "cm_hash.h"
#include "dss_defs.h"
#include "dss_errno.h"
#include "dss_file.h"
#include "dss_malloc.h"
#include "dss_redo.h"
#include "dss_fs_aux.h"
#include "dss_syn_meta.h"

static status_t dss_recover_core_ctrlinfo(dss_vg_info_item_t *vg_item)
{
    status_t status;
    uint32 checksum;
    bool32 remote = CM_FALSE;
    status = dss_load_vg_ctrl_part(
        vg_item, (int64)DSS_CTRL_CORE_OFFSET, &vg_item->dss_ctrl->core, (int32)DSS_CORE_CTRL_SIZE, &remote);
    DSS_RETURN_IFERR2(status, LOG_RUN_ERR("Load dss ctrl core failed."));
    checksum = dss_get_checksum(&vg_item->dss_ctrl->core, DSS_CORE_CTRL_SIZE);
    if (checksum != vg_item->dss_ctrl->core.checksum) {
        LOG_RUN_INF("Try recover dss ctrl core.");
        status = dss_load_vg_ctrl_part(
            vg_item, (int64)DSS_CTRL_BAK_CORE_OFFSET, &vg_item->dss_ctrl->core, (int32)DSS_CORE_CTRL_SIZE, &remote);
        DSS_RETURN_IFERR2(status, LOG_RUN_ERR("Load dss ctrl bak core failed."));
        checksum = dss_get_checksum(&vg_item->dss_ctrl->core, DSS_CORE_CTRL_SIZE);
        dss_check_checksum(checksum, vg_item->dss_ctrl->core.checksum);
        status =
            dss_write_ctrl_to_disk(vg_item, (int64)DSS_CTRL_CORE_OFFSET, &vg_item->dss_ctrl->core, DSS_CORE_CTRL_SIZE);
        DSS_RETURN_IFERR2(status, LOG_RUN_ERR("Write dss ctrl core failed."));
    } else {
        status = dss_write_ctrl_to_disk(
            vg_item, (int64)DSS_CTRL_BAK_CORE_OFFSET, &vg_item->dss_ctrl->core, DSS_CORE_CTRL_SIZE);
        DSS_RETURN_IFERR2(status, LOG_RUN_ERR("Write dss ctrl bak core failed."));
    }
    return status;
}

static status_t dss_recover_volume_ctrlinfo(dss_vg_info_item_t *vg_item)
{
    status_t status;
    uint32 checksum;
    bool32 remote = CM_FALSE;
    dss_volume_ctrl_t *volume = (dss_volume_ctrl_t *)cm_malloc_align(DSS_ALIGN_SIZE, DSS_VOLUME_CTRL_SIZE);
    if (volume == NULL) {
        DSS_RETURN_IFERR2(CM_ERROR, LOG_RUN_ERR("Can not allocate memory in stack."));
    }
    status =
        dss_load_vg_ctrl_part(vg_item, (int64)DSS_CTRL_VOLUME_OFFSET, volume, (int32)DSS_VOLUME_CTRL_SIZE, &remote);
    DSS_RETURN_IFERR3(status, DSS_FREE_POINT(volume), LOG_RUN_ERR("Load dss ctrl volume failed."));
    checksum = dss_get_checksum(volume, DSS_VOLUME_CTRL_SIZE);
    if (checksum != volume->checksum) {
        LOG_RUN_INF("Try recover dss ctrl volume.");
        status = dss_load_vg_ctrl_part(
            vg_item, (int64)DSS_CTRL_BAK_VOLUME_OFFSET, volume, (int32)DSS_VOLUME_CTRL_SIZE, &remote);
        DSS_RETURN_IFERR3(status, DSS_FREE_POINT(volume), LOG_RUN_ERR("Load dss ctrl bak volume failed."));
        checksum = dss_get_checksum(volume, DSS_VOLUME_CTRL_SIZE);
        dss_check_checksum(checksum, volume->checksum);
        status = dss_write_ctrl_to_disk(vg_item, (int64)DSS_CTRL_VOLUME_OFFSET, volume, DSS_VOLUME_CTRL_SIZE);
        DSS_RETURN_IFERR3(status, DSS_FREE_POINT(volume), LOG_RUN_ERR("Write dss ctrl volume failed."));
    } else {
        status = dss_write_ctrl_to_disk(vg_item, (int64)DSS_CTRL_BAK_VOLUME_OFFSET, volume, DSS_VOLUME_CTRL_SIZE);
        DSS_RETURN_IFERR3(status, DSS_FREE_POINT(volume), LOG_RUN_ERR("Write dss ctrl bak volume failed."));
    }
    status = dss_init_volume(vg_item, volume);
    if (status == CM_SUCCESS) {  // - redundant?
        vg_item->dss_ctrl->volume.checksum = volume->checksum;
        vg_item->dss_ctrl->volume.version = volume->version;
    }
    DSS_FREE_POINT(volume);
    return status;
}

static status_t dss_recover_root_ft_ctrlinfo(dss_vg_info_item_t *vg_item)
{
    status_t status;
    uint32 checksum;
    bool32 remote = CM_FALSE;
    dss_common_block_t *block = (dss_common_block_t *)vg_item->dss_ctrl->root;
    status = dss_load_vg_ctrl_part(vg_item, (int64)DSS_CTRL_ROOT_OFFSET, block, (int32)DSS_BLOCK_SIZE, &remote);
    DSS_RETURN_IFERR2(status, LOG_RUN_ERR("Load dss ctrl root failed."));
    checksum = dss_get_checksum(block, DSS_BLOCK_SIZE);
    if (checksum != block->checksum) {
        LOG_RUN_INF("Try recover dss ctrl root.");
        status = dss_load_vg_ctrl_part(vg_item, (int64)DSS_CTRL_BAK_ROOT_OFFSET, block, (int32)DSS_BLOCK_SIZE, &remote);
        DSS_RETURN_IFERR2(status, LOG_RUN_ERR("Load dss ctrl bak root failed."));
        checksum = dss_get_checksum(block, DSS_BLOCK_SIZE);
        dss_check_checksum(checksum, block->checksum);
        status = dss_write_ctrl_to_disk(vg_item, (int64)DSS_CTRL_ROOT_OFFSET, block, DSS_BLOCK_SIZE);
        DSS_RETURN_IFERR2(status, LOG_RUN_ERR("Write dss ctrl root failed."));
    } else {
        status = dss_write_ctrl_to_disk(vg_item, (int64)DSS_CTRL_BAK_ROOT_OFFSET, block, DSS_BLOCK_SIZE);
        DSS_RETURN_IFERR2(status, LOG_RUN_ERR("Write dss ctrl bak root failed."));
    }
    return status;
}
static status_t dss_recover_redo_ctrlinfo(dss_vg_info_item_t *vg_item)
{
    status_t status;
    uint32 checksum;
    bool32 remote = CM_FALSE;
    status = dss_load_vg_ctrl_part(
        vg_item, (int64)DSS_CTRL_REDO_OFFSET, &vg_item->dss_ctrl->redo_ctrl, (int32)DSS_DISK_UNIT_SIZE, &remote);
    DSS_RETURN_IFERR2(status, LOG_DEBUG_ERR("Load dss redo ctrl failed."));
    checksum = dss_get_checksum(&vg_item->dss_ctrl->redo_ctrl, DSS_DISK_UNIT_SIZE);
    if (checksum != vg_item->dss_ctrl->redo_ctrl.checksum) {
        LOG_RUN_INF("Try recover dss redo ctrl.");
        status = dss_load_vg_ctrl_part(vg_item, (int64)DSS_CTRL_BAK_REDO_OFFSET, &vg_item->dss_ctrl->redo_ctrl,
            (int32)DSS_DISK_UNIT_SIZE, &remote);
        DSS_RETURN_IFERR2(status, LOG_DEBUG_ERR("Load dss redo ctrl bak failed."));
        checksum = dss_get_checksum(&vg_item->dss_ctrl->redo_ctrl, DSS_DISK_UNIT_SIZE);
        dss_check_checksum(checksum, vg_item->dss_ctrl->redo_ctrl.checksum);
        status = dss_write_ctrl_to_disk(
            vg_item, (int64)DSS_CTRL_REDO_OFFSET, &vg_item->dss_ctrl->redo_ctrl, DSS_DISK_UNIT_SIZE);
        DSS_RETURN_IFERR2(status, LOG_DEBUG_ERR("Write dss redo ctrl failed."));
    } else {
        status = dss_write_ctrl_to_disk(
            vg_item, (int64)DSS_CTRL_BAK_REDO_OFFSET, &vg_item->dss_ctrl->redo_ctrl, DSS_DISK_UNIT_SIZE);
        DSS_RETURN_IFERR2(status, LOG_DEBUG_ERR("Write dss redo ctrl bak failed."));
    }
    return status;
}

static status_t dss_recover_volume_head(dss_vg_info_item_t *vg_item, uint32 id)
{
#ifndef WIN32
    char buf[DSS_DISK_UNIT_SIZE] __attribute__((__aligned__(DSS_ALIGN_SIZE)));
#else
    char buf[DSS_DISK_UNIT_SIZE];
#endif
    dss_volume_header_t *vol_head = (dss_volume_header_t *)buf;
    CM_RETURN_IFERR(
        dss_open_volume(vg_item->dss_ctrl->volume.defs[id].name, NULL, DSS_CLI_OPEN_FLAG, &vg_item->volume_handle[id]));
    status_t ret = dss_read_volume(&vg_item->volume_handle[id], 0, vol_head, DSS_DISK_UNIT_SIZE);
    if (ret != CM_SUCCESS) {
        dss_close_volume(&vg_item->volume_handle[id]);
        return ret;
    }
    if (vol_head->valid_flag != DSS_CTRL_VALID_FLAG) {
        dss_close_volume(&vg_item->volume_handle[id]);
        return CM_SUCCESS;
    }
    vol_head->valid_flag = 0;
    ret = dss_write_volume(&vg_item->volume_handle[id], 0, vol_head, DSS_DISK_UNIT_SIZE);
    dss_close_volume(&vg_item->volume_handle[id]);
    return ret;
}

static status_t dss_recover_volume_size(dss_vg_info_item_t *vg_item, uint64 id)
{
    CM_RETURN_IFERR(
        dss_open_volume(vg_item->dss_ctrl->volume.defs[id].name, NULL, DSS_CLI_OPEN_FLAG, &vg_item->volume_handle[id]));
    uint64 old_size = dss_get_volume_size(&vg_item->volume_handle[id]);
    dss_close_volume(&vg_item->volume_handle[id]);
    if (old_size == DSS_INVALID_64) {
        return CM_ERROR;
    }
    vg_item->dss_ctrl->core.volume_attrs[id].size = old_size;
    vg_item->dss_ctrl->core.volume_attrs[id].free = old_size - vg_item->dss_ctrl->core.volume_attrs[id].hwm;
    return CM_SUCCESS;
}

static status_t dss_recover_modify_info(dss_vg_info_item_t *vg_item)
{
    uint32 volume_count = 0;
    bool32 is_update_ctrl = CM_FALSE;
    for (uint32 i = 0; i < DSS_MAX_VOLUMES; i++) {
        if (vg_item->dss_ctrl->volume.defs[i].flag == VOLUME_FREE) {
            continue;
        }
        if (vg_item->dss_ctrl->volume.defs[i].flag != VOLUME_ADD) {
            volume_count++;
        }
        is_update_ctrl = CM_TRUE;
        if (vg_item->dss_ctrl->volume.defs[i].flag == VOLUME_ADD) {
            vg_item->dss_ctrl->volume.defs[i].flag = VOLUME_FREE;
            // The volume has been flushed to disk, but core_ctrl has not been flushed to disk.
            if (vg_item->dss_ctrl->volume.defs[i].id != vg_item->dss_ctrl->core.volume_attrs[i].id) {
                continue;
            }
            DSS_RETURN_IF_ERROR(dss_recover_volume_head(vg_item, vg_item->dss_ctrl->volume.defs[i].id));
            vg_item->dss_ctrl->core.volume_attrs[i].id = 0;
            vg_item->dss_ctrl->volume.defs[i].id = 0;
        } else if (vg_item->dss_ctrl->volume.defs[i].flag == VOLUME_REMOVE) {
            vg_item->dss_ctrl->volume.defs[i].flag = VOLUME_OCCUPY;
            // The core_ctrl has been flushed to disk, but volume has not been flushed to disk.
            if (vg_item->dss_ctrl->volume.defs[i].id != vg_item->dss_ctrl->core.volume_attrs[i].id) {
                vg_item->dss_ctrl->core.volume_attrs[i].id = vg_item->dss_ctrl->volume.defs[i].id;
            }
        } else if (vg_item->dss_ctrl->volume.defs[i].flag == VOLUME_REPLACE) {
            vg_item->dss_ctrl->volume.defs[i].flag = VOLUME_OCCUPY;
            if (i == 0) {
                continue;
            }
            DSS_RETURN_IF_ERROR(dss_recover_volume_size(vg_item, vg_item->dss_ctrl->volume.defs[i].id));
        }
    }

    if (!is_update_ctrl) {
        return CM_SUCCESS;
    }
    vg_item->dss_ctrl->core.volume_count = volume_count;
    DSS_RETURN_IF_ERROR(dss_update_core_ctrl_disk(vg_item));
    return dss_update_volume_ctrl(vg_item);
}

/*
 * Check and recover dss ctrl info from backup area, including core ctrl, volume ctrl and root FTB ctrl.
 * Ctrl info that doesn't need recovery must be backed up.
 * Bug note 08272021: ctrl info that is recovered must be synced. Otherwise checksum would fail supposedly.
 * In standby cluster, xlog vg is copy from primary cluster,
 * we do not need to recover ctrlinfo in standby cluster before it promote
 */
status_t dss_recover_ctrlinfo(dss_vg_info_item_t *vg_item)
{
    if (DSS_STANDBY_CLUSTER_XLOG_VG(vg_item->id)) {
        return CM_SUCCESS;
    }
    DSS_RETURN_IF_ERROR(dss_recover_core_ctrlinfo(vg_item));
    DSS_RETURN_IF_ERROR(dss_recover_volume_ctrlinfo(vg_item));
    DSS_RETURN_IF_ERROR(dss_recover_root_ft_ctrlinfo(vg_item));
    uint32 software_version = dss_get_software_version(&vg_item->dss_ctrl->vg_info);
    if (software_version >= DSS_SOFTWARE_VERSION_2) {
        DSS_RETURN_IF_ERROR(dss_recover_redo_ctrlinfo(vg_item));
    }
    return dss_recover_modify_info(vg_item);
}

bool32 dss_check_redo_batch_complete(dss_redo_batch_t *batch, dss_redo_batch_t *tail, bool32 check_hash)
{
    if (batch->size <= DSS_REDO_BATCH_HEAD_SIZE || batch->size > DSS_VG_LOG_SPLIT_SIZE) {
        LOG_RUN_INF("Invalid size %u of redo log.", batch->size);
        return CM_FALSE;
    }
    if (batch->size != tail->size) {
        LOG_RUN_INF("Batch head data size is not the same with tail, batch head is %u, batch tail is %u.", batch->size,
            tail->size);
        return CM_FALSE;
    }
    if (batch->time != tail->time) {
        LOG_RUN_INF("Batch head time is not the same with tail, batch head is %lld, batch tail is %lld.", batch->time,
            tail->time);
        return CM_FALSE;
    }
    uint32 data_size = batch->size - DSS_REDO_BATCH_HEAD_SIZE;
    uint32 hash_code = cm_hash_bytes((uint8 *)batch->data, data_size, INFINITE_HASH_RANGE);
    if (check_hash && batch->hash_code != hash_code) {
        LOG_RUN_INF("Batch head hash code is not the same with data, batch head is %u, data is %u.", batch->hash_code,
            hash_code);
        return CM_FALSE;
    }
    if (batch->hash_code != tail->hash_code) {
        LOG_RUN_INF("Batch head hash code is not the same with tail, batch head is %u, batch tail is %u.",
            batch->hash_code, tail->hash_code);
        return CM_FALSE;
    }
    return CM_TRUE;
}

status_t dss_read_redolog_from_disk(dss_vg_info_item_t *vg_item, uint32 volume_id, int64 offset, char *buf, int32 size)
{
    CM_ASSERT(vg_item != NULL);
    CM_ASSERT(buf != NULL);
    status_t status;
    bool32 remote_chksum = CM_FALSE;
    if (vg_item->volume_handle[volume_id].handle != DSS_INVALID_HANDLE) {
        return dss_read_volume_inst(vg_item, &vg_item->volume_handle[volume_id], offset, buf, size, &remote_chksum);
    }
    status = dss_open_volume(vg_item->dss_ctrl->volume.defs[volume_id].name, NULL, DSS_INSTANCE_OPEN_FLAG,
        &vg_item->volume_handle[volume_id]);
    if (status != CM_SUCCESS) {
        return status;
    }
    status = dss_read_volume_inst(vg_item, &vg_item->volume_handle[volume_id], offset, buf, size, &remote_chksum);
    if (status != CM_SUCCESS) {
        LOG_RUN_ERR("Failed to read redo file, offset:%lld, size:%d.", offset, size);
        return status;
    }
    return CM_SUCCESS;
}

status_t dss_load_log_buffer_from_slot(dss_vg_info_item_t *vg_item, bool8 *need_recovery)
{
    dss_vg_info_item_t *first_vg_item = dss_get_first_vg_item();
    LOG_RUN_INF("[RECOVERY]Try to load log buf from first vg %s.", first_vg_item->vg_name);
    uint64 redo_start = dss_get_redo_log_v0_start(first_vg_item->dss_ctrl, vg_item->id);
    char *log_buf = vg_item->log_file_ctrl.log_buf;
    status_t status =
        dss_read_redolog_from_disk(first_vg_item, 0, (int64)redo_start, log_buf, (int32)DSS_DISK_UNIT_SIZE);
    DSS_RETURN_IFERR2(
        status, LOG_RUN_ERR("[RECOVERY]Failed to load log_buf from vg:%s when recover.", vg_item->vg_name));
    dss_redo_batch_t *batch = (dss_redo_batch_t *)log_buf;
    if (batch->size == 0) {
        LOG_RUN_INF("[RECOVERY]size of redo log is 0, vg id is %u, ignore.", vg_item->id);
        return CM_SUCCESS;
    }
    uint64 load_size = (uint64)(CM_CALC_ALIGN(batch->size + sizeof(dss_redo_batch_t), DSS_DISK_UNIT_SIZE));
    if (load_size > DSS_INSTANCE_LOG_SPLIT_SIZE) {
        // invalid log ,ignored it.
        LOG_RUN_INF("[RECOVERY]Redo log slot from vg:%s is invalid, ignored it. size is %llu, which is greater than %u",
            vg_item->vg_name, load_size, DSS_INSTANCE_LOG_SPLIT_SIZE);
        (void)dss_reset_log_slot_head(vg_item->id, log_buf);
        return CM_SUCCESS;
    }
    if (load_size > DSS_DISK_UNIT_SIZE) {
        status = dss_read_redolog_from_disk(first_vg_item, 0, (int64)redo_start, log_buf, (int32)load_size);
        DSS_RETURN_IFERR2(
            status, LOG_RUN_ERR("[RECOVERY]Failed to load log_buf from vg:%s when recover.", vg_item->vg_name));
    }
    dss_redo_batch_t *tail = (dss_redo_batch_t *)((char *)batch + load_size - sizeof(dss_redo_batch_t));
    if (!dss_check_redo_batch_complete(batch, tail, CM_TRUE)) {
        LOG_RUN_INF("[RECOVERY]No complete redo log.");
        (void)dss_reset_log_slot_head(vg_item->id, log_buf);
        return CM_SUCCESS;
    }
    *need_recovery = CM_TRUE;
    return status;
}

status_t dss_load_log_buffer_from_offset(dss_vg_info_item_t *vg_item, bool8 *need_recovery)
{
    dss_ctrl_t *dss_ctrl = vg_item->dss_ctrl;
    dss_redo_ctrl_t *redo_ctrl = &dss_ctrl->redo_ctrl;
    uint32 redo_index = redo_ctrl->redo_index;
    auid_t redo_au = redo_ctrl->redo_start_au[redo_index];
    uint64 redo_size = (uint64)redo_ctrl->redo_size[redo_index];
    uint32 count = redo_ctrl->count;
    uint64 log_start = dss_get_vg_au_size(dss_ctrl) * redo_au.au;
    uint64 offset = redo_ctrl->offset;
    uint64 log_offset = log_start + offset;
    dss_log_file_ctrl_t *log_ctrl = &vg_item->log_file_ctrl;
    char *log_buf = log_ctrl->log_buf;
    status_t status;
    LOG_RUN_INF("[RECOVERY]begin to load log buf of vg %s, redo au:%s, start: %llu, offset:%llu, size:%u.",
        vg_item->vg_name, dss_display_metaid(redo_au), log_start, offset, DSS_DISK_UNIT_SIZE);
    status = dss_read_redolog_from_disk(vg_item, redo_au.volume, (int64)log_offset, log_buf, (int32)DSS_DISK_UNIT_SIZE);
    DSS_RETURN_IFERR2(
        status, LOG_RUN_ERR("[RECOVERY]Failed to load log_buf from vg:%s when recover.", vg_item->vg_name));
    dss_redo_batch_t *batch = (dss_redo_batch_t *)log_buf;
    if (batch->size == 0) {
        LOG_RUN_INF("[RECOVERY]No redo log need to recover.");
        return CM_SUCCESS;
    }
    uint64 load_size = (uint64)(CM_CALC_ALIGN(batch->size + sizeof(dss_redo_batch_t), DSS_DISK_UNIT_SIZE));
    if (load_size > DSS_VG_LOG_SPLIT_SIZE) {
        // invalid log ,ignored it.
        LOG_RUN_INF(
            "[RECOVERY]Redo log from offset %llu is invalid, ignored it. size is %llu, which is greater than %u",
            log_offset, load_size, DSS_VG_LOG_SPLIT_SIZE);
        return CM_SUCCESS;
    }
    log_ctrl->index = redo_index;
    log_ctrl->offset = offset + load_size;
    if (load_size > DSS_DISK_UNIT_SIZE) {
        if (offset + load_size > redo_size) {
            uint64 load_size_2 = (load_size + offset) % redo_size;
            uint64 load_size_1 = load_size - load_size_2;
            status =
                dss_read_redolog_from_disk(vg_item, redo_au.volume, (int64)log_offset, log_buf, (int32)load_size_1);
            DSS_RETURN_IFERR2(status, LOG_RUN_ERR("[RECOVERY]Failed to load redo log."));
            auid_t redo_au_next;
            if (redo_index == count - 1) {
                redo_au_next = redo_ctrl->redo_start_au[0];
                log_ctrl->index = 0;
            } else {
                redo_au_next = redo_ctrl->redo_start_au[redo_index + 1];
                log_ctrl->index = redo_index + 1;
            }
            uint64 log_start_next = dss_get_vg_au_size(dss_ctrl) * redo_au_next.au;
            status = dss_read_redolog_from_disk(
                vg_item, redo_au_next.volume, (int64)log_start_next, log_buf + load_size_1, (int32)load_size_2);
            DSS_RETURN_IFERR2(status, LOG_RUN_ERR("[RECOVERY]Failed to load redo log."));
            log_ctrl->offset = load_size_2;
        } else {
            status = dss_read_redolog_from_disk(vg_item, redo_au.volume, (int64)log_offset, log_buf, (int32)load_size);
            DSS_RETURN_IFERR2(status, LOG_RUN_ERR("[RECOVERY]Failed to load redo log."));
            if (offset + load_size == redo_size) {
                log_ctrl->index = (redo_index == count - 1) ? 0 : redo_index + 1;
                log_ctrl->offset = 0;
            }
        }
    }
    // batch_head|entry1|entry2|reserve|batch_tail
    dss_redo_batch_t *tail = (dss_redo_batch_t *)((char *)batch + load_size - sizeof(dss_redo_batch_t));
    if (!dss_check_redo_batch_complete(batch, tail, CM_TRUE)) {
        LOG_RUN_INF("[RECOVERY]No complete redo log.");
        return CM_SUCCESS;
    }
    if (batch->lsn <= redo_ctrl->lsn) {
        LOG_RUN_INF("[RECOVERY]history redo batch lsn %llu is not greater than current lsn %llu, no need to replay.",
            batch->lsn, redo_ctrl->lsn);
        return CM_SUCCESS;
    }
    if (redo_ctrl->lsn + 1 != batch->lsn) {
        LOG_RUN_INF("[RECOVERY]history redo batch lsn %llu is not one more than current lsn %llu, no need to replay.",
            batch->lsn, redo_ctrl->lsn);
        return CM_SUCCESS;
    }
    log_ctrl->lsn = batch->lsn;
    *need_recovery = CM_TRUE;
    return CM_SUCCESS;
}

status_t dss_check_recover_redo_log(dss_vg_info_item_t *vg_item, bool8 *recover_redo)
{
    char *log_buf = NULL;
    if (!dss_is_server()) {
        log_buf = (char *)cm_malloc_align(DSS_ALIGN_SIZE, DSS_VG_LOG_SPLIT_SIZE);
        if (log_buf == NULL) {
            DSS_RETURN_IFERR2(CM_ERROR, DSS_THROW_ERROR(ERR_ALLOC_MEMORY, DSS_VG_LOG_SPLIT_SIZE, "log buffer"));
        }
        vg_item->log_file_ctrl.log_buf = log_buf;
    }
    uint32 software_version = dss_get_software_version(&vg_item->dss_ctrl->vg_info);
    status_t status;
    if (software_version < DSS_SOFTWARE_VERSION_2) {
        status = dss_load_log_buffer_from_slot(vg_item, recover_redo);
    } else {
        status = dss_load_log_buffer_from_offset(vg_item, recover_redo);
    }
    if (!dss_is_server()) {
        DSS_FREE_POINT(log_buf);
    }
    return status;
}

void dss_set_vg_status_recovery()
{
    for (uint32 i = 0; i < g_vgs_info->group_num; i++) {
        g_vgs_info->volume_group[i].status = DSS_VG_STATUS_RECOVERY;
    }
}

void dss_set_vg_status_open()
{
    for (uint32 i = 0; i < g_vgs_info->group_num; i++) {
        g_vgs_info->volume_group[i].status = DSS_VG_STATUS_OPEN;
    }
}

status_t dss_recover_from_slot_inner(dss_session_t *session, dss_vg_info_item_t *vg_item, char *log_buf)
{
    LOG_RUN_INF("[RECOVERY]Set vg status recovery.");
    dss_set_vg_status_recovery();
    LOG_RUN_INF("[RECOVERY]Begin recovering.");
    status_t status = dss_apply_log(session, vg_item, log_buf);
    if (status != CM_SUCCESS) {
        LOG_RUN_ERR("[RECOVERY]Failed to do recovery.");
        return status;
    }
    (void)dss_reset_log_slot_head(vg_item->id, log_buf);
    dss_set_vg_status_open();
    LOG_RUN_INF("[RECOVERY]Succeed to recovery.");
    return CM_SUCCESS;
}
status_t dss_recover_from_offset_inner(dss_session_t *session, dss_vg_info_item_t *vg_item, char *log_buf)
{
    LOG_RUN_INF("[RECOVERY]Set vg status recovery.");
    dss_set_vg_status_recovery();
    LOG_RUN_INF("[RECOVERY]Begin recovering.");
    status_t status = dss_apply_log(session, vg_item, log_buf);
    if (status != CM_SUCCESS) {
        LOG_RUN_ERR("[RECOVERY]Failed to do recovery.");
        return status;
    }
    status = dss_update_redo_info(vg_item, log_buf);
    if (status != CM_SUCCESS) {
        LOG_RUN_ERR("[RECOVERY]Failed to update redo info.");
        return CM_ERROR;
    }
    dss_set_vg_status_open();
    LOG_RUN_INF("[RECOVERY]Succeed to recovery.");
    return CM_SUCCESS;
}
