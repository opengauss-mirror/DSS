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
 * dss_redo.c
 *
 *
 * IDENTIFICATION
 *    src/common/persist/dss_redo.c
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
#include "dss_defs_print.h"

status_t dss_set_log_buf(const char *vg_name, dss_vg_info_item_t *vg_item)
{
    dss_ctrl_t *dss_ctrl = vg_item->dss_ctrl;
    uint64 au_size = dss_get_vg_au_size(dss_ctrl);
    LOG_DEBUG_INF("[REDO][INIT] Before init redo log. au_size:%llu, hwm:%llu, free:%llu", au_size,
        dss_ctrl->core.volume_attrs[0].hwm, dss_ctrl->core.volume_attrs[0].free);
    uint32 log_size = dss_get_log_size(au_size);
    if (dss_ctrl->core.volume_attrs[0].free < log_size) {
        DSS_RETURN_IFERR2(CM_ERROR, LOG_DEBUG_ERR("[REDO][INIT]The vg %s has no enough space for redo log.", vg_name));
    }
    auid_t auid;
    auid.au = dss_get_au_id(vg_item, dss_ctrl->core.volume_attrs[0].hwm);
    auid.volume = dss_ctrl->core.volume_attrs[0].id;
    auid.block = 0;
    auid.item = 0;
    dss_ctrl->redo_ctrl.redo_index = 0;
    dss_ctrl->redo_ctrl.count = 0;
    dss_ctrl->redo_ctrl.redo_start_au[dss_ctrl->redo_ctrl.count] = auid;
    dss_ctrl->redo_ctrl.redo_size[dss_ctrl->redo_ctrl.count] = log_size;
    dss_ctrl->redo_ctrl.count++;
    dss_ctrl->core.volume_attrs[0].hwm = dss_ctrl->core.volume_attrs[0].hwm + log_size;
    dss_ctrl->core.volume_attrs[0].free = dss_ctrl->core.volume_attrs[0].free - log_size;
    DSS_RETURN_IF_ERROR(dss_update_core_ctrl_disk(vg_item));
    DSS_RETURN_IF_ERROR(dss_update_redo_ctrl(vg_item, 0, 0, 0));
    LOG_RUN_INF("[REDO][INIT] Begin to init log slot.au_size:%llu, hwm:%llu, free:%llu", au_size,
        dss_ctrl->core.volume_attrs[0].hwm, dss_ctrl->core.volume_attrs[0].free);
    char *log_buf = (char *)cm_malloc_align(DSS_ALIGN_SIZE, DSS_VG_LOG_BUFFER_SIZE);
    if (log_buf == NULL) {
        DSS_RETURN_IFERR2(CM_ERROR, DSS_THROW_ERROR(ERR_ALLOC_MEMORY, DSS_VG_LOG_BUFFER_SIZE, "log buffer"));
    }
    errno_t rc = memset_s(log_buf, DSS_VG_LOG_BUFFER_SIZE, 0, DSS_VG_LOG_BUFFER_SIZE);
    if (rc != EOK) {
        LOG_RUN_ERR("[REDO][INIT] Init log buf head failed.");
        DSS_FREE_POINT(log_buf);
        return CM_ERROR;
    }
    uint64 offset = dss_get_vg_au_size(dss_ctrl) * auid.au;
    DSS_RETURN_IFERR3(
        dss_write_volume(&vg_item->volume_handle[0], (int64)offset, log_buf, (int32)DSS_VG_LOG_BUFFER_SIZE),
        DSS_FREE_POINT(log_buf), LOG_RUN_ERR("[REDO][INIT] Init log buf head from offset %llu failed.", offset));
    LOG_RUN_INF(
        "[REDO][INIT] Succeed to init redo log. au_size:%llu, log_size is %u, hwm:%llu, free:%llu, redo_start_au: %s",
        au_size, log_size, dss_ctrl->core.volume_attrs[0].hwm, dss_ctrl->core.volume_attrs[0].free,
        dss_display_metaid(auid));
    DSS_FREE_POINT(log_buf);
    return CM_SUCCESS;
}

status_t dss_reset_log_slot_head(uint32 vg_id, char *log_buf)
{
    CM_ASSERT(vg_id < DSS_MAX_VOLUME_GROUP_NUM);
    dss_vg_info_item_t *first_vg_item = dss_get_first_vg_item();
    uint64 redo_start = dss_get_redo_log_v0_start(first_vg_item->dss_ctrl, vg_id);
    errno_t errcode = memset_s(log_buf, DSS_DISK_UNIT_SIZE, 0, DSS_DISK_UNIT_SIZE);
    securec_check_ret(errcode);
    status_t status = dss_write_redolog_to_disk(first_vg_item, 0, (int64)redo_start, log_buf, DSS_DISK_UNIT_SIZE);
    if (status != CM_SUCCESS) {
        LOG_RUN_ERR(
            "[REDO][RESET]Failed to reset redo log, offset is %lld, size is %u.", redo_start, DSS_DISK_UNIT_SIZE);
        return status;
    }
    LOG_DEBUG_INF(
        "[REDO][RESET] Reset head of redo log, first vg is %s, actural vg id is %u, offset is %lld, size is %u.",
        first_vg_item->vg_name, vg_id, redo_start, DSS_DISK_UNIT_SIZE);
    return status;
}

char *dss_get_log_buf_from_vg(dss_session_t *session, dss_vg_info_item_t *vg_item, dss_redo_type_t type)
{
    char *log_buf = NULL;
    dss_redo_batch_t *batch = NULL;
    dss_log_file_ctrl_t *log_file_ctrl = &vg_item->log_file_ctrl;
    while (session->put_log == CM_FALSE) {
        LOG_DEBUG_INF("[REDO][ALLOC]Try to allocate redo for session %u, first type is %d\n", session->id, (int32)type);
        cm_spin_lock(&log_file_ctrl->lock, NULL);
        if (log_file_ctrl->used) {
            cm_spin_unlock(&log_file_ctrl->lock);
            cm_spin_sleep();
            continue;
        }
        log_file_ctrl->used = CM_TRUE;
        session->put_log = CM_TRUE;
        log_file_ctrl->lsn = dss_inc_redo_log_lsn(vg_item);
        cm_spin_unlock(&log_file_ctrl->lock);
        LOG_DEBUG_INF("[REDO][ALLOC]End to allocate log of vg %s for session %u.\n", vg_item->vg_name, session->id);
        batch = (dss_redo_batch_t *)(log_file_ctrl->log_buf);
        batch->lsn = log_file_ctrl->lsn;
        batch->size = 0;
    }
    log_buf = (char *)(log_file_ctrl->log_buf);
    return log_buf;
}

void dss_put_log(dss_session_t *session, dss_vg_info_item_t *vg_item, dss_redo_type_t type, void *data, uint32 size)
{
    dss_redo_entry_t *entry = NULL;
    dss_redo_batch_t *batch = NULL;
    char *put_addr = NULL;
    char *log_buf = NULL;

    if (session == NULL || vg_item->status == DSS_VG_STATUS_RECOVERY || vg_item->status == DSS_VG_STATUS_ROLLBACK) {
        return;
    }
    log_buf = dss_get_log_buf_from_vg(session, vg_item, type);
    batch = (dss_redo_batch_t *)(log_buf);
    if (batch->size == 0) {
        batch->size = sizeof(dss_redo_batch_t);
        batch->count = 0;
    }
    LOG_DEBUG_INF("[REDO]prepare to put log, size is %u, type is %d.", size, type);
    entry = (dss_redo_entry_t *)(log_buf + batch->size);
    entry->size = (size + sizeof(dss_redo_entry_t));
    entry->type = type;
    put_addr = log_buf + batch->size + sizeof(dss_redo_entry_t);
    // check wraparound
    if (size != 0) {
        if (memcpy_s(put_addr, (DSS_VG_LOG_SPLIT_SIZE - batch->size) - sizeof(dss_redo_entry_t), data, size) != EOK) {
            cm_panic(0);
        }
    }
    batch->size += entry->size;
    batch->count++;
    LOG_DEBUG_INF("[REDO] after put log, batch size is %u, count is %d.", batch->size, batch->count);
    if (batch->size + sizeof(dss_redo_batch_t) + DSS_DISK_UNIT_SIZE >= DSS_VG_LOG_SPLIT_SIZE) {
        LOG_RUN_ERR("[REDO] failed to put batch, for batch size is %u, log_buf size is %u.", batch->size, batch->count);
    }
    // 'dss_redo_batch_t' will be putted at batch tail also
    CM_ASSERT(batch->size + sizeof(dss_redo_batch_t) + DSS_DISK_UNIT_SIZE <= DSS_VG_LOG_SPLIT_SIZE);
}

status_t dss_write_redolog_to_disk(dss_vg_info_item_t *vg_item, uint32 volume_id, int64 offset, char *buf, uint32 size)
{
    CM_ASSERT(vg_item != NULL);
    CM_ASSERT(buf != NULL);
    status_t status;
    if (vg_item->volume_handle[volume_id].handle != DSS_INVALID_HANDLE) {
        return dss_write_volume_inst(vg_item, &vg_item->volume_handle[volume_id], offset, buf, size);
    }
    status = dss_open_volume(vg_item->dss_ctrl->volume.defs[volume_id].name, NULL, DSS_INSTANCE_OPEN_FLAG,
        &vg_item->volume_handle[volume_id]);
    if (status != CM_SUCCESS) {
        return status;
    }
    status = dss_write_volume_inst(vg_item, &vg_item->volume_handle[volume_id], offset, buf, size);
    if (status != CM_SUCCESS) {
        LOG_RUN_ERR("Failed to read write file, offset:%lld, size:%u.", offset, size);
        return status;
    }
    return CM_SUCCESS;
}

status_t dss_flush_log_v0_inner(dss_vg_info_item_t *vg_item, char *log_buf, uint32 flush_size)
{
    dss_vg_info_item_t *first_vg_item = dss_get_first_vg_item();
    uint64 redo_start = dss_get_redo_log_v0_start(first_vg_item->dss_ctrl, vg_item->id);
    if (flush_size > DSS_INSTANCE_LOG_SPLIT_SIZE) {
        LOG_RUN_ERR("redo log size %u is bigger than %u", flush_size, (uint32)DSS_INSTANCE_LOG_SPLIT_SIZE);
        return CM_ERROR;
    }
    status_t status = dss_write_redolog_to_disk(first_vg_item, 0, redo_start, log_buf, flush_size);
    if (status != CM_SUCCESS) {
        LOG_RUN_ERR("Failed to flush redo log, offset is %lld, size is %u.", redo_start, flush_size);
        return status;
    }
    return status;
}

status_t dss_flush_log_inner(dss_vg_info_item_t *vg_item, char *log_buf, uint32 flush_size)
{
    dss_ctrl_t *dss_ctrl = vg_item->dss_ctrl;
    dss_redo_ctrl_t *redo_ctrl = &dss_ctrl->redo_ctrl;
    uint32 redo_index = redo_ctrl->redo_index;
    auid_t redo_au = redo_ctrl->redo_start_au[redo_index];
    uint64 redo_size = (uint64)redo_ctrl->redo_size[redo_index];
    uint32 count = redo_ctrl->count;
    CM_ASSERT(flush_size < DSS_VG_LOG_SPLIT_SIZE);
    uint64 log_start = dss_get_vg_au_size(dss_ctrl) * redo_au.au;
    uint64 offset = redo_ctrl->offset;
    uint64 log_offset = log_start + offset;
    dss_log_file_ctrl_t *log_ctrl = &vg_item->log_file_ctrl;
    status_t status;
    // redo_au0 | redo_au1 | redo_au2 |...|redo_aun
    if (offset + flush_size > redo_size) {
        uint64 flush_size_2 = (flush_size + offset) % redo_size;
        uint64 flush_size_1 = flush_size - flush_size_2;
        auid_t redo_au_next;
        if (redo_index == count - 1) {
            redo_au_next = redo_ctrl->redo_start_au[0];
            log_ctrl->index = 0;
        } else {
            redo_au_next = redo_ctrl->redo_start_au[redo_index + 1];
            log_ctrl->index = redo_index + 1;
        }
        uint64 log_start_next = dss_get_vg_au_size(dss_ctrl) * redo_au_next.au;
        LOG_DEBUG_INF("Begin to flush redo log, offset is %lld, size is %llu.", offset, flush_size_1);
        status = dss_write_redolog_to_disk(vg_item, redo_au.volume, (int64)log_offset, log_buf, (uint32)flush_size_1);
        if (status != CM_SUCCESS) {
            LOG_RUN_ERR("Failed to flush redo log, offset is %lld, size is %u.", log_offset, (uint32)flush_size_1);
            return status;
        }
        LOG_DEBUG_INF("Begin to flush redo log, offset is %d, size is %llu.", 0, flush_size_2);
        status = dss_write_redolog_to_disk(
            vg_item, redo_au_next.volume, (int64)log_start_next, log_buf + flush_size_1, (uint32)flush_size_2);
        if (status != CM_SUCCESS) {
            LOG_RUN_ERR("Failed to flush redo log, offset is %d, size is %u.", 0, (uint32)flush_size_2);
            return status;
        }
        log_ctrl->offset = flush_size_2;
        return status;
    }
    LOG_DEBUG_INF("Begin to flush redo log, offset is %lld, size is %u.", offset, flush_size);
    status = dss_write_redolog_to_disk(vg_item, redo_au.volume, (int64)log_offset, log_buf, flush_size);
    if (status != CM_SUCCESS) {
        LOG_RUN_ERR("Failed to flush redo log, offset is %llu, size is %u.", log_offset, flush_size);
        return status;
    }
    if (offset + flush_size == redo_size) {
        log_ctrl->index = (redo_index == count - 1) ? 0 : redo_index + 1;
        log_ctrl->offset = 0;
    } else {
        log_ctrl->index = redo_index;
        log_ctrl->offset = offset + flush_size;
    }
    return status;
}

status_t dss_flush_log(dss_vg_info_item_t *vg_item, char *log_buf)
{
    errno_t errcode = 0;
    dss_redo_batch_t *batch = (dss_redo_batch_t *)(log_buf);
    uint32 data_size;
    uint32 flush_size;
    if (batch->size == sizeof(dss_redo_batch_t) || vg_item->status == DSS_VG_STATUS_RECOVERY) {
        return CM_SUCCESS;
    }
    data_size = batch->size - sizeof(dss_redo_batch_t);
    batch->hash_code = cm_hash_bytes((uint8 *)log_buf + sizeof(dss_redo_batch_t), data_size, INFINITE_HASH_RANGE);
    batch->time = cm_now();
    flush_size = CM_CALC_ALIGN(batch->size + sizeof(dss_redo_batch_t), DSS_DISK_UNIT_SIZE);  // align with 512
    // batch_head|entry1|entry2|reserve|batch_tail   --align with 512
    uint64 tail = (uint64)(flush_size - sizeof(dss_redo_batch_t));
    errcode = memcpy_s(log_buf + tail, sizeof(dss_redo_batch_t), batch, sizeof(dss_redo_batch_t));
    securec_check_ret(errcode);
    uint32 software_version = dss_get_software_version(&vg_item->dss_ctrl->vg_info);
    LOG_DEBUG_INF("[REDO] Before flush log, batch size is %u, count is %d, flush size is %u.", batch->size,
        batch->count, flush_size);
    if (software_version < DSS_SOFTWARE_VERSION_2) {
        return dss_flush_log_v0_inner(vg_item, log_buf, flush_size);
    }
    status_t status = dss_flush_log_inner(vg_item, log_buf, flush_size);
    return status;
}

static status_t rp_redo_update_volhead(dss_session_t *session, dss_vg_info_item_t *vg_item, dss_redo_entry_t *entry)
{
#ifndef WIN32
    char align_buf[DSS_DISK_UNIT_SIZE] __attribute__((__aligned__(DSS_DISK_UNIT_SIZE)));
#else
    char align_buf[DSS_DISK_UNIT_SIZE];
#endif
    dss_redo_volhead_t *redo = (dss_redo_volhead_t *)entry->data;
    if (entry->size == 0) {
        DSS_RETURN_IFERR2(CM_ERROR, DSS_THROW_ERROR(ERR_DSS_REDO_ILL, "invalid entry log size 0."));
    }
    int32 errcode = memcpy_sp(align_buf, DSS_DISK_UNIT_SIZE, redo->head, DSS_DISK_UNIT_SIZE);
    securec_check_ret(errcode);
    dss_volume_t volume;
    if (dss_open_volume(redo->name, NULL, DSS_INSTANCE_OPEN_FLAG, &volume) != CM_SUCCESS) {
        return CM_ERROR;
    }
    status_t status = dss_write_volume(&volume, 0, align_buf, (int32)DSS_ALIGN_SIZE);
    dss_close_volume(&volume);
    return status;
}

static status_t rp_redo_add_or_remove_volume(
    dss_session_t *session, dss_vg_info_item_t *vg_item, dss_redo_entry_t *entry)
{
    errno_t errcode = 0;
    dss_redo_volop_t *redo = (dss_redo_volop_t *)entry->data;
    if (entry->size == 0) {
        DSS_RETURN_IFERR2(CM_ERROR, DSS_THROW_ERROR(ERR_DSS_REDO_ILL, "invalid entry log size 0."));
    }
    dss_volume_attr_t *attr = (dss_volume_attr_t *)redo->attr;
    uint32 id = attr->id;

    if (vg_item->status == DSS_VG_STATUS_RECOVERY) {
        if (dss_refresh_vginfo(vg_item) != CM_SUCCESS) {
            DSS_RETURN_IFERR2(
                CM_ERROR, LOG_DEBUG_ERR("[REDO][REPLAY][ADD_OR_REMOVE_VOLUME] %s", "refresh vginfo failed."));
        }

        // in recovery
        if (redo->is_add) {
            CM_ASSERT((vg_item->dss_ctrl->core.volume_count + 1 == redo->volume_count) ||
                      (vg_item->dss_ctrl->core.volume_count == redo->volume_count));
        } else {
            CM_ASSERT((vg_item->dss_ctrl->core.volume_count - 1 == redo->volume_count) ||
                      (vg_item->dss_ctrl->core.volume_count == redo->volume_count));
        }

        errcode = memcpy_s(&vg_item->dss_ctrl->core.volume_attrs[id], sizeof(dss_volume_attr_t), redo->attr,
            sizeof(dss_volume_attr_t));
        securec_check_ret(errcode);
        errcode = memcpy_s(
            &vg_item->dss_ctrl->volume.defs[id], sizeof(dss_volume_def_t), redo->def, sizeof(dss_volume_def_t));
        securec_check_ret(errcode);

        LOG_RUN_INF("[REDO][REPLAY][ADD_OR_REMOVE_VOLUME] recovery add volume core\n"
                    "[before]core version:%llu, volume version:%llu, volume count:%u.\n"
                    "[after]core version:%llu, volume version:%llu, volume count:%u.",
            vg_item->dss_ctrl->core.version, vg_item->dss_ctrl->volume.version, vg_item->dss_ctrl->core.volume_count,
            redo->core_version, redo->volume_version, redo->volume_count);

        vg_item->dss_ctrl->core.version = redo->core_version;
        vg_item->dss_ctrl->core.volume_count = redo->volume_count;
        vg_item->dss_ctrl->volume.version = redo->volume_version;
    }
    status_t status = dss_update_volume_id_info(vg_item, id);
    DSS_RETURN_IFERR2(status,
        LOG_DEBUG_ERR("[REDO][REPLAY][ADD_OR_REMOVE_VOLUME] Failed to update core ctrl and volume to disk, vg:%s.",
            vg_item->vg_name));
    DSS_LOG_DEBUG_OP("[REDO][REPLAY][ADD_OR_REMOVE_VOLUME] Succeed to replay add or remove volume:%u.", id);
    return CM_SUCCESS;
}

static status_t rb_redo_update_volhead(dss_session_t *session, dss_vg_info_item_t *vg_item, dss_redo_entry_t *entry)
{
    // no need to update volume head.
    return CM_SUCCESS;
}

static void print_redo_update_volhead(dss_redo_entry_t *entry)
{
    dss_redo_volhead_t *redo = (dss_redo_volhead_t *)entry->data;
    (void)printf("    redo_volhead = {\n");
    (void)printf("      head = %s\n", redo->head);
    (void)printf("      name = %s\n", redo->name);
    (void)printf("    }\n");
}
static status_t rb_redo_add_or_remove_volume(
    dss_session_t *session, dss_vg_info_item_t *vg_item, dss_redo_entry_t *entry)
{
    bool32 remote = CM_FALSE;
    dss_redo_volop_t *redo = (dss_redo_volop_t *)entry->data;
    DSS_LOG_DEBUG_OP(
        "[REDO][ROLLBACK][ADD_OR_REMOVE_VOL] rollback %s volume operate", (redo->is_add) ? "add" : "remove");
    return dss_load_vg_ctrl_part(vg_item, (int64)DSS_CTRL_CORE_OFFSET, vg_item->dss_ctrl->core_data,
        (int32)(DSS_CORE_CTRL_SIZE + DSS_VOLUME_CTRL_SIZE), &remote);
}

static void print_redo_add_or_remove_volume(dss_redo_entry_t *entry)
{
    dss_redo_volop_t *data = (dss_redo_volop_t *)entry->data;
    (void)printf("    redo_volop = {\n");
    (void)printf("      attr = %s\n", data->attr);
    (void)printf("      def = %s\n", data->def);
    (void)printf("      is_add = %u\n", data->is_add);
    (void)printf("      volume_count = %u\n", data->volume_count);
    (void)printf("      core_version = %llu\n", data->core_version);
    (void)printf("      volume_version = %llu\n", data->volume_version);
    (void)printf("    }\n");
}

static status_t rp_update_core_ctrl(dss_session_t *session, dss_vg_info_item_t *vg_item, dss_redo_entry_t *entry)
{
    errno_t errcode = 0;
    dss_core_ctrl_t *data = (dss_core_ctrl_t *)entry->data;
    if (entry->size != 0 && vg_item->status == DSS_VG_STATUS_RECOVERY) {
        errcode =
            memcpy_s(vg_item->dss_ctrl->core_data, DSS_CORE_CTRL_SIZE, data, entry->size - sizeof(dss_redo_entry_t));
        securec_check_ret(errcode);
    }
    LOG_DEBUG_INF("[REDO] replay to update core ctrl, hwm:%llu.", vg_item->dss_ctrl->core.volume_attrs[0].hwm);
    status_t status = dss_update_core_ctrl_disk(vg_item);
    DSS_RETURN_IFERR2(status, LOG_DEBUG_ERR("[REDO] Failed to update core ctrl to disk, vg:%s.", vg_item->vg_name));
    DSS_LOG_DEBUG_OP("[REDO] Succeed to replay update core ctrl:%s.", vg_item->vg_name);
    return CM_SUCCESS;
}

static status_t rb_update_core_ctrl(dss_session_t *session, dss_vg_info_item_t *vg_item, dss_redo_entry_t *entry)
{
    bool32 remote = CM_FALSE;
    DSS_LOG_DEBUG_OP(
        "[REDO][ROLLBACK] rollback update core ctrl, hwm:%llu.", vg_item->dss_ctrl->core.volume_attrs[0].hwm);
    return dss_load_vg_ctrl_part(
        vg_item, (int64)DSS_CTRL_CORE_OFFSET, vg_item->dss_ctrl->core_data, (int32)DSS_CORE_CTRL_SIZE, &remote);
}

static void print_redo_update_core_ctrl(dss_redo_entry_t *entry)
{
    dss_core_ctrl_t *data = (dss_core_ctrl_t *)entry->data;
    dss_printf_core_ctrl_base(data);
}

void rp_init_block_addr_history(dss_block_addr_his_t *addr_his)
{
    CM_ASSERT(addr_his != NULL);
    addr_his->count = 0;
}
void rp_insert_block_addr_history(dss_block_addr_his_t *addr_his, void *block)
{
    CM_ASSERT(addr_his != NULL);
    CM_ASSERT(block != NULL);
    CM_ASSERT(addr_his->count < DSS_MAX_BLOCK_ADDR_NUM);
    addr_his->addrs[addr_his->count] = block;
    addr_his->count++;
}

bool32 rp_check_block_addr(const dss_block_addr_his_t *addr_his, const void *block)
{
    CM_ASSERT(addr_his != NULL);
    CM_ASSERT(block != NULL);

    for (uint32 i = 0; i < addr_his->count; i++) {
        if (addr_his->addrs[i] == block) {
            return CM_TRUE;
        }
    }
    return CM_FALSE;
}
static status_t rp_redo_alloc_ft_node_core(dss_session_t *session, dss_vg_info_item_t *vg_item,
    dss_redo_alloc_ft_node_t *data, dss_root_ft_block_t *ft_block, bool32 check_version)
{
    bool32 cmp;
    status_t status;
    gft_node_t *node;
    dss_ft_block_t *cur_block;
    dss_block_addr_his_t addr_his;
    rp_init_block_addr_history(&addr_his);
    rp_insert_block_addr_history(&addr_his, ft_block);
    for (uint32 i = 0; i < DSS_REDO_ALLOC_FT_NODE_NUM; i++) {
        cmp = dss_cmp_auid(data->node[i].id, CM_INVALID_ID64);
        if (cmp) {
            continue;
        }
        node = dss_get_ft_node_by_ftid(session, vg_item, data->node[i].id, check_version, CM_FALSE);
        if (node == NULL) {
            DSS_RETURN_IFERR2(CM_ERROR, DSS_THROW_ERROR(ERR_DSS_FNODE_CHECK, "invalid ft node."));
        }
        cur_block = dss_get_ft_by_node(node);
        if (vg_item->status == DSS_VG_STATUS_RECOVERY) {
            *node = data->node[i];
            if (i == DSS_REDO_ALLOC_FT_NODE_SELF_INDEX) {
                cur_block->common.flags = DSS_BLOCK_FLAG_USED;
            }
        }

        LOG_DEBUG_INF("[REDO] replay alloc file table node, name:%s.", node->name);

        cur_block = dss_get_ft_by_node(node);
        if (rp_check_block_addr(&addr_his, cur_block) && vg_item->status != DSS_VG_STATUS_RECOVERY) {
            continue;  // already update the block to disk
        }
        status = dss_update_ft_block_disk(vg_item, cur_block, data->node[i].id);
        DSS_RETURN_IF_ERROR(status);
        rp_insert_block_addr_history(&addr_his, cur_block);
    }
    return CM_SUCCESS;
}

static status_t rp_redo_alloc_ft_node(dss_session_t *session, dss_vg_info_item_t *vg_item, dss_redo_entry_t *entry)
{
    CM_ASSERT(vg_item != NULL);
    CM_ASSERT(entry != NULL);
    status_t status;
    dss_redo_alloc_ft_node_t *data = (dss_redo_alloc_ft_node_t *)entry->data;
    dss_root_ft_block_t *ft_block = DSS_GET_ROOT_BLOCK(vg_item->dss_ctrl);
    gft_root_t *gft = &ft_block->ft_root;
    bool32 check_version = CM_FALSE;

    if (entry->size == 0) {
        DSS_RETURN_IFERR2(CM_ERROR, DSS_THROW_ERROR(ERR_DSS_REDO_ILL, "invalid entry log size 0."));
    }
    if (vg_item->status == DSS_VG_STATUS_RECOVERY) {
        status = dss_refresh_root_ft(vg_item, CM_TRUE, CM_FALSE);
        if (status != CM_SUCCESS) {
            LOG_DEBUG_ERR("[REDO] Failed to refresh file table root, vg:%s.", vg_item->vg_name);
            return status;
        }

        *gft = data->ft_root;
        check_version = CM_TRUE;
        LOG_DEBUG_INF("[REDO] replay alloc file table node when recovery.");
    }

    status = dss_update_ft_root(vg_item);
    DSS_RETURN_IFERR2(status, DSS_THROW_ERROR(ERR_DSS_REDO_ILL, "Failed to update file table root."));
    DSS_RETURN_IF_ERROR(rp_redo_alloc_ft_node_core(session, vg_item, data, ft_block, check_version));
    LOG_DEBUG_INF("[REDO] Succeed to replay alloc ft node, vg name:%s.", vg_item->vg_name);
    return CM_SUCCESS;
}

static status_t rb_rollback_ft_block(
    dss_session_t *session, dss_vg_info_item_t *vg_item, gft_node_t *node, uint32 node_num)
{
    CM_ASSERT(vg_item != NULL);
    CM_ASSERT(node != NULL);
    status_t status;
    bool32 check_version = CM_FALSE;
    bool32 remote = CM_FALSE;

    status = dss_load_vg_ctrl_part(
        vg_item, (int64)DSS_CTRL_ROOT_OFFSET, vg_item->dss_ctrl->root, (int32)DSS_BLOCK_SIZE, &remote);
    if (status != CM_SUCCESS) {
        return status;
    }

    gft_node_t *cur_node;
    dss_ft_block_t *cur_block = NULL;
    bool32 cmp;
    int64 offset = 0;
    for (uint32 i = 0; i < node_num; i++) {
        cmp = dss_cmp_auid(node[i].id, CM_INVALID_ID64);
        if (cmp) {
            continue;
        }
        cur_node = dss_get_ft_node_by_ftid(session, vg_item, node[i].id, check_version, CM_FALSE);
        if (!cur_node) {
            DSS_RETURN_IFERR2(CM_ERROR, DSS_THROW_ERROR(ERR_DSS_FNODE_CHECK, "invalid ft node."));
        }

        cur_block = dss_get_ft_by_node(cur_node);
        offset = dss_get_ft_block_offset(vg_item, node[i].id);
        status =
            dss_get_block_from_disk(vg_item, node[i].id, (char *)cur_block, offset, (int32)DSS_BLOCK_SIZE, CM_TRUE);
        if (status != CM_SUCCESS) {
            return status;
        }
    }
    return CM_SUCCESS;
}

static status_t rb_redo_alloc_ft_node(dss_session_t *session, dss_vg_info_item_t *vg_item, dss_redo_entry_t *entry)
{
    CM_ASSERT(vg_item != NULL);
    CM_ASSERT(entry != NULL);
    dss_redo_alloc_ft_node_t *data = (dss_redo_alloc_ft_node_t *)entry->data;

    if (entry->size == 0) {
        DSS_RETURN_IFERR2(CM_ERROR, DSS_THROW_ERROR(ERR_DSS_REDO_ILL, "invalid entry log size 0."));
    }

    return rb_rollback_ft_block(session, vg_item, data->node, DSS_REDO_ALLOC_FT_NODE_NUM);
}

static void print_redo_alloc_ft_node(dss_redo_entry_t *entry)
{
    dss_redo_alloc_ft_node_t *data = (dss_redo_alloc_ft_node_t *)entry->data;
    (void)printf("    alloc_ft_node = {\n");
    (void)printf("      ft_root = {\n");
    printf_gft_root(&data->ft_root);
    (void)printf("      }\n");
    for (uint32 i = 0; i < DSS_REDO_ALLOC_FT_NODE_NUM; i++) {
        if (dss_cmp_auid(data->node[i].id, CM_INVALID_ID64)) {
            continue;
        }
        (void)printf("    gft_node[%u] = {\n", i);
        printf_gft_node(&data->node[i], "    ");
        (void)printf("    }\n");
    }
    (void)printf("    }\n");
}

static status_t dss_update_ft_info(dss_vg_info_item_t *vg_item, dss_ft_block_t *block, dss_redo_format_ft_t *data)
{
    status_t status = dss_update_ft_block_disk(vg_item, block, data->old_last_block);
    if (status != CM_SUCCESS) {
        LOG_DEBUG_ERR(
            "[REDO] Failed to update file table block to disk, %s.", dss_display_metaid(data->old_last_block));
        return status;
    }
    status = dss_update_ft_root(vg_item);
    DSS_RETURN_IFERR2(status, LOG_DEBUG_ERR("[REDO] Failed to update file table root, vg:%s.", vg_item->vg_name));
    return CM_SUCCESS;
}

static status_t rp_redo_format_ft_node(dss_session_t *session, dss_vg_info_item_t *vg_item, dss_redo_entry_t *entry)
{
    CM_ASSERT(vg_item != NULL && entry != NULL);

    status_t status;
    dss_redo_format_ft_t *data = (dss_redo_format_ft_t *)entry->data;
    dss_ft_block_t *block = NULL;
    if (vg_item->status == DSS_VG_STATUS_RECOVERY) {
        status = dss_refresh_root_ft(vg_item, CM_TRUE, CM_FALSE);
        DSS_RETURN_IFERR2(status, LOG_DEBUG_ERR("[REDO] Failed to refresh file table root, vg:%s.", vg_item->vg_name));
        // note:first load
        block = (dss_ft_block_t *)dss_get_ft_block_by_ftid(session, vg_item, data->old_last_block);
        if (block == NULL) {
            DSS_RETURN_IFERR2(CM_ERROR, LOG_DEBUG_ERR("[REDO]Failed to get last file table block, blockid: %s.",
                                            dss_display_metaid(data->old_last_block)));
        }
        dss_root_ft_block_t *root_block = DSS_GET_ROOT_BLOCK(vg_item->dss_ctrl);
        root_block->ft_root.free_list = data->old_free_list;
        root_block->ft_root.last = data->old_last_block;
        status = dss_format_ft_node(session, vg_item, data->auid);
        DSS_RETURN_IFERR2(
            status, LOG_DEBUG_ERR("[REDO] Failed to format file table node, %s.", dss_display_metaid(data->auid)));
    }
    // when recover, has load old last block.
    if (vg_item->status != DSS_VG_STATUS_RECOVERY) {  // just find the block, it has already in memory.
        block = (dss_ft_block_t *)dss_get_ft_block_by_ftid(session, vg_item, data->old_last_block);
        if (block == NULL) {
            DSS_RETURN_IFERR2(CM_ERROR, LOG_DEBUG_ERR("[REDO]Failed to get last file table block, blockid: %s.",
                                            dss_display_metaid(data->old_last_block)));
        }
    }
    CM_RETURN_IFERR(dss_update_ft_info(vg_item, block, data));
    dss_block_id_t first = data->auid;
    ga_obj_id_t obj_id;
    status = dss_find_block_objid_in_shm(session, vg_item, first, DSS_BLOCK_TYPE_FT, &obj_id);
    DSS_RETURN_IFERR2(status, LOG_DEBUG_ERR("[REDO] Failed to find block: %s.", dss_display_metaid(first)));
    status = dss_update_au_disk(vg_item, data->auid, GA_8K_POOL, obj_id.obj_id, data->count, DSS_BLOCK_SIZE);
    DSS_RETURN_IFERR2(status, LOG_DEBUG_ERR("[REDO] Failed to update au to disk, %s.", dss_display_metaid(data->auid)));
    DSS_LOG_DEBUG_OP("[REDO] Succeed to replay formate ft node: %s , obj_id:%u, count:%u.",
        dss_display_metaid(data->auid), data->obj_id, data->count);
    LOG_DEBUG_INF("[REDO] old_last_block: %s", dss_display_metaid(data->old_last_block));
    return CM_SUCCESS;
}

static status_t rb_redo_format_ft_node(dss_session_t *session, dss_vg_info_item_t *vg_item, dss_redo_entry_t *entry)
{
    // format file table node only when new au, if fail, just free the memory, no need to rollback.
    return CM_SUCCESS;
}

static void print_redo_format_ft_node(dss_redo_entry_t *entry)
{
    dss_redo_format_ft_t *data = (dss_redo_format_ft_t *)entry->data;
    (void)printf("    format_ft = {\n");
    (void)printf("     auid = {\n");
    printf_auid(&data->auid);
    (void)printf("      }\n");
    (void)printf("      obj_id = %u\n", data->obj_id);
    (void)printf("      count = %u\n", data->count);
    (void)printf("     old_last_block = {\n");
    printf_auid(&data->old_last_block);
    (void)printf("      }\n");
    (void)printf("     old_free_list = {\n");
    printf_gft_list(&data->old_free_list);
    (void)printf("      }\n");
    (void)printf("      obj_id = %u\n", data->obj_id);
    (void)printf("    }\n");
}

static status_t rp_redo_free_fs_block(dss_session_t *session, dss_vg_info_item_t *vg_item, dss_redo_entry_t *entry)
{
    CM_ASSERT(vg_item != NULL);
    CM_ASSERT(entry != NULL);

    status_t status;
    dss_redo_free_fs_block_t *data = (dss_redo_free_fs_block_t *)entry->data;

    dss_fs_block_t *block;
    dss_fs_block_t *log_block = (dss_fs_block_t *)data->head;
    if (vg_item->status == DSS_VG_STATUS_RECOVERY) {
        ga_obj_id_t obj_id;
        block = (dss_fs_block_t *)dss_find_block_in_shm(
            session, vg_item, log_block->head.common.id, DSS_BLOCK_TYPE_FS, CM_TRUE, &obj_id, CM_FALSE);
        if (block == NULL) {
            DSS_RETURN_IFERR2(CM_ERROR, DSS_THROW_ERROR(ERR_DSS_FNODE_CHECK, "invalid block"));
        }
        block->head.next = log_block->head.next;
        block->head.index = DSS_FS_INDEX_INIT;
        block->head.common.flags = DSS_BLOCK_FLAG_FREE;
        dss_set_auid(&block->head.ftid, DSS_BLOCK_ID_INIT);
        status = dss_update_fs_bitmap_block_disk(vg_item, block, DSS_DISK_UNIT_SIZE, CM_FALSE);
        DSS_RETURN_IF_ERROR(status);
        dss_unregister_buffer_cache(session, vg_item, log_block->head.common.id);
        ga_free_object(obj_id.pool_id, obj_id.obj_id);
        return CM_SUCCESS;
    }

    status = dss_update_fs_bitmap_block_disk(vg_item, log_block, DSS_DISK_UNIT_SIZE, CM_TRUE);
    DSS_RETURN_IFERR2(status,
        LOG_DEBUG_ERR("[REDO] Failed to update fs bitmap block: %s.", dss_display_metaid(log_block->head.common.id)));
    LOG_DEBUG_INF("[REDO] Succeed to replay free fs block: %s, vg name:%s.",
        dss_display_metaid(log_block->head.common.id), vg_item->vg_name);
    return CM_SUCCESS;
}

status_t rb_redo_free_fs_block(dss_session_t *session, dss_vg_info_item_t *vg_item, dss_redo_entry_t *entry)
{
    CM_ASSERT(vg_item != NULL);
    CM_ASSERT(entry != NULL);

    dss_redo_free_fs_block_t *data = (dss_redo_free_fs_block_t *)entry->data;
    dss_fs_block_t *log_block = (dss_fs_block_t *)data->head;

    return dss_load_fs_block_by_blockid(session, vg_item, log_block->head.common.id, (int32)DSS_FILE_SPACE_BLOCK_SIZE);
}
static void print_redo_free_fs_block(dss_redo_entry_t *entry)
{
    dss_redo_free_fs_block_t *data = (dss_redo_free_fs_block_t *)entry->data;
    (void)printf("    free_fs_block = {\n");
    (void)printf("     head = %s\n", data->head);
    (void)printf("    }\n");
}
static status_t rp_redo_alloc_fs_block(dss_session_t *session, dss_vg_info_item_t *vg_item, dss_redo_entry_t *entry)
{
    CM_ASSERT(vg_item != NULL);
    CM_ASSERT(entry != NULL);

    status_t status;
    dss_redo_alloc_fs_block_t *data = (dss_redo_alloc_fs_block_t *)entry->data;
    dss_fs_block_root_t *root = DSS_GET_FS_BLOCK_ROOT(vg_item->dss_ctrl);
    dss_fs_block_t *block = NULL;

    if (vg_item->status == DSS_VG_STATUS_RECOVERY) {
        status = dss_check_refresh_core(vg_item);
        DSS_RETURN_IFERR2(status, LOG_DEBUG_ERR("[REDO] Failed to refresh vg core:%s.", vg_item->vg_name));
        block = (dss_fs_block_t *)dss_find_block_in_shm(
            session, vg_item, data->id, DSS_BLOCK_TYPE_FS, CM_TRUE, NULL, CM_FALSE);
        if (block == NULL) {
            DSS_RETURN_IFERR2(CM_ERROR, DSS_THROW_ERROR(ERR_DSS_FNODE_CHECK, "invalid block"));
        }

        dss_init_fs_block_head(block);
        block->head.ftid = data->ftid;
        block->head.index = data->index;
        block->head.common.flags = DSS_BLOCK_FLAG_USED;
        *root = data->root;
    }
    status = dss_update_core_ctrl_disk(vg_item);
    DSS_RETURN_IFERR2(status, LOG_DEBUG_ERR("[REDO] Failed to update vg core:%s to disk.", vg_item->vg_name));

    if (block == NULL) {
        block = (dss_fs_block_t *)dss_find_block_in_shm(
            session, vg_item, data->id, DSS_BLOCK_TYPE_FS, CM_FALSE, NULL, CM_FALSE);
    }

    if (block == NULL) {
        DSS_RETURN_IFERR2(CM_ERROR, DSS_THROW_ERROR(ERR_DSS_FNODE_CHECK, "invalid block"));
    }

    status = dss_update_fs_bitmap_block_disk(vg_item, block, DSS_FILE_SPACE_BLOCK_SIZE, CM_FALSE);
    DSS_RETURN_IFERR2(
        status, LOG_DEBUG_ERR("[REDO] Failed to update fs bitmap block: %s.", dss_display_metaid(data->id)));
    LOG_DEBUG_INF(
        "[REDO] Succeed to replay alloc fs block: %s, vg name:%s.", dss_display_metaid(data->id), vg_item->vg_name);
    return CM_SUCCESS;
}

static status_t rb_redo_alloc_fs_block(dss_session_t *session, dss_vg_info_item_t *vg_item, dss_redo_entry_t *entry)
{
    CM_ASSERT(vg_item != NULL);
    CM_ASSERT(entry != NULL);

    status_t status;
    bool32 remote = CM_FALSE;
    dss_redo_alloc_fs_block_t *data = (dss_redo_alloc_fs_block_t *)entry->data;

    ga_obj_id_t obj_id;
    dss_fs_block_t *block = (dss_fs_block_t *)dss_find_block_in_shm(
        session, vg_item, data->id, DSS_BLOCK_TYPE_FS, CM_FALSE, &obj_id, CM_FALSE);
    CM_ASSERT(block != NULL);
    dss_unregister_buffer_cache(session, vg_item, block->head.common.id);
    ga_free_object(obj_id.pool_id, obj_id.obj_id);
    status = dss_load_vg_ctrl_part(
        vg_item, (int64)DSS_CTRL_CORE_OFFSET, vg_item->dss_ctrl->core_data, DSS_DISK_UNIT_SIZE, &remote);
    CM_ASSERT(status == CM_SUCCESS);
    return status;
}

static void print_redo_alloc_fs_block(dss_redo_entry_t *entry)
{
    dss_redo_alloc_fs_block_t *data = (dss_redo_alloc_fs_block_t *)entry->data;
    (void)printf("    alloc_fs_block = {\n");
    (void)printf("     id = {\n");
    printf_auid(&data->id);
    (void)printf("      }\n");
    (void)printf("     ftid = {\n");
    printf_auid(&data->ftid);
    (void)printf("      }\n");
    (void)printf("     root = {\n");
    printf_dss_fs_block_root(&data->root);
    (void)printf("      }\n");
    (void)printf("     index = %hu\n", data->index);
    (void)printf("    }\n");
}
status_t rp_redo_init_fs_block(dss_session_t *session, dss_vg_info_item_t *vg_item, dss_redo_entry_t *entry)
{
    CM_ASSERT(vg_item != NULL);
    CM_ASSERT(entry != NULL);

    status_t status;
    dss_redo_init_fs_block_t *data = (dss_redo_init_fs_block_t *)entry->data;

    dss_fs_block_t *block = NULL;

    if (vg_item->status == DSS_VG_STATUS_RECOVERY) {
        block = (dss_fs_block_t *)dss_find_block_in_shm(
            session, vg_item, data->id, DSS_BLOCK_TYPE_FS, CM_TRUE, NULL, CM_FALSE);
        if (block == NULL) {
            DSS_RETURN_IFERR2(CM_ERROR, DSS_THROW_ERROR(ERR_DSS_FNODE_CHECK, "invalid block"));
        }
        block->bitmap[data->index] = data->second_id;
        block->head.used_num = data->used_num;
    }

    if (block == NULL) {
        block = (dss_fs_block_t *)dss_find_block_in_shm(
            session, vg_item, data->id, DSS_BLOCK_TYPE_FS, CM_FALSE, NULL, CM_FALSE);
        if (block == NULL) {
            DSS_RETURN_IFERR2(CM_ERROR, DSS_THROW_ERROR(ERR_DSS_FNODE_CHECK, "invalid block"));
        }
    }

    status = dss_update_fs_bitmap_block_disk(vg_item, block, DSS_FILE_SPACE_BLOCK_SIZE, CM_FALSE);
    DSS_RETURN_IFERR2(
        status, LOG_DEBUG_ERR("[REDO] Failed to update fs bitmap block: %s to disk.", dss_display_metaid(data->id)));
    LOG_DEBUG_INF(
        "[REDO] Succeed to replay init fs block: %s, vg name:%s.", dss_display_metaid(data->id), vg_item->vg_name);
    return CM_SUCCESS;
}

status_t rb_redo_init_fs_block(dss_session_t *session, dss_vg_info_item_t *vg_item, dss_redo_entry_t *entry)
{
    CM_ASSERT(vg_item != NULL);
    CM_ASSERT(entry != NULL);

    dss_redo_init_fs_block_t *data = (dss_redo_init_fs_block_t *)entry->data;

    dss_fs_block_t *block = (dss_fs_block_t *)dss_find_block_in_shm(
        session, vg_item, data->id, DSS_BLOCK_TYPE_FS, CM_FALSE, NULL, CM_FALSE);
    if (block == NULL) {
        DSS_RETURN_IFERR2(CM_ERROR, DSS_THROW_ERROR(ERR_DSS_FNODE_CHECK, "invalid block"));
    }

    dss_set_blockid(&block->bitmap[data->index], CM_INVALID_ID64);
    block->head.used_num = 0;

    return CM_SUCCESS;
}
static void print_redo_init_fs_block(dss_redo_entry_t *entry)
{
    dss_redo_init_fs_block_t *data = (dss_redo_init_fs_block_t *)entry->data;
    (void)printf("    init_fs_block = {\n");
    (void)printf("     id = {\n");
    printf_auid(&data->id);
    (void)printf("      }\n");
    (void)printf("     second_id = {\n");
    printf_auid(&data->second_id);
    (void)printf("      }\n");
    (void)printf("     index = %hu\n", data->index);
    (void)printf("     used_num = %hu\n", data->used_num);
    (void)printf("    }\n");
}
status_t rp_redo_rename_file(dss_session_t *session, dss_vg_info_item_t *vg_item, dss_redo_entry_t *entry)
{
    CM_ASSERT(vg_item != NULL);
    CM_ASSERT(entry != NULL);

    if (entry->size == 0) {
        DSS_RETURN_IFERR2(CM_ERROR, DSS_THROW_ERROR(ERR_DSS_REDO_ILL, "invalid entry log size 0."));
    }

    bool32 check_version = CM_FALSE;
    if (vg_item->status == DSS_VG_STATUS_RECOVERY) {
        check_version = CM_TRUE;
    }

    dss_redo_rename_t *data = (dss_redo_rename_t *)entry->data;
    if (dss_cmp_auid(data->node.id, CM_INVALID_ID64)) {
        DSS_RETURN_IFERR2(CM_ERROR, DSS_THROW_ERROR(ERR_DSS_FNODE_CHECK, "invalid node 0xFFFFFFFF"));
    }

    gft_node_t *node = dss_get_ft_node_by_ftid(session, vg_item, data->node.id, check_version, CM_FALSE);
    if (!node) {
        DSS_RETURN_IFERR2(CM_ERROR, DSS_THROW_ERROR(ERR_DSS_FNODE_CHECK, "invalid node"));
    }

    if (vg_item->status == DSS_VG_STATUS_RECOVERY) {
        int32 ret = snprintf_s(node->name, DSS_MAX_NAME_LEN, strlen(data->name), "%s", data->name);
        DSS_SECUREC_SS_RETURN_IF_ERROR(ret, CM_ERROR);
    }

    dss_ft_block_t *cur_block = dss_get_ft_by_node(node);
    if (cur_block == NULL) {
        DSS_RETURN_IFERR2(CM_ERROR, DSS_THROW_ERROR(ERR_DSS_FNODE_CHECK, "invalid block"));
    }

    status_t status = dss_update_ft_block_disk(vg_item, cur_block, data->node.id);
    DSS_RETURN_IFERR2(
        status, LOG_DEBUG_ERR("[REDO] Failed to update fs block: %s to disk.", dss_display_metaid(data->node.id)));

    dss_block_ctrl_t *block_ctrl = DSS_GET_BLOCK_CTRL_FROM_META(cur_block);
    dss_add_syn_meta(vg_item, block_ctrl, cur_block->common.version);

    LOG_DEBUG_INF(
        "Succeed to replay rename file:%s, old_name:%s, name:%s.", data->name, data->old_name, vg_item->vg_name);
    return CM_SUCCESS;
}
status_t rb_redo_rename_file(dss_session_t *session, dss_vg_info_item_t *vg_item, dss_redo_entry_t *entry)
{
    CM_ASSERT(vg_item != NULL);
    CM_ASSERT(entry != NULL);

    dss_redo_rename_t *data = (dss_redo_rename_t *)entry->data;
    bool32 check_version = CM_FALSE;

    if (entry->size == 0) {
        DSS_RETURN_IFERR2(CM_ERROR, DSS_THROW_ERROR(ERR_DSS_REDO_ILL, "invalid entry log size 0."));
    }
    if (vg_item->status == DSS_VG_STATUS_RECOVERY) {
        check_version = CM_TRUE;
    }

    if (dss_cmp_auid(data->node.id, CM_INVALID_ID64)) {
        DSS_RETURN_IFERR2(CM_ERROR, DSS_THROW_ERROR(ERR_DSS_FNODE_CHECK, "invalid node 0xFFFFFFFF"));
    }

    gft_node_t *node = dss_get_ft_node_by_ftid(session, vg_item, data->node.id, check_version, CM_FALSE);
    if (!node) {
        DSS_RETURN_IFERR2(CM_ERROR, DSS_THROW_ERROR(ERR_DSS_FNODE_CHECK, "invalid node"));
    }

    int32 ret = snprintf_s(node->name, DSS_MAX_NAME_LEN, strlen(data->old_name), "%s", data->old_name);
    DSS_SECUREC_SS_RETURN_IF_ERROR(ret, CM_ERROR);
    return CM_SUCCESS;
}
static void print_redo_rename_file(dss_redo_entry_t *entry)
{
    dss_redo_rename_t *data = (dss_redo_rename_t *)entry->data;
    (void)printf("    set_file_size = {\n");
    (void)printf("     node = {\n");
    printf_gft_node(&data->node, "    ");
    (void)printf("      }\n");
    (void)printf("     name = %s\n", data->name);
    (void)printf("     old_name = %s\n", data->old_name);
    (void)printf("    }\n");
}
status_t rp_redo_set_fs_block(dss_session_t *session, dss_vg_info_item_t *vg_item, dss_redo_entry_t *entry)
{
    CM_ASSERT(vg_item != NULL);
    CM_ASSERT(entry != NULL);

    status_t status;
    dss_redo_set_fs_block_t *data = (dss_redo_set_fs_block_t *)entry->data;

    bool32 check_version = CM_FALSE;
    if (vg_item->status == DSS_VG_STATUS_RECOVERY) {
        check_version = CM_TRUE;
    }

    dss_fs_block_t *block = (dss_fs_block_t *)dss_find_block_in_shm(
        session, vg_item, data->id, DSS_BLOCK_TYPE_FS, check_version, NULL, CM_FALSE);
    if (block == NULL) {
        DSS_RETURN_IFERR2(CM_ERROR, DSS_THROW_ERROR(ERR_DSS_FNODE_CHECK, "invalid block"));
    }

    if (vg_item->status == DSS_VG_STATUS_RECOVERY) {
        block->bitmap[data->index] = data->value;
        block->head.used_num = data->used_num;
    }

    status = dss_update_fs_bitmap_block_disk(vg_item, block, DSS_FILE_SPACE_BLOCK_SIZE, CM_FALSE);
    DSS_RETURN_IFERR2(status, LOG_DEBUG_ERR("Failed to update fs block: %s to disk.", dss_display_metaid(data->id)));

    dss_block_ctrl_t *block_ctrl = DSS_GET_BLOCK_CTRL_FROM_META(block);
    dss_add_syn_meta(vg_item, block_ctrl, block->head.common.version);
    LOG_DEBUG_INF("[REDO] Succeed to replay set fs block: %s, used_num:%hu, vg name:%s.", dss_display_metaid(data->id),
        block->head.used_num, vg_item->vg_name);
    return CM_SUCCESS;
}

status_t rb_redo_set_fs_block(dss_session_t *session, dss_vg_info_item_t *vg_item, dss_redo_entry_t *entry)
{
    CM_ASSERT(vg_item != NULL);
    CM_ASSERT(entry != NULL);

    dss_redo_set_fs_block_t *data = (dss_redo_set_fs_block_t *)entry->data;

    dss_fs_block_t *block;
    bool32 check_version = CM_FALSE;

    block = (dss_fs_block_t *)dss_find_block_in_shm(
        session, vg_item, data->id, DSS_BLOCK_TYPE_FS, check_version, NULL, CM_FALSE);
    if (block == NULL) {
        DSS_RETURN_IFERR2(CM_ERROR, DSS_THROW_ERROR(ERR_DSS_FNODE_CHECK, "invalid block"));
    }

    block->bitmap[data->index] = data->old_value;
    block->head.used_num = data->old_used_num;

    return CM_SUCCESS;
}

static void print_redo_set_fs_block(dss_redo_entry_t *entry)
{
    dss_redo_set_fs_block_t *data = (dss_redo_set_fs_block_t *)entry->data;
    (void)printf("    set_fs_block = {\n");
    (void)printf("     id = {\n");
    printf_auid(&data->id);
    (void)printf("      }\n");
    (void)printf("     value = {\n");
    printf_auid(&data->value);
    (void)printf("      }\n");
    (void)printf("     old_value = {\n");
    printf_auid(&data->old_value);
    (void)printf("      }\n");
    (void)printf("     index = %hu\n", data->index);
    (void)printf("     used_num = %hu\n", data->used_num);
    (void)printf("     old_used_num = %hu\n", data->old_used_num);
    (void)printf("    }\n");
}

static status_t rp_redo_free_ft_node_core(dss_session_t *session, dss_vg_info_item_t *vg_item,
    dss_root_ft_block_t *ft_block, dss_redo_free_ft_node_t *data, bool32 check_version)
{
    status_t status = dss_update_ft_root(vg_item);
    if (status != CM_SUCCESS) {
        return status;
    }

    dss_block_addr_his_t addr_his;
    rp_init_block_addr_history(&addr_his);
    rp_insert_block_addr_history(&addr_his, ft_block);

    gft_node_t *node;
    dss_ft_block_t *cur_block = NULL;
    bool32 cmp;
    for (uint32 i = 0; i < DSS_REDO_FREE_FT_NODE_NUM; i++) {
        cmp = dss_cmp_auid(data->node[i].id, CM_INVALID_ID64);
        if (cmp) {
            continue;
        }
        node = dss_get_ft_node_by_ftid(session, vg_item, data->node[i].id, check_version, CM_FALSE);
        if (!node) {
            return CM_ERROR;
        }
        cur_block = dss_get_ft_by_node(node);
        if (vg_item->status == DSS_VG_STATUS_RECOVERY) {
            *node = data->node[i];
            if (i == DSS_REDO_FREE_FT_NODE_SELF_INDEX && node->size == 0) {
                cur_block->common.flags = DSS_BLOCK_FLAG_FREE;
            }
        }

        cur_block = dss_get_ft_by_node(node);
        if (rp_check_block_addr(&addr_his, cur_block) && vg_item->status != DSS_VG_STATUS_RECOVERY) {
            DSS_LOG_DEBUG_OP("[REDO] Replay free ft node, block has updated, cur_block:%p, node id: %s.", cur_block,
                dss_display_metaid(node->id));
            continue;  // already update the block to disk
        }

        DSS_LOG_DEBUG_OP(
            "[REDO] Replay free ft node, cur_block:%p, node id: %s.", cur_block, dss_display_metaid(node->id));

        status = dss_update_ft_block_disk(vg_item, cur_block, data->node[i].id);
        if (status != CM_SUCCESS) {
            return status;
        }
        rp_insert_block_addr_history(&addr_his, cur_block);
    }
    DSS_LOG_DEBUG_OP("[REDO] Succeed to replay free ft node, vg name:%s.", vg_item->vg_name);
    return CM_SUCCESS;
}

status_t rp_redo_free_ft_node(dss_session_t *session, dss_vg_info_item_t *vg_item, dss_redo_entry_t *entry)
{
    CM_ASSERT(vg_item != NULL);
    CM_ASSERT(entry != NULL);

    dss_redo_free_ft_node_t *data = (dss_redo_free_ft_node_t *)entry->data;
    dss_root_ft_block_t *ft_block = DSS_GET_ROOT_BLOCK(vg_item->dss_ctrl);
    gft_root_t *gft = &ft_block->ft_root;
    bool32 check_version = CM_FALSE;

    if (entry->size == 0) {
        DSS_RETURN_IFERR2(CM_ERROR, DSS_THROW_ERROR(ERR_DSS_REDO_ILL, "invalid entry log size 0."));
    }
    if (vg_item->status == DSS_VG_STATUS_RECOVERY) {
        CM_RETURN_IFERR_EX(dss_refresh_root_ft(vg_item, CM_TRUE, CM_FALSE),
            LOG_DEBUG_ERR("[REDO] Failed to refresh file table root, vg:%s.", vg_item->vg_name));

        *gft = data->ft_root;
        check_version = CM_TRUE;
    }
    return rp_redo_free_ft_node_core(session, vg_item, ft_block, data, check_version);
}

status_t rb_redo_free_ft_node(dss_session_t *session, dss_vg_info_item_t *vg_item, dss_redo_entry_t *entry)
{
    CM_ASSERT(vg_item != NULL);
    CM_ASSERT(entry != NULL);

    dss_redo_free_ft_node_t *data = (dss_redo_free_ft_node_t *)entry->data;

    if (entry->size == 0) {
        DSS_RETURN_IFERR2(CM_ERROR, DSS_THROW_ERROR(ERR_DSS_REDO_ILL, "invalid entry log size 0."));
    }

    return rb_rollback_ft_block(session, vg_item, data->node, DSS_REDO_FREE_FT_NODE_NUM);
}

static void print_redo_free_ft_node(dss_redo_entry_t *entry)
{
    dss_redo_free_ft_node_t *data = (dss_redo_free_ft_node_t *)entry->data;
    (void)printf("    free_ft_node = {\n");
    (void)printf("      ft_root = {\n");
    printf_gft_root(&data->ft_root);
    (void)printf("      }\n");
    for (uint32 i = 0; i < DSS_REDO_FREE_FT_NODE_NUM; i++) {
        if (dss_cmp_auid(data->node[i].id, CM_INVALID_ID64)) {
            continue;
        }
        (void)printf("    gft_node[%u] = {\n", i);
        printf_gft_node(&data->node[i], "    ");
        (void)printf("    }\n");
    }
    (void)printf("    }\n");
}

status_t rp_redo_move_ft_node(dss_session_t *session, dss_vg_info_item_t *vg_item, dss_redo_entry_t *entry)
{
    CM_ASSERT(vg_item != NULL);
    CM_ASSERT(entry != NULL);

    dss_redo_move_ft_node_t *data = (dss_redo_move_ft_node_t *)entry->data;
    bool32 check_version = CM_FALSE;

    if (vg_item->status == DSS_VG_STATUS_RECOVERY) {
        check_version = CM_TRUE;
    }

    if (entry->size == 0) {
        DSS_RETURN_IFERR2(CM_ERROR, DSS_THROW_ERROR(ERR_DSS_REDO_ILL, "invalid entry log size 0."));
    }

    dss_block_addr_his_t addr_his;
    rp_init_block_addr_history(&addr_his);

    gft_node_t *node;
    dss_ft_block_t *cur_block = NULL;

    for (uint32 i = 0; i < DSS_REDO_MOVE_FT_NODE_NUM; i++) {
        if (dss_cmp_auid(data->node[i].id, CM_INVALID_ID64)) {
            continue;
        }
        node = dss_get_ft_node_by_ftid(session, vg_item, data->node[i].id, check_version, CM_FALSE);
        if (node == NULL) {
            DSS_RETURN_IFERR2(CM_ERROR, DSS_THROW_ERROR(ERR_DSS_FNODE_CHECK, "invalid ft node."));
        }

        if (vg_item->status == DSS_VG_STATUS_RECOVERY) {
            *node = data->node[i];
        }

        cur_block = dss_get_ft_by_node(node);
        if (rp_check_block_addr(&addr_his, cur_block) && vg_item->status != DSS_VG_STATUS_RECOVERY) {
            continue;  // already update the block to disk
        }
        CM_RETURN_IFERR(dss_update_ft_block_disk(vg_item, cur_block, data->node[i].id));
        rp_insert_block_addr_history(&addr_his, cur_block);
    }
    LOG_DEBUG_INF("[REDO] Succeed to replay recycle ft node, vg name:%s.", vg_item->vg_name);
    return CM_SUCCESS;
}

status_t rb_redo_move_ft_node(dss_session_t *session, dss_vg_info_item_t *vg_item, dss_redo_entry_t *entry)
{
    CM_ASSERT(vg_item != NULL);
    CM_ASSERT(entry != NULL);

    status_t status;
    dss_redo_move_ft_node_t *data = (dss_redo_move_ft_node_t *)entry->data;
    bool32 check_version = CM_FALSE;

    if (entry->size == 0) {
        DSS_RETURN_IFERR2(CM_ERROR, DSS_THROW_ERROR(ERR_DSS_REDO_ILL, "invalid entry log size 0."));
    }

    gft_node_t *node;
    dss_ft_block_t *cur_block = NULL;
    bool32 cmp;
    for (uint32 i = 0; i < DSS_REDO_MOVE_FT_NODE_NUM; i++) {
        cmp = dss_cmp_auid(data->node[i].id, CM_INVALID_ID64);
        if (cmp) {
            continue;
        }
        node = dss_get_ft_node_by_ftid(session, vg_item, data->node[i].id, check_version, CM_FALSE);
        if (!node) {
            DSS_RETURN_IFERR2(CM_ERROR, DSS_THROW_ERROR(ERR_DSS_FNODE_CHECK, "invalid ft node."));
        }

        cur_block = dss_get_ft_by_node(node);
        int64 offset = dss_get_ft_block_offset(vg_item, data->node[i].id);
        status = dss_get_block_from_disk(
            vg_item, data->node[i].id, (char *)cur_block, offset, (int32)DSS_BLOCK_SIZE, CM_TRUE);
        DSS_RETURN_IF_ERROR(status);
    }
    return CM_SUCCESS;
}

static void print_redo_move_ft_node(dss_redo_entry_t *entry)
{
    dss_redo_move_ft_node_t *data = (dss_redo_move_ft_node_t *)entry->data;
    (void)printf("    move_ft_node = {\n");
    for (uint32 i = 0; i < DSS_REDO_MOVE_FT_NODE_NUM; i++) {
        if (dss_cmp_auid(data->node[i].id, CM_INVALID_ID64)) {
            continue;
        }
        (void)printf("    gft_node[%u] = {\n", i);
        printf_gft_node(&data->node[i], "    ");
        (void)printf("    }\n");
    }
    (void)printf("    }\n");
}

static status_t rp_redo_remove_ft_node_core(dss_session_t *session, dss_vg_info_item_t *vg_item,
    dss_root_ft_block_t *ft_block, dss_redo_remove_ft_node_t *data, bool32 check_version)
{
    status_t status = CM_SUCCESS;
    dss_block_addr_his_t addr_his;
    rp_init_block_addr_history(&addr_his);
    rp_insert_block_addr_history(&addr_his, ft_block);

    gft_node_t *node;
    dss_ft_block_t *cur_block = NULL;
    bool32 cmp;
    for (uint32 i = 0; i < DSS_REDO_REMOVE_FT_NODE_NUM; i++) {
        cmp = dss_cmp_auid(data->node[i].id, CM_INVALID_ID64);
        if (cmp) {
            continue;
        }
        node = dss_get_ft_node_by_ftid(session, vg_item, data->node[i].id, check_version, CM_FALSE);
        if (!node) {
            return CM_ERROR;
        }
        cur_block = dss_get_ft_by_node(node);
        if (vg_item->status == DSS_VG_STATUS_RECOVERY) {
            *node = data->node[i];
        }

        cur_block = dss_get_ft_by_node(node);
        if (rp_check_block_addr(&addr_his, cur_block) && vg_item->status != DSS_VG_STATUS_RECOVERY) {
            DSS_LOG_DEBUG_OP("[REDO] Replay remove ft node, block has updated, cur_block:%p, node id: %s.", cur_block,
                dss_display_metaid(node->id));
            continue;  // already update the block to disk
        }

        DSS_LOG_DEBUG_OP(
            "[REDO] Replay remove ft node, cur_block:%p, node id: %s.", cur_block, dss_display_metaid(node->id));

        status = dss_update_ft_block_disk(vg_item, cur_block, data->node[i].id);
        if (status != CM_SUCCESS) {
            return status;
        }
        rp_insert_block_addr_history(&addr_his, cur_block);
    }
    DSS_LOG_DEBUG_OP("[REDO] Succeed to replay remove ft node, vg name:%s.", vg_item->vg_name);
    return CM_SUCCESS;
}

status_t rp_redo_remove_ft_node(dss_session_t *session, dss_vg_info_item_t *vg_item, dss_redo_entry_t *entry)
{
    CM_ASSERT(vg_item != NULL);
    CM_ASSERT(entry != NULL);

    dss_redo_remove_ft_node_t *data = (dss_redo_remove_ft_node_t *)entry->data;
    dss_root_ft_block_t *ft_block = DSS_GET_ROOT_BLOCK(vg_item->dss_ctrl);
    if (entry->size == 0) {
        DSS_RETURN_IFERR2(CM_ERROR, DSS_THROW_ERROR(ERR_DSS_REDO_ILL, "invalid entry log size 0."));
    }

    bool32 check_version = (vg_item->status == DSS_VG_STATUS_RECOVERY);
    return rp_redo_remove_ft_node_core(session, vg_item, ft_block, data, check_version);
}

status_t rb_redo_remove_ft_node(dss_session_t *session, dss_vg_info_item_t *vg_item, dss_redo_entry_t *entry)
{
    CM_ASSERT(vg_item != NULL);
    CM_ASSERT(entry != NULL);

    dss_redo_remove_ft_node_t *data = (dss_redo_remove_ft_node_t *)entry->data;

    if (entry->size == 0) {
        DSS_RETURN_IFERR2(CM_ERROR, DSS_THROW_ERROR(ERR_DSS_REDO_ILL, "invalid entry log size 0."));
    }

    return rb_rollback_ft_block(session, vg_item, data->node, DSS_REDO_REMOVE_FT_NODE_NUM);
}

static void print_redo_remove_ft_node(dss_redo_entry_t *entry)
{
    dss_redo_remove_ft_node_t *data = (dss_redo_remove_ft_node_t *)entry->data;
    (void)printf("    remove_ft_node = {\n");
    (void)printf("      ft_root = {\n");
    printf_gft_root(&data->ft_root);
    (void)printf("      }\n");
    for (uint32 i = 0; i < DSS_REDO_REMOVE_FT_NODE_NUM; i++) {
        if (dss_cmp_auid(data->node[i].id, CM_INVALID_ID64)) {
            continue;
        }
        (void)printf("    gft_node[%u] = {\n", i);
        printf_gft_node(&data->node[i], "    ");
        (void)printf("    }\n");
    }
    (void)printf("    }\n");
}

static status_t rp_redo_set_file_size_inner(
    dss_session_t *session, dss_vg_info_item_t *vg_item, dss_redo_entry_t *entry, ftid_t *ftid)
{
    CM_ASSERT(vg_item != NULL);
    CM_ASSERT(entry != NULL);
    bool32 check_version = CM_FALSE;
    if (vg_item->status == DSS_VG_STATUS_RECOVERY) {
        check_version = CM_TRUE;
    }
    if (entry->size == 0) {
        DSS_RETURN_IFERR2(CM_ERROR, DSS_THROW_ERROR(ERR_DSS_REDO_ILL, "invalid entry log size 0."));
    }
    gft_node_t *node;
    dss_ft_block_t *cur_block = NULL;
    dss_redo_set_file_size_t *set_file_size = (dss_redo_set_file_size_t *)entry->data;
    *ftid = set_file_size->ftid;
    node = dss_get_ft_node_by_ftid(session, vg_item, *ftid, check_version, CM_FALSE);
    if (!node) {
        DSS_RETURN_IFERR2(CM_ERROR, DSS_THROW_ERROR(ERR_DSS_FNODE_CHECK, "invalid ft node."));
    }
    dss_redo_set_file_size_t *size_info = (dss_redo_set_file_size_t *)entry->data;
    DSS_LOG_DEBUG_OP("[REDO] Begin to replay set file: %s, size:%llu, oldsize:%llu, node size:%llu, vg name:%s.",
        dss_display_metaid(size_info->ftid), size_info->size, size_info->oldsize, node->size, vg_item->vg_name);

    if (vg_item->status == DSS_VG_STATUS_RECOVERY) {
        node->size = set_file_size->size;
        if (node->written_size > (uint64)node->size) {
            node->written_size = (uint64)node->size;
        }
        if (node->min_inited_size > (uint64)node->size) {
            node->min_inited_size = (uint64)node->size;
        }
    }
    if (set_file_size->size < set_file_size->oldsize) {
        node->file_ver++;
        LOG_RUN_INF("Update ft block: %s file_ver to:%llu.", dss_display_metaid(*ftid), node->file_ver);
    }
    cur_block = dss_get_ft_by_node(node);
    CM_RETURN_IFERR_EX(dss_update_ft_block_disk(vg_item, cur_block, *ftid),
        LOG_DEBUG_ERR("[REDO] Failed to update ft block: %s to disk.", dss_display_metaid(*ftid)));

    dss_block_ctrl_t *block_ctrl = DSS_GET_BLOCK_CTRL_FROM_META(cur_block);
    dss_add_syn_meta(vg_item, block_ctrl, cur_block->common.version);

    return CM_SUCCESS;
}

status_t rp_redo_set_file_size(dss_session_t *session, dss_vg_info_item_t *vg_item, dss_redo_entry_t *entry)
{
    ftid_t ftid;
    if (rp_redo_set_file_size_inner(session, vg_item, entry, &ftid) != CM_SUCCESS) {
        return CM_ERROR;
    }
    DSS_LOG_DEBUG_OP(
        "[REDO] Succeed to replay set file: %s size, vg name:%s.", dss_display_metaid(ftid), vg_item->vg_name);
    return CM_SUCCESS;
}

static status_t rb_redo_get_ft_node(
    dss_session_t *session, dss_vg_info_item_t *vg_item, dss_redo_entry_t *entry, ftid_t ftid, gft_node_t **node)
{
    bool32 check_version = CM_FALSE;
    if (entry->size == 0) {
        DSS_RETURN_IFERR2(CM_ERROR, DSS_THROW_ERROR(ERR_DSS_REDO_ILL, "invalid entry log size 0."));
    }

    *node = dss_get_ft_node_by_ftid(session, vg_item, ftid, check_version, CM_FALSE);
    if (!(*node)) {
        DSS_RETURN_IFERR2(CM_ERROR, DSS_THROW_ERROR(ERR_DSS_FNODE_CHECK, "invalid ft node."));
    }
    return CM_SUCCESS;
}

status_t rb_redo_set_file_size(dss_session_t *session, dss_vg_info_item_t *vg_item, dss_redo_entry_t *entry)
{
    CM_ASSERT(vg_item != NULL);
    CM_ASSERT(entry != NULL);
    dss_redo_set_file_size_t *data = (dss_redo_set_file_size_t *)entry->data;
    gft_node_t *node;
    DSS_RETURN_IF_ERROR(rb_redo_get_ft_node(session, vg_item, entry, data->ftid, &node));
    node->size = data->oldsize;
    return CM_SUCCESS;
}

static void print_redo_set_file_size(dss_redo_entry_t *entry)
{
    dss_redo_set_file_size_t *data = (dss_redo_set_file_size_t *)entry->data;
    (void)printf("    set_file_size = {\n");
    (void)printf("     ftid = {\n");
    printf_auid(&data->ftid);
    (void)printf("      }\n");
    (void)printf("     size = %llu\n", data->size);
    (void)printf("     oldsize = %llu\n", data->oldsize);
    (void)printf("    }\n");
}

status_t rp_redo_format_fs_block(dss_session_t *session, dss_vg_info_item_t *vg_item, dss_redo_entry_t *entry)
{
    CM_ASSERT(vg_item != NULL);
    CM_ASSERT(entry != NULL);

    status_t status;
    dss_redo_format_fs_t *data = (dss_redo_format_fs_t *)entry->data;

    if (vg_item->status == DSS_VG_STATUS_RECOVERY) {
        status = dss_check_refresh_core(vg_item);
        DSS_RETURN_IFERR2(status, LOG_DEBUG_ERR("[REDO] Failed to refresh vg core:%s.", vg_item->vg_name));
        dss_fs_block_root_t *block_root = DSS_GET_FS_BLOCK_ROOT(vg_item->dss_ctrl);
        block_root->free = data->old_free_list;
        status = dss_format_bitmap_node(session, vg_item, data->auid);
        DSS_RETURN_IFERR2(
            status, LOG_DEBUG_ERR("[REDO] Fail to format file space node: %s.", dss_display_metaid(data->auid)));
    }

    status = dss_update_core_ctrl_disk(vg_item);
    DSS_RETURN_IFERR2(status, LOG_DEBUG_ERR("[REDO] Fail to write ctrl to disk, vg:%s.", vg_item->vg_name));
    dss_block_id_t first = data->auid;
    ga_obj_id_t obj_id;
    status = dss_find_block_objid_in_shm(session, vg_item, first, DSS_BLOCK_TYPE_FS, &obj_id);
    DSS_RETURN_IFERR2(status, LOG_DEBUG_ERR("[REDO] Fail to find block: %s.", dss_display_metaid(first)));

    status =
        dss_update_au_disk(vg_item, data->auid, GA_16K_POOL, obj_id.obj_id, data->count, DSS_FILE_SPACE_BLOCK_SIZE);
    DSS_RETURN_IFERR2(status, LOG_DEBUG_ERR("[REDO] Fail to update au: %s.", dss_display_metaid(data->auid)));
    DSS_LOG_DEBUG_OP("[REDO] Succeed to replay format fs block au: %s, vg name:%s.", dss_display_metaid(data->auid),
        vg_item->vg_name);
    return CM_SUCCESS;
}

void rb_redo_clean_resource(
    dss_session_t *session, dss_vg_info_item_t *item, auid_t auid, ga_pool_id_e pool_id, uint32 first, uint32 count)
{
    dss_fs_block_header *block;
    uint32 obj_id = first;
    uint32 last = first;
    CM_ASSERT(count > 0);
    for (uint32 i = 0; i < count; i++) {
        block = (dss_fs_block_header *)dss_buffer_get_meta_addr(pool_id, obj_id);
        CM_ASSERT(block != NULL);
        dss_unregister_buffer_cache(session, item, block->common.id);
        if (i == count - 1) {
            last = obj_id;
        }
        obj_id = ga_next_object(pool_id, obj_id);
    }
    ga_queue_t queue;
    queue.count = count;
    queue.first = first;
    queue.last = last;
    ga_free_object_list(pool_id, &queue);
}

status_t rb_redo_format_fs_block(dss_session_t *session, dss_vg_info_item_t *vg_item, dss_redo_entry_t *entry)
{
    CM_ASSERT(vg_item != NULL);
    CM_ASSERT(entry != NULL);

    status_t status;
    bool32 remote = CM_FALSE;
    dss_redo_format_fs_t *data = (dss_redo_format_fs_t *)entry->data;

    dss_block_id_t first = data->auid;
    ga_obj_id_t obj_id;
    status = dss_find_block_objid_in_shm(session, vg_item, first, DSS_BLOCK_TYPE_FS, &obj_id);
    DSS_RETURN_IFERR2(status, LOG_DEBUG_ERR("Failed to find block: %s.", dss_display_metaid(first)));
    rb_redo_clean_resource(session, vg_item, data->auid, GA_16K_POOL, obj_id.obj_id, data->count);
    status = dss_load_vg_ctrl_part(
        vg_item, (int64)DSS_CTRL_CORE_OFFSET, vg_item->dss_ctrl->core_data, DSS_DISK_UNIT_SIZE, &remote);
    DSS_RETURN_IFERR2(status, LOG_DEBUG_ERR("Failed to load vg:%s.", vg_item->vg_name));
    return CM_SUCCESS;
}

static void print_redo_format_fs_block(dss_redo_entry_t *entry)
{
    dss_redo_format_fs_t *data = (dss_redo_format_fs_t *)entry->data;
    (void)printf("    format_fs = {\n");
    (void)printf("     auid = {\n");
    printf_auid(&data->auid);
    (void)printf("      }\n");
    (void)printf("     obj_id = %u\n", data->obj_id);
    (void)printf("     count = %u\n", data->count);
    (void)printf("     old_free_list = {\n");
    printf_dss_fs_block_list(&data->old_free_list);
    (void)printf("      }\n");
    (void)printf("    }\n");
}

static status_t rp_redo_set_node_flag(dss_session_t *session, dss_vg_info_item_t *vg_item, dss_redo_entry_t *entry)
{
    CM_ASSERT(vg_item != NULL);
    CM_ASSERT(entry != NULL);

    if (entry->size == 0) {
        DSS_RETURN_IFERR2(CM_ERROR, DSS_THROW_ERROR(ERR_DSS_REDO_ILL, "invalid entry log size 0."));
    }
    gft_node_t *node;
    dss_ft_block_t *cur_block = NULL;
    dss_redo_set_file_flag_t *file_flag = (dss_redo_set_file_flag_t *)entry->data;

    bool32 check_version = CM_FALSE;
    if (vg_item->status == DSS_VG_STATUS_RECOVERY) {
        check_version = CM_TRUE;
    }
    node = dss_get_ft_node_by_ftid(session, vg_item, file_flag->ftid, check_version, CM_FALSE);
    if (!node) {
        DSS_RETURN_IFERR2(CM_ERROR, DSS_THROW_ERROR(ERR_DSS_FNODE_CHECK, "invalid ft node."));
    }
    LOG_DEBUG_INF("[REDO] Begin to replay set file: %s, flags:%u, old_flags:%u, vg_name:%s.",
        dss_display_metaid(file_flag->ftid), file_flag->flags, file_flag->old_flags, vg_item->vg_name);

    if (vg_item->status == DSS_VG_STATUS_RECOVERY) {
        node->flags = file_flag->flags;
    }
    cur_block = dss_get_ft_by_node(node);
    CM_RETURN_IFERR_EX(dss_update_ft_block_disk(vg_item, cur_block, file_flag->ftid),
        LOG_DEBUG_ERR("[REDO] Failed to update ft block: %s, vg_name:%s to disk.", dss_display_metaid(file_flag->ftid),
            vg_item->vg_name));

    dss_block_ctrl_t *block_ctrl = DSS_GET_BLOCK_CTRL_FROM_META(cur_block);
    dss_add_syn_meta(vg_item, block_ctrl, cur_block->common.version);

    LOG_DEBUG_INF("[REDO] Succeed to replay set file: %s, flags:%u, old_flag:%u, vg_name:%s.",
        dss_display_metaid(file_flag->ftid), file_flag->flags, file_flag->old_flags, vg_item->vg_name);

    return CM_SUCCESS;
}

static status_t rb_redo_set_node_flag(dss_session_t *session, dss_vg_info_item_t *vg_item, dss_redo_entry_t *entry)
{
    CM_ASSERT(vg_item != NULL);
    CM_ASSERT(entry != NULL);

    if (entry->size == 0) {
        DSS_RETURN_IFERR2(CM_ERROR, DSS_THROW_ERROR(ERR_DSS_REDO_ILL, "invalid entry log size 0."));
    }
    gft_node_t *node;
    dss_ft_block_t *cur_block = NULL;
    dss_redo_set_file_flag_t *file_flag = (dss_redo_set_file_flag_t *)entry->data;

    node = dss_get_ft_node_by_ftid(session, vg_item, file_flag->ftid, CM_FALSE, CM_FALSE);
    if (!node) {
        DSS_RETURN_IFERR2(CM_ERROR, DSS_THROW_ERROR(ERR_DSS_FNODE_CHECK, "invalid ft node."));
    }
    LOG_DEBUG_INF("[REDO] Begin to replay rollback set file: %s, flags:%u, old_flags:%u, vg_name:%s.",
        dss_display_metaid(file_flag->ftid), file_flag->flags, file_flag->old_flags, vg_item->vg_name);

    node->flags = file_flag->old_flags;

    cur_block = dss_get_ft_by_node(node);
    CM_RETURN_IFERR_EX(dss_update_ft_block_disk(vg_item, cur_block, file_flag->ftid),
        LOG_DEBUG_ERR("[REDO] Failed to update ft block: %s, vg_name:%s to disk.", dss_display_metaid(file_flag->ftid),
            vg_item->vg_name));
    LOG_DEBUG_INF("[REDO] Succeed to replay rollback set file: %s, flags:%u, old_flag:%u, vg_name:%s.",
        dss_display_metaid(file_flag->ftid), file_flag->flags, file_flag->old_flags, vg_item->vg_name);
    return CM_SUCCESS;
}

static void print_redo_set_node_flag(dss_redo_entry_t *entry)
{
    dss_redo_set_file_flag_t *data = (dss_redo_set_file_flag_t *)entry->data;
    (void)printf("    set_file_flag = {\n");
    (void)printf("     id = {\n");
    printf_auid(&data->ftid);
    (void)printf("      }\n");
    (void)printf("     flags = %u\n", data->flags);
    (void)printf("     old_flags = %u\n", data->old_flags);
    (void)printf("    }\n");
}

status_t rp_redo_set_fs_block_batch(dss_session_t *session, dss_vg_info_item_t *vg_item, dss_redo_entry_t *entry)
{
    CM_ASSERT(vg_item != NULL);
    CM_ASSERT(entry != NULL);

    status_t status;
    dss_redo_set_fs_block_batch_t *data = (dss_redo_set_fs_block_batch_t *)entry->data;

    dss_fs_block_t *block;
    bool32 check_version = CM_FALSE;

    if (vg_item->status == DSS_VG_STATUS_RECOVERY) {
        check_version = CM_TRUE;
    }

    block = (dss_fs_block_t *)dss_find_block_in_shm(
        session, vg_item, data->id, DSS_BLOCK_TYPE_FS, check_version, NULL, CM_FALSE);
    if (block == NULL) {
        DSS_RETURN_IFERR2(CM_ERROR, DSS_THROW_ERROR(ERR_DSS_FNODE_CHECK, "invalid block"));
    }

    if (vg_item->status == DSS_VG_STATUS_RECOVERY) {
        for (uint16 i = data->old_used_num, j = 0; i < data->used_num; i++, j++) {
            block->bitmap[i] = data->id_set[j];
        }
    }

    status = dss_update_fs_bitmap_block_disk(vg_item, block, DSS_FILE_SPACE_BLOCK_SIZE, CM_FALSE);
    DSS_RETURN_IFERR2(status, LOG_DEBUG_ERR("Failed to update fs batch block:%llu to disk.", DSS_ID_TO_U64(data->id)));

    dss_block_ctrl_t *block_ctrl = DSS_GET_BLOCK_CTRL_FROM_META(block);
    dss_add_syn_meta(vg_item, block_ctrl, block->head.common.version);

    DSS_LOG_DEBUG_OP("Succeed to replay set fs batch block:%llu, used_num:%hu, vg name:%s.", DSS_ID_TO_U64(data->id),
        block->head.used_num, vg_item->vg_name);
    return CM_SUCCESS;
}

status_t rb_redo_set_fs_block_batch(dss_session_t *session, dss_vg_info_item_t *vg_item, dss_redo_entry_t *entry)
{
    CM_ASSERT(vg_item != NULL);
    CM_ASSERT(entry != NULL);

    dss_redo_set_fs_block_batch_t *data = (dss_redo_set_fs_block_batch_t *)entry->data;
    dss_fs_block_t *block;
    bool32 check_version = CM_FALSE;

    block = (dss_fs_block_t *)dss_find_block_in_shm(
        session, vg_item, data->id, DSS_BLOCK_TYPE_FS, check_version, NULL, CM_FALSE);
    if (block == NULL) {
        DSS_RETURN_IFERR2(CM_ERROR, DSS_THROW_ERROR(ERR_DSS_FNODE_CHECK, "invalid block"));
    }
    if (data->old_used_num > 0) {
        block->bitmap[data->old_used_num - 1] = dss_invalid_auid;
    }
    block->head.used_num = data->old_used_num;
    return CM_SUCCESS;
}

static void print_redo_set_fs_block_batch(dss_redo_entry_t *entry)
{
    dss_redo_set_fs_block_batch_t *data = (dss_redo_set_fs_block_batch_t *)entry->data;
    (void)printf("    set_fs_block_batch = {\n");
    (void)printf("     id = {\n");
    printf_auid(&data->id);
    (void)printf("      }\n");
    (void)printf("     used_num = %hu\n", data->used_num);
    (void)printf("     old_used_num = %hu\n", data->old_used_num);
    for (uint16 i = data->old_used_num, j = 0; i < data->used_num; i++, j++) {
        (void)printf("     id_set[%hu] = {\n", j);
        printf_auid(&data->id_set[j]);
        (void)printf("      }\n");
    }
    (void)printf("    }\n");
}

status_t rp_redo_set_fs_aux_block_batch_in_recovery(dss_session_t *session, dss_vg_info_item_t *vg_item,
    dss_redo_entry_t *entry, dss_fs_block_t *second_block, gft_node_t *node)
{
    dss_redo_set_fs_aux_block_batch_t *data = (dss_redo_set_fs_aux_block_batch_t *)entry->data;
    status_t status = dss_check_refresh_core(vg_item);
    DSS_RETURN_IFERR2(status, LOG_RUN_ERR("[REDO][FS AUX]Failed to refresh vg core:%s.", vg_item->vg_name));
    dss_fs_aux_root_t *root = DSS_GET_FS_AUX_ROOT(vg_item->dss_ctrl);
    uint16 batch_count = data->batch_count;
    uint16 block_au_count = data->old_used_num;
    uint16 index;
    dss_block_id_t block_id;
    dss_fs_aux_t *fs_aux = NULL;
    auid_t auid;
    auid_t batch_first = data->first_batch_au;
    for (uint32 i = 0, j = block_au_count; i < batch_count; i++, j++) {
        auid = batch_first;
        index = (uint16)j;
        block_id = data->id_set[i];
        fs_aux = (dss_fs_aux_t *)dss_find_block_in_shm(
            session, vg_item, block_id, DSS_BLOCK_TYPE_FS_AUX, CM_TRUE, NULL, CM_FALSE);
        if (fs_aux == NULL) {
            LOG_RUN_ERR("[REDO][FS AUX]Failed to find fs_aux %s.", dss_display_metaid(block_id));
            return CM_ERROR;
        }
        dss_init_fs_aux_head(fs_aux, node->id, index);
        dss_set_blockid(&fs_aux->head.data_id, DSS_BLOCK_ID_SET_UNINITED(auid));
        fs_aux->head.ftid = node->id;
        LOG_RUN_INF("[REDO][FS AUX]Init fs aux, fs aux id:%s, data_id:%s.", dss_display_metaid(fs_aux->head.common.id),
            dss_display_metaid(fs_aux->head.data_id));
        dss_set_blockid(&auid, DSS_BLOCK_ID_SET_AUX(fs_aux->head.common.id));
        dss_updt_fs_aux_file_ver(node, fs_aux);
        second_block->bitmap[j] = auid;
        LOG_RUN_INF("[REDO][FS AUX]second block %s, bitmap %u, fs_aux %s, au %s.",
            dss_display_metaid(second_block->head.common.id), j, dss_display_metaid(fs_aux->head.common.id),
            dss_display_metaid(batch_first));
        status = dss_update_fs_aux_bitmap2disk(vg_item, fs_aux, DSS_FS_AUX_SIZE, CM_FALSE);
        DSS_RETURN_IFERR2(
            status, LOG_RUN_ERR("[REDO][FS AUX]Failed to update fs aux bitmap fs_aux:%s to disk, vg name:%s.",
                        dss_display_metaid(block_id), vg_item->vg_name));
        LOG_RUN_INF("[REDO][FS AUX]Succeed to replay alloc fs aux fs_aux:%s, vg name:%s.", dss_display_metaid(block_id),
            vg_item->vg_name);
        batch_first.au++;
    }
    root->free = data->new_free_list;
    second_block->head.used_num = data->old_used_num + (uint16)batch_count;
    return CM_SUCCESS;
}

status_t rp_redo_set_fs_aux_block_batch_inner(dss_session_t *session, dss_vg_info_item_t *vg_item,
    dss_redo_entry_t *entry, dss_fs_block_t *second_block, gft_node_t *node)
{
    status_t status;
    dss_redo_set_fs_aux_block_batch_t *data = (dss_redo_set_fs_aux_block_batch_t *)entry->data;
    uint16 batch_count = data->batch_count;
    dss_block_id_t block_id;
    dss_fs_aux_t *fs_aux = NULL;
    for (uint32 i = 0; i < batch_count; i++) {
        block_id = data->id_set[i];
        fs_aux = (dss_fs_aux_t *)dss_find_block_in_shm(
            session, vg_item, block_id, DSS_BLOCK_TYPE_FS_AUX, CM_FALSE, NULL, CM_FALSE);
        if (fs_aux == NULL) {
            LOG_RUN_ERR("[REDO][FS AUX]Failed to find fs_aux %s.", dss_display_metaid(block_id));
            return CM_ERROR;
        }
        status = dss_update_fs_aux_bitmap2disk(vg_item, fs_aux, DSS_FS_AUX_SIZE, CM_FALSE);
        DSS_RETURN_IFERR2(
            status, LOG_RUN_ERR("[REDO][FS AUX]Failed to update fs aux bitmap fs_aux:%s to disk, vg name:%s.",
                        dss_display_metaid(block_id), vg_item->vg_name));
        LOG_DEBUG_INF("[REDO][FS AUX]Succeed to replay alloc fs aux:%s, vg name:%s.", dss_display_metaid(block_id),
            vg_item->vg_name);
    }
    return CM_SUCCESS;
}

status_t rp_redo_set_fs_aux_block_batch(dss_session_t *session, dss_vg_info_item_t *vg_item, dss_redo_entry_t *entry)
{
    CM_ASSERT(vg_item != NULL);
    CM_ASSERT(entry != NULL);

    status_t status;
    dss_redo_set_fs_aux_block_batch_t *data = (dss_redo_set_fs_aux_block_batch_t *)entry->data;
    bool32 check_version = CM_FALSE;
    if (vg_item->status == DSS_VG_STATUS_RECOVERY) {
        check_version = CM_TRUE;
    }
    dss_fs_block_t *block = (dss_fs_block_t *)dss_find_block_in_shm(
        session, vg_item, data->fs_block_id, DSS_BLOCK_TYPE_FS, check_version, NULL, CM_FALSE);
    if (block == NULL) {
        DSS_RETURN_IFERR2(CM_ERROR, DSS_THROW_ERROR(ERR_DSS_FNODE_CHECK, "invalid block"));
    }
    gft_node_t *node = dss_get_ft_node_by_ftid(session, vg_item, data->node_id, check_version, CM_FALSE);
    if (node == NULL) {
        DSS_RETURN_IFERR2(CM_ERROR, DSS_THROW_ERROR(ERR_DSS_FNODE_CHECK, "invalid ft node"));
    }
    if (vg_item->status == DSS_VG_STATUS_RECOVERY) {
        status = rp_redo_set_fs_aux_block_batch_in_recovery(session, vg_item, entry, block, node);
    } else {
        status = rp_redo_set_fs_aux_block_batch_inner(session, vg_item, entry, block, node);
    }
    DSS_RETURN_IF_ERROR(status);
    status = dss_update_core_ctrl_disk(vg_item);
    DSS_RETURN_IFERR2(status, LOG_RUN_ERR("[REDO][FS AUX]Failed to update vg core:%s to disk.", vg_item->vg_name));
    status = dss_update_fs_bitmap_block_disk(vg_item, block, DSS_FILE_SPACE_BLOCK_SIZE, CM_FALSE);
    DSS_RETURN_IFERR2(status,
        LOG_RUN_ERR("[REDO][FS AUX]Failed to update fs batch block:%llu to disk.", DSS_ID_TO_U64(data->fs_block_id)));
    dss_block_ctrl_t *block_ctrl = DSS_GET_BLOCK_CTRL_FROM_META(block);
    dss_add_syn_meta(vg_item, block_ctrl, block->head.common.version);
    DSS_LOG_DEBUG_OP("Succeed to replay set fs batch block:%llu, used_num:%hu, vg name:%s.",
        DSS_ID_TO_U64(data->fs_block_id), block->head.used_num, vg_item->vg_name);
    return CM_SUCCESS;
}

status_t rb_redo_set_fs_aux_block_batch(dss_session_t *session, dss_vg_info_item_t *vg_item, dss_redo_entry_t *entry)
{
    CM_ASSERT(vg_item != NULL);
    CM_ASSERT(entry != NULL);

    dss_redo_set_fs_aux_block_batch_t *data = (dss_redo_set_fs_aux_block_batch_t *)entry->data;
    dss_fs_block_t *block = (dss_fs_block_t *)dss_find_block_from_disk_and_refresh_shm(
        session, vg_item, data->fs_block_id, DSS_BLOCK_TYPE_FS, NULL);
    if (block == NULL) {
        DSS_RETURN_IFERR2(CM_ERROR, DSS_THROW_ERROR(ERR_DSS_FNODE_CHECK, "invalid block"));
    }
    gft_node_t *node = dss_get_ft_node_by_ftid_from_disk_and_refresh_shm(session, vg_item, data->node_id);
    if (node == NULL) {
        DSS_RETURN_IFERR2(CM_ERROR, DSS_THROW_ERROR(ERR_DSS_FNODE_CHECK, "invalid ft node."));
    }
    dss_fs_aux_t *fs_aux = NULL;
    dss_block_id_t block_id;
    uint16 batch_count = data->batch_count;
    for (uint32 i = 0; i < batch_count; i++) {
        block_id = data->id_set[i];
        LOG_RUN_INF("[REDO][FS AUX]begin to rollback fs_aux %s in shm.", dss_display_metaid(block_id));
        fs_aux = (dss_fs_aux_t *)dss_find_block_from_disk_and_refresh_shm(
            session, vg_item, block_id, DSS_BLOCK_TYPE_FS_AUX, NULL);
        CM_ASSERT(fs_aux != NULL);
        (void)memset_s(&fs_aux->bitmap[0], fs_aux->head.bitmap_num, 0xFF, fs_aux->head.bitmap_num);
        LOG_RUN_INF("[REDO][FS AUX]end to rollback fs_aux %s in shm.", dss_display_metaid(block_id));
    }
    LOG_RUN_INF("[REDO][FS AUX]begin to rollback block %s in shm.", dss_display_metaid(data->fs_block_id));
    block->bitmap[data->old_used_num] = dss_invalid_auid;
    block->head.used_num = data->old_used_num;
    status_t status = rb_reload_fs_aux_root(vg_item);
    DSS_RETURN_IFERR2(status, LOG_RUN_ERR("[REDO][FS AUX]Failed to update fs aux root fs aux id disk."));
    return CM_SUCCESS;
}

static void print_redo_set_fs_aux_block_batch(dss_redo_entry_t *entry)
{
    dss_redo_set_fs_aux_block_batch_t *data = (dss_redo_set_fs_aux_block_batch_t *)entry->data;
    (void)printf("    fs_aux_block_batch = {\n");
    (void)printf("     fs_block_id = {\n");
    printf_auid(&data->fs_block_id);
    (void)printf("      }\n");
    (void)printf("     first_batch_au = {\n");
    printf_auid(&data->first_batch_au);
    (void)printf("      }\n");
    (void)printf("     node_id = {\n");
    printf_auid(&data->node_id);
    (void)printf("      }\n");
    (void)printf("     old_used_num = %hu\n", data->old_used_num);
    (void)printf("     batch_count = %hu\n", data->batch_count);
    (void)printf("     new_free_list = {\n");
    printf_dss_fs_block_list(&data->new_free_list);
    (void)printf("      }\n");
    for (uint16 i = 0; i < data->batch_count; i++) {
        (void)printf("     id_set[%hu] = {\n", i);
        printf_auid(&data->id_set[i]);
        (void)printf("      }\n");
    }
    (void)printf("    }\n");
}

status_t rp_redo_truncate_fs_block_batch(dss_session_t *session, dss_vg_info_item_t *vg_item, dss_redo_entry_t *entry)
{
    CM_ASSERT(vg_item != NULL);
    CM_ASSERT(entry != NULL);

    status_t status;
    dss_redo_truncate_fs_block_batch_t *redo = (dss_redo_truncate_fs_block_batch_t *)entry->data;

    bool32 check_version = CM_FALSE;

    if (vg_item->status == DSS_VG_STATUS_RECOVERY) {
        check_version = CM_TRUE;
    }

    dss_fs_block_t *src_block = (dss_fs_block_t *)dss_find_block_in_shm(
        session, vg_item, redo->src_id, DSS_BLOCK_TYPE_FS, check_version, NULL, CM_FALSE);
    if (src_block == NULL) {
        DSS_RETURN_IFERR2(CM_ERROR, DSS_THROW_ERROR(ERR_DSS_FNODE_CHECK, "invalid block"));
    }
    dss_fs_block_t *dst_block = (dss_fs_block_t *)dss_find_block_in_shm(
        session, vg_item, redo->dst_id, DSS_BLOCK_TYPE_FS, check_version, NULL, CM_FALSE);
    if (dst_block == NULL) {
        DSS_RETURN_IFERR2(CM_ERROR, DSS_THROW_ERROR(ERR_DSS_FNODE_CHECK, "invalid block"));
    }
    uint16 src_begin = redo->src_begin;
    uint16 dst_begin = redo->dst_begin;
    if (vg_item->status == DSS_VG_STATUS_RECOVERY) {
        MEMS_RETURN_IFERR(memcpy_s(&dst_block->bitmap[dst_begin], sizeof(dss_block_id_t) * redo->count,
            &redo->id_set[0], sizeof(dss_block_id_t) * redo->count));
        for (uint16 i = 0; i < redo->count; i++) {
            dss_set_blockid(&src_block->bitmap[src_begin], DSS_INVALID_64);
            dst_begin++;
            src_begin++;
        }
        src_block->head.used_num = (uint16_t)(redo->src_old_used_num - redo->count);
        dst_block->head.used_num = redo->dst_old_used_num + redo->count;
    }

    status = dss_update_fs_bitmap_block_disk(vg_item, src_block, DSS_FILE_SPACE_BLOCK_SIZE, CM_FALSE);
    DSS_RETURN_IFERR2(
        status, LOG_DEBUG_ERR("Failed to update fs batch block:%llu to disk.", DSS_ID_TO_U64(redo->src_id)));
    status = dss_update_fs_bitmap_block_disk(vg_item, dst_block, DSS_FILE_SPACE_BLOCK_SIZE, CM_FALSE);
    DSS_RETURN_IFERR2(
        status, LOG_DEBUG_ERR("Failed to update fs batch block:%llu to disk.", DSS_ID_TO_U64(redo->dst_id)));

    dss_block_ctrl_t *src_block_ctrl = DSS_GET_BLOCK_CTRL_FROM_META(src_block);
    dss_add_syn_meta(vg_item, src_block_ctrl, src_block->head.common.version);
    dss_block_ctrl_t *dst_block_ctrl = DSS_GET_BLOCK_CTRL_FROM_META(dst_block);
    dss_add_syn_meta(vg_item, dst_block_ctrl, dst_block->head.common.version);

    DSS_LOG_DEBUG_OP("Succeed to replay truncate fs batch block:%llu to block:%llu, count:%hu, vg name:%s.",
        DSS_ID_TO_U64(redo->src_id), DSS_ID_TO_U64(redo->dst_id), redo->count, vg_item->vg_name);
    return CM_SUCCESS;
}

status_t rb_redo_truncate_fs_block_batch(dss_session_t *session, dss_vg_info_item_t *vg_item, dss_redo_entry_t *entry)
{
    CM_ASSERT(vg_item != NULL);
    CM_ASSERT(entry != NULL);

    dss_redo_truncate_fs_block_batch_t *redo = (dss_redo_truncate_fs_block_batch_t *)entry->data;
    dss_fs_block_t *src_block = (dss_fs_block_t *)dss_find_block_from_disk_and_refresh_shm(
        session, vg_item, redo->src_id, DSS_BLOCK_TYPE_FS, NULL);
    if (src_block == NULL) {
        DSS_RETURN_IFERR2(CM_ERROR, DSS_THROW_ERROR(ERR_DSS_FNODE_CHECK, "invalid block"));
    }
    dss_fs_block_t *dst_block = (dss_fs_block_t *)dss_find_block_from_disk_and_refresh_shm(
        session, vg_item, redo->dst_id, DSS_BLOCK_TYPE_FS, NULL);
    if (dst_block == NULL) {
        DSS_RETURN_IFERR2(CM_ERROR, DSS_THROW_ERROR(ERR_DSS_FNODE_CHECK, "invalid block"));
    }
    DSS_ASSERT_LOG(src_block->head.used_num == redo->src_old_used_num, "src block used num is %u, except is %u.",
        src_block->head.used_num, redo->src_old_used_num);
    DSS_ASSERT_LOG(dst_block->head.used_num == redo->dst_old_used_num, "dst block used num is %u, except is %u.",
        dst_block->head.used_num, redo->dst_old_used_num);
    return CM_SUCCESS;
}
static void print_redo_truncate_fs_block_batch(dss_redo_entry_t *entry)
{
    dss_redo_truncate_fs_block_batch_t *data = (dss_redo_truncate_fs_block_batch_t *)entry->data;
    (void)printf("    truncate_fs_block_batch = {\n");
    (void)printf("     src_id = {\n");
    printf_auid(&data->src_id);
    (void)printf("      }\n");
    (void)printf("     dst_id = {\n");
    printf_auid(&data->dst_id);
    (void)printf("      }\n");
    (void)printf("     src_begin = %hu\n", data->src_begin);
    (void)printf("     dst_begin = %hu\n", data->dst_begin);
    (void)printf("     src_old_used_num = %hu\n", data->src_old_used_num);
    (void)printf("     dst_old_used_num = %hu\n", data->dst_old_used_num);
    (void)printf("     count = %hu\n", data->count);
    for (uint16 i = 0; i < data->count; i++) {
        (void)printf("     id_set[%hu] = {\n", i);
        printf_auid(&data->id_set[i]);
        (void)printf("      }\n");
    }
    (void)printf("    }\n");
}

static dss_redo_handler_t g_dss_handlers[] = {
    {DSS_RT_UPDATE_CORE_CTRL, rp_update_core_ctrl, rb_update_core_ctrl, print_redo_update_core_ctrl},
    {DSS_RT_ADD_OR_REMOVE_VOLUME, rp_redo_add_or_remove_volume, rb_redo_add_or_remove_volume,
        print_redo_add_or_remove_volume},
    {DSS_RT_UPDATE_VOLHEAD, rp_redo_update_volhead, rb_redo_update_volhead, print_redo_update_volhead},
    // ft_au initializes multiple ft_blocks and mounts them to gft->free_list
    {DSS_RT_FORMAT_AU_FILE_TABLE, rp_redo_format_ft_node, rb_redo_format_ft_node, print_redo_format_ft_node},
    // mount a gft_node to a directory
    {DSS_RT_ALLOC_FILE_TABLE_NODE, rp_redo_alloc_ft_node, rb_redo_alloc_ft_node, print_redo_alloc_ft_node},
    // recycle gft_node to gft->free_list
    {DSS_RT_FREE_FILE_TABLE_NODE, rp_redo_free_ft_node, rb_redo_free_ft_node, print_redo_free_ft_node},
    // recycle gft_node to dss_ctrl->core.au_root->free_root
    {DSS_RT_MOVE_FILE_TABLE_NODE, rp_redo_move_ft_node, rb_redo_move_ft_node, print_redo_move_ft_node},
    {DSS_RT_SET_FILE_SIZE, rp_redo_set_file_size, rb_redo_set_file_size, print_redo_set_file_size},
    {DSS_RT_RENAME_FILE, rp_redo_rename_file, rb_redo_rename_file, print_redo_rename_file},

    // bitmap_au is initialized to multiple fs_blocks and mounted to dss_ctrl->core.fs_block_root
    {DSS_RT_FORMAT_AU_FILE_SPACE, rp_redo_format_fs_block, rb_redo_format_fs_block, print_redo_format_fs_block},
    // allocate an idle fs_block from the dss_ctrl->core.fs_block_root
    {DSS_RT_ALLOC_FS_BLOCK, rp_redo_alloc_fs_block, rb_redo_alloc_fs_block, print_redo_alloc_fs_block},
    // recycle fs_block to dss_ctrl->core.fs_block_root->free
    {DSS_RT_FREE_FS_BLOCK, rp_redo_free_fs_block, rb_redo_free_fs_block, print_redo_free_fs_block},
    // initialize fs_block on gft_node
    {DSS_RT_INIT_FILE_FS_BLOCK, rp_redo_init_fs_block, rb_redo_init_fs_block, print_redo_init_fs_block},
    // adds or removes a managed object of fs_block
    {DSS_RT_SET_FILE_FS_BLOCK, rp_redo_set_fs_block, rb_redo_set_fs_block, print_redo_set_fs_block},
    {DSS_RT_SET_NODE_FLAG, rp_redo_set_node_flag, rb_redo_set_node_flag, print_redo_set_node_flag},

    // initalize fs_block on gft_node
    {DSS_RT_FORMAT_FS_AUX, rp_redo_format_fs_aux, rb_redo_format_fs_aux, print_redo_format_fs_aux},
    {DSS_RT_ALLOC_FS_AUX, rp_redo_alloc_fs_aux, rb_redo_alloc_fs_aux, print_redo_alloc_fs_aux},
    {DSS_RT_FREE_FS_AUX, rp_redo_free_fs_aux, rb_redo_free_fs_aux, print_redo_free_fs_aux},
    {DSS_RT_INIT_FS_AUX, rp_redo_init_fs_aux, rb_redo_init_fs_aux, print_redo_init_fs_aux},
    {DSS_RT_SET_FS_BLOCK_BATCH, rp_redo_set_fs_block_batch, rb_redo_set_fs_block_batch, print_redo_set_fs_block_batch},
    {DSS_RT_SET_FS_AUX_BLOCK_BATCH, rp_redo_set_fs_aux_block_batch, rb_redo_set_fs_aux_block_batch,
        print_redo_set_fs_aux_block_batch},
    {DSS_RT_TRUNCATE_FS_BLOCK_BATCH, rp_redo_truncate_fs_block_batch, rb_redo_truncate_fs_block_batch,
        print_redo_truncate_fs_block_batch},
    {DSS_RT_REMOVE_FILE_TABLE_NODE, rp_redo_remove_ft_node, rb_redo_remove_ft_node, print_redo_remove_ft_node},
};

static status_t dss_replay(dss_session_t *session, dss_vg_info_item_t *vg_item, dss_redo_entry_t *entry)
{
    DSS_LOG_DEBUG_OP("[REDO][REPLAY] Replay redo, type:%u.", entry->type);
    dss_redo_handler_t *handler = &g_dss_handlers[entry->type];
    if (DSS_STANDBY_CLUSTER_XLOG_VG(vg_item->id)) {
        return CM_SUCCESS;
    }
    return handler->replay(session, vg_item, entry);
}

void dss_print_redo_entry(dss_redo_entry_t *entry)
{
    (void)printf("    redo entry type = %u\n", entry->type);
    (void)printf("    redo entry size = %u\n", entry->size);
    dss_redo_handler_t *handler = &g_dss_handlers[entry->type];
    handler->print(entry);
}

// apply log to update meta
status_t dss_apply_log(dss_session_t *session, dss_vg_info_item_t *vg_item, char *log_buf)
{
    dss_redo_entry_t *entry = NULL;
    dss_redo_batch_t *batch = NULL;
    uint32 data_size, offset;

    batch = (dss_redo_batch_t *)log_buf;
    data_size = batch->size - DSS_REDO_BATCH_HEAD_SIZE;
    status_t status;
    offset = 0;
    while (offset < data_size) {
        entry = (dss_redo_entry_t *)(batch->data + offset);
        status = dss_replay(session, vg_item, entry);
        DSS_RETURN_IF_ERROR(status);
        offset += entry->size;
    }

    return CM_SUCCESS;
}

status_t dss_update_redo_info(dss_vg_info_item_t *vg_item, char *log_buf)
{
    uint32 software_version = dss_get_software_version(&vg_item->dss_ctrl->vg_info);
    if (software_version < DSS_SOFTWARE_VERSION_2) {
        return dss_reset_log_slot_head(vg_item->id, log_buf);
    }
    dss_log_file_ctrl_t *log_ctrl = &vg_item->log_file_ctrl;
    status_t status = dss_update_redo_ctrl(vg_item, log_ctrl->index, log_ctrl->offset, log_ctrl->lsn);
    DSS_RETURN_IFERR2(status, LOG_DEBUG_ERR("Failed to update redo info, index:%u, offset:%llu, lsn:%llu.",
                                  log_ctrl->index, log_ctrl->offset, log_ctrl->lsn));
    LOG_DEBUG_INF("Succeed to update redo info, vg_name: %s, index:%u, offset:%llu, lsn:%llu.", vg_item->vg_name,
        log_ctrl->index, log_ctrl->offset, log_ctrl->lsn);
    return status;
}

status_t dss_process_redo_log_inner(dss_session_t *session, dss_vg_info_item_t *vg_item)
{
    char *log_buf = vg_item->log_file_ctrl.log_buf;
    if (log_buf == NULL || session == NULL || !session->put_log) {
        LOG_DEBUG_INF("No redo log buf to process.");
        return CM_SUCCESS;
    }
    dss_redo_batch_t *batch = (dss_redo_batch_t *)log_buf;
    if (batch->size == 0) {
        return CM_SUCCESS;
    }

    if (batch->size == sizeof(dss_redo_batch_t) || vg_item->status == DSS_VG_STATUS_RECOVERY) {
        return CM_SUCCESS;
    }
    status_t status = dss_flush_log(vg_item, log_buf);
    DSS_RETURN_IFERR2(status, LOG_DEBUG_ERR("[REDO][REFLUSH]Failed to flush log,errcode:%d.", cm_get_error_code()));
    status = dss_apply_log(session, vg_item, log_buf);
    if (status != CM_SUCCESS) {
        LOG_DEBUG_ERR("[REDO] Failed to apply log,errcode:%d.", cm_get_error_code());
        return status;
    }
    return dss_update_redo_info(vg_item, log_buf);
}

status_t dss_process_redo_log(dss_session_t *session, dss_vg_info_item_t *vg_item)
{
    status_t status = dss_process_redo_log_inner(session, vg_item);
    if (status == CM_SUCCESS) {
        dss_log_file_ctrl_t *log_file_ctrl = &vg_item->log_file_ctrl;
        char *log_buf = vg_item->log_file_ctrl.log_buf;
        cm_spin_lock(&log_file_ctrl->lock, NULL);
        log_file_ctrl->used = CM_FALSE;
        session->put_log = CM_FALSE;
        errno_t errcode = memset_s(log_buf, DSS_DISK_UNIT_SIZE, 0, DSS_DISK_UNIT_SIZE);
        securec_check_ret(errcode);
        cm_spin_unlock(&log_file_ctrl->lock);
        LOG_DEBUG_INF("[REDO][RESET]Succeed to reset redo for session %u.\n", session->id);
    }
    return status;
}

static status_t dss_rollback(dss_session_t *session, dss_vg_info_item_t *vg_item, dss_redo_entry_t *entry)
{
    DSS_LOG_DEBUG_OP("[REDO][ROLLBACK] rollback redo, type:%u.", entry->type);
    dss_redo_handler_t *handler = &g_dss_handlers[entry->type];
    return handler->rollback(session, vg_item, entry);
}

status_t dss_rollback_log(dss_session_t *session, dss_vg_info_item_t *vg_item, char *log_buf)
{
    dss_redo_entry_t *entry = NULL;
    dss_redo_batch_t *batch = NULL;
    uint32 data_size, offset;
    int32 log_num = 0;
    uint32 undo_offset[DSS_UNDO_LOG_NUM];
    batch = (dss_redo_batch_t *)log_buf;
    data_size = batch->size - DSS_REDO_BATCH_HEAD_SIZE;
    status_t status;
    offset = 0;
    while (offset < data_size) {
        entry = (dss_redo_entry_t *)(batch->data + offset);
        undo_offset[log_num] = offset;
        log_num++;
        offset += entry->size;
    }
    for (int32 i = log_num; i > 0; i--) {
        entry = (dss_redo_entry_t *)(batch->data + undo_offset[i - 1]);
        status = dss_rollback(session, vg_item, entry);
        if (status != CM_SUCCESS) {
            LOG_DEBUG_ERR("[REDO][ROLLBACK] rollback failed!");
            return status;
        }
    }
    return CM_SUCCESS;
}

void dss_rollback_mem_update(dss_session_t *session, dss_vg_info_item_t *vg_item)
{
    if (!session->put_log) {
        LOG_RUN_INF("No redo log need to recover.");
        return;
    }
    char *log_buf = vg_item->log_file_ctrl.log_buf;
    dss_redo_batch_t *batch = (dss_redo_batch_t *)log_buf;
    if (batch->size == 0) {
        return;
    }
    if (batch->size == sizeof(dss_redo_batch_t)) {
        return;
    }
    LOG_RUN_INF("Try to rollback!!!");
    status_t status;
    vg_item->status = DSS_VG_STATUS_ROLLBACK;
    status = dss_rollback_log(session, vg_item, log_buf);
    CM_ASSERT(status == CM_SUCCESS);
    dss_log_file_ctrl_t *log_file_ctrl = &vg_item->log_file_ctrl;
    cm_spin_lock(&log_file_ctrl->lock, NULL);
    log_file_ctrl->used = CM_FALSE;
    session->put_log = CM_FALSE;
    (void)memset_s(log_buf, DSS_DISK_UNIT_SIZE, 0, DSS_DISK_UNIT_SIZE);
    cm_spin_unlock(&log_file_ctrl->lock);
    LOG_DEBUG_INF("[REDO][RESET]Succeed to reset redo for session %u when rollback.\n", session->id);
    vg_item->status = DSS_VG_STATUS_OPEN;
    return;
}
