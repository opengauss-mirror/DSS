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
 *    src/common/dss_redo.c
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

bool32 is_first_vg(const char *vg_name)
{
    return (strcmp(g_vgs_info->volume_group[0].vg_name, vg_name) == 0);
}

status_t dss_set_log_buf_for_first_vg(const char *vg_name, dss_vg_info_item_t *vg_item, dss_volume_t *volume)
{
    dss_ctrl_t *dss_ctrl = vg_item->dss_ctrl;
    uint64 au_size = dss_get_vg_au_size(dss_ctrl);
    LOG_DEBUG_INF("Before init log slot.au_size:%llu, hwm:%llu, free:%llu", au_size, dss_ctrl->core.volume_attrs[0].hwm,
        dss_ctrl->core.volume_attrs[0].free);
    uint64 log_offset = dss_get_log_offset(au_size);
    if (dss_ctrl->core.volume_attrs[0].free < log_offset) {
        DSS_RETURN_IFERR2(CM_ERROR, LOG_DEBUG_ERR("The first vg has no enough space for global log."));
    }
    dss_ctrl->core.volume_attrs[0].hwm = dss_ctrl->core.volume_attrs[0].hwm + log_offset;
    dss_ctrl->core.volume_attrs[0].free = dss_ctrl->core.volume_attrs[0].free - log_offset;
    DSS_RETURN_IF_ERROR(dss_update_core_ctrl_disk(vg_item));
    LOG_DEBUG_INF("Begin to init log slot.au_size:%llu, hwm:%llu, free:%llu", au_size,
        dss_ctrl->core.volume_attrs[0].hwm, dss_ctrl->core.volume_attrs[0].free);
#ifndef WIN32
    char log_buf_head[DSS_DISK_UNIT_SIZE] __attribute__((__aligned__(DSS_DISK_UNIT_SIZE)));
#else
    char log_buf_head[DSS_DISK_UNIT_SIZE];
#endif
    errno_t rc = memset_s(log_buf_head, DSS_DISK_UNIT_SIZE, 0, DSS_DISK_UNIT_SIZE);
    DSS_SECUREC_RETURN_IF_ERROR2(rc, LOG_DEBUG_ERR("Init log buf head failed."), CM_ERROR);
    int64 offset;
    for (uint32 i = 0; i < DSS_LOG_BUF_SLOT_COUNT; i++) {
        offset = (int64)au_size + i * DSS_INSTANCE_LOG_SPLIT_SIZE;
        LOG_DEBUG_INF("Init log slot %u .offset:%lld. log split size:%u", i, offset, DSS_INSTANCE_LOG_SPLIT_SIZE);
        DSS_RETURN_IFERR2(dss_write_volume(volume, offset, log_buf_head, DSS_DISK_UNIT_SIZE),
            LOG_DEBUG_ERR("Init log slot %u failed.", i));
    }
    return CM_SUCCESS;
}

status_t dss_set_log_buf(const char *vg_name, dss_vg_info_item_t *vg_item, dss_volume_t *volume)
{
    if (!is_first_vg(vg_name)) {
        return CM_SUCCESS;
    }
    return dss_set_log_buf_for_first_vg(vg_name, vg_item, volume);
}

uint8_t dss_allocate_log_slot_for_session()
{
    dss_log_file_ctrl_t *log_ctrl = dss_get_kernel_instance_log_ctrl();
    for (;;) {
        if (log_ctrl->used_slot == DSS_LOG_BUF_SLOT_COUNT) {
            cm_spin_sleep();
            continue;
        }
        cm_spin_lock(&log_ctrl->lock, NULL);
        for (uint8_t i = 0; i < DSS_LOG_BUF_SLOT_COUNT; i++) {
            if (log_ctrl->slots[i] == 0) {
                log_ctrl->slots[i] = 1;
                log_ctrl->used_slot++;
                cm_spin_unlock(&log_ctrl->lock);
                return i;
            }
        }
        cm_spin_unlock(&log_ctrl->lock);
    }
}

void dss_free_log_slot(dss_session_t *session)
{
    CM_ASSERT(session->log_split < DSS_LOG_BUF_SLOT_COUNT);
    if (session->log_split == DSS_INVALID_SLOT) {
        return;
    }
    dss_log_file_ctrl_t *log_ctrl = dss_get_kernel_instance_log_ctrl();
    cm_spin_lock(&log_ctrl->lock, NULL);
    log_ctrl->slots[session->log_split] = 0;
    log_ctrl->used_slot--;
    CM_ASSERT(log_ctrl->used_slot >= 0);
    cm_spin_unlock(&log_ctrl->lock);
    LOG_DEBUG_INF("Free log slot %d from session %u", session->log_split, session->id);
    session->log_split = DSS_INVALID_SLOT;
}

status_t dss_reset_log_slot_head(int32_t slot)
{
    CM_ASSERT(slot < DSS_LOG_BUF_SLOT_COUNT);
    dss_log_file_ctrl_t *log_ctrl = dss_get_kernel_instance_log_ctrl();
    char *log_buf = (char *)(log_ctrl->log_buf + slot * DSS_INSTANCE_LOG_SPLIT_SIZE);
    errno_t errcode = memset_s(log_buf, DSS_DISK_UNIT_SIZE, 0, DSS_DISK_UNIT_SIZE);
    securec_check_ret(errcode);
    status_t status;
    dss_vg_info_item_t *vg_item = dss_get_first_vg_item();
    if (vg_item->volume_handle[0].handle == DSS_INVALID_HANDLE) {
        status = dss_open_volume(vg_item->entry_path, NULL, DSS_INSTANCE_OPEN_FLAG, &vg_item->volume_handle[0]);
        DSS_RETURN_IFERR2(status, LOG_DEBUG_ERR("Failed to open volume %s.", vg_item->entry_path));
    }
    uint64 au_size = dss_get_vg_au_size(vg_item->dss_ctrl);
    int64 offset = au_size + slot * DSS_INSTANCE_LOG_SPLIT_SIZE;
    CM_ASSERT(offset % DSS_DISK_UNIT_SIZE == 0);
    status = dss_write_volume(&vg_item->volume_handle[0], offset, log_buf, DSS_DISK_UNIT_SIZE);
    DSS_RETURN_IFERR2(status,
        LOG_DEBUG_ERR("Failed to write log head, slot: %d, offset:%lld, size:%u.", slot, offset, DSS_DISK_UNIT_SIZE));
    LOG_DEBUG_INF("Reset head of log slot %d.", slot);
    return status;
}

char *dss_get_log_buf_from_instance(dss_session_t *session, dss_vg_info_item_t *vg_item, dss_redo_type_t type)
{
    char *log_buf = NULL;
    dss_redo_batch_t *batch = NULL;
    dss_log_file_ctrl_t *log_ctrl = dss_get_kernel_instance_log_ctrl();
    if (session->log_split == DSS_INVALID_SLOT) {
        LOG_DEBUG_INF("Try to allocate log slot for session %u, used_slot is %d, first type is %d\n", session->id,
            log_ctrl->used_slot, (int32)type);
        session->log_split = dss_allocate_log_slot_for_session();
        LOG_DEBUG_INF("End to allocate log slot %d for session %u.\n", session->log_split, session->id);
        batch = (dss_redo_batch_t *)(log_ctrl->log_buf + session->log_split * DSS_INSTANCE_LOG_SPLIT_SIZE);
        batch->size = 0;
    }
    log_buf = (char *)(log_ctrl->log_buf + session->log_split * DSS_INSTANCE_LOG_SPLIT_SIZE);
    return log_buf;
}

char *dss_get_total_log_buf(dss_session_t *session, dss_vg_info_item_t *vg_item, dss_redo_type_t type)
{
    char *log_buf = dss_get_log_buf_from_instance(session, vg_item, type);
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
    log_buf = dss_get_total_log_buf(session, vg_item, type);
    batch = (dss_redo_batch_t *)(log_buf);
    if (batch->size == 0) {
        batch->size = sizeof(dss_redo_batch_t);
        batch->count = 0;
    }

    entry = (dss_redo_entry_t *)(log_buf + batch->size);
    entry->size = (size + sizeof(dss_redo_entry_t));
    entry->type = type;
    entry->vg_id = vg_item->id;
    session->curr_lsn = (uint64)cm_inc_lsn();
    entry->lsn = session->curr_lsn;
    CM_ASSERT(DSS_INSTANCE_LOG_SPLIT_SIZE == DSS_LOG_BUFFER_SIZE);
    put_addr = log_buf + batch->size + sizeof(dss_redo_entry_t);
    if (size != 0) {
        if (memcpy_s(put_addr, (DSS_LOG_BUFFER_SIZE - batch->size) - sizeof(dss_redo_entry_t), data, size) != EOK) {
            cm_panic(0);
        }
    }
    batch->size += entry->size;
    batch->count++;
    // 'dss_redo_batch_t' will be putted at batch tail also
    CM_ASSERT(batch->size + sizeof(dss_redo_batch_t) + DSS_DISK_UNIT_SIZE <= DSS_LOG_BUFFER_SIZE);
}

status_t dss_write_redolog_to_disk(dss_vg_info_item_t *item, int64 offset, char *buf, uint32 size)
{
    return dss_write_ctrl_to_disk(item, offset, buf, size);
}

status_t dss_flush_log_inner(int32_t log_split, char *log_buf, uint32 flush_size)
{
    dss_vg_info_item_t *vg_item = dss_get_first_vg_item();
    dss_ctrl_t *dss_ctrl = vg_item->dss_ctrl;
    uint64 au_size = dss_get_vg_au_size(dss_ctrl);
    int64 offset = au_size + log_split * DSS_INSTANCE_LOG_SPLIT_SIZE;
    status_t status = dss_write_redolog_to_disk(vg_item, offset, log_buf, flush_size);
    return status;
}

status_t dss_flush_log(int32_t log_split, dss_vg_info_item_t *vg_item, char *log_buf)
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
    // tail                                                                                         // tail
    errcode = memcpy_s(log_buf + batch->size, DSS_LOG_BUFFER_SIZE - batch->size, batch, sizeof(dss_redo_batch_t));
    securec_check_ret(errcode);
    status_t status = dss_flush_log_inner(log_split, log_buf, flush_size);
    return status;
}

static status_t rp_redo_update_volhead(dss_vg_info_item_t *vg_item, dss_redo_entry_t *entry)
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

static status_t rp_redo_add_or_remove_volume(dss_vg_info_item_t *vg_item, dss_redo_entry_t *entry)
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
            DSS_RETURN_IFERR2(CM_ERROR, LOG_DEBUG_ERR("%s refresh vginfo failed.", "rp_redo_add_or_remove_volume"));
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

        LOG_RUN_INF("recovery add volume core\n[before]core version:%llu, volume version:%llu, volume count:%u.\n"
                    "[after]core version:%llu, volume version:%llu, volume count:%u.",
            vg_item->dss_ctrl->core.version, vg_item->dss_ctrl->volume.version, vg_item->dss_ctrl->core.volume_count,
            redo->core_version, redo->volume_version, redo->volume_count);

        vg_item->dss_ctrl->core.version = redo->core_version;
        vg_item->dss_ctrl->core.volume_count = redo->volume_count;
        vg_item->dss_ctrl->volume.version = redo->volume_version;
    }
    status_t status = dss_update_volume_id_info(vg_item, id);
    DSS_RETURN_IFERR2(status, LOG_DEBUG_ERR("Failed to update core ctrl and volume to disk, vg:%s.", vg_item->vg_name));
    DSS_LOG_DEBUG_OP("Succeed to replay add or remove volume:%u.", id);
    return CM_SUCCESS;
}

static status_t rb_redo_update_volhead(dss_vg_info_item_t *vg_item, dss_redo_entry_t *entry)
{
    // no need to update volume head.
    return CM_SUCCESS;
}
static status_t rb_redo_add_or_remove_volume(dss_vg_info_item_t *vg_item, dss_redo_entry_t *entry)
{
    bool32 remote = CM_FALSE;
    dss_redo_volop_t *redo = (dss_redo_volop_t *)entry->data;
    DSS_LOG_DEBUG_OP("rollback %s volume operate", (redo->is_add) ? "add" : "remove");
    return dss_load_vg_ctrl_part(vg_item, (int64)DSS_CTRL_CORE_OFFSET, vg_item->dss_ctrl->core_data,
        (int32)(DSS_CORE_CTRL_SIZE + DSS_VOLUME_CTRL_SIZE), &remote);
}

static status_t rp_update_core_ctrl(dss_vg_info_item_t *vg_item, dss_redo_entry_t *entry)
{
    errno_t errcode = 0;
    dss_core_ctrl_t *data = (dss_core_ctrl_t *)entry->data;
    if (entry->size != 0 && vg_item->status == DSS_VG_STATUS_RECOVERY) {
        errcode =
            memcpy_s(vg_item->dss_ctrl->core_data, DSS_CORE_CTRL_SIZE, data, entry->size - sizeof(dss_redo_entry_t));
        securec_check_ret(errcode);
    }
    LOG_DEBUG_INF("replay to update core ctrl, hwm:%llu.", vg_item->dss_ctrl->core.volume_attrs[0].hwm);
    status_t status = dss_update_core_ctrl_disk(vg_item);
    DSS_RETURN_IFERR2(status, LOG_DEBUG_ERR("Failed to update core ctrl to disk, vg:%s.", vg_item->vg_name));
    DSS_LOG_DEBUG_OP("Succeed to replay update core ctrl:%s.", vg_item->vg_name);
    return CM_SUCCESS;
}

static status_t rb_update_core_ctrl(dss_vg_info_item_t *vg_item, dss_redo_entry_t *entry)
{
    bool32 remote = CM_FALSE;
    DSS_LOG_DEBUG_OP("rollback update core ctrl, hwm:%llu.", vg_item->dss_ctrl->core.volume_attrs[0].hwm);
    return dss_load_vg_ctrl_part(
        vg_item, (int64)DSS_CTRL_CORE_OFFSET, vg_item->dss_ctrl->core_data, (int32)DSS_CORE_CTRL_SIZE, &remote);
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
static status_t rp_redo_alloc_ft_node_core(
    dss_vg_info_item_t *vg_item, dss_redo_alloc_ft_node_t *data, dss_root_ft_block_t *ft_block, bool32 check_version)
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
        node = dss_get_ft_node_by_ftid(NULL, vg_item, data->node[i].id, check_version, CM_FALSE);
        if (node == NULL) {
            DSS_RETURN_IFERR2(CM_ERROR, DSS_THROW_ERROR(ERR_DSS_FNODE_CHECK, "invalid ft node."));
        }

        if (vg_item->status == DSS_VG_STATUS_RECOVERY) {
            *node = data->node[i];
        }

        LOG_DEBUG_INF("replay alloc file table node, name:%s.", node->name);

        cur_block = dss_get_ft_block_by_node(node);
        if (rp_check_block_addr(&addr_his, cur_block) && vg_item->status != DSS_VG_STATUS_RECOVERY) {
            continue;  // already update the block to disk
        }
        status = dss_update_ft_block_disk(vg_item, cur_block, data->node[i].id);
        DSS_RETURN_IF_ERROR(status);
        rp_insert_block_addr_history(&addr_his, cur_block);
    }
    return CM_SUCCESS;
}

static status_t rp_redo_alloc_ft_node(dss_vg_info_item_t *vg_item, dss_redo_entry_t *entry)
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
            LOG_DEBUG_ERR("Failed to refresh file table root, vg:%s.", vg_item->vg_name);
            return status;
        }

        *gft = data->ft_root;
        check_version = CM_TRUE;
        LOG_DEBUG_INF("replay alloc file table node when recovery.");
    }

    status = dss_update_ft_root(vg_item);
    DSS_RETURN_IFERR2(status, DSS_THROW_ERROR(ERR_DSS_REDO_ILL, "Failed to update file table root."));
    DSS_RETURN_IF_ERROR(rp_redo_alloc_ft_node_core(vg_item, data, ft_block, check_version));
    DSS_LOG_DEBUG_OP("Succeed to replay alloc ft node, vg name:%s.", vg_item->vg_name);
    return CM_SUCCESS;
}

static status_t rb_rollback_ft_block(dss_vg_info_item_t *vg_item, gft_node_t *node, uint32 node_num)
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
        cur_node = dss_get_ft_node_by_ftid(NULL, vg_item, node[i].id, check_version, CM_FALSE);
        if (!cur_node) {
            DSS_RETURN_IFERR2(CM_ERROR, DSS_THROW_ERROR(ERR_DSS_FNODE_CHECK, "invalid ft node."));
        }

        cur_block = dss_get_ft_block_by_node(cur_node);
        offset = dss_get_ft_block_offset(vg_item, node[i].id);
        status =
            dss_get_block_from_disk(vg_item, node[i].id, (char *)cur_block, offset, (int32)DSS_BLOCK_SIZE, CM_TRUE);
        if (status != CM_SUCCESS) {
            return status;
        }
    }
    return CM_SUCCESS;
}

static status_t rb_redo_alloc_ft_node(dss_vg_info_item_t *vg_item, dss_redo_entry_t *entry)
{
    CM_ASSERT(vg_item != NULL);
    CM_ASSERT(entry != NULL);
    dss_redo_alloc_ft_node_t *data = (dss_redo_alloc_ft_node_t *)entry->data;

    if (entry->size == 0) {
        DSS_RETURN_IFERR2(CM_ERROR, DSS_THROW_ERROR(ERR_DSS_REDO_ILL, "invalid entry log size 0."));
    }

    return rb_rollback_ft_block(vg_item, data->node, DSS_REDO_ALLOC_FT_NODE_NUM);
}

static status_t dss_update_ft_info(dss_vg_info_item_t *vg_item, dss_ft_block_t *block, dss_redo_format_ft_t *data)
{
    status_t status = dss_update_ft_block_disk(vg_item, block, data->old_last_block);
    DSS_RETURN_IFERR2(status,
        LOG_DEBUG_ERR("Failed to update file table block to disk, auid:%llu.", DSS_ID_TO_U64(data->old_last_block)));
    status = dss_update_ft_root(vg_item);
    DSS_RETURN_IFERR2(status, LOG_DEBUG_ERR("Failed to update file table root, vg:%s.", vg_item->vg_name));
    return CM_SUCCESS;
}

static status_t rp_redo_format_ft_node(dss_vg_info_item_t *vg_item, dss_redo_entry_t *entry)
{
    CM_ASSERT(vg_item != NULL && entry != NULL);

    status_t status;
    dss_redo_format_ft_t *data = (dss_redo_format_ft_t *)entry->data;
    dss_ft_block_t *block = NULL;
    if (vg_item->status == DSS_VG_STATUS_RECOVERY) {
        status = dss_refresh_root_ft(vg_item, CM_TRUE, CM_FALSE);
        DSS_RETURN_IFERR2(status, LOG_DEBUG_ERR("Failed to refresh file table root, vg:%s.", vg_item->vg_name));
        // note:first load
        block = (dss_ft_block_t *)dss_get_ft_block_by_ftid(vg_item, data->old_last_block);
        if (block == NULL) {
            DSS_RETURN_IFERR2(CM_ERROR, LOG_DEBUG_ERR("Failed to get last file table block, blockid:%llu.",
                                            DSS_ID_TO_U64(data->old_last_block)));
        }
        dss_root_ft_block_t *root_block = DSS_GET_ROOT_BLOCK(vg_item->dss_ctrl);
        root_block->ft_root.free_list = data->old_free_list;
        root_block->ft_root.last = data->old_last_block;
        status = dss_format_ft_node(NULL, vg_item, data->auid);
        DSS_RETURN_IFERR2(
            status, LOG_DEBUG_ERR("Failed to format file table node, auid:%llu.", DSS_ID_TO_U64(data->auid)));
    }
    // when recover, has load old last block.
    if (vg_item->status != DSS_VG_STATUS_RECOVERY) {  // just find the block, it has already in memory.
        block = (dss_ft_block_t *)dss_get_ft_block_by_ftid(vg_item, data->old_last_block);
        if (block == NULL) {
            DSS_RETURN_IFERR2(CM_ERROR, LOG_DEBUG_ERR("Failed to get last file table block, blockid:%llu.",
                                            DSS_ID_TO_U64(data->old_last_block)));
        }
    }
    CM_RETURN_IFERR(dss_update_ft_info(vg_item, block, data));
    dss_block_id_t first = data->auid;
    ga_obj_id_t obj_id;
    status = dss_find_block_objid_in_shm(vg_item, first, DSS_BLOCK_TYPE_FT, &obj_id);
    DSS_RETURN_IFERR2(status, LOG_DEBUG_ERR("Failed to find block:%llu.", DSS_ID_TO_U64(first)));
    status = dss_update_au_disk(vg_item, data->auid, GA_8K_POOL, obj_id.obj_id, data->count, DSS_BLOCK_SIZE);
    DSS_RETURN_IFERR2(status, LOG_DEBUG_ERR("Failed to update au to disk, au:%llu.", DSS_ID_TO_U64(data->auid)));
    DSS_LOG_DEBUG_OP("Succeed to replay formate ft node, auid:%llu, obj_id:%u, count:%u, old_last_block:%llu.",
        DSS_ID_TO_U64(data->auid), data->obj_id, data->count, DSS_ID_TO_U64(data->old_last_block));
    return CM_SUCCESS;
}

static status_t rb_redo_format_ft_node(dss_vg_info_item_t *vg_item, dss_redo_entry_t *entry)
{
    // format file table node only when new au, if fail, just free the memory, no need to rollback.
    return CM_SUCCESS;
}

static status_t rp_redo_free_fs_block(dss_vg_info_item_t *vg_item, dss_redo_entry_t *entry)
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
            NULL, vg_item, log_block->head.common.id, DSS_BLOCK_TYPE_FS, CM_TRUE, &obj_id, CM_FALSE);
        if (block == NULL) {
            DSS_RETURN_IFERR2(CM_ERROR, DSS_THROW_ERROR(ERR_DSS_FNODE_CHECK, "invalid block"));
        }
        block->head.next = log_block->head.next;
        status = dss_update_fs_bitmap_block_disk(vg_item, block, DSS_DISK_UNIT_SIZE, CM_FALSE);
        DSS_RETURN_IF_ERROR(status);
        dss_unregister_buffer_cache(vg_item, log_block->head.common.id);
        ga_free_object(obj_id.pool_id, obj_id.obj_id);
        return CM_SUCCESS;
    }

    status = dss_update_fs_bitmap_block_disk(vg_item, log_block, DSS_DISK_UNIT_SIZE, CM_TRUE);
    DSS_RETURN_IFERR2(
        status, LOG_DEBUG_ERR("Failed to update fs bitmap block:%llu to disk.", DSS_ID_TO_U64(log_block->head.common.id)));
    DSS_LOG_DEBUG_OP(
        "Succeed to replay free fs block:%llu, vg name:%s.", DSS_ID_TO_U64(log_block->head.common.id), vg_item->vg_name);
    return CM_SUCCESS;
}

status_t rb_redo_free_fs_block(dss_vg_info_item_t *vg_item, dss_redo_entry_t *entry)
{
    CM_ASSERT(vg_item != NULL);
    CM_ASSERT(entry != NULL);

    dss_redo_free_fs_block_t *data = (dss_redo_free_fs_block_t *)entry->data;
    dss_fs_block_t *log_block = (dss_fs_block_t *)data->head;

    return dss_load_fs_block_by_blockid(vg_item, log_block->head.common.id, (int32)DSS_FILE_SPACE_BLOCK_SIZE);
}

static status_t rp_redo_alloc_fs_block(dss_vg_info_item_t *vg_item, dss_redo_entry_t *entry)
{
    CM_ASSERT(vg_item != NULL);
    CM_ASSERT(entry != NULL);

    status_t status;
    dss_redo_alloc_fs_block_t *data = (dss_redo_alloc_fs_block_t *)entry->data;
    dss_fs_block_root_t *root = DSS_GET_FS_BLOCK_ROOT(vg_item->dss_ctrl);
    dss_fs_block_t *block = NULL;

    if (vg_item->status == DSS_VG_STATUS_RECOVERY) {
        status = dss_check_refresh_core(vg_item);
        DSS_RETURN_IFERR2(status, LOG_DEBUG_ERR("Failed to refresh vg core:%s.", vg_item->vg_name));
        block = (dss_fs_block_t *)dss_find_block_in_shm(
            NULL, vg_item, data->id, DSS_BLOCK_TYPE_FS, CM_TRUE, NULL, CM_FALSE);
        if (block == NULL) {
            DSS_RETURN_IFERR2(CM_ERROR, DSS_THROW_ERROR(ERR_DSS_FNODE_CHECK, "invalid block"));
        }

        dss_init_fs_block_head(block);
        *root = data->root;
    }

    vg_item->dss_ctrl->core.version++;
    status = dss_update_core_ctrl_disk(vg_item);
    DSS_RETURN_IFERR2(status, LOG_DEBUG_ERR("Failed to update vg core:%s to disk.", vg_item->vg_name));

    if (block == NULL) {
        block = (dss_fs_block_t *)dss_find_block_in_shm(
            NULL, vg_item, data->id, DSS_BLOCK_TYPE_FS, CM_FALSE, NULL, CM_FALSE);
    }

    if (block == NULL) {
        DSS_RETURN_IFERR2(CM_ERROR, DSS_THROW_ERROR(ERR_DSS_FNODE_CHECK, "invalid block"));
    }

    status = dss_update_fs_bitmap_block_disk(vg_item, block, DSS_FILE_SPACE_BLOCK_SIZE, CM_FALSE);
    DSS_RETURN_IFERR2(status, LOG_DEBUG_ERR("Failed to update fs bitmap block:%llu to disk.", DSS_ID_TO_U64(data->id)));
    DSS_LOG_DEBUG_OP("Succeed to replay alloc fs block:%llu, vg name:%s.", DSS_ID_TO_U64(data->id), vg_item->vg_name);
    return CM_SUCCESS;
}

static status_t rb_redo_alloc_fs_block(dss_vg_info_item_t *vg_item, dss_redo_entry_t *entry)
{
    CM_ASSERT(vg_item != NULL);
    CM_ASSERT(entry != NULL);

    status_t status;
    bool32 remote = CM_FALSE;
    dss_redo_alloc_fs_block_t *data = (dss_redo_alloc_fs_block_t *)entry->data;

    ga_obj_id_t obj_id;
    dss_fs_block_t *block = (dss_fs_block_t *)dss_find_block_in_shm(
        NULL, vg_item, data->id, DSS_BLOCK_TYPE_FS, CM_FALSE, &obj_id, CM_FALSE);
    CM_ASSERT(block != NULL);
    dss_unregister_buffer_cache(vg_item, block->head.common.id);
    ga_free_object(obj_id.pool_id, obj_id.obj_id);
    status = dss_load_vg_ctrl_part(
        vg_item, (int64)DSS_CTRL_CORE_OFFSET, vg_item->dss_ctrl->core_data, DSS_DISK_UNIT_SIZE, &remote);
    CM_ASSERT(status == CM_SUCCESS);
    return status;
}

status_t rp_redo_init_fs_block(dss_vg_info_item_t *vg_item, dss_redo_entry_t *entry)
{
    CM_ASSERT(vg_item != NULL);
    CM_ASSERT(entry != NULL);

    status_t status;
    dss_redo_init_fs_block_t *data = (dss_redo_init_fs_block_t *)entry->data;

    dss_fs_block_t *block = NULL;

    if (vg_item->status == DSS_VG_STATUS_RECOVERY) {
        block = (dss_fs_block_t *)dss_find_block_in_shm(
            NULL, vg_item, data->id, DSS_BLOCK_TYPE_FS, CM_TRUE, NULL, CM_FALSE);
        if (block == NULL) {
            DSS_RETURN_IFERR2(CM_ERROR, DSS_THROW_ERROR(ERR_DSS_FNODE_CHECK, "invalid block"));
        }
        block->bitmap[data->index] = data->second_id;
        block->head.used_num = data->used_num;
    }

    if (block == NULL) {
        block = (dss_fs_block_t *)dss_find_block_in_shm(
            NULL, vg_item, data->id, DSS_BLOCK_TYPE_FS, CM_FALSE, NULL, CM_FALSE);
        if (block == NULL) {
            DSS_RETURN_IFERR2(CM_ERROR, DSS_THROW_ERROR(ERR_DSS_FNODE_CHECK, "invalid block"));
        }
    }

    status = dss_update_fs_bitmap_block_disk(vg_item, block, DSS_FILE_SPACE_BLOCK_SIZE, CM_FALSE);
    DSS_RETURN_IFERR2(status, LOG_DEBUG_ERR("Failed to update fs bitmap block:%llu to disk.", DSS_ID_TO_U64(data->id)));
    DSS_LOG_DEBUG_OP("Succeed to replay init fs block:%llu, vg name:%s.", DSS_ID_TO_U64(data->id), vg_item->vg_name);
    return CM_SUCCESS;
}

status_t rb_redo_init_fs_block(dss_vg_info_item_t *vg_item, dss_redo_entry_t *entry)
{
    CM_ASSERT(vg_item != NULL);
    CM_ASSERT(entry != NULL);

    dss_redo_init_fs_block_t *data = (dss_redo_init_fs_block_t *)entry->data;

    dss_fs_block_t *block =
        (dss_fs_block_t *)dss_find_block_in_shm(NULL, vg_item, data->id, DSS_BLOCK_TYPE_FS, CM_FALSE, NULL, CM_FALSE);
    if (block == NULL) {
        DSS_RETURN_IFERR2(CM_ERROR, DSS_THROW_ERROR(ERR_DSS_FNODE_CHECK, "invalid block"));
    }

    dss_set_blockid(&block->bitmap[data->index], CM_INVALID_ID64);
    block->head.used_num = 0;

    return CM_SUCCESS;
}

status_t rp_redo_rename_file(dss_vg_info_item_t *vg_item, dss_redo_entry_t *entry)
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

    gft_node_t *node = dss_get_ft_node_by_ftid(NULL, vg_item, data->node.id, check_version, CM_FALSE);
    if (!node) {
        DSS_RETURN_IFERR2(CM_ERROR, DSS_THROW_ERROR(ERR_DSS_FNODE_CHECK, "invalid node"));
    }

    if (vg_item->status == DSS_VG_STATUS_RECOVERY) {
        int32 ret = snprintf_s(node->name, DSS_MAX_NAME_LEN, strlen(data->name), "%s", data->name);
        DSS_SECUREC_SS_RETURN_IF_ERROR(ret, CM_ERROR);
    }

    dss_ft_block_t *cur_block = dss_get_ft_block_by_node(node);
    if (cur_block == NULL) {
        DSS_RETURN_IFERR2(CM_ERROR, DSS_THROW_ERROR(ERR_DSS_FNODE_CHECK, "invalid block"));
    }

    status_t status = dss_update_ft_block_disk(vg_item, cur_block, data->node.id);
    DSS_RETURN_IFERR2(status, LOG_DEBUG_ERR("Failed to update fs block:%llu to disk.", DSS_ID_TO_U64(data->node.id)));
    DSS_LOG_DEBUG_OP("Succeed to replay rename file:%s, vg name:%s.", data->name, vg_item->vg_name);
    return CM_SUCCESS;
}
status_t rb_redo_rename_file(dss_vg_info_item_t *vg_item, dss_redo_entry_t *entry)
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

    gft_node_t *node = dss_get_ft_node_by_ftid(NULL, vg_item, data->node.id, check_version, CM_FALSE);
    if (!node) {
        DSS_RETURN_IFERR2(CM_ERROR, DSS_THROW_ERROR(ERR_DSS_FNODE_CHECK, "invalid node"));
    }

    int32 ret = snprintf_s(node->name, DSS_MAX_NAME_LEN, strlen(data->old_name), "%s", data->old_name);
    DSS_SECUREC_SS_RETURN_IF_ERROR(ret, CM_ERROR);
    return CM_SUCCESS;
}

status_t rp_redo_set_fs_block(dss_vg_info_item_t *vg_item, dss_redo_entry_t *entry)
{
    CM_ASSERT(vg_item != NULL);
    CM_ASSERT(entry != NULL);

    status_t status;
    dss_redo_set_fs_block_t *data = (dss_redo_set_fs_block_t *)entry->data;

    dss_fs_block_t *block;
    bool32 check_version = CM_FALSE;
    if (vg_item->status == DSS_VG_STATUS_RECOVERY) {
        check_version = CM_TRUE;
    }

    block = (dss_fs_block_t *)dss_find_block_in_shm(
        NULL, vg_item, data->id, DSS_BLOCK_TYPE_FS, check_version, NULL, CM_FALSE);
    if (block == NULL) {
        DSS_RETURN_IFERR2(CM_ERROR, DSS_THROW_ERROR(ERR_DSS_FNODE_CHECK, "invalid block"));
        return CM_ERROR;
    }

    if (vg_item->status == DSS_VG_STATUS_RECOVERY) {
        block->bitmap[data->index] = data->value;
        block->head.used_num = data->used_num;
    }

    status = dss_update_fs_bitmap_block_disk(vg_item, block, DSS_FILE_SPACE_BLOCK_SIZE, CM_FALSE);
    DSS_RETURN_IFERR2(status, LOG_DEBUG_ERR("Failed to update fs block:%llu to disk.", DSS_ID_TO_U64(data->id)));
    DSS_LOG_DEBUG_OP("Succeed to replay set fs block:%llu, used_num:%hu, vg name:%s.", DSS_ID_TO_U64(data->id),
        block->head.used_num, vg_item->vg_name);
    return CM_SUCCESS;
}

status_t rb_redo_set_fs_block(dss_vg_info_item_t *vg_item, dss_redo_entry_t *entry)
{
    CM_ASSERT(vg_item != NULL);
    CM_ASSERT(entry != NULL);

    dss_redo_set_fs_block_t *data = (dss_redo_set_fs_block_t *)entry->data;

    dss_fs_block_t *block;
    bool32 check_version = CM_FALSE;

    block = (dss_fs_block_t *)dss_find_block_in_shm(
        NULL, vg_item, data->id, DSS_BLOCK_TYPE_FS, check_version, NULL, CM_FALSE);
    if (block == NULL) {
        DSS_RETURN_IFERR2(CM_ERROR, DSS_THROW_ERROR(ERR_DSS_FNODE_CHECK, "invalid block"));
        return CM_ERROR;
    }

    block->bitmap[data->index] = data->old_value;
    block->head.used_num = data->old_used_num;

    return CM_SUCCESS;
}

static status_t rp_redo_free_ft_node_core(
    dss_vg_info_item_t *vg_item, dss_root_ft_block_t *ft_block, dss_redo_free_ft_node_t *data, bool32 check_version)
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
        node = dss_get_ft_node_by_ftid(NULL, vg_item, data->node[i].id, check_version, CM_FALSE);
        if (!node) {
            return CM_ERROR;
        }

        if (vg_item->status == DSS_VG_STATUS_RECOVERY) {
            *node = data->node[i];
        }

        cur_block = dss_get_ft_block_by_node(node);
        if (rp_check_block_addr(&addr_his, cur_block) && vg_item->status != DSS_VG_STATUS_RECOVERY) {
            DSS_LOG_DEBUG_OP("Replay free ft node, block has updated, cur_block:%p, node id:%llu.", cur_block,
                DSS_ID_TO_U64(node->id));
            continue;  // already update the block to disk
        }

        DSS_LOG_DEBUG_OP("Replay free ft node, cur_block:%p, node id:%llu.", cur_block, DSS_ID_TO_U64(node->id));

        status = dss_update_ft_block_disk(vg_item, cur_block, data->node[i].id);
        if (status != CM_SUCCESS) {
            return status;
        }
        rp_insert_block_addr_history(&addr_his, cur_block);
    }
    DSS_LOG_DEBUG_OP("Succeed to replay free ft node, vg name:%s.", vg_item->vg_name);
    return CM_SUCCESS;
}

status_t rp_redo_free_ft_node(dss_vg_info_item_t *vg_item, dss_redo_entry_t *entry)
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
            LOG_DEBUG_ERR("Failed to refresh file table root, vg:%s.", vg_item->vg_name));

        *gft = data->ft_root;
        check_version = CM_TRUE;
    }
    return rp_redo_free_ft_node_core(vg_item, ft_block, data, check_version);
}

status_t rb_redo_free_ft_node(dss_vg_info_item_t *vg_item, dss_redo_entry_t *entry)
{
    CM_ASSERT(vg_item != NULL);
    CM_ASSERT(entry != NULL);

    dss_redo_free_ft_node_t *data = (dss_redo_free_ft_node_t *)entry->data;

    if (entry->size == 0) {
        DSS_RETURN_IFERR2(CM_ERROR, DSS_THROW_ERROR(ERR_DSS_REDO_ILL, "invalid entry log size 0."));
    }

    return rb_rollback_ft_block(vg_item, data->node, DSS_REDO_FREE_FT_NODE_NUM);
}

status_t rp_redo_recycle_ft_node(dss_vg_info_item_t *vg_item, dss_redo_entry_t *entry)
{
    CM_ASSERT(vg_item != NULL);
    CM_ASSERT(entry != NULL);

    dss_redo_recycle_ft_node_t *data = (dss_redo_recycle_ft_node_t *)entry->data;
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

    for (uint32 i = 0; i < DSS_REDO_RECYCLE_FT_NODE_NUM; i++) {
        if (dss_cmp_auid(data->node[i].id, CM_INVALID_ID64)) {
            continue;
        }
        node = dss_get_ft_node_by_ftid(NULL, vg_item, data->node[i].id, check_version, CM_FALSE);
        if (!node) {
            DSS_RETURN_IFERR2(CM_ERROR, DSS_THROW_ERROR(ERR_DSS_FNODE_CHECK, "invalid ft node."));
        }

        if (vg_item->status == DSS_VG_STATUS_RECOVERY) {
            *node = data->node[i];
        }

        cur_block = dss_get_ft_block_by_node(node);
        if (rp_check_block_addr(&addr_his, cur_block) && vg_item->status != DSS_VG_STATUS_RECOVERY) {
            continue;  // already update the block to disk
        }
        CM_RETURN_IFERR(dss_update_ft_block_disk(vg_item, cur_block, data->node[i].id));
        rp_insert_block_addr_history(&addr_his, cur_block);
    }
    DSS_LOG_DEBUG_OP("Succeed to replay recycle ft node, vg name:%s.", vg_item->vg_name);
    return CM_SUCCESS;
}

status_t rb_redo_recycle_ft_node(dss_vg_info_item_t *vg_item, dss_redo_entry_t *entry)
{
    CM_ASSERT(vg_item != NULL);
    CM_ASSERT(entry != NULL);

    status_t status;
    dss_redo_recycle_ft_node_t *data = (dss_redo_recycle_ft_node_t *)entry->data;
    bool32 check_version = CM_FALSE;

    if (entry->size == 0) {
        DSS_RETURN_IFERR2(CM_ERROR, DSS_THROW_ERROR(ERR_DSS_REDO_ILL, "invalid entry log size 0."));
    }

    gft_node_t *node;
    dss_ft_block_t *cur_block = NULL;
    bool32 cmp;
    for (uint32 i = 0; i < DSS_REDO_RECYCLE_FT_NODE_NUM; i++) {
        cmp = dss_cmp_auid(data->node[i].id, CM_INVALID_ID64);
        if (cmp) {
            continue;
        }
        node = dss_get_ft_node_by_ftid(NULL, vg_item, data->node[i].id, check_version, CM_FALSE);
        if (!node) {
            DSS_RETURN_IFERR2(CM_ERROR, DSS_THROW_ERROR(ERR_DSS_FNODE_CHECK, "invalid ft node."));
        }

        cur_block = dss_get_ft_block_by_node(node);
        int64 offset = dss_get_ft_block_offset(vg_item, data->node[i].id);
        status = dss_get_block_from_disk(
            vg_item, data->node[i].id, (char *)cur_block, offset, (int32)DSS_BLOCK_SIZE, CM_TRUE);
        DSS_RETURN_IF_ERROR(status);
    }
    return CM_SUCCESS;
}

static status_t rp_redo_set_file_size_inner(dss_vg_info_item_t *vg_item, dss_redo_entry_t *entry, ftid_t *ftid)
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
    node = dss_get_ft_node_by_ftid(NULL, vg_item, *ftid, check_version, CM_FALSE);
    if (!node) {
        DSS_RETURN_IFERR2(CM_ERROR, DSS_THROW_ERROR(ERR_DSS_FNODE_CHECK, "invalid ft node."));
    }
    dss_redo_set_file_size_t *size_info = (dss_redo_set_file_size_t *)entry->data;
    LOG_DEBUG_INF("Begin to replay set file:%llu, size:%llu, oldsize:%llu, node size:%llu,vg name:%s.", DSS_ID_TO_U64(size_info->ftid),
        size_info->size, size_info->oldsize, node->size, vg_item->vg_name);

    if (vg_item->status == DSS_VG_STATUS_RECOVERY) {
        node->size = set_file_size->size;
    }
    if (set_file_size->size < set_file_size->oldsize) {
        node->file_ver++;
        LOG_RUN_INF("Update ft block:%llu file_ver to:%llu.", DSS_ID_TO_U64(*ftid), node->file_ver);
    }
    cur_block = dss_get_ft_block_by_node(node);
    CM_RETURN_IFERR_EX(dss_update_ft_block_disk(vg_item, cur_block, *ftid),
        LOG_DEBUG_ERR("Failed to update ft block:%llu to disk.", DSS_ID_TO_U64(*ftid)));
    return CM_SUCCESS;
}

status_t rp_redo_set_file_size(dss_vg_info_item_t *vg_item, dss_redo_entry_t *entry)
{
    ftid_t ftid;
    if (rp_redo_set_file_size_inner(vg_item, entry, &ftid) != CM_SUCCESS) {
        return CM_ERROR;
    }
    DSS_LOG_DEBUG_OP("Succeed to replay set file:%llu size, vg name:%s.", DSS_ID_TO_U64(ftid), vg_item->vg_name);
    return CM_SUCCESS;
}

static status_t rb_redo_get_ft_node(
    dss_vg_info_item_t *vg_item, dss_redo_entry_t *entry, ftid_t ftid, gft_node_t **node)
{
    bool32 check_version = CM_FALSE;
    if (entry->size == 0) {
        DSS_RETURN_IFERR2(CM_ERROR, DSS_THROW_ERROR(ERR_DSS_REDO_ILL, "invalid entry log size 0."));
    }

    *node = dss_get_ft_node_by_ftid(NULL, vg_item, ftid, check_version, CM_FALSE);
    if (!(*node)) {
        DSS_RETURN_IFERR2(CM_ERROR, DSS_THROW_ERROR(ERR_DSS_FNODE_CHECK, "invalid ft node."));
    }
    return CM_SUCCESS;
}

status_t rb_redo_set_file_size(dss_vg_info_item_t *vg_item, dss_redo_entry_t *entry)
{
    CM_ASSERT(vg_item != NULL);
    CM_ASSERT(entry != NULL);
    dss_redo_set_file_size_t *data = (dss_redo_set_file_size_t *)entry->data;
    gft_node_t *node;
    DSS_RETURN_IF_ERROR(rb_redo_get_ft_node(vg_item, entry, data->ftid, &node));
    node->size = data->oldsize;
    return CM_SUCCESS;
}

status_t rp_redo_format_fs_block(dss_vg_info_item_t *vg_item, dss_redo_entry_t *entry)
{
    CM_ASSERT(vg_item != NULL);
    CM_ASSERT(entry != NULL);

    status_t status;
    dss_redo_format_fs_t *data = (dss_redo_format_fs_t *)entry->data;

    if (vg_item->status == DSS_VG_STATUS_RECOVERY) {
        status = dss_check_refresh_core(vg_item);
        DSS_RETURN_IFERR2(status, LOG_DEBUG_ERR("Failed to refresh vg core:%s.", vg_item->vg_name));
        dss_fs_block_root_t *block_root = DSS_GET_FS_BLOCK_ROOT(vg_item->dss_ctrl);
        block_root->free = data->old_free_list;
        status = dss_format_bitmap_node(NULL, vg_item, data->auid);
        DSS_RETURN_IFERR2(
            status, LOG_DEBUG_ERR("Fail to format file space node, auid:%llu.", DSS_ID_TO_U64(data->auid)));
    }

    status = dss_update_core_ctrl_disk(vg_item);
    DSS_RETURN_IFERR2(status, LOG_DEBUG_ERR("Fail to write ctrl to disk, vg:%s.", vg_item->vg_name));
    dss_block_id_t first = data->auid;
    ga_obj_id_t obj_id;
    status = dss_find_block_objid_in_shm(vg_item, first, DSS_BLOCK_TYPE_FS, &obj_id);
    DSS_RETURN_IFERR2(status, LOG_DEBUG_ERR("Fail to find block:%llu.", DSS_ID_TO_U64(first)));

    status =
        dss_update_au_disk(vg_item, data->auid, GA_16K_POOL, obj_id.obj_id, data->count, DSS_FILE_SPACE_BLOCK_SIZE);
    DSS_RETURN_IFERR2(status, LOG_DEBUG_ERR("Fail to update au:%llu.", DSS_ID_TO_U64(data->auid)));
    DSS_LOG_DEBUG_OP(
        "Succeed to replay format au:%llu fs block, vg name:%s.", DSS_ID_TO_U64(data->auid), vg_item->vg_name);
    return CM_SUCCESS;
}

void rb_redo_clean_resource(dss_vg_info_item_t *item, auid_t auid, ga_pool_id_e pool_id, uint32 first, uint32 count)
{
    dss_fs_block_header *block;
    uint32 obj_id = first;
    uint32 last = first;
    CM_ASSERT(count > 0);
    for (uint32 i = 0; i < count; i++) {
        block = (dss_fs_block_header *)ga_object_addr(pool_id, obj_id);
        CM_ASSERT(block != NULL);
        dss_unregister_buffer_cache(item, block->common.id);
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

static status_t rp_redo_set_node_flag(dss_vg_info_item_t *vg_item, dss_redo_entry_t *entry)
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
    node = dss_get_ft_node_by_ftid(NULL, vg_item, file_flag->ftid, check_version, CM_FALSE);
    if (!node) {
        DSS_RETURN_IFERR2(CM_ERROR, DSS_THROW_ERROR(ERR_DSS_FNODE_CHECK, "invalid ft node."));
    }
    LOG_DEBUG_INF("Begin to replay set file:%llu, flags:%u, old_flags:%u, vg_name:%s.", DSS_ID_TO_U64(file_flag->ftid),
        file_flag->flags, file_flag->old_flags, vg_item->vg_name);

    if (vg_item->status == DSS_VG_STATUS_RECOVERY) {
        node->flags = file_flag->flags;
    }
    cur_block = dss_get_ft_block_by_node(node);
    CM_RETURN_IFERR_EX(dss_update_ft_block_disk(vg_item, cur_block, file_flag->ftid),
        LOG_DEBUG_ERR(
            "Failed to update ft block:%llu, vg_name:%s to disk.", DSS_ID_TO_U64(file_flag->ftid), vg_item->vg_name));
    LOG_DEBUG_INF("Success to replay set file:%llu, flags:%u, old_flag:%u, vg_name:%s.",
        DSS_ID_TO_U64(file_flag->ftid), file_flag->flags, file_flag->old_flags, vg_item->vg_name);
    return CM_SUCCESS;
}

static status_t rb_redo_set_node_flag(dss_vg_info_item_t *vg_item, dss_redo_entry_t *entry)
{
    CM_ASSERT(vg_item != NULL);
    CM_ASSERT(entry != NULL);

    if (entry->size == 0) {
        DSS_RETURN_IFERR2(CM_ERROR, DSS_THROW_ERROR(ERR_DSS_REDO_ILL, "invalid entry log size 0."));
    }
    gft_node_t *node;
    dss_ft_block_t *cur_block = NULL;
    dss_redo_set_file_flag_t *file_flag = (dss_redo_set_file_flag_t *)entry->data;

    node = dss_get_ft_node_by_ftid(NULL, vg_item, file_flag->ftid, CM_FALSE, CM_FALSE);
    if (!node) {
        DSS_RETURN_IFERR2(CM_ERROR, DSS_THROW_ERROR(ERR_DSS_FNODE_CHECK, "invalid ft node."));
    }
    LOG_DEBUG_INF("Begin to replay  rollback set file:%llu, flags:%u, old_flags:%u, vg_name:%s.",
        DSS_ID_TO_U64(file_flag->ftid), file_flag->flags, file_flag->old_flags, vg_item->vg_name);

    node->flags = file_flag->old_flags;

    cur_block = dss_get_ft_block_by_node(node);
    CM_RETURN_IFERR_EX(dss_update_ft_block_disk(vg_item, cur_block, file_flag->ftid),
        LOG_DEBUG_ERR(
            "Failed to update ft block:%llu, vg_name:%s to disk.", DSS_ID_TO_U64(file_flag->ftid), vg_item->vg_name));
    LOG_DEBUG_INF("Success to replay rollback set file:%llu, flags:%u, old_flag:%u, vg_name:%s.",
        DSS_ID_TO_U64(file_flag->ftid), file_flag->flags, file_flag->old_flags, vg_item->vg_name);
    return CM_SUCCESS;
}

status_t rb_redo_format_fs_block(dss_vg_info_item_t *vg_item, dss_redo_entry_t *entry)
{
    CM_ASSERT(vg_item != NULL);
    CM_ASSERT(entry != NULL);

    status_t status;
    bool32 remote = CM_FALSE;
    dss_redo_format_fs_t *data = (dss_redo_format_fs_t *)entry->data;

    dss_block_id_t first = data->auid;
    ga_obj_id_t obj_id;
    status = dss_find_block_objid_in_shm(vg_item, first, DSS_BLOCK_TYPE_FS, &obj_id);
    DSS_RETURN_IFERR2(status, LOG_DEBUG_ERR("Failed to find block:%llu.", DSS_ID_TO_U64(first)));
    rb_redo_clean_resource(vg_item, data->auid, GA_16K_POOL, obj_id.obj_id, data->count);
    status = dss_load_vg_ctrl_part(
        vg_item, (int64)DSS_CTRL_CORE_OFFSET, vg_item->dss_ctrl->core_data, DSS_DISK_UNIT_SIZE, &remote);
    DSS_RETURN_IFERR2(status, LOG_DEBUG_ERR("Failed to load vg:%s.", vg_item->vg_name));
    return CM_SUCCESS;
}

static dss_redo_handler_t g_dss_handlers[] = {{DSS_RT_UPDATE_CORE_CTRL, rp_update_core_ctrl, rb_update_core_ctrl},
    {DSS_RT_ADD_OR_REMOVE_VOLUME, rp_redo_add_or_remove_volume, rb_redo_add_or_remove_volume},
    {DSS_RT_UPDATE_VOLHEAD, rp_redo_update_volhead, rb_redo_update_volhead},
    // ft_au initializes multiple ft_blocks and mounts them to gft->free_list
    {DSS_RT_FORMAT_AU_FILE_TABLE, rp_redo_format_ft_node, rb_redo_format_ft_node},
    // mount a gft_node to a directory
    {DSS_RT_ALLOC_FILE_TABLE_NODE, rp_redo_alloc_ft_node, rb_redo_alloc_ft_node},
    // recycle gft_node to gft->free_list
    {DSS_RT_FREE_FILE_TABLE_NODE, rp_redo_free_ft_node, rb_redo_free_ft_node},
    // recycle gft_node to dss_ctrl->core.au_root->free_root
    {DSS_RT_RECYCLE_FILE_TABLE_NODE, rp_redo_recycle_ft_node, rb_redo_recycle_ft_node},
    {DSS_RT_SET_FILE_SIZE, rp_redo_set_file_size, rb_redo_set_file_size},
    {DSS_RT_RENAME_FILE, rp_redo_rename_file, rb_redo_rename_file},

    // bitmap_au is initialized to multiple fs_blocks and mounted to dss_ctrl->core.fs_block_root
    {DSS_RT_FORMAT_AU_FILE_SPACE, rp_redo_format_fs_block, rb_redo_format_fs_block},
    // allocate an idle fs_block from the dss_ctrl->core.fs_block_root
    {DSS_RT_ALLOC_FS_BLOCK, rp_redo_alloc_fs_block, rb_redo_alloc_fs_block},
    // recycle fs_block to dss_ctrl->core.fs_block_root->free
    {DSS_RT_FREE_FS_BLOCK, rp_redo_free_fs_block, rb_redo_free_fs_block},
    // initialize fs_block on gft_node
    {DSS_RT_INIT_FILE_FS_BLOCK, rp_redo_init_fs_block, rb_redo_init_fs_block},
    // adds or removes a managed object of fs_block
    {DSS_RT_SET_FILE_FS_BLOCK, rp_redo_set_fs_block, rb_redo_set_fs_block},
    {DSS_RT_SET_NODE_FLAG, rp_redo_set_node_flag, rb_redo_set_node_flag},
};

static status_t dss_replay(dss_vg_info_item_t *vg_item, dss_redo_entry_t *entry)
{
    DSS_LOG_DEBUG_OP("Replay redo, type:%u.", entry->type);
    dss_redo_handler_t *handler = &g_dss_handlers[entry->type];
    dss_vg_info_item_t *actual_vg_item = vg_item;
    if (vg_item->id != entry->vg_id) {
        // load vg_item
        actual_vg_item = &g_vgs_info->volume_group[entry->vg_id];
    }
    if (DSS_STANDBY_CLUSTER_XLOG_VG(actual_vg_item->id)) {
        return CM_SUCCESS;
    }
    return handler->replay(actual_vg_item, entry);
}

// apply log to update meta
status_t dss_apply_log(dss_vg_info_item_t *vg_item, char *log_buf)
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
        status = dss_replay(vg_item, entry);
        DSS_RETURN_IF_ERROR(status);
        offset += entry->size;
    }

    return CM_SUCCESS;
}

static status_t dss_recover_core_ctrlinfo(dss_vg_info_item_t *vg_item)
{
    status_t status;
    uint32 checksum;
    bool32 remote = CM_FALSE;
    status = dss_load_vg_ctrl_part(
        vg_item, (int64)DSS_CTRL_CORE_OFFSET, &vg_item->dss_ctrl->core, (int32)DSS_CORE_CTRL_SIZE, &remote);
    DSS_RETURN_IFERR2(status, LOG_DEBUG_ERR("Load dss ctrl core failed."));
    checksum = dss_get_checksum(&vg_item->dss_ctrl->core, DSS_CORE_CTRL_SIZE);
    if (checksum != vg_item->dss_ctrl->core.checksum) {
        LOG_RUN_INF("Try recover dss ctrl core.");
        status = dss_load_vg_ctrl_part(
            vg_item, (int64)DSS_CTRL_BAK_CORE_OFFSET, &vg_item->dss_ctrl->core, (int32)DSS_CORE_CTRL_SIZE, &remote);
        DSS_RETURN_IFERR2(status, LOG_DEBUG_ERR("Load dss ctrl bak core failed."));
        checksum = dss_get_checksum(&vg_item->dss_ctrl->core, DSS_CORE_CTRL_SIZE);
        dss_check_checksum(checksum, vg_item->dss_ctrl->core.checksum);
        status =
            dss_write_ctrl_to_disk(vg_item, (int64)DSS_CTRL_CORE_OFFSET, &vg_item->dss_ctrl->core, DSS_CORE_CTRL_SIZE);
        DSS_RETURN_IFERR2(status, LOG_DEBUG_ERR("Write dss ctrl core failed."));
    } else {
        status = dss_write_ctrl_to_disk(
            vg_item, (int64)DSS_CTRL_BAK_CORE_OFFSET, &vg_item->dss_ctrl->core, DSS_CORE_CTRL_SIZE);
        DSS_RETURN_IFERR2(status, LOG_DEBUG_ERR("Write dss ctrl bak core failed."));
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
        DSS_RETURN_IFERR2(CM_ERROR, LOG_DEBUG_ERR("Can not allocate memory in stack."));
    }
    status =
        dss_load_vg_ctrl_part(vg_item, (int64)DSS_CTRL_VOLUME_OFFSET, volume, (int32)DSS_VOLUME_CTRL_SIZE, &remote);
    DSS_RETURN_IFERR3(status, DSS_FREE_POINT(volume), LOG_DEBUG_ERR("Load dss ctrl volume failed."));
    checksum = dss_get_checksum(volume, DSS_VOLUME_CTRL_SIZE);
    if (checksum != volume->checksum) {
        LOG_RUN_INF("Try recover dss ctrl volume.");
        status = dss_load_vg_ctrl_part(
            vg_item, (int64)DSS_CTRL_BAK_VOLUME_OFFSET, volume, (int32)DSS_VOLUME_CTRL_SIZE, &remote);
        DSS_RETURN_IFERR3(status, DSS_FREE_POINT(volume), LOG_DEBUG_ERR("Load dss ctrl bak volume failed."));
        checksum = dss_get_checksum(volume, DSS_VOLUME_CTRL_SIZE);
        dss_check_checksum(checksum, volume->checksum);
        status = dss_write_ctrl_to_disk(vg_item, (int64)DSS_CTRL_VOLUME_OFFSET, volume, DSS_VOLUME_CTRL_SIZE);
        DSS_RETURN_IFERR3(status, DSS_FREE_POINT(volume), LOG_DEBUG_ERR("Write dss ctrl volume failed."));
    } else {
        status = dss_write_ctrl_to_disk(vg_item, (int64)DSS_CTRL_BAK_VOLUME_OFFSET, volume, DSS_VOLUME_CTRL_SIZE);
        DSS_RETURN_IFERR3(status, DSS_FREE_POINT(volume), LOG_DEBUG_ERR("Write dss ctrl bak volume failed."));
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
    DSS_RETURN_IFERR2(status, LOG_DEBUG_ERR("Load dss ctrl root failed."));
    checksum = dss_get_checksum(block, DSS_BLOCK_SIZE);
    if (checksum != block->checksum) {
        LOG_RUN_INF("Try recover dss ctrl root.");
        status = dss_load_vg_ctrl_part(vg_item, (int64)DSS_CTRL_BAK_ROOT_OFFSET, block, (int32)DSS_BLOCK_SIZE, &remote);
        DSS_RETURN_IFERR2(status, LOG_DEBUG_ERR("Load dss ctrl bak root failed."));
        checksum = dss_get_checksum(block, DSS_BLOCK_SIZE);
        dss_check_checksum(checksum, block->checksum);
        status = dss_write_ctrl_to_disk(vg_item, (int64)DSS_CTRL_ROOT_OFFSET, block, DSS_BLOCK_SIZE);
        DSS_RETURN_IFERR2(status, LOG_DEBUG_ERR("Write dss ctrl root failed."));
    } else {
        status = dss_write_ctrl_to_disk(vg_item, (int64)DSS_CTRL_BAK_ROOT_OFFSET, block, DSS_BLOCK_SIZE);
        DSS_RETURN_IFERR2(status, LOG_DEBUG_ERR("Write dss ctrl bak root failed."));
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
    vol_head->software_version = 0;
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
    vg_item->dss_ctrl->core.volume_attrs[id].size =  old_size;
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
            DSS_RETURN_IF_ERROR(dss_recover_volume_head(vg_item,  vg_item->dss_ctrl->volume.defs[i].id));
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
    return dss_recover_modify_info(vg_item);
}

void dss_reset_all_log_slot()
{
    for (int32_t i = 0; i < DSS_LOG_BUF_SLOT_COUNT; i++) {
        (void)dss_reset_log_slot_head(i);
    }
}

// Reserve the batch head for verification at both the head and the tail
bool32 dss_check_redo_log_available(dss_redo_batch_t *batch, dss_vg_info_item_t *vg_item, uint8 slot)
{
    dss_redo_batch_t *tail = NULL;
    uint32 data_size, hash_code;

    tail = (dss_redo_batch_t *)((char *)batch + batch->size);
    bool32 is_complete = CM_TRUE;
    do {
        if (batch->size <= DSS_REDO_BATCH_HEAD_SIZE) {
            LOG_RUN_INF("Invalid size %u of log slot %u.", batch->size, slot);
            is_complete = CM_FALSE;
            break;
        }
        if (batch->size != tail->size) {
            LOG_RUN_INF("Batch head data size is not the same with tail, batch head is %u, batch tail is %u.",
                batch->size, tail->size);
            is_complete = CM_FALSE;
            break;
        }
        if (batch->time != tail->time) {
            LOG_RUN_INF("Batch head time is not the same with tail, batch head is %lld, batch tail is %lld.",
                batch->time, tail->time);
            is_complete = CM_FALSE;
            break;
        }
        data_size = batch->size - DSS_REDO_BATCH_HEAD_SIZE;
        hash_code = cm_hash_bytes((uint8 *)batch->data, data_size, INFINITE_HASH_RANGE);
        if (batch->hash_code != hash_code) {
            LOG_RUN_INF("Batch head hash code is not the same with data, batch head is %u, data is %u.",
                batch->hash_code, hash_code);
            is_complete = CM_FALSE;
            break;
        }
        if (batch->hash_code != tail->hash_code) {
            LOG_RUN_INF("Batch head hash code is not the same with tail, batch head is %u, batch tail is %u.",
                batch->hash_code, tail->hash_code);
            is_complete = CM_FALSE;
            break;
        }
    } while (0);
    if (!is_complete) {
        if (slot == DSS_LOG_BUF_SLOT_COUNT) {
            dss_reset_all_log_slot();
        } else {
            (void)dss_reset_log_slot_head(slot);
        }
        return CM_FALSE;
    }
    return CM_TRUE;
}

static int32 lsn_compare(const void *pa, const void *pb)
{
    const dss_sort_handle_t *a = (const dss_sort_handle_t *)pa;
    const dss_sort_handle_t *b = (const dss_sort_handle_t *)pb;
    return (int32)(a->lsn - b->lsn);
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

status_t dss_recover_when_instance_start(dss_redo_batch_t *batch, bool32 need_check)
{
    LOG_RUN_INF("Begin to check assembled redo when instance start.");
    if (need_check) {
        if (!dss_check_redo_log_available(batch, NULL, DSS_LOG_BUF_SLOT_COUNT)) {
            LOG_RUN_INF("The redo log is not complete, ignore.");
            return CM_SUCCESS;
        }
    }

    dss_redo_entry_t *entry = NULL;
    dss_sort_handle_t *sort_handle = (dss_sort_handle_t *)cm_malloc(batch->count * (uint32)(sizeof(dss_sort_handle_t)));
    if (sort_handle == NULL) {
        DSS_RETURN_IFERR2(CM_ERROR, LOG_DEBUG_ERR("Malloc sort handle failed when recover."));
    }
    uint64 offset = 0;
    for (uint32 i = 0; i < batch->count; i++) {
        entry = (dss_redo_entry_t *)(batch->data + offset);
        sort_handle[i].offset = offset;
        sort_handle[i].lsn = entry->lsn;
        offset += entry->size;
    }
    qsort(sort_handle, batch->count, sizeof(dss_sort_handle_t), lsn_compare);

    dss_vg_info_item_t *vg_item = &g_vgs_info->volume_group[0];
    dss_ctrl_t *dss_ctrl = vg_item->dss_ctrl;
    int64 au_size = (int64)dss_get_vg_au_size(dss_ctrl);
    LOG_RUN_INF("Set vg status recovery.");
    dss_set_vg_status_recovery();
    LOG_RUN_INF("Begin recovering by sort.");
    for (uint32 i = batch->sort_offset; i < batch->count; i++) {
        entry = (dss_redo_entry_t *)(batch->data + sort_handle[i].offset);
        LOG_RUN_INF("Start to replay redo log, entry type %u, vg_id %u.", entry->type, entry->vg_id);
        status_t status = dss_replay(vg_item, entry);
        DSS_RETURN_IFERR3(status, DSS_FREE_POINT(sort_handle),
            LOG_RUN_ERR("Failed to replay redo log, entry type %u, vg_id %u.", entry->type, entry->vg_id));
        batch->sort_offset = i;
        status = dss_write_volume_inst(vg_item, &vg_item->volume_handle[0], au_size, batch, DSS_DISK_UNIT_SIZE);
        DSS_RETURN_IFERR3(
            status, DSS_FREE_POINT(sort_handle), LOG_RUN_ERR("Failed to flush redo log head when recovery."));
    }
    DSS_FREE_POINT(sort_handle);
    dss_reset_all_log_slot();
    dss_set_vg_status_open();
    LOG_RUN_INF("Complete recovering by sort.");
    return CM_SUCCESS;
}

char *dss_get_log_buf(dss_session_t *session, dss_vg_info_item_t *vg_item)
{
    if (session->log_split == DSS_INVALID_SLOT) {
        return NULL;
    }
    dss_log_file_ctrl_t *log_ctrl = dss_get_kernel_instance_log_ctrl();
    char *log_buf = (char *)(log_ctrl->log_buf + session->log_split * DSS_LOG_BUFFER_SIZE);
    return log_buf;
}

void dss_reset_log_buf(dss_session_t *session, dss_vg_info_item_t *vg_item)
{
    (void)dss_reset_log_slot_head(session->log_split);
    dss_free_log_slot(session);
}

status_t dss_process_redo_log(dss_session_t *session, dss_vg_info_item_t *vg_item)
{
    char *log_buf = dss_get_log_buf(session, vg_item);
    if (log_buf == NULL) {
        return CM_SUCCESS;
    }
    dss_redo_batch_t *batch = (dss_redo_batch_t *)log_buf;
    if (batch->size == 0) {
        return CM_SUCCESS;
    }

    if (batch->size == sizeof(dss_redo_batch_t) || vg_item->status == DSS_VG_STATUS_RECOVERY || session == NULL) {
        return CM_SUCCESS;
    }

    status_t status = dss_flush_log(session->log_split, vg_item, log_buf);
    DSS_RETURN_IFERR2(status, LOG_DEBUG_ERR("Failed to flush log,errcode:%d.", cm_get_error_code()));

    status = dss_apply_log(vg_item, log_buf);
    if (status != CM_SUCCESS) {
        LOG_DEBUG_ERR("Failed to apply log,errcode:%d.", cm_get_error_code());
        return status;
    }
    dss_reset_log_buf(session, vg_item);
    return CM_SUCCESS;
}

static status_t dss_rollback(dss_vg_info_item_t *vg_item, dss_redo_entry_t *entry)
{
    DSS_LOG_DEBUG_OP("rollback redo, type:%u.", entry->type);
    dss_redo_handler_t *handler = &g_dss_handlers[entry->type];
    dss_vg_info_item_t *actual_vg_item = vg_item;
    if (vg_item->id != entry->vg_id) {
        // load vg_item
        actual_vg_item = &g_vgs_info->volume_group[entry->vg_id];
    }
    return handler->rollback(actual_vg_item, entry);
}

status_t dss_rollback_log(dss_vg_info_item_t *vg_item, char *log_buf)
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
        status = dss_rollback(vg_item, entry);
        if (status != CM_SUCCESS) {
            return status;
        }
    }

    return CM_SUCCESS;
}

void dss_rollback_mem_update(int32_t log_split, dss_vg_info_item_t *vg_item)
{
    char *log_buf = NULL;
    if (log_split == DSS_INVALID_SLOT) {
        return;
    }
    dss_log_file_ctrl_t *log_ctrl = dss_get_kernel_instance_log_ctrl();
    log_buf = (char *)(log_ctrl->log_buf + log_split * DSS_INSTANCE_LOG_SPLIT_SIZE);
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
    status = dss_rollback_log(vg_item, log_buf);
    CM_ASSERT(status == CM_SUCCESS);
    (void)dss_reset_log_slot_head(log_split);
    vg_item->status = DSS_VG_STATUS_OPEN;
    return;
}
