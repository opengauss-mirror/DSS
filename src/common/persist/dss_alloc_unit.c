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
 * dss_alloc_unit.c
 *
 *
 * IDENTIFICATION
 *    src/common/persist/dss_alloc_unit.c
 *
 * -------------------------------------------------------------------------
 */

#include "dss_defs.h"
#include "dss_alloc_unit.h"
#include "dss_file.h"
#include "dss_redo.h"
#include "dss_fs_aux.h"

#ifdef __cplusplus
extern "C" {
#endif

void dss_init_au_root(dss_ctrl_t *dss_ctrl)
{
    CM_ASSERT(dss_ctrl != NULL);
    dss_au_root_t *au_root = DSS_GET_AU_ROOT(dss_ctrl);
    au_root->count = 0;
    au_root->free_root = CM_INVALID_ID64;
    au_root->free_vol_id = 0;

    return;
}

bool32 dss_can_alloc_from_recycle(const gft_node_t *root_node, bool32 is_before)
{
    if ((is_before && root_node->items.count >= DSS_MIN_FILE_NUM_IN_RECYCLE) ||
        (!is_before && root_node->items.count > 0)) {
        return DSS_TRUE;
    }

    return CM_FALSE;
}

static status_t dss_alloc_au_recycle_fs_aux(
    dss_session_t *session, dss_vg_info_item_t *vg_item, gft_node_t *node, dss_block_id_t *auid, uint16 sec_index)
{
    // if *auid is aux, need to get the real auid from the aux
    if (DSS_IS_FILE_INNER_INITED(node->flags) && DSS_BLOCK_ID_IS_AUX(*auid)) {
        dss_fs_aux_t *fs_aux = dss_find_fs_aux(session, vg_item, node, *auid, CM_TRUE, NULL, sec_index);
        if (fs_aux == NULL) {
            LOG_DEBUG_ERR("Failed to get fs aux block :%llu,%llu,%llu, maybe no memory.", (uint64)auid->au,
                (uint64)auid->volume, (uint64)auid->block);
            return CM_ERROR;
        }

        // may exist aux uninited flag, clean it
        dss_set_auid(auid, DSS_BLOCK_ID_SET_INITED(fs_aux->head.data_id));
        // after get the real auid, recycle the aux
        dss_fs_aux_root_t *fs_aux_root = DSS_GET_FS_AUX_ROOT(vg_item->dss_ctrl);
        dss_free_fs_aux(session, vg_item, fs_aux, fs_aux_root);
    }
    return CM_SUCCESS;
}

static void dss_remove_last_au_from_sec_fs_block(dss_session_t *session, dss_vg_info_item_t *vg_item,
    gft_node_t *ft_node, dss_fs_block_t *entry_fs_block, uint16 entry_fs_idx, ga_obj_id_t obj_id, dss_fs_block_t *block)
{
    uint16 tail_idx = (uint16)(block->head.used_num - 1);
    uint16 old_sec_used_num = block->head.used_num;
    dss_block_id_t old_sec_id = block->bitmap[tail_idx];
    block->head.used_num--;
    dss_set_blockid(&block->bitmap[tail_idx], DSS_INVALID_64);
    dss_redo_set_file_size_t redo_size;
    uint64 old_size = (uint64)ft_node->size;
    uint64 au_size = dss_get_vg_au_size(vg_item->dss_ctrl);
    (void)cm_atomic_set(&ft_node->size, (int64)((uint64)ft_node->size - au_size));
    redo_size.ftid = ft_node->id;
    redo_size.size = (uint64)ft_node->size;
    redo_size.oldsize = old_size;
    dss_put_log(session, vg_item, DSS_RT_SET_FILE_SIZE, &redo_size, sizeof(redo_size));
    // If the fs_block is exhausted after this allocation, it should be feed.
    // If not exhausted, it should be modified for loss the allcated AU.
    if (block->head.used_num == 0) {
        LOG_DEBUG_INF("[AU][ALLOC] Second FSB(%s) is exhausted after allocation, free its space.",
            dss_display_metaid(block->head.common.id));
        dss_free_fs_block_addr(session, vg_item, (char *)block, obj_id);
        dss_set_blockid(&entry_fs_block->bitmap[entry_fs_idx], DSS_INVALID_64);
    } else {
        dss_redo_set_fs_block_t redo;
        redo.index = tail_idx;
        redo.id = block->head.common.id;
        redo.used_num = block->head.used_num;
        redo.value = block->bitmap[tail_idx];
        redo.old_used_num = old_sec_used_num;
        redo.old_value = old_sec_id;
        dss_put_log(session, vg_item, DSS_RT_SET_FILE_FS_BLOCK, &redo, sizeof(redo));
    }
}

static void dss_remove_last_sec_fs_from_entry_fs(dss_session_t *session, dss_vg_info_item_t *vg_item,
    gft_node_t *recycle_root_node, gft_node_t *ft_node, dss_fs_block_t *entry_fs_block, ga_obj_id_t entry_objid)
{
    dss_fs_block_header *entry_block = &(entry_fs_block->head);
    uint16 old_used_num = entry_block->used_num;
    uint16 entry_fs_tail_idx = (uint16)(entry_block->used_num - 1);
    dss_block_id_t old_id = entry_fs_block->bitmap[entry_fs_tail_idx];
    entry_block->used_num--;
    dss_redo_set_fs_block_t redo;
    if (entry_block->used_num == 0) {
        LOG_DEBUG_INF("[AU][ALLOC] entry FSB(%s) become empty, free its space.", dss_display_metaid(ft_node->entry));
        dss_free_fs_block_addr(session, vg_item, (char *)entry_block, entry_objid);
        dss_free_ft_node(session, vg_item, recycle_root_node, ft_node, CM_TRUE);
    } else {
        redo.index = entry_fs_tail_idx;
        redo.id = entry_block->common.id;
        redo.used_num = entry_block->used_num;
        redo.value = entry_fs_block->bitmap[entry_fs_tail_idx];
        redo.old_used_num = old_used_num;
        redo.old_value = old_id;
        dss_put_log(session, vg_item, DSS_RT_SET_FILE_FS_BLOCK, &redo, sizeof(redo));
    }
}

// Try to allocate one au from the specified recycle file, there are such possibilities:
// 1. If the recycle file has more than one AUs, then allocate it.
//  1.1 If after allocation, the recycle file is exhausted, its metadata would be directly freed.
//  1.2 If after allocation, it still has AUs left, just update its metadata accordingly.
// 2. If the recycle file has no AUs, its metadata would be directly freed.
static status_t dss_alloc_au_from_one_recycle_file(dss_session_t *session, dss_vg_info_item_t *vg_item,
    gft_node_t *recycle_root_node, gft_node_t *ft_node, bool32 *found, auid_t *auid)
{
    LOG_DEBUG_INF("[AU][ALLOC] Begin to alloc au from recycle file %s.", ft_node->name);
    *found = DSS_FALSE;
    ga_obj_id_t entry_objid;
    dss_fs_block_t *entry_fs_block = (dss_fs_block_t *)dss_find_block_in_shm(
        session, vg_item, ft_node->entry, DSS_BLOCK_TYPE_FS, CM_TRUE, &entry_objid, CM_FALSE);
    if (entry_fs_block == NULL) {
        LOG_DEBUG_ERR("[AU][ALLOC] Failed to get fs block: %s.", dss_display_metaid(ft_node->entry));
        return CM_ERROR;
    }
    dss_fs_block_header *entry_block = (dss_fs_block_header *)(&entry_fs_block->head);
    CM_ASSERT(entry_block->used_num > 0);
    dss_check_fs_block_affiliation(entry_block, ft_node->id, DSS_ENTRY_FS_INDEX);
    ga_obj_id_t sec_objid;
    uint16 entry_fs_tail_idx = (uint16)(entry_block->used_num - 1);
    dss_block_id_t sec_block_id = entry_fs_block->bitmap[entry_fs_tail_idx];
    dss_fs_block_t *block = (dss_fs_block_t *)dss_find_block_in_shm(
        session, vg_item, sec_block_id, DSS_BLOCK_TYPE_FS, DSS_TRUE, &sec_objid, CM_FALSE);
    if (block == NULL) {
        LOG_DEBUG_ERR("[AU][ALLOC] Failed to get fs block: %s.", dss_display_metaid(ft_node->entry));
        return CM_ERROR;
    }
    dss_check_fs_block_flags(&block->head, DSS_BLOCK_FLAG_USED);
    bool32 is_sec_fs_empty = DSS_FALSE;
    if (block->head.used_num > 0) {
        uint16 tail_idx = (uint16)(block->head.used_num - 1);
        *auid = block->bitmap[tail_idx];
        CM_ASSERT(auid->volume < DSS_MAX_VOLUMES);
        DSS_RETURN_IF_ERROR(dss_alloc_au_recycle_fs_aux(session, vg_item, ft_node, auid, tail_idx));
        dss_remove_last_au_from_sec_fs_block(
            session, vg_item, ft_node, entry_fs_block, entry_fs_tail_idx, sec_objid, block);
        if (block->head.used_num == 0) {
            is_sec_fs_empty = DSS_TRUE;
        }
        *found = DSS_TRUE;
    } else {
        LOG_DEBUG_INF(
            "[AU][ALLOC] Second FSB(%s) is empty, free its space.", dss_display_metaid(block->head.common.id));
        dss_free_fs_block_addr(session, vg_item, (char *)block, sec_objid);
        dss_set_blockid(&entry_fs_block->bitmap[entry_fs_tail_idx], DSS_INVALID_64);
        is_sec_fs_empty = DSS_TRUE;
    }

    if (is_sec_fs_empty) {
        LOG_DEBUG_INF("[AU][ALLOC] Second FSB(%s) is freed, its entry FSB(%s) needs modification.",
            dss_display_metaid(sec_block_id), dss_display_metaid(ft_node->entry));
        dss_remove_last_sec_fs_from_entry_fs(session, vg_item, recycle_root_node, ft_node, entry_fs_block, entry_objid);
    }

    if (*found) {
        DSS_LOG_DEBUG_OP(
            "[AU][ALLOC] Succeed to allocate au: %s from recycle file %s.", dss_display_metaid(*auid), ft_node->name);
    } else {
        DSS_LOG_DEBUG_OP("[AU][ALLOC] No au found in recycle file %s.", ft_node->name);
    }
    return CM_SUCCESS;
}

static status_t dss_alloc_au_from_recycle(
    dss_session_t *session, dss_vg_info_item_t *vg_item, bool32 is_before, bool32 *found, auid_t *auid)
{
    dss_set_auid(auid, DSS_INVALID_64);
    dss_au_root_t *dss_au_root = DSS_GET_AU_ROOT(vg_item->dss_ctrl);
    ftid_t free_root = *(ftid_t *)(&dss_au_root->free_root);
    gft_node_t *recycle_root_node = dss_get_ft_node_by_ftid(session, vg_item, free_root, DSS_TRUE, CM_FALSE);
    CM_ASSERT(recycle_root_node != NULL);
    *found = DSS_FALSE;
    if (!dss_can_alloc_from_recycle(recycle_root_node, is_before)) {
        LOG_DEBUG_INF("[AU][ALLOC] Currently we cannot allocate AUs from .recycle of vg:%s.", vg_item->vg_name);
        return CM_SUCCESS;
    }

    LOG_DEBUG_INF("[AU][ALLOC] Begin to alloc au from recycle dir in vg:%s.", vg_item->vg_name);

    // Try every file under .recycle one by one until one available AU is found for allocation.
    do {
        ftid_t cur_ftid = recycle_root_node->items.first;
        gft_node_t *cur_node = dss_get_ft_node_by_ftid(session, vg_item, cur_ftid, DSS_TRUE, CM_FALSE);
        if (cur_node == NULL) {
            LOG_DEBUG_ERR("[AU][ALLOC] Failed to get ft node: %s.", dss_display_metaid(cur_ftid));
            return CM_ERROR;
        }

        CM_ASSERT(cur_node->type == GFT_FILE || cur_node->type == GFT_LINK);
        dss_check_ft_node_parent(cur_node, free_root);
        // The recycle file may be freed in dss_alloc_au_from_one_recycle_file.
        DSS_RETURN_IF_ERROR(
            dss_alloc_au_from_one_recycle_file(session, vg_item, recycle_root_node, cur_node, found, auid));
        if (*found || recycle_root_node->items.count == 0) {
            break;
        }
    } while (DSS_TRUE);

    return CM_SUCCESS;
}

status_t dss_alloc_au_core(dss_session_t *session, dss_ctrl_t *dss_ctrl, dss_vg_info_item_t *vg_item, auid_t *auid)
{
    dss_au_root_t *dss_au_root = DSS_GET_AU_ROOT(dss_ctrl);
    char *entry_path = vg_item->entry_path;
    uint32 found = 0;
    uint32 used_count = 0;
    uint64 au_size = dss_get_vg_au_size(dss_ctrl);
    uint64 disk_version = dss_ctrl->core.version;
    for (uint32 i = 0; used_count < dss_ctrl->core.volume_count && i < DSS_MAX_VOLUMES; i++) {
        if (dss_ctrl->volume.defs[i].flag != VOLUME_OCCUPY) {
            continue;
        }
        LOG_DEBUG_INF("[AU][ALLOC] Allocate au, volume id:%u, free:%llu, au_size:%llu, version:%llu.", i,
            dss_ctrl->core.volume_attrs[i].free, au_size, disk_version);
        used_count++;
        if (dss_ctrl->core.volume_attrs[i].free >= au_size) {
            auid->au = dss_get_au_id(vg_item, dss_ctrl->core.volume_attrs[i].hwm);
            auid->volume = dss_ctrl->core.volume_attrs[i].id;
            auid->block = 0;
            auid->item = 0;
            dss_ctrl->core.volume_attrs[i].hwm = dss_ctrl->core.volume_attrs[i].hwm + au_size;
            dss_ctrl->core.volume_attrs[i].free = dss_ctrl->core.volume_attrs[i].free - au_size;

            dss_au_root->count++;
            found = 1;

            dss_update_core_ctrl(session, vg_item, &dss_ctrl->core, 0, CM_FALSE);
            DSS_LOG_DEBUG_OP("[AU][ALLOC] Succed to allocate au: %s, hwm:%llu,i:%u.", dss_display_metaid(*auid),
                dss_ctrl->core.volume_attrs[i].hwm, i);
            break;
        }
    }

    if (found) {
        return CM_SUCCESS;
    }
    status_t status = dss_alloc_au_from_recycle(session, vg_item, CM_FALSE, &found, auid);
    if (status != CM_SUCCESS) {
        LOG_DEBUG_ERR(
            "[AU][ALLOC] Failed to allocate au from recycle dir after trying to allocate vg disk, vg %s.", entry_path);
        return status;
    }
    if (!found) {
        DSS_THROW_ERROR(ERR_DSS_NO_SPACE);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

status_t dss_refresh_core_and_volume(dss_vg_info_item_t *vg_item)
{
    if (!DSS_STANDBY_CLUSTER && dss_is_readwrite()) {
        DSS_ASSERT_LOG(dss_need_exec_local(), "only masterid %u can be readwrite.", dss_get_master_id());
        return CM_SUCCESS;
    }
    status_t status;
    char *entry_path = vg_item->entry_path;
    dss_ctrl_t *dss_ctrl = vg_item->dss_ctrl;

    uint64 disk_version;
    status = dss_get_core_version(vg_item, &disk_version);
    if (status != CM_SUCCESS) {
        LOG_DEBUG_ERR("[AU][ALLOC] Failed to get core version, vg %s.", entry_path);
        return status;
    }

    if (dss_compare_version(disk_version, dss_ctrl->core.version)) {
        status = dss_check_volume(vg_item, CM_INVALID_ID32);
        if (status != CM_SUCCESS) {
            LOG_DEBUG_ERR("[AU][ALLOC] Failed to check volume, vg %s.", entry_path);
            return status;
        }
        status = dss_load_core_ctrl(vg_item, &dss_ctrl->core);
        if (status != CM_SUCCESS) {
            LOG_DEBUG_ERR("Failed to get core ctrl, vg %s.", entry_path);
            return status;
        }
        DSS_LOG_DEBUG_OP(
            "[AU][ALLOC] Allocate au check version, old:%llu, new:%llu.", dss_ctrl->core.version, disk_version);
    }
    return CM_SUCCESS;
}
bool32 dss_alloc_au_batch(dss_session_t *session, dss_vg_info_item_t *vg_item, auid_t *auid, uint32 count)
{
    dss_ctrl_t *dss_ctrl = vg_item->dss_ctrl;
    dss_au_root_t *dss_au_root = DSS_GET_AU_ROOT(dss_ctrl);
    uint32 found = 0;
    uint32 used_count = 0;
    uint64 au_size = dss_get_vg_au_size(dss_ctrl);

    for (uint32 i = 0; used_count < dss_ctrl->core.volume_count && i < DSS_MAX_VOLUMES; i++) {
        if (dss_ctrl->volume.defs[i].flag == VOLUME_FREE || dss_ctrl->volume.defs[i].flag == VOLUME_PREPARE) {
            continue;
        }
        LOG_DEBUG_INF("Allocate batch au, volume id:%u, free:%llu, size:%llu, version:%llu.", i,
            dss_ctrl->core.volume_attrs[i].free, (au_size * count), dss_ctrl->core.version);
        used_count++;
        if (dss_ctrl->core.volume_attrs[i].free >= (au_size * count)) {
            auid->au = dss_get_au_id(vg_item, dss_ctrl->core.volume_attrs[i].hwm);
            auid->volume = dss_ctrl->core.volume_attrs[i].id;
            auid->block = 0;
            auid->item = 0;
            dss_ctrl->core.volume_attrs[i].hwm = dss_ctrl->core.volume_attrs[i].hwm + (au_size * count);
            dss_ctrl->core.volume_attrs[i].free = dss_ctrl->core.volume_attrs[i].free - (au_size * count);

            dss_au_root->count += count;
            found = 1;

            dss_update_core_ctrl(session, vg_item, &dss_ctrl->core, 0, CM_FALSE);
            DSS_LOG_DEBUG_OP("Allocate batch count:%u, first au %s,hwm:%llu,i:%u.", count, dss_display_metaid(*auid),
                dss_ctrl->core.volume_attrs[i].hwm, i);
            break;
        }
    }
    return (found > 0) ? CM_TRUE : CM_FALSE;
}

status_t dss_alloc_au(dss_session_t *session, dss_vg_info_item_t *vg_item, auid_t *auid)
{
    CM_ASSERT(vg_item != NULL && auid != NULL);
    LOG_DEBUG_INF("[AU][ALLOC] Begin to allocate au in vg:%s", vg_item->vg_name);
    DSS_RETURN_IF_ERROR(dss_refresh_core_and_volume(vg_item));
    char *entry_path = vg_item->entry_path;
    dss_ctrl_t *dss_ctrl = vg_item->dss_ctrl;

    dss_au_root_t *au_root = DSS_GET_AU_ROOT(dss_ctrl);
    /* when we are creating vg, the free_root may be not initialized yet! */
    if (au_root->free_root != CM_INVALID_ID64) {
        bool32 found = CM_FALSE;
        status_t status = dss_alloc_au_from_recycle(session, vg_item, DSS_TRUE, &found, auid);
        if (status != CM_SUCCESS) {
            LOG_DEBUG_ERR("[AU][ALLOC] Failed to allocate au from recycle dir, vg %s.", entry_path);
            return status;
        }

        if (found) {
            DSS_LOG_DEBUG_OP(
                "[AU][ALLOC] Succeed to allocate au: %s from recyle dir at first.", dss_display_metaid(*auid));
            return CM_SUCCESS;
        }
    }

    DSS_RETURN_IF_ERROR(dss_alloc_au_core(session, dss_ctrl, vg_item, auid));
    return CM_SUCCESS;
}

status_t dss_get_core_version(dss_vg_info_item_t *item, uint64 *version)
{
    CM_ASSERT(item != NULL);
    CM_ASSERT(version != NULL);
#ifndef WIN32
    char temp[DSS_DISK_UNIT_SIZE] __attribute__((__aligned__(DSS_DISK_UNIT_SIZE)));
#else
    char temp[DSS_DISK_UNIT_SIZE];
#endif
    bool32 remote = CM_FALSE;
    status_t status =
        dss_load_vg_ctrl_part(item, (int64)DSS_CTRL_CORE_OFFSET, temp, (int32)DSS_DISK_UNIT_SIZE, &remote);
    if (status != CM_SUCCESS) {
        LOG_DEBUG_ERR("Failed to load vg core version %s.", item->entry_path);
        return status;
    }
    *version = ((dss_core_ctrl_t *)temp)->version;
    return CM_SUCCESS;
}

// shoud lock in caller
status_t dss_load_core_ctrl(dss_vg_info_item_t *item, dss_core_ctrl_t *core)
{
    bool32 remote_chksum = CM_TRUE;
    status_t status =
        dss_load_vg_ctrl_part(item, (int64)DSS_CTRL_CORE_OFFSET, core, (int32)DSS_CORE_CTRL_SIZE, &remote_chksum);
    if (status != CM_SUCCESS) {
        return status;
    }

    if (remote_chksum == CM_FALSE) {
        uint32 checksum = dss_get_checksum(core, DSS_CORE_CTRL_SIZE);
        dss_check_checksum(checksum, core->checksum);
    }

    return CM_SUCCESS;
}

status_t dss_load_redo_ctrl(dss_vg_info_item_t *vg_item)
{
    if (vg_item->volume_handle[0].handle == DSS_INVALID_HANDLE) {
        status_t ret = dss_open_volume(vg_item->entry_path, NULL, DSS_INSTANCE_OPEN_FLAG, &vg_item->volume_handle[0]);
        DSS_RETURN_IFERR2(ret, LOG_DEBUG_ERR("Failed to open volume %s.", vg_item->entry_path));
    }
    bool32 remote_checksum = CM_FALSE;
    status_t status = dss_load_vg_ctrl_part(
        vg_item, (int64)DSS_CTRL_REDO_OFFSET, &vg_item->dss_ctrl->redo_ctrl, DSS_DISK_UNIT_SIZE, &remote_checksum);
    if (status != CM_SUCCESS) {
        return status;
    }
    return CM_SUCCESS;
}

void dss_update_core_ctrl(
    dss_session_t *session, dss_vg_info_item_t *item, dss_core_ctrl_t *core, uint32 volume_id, bool32 is_only_root)
{
    CM_ASSERT(item != NULL);
    CM_ASSERT(core != NULL);

    char *buf;
    uint32 size;

    if (is_only_root) {
        buf = (char *)core;
        size = DSS_DISK_UNIT_SIZE;
    } else {
        buf = (char *)core;
        size = sizeof(dss_core_ctrl_t);
    }

    // when update core ctrl ,handle should be valid.
    dss_put_log(session, item, DSS_RT_UPDATE_CORE_CTRL, buf, size);
}

int64 dss_get_au_offset(dss_vg_info_item_t *item, auid_t auid)
{
    return (int64)((uint64)auid.au * (uint64)dss_get_vg_au_size(item->dss_ctrl));
}

status_t dss_get_au(dss_vg_info_item_t *item, auid_t auid, char *buf, int32 size)
{
    if (auid.volume >= DSS_MAX_VOLUMES) {
        return CM_ERROR;
    }

    bool32 remote = CM_FALSE;
    int64_t offset = dss_get_au_offset(item, auid);
    return dss_check_read_volume(item, (uint32)auid.volume, offset, buf, size, &remote);
}

status_t dss_get_au_head(dss_vg_info_item_t *item, auid_t auid, dss_au_head_t *au_head)
{
    CM_ASSERT(item != NULL);
    CM_ASSERT(au_head != NULL);

    if (auid.volume >= DSS_MAX_VOLUMES) {
        return CM_ERROR;
    }

    return dss_get_au(item, auid, (char *)au_head, sizeof(dss_au_head_t));
}

bool32 dss_cmp_auid(auid_t auid, uint64 id)
{
    return *(uint64 *)&auid == id;
}

void dss_set_auid(auid_t *auid, uint64 id)
{
    *(uint64 *)auid = id;
}

void dss_set_blockid(dss_block_id_t *blockid, uint64 id)
{
    *(uint64 *)blockid = id;
}

bool32 dss_cmp_blockid(dss_block_id_t blockid, uint64 id)
{
    return *(uint64 *)&blockid == id;
}

uint64 dss_get_au_id(dss_vg_info_item_t *item, uint64 offset)
{
    return offset / (uint64)dss_get_vg_au_size(item->dss_ctrl);
}

status_t dss_get_volume_version(dss_vg_info_item_t *item, uint64 *version)
{
    CM_ASSERT(item != NULL);
    CM_ASSERT(version != NULL);
#ifndef WIN32
    char temp[DSS_DISK_UNIT_SIZE] __attribute__((__aligned__(DSS_DISK_UNIT_SIZE)));
#else
    char temp[DSS_DISK_UNIT_SIZE];
#endif
    bool32 remote = CM_FALSE;
    status_t status =
        dss_load_vg_ctrl_part(item, (int64)DSS_CTRL_VOLUME_OFFSET, temp, (int32)DSS_DISK_UNIT_SIZE, &remote);
    if (status != CM_SUCCESS) {
        LOG_DEBUG_ERR("Failed to load vg core version %s.", item->entry_path);
        return status;
    }
    *version = ((dss_core_ctrl_t *)temp)->version;
    return CM_SUCCESS;
}
#ifdef __cplusplus
}
#endif
