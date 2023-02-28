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
 *    src/common/dss_alloc_unit.c
 *
 * -------------------------------------------------------------------------
 */

#include "dss_alloc_unit.h"
#include "dss_file.h"
#include "dss_syncpoint.h"
#include "dss_redo.h"

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

static status_t dss_alloc_au_from_recycle(
    dss_session_t *session, dss_vg_info_item_t *vg_item, bool32 is_before, auid_t *auid, bool8 latch_ft_root)
{
    dss_ctrl_t *dss_ctrl = vg_item->dss_ctrl;
    dss_au_root_t *dss_au_root = DSS_GET_AU_ROOT(dss_ctrl);
    bool32 entry_changed = CM_FALSE;
    ftid_t free_root = *(ftid_t *)(&dss_au_root->free_root);
    gft_node_t *root_node = dss_get_ft_node_by_ftid(vg_item, free_root, DSS_TRUE, CM_FALSE);
    CM_ASSERT(root_node != NULL);
    if (dss_can_alloc_from_recycle(root_node, is_before)) {
        ftid_t id = root_node->items.first;
        gft_node_t *node = dss_get_ft_node_by_ftid(vg_item, id, DSS_TRUE, CM_FALSE);
        if (node == NULL) {
            LOG_DEBUG_ERR("Failed to get ft node %llu,%llu, maybe no memory.", (uint64)(id.au), (uint64)(id.volume));
            return ERR_ALLOC_MEMORY;
        }

        CM_ASSERT(node->type == GFT_FILE || node->type == GFT_LINK);
        ga_obj_id_t entry_objid;
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
        CM_ASSERT(entry_block->used_num > 0);

        index = (uint16)(entry_block->used_num - 1);
        dss_fs_block_t *block = (dss_fs_block_t *)dss_find_block_in_shm(
            vg_item, entry_fs_block->bitmap[index], DSS_BLOCK_TYPE_FS, DSS_TRUE, &sec_objid, CM_FALSE);
        if (!block) {
            LOG_DEBUG_ERR("Failed to get fs block %llu,%llu,%llu, maybe no memory.", (uint64)node->entry.au,
                (uint64)node->entry.volume, (uint64)node->entry.block);
            return ERR_ALLOC_MEMORY;
        }
        CM_ASSERT(block->head.used_num > 0);
        uint16 old_used_num = entry_fs_block->head.used_num;
        dss_block_id_t old_id = entry_fs_block->bitmap[index];
        uint16 old_sec_used_num = block->head.used_num;
        dss_block_id_t old_sec_id;
        if (block->head.used_num > 0) {
            uint16 sec_index = (uint16)(block->head.used_num - 1);
            *auid = block->bitmap[sec_index];
            old_sec_id = *auid;
            CM_ASSERT(auid->volume < DSS_MAX_VOLUMES);
            block->head.used_num--;
            dss_set_blockid(&block->bitmap[sec_index], DSS_INVALID_64);
            dss_redo_set_file_size_t redo_size;
            uint64 old_size = node->size;
            uint64 au_size = dss_get_vg_au_size(dss_ctrl);
            node->size = node->size - au_size;
            redo_size.ftid = node->id;
            redo_size.size = node->size;
            redo_size.oldsize = old_size;
            dss_put_log(session, vg_item, DSS_RT_SET_FILE_SIZE, &redo_size, sizeof(redo_size));
            if (block->head.used_num == 0) {
                dss_free_fs_block_addr(session, vg_item, (char *)block, sec_objid);
                dss_set_blockid(&entry_fs_block->bitmap[index], DSS_INVALID_64);
                entry_changed = DSS_TRUE;
            }

            // if not free ,change
            if (!entry_changed) {
                dss_redo_set_fs_block_t redo;
                redo.index = sec_index;
                redo.id = block->head.id;
                redo.used_num = block->head.used_num;
                redo.value = block->bitmap[sec_index];
                redo.old_used_num = old_sec_used_num;
                redo.old_value = old_sec_id;
                dss_put_log(session, vg_item, DSS_RT_SET_FILE_FS_BLOCK, &redo, sizeof(redo));
            }
        } else {
            dss_free_fs_block_addr(session, vg_item, (char *)block, sec_objid);
            dss_set_blockid(&entry_fs_block->bitmap[index], DSS_INVALID_64);
            entry_changed = DSS_TRUE;
        }

        dss_redo_set_fs_block_t redo;
        if (entry_changed) {
            entry_block->used_num--;
            if (entry_block->used_num == 0) {
                dss_free_fs_block_addr(session, vg_item, (char *)entry_block, entry_objid);
                dss_free_ft_node(session, vg_item, root_node, node, CM_TRUE, CM_TRUE);
            } else {
                redo.index = index;
                redo.id = entry_block->id;
                redo.used_num = entry_block->used_num;
                redo.value = entry_fs_block->bitmap[index];
                redo.old_used_num = old_used_num;
                redo.old_value = old_id;
                dss_put_log(session, vg_item, DSS_RT_SET_FILE_FS_BLOCK, &redo, sizeof(redo));
            }
        }

        DSS_LOG_DEBUG_OP("Succeed to allocate au:%llu from recyle dir.", DSS_ID_TO_U64(*auid));
        return CM_SUCCESS;
    }

    if (is_before) {
        dss_set_auid(auid, DSS_INVALID_64);
        return CM_SUCCESS;
    } else {
        DSS_THROW_ERROR(ERR_DSS_NO_SPACE);
        return CM_ERROR;
    }
}

status_t dss_alloc_au_core(
    dss_session_t *session, dss_ctrl_t *dss_ctrl, dss_vg_info_item_t *vg_item, auid_t *auid, bool8 latch_ft_root)
{
    dss_au_root_t *dss_au_root = DSS_GET_AU_ROOT(dss_ctrl);
    char *entry_path = vg_item->entry_path;
    uint32 found = 0;
    uint32 used_count = 0;
    uint64 au_size = dss_get_vg_au_size(dss_ctrl);
    uint64 disk_version = dss_ctrl->core.version;
    for (uint32 i = 0; used_count < dss_ctrl->core.volume_count && i < DSS_MAX_VOLUMES; i++) {
        if (dss_ctrl->core.volume_attrs[i].flag == VOLUME_FREE) {
            continue;
        }
        LOG_DEBUG_INF("Allocate au, volume id:%u, free:%llu, au_size:%llu, version:%llu.", i,
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
            DSS_LOG_DEBUG_OP("Allocate au, v:%u,au:%llu,block:%u,item:%u,hwm:%llu,i:%u.", auid->volume,
                (uint64)auid->au, auid->block, auid->item, dss_ctrl->core.volume_attrs[i].hwm, i);
            break;
        }
    }

    if (found == 0) {
        status_t status = dss_alloc_au_from_recycle(session, vg_item, CM_FALSE, auid, latch_ft_root);
        if (status != CM_SUCCESS) {
            LOG_DEBUG_ERR(
                "Failed to allocate au from recycle dir after trying to allocate vg disk, vg %s.", entry_path);
            return status;
        }
    }
    return CM_SUCCESS;
}

status_t dss_refresh_core_and_volume(dss_vg_info_item_t *vg_item)
{
    if (dss_is_readwrite()) {
        return CM_SUCCESS;
    }
    status_t status;
    char *entry_path = vg_item->entry_path;
    dss_ctrl_t *dss_ctrl = vg_item->dss_ctrl;

    uint64 disk_version;
    status = dss_get_core_version(vg_item, &disk_version);
    if (status != CM_SUCCESS) {
        LOG_DEBUG_ERR("Failed to get core version, vg %s.", entry_path);
        return status;
    }

    if (dss_compare_version(disk_version, dss_ctrl->core.version)) {
        status = dss_check_volume(vg_item, CM_INVALID_ID32);
        if (status != CM_SUCCESS) {
            LOG_DEBUG_ERR("Failed to check volume, vg %s.", entry_path);
            return status;
        }
        status = dss_load_core_ctrl(vg_item, &dss_ctrl->core);
        if (status != CM_SUCCESS) {
            LOG_DEBUG_ERR("Failed to get core ctrl, vg %s.", entry_path);
            return status;
        }
        DSS_LOG_DEBUG_OP("Allocate au check version, old:%llu, new:%llu.", dss_ctrl->core.version, disk_version);
    }
    return CM_SUCCESS;
}

status_t dss_alloc_au(dss_session_t *session, dss_vg_info_item_t *vg_item, auid_t *auid, bool8 latch_ft_root)
{
#ifdef DB_DEBUG_VERSION
    DSS_TEST_ROLLBACK2(ERR_DSS_NO_SPACE);
#endif
    CM_ASSERT(vg_item != NULL && auid != NULL);
    status_t status = dss_refresh_core_and_volume(vg_item);
    if (status != CM_SUCCESS) {
        return status;
    }
    char *entry_path = vg_item->entry_path;
    dss_ctrl_t *dss_ctrl = vg_item->dss_ctrl;

    dss_au_root_t *au_root = DSS_GET_AU_ROOT(dss_ctrl);
    /* when we are creating vg, the free_root may be not initialized yet! */
    if (au_root->free_root != CM_INVALID_ID64) {
        status = dss_alloc_au_from_recycle(session, vg_item, DSS_TRUE, auid, latch_ft_root);
        if (status != CM_SUCCESS) {
            LOG_DEBUG_ERR("Failed to allocate au from recycle dir, vg %s.", entry_path);
            return status;
        }

        if (!dss_cmp_auid(*auid, DSS_INVALID_64)) {
            DSS_LOG_DEBUG_OP("Succeed to allocate au:%llu from recyle dir at first.", DSS_ID_TO_U64(*auid));
            return CM_SUCCESS;
        }
    }

    status = dss_alloc_au_core(session, dss_ctrl, vg_item, auid, latch_ft_root);
    if (status != CM_SUCCESS) {
        return status;
    }

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
