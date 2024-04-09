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
 * dss_fs_aux.c
 *
 *
 * IDENTIFICATION
 *    src/common/dss_fs_aux.c
 *
 * -------------------------------------------------------------------------
 */
#include "dss_file.h"
#include "dss_fs_aux.h"
#include "dss_zero.h"
#include "dss_syn_meta.h"

#ifdef __cplusplus
extern "C" {
#endif
// range is [beg, end)
void dss_calc_fs_aux_pos(uint64 au_size, int64 offset, dss_fs_aux_pos_desc_t *pos, bool32 is_end)
{
    uint64 au_offset = ((uint64)offset % au_size);
    if (is_end && (offset > 0 && au_offset == 0)) {
        au_offset = au_size;
    }
    uint32 block_len = (DSS_BYTE_BITS_SIZE * DSS_PAGE_SIZE);

    pos->byte_index = (au_offset / (int64)block_len);
    int64 block_offset = (au_offset % (int64)block_len);
    if (is_end) {
        // such as 512 byte, it's in [(0, 0), (0,1))
        block_offset = CM_CALC_ALIGN(block_offset, DSS_PAGE_SIZE);
    }
    pos->bit_index = (uint8)(block_offset / (int64)DSS_PAGE_SIZE);
}

void dss_calc_fs_aux_range(dss_vg_info_item_t *vg_item, int64 offset, int64 size, dss_fs_aux_range_desc_t *range)
{
    uint64 au_size = dss_get_vg_au_size(vg_item->dss_ctrl);
    int64 end_size = (offset + size);
    dss_calc_fs_aux_pos(au_size, offset, &range->beg, CM_FALSE);
    dss_calc_fs_aux_pos(au_size, end_size, &range->end, CM_TRUE);
    CM_ASSERT((range->beg.byte_index * DSS_BYTE_BITS_SIZE + range->beg.bit_index) <=
              (range->end.byte_index * DSS_BYTE_BITS_SIZE + range->end.bit_index));
}

static void dss_updt_fs_aux_pos_range(
    dss_fs_aux_range_desc_t *range, uint32 byte_index, uint8 *beg_bit_index, uint8 *end_bit_index)
{
    if (byte_index == range->beg.byte_index) {
        *beg_bit_index = range->beg.bit_index;
        if (byte_index == range->end.byte_index) {
            *end_bit_index = range->end.bit_index;
        } else {
            *end_bit_index = DSS_BYTE_BITS_SIZE;
        }
    } else if (byte_index == range->end.byte_index) {
        *beg_bit_index = 0;
        *end_bit_index = range->end.bit_index;
    } else {
        *beg_bit_index = 0;
        *end_bit_index = DSS_BYTE_BITS_SIZE;
    }
}

void dss_calc_fs_aux_bitmap_value(uint8 bit_beg, uint8 bit_end, uint8 *value)
{
    *value = 0;
    for (uint8 offset = bit_beg; offset < bit_end; offset++) {
        *value |= ((uint8)1 << offset);
    }
}

int64 dss_get_fs_aux_offset(dss_vg_info_item_t *vg_item, dss_block_id_t blockid)
{
    return dss_get_block_offset(vg_item, DSS_FS_AUX_SIZE, blockid.block, blockid.au);
}

status_t dss_update_fs_aux_bitmap2disk(dss_vg_info_item_t *item, dss_fs_aux_t *block, uint32 size, bool32 had_checksum)
{
    CM_ASSERT(item != NULL);
    CM_ASSERT(block != NULL);
    uint32 volume_id = (uint32)block->head.common.id.volume;
    int64 offset = dss_get_fs_aux_offset(item, block->head.common.id);

    if (!had_checksum) {
        block->head.common.version++;
        block->head.common.checksum = dss_get_checksum(block, DSS_FS_AUX_SIZE);
    }

    LOG_DEBUG_INF("[FS AUX]dss_update_fs_aux_bitmap2disk id:%s, checksum:%u, version:%llu, size:%u.",
        dss_display_metaid(block->head.common.id), block->head.common.checksum, block->head.common.version, size);

    CM_ASSERT(item->volume_handle[volume_id].handle != DSS_INVALID_HANDLE);
    return dss_check_write_volume(item, volume_id, offset, block, size);
}

void dss_check_fs_aux_flags(dss_fs_aux_header_t *block, dss_block_flag_e flags)
{
    bool8 is_invalid = (block->common.flags != flags && block->common.flags != DSS_BLOCK_FLAG_RESERVE);
    DSS_ASSERT_LOG(!is_invalid, "[FS AUX][CHECK]Error flags, fs aux id:%s, flags:%u, expect flags:%u",
        dss_display_metaid(block->common.id), block->common.flags, flags);
}

void dss_check_fs_aux_parent(dss_fs_aux_header_t *block, ftid_t id)
{
    bool8 is_invalid =
        (!dss_cmp_blockid(block->ftid, DSS_ID_TO_U64(id)) && !dss_cmp_blockid(block->ftid, DSS_INVALID_64));
    DSS_ASSERT_LOG(!is_invalid, "[FS AUX][CHECK]Error ftid, fs aux id:%s, ftid:%s, expect ftid:%s",
        dss_display_metaid(block->common.id), dss_display_metaid(block->ftid), dss_display_metaid(id));
    dss_check_fs_aux_flags(block, DSS_BLOCK_FLAG_USED);
}

void dss_check_fs_aux_affiliation(dss_fs_aux_header_t *block, ftid_t id, uint16_t index)
{
    dss_check_fs_aux_parent(block, id);
    bool8 is_invalid = (block->index != index && block->index != DSS_INVALID_ID16);
    DSS_ASSERT_LOG(!is_invalid, "[FS AUX][CHECK]Error index, fs aux id:%s, index:%u, expect index:%u.",
        dss_display_metaid(block->common.id), block->index, index);
}

void dss_check_fs_aux_free(dss_fs_aux_header_t *block)
{
    bool8 is_invalid = (!dss_cmp_auid(block->ftid, DSS_BLOCK_ID_INIT) && !dss_cmp_auid(block->ftid, DSS_INVALID_64));
    DSS_ASSERT_LOG(!is_invalid, "[FS AUX][CHECK] Error ftid, fs aux id:%s, ftid:%s",
        dss_display_metaid(block->common.id), dss_display_metaid(block->ftid));
    is_invalid = (block->index != DSS_FS_INDEX_INIT && block->index != DSS_INVALID_ID16);
    DSS_ASSERT_LOG(!is_invalid, "[FS AUX][CHECK] Error index, fs aux id:%s, index:%u",
        dss_display_metaid(block->common.id), block->index);
    dss_check_fs_aux_flags(block, DSS_BLOCK_FLAG_FREE);
}

void dss_init_fs_aux_head(dss_fs_aux_t *fs_aux, dss_block_id_t ftid, uint16 index)
{
    CM_ASSERT(fs_aux != NULL);
    dss_set_blockid(&fs_aux->head.next, CM_INVALID_ID64);
    dss_set_blockid(&fs_aux->head.data_id, CM_INVALID_ID64);
    dss_set_blockid(&fs_aux->head.ftid, DSS_ID_TO_U64(ftid));
    fs_aux->head.index = index;
    fs_aux->head.common.flags = DSS_BLOCK_FLAG_USED;
    (void)memset_s(&fs_aux->bitmap[0], fs_aux->head.bitmap_num, 0xFF, fs_aux->head.bitmap_num);
    dss_latch_fs_aux_init(fs_aux);
}

void dss_format_fs_aux_inner(dss_ctrl_t *dss_ctrl, dss_fs_aux_t *fs_aux, uint32_t block_id, auid_t auid)
{
    (void)memset_s(&fs_aux->head, DSS_FS_AUX_HEAD_SIZE_MAX, 0, DSS_FS_AUX_HEAD_SIZE_MAX);
    fs_aux->head.common.type = DSS_BLOCK_TYPE_FS_AUX;
    fs_aux->head.common.version = 0;
    fs_aux->head.common.flags = DSS_BLOCK_FLAG_FREE;

    fs_aux->head.common.id.au = auid.au;
    fs_aux->head.common.id.volume = auid.volume;
    fs_aux->head.common.id.block = block_id;
    fs_aux->head.common.id.item = 0;

    fs_aux->head.data_id = DSS_INVALID_BLOCK_ID;
    fs_aux->head.ftid = DSS_INVALID_BLOCK_ID;
    fs_aux->head.index = DSS_FS_INDEX_INIT;
    uint64 au_size = dss_get_vg_au_size(dss_ctrl);
    // fixed size for every au
    fs_aux->head.bitmap_num = DSS_FS_AUX_BITMAP_SIZE(au_size);
    (void)memset_s(&fs_aux->bitmap[0], fs_aux->head.bitmap_num, 0xFF, fs_aux->head.bitmap_num);

    dss_fs_aux_root_t *fs_aux_root = DSS_GET_FS_AUX_ROOT(dss_ctrl);
    fs_aux_root->free.count++;
    dss_block_id_t first = fs_aux_root->free.first;
    fs_aux_root->free.first = fs_aux->head.common.id;
    fs_aux->head.next = first;

    if (fs_aux_root->free.count == 1) {
        fs_aux_root->free.last = fs_aux_root->free.first;
    }

    LOG_DEBUG_INF("[FS AUX]Init bitmap block, free count:%llu, old first:%s, new first:%s, first next:%s.",
        fs_aux_root->free.count, dss_display_metaid(first), dss_display_metaid(fs_aux_root->free.first),
        dss_display_metaid(fs_aux->head.next));
}

status_t dss_format_fs_aux(dss_session_t *session, dss_vg_info_item_t *vg_item, auid_t auid)
{
    dss_ctrl_t *dss_ctrl = vg_item->dss_ctrl;

    // save fs_aux_root here before change
    dss_fs_aux_root_t *fs_aux_root = DSS_GET_FS_AUX_ROOT(dss_ctrl);
    dss_fs_block_list_t bk_list = fs_aux_root->free;

    uint32 block_num = (uint32)DSS_GET_FS_AUX_NUM_IN_AU(dss_ctrl);
    ga_queue_t queue;
    status_t status = ga_alloc_object_list(GA_FS_AUX_POOL, block_num, &queue);
    DSS_RETURN_IFERR2(status, LOG_RUN_ERR("[FS AUX]Failed to alloc object list, block num is %u.", block_num));

    uint32 obj_id = queue.first;
    ga_obj_id_t ga_obj_id;
    ga_obj_id.pool_id = GA_FS_AUX_POOL;

    dss_fs_aux_t *block = NULL;
    for (uint32 i = 0; i < block_num; i++) {
        block = (dss_fs_aux_t *)ga_object_addr(GA_FS_AUX_POOL, obj_id);
        dss_format_fs_aux_inner(dss_ctrl, block, i, auid);

        ga_obj_id.obj_id = obj_id;
        status = dss_register_buffer_cache(vg_item, block->head.common.id, ga_obj_id,
            (dss_block_ctrl_t *)((char *)block + DSS_FS_AUX_SIZE), DSS_BLOCK_TYPE_FS_AUX);
        DSS_RETURN_IFERR2(status, LOG_RUN_ERR("[FS AUX]Failed to register fs aux, id:%s, obj id:%u.",
                                      dss_display_metaid(block->head.common.id), obj_id));
        obj_id = ga_next_object(GA_FS_AUX_POOL, obj_id);
    }

    dss_redo_format_fs_aux_t redo;
    redo.auid = auid;
    redo.count = block_num;
    redo.old_free_list = bk_list;
    dss_put_log(session, vg_item, DSS_RT_FORMAT_FS_AUX, &redo, sizeof(dss_redo_format_fs_aux_t));

    return CM_SUCCESS;
}

status_t dss_alloc_fs_aux_inner(dss_session_t *session, dss_vg_info_item_t *vg_item, bool32 check_version,
    dss_fs_aux_root_t *root, dss_alloc_fs_block_info_t *info, dss_fs_aux_t **block)
{
    dss_fs_aux_t *fs_aux;
    dss_block_id_t block_id;

    CM_ASSERT(root->free.count > 0);
    CM_ASSERT(dss_cmp_blockid(root->free.first, CM_INVALID_ID64) == 0);

    block_id = root->free.first;
    fs_aux = (dss_fs_aux_t *)dss_find_block_in_shm(
        session, vg_item, block_id, DSS_BLOCK_TYPE_FS_AUX, check_version, NULL, CM_FALSE);
    if (fs_aux == NULL) {
        return CM_ERROR;
    }

    dss_check_fs_aux_free(&fs_aux->head);

    root->free.count--;
    root->free.first = fs_aux->head.next;
    if (root->free.count == 0) {
        dss_set_blockid(&root->free.first, CM_INVALID_ID64);
        dss_set_blockid(&root->free.last, CM_INVALID_ID64);
    }

    dss_init_fs_aux_head(fs_aux, info->node->id, info->index);
    *block = fs_aux;

    dss_redo_alloc_fs_aux_t redo;
    redo.id = block_id;
    redo.ftid = info->node->id;
    redo.index = info->index;
    redo.root = *root;
    dss_put_log(session, vg_item, DSS_RT_ALLOC_FS_AUX, &redo, sizeof(redo));

    LOG_DEBUG_INF("[FS AUX]Alloc fs aux, id:%s, free count:%llu, new free first:%s.", dss_display_metaid(block_id),
        root->free.count, dss_display_metaid(root->free.first));
    return CM_SUCCESS;
}

status_t dss_alloc_fs_aux(dss_session_t *session, dss_vg_info_item_t *vg_item, gft_node_t *node,
    dss_alloc_fs_block_info_t *info, dss_fs_aux_t **block)
{
    CM_ASSERT(vg_item != NULL);
    CM_ASSERT(block != NULL);
    status_t status;
    auid_t auid;
    dss_fs_aux_root_t *root = DSS_GET_FS_AUX_ROOT(vg_item->dss_ctrl);
    bool32 check_version = CM_TRUE;

    if (root->free.count > 0) {
        if (info->is_new_au) {
            check_version = CM_FALSE;
        }
        status = dss_alloc_fs_aux_inner(session, vg_item, check_version, root, info, block);
    } else {
        // check version must be CM_FALSE, because the au is new.
        check_version = CM_FALSE;
        info->is_new_au = CM_TRUE;

        status = dss_alloc_au(session, vg_item, &auid);
        DSS_RETURN_IFERR2(status, LOG_RUN_ERR("[FS AUX]Failed to allocate au from vg:%s,%d", vg_item->vg_name, status));
        LOG_DEBUG_INF("[FS AUX]Allocate au:%s for file space", dss_display_metaid(auid));

        status = dss_format_fs_aux(session, vg_item, auid);
        char *err_msg = "Failed to format bitmap meta from vg";
        DSS_RETURN_IFERR2(
            status, LOG_RUN_ERR("[FS AUX]%s vg name:%s, id:%s", err_msg, vg_item->vg_name, dss_display_metaid(auid)));

        status = dss_alloc_fs_aux_inner(session, vg_item, check_version, root, info, block);
    }
    if (status == CM_SUCCESS) {
        dss_updt_fs_aux_file_ver(node, (dss_fs_aux_t *)(*block));
    }
    return status;
}

void dss_free_fs_aux(dss_session_t *session, dss_vg_info_item_t *vg_item, dss_fs_aux_t *fs_aux, dss_fs_aux_root_t *root)
{
    CM_ASSERT(vg_item != NULL);
    CM_ASSERT(fs_aux != NULL);

    dss_block_id_t block_id;
    if (root->free.count) {
        block_id = root->free.first;
    } else {
        dss_set_blockid(&block_id, DSS_INVALID_ID64);
    }

    fs_aux->head.next = block_id;
    fs_aux->head.common.version++;
    fs_aux->head.common.flags = DSS_BLOCK_FLAG_FREE;
    fs_aux->head.ftid = DSS_INVALID_BLOCK_ID;
    fs_aux->head.index = DSS_FS_INDEX_INIT;
    fs_aux->head.common.checksum = dss_get_checksum(fs_aux, DSS_FS_AUX_SIZE);
    root->free.first = fs_aux->head.common.id;
    root->free.count++;
    CM_ASSERT(dss_cmp_blockid(root->free.first, DSS_INVALID_ID64) == 0);

    if (root->free.count == 1) {
        root->free.last = root->free.first;
    }

    dss_redo_free_fs_aux_t redo;
    redo.id = fs_aux->head.common.id;
    redo.next = block_id;
    redo.root = *root;
    dss_put_log(session, vg_item, DSS_RT_FREE_FS_AUX, &redo, sizeof(redo));

    LOG_DEBUG_INF("[FS AUX]Free fs aux, id:%s, next:%s, count:%llu for fs aux root.",
        dss_display_metaid(fs_aux->head.common.id), dss_display_metaid(fs_aux->head.next), root->free.count);
}

void dss_init_fs_aux(dss_session_t *session, dss_vg_info_item_t *vg_item, dss_fs_aux_t *block, dss_block_id_t data_id,
    dss_block_id_t ftid)
{
    dss_set_blockid(&block->head.data_id, DSS_BLOCK_ID_SET_UNINITED(data_id));
    block->head.ftid = ftid;
    dss_redo_init_fs_aux_t redo;
    redo.id = block->head.common.id;
    redo.data_id = block->head.data_id;
    redo.ftid = ftid;
    dss_put_log(session, vg_item, DSS_RT_INIT_FS_AUX, &redo, sizeof(redo));

    LOG_DEBUG_INF(
        "Init fs aux, fs aux id:%s, data_id:%s.", dss_display_metaid(redo.id), dss_display_metaid(redo.data_id));
}

static bool32 dss_updt_fs_aux_bitmap_value(bool32 is_set, uint8 bit_beg, uint8 bit_end, uint8 *value)
{
    uint8 calc_value = 0;
    uint8 save_value = 0;
    dss_calc_fs_aux_bitmap_value(bit_beg, bit_end, &calc_value);

    save_value = *value;
    if (is_set) {
        *value |= calc_value;
    } else {
        *value &= ~calc_value;
    }

    if (*value == save_value) {
        return CM_FALSE;
    } else {
        return CM_TRUE;
    }
}

static bool32 dss_updt_fs_aux_base(
    dss_vg_info_item_t *vg_item, int64 offset, int64 size, bool32 is_set, dss_fs_aux_t *block)
{
    bool32 has_changed = CM_FALSE;
    bool32 has_changed2 = CM_FALSE;

    dss_fs_aux_range_desc_t range;
    dss_calc_fs_aux_range(vg_item, offset, size, &range);
    for (uint32 byte_index = range.beg.byte_index; byte_index <= range.end.byte_index; byte_index++) {
        uint8 beg_bit_index;
        uint8 end_bit_index;
        dss_updt_fs_aux_pos_range(&range, byte_index, &beg_bit_index, &end_bit_index);
        has_changed2 = dss_updt_fs_aux_bitmap_value(is_set, beg_bit_index, end_bit_index, &block->bitmap[byte_index]);
        if (has_changed2 && !has_changed) {
            has_changed = CM_TRUE;
        }
    }
    return has_changed;
}

static void dss_updt_fs_aux_inner(dss_session_t *session, dss_vg_info_item_t *vg_item, int64 offset, int64 size,
    dss_fs_aux_t *block, bool32 *has_changed)
{
    // update the same part, do nothing
    *has_changed = dss_updt_fs_aux_base(vg_item, offset, size, CM_FALSE, block);
    if (!(*has_changed)) {
        return;
    }

    uint32 i = 0;
    for (; i < block->head.bitmap_num; i++) {
        // not inited fully if not 0
        if (block->bitmap[i] != 0) {
            break;
        }
    }
    if (i == block->head.bitmap_num) {
        dss_set_blockid(&block->head.data_id, DSS_BLOCK_ID_SET_INITED(block->head.data_id));
    }
}

static status_t dss_updt_fs_aux_with_latch_and_init(dss_session_t *session, dss_vg_info_item_t *vg_item,
    gft_node_t *node, dss_fs_aux_t *fs_aux, int64 offset, int64 size, bool32 *has_changed)
{
    *has_changed = CM_FALSE;
    if (DSS_BLOCK_ID_IS_INITED(fs_aux->head.data_id)) {
        return CM_SUCCESS;
    }

    int64 new_offset = (offset + size);
    int64 align_size = (int64)CM_CALC_ALIGN((uint64)new_offset, DSS_PAGE_SIZE);
    if (align_size != new_offset) {
        int32 tail_size = (align_size - new_offset);
        int32 inited_size = 0;
        dss_get_inited_size_with_fs_aux(vg_item, fs_aux, new_offset, tail_size, &inited_size);
        if (inited_size != tail_size) {
            new_offset += inited_size;
            tail_size -= inited_size;
            uint64 au_size = dss_get_vg_au_size(vg_item->dss_ctrl);
            uint32 au_offset = (uint64)new_offset % au_size;
            char *zero_buf = dss_get_zero_buf();
            status_t status = dss_data_oper(
                "updt fs aux with init tail", CM_TRUE, vg_item, fs_aux->head.data_id, au_offset, zero_buf, tail_size);
            DSS_RETURN_IFERR2(status, LOG_RUN_ERR("[FS AUX]Failed to find write tail data for block:%s.",
                                          dss_display_metaid(fs_aux->head.data_id)));
            size = align_size - offset;
        }
    }

    dss_updt_fs_aux_inner(session, vg_item, offset, size, fs_aux, has_changed);
    if (*has_changed) {
        status_t status = dss_update_fs_aux_bitmap2disk(vg_item, fs_aux, DSS_FS_AUX_SIZE, CM_FALSE);
        DSS_RETURN_IFERR2(status,
            LOG_RUN_ERR("[FS AUX]Failed to updt fs aux block:%s to disk.", dss_display_metaid(fs_aux->head.common.id)));
    }

    return CM_SUCCESS;
}

static status_t dss_updt_fs_aux_with_latch(dss_session_t *session, dss_vg_info_item_t *vg_item, gft_node_t *node,
    dss_fs_aux_t *fs_aux, int64 offset, int64 size, bool32 *has_changed)
{
    *has_changed = CM_FALSE;
    if (DSS_BLOCK_ID_IS_INITED(fs_aux->head.data_id)) {
        return CM_SUCCESS;
    }

    dss_updt_fs_aux_inner(session, vg_item, offset, size, fs_aux, has_changed);
    if (*has_changed) {
        status_t status = dss_update_fs_aux_bitmap2disk(vg_item, fs_aux, DSS_FS_AUX_SIZE, CM_FALSE);
        DSS_RETURN_IFERR2(status,
            LOG_RUN_ERR("[FS AUX]Failed to updt fs aux block:%s to disk", dss_display_metaid(fs_aux->head.common.id)));
    }
    return CM_SUCCESS;
}

static status_t dss_updt_one_fs_aux_base(dss_session_t *session, dss_vg_info_item_t *vg_item, gft_node_t *node,
    auid_t auid, uint32 block_au_count, int64 offset, int64 size, bool32 is_init_tail)
{
    dss_fs_aux_t *fs_aux = NULL;

    status_t status = dss_get_fs_aux_with_cache(session, vg_item, node, auid, (block_au_count), &fs_aux);
    DSS_RETURN_IFERR2(status, LOG_RUN_ERR("[FS AUX]Failed to find fs aux block:%s.", dss_display_metaid(auid)));
    DSS_RETURN_IF_FALSE2(
        (fs_aux != NULL), LOG_RUN_ERR("[FS AUX]Failed to find fs aux block:%s.", dss_display_metaid(auid)));

    LOG_DEBUG_INF("[FS AUX]Try updt fs aux, fid:%llu, ftid:%s, offset:%lld, size:%lld, fs aux id:%s, data_id:%s.",
        node->fid, dss_display_metaid(node->id), offset, size, dss_display_metaid(auid),
        dss_display_metaid(fs_aux->head.data_id));

    if (!DSS_BLOCK_ID_IS_INITED(fs_aux->head.data_id)) {
        bool32 has_changed = CM_FALSE;
        dss_latch_x_fs_aux(session, fs_aux, NULL);
        if (!is_init_tail) {
            status = dss_updt_fs_aux_with_latch(session, vg_item, node, fs_aux, offset, size, &has_changed);
        } else {
            status = dss_updt_fs_aux_with_latch_and_init(session, vg_item, node, fs_aux, offset, size, &has_changed);
        }
        DSS_RETURN_IFERR3(status, dss_unlatch_fs_aux(fs_aux),
            LOG_RUN_ERR("[FS AUX]Failed to updt fs aux block:%s.", dss_display_metaid(auid)));

        dss_unlatch_fs_aux(fs_aux);
        if (has_changed) {
            dss_block_ctrl_t *fs_aux_block_ctrl = dss_get_fs_aux_ctrl(fs_aux);
            dss_add_syn_meta(vg_item, fs_aux_block_ctrl);
        }
    }
    LOG_DEBUG_INF("[FS AUX]End updt fs aux, fid:%llu, ftid:%s, offset:%lld, size:%lld, fs aux id:%s, data_id:%s.",
        node->fid, dss_display_metaid(node->id), offset, size, dss_display_metaid(auid),
        dss_display_metaid(fs_aux->head.data_id));

    return CM_SUCCESS;
}

static status_t dss_updt_one_fs_aux(dss_session_t *session, dss_vg_info_item_t *vg_item, gft_node_t *node,
    dss_fs_block_t *entry_block, int64 offset, int64 size, bool32 is_init_tail)
{
    uint32 block_count = 0;
    uint32 block_au_count = 0;
    uint32 au_offset = 0;
    uint64 au_size = dss_get_vg_au_size(vg_item->dss_ctrl);

    status_t status = dss_get_fs_block_info_by_offset(offset, au_size, &block_count, &block_au_count, &au_offset);
    if (status != CM_SUCCESS) {
        LOG_RUN_ERR("[FS AUX]The offset:%llu is not correct.", offset);
        return CM_ERROR;
    }

    auid_t auid = entry_block->bitmap[block_count];
    if (dss_cmp_auid(auid, CM_INVALID_ID64)) {
        LOG_RUN_ERR("[FS AUX]The offset:%llu is not correct.", offset);
        return CM_ERROR;
    }

    dss_fs_block_t *second_block = NULL;
    status = dss_get_second_block_with_cache(session, vg_item, node, auid, block_count, &second_block);
    DSS_RETURN_IFERR2(status, LOG_RUN_ERR("[FS AUX]Failed to find second block:%s.", dss_display_metaid(auid)));
    DSS_RETURN_IF_FALSE2(
        (second_block != NULL), LOG_RUN_ERR("[FS AUX]Failed to find entry block:%s.", dss_display_metaid(auid)));

    auid = second_block->bitmap[block_au_count];
    if (!dss_cmp_auid(auid, CM_INVALID_ID64)) {
        if (DSS_BLOCK_ID_IS_AUX(auid)) {
            status = dss_updt_one_fs_aux_base(session, vg_item, node, auid, block_au_count, offset, size, is_init_tail);
            DSS_RETURN_IF_ERROR(status);
        }
    }

    return CM_SUCCESS;
}

// do not record redo log, because too much update for one au, redo log cost too much
// if with redo log, means:
// step 1: write redo log to disk, step 2: replay redo log to disk, step 3:clean disk redo log
// if without redo log, means:
// step 1: write the change to disk
status_t dss_updt_fs_aux(dss_session_t *session, dss_vg_info_item_t *vg_item, gft_node_t *node, int64 offset,
    int64 size, bool32 is_init_tail)
{
    uint64 au_size = dss_get_vg_au_size(vg_item->dss_ctrl);

    // when be primary, reload all the block meta by dss_refresh_buffer_cahe
    LOG_DEBUG_INF("[FS AUX]Begin to update file fid:%llu, ftid:%s, fs aux offset:%lld, size:%lld.", node->fid,
        dss_display_metaid(node->id), offset, size);

    // check the entry and load
    dss_fs_block_t *entry_block = NULL;
    status_t status = dss_get_entry_block_with_cache(session, vg_item, node, &entry_block);
    DSS_RETURN_IFERR2(status, LOG_RUN_ERR("[FS AUX]Failed to find entry block:%s.", dss_display_metaid(node->entry)));
    DSS_RETURN_IF_FALSE2(
        (entry_block != NULL), LOG_RUN_ERR("[FS AUX]Failed to find entry block:%s.", dss_display_metaid(node->entry)));

    int64 top_size = (node->size > (offset + size)) ? (offset + size) : node->size;
    int64 left_size = size;
    int64 cur_size = 0;
    do {
        int64 align_size = (int64)CM_CALC_ALIGN((uint64)(offset + 1), au_size);
        if (offset + left_size > align_size) {
            cur_size = align_size - offset;
        } else {
            cur_size = left_size;
        }

        status = dss_updt_one_fs_aux(session, vg_item, node, entry_block, offset, cur_size, is_init_tail);
        DSS_RETURN_IF_ERROR(status);

        offset += cur_size;
        left_size -= cur_size;
    } while (offset < top_size);

    return CM_SUCCESS;
}

static inline bool32 dss_check_fs_aux_bits_inited(uint8 bit_beg, uint8 bit_end, uint8 value)
{
    uint8 new_value = 0;
    dss_calc_fs_aux_bitmap_value(bit_beg, bit_end, &new_value);
    return ((new_value & value) == 0);
}

bool32 dss_check_fs_aux_inited(dss_vg_info_item_t *vg_item, dss_fs_aux_t *fs_aux, int64 offset, int64 size)
{
    if (DSS_BLOCK_ID_IS_INITED(fs_aux->head.data_id)) {
        return CM_TRUE;
    }

    dss_fs_aux_range_desc_t range;
    dss_calc_fs_aux_range(vg_item, offset, size, &range);

    for (uint32 byte_index = range.beg.byte_index; byte_index <= range.end.byte_index; byte_index++) {
        uint8 beg_bit_index;
        uint8 end_bit_index;
        dss_updt_fs_aux_pos_range(&range, byte_index, &beg_bit_index, &end_bit_index);
        bool32 is_inited = dss_check_fs_aux_bits_inited(beg_bit_index, end_bit_index, fs_aux->bitmap[byte_index]);
        if (!is_inited) {
            return CM_FALSE;
        }
    }
    return CM_TRUE;
}

static status_t dss_check_need_updt_one_fs_aux(dss_session_t *session, dss_vg_info_item_t *vg_item, gft_node_t *node,
    dss_fs_block_t *entry_block, int64 offset, int64 size, bool32 *need_updt_fs_aux)
{
    uint32 block_count = 0;
    uint32 block_au_count = 0;
    uint32 au_offset = 0;
    uint64 au_size = dss_get_vg_au_size(vg_item->dss_ctrl);

    status_t status = dss_get_fs_block_info_by_offset(offset, au_size, &block_count, &block_au_count, &au_offset);
    if (status != CM_SUCCESS) {
        LOG_RUN_ERR("[FS AUX]The offset:%llu is not correct.", offset);
        return CM_ERROR;
    }

    auid_t auid = entry_block->bitmap[block_count];
    if (dss_cmp_auid(auid, CM_INVALID_ID64)) {
        LOG_RUN_ERR("[FS AUX]The offset:%llu is not correct.", offset);
        return CM_ERROR;
    }

    dss_fs_block_t *second_block = dss_find_fs_block(session, vg_item, node, auid, CM_FALSE, NULL, (uint16)block_count);
    DSS_RETURN_IF_FALSE2(
        (second_block != NULL), LOG_RUN_ERR("[FS AUX]Failed to find second block:%s.", dss_display_metaid(auid)));

    auid = second_block->bitmap[block_au_count];
    if (!dss_cmp_auid(auid, CM_INVALID_ID64)) {
        if (DSS_BLOCK_ID_IS_AUX(auid)) {
            dss_fs_aux_t *fs_aux =
                dss_find_fs_aux(session, vg_item, node, auid, CM_FALSE, NULL, (uint16)block_au_count);
            DSS_RETURN_IF_FALSE2(
                (fs_aux != NULL), LOG_RUN_ERR("[FS AUX]Failed to find fs aux block:%s.", dss_display_metaid(auid)));

            // if found one, ignore others
            bool32 is_inited = dss_check_fs_aux_inited(vg_item, fs_aux, offset, size);
            if (!is_inited) {
                *need_updt_fs_aux = CM_TRUE;
            }
        }
    }

    return CM_SUCCESS;
}

status_t dss_check_need_updt_fs_aux(dss_session_t *session, dss_vg_info_item_t *vg_item, gft_node_t *node, int64 offset,
    int64 size, bool32 *need_updt_fs_aux)
{
    *need_updt_fs_aux = CM_FALSE;
    if (node->min_inited_size >= (uint64)(offset + size)) {
        return CM_SUCCESS;
    }

    uint64 au_size = dss_get_vg_au_size(vg_item->dss_ctrl);

    // check the entry and load
    dss_fs_block_t *entry_block =
        dss_find_fs_block(session, vg_item, node, node->entry, CM_FALSE, NULL, DSS_ENTRY_FS_INDEX);
    if (!entry_block) {
        DSS_RETURN_IFERR2(
            CM_ERROR, LOG_RUN_ERR("[FS AUX]Failed to find entry block:%s.", dss_display_metaid(node->entry)));
    }

    int64 top_size = (node->size > (offset + size)) ? (offset + size) : node->size;
    int64 left_size = size;
    int64 cur_size = 0;
    do {
        int64 align_size = (int64)CM_CALC_ALIGN((uint64)(offset + 1), au_size);
        if (offset + left_size > align_size) {
            cur_size = align_size - offset;
        } else {
            cur_size = left_size;
        }

        status_t status =
            dss_check_need_updt_one_fs_aux(session, vg_item, node, entry_block, offset, cur_size, need_updt_fs_aux);
        DSS_RETURN_IF_ERROR(status);

        if (*need_updt_fs_aux) {
            break;
        }

        offset += cur_size;
        left_size -= cur_size;
    } while (offset < top_size);

    return CM_SUCCESS;
}

dss_fs_aux_t *dss_find_fs_aux(dss_session_t *session, dss_vg_info_item_t *vg_item, gft_node_t *node,
    dss_block_id_t block_id, bool32 check_version, ga_obj_id_t *out_obj_id, uint16 index)
{
    dss_fs_aux_t *fs_aux = (dss_fs_aux_t *)dss_find_block_in_shm(
        session, vg_item, block_id, DSS_BLOCK_TYPE_FS_AUX, check_version, out_obj_id, CM_FALSE);
    if (fs_aux == NULL) {
        LOG_RUN_ERR("[FS AUX]Failed to get fs aux block:%s.", dss_display_metaid(block_id));
        return NULL;
    }

    if (!dss_is_fs_aux_valid_all(node, fs_aux, index)) {
        LOG_DEBUG_INF(
            "block:%s fid:%llu, file ver:%llu is not same as node:%s, fid:%llu, file ver:%llu by session id:%u",
            dss_display_metaid(block_id), dss_get_fs_aux_fid(fs_aux), dss_get_fs_aux_file_ver(fs_aux),
            dss_display_metaid(node->id), node->fid, node->file_ver, session->id);
        if (!dss_is_server()) {
            return NULL;
        }
        dss_updt_fs_aux_file_ver(node, fs_aux);
        LOG_DEBUG_INF("block:%s fid:%llu, file ver:%llu setted with node:%s, fid:%llu, file ver:%llu by session id:%u",
            dss_display_metaid(block_id), dss_get_fs_aux_fid(fs_aux), dss_get_fs_aux_file_ver(fs_aux),
            dss_display_metaid(node->id), node->fid, node->file_ver, session->id);
    }
    return fs_aux;
}

void dss_get_inited_size_with_fs_aux(
    dss_vg_info_item_t *vg_item, dss_fs_aux_t *fs_aux, int64 offset, int32 size, int32 *inited_size)
{
    if (fs_aux == NULL || DSS_BLOCK_ID_IS_INITED(fs_aux->head.data_id)) {
        *inited_size = size;
        return;
    }

    int32 cur_size = 0;
    int32 left_size = size;
    uchar cur_map = 0;

    dss_fs_aux_range_desc_t range;
    dss_calc_fs_aux_range(vg_item, offset, size, &range);
    for (uint32 byte_index = range.beg.byte_index; byte_index <= range.end.byte_index; byte_index++) {
        uint8 beg_bit_index;
        uint8 end_bit_index;
        dss_updt_fs_aux_pos_range(&range, byte_index, &beg_bit_index, &end_bit_index);
        for (uint8 bit_index = beg_bit_index; bit_index < end_bit_index; bit_index++) {
            cur_map = ((fs_aux->bitmap[byte_index] >> bit_index) & 0x01);
            if (cur_map == 1) {
                *inited_size = cur_size;
                return;
            }

            if (left_size > DSS_PAGE_SIZE) {
                cur_size += DSS_PAGE_SIZE;
                left_size -= DSS_PAGE_SIZE;
            } else {
                cur_size += left_size;
                left_size = 0;
            }
        }
    }

    *inited_size = size;
}

status_t dss_try_find_data_au_batch(dss_session_t *session, dss_vg_info_item_t *vg_item, gft_node_t *node,
    dss_fs_block_t *second_block, uint32 block_au_count_beg)
{
    // whn be primary, reload all th eblock meta by dss_refresh buffer_cache
    bool32 check_version = CM_TRUE;
    if (dss_need_exec_local()) {
        check_version = CM_FALSE;
    }

    auid_t auid;
    for (uint32 i = block_au_count_beg + 1; i < second_block->head.used_num; i++) {
        auid = second_block->bitmap[i];
        if (DSS_BLOCK_ID_IS_AUX(auid)) {
            if (dss_find_block_in_shm_no_refresh(session, vg_item, auid, NULL) != NULL) {
                continue;
            }
            dss_fs_aux_t *fs_aux_tmp = dss_find_fs_aux(session, vg_item, node, auid, check_version, NULL, (uint16)i);
            DSS_RETURN_IF_FALSE2(
                (fs_aux_tmp != NULL), LOG_RUN_ERR("[FS AUX]Failed to find fs aux block:%s.", dss_display_metaid(auid)));
        }
    }

    return CM_SUCCESS;
}

status_t dss_find_data_au_by_offset(
    dss_session_t *session, dss_vg_info_item_t *vg_item, gft_node_t *node, int64 offset, dss_fs_pos_desc_t *fs_pos)
{
    uint64 au_size = dss_get_vg_au_size(vg_item->dss_ctrl);
    fs_pos->is_valid = CM_FALSE;

    status_t status = dss_get_fs_block_info_by_offset(
        offset, au_size, &fs_pos->block_count, &fs_pos->block_au_count, &fs_pos->au_offset);
    if (status != CM_SUCCESS) {
        LOG_RUN_ERR("[FS AUX]The offset:%llu is not correct.", offset);
        return CM_ERROR;
    }

    bool32 check_version = CM_TRUE;
    if (dss_need_exec_local()) {
        check_version = CM_FALSE;
    }

    fs_pos->entry_fs_block =
        dss_find_fs_block(session, vg_item, node, node->entry, check_version, NULL, DSS_ENTRY_FS_INDEX);
    DSS_RETURN_IF_FALSE2((fs_pos->entry_fs_block != NULL),
        LOG_RUN_ERR("[FS AUX]Failed to find entry block:%s.", dss_display_metaid(node->entry)));

    auid_t auid = fs_pos->entry_fs_block->bitmap[fs_pos->block_count];
    if (dss_cmp_auid(auid, CM_INVALID_ID64)) {
        LOG_RUN_ERR("[FS AUX]The offset:%llu is not correct.", offset);
        return CM_ERROR;
    }

    fs_pos->second_fs_block =
        dss_find_fs_block(session, vg_item, node, auid, check_version, NULL, (uint16)fs_pos->block_count);
    DSS_RETURN_IF_FALSE2((fs_pos->second_fs_block != NULL),
        LOG_RUN_ERR("[FS AUX]Failed to find second block:%s.", dss_display_metaid(auid)));

    auid = fs_pos->second_fs_block->bitmap[fs_pos->block_au_count];
    if (!dss_cmp_auid(auid, CM_INVALID_ID64)) {
        fs_pos->data_auid = auid;
        if (DSS_IS_FILE_INNER_INITED(node->flags) && DSS_BLOCK_ID_IS_AUX(auid)) {
            fs_pos->fs_aux =
                dss_find_fs_aux(session, vg_item, node, auid, check_version, NULL, (uint16)fs_pos->block_au_count);
            DSS_RETURN_IF_FALSE2((fs_pos->fs_aux != NULL),
                LOG_RUN_ERR("[FS AUX]Failed to find fs aux block:%s.", dss_display_metaid(auid)));
            if (dss_cmp_auid(fs_pos->fs_aux->head.data_id, CM_INVALID_ID64)) {
                LOG_RUN_ERR("[FS AUX]The offset:%llu fs aux not correct.", offset);
                return CM_ERROR;
            }
            fs_pos->data_auid = fs_pos->fs_aux->head.data_id;
            fs_pos->is_exist_aux = CM_TRUE;
        }

        fs_pos->is_valid = CM_TRUE;
    }

    return CM_SUCCESS;
}

static status_t dss_read_volume_with_fs_aux_base(
    dss_volume_t *volume, int64 vol_offset, uchar last_map, void *buf, int64 buf_offset, int64 read_size)
{
    if (last_map == 0) {
        return dss_read_volume(volume, (int64)vol_offset + buf_offset, (char *)buf + buf_offset, read_size);
    } else {
        (void)memset_s((char *)buf + buf_offset, (size_t)read_size, 0x00, (size_t)read_size);
    }
    return CM_SUCCESS;
}

static void dss_read_volume_updt_data_info(int64 *read_size, int64 *left_size, uchar *last_map, uchar cur_map)
{
    if (*left_size > DSS_PAGE_SIZE) {
        *read_size += DSS_PAGE_SIZE;
        *left_size -= DSS_PAGE_SIZE;
    } else {
        *read_size += *left_size;
        *left_size = 0;
    }
    if (*last_map == DSS_INVALID_ID8 || *last_map != cur_map) {
        *last_map = cur_map;
    }
}

status_t dss_read_volume_with_fs_aux(dss_vg_info_item_t *vg_item, gft_node_t *node, dss_fs_aux_t *fs_aux,
    dss_volume_t *volume, int64 vol_offset, int64 offset, void *buf, int32 size)
{
    status_t status = CM_ERROR;
    if (!DSS_IS_FILE_INNER_INITED(node->flags) || fs_aux == NULL || DSS_BLOCK_ID_IS_INITED(fs_aux->head.data_id) ||
        node->min_inited_size >= (offset + size)) {
        return dss_read_volume(volume, (int64)vol_offset, buf, size);
    }

    int64 buf_offset = 0;
    int64 read_size = 0;
    int64 left_size = size;
    uchar last_map = DSS_INVALID_ID8;
    uchar cur_map = 0;

    read_size = 0;
    dss_fs_aux_range_desc_t range;

    dss_calc_fs_aux_range(vg_item, offset, size, &range);
    for (uint32 byte_index = range.beg.byte_index; byte_index <= range.end.byte_index; byte_index++) {
        uint8 beg_bit_index;
        uint8 end_bit_index;
        dss_updt_fs_aux_pos_range(&range, byte_index, &beg_bit_index, &end_bit_index);
        for (uint8 bit_index = beg_bit_index; bit_index < end_bit_index; bit_index++) {
            cur_map = ((fs_aux->bitmap[byte_index] >> bit_index) & 0x01);
            if (last_map == DSS_INVALID_ID8 || cur_map == last_map) {
                dss_read_volume_updt_data_info(&read_size, &left_size, &last_map, cur_map);
                continue;
            }

            status = dss_read_volume_with_fs_aux_base(volume, vol_offset, last_map, buf, buf_offset, read_size);
            DSS_RETURN_IFERR2(status, LOG_RUN_ERR("[FS AUX]read volume error"));

            buf_offset += read_size;
            read_size = 0;

            dss_read_volume_updt_data_info(&read_size, &left_size, &last_map, cur_map);
        }
    }

    if (read_size > 0) {
        status = dss_read_volume_with_fs_aux_base(volume, vol_offset, last_map, buf, buf_offset, read_size);
        DSS_RETURN_IFERR2(status, LOG_RUN_ERR("[FS AUX]read volume error"));
    }

    return CM_SUCCESS;
}

status_t dss_get_gft_node_with_cache(
    dss_session_t *session, dss_vg_info_item_t *vg_item, uint64 fid, dss_block_id_t ftid, gft_node_t **node_out)
{
    uint32 ftid_cache_index = DSS_ID_TO_U64(ftid) % DSS_VG_ITEM_CACHE_NODE_MAX;
    dss_vg_cache_node_t *vg_cache_node = &vg_item->vg_cache_node[ftid_cache_index];

    gft_node_t *node = NULL;
    dss_latch_s(&vg_cache_node->latch);
    if (vg_cache_node->fid == fid && vg_cache_node->ftid == DSS_ID_TO_U64(ftid) && vg_cache_node->node != NULL) {
        node = (gft_node_t *)vg_cache_node->node;
        dss_unlatch(&vg_cache_node->latch);
        *node_out = node;
    } else {
        dss_unlatch(&vg_cache_node->latch);
        node = dss_get_ft_node_by_ftid(session, vg_item, ftid, CM_FALSE, CM_FALSE);
        if (!node) {
            DSS_RETURN_IFERR2(CM_ERROR, LOG_RUN_ERR("[FS AUX]Failed to find FTN, ftid:%s.", dss_display_metaid(ftid)));
        }

        dss_latch_x(&vg_cache_node->latch);
        if (fid != node->fid) {
            vg_cache_node->node = NULL;
            vg_cache_node->ftid = DSS_INVALID_ID64;
            vg_cache_node->fid = 0;
            *node_out = NULL;
        } else {
            vg_cache_node->node = (char *)node;
            vg_cache_node->ftid = DSS_ID_TO_U64(ftid);
            vg_cache_node->fid = node->fid;
            *node_out = node;
        }
        dss_unlatch(&vg_cache_node->latch);
    }

    return CM_SUCCESS;
}

status_t dss_get_entry_block_with_cache(
    dss_session_t *session, dss_vg_info_item_t *vg_item, gft_node_t *node, dss_fs_block_t **fs_block_out)
{
    // check the entry and load
    dss_block_ctrl_t *block_ctrl = dss_get_block_ctrl_by_node(node);

    dss_fs_block_t *entry_block = NULL;
    dss_latch_s_node(session, node, NULL);
    if (block_ctrl->fs_block_cache_info.entry_block_id == DSS_ID_TO_U64(node->entry) &&
        block_ctrl->fs_block_cache_info.entry_block_addr != NULL &&
        dss_is_fs_block_valid(node, (dss_fs_block_t *)block_ctrl->fs_block_cache_info.entry_block_addr)) {
        entry_block = (dss_fs_block_t *)block_ctrl->fs_block_cache_info.entry_block_addr;
        dss_unlatch_node(node);
    } else {
        dss_unlatch_node(node);
        entry_block = dss_find_fs_block(session, vg_item, node, node->entry, CM_FALSE, NULL, DSS_ENTRY_FS_INDEX);
        if (!entry_block) {
            DSS_RETURN_IFERR2(
                CM_ERROR, LOG_RUN_ERR("[FS AUX]Failed to find entry block:%s.", dss_display_metaid(node->entry)));
        }

        dss_latch_x_node(session, node, NULL);
        block_ctrl->fs_block_cache_info.entry_block_addr = (char *)entry_block;
        block_ctrl->fs_block_cache_info.entry_block_id = DSS_ID_TO_U64(node->entry);
        dss_unlatch_node(node);
    }
    *fs_block_out = entry_block;
    return CM_SUCCESS;
}

status_t dss_get_second_block_with_cache(dss_session_t *session, dss_vg_info_item_t *vg_item, gft_node_t *node,
    dss_block_id_t block_id, uint32 block_count, dss_fs_block_t **fs_block_out)
{
    dss_block_ctrl_t *block_ctrl = dss_get_block_ctrl_by_node(node);

    dss_fs_block_t *second_block = NULL;
    dss_latch_s_node(session, node, NULL);
    if (block_ctrl->fs_block_cache_info.fs_block_id == DSS_ID_TO_U64(block_id) &&
        block_ctrl->fs_block_cache_info.fs_block_addr != NULL &&
        dss_is_fs_block_valid(node, (dss_fs_block_t *)block_ctrl->fs_block_cache_info.fs_block_addr)) {
        second_block = (dss_fs_block_t *)block_ctrl->fs_block_cache_info.fs_block_addr;
        dss_unlatch_node(node);
    } else {
        dss_unlatch_node(node);
        second_block = dss_find_fs_block(session, vg_item, node, block_id, CM_FALSE, NULL, (uint16)block_count);
        if (!second_block) {
            DSS_RETURN_IFERR2(
                CM_ERROR, LOG_RUN_ERR("[FS AUX]Failed to find second block:%s.", dss_display_metaid(block_id)));
        }

        dss_latch_x_node(session, node, NULL);
        block_ctrl->fs_block_cache_info.fs_block_addr = (char *)second_block;
        block_ctrl->fs_block_cache_info.fs_block_id = DSS_ID_TO_U64(block_id);
        dss_unlatch_node(node);
    }
    *fs_block_out = second_block;
    return CM_SUCCESS;
}

status_t dss_get_fs_aux_with_cache(dss_session_t *session, dss_vg_info_item_t *vg_item, gft_node_t *node,
    dss_block_id_t block_id, uint32 block_au_count, dss_fs_aux_t **fs_aux_out)
{
    dss_block_ctrl_t *block_ctrl = dss_get_block_ctrl_by_node(node);

    dss_fs_aux_t *fs_aux = NULL;
    dss_latch_s_node(session, node, NULL);
    if (block_ctrl->fs_block_cache_info.fs_aux_block_id == DSS_ID_TO_U64(block_id) &&
        block_ctrl->fs_block_cache_info.fs_aux_addr != NULL &&
        dss_is_fs_aux_valid(node, (dss_fs_aux_t *)block_ctrl->fs_block_cache_info.fs_aux_addr)) {
        fs_aux = (dss_fs_aux_t *)block_ctrl->fs_block_cache_info.fs_aux_addr;
        dss_unlatch_node(node);
    } else {
        dss_unlatch_node(node);
        fs_aux = dss_find_fs_aux(session, vg_item, node, block_id, CM_FALSE, NULL, (uint16)block_au_count);
        if (!fs_aux) {
            DSS_RETURN_IFERR2(
                CM_ERROR, LOG_RUN_ERR("[FS AUX]Failed to find fs aux block:%s.", dss_display_metaid(block_id)));
        }

        dss_latch_x_node(session, node, NULL);
        block_ctrl->fs_block_cache_info.fs_aux_addr = (char *)fs_aux;
        block_ctrl->fs_block_cache_info.fs_aux_block_id = DSS_ID_TO_U64(block_id);
        dss_unlatch_node(node);
    }

    *fs_aux_out = fs_aux;
    return CM_SUCCESS;
}

// for redo
status_t rp_redo_format_fs_aux(dss_vg_info_item_t *vg_item, dss_redo_entry_t *entry)
{
    CM_ASSERT(vg_item != NULL);
    CM_ASSERT(entry != NULL);

    status_t status;
    dss_redo_format_fs_aux_t *data = (dss_redo_format_fs_aux_t *)entry->data;

    if (vg_item->status == DSS_VG_STATUS_RECOVERY) {
        status = dss_check_refresh_core(vg_item);
        DSS_RETURN_IFERR2(status, LOG_RUN_ERR("[REDO][FS AUX]Failed to refresh vg core:%s.", vg_item->vg_name));
        dss_fs_aux_root_t *block_root = DSS_GET_FS_AUX_ROOT(vg_item->dss_ctrl);
        block_root->free = data->old_free_list;
        status = dss_format_fs_aux(NULL, vg_item, data->auid);
        DSS_RETURN_IFERR2(status,
            LOG_RUN_ERR("[REDO][FS AUX]Fail to format file space aux node, auid:%s.", dss_display_metaid(data->auid)));
    }

    status = dss_update_core_ctrl_disk(vg_item);
    DSS_RETURN_IFERR2(status, LOG_RUN_ERR("[REDO][FS AUX]Fail to write ctrl to disk, vg:%s.", vg_item->vg_name));
    dss_block_id_t first = data->auid;
    ga_obj_id_t obj_id;
    status = dss_find_block_objid_in_shm(vg_item, first, DSS_BLOCK_TYPE_FS_AUX, &obj_id);
    DSS_RETURN_IFERR2(status, LOG_RUN_ERR("[REDO][FS AUX]Fail to find block:%s.", dss_display_metaid(first)));

    status = dss_update_au_disk(vg_item, data->auid, GA_FS_AUX_POOL, obj_id.obj_id, data->count, DSS_FS_AUX_SIZE);
    DSS_RETURN_IFERR2(status, LOG_RUN_ERR("[REDO][FS AUX]Fail to update au:%s.", dss_display_metaid(data->auid)));
    LOG_DEBUG_INF("[REDO][FS AUX]Succeed to replay format au:%s fs aux block, vg name:%s.",
        dss_display_metaid(data->auid), vg_item->vg_name);
    return CM_SUCCESS;
}

status_t rb_redo_format_fs_aux(dss_vg_info_item_t *vg_item, dss_redo_entry_t *entry)
{
    CM_ASSERT(vg_item != NULL);
    CM_ASSERT(entry != NULL);

    status_t status;
    bool32 remote = CM_FALSE;
    dss_redo_format_fs_aux_t *data = (dss_redo_format_fs_aux_t *)entry->data;

    dss_block_id_t first = data->auid;
    ga_obj_id_t obj_id;
    status = dss_find_block_objid_in_shm(vg_item, first, DSS_BLOCK_TYPE_FS_AUX, &obj_id);
    DSS_RETURN_IFERR2(status, LOG_RUN_ERR("[REDO][FS AUX]Failed to find block:%s.", dss_display_metaid(first)));
    rb_redo_clean_resource(vg_item, data->auid, GA_FS_AUX_POOL, obj_id.obj_id, data->count);
    status = dss_load_vg_ctrl_part(
        vg_item, (int64)DSS_CTRL_CORE_OFFSET, vg_item->dss_ctrl->core_data, DSS_DISK_UNIT_SIZE, &remote);
    DSS_RETURN_IFERR2(status, LOG_RUN_ERR("[REDO][FS AUX]Failed to load vg:%s.", vg_item->vg_name));
    return CM_SUCCESS;
}

static status_t rp_updt_fs_aux_root_base(
    dss_vg_info_item_t *vg_item, dss_fs_aux_root_t *root_expect, bool32 check_version)
{
    status_t status;
    dss_fs_aux_root_t *root = DSS_GET_FS_AUX_ROOT(vg_item->dss_ctrl);
    if (vg_item->status == DSS_VG_STATUS_RECOVERY) {
        status = dss_check_refresh_core(vg_item);
        DSS_RETURN_IFERR2(status, LOG_RUN_ERR("[REDO][FS AUX]Failed to refresh vg core:%s.", vg_item->vg_name));
        *root = *root_expect;
    }

    status = dss_update_core_ctrl_disk(vg_item);
    DSS_RETURN_IFERR2(status, LOG_RUN_ERR("[REDO][FS AUX]Failed to update vg core:%s to disk.", vg_item->vg_name));

    return CM_SUCCESS;
}

static status_t rb_reload_fs_aux_root(dss_vg_info_item_t *vg_item)
{
    bool32 remote = CM_FALSE;
    status_t status = dss_load_vg_ctrl_part(
        vg_item, (int64)DSS_CTRL_CORE_OFFSET, vg_item->dss_ctrl->core_data, DSS_DISK_UNIT_SIZE, &remote);
    DSS_RETURN_IFERR2(status, LOG_RUN_ERR("[REDO][FS AUX]Failed to load vg ctrl part."));

    return CM_SUCCESS;
}

status_t rp_redo_alloc_fs_aux(dss_vg_info_item_t *vg_item, dss_redo_entry_t *entry)
{
    CM_ASSERT(vg_item != NULL);
    CM_ASSERT(entry != NULL);

    status_t status;
    dss_redo_alloc_fs_aux_t *data = (dss_redo_alloc_fs_aux_t *)entry->data;
    bool32 check_version = CM_FALSE;
    dss_fs_aux_t *fs_aux = NULL;

    if (vg_item->status == DSS_VG_STATUS_RECOVERY) {
        check_version = CM_TRUE;
    }

    status = rp_updt_fs_aux_root_base(vg_item, &data->root, check_version);
    DSS_RETURN_IFERR2(
        status, LOG_RUN_ERR("[REDO][FS AUX]Failed to fs aux root, fs aux fs aux id:%s.", dss_display_metaid(data->id)));

    fs_aux = (dss_fs_aux_t *)dss_find_block_in_shm(
        NULL, vg_item, data->id, DSS_BLOCK_TYPE_FS_AUX, check_version, NULL, CM_FALSE);
    DSS_RETURN_IF_FALSE2(
        (fs_aux != NULL), LOG_RUN_ERR("[REDO][FS AUX]Failed to fs aux fs aux id:%s.", dss_display_metaid(data->id)));

    if (vg_item->status == DSS_VG_STATUS_RECOVERY) {
        dss_init_fs_aux_head(fs_aux, data->ftid, data->index);
    }

    status = dss_update_fs_aux_bitmap2disk(vg_item, fs_aux, DSS_FS_AUX_SIZE, CM_FALSE);
    DSS_RETURN_IFERR2(status,
        LOG_RUN_ERR("[REDO][FS AUX]Failed to update fs aux bitmap fs_aux:%s to disk.", dss_display_metaid(data->id)));
    LOG_DEBUG_INF("[REDO][FS AUX]Succeed to replay alloc fs aux fs_aux:%s, vg name:%s.", dss_display_metaid(data->id),
        vg_item->vg_name);
    return CM_SUCCESS;
}

status_t rb_redo_alloc_fs_aux(dss_vg_info_item_t *vg_item, dss_redo_entry_t *entry)
{
    CM_ASSERT(vg_item != NULL);
    CM_ASSERT(entry != NULL);

    status_t status;

    dss_redo_alloc_fs_aux_t *data = (dss_redo_alloc_fs_aux_t *)entry->data;

    // reload the fs_aux
    ga_obj_id_t obj_id;
    dss_fs_aux_t *fs_aux = (dss_fs_aux_t *)dss_find_block_in_shm(
        NULL, vg_item, data->id, DSS_BLOCK_TYPE_FS_AUX, CM_TRUE, &obj_id, CM_FALSE);
    CM_ASSERT(fs_aux != NULL);

    // release the mem
    dss_unregister_buffer_cache(vg_item, fs_aux->head.common.id);
    ga_free_object(obj_id.pool_id, obj_id.obj_id);

    // reload the root
    status = rb_reload_fs_aux_root(vg_item);
    DSS_RETURN_IFERR2(status,
        LOG_RUN_ERR("[REDO][FS AUX]Failed to update fs aux root fs aux id:%s to disk.", dss_display_metaid(data->id)));

    return CM_SUCCESS;
}

status_t rp_redo_free_fs_aux(dss_vg_info_item_t *vg_item, dss_redo_entry_t *entry)
{
    CM_ASSERT(vg_item != NULL);
    CM_ASSERT(entry != NULL);

    status_t status;
    dss_redo_free_fs_aux_t *data = (dss_redo_free_fs_aux_t *)entry->data;

    dss_fs_aux_t *fs_aux = NULL;
    bool32 check_version = CM_FALSE;

    if (vg_item->status == DSS_VG_STATUS_RECOVERY) {
        check_version = CM_TRUE;
    }

    // replay the root
    status = rp_updt_fs_aux_root_base(vg_item, &data->root, check_version);
    DSS_RETURN_IFERR2(
        status, LOG_RUN_ERR("[REDO][FS AUX]Failed to fs aux root, fs aux fs aux id:%s.", dss_display_metaid(data->id)));

    // free the fs aux fs_aux
    ga_obj_id_t obj_id;
    fs_aux = (dss_fs_aux_t *)dss_find_block_in_shm(
        NULL, vg_item, data->id, DSS_BLOCK_TYPE_FS_AUX, check_version, &obj_id, CM_FALSE);
    DSS_RETURN_IF_FALSE2((fs_aux != NULL), DSS_THROW_ERROR(ERR_DSS_FNODE_CHECK, "invalid fs_aux"));

    if (vg_item->status == DSS_VG_STATUS_RECOVERY) {
        fs_aux->head.next = data->next;
        fs_aux->head.common.flags = DSS_BLOCK_FLAG_FREE;
        fs_aux->head.ftid = DSS_INVALID_BLOCK_ID;
        fs_aux->head.index = DSS_FS_INDEX_INIT;
    }

    status = dss_update_fs_aux_bitmap2disk(vg_item, fs_aux, DSS_FS_AUX_SIZE, CM_FALSE);
    DSS_RETURN_IFERR2(status,
        LOG_RUN_ERR("[REDO][FS AUX]Failed to update fs aux bitmap fs_aux:%s to disk.", dss_display_metaid(data->id)));

    // release the mem
    dss_unregister_buffer_cache(vg_item, fs_aux->head.common.id);
    ga_free_object(obj_id.pool_id, obj_id.obj_id);

    LOG_DEBUG_INF("[REDO][FS AUX]Succeed to replay free fs aux fs_aux:%s, vg name:%s.", dss_display_metaid(data->id),
        vg_item->vg_name);

    return CM_SUCCESS;
}

status_t rb_redo_free_fs_aux(dss_vg_info_item_t *vg_item, dss_redo_entry_t *entry)
{
    CM_ASSERT(vg_item != NULL);
    CM_ASSERT(entry != NULL);

    dss_redo_free_fs_aux_t *data = (dss_redo_free_fs_aux_t *)entry->data;

    // recover the fs aux
    dss_fs_aux_t *fs_aux =
        (dss_fs_aux_t *)dss_find_block_in_shm(NULL, vg_item, data->id, DSS_BLOCK_TYPE_FS_AUX, CM_TRUE, NULL, CM_FALSE);
    DSS_RETURN_IF_FALSE2(
        (fs_aux != NULL), LOG_RUN_ERR("[REDO][FS AUX]Failed to fs aux fs aux id:%s.", dss_display_metaid(data->id)));

    // recover the root
    status_t status = rb_reload_fs_aux_root(vg_item);
    DSS_RETURN_IFERR2(status,
        LOG_RUN_ERR("[REDO][FS AUX]Failed to update fs aux root fs_aux:%s to disk.", dss_display_metaid(data->id)));

    return CM_SUCCESS;
}

status_t rp_redo_init_fs_aux(dss_vg_info_item_t *vg_item, dss_redo_entry_t *entry)
{
    CM_ASSERT(vg_item != NULL);
    CM_ASSERT(entry != NULL);

    status_t status;
    dss_redo_init_fs_aux_t *data = (dss_redo_init_fs_aux_t *)entry->data;

    dss_fs_aux_t *fs_aux = NULL;

    if (vg_item->status == DSS_VG_STATUS_RECOVERY) {
        fs_aux = (dss_fs_aux_t *)dss_find_block_in_shm(
            NULL, vg_item, data->id, DSS_BLOCK_TYPE_FS_AUX, CM_TRUE, NULL, CM_FALSE);
        DSS_RETURN_IF_FALSE2((fs_aux != NULL),
            LOG_RUN_ERR("[REDO][FS AUX]Failed to fs aux fs aux id:%s.", dss_display_metaid(data->id)));

        dss_set_blockid(&fs_aux->head.data_id, DSS_BLOCK_ID_SET_UNINITED(data->data_id));
        fs_aux->head.ftid = data->ftid;
    } else {
        fs_aux = (dss_fs_aux_t *)dss_find_block_in_shm(
            NULL, vg_item, data->id, DSS_BLOCK_TYPE_FS_AUX, CM_FALSE, NULL, CM_FALSE);
        DSS_RETURN_IF_FALSE2((fs_aux != NULL),
            LOG_RUN_ERR("[REDO][FS AUX]Failed to fs aux fs aux id:%s.", dss_display_metaid(data->id)));
    }

    status = dss_update_fs_aux_bitmap2disk(vg_item, fs_aux, DSS_FS_AUX_SIZE, CM_FALSE);
    DSS_RETURN_IFERR2(status,
        LOG_RUN_ERR("[REDO][FS AUX]Failed to update fs aux bitmap fs_aux:%s to disk.", dss_display_metaid(data->id)));
    LOG_DEBUG_INF("[REDO][FS AUX]Succeed to replay init fs aux fs_aux:%s, vg name:%s.", dss_display_metaid(data->id),
        vg_item->vg_name);
    return CM_SUCCESS;
}

status_t rb_redo_init_fs_aux(dss_vg_info_item_t *vg_item, dss_redo_entry_t *entry)
{
    CM_ASSERT(vg_item != NULL);
    CM_ASSERT(entry != NULL);

    dss_redo_init_fs_aux_t *data = (dss_redo_init_fs_aux_t *)entry->data;

    dss_fs_aux_t *fs_aux =
        (dss_fs_aux_t *)dss_find_block_in_shm(NULL, vg_item, data->id, DSS_BLOCK_TYPE_FS_AUX, CM_TRUE, NULL, CM_FALSE);
    DSS_RETURN_IF_FALSE2(
        (fs_aux != NULL), LOG_RUN_ERR("[REDO][FS AUX]Failed to fs aux fs aux id:%s.", dss_display_metaid(data->id)));

    (void)memset_s(&fs_aux->bitmap[0], fs_aux->head.bitmap_num, 0xFF, fs_aux->head.bitmap_num);

    return CM_SUCCESS;
}

#ifdef __cplusplus
}
#endif