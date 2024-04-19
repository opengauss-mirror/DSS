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
 * dss_syn_meta.c
 *
 *
 * IDENTIFICATION
 *    src/common/dss_syn_meta.c
 *
 * -------------------------------------------------------------------------
 */
#include "dss_syn_meta.h"
#include "dss_file.h"

#ifdef __cplusplus
extern "C" {
#endif

static bool32 enable_syn_meta = CM_TRUE;
bool32 dss_is_syn_meta_enable()
{
    return enable_syn_meta;
}

void dss_set_syn_meta_enable(bool32 is_enable_syn_meta)
{
    enable_syn_meta = is_enable_syn_meta;
}

dss_meta_syn2other_nodes_proc_t meta_syn2other_nodes_proc = NULL;
void regist_meta_syn2other_nodes_proc(dss_meta_syn2other_nodes_proc_t proc)
{
    meta_syn2other_nodes_proc = proc;
}

void dss_add_syn_meta(dss_vg_info_item_t *vg_item, dss_block_ctrl_t *block_ctrl, uint64 version)
{
    if (!enable_syn_meta || meta_syn2other_nodes_proc == NULL || !dss_is_block_ctrl_valid(block_ctrl)) {
        return;
    }

    (void)cm_atomic_inc((atomic_t *)&block_ctrl->syn_meta_ref_cnt);
    LOG_DEBUG_INF("add syn meta for fid:%llu, ftid:%llu, file_ver:%llu, type:%u, id:%llu, ref_cnt:%llu, version:%llu",
        block_ctrl->fid, block_ctrl->ftid, block_ctrl->file_ver, (uint32)block_ctrl->type,
        DSS_ID_TO_U64(block_ctrl->block_id), block_ctrl->syn_meta_ref_cnt, version);

    dss_latch_x(&vg_item->syn_meta_desc.latch);
    // if has been in the link, just leave
    if (block_ctrl->syn_meta_node.next != NULL || block_ctrl->syn_meta_node.prev != NULL) {
        dss_unlatch(&vg_item->syn_meta_desc.latch);
        return;
    }

    // add to tail of syn_meta_desc
    cm_bilist_add_tail(&block_ctrl->syn_meta_node, &vg_item->syn_meta_desc.bilist);
    dss_unlatch(&vg_item->syn_meta_desc.latch);
}

void dss_del_syn_meta(dss_vg_info_item_t *vg_item, dss_block_ctrl_t *block_ctrl, int64 syn_meta_ref_cnt)
{
    if (!enable_syn_meta || meta_syn2other_nodes_proc == NULL) {
        return;
    }

    // syn_meta_ref_cnt at most eq block_ctrl->syn_meta_ref_cnt, may less
    if ((uint64)cm_atomic_get((atomic_t *)&block_ctrl->syn_meta_ref_cnt) > 0) {
        (void)cm_atomic_add((atomic_t *)&block_ctrl->syn_meta_ref_cnt, (0 - syn_meta_ref_cnt));
    }
    if ((uint64)cm_atomic_get((atomic_t *)&block_ctrl->syn_meta_ref_cnt) != 0) {
        return;
    }
    dss_latch_x(&vg_item->syn_meta_desc.latch);
    LOG_DEBUG_INF("del syn meta for fid:%llu, ftid:%llu, file_ver:%llu, type:%u, id:%llu, ref_cnt:%llu",
        block_ctrl->fid, block_ctrl->ftid, block_ctrl->file_ver, (uint32)block_ctrl->type,
        DSS_ID_TO_U64(block_ctrl->block_id), block_ctrl->syn_meta_ref_cnt);
    cm_bilist_del(&block_ctrl->syn_meta_node, &vg_item->syn_meta_desc.bilist);
    dss_unlatch(&vg_item->syn_meta_desc.latch);
}

void dss_syn_meta(dss_vg_info_item_t *vg_item, dss_block_ctrl_t *block_ctrl, dss_common_block_t *block)
{
    if (dss_need_exec_local() && dss_is_readwrite()) {
        dss_meta_syn_t meta_syn;
        // too many place to change the value of block_ctrl->data
        dss_lock_vg_mem_and_shm_s(NULL, vg_item);
        char *addr = (char *)block_ctrl;
        block = (dss_common_block_t *)(addr - dss_buffer_cache_get_block_size(block_ctrl->type));
        meta_syn.ftid = block_ctrl->ftid;
        meta_syn.fid = block_ctrl->fid;
        meta_syn.file_ver = block_ctrl->file_ver;
        meta_syn.syn_meta_version = block->version;
        meta_syn.meta_block_id = DSS_ID_TO_U64(block->id);
        meta_syn.vg_id = vg_item->id;
        meta_syn.meta_type = block_ctrl->type;
        meta_syn.meta_len = dss_buffer_cache_get_block_size(block_ctrl->type);
        errno_t errcode = memcpy_s(meta_syn.meta, meta_syn.meta_len, (char *)block, meta_syn.meta_len);
        if (SECUREC_UNLIKELY(errcode != EOK)) {
            dss_unlock_vg_mem_and_shm(NULL, vg_item);
            DSS_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
            return;
        }
        dss_unlock_vg_mem_and_shm(NULL, vg_item);

        (void)meta_syn2other_nodes_proc(
            vg_item, (char *)&meta_syn, (OFFSET_OF(dss_meta_syn_t, meta) + meta_syn.meta_len), NULL);
        LOG_DEBUG_INF("syn meta file:%llu file_ver:%llu, vg:%u, block:%llu type:%u, with version:%llu.", meta_syn.fid,
            meta_syn.file_ver, meta_syn.vg_id, meta_syn.meta_block_id, meta_syn.meta_type, meta_syn.syn_meta_version);
    }
}

// if primary, syn meta, if not, just clean the link
bool32 dss_syn_buffer_cache(dss_vg_info_item_t *vg_item)
{
    if (!enable_syn_meta || meta_syn2other_nodes_proc == NULL) {
        return CM_TRUE;
    }

    if (cm_bilist_empty(&vg_item->syn_meta_desc.bilist)) {
        return CM_TRUE;
    }

    bool32 is_valid;
    dss_common_block_t *block = NULL;
    dss_block_ctrl_t *block_ctrl = NULL;
    dss_block_ctrl_t *onwer_block_ctrl = NULL;

    bilist_node_t *bilist_node = NULL;
    bilist_node_t *bilist_node_tail = NULL;
    bilist_node_t *bilist_node_next = NULL;

    // without latch here, may miss this time, bu can get next time
    bilist_node = cm_bilist_head(&vg_item->syn_meta_desc.bilist);
    bilist_node_tail = cm_bilist_tail(&vg_item->syn_meta_desc.bilist);
    while (bilist_node != NULL) {
        block_ctrl = BILIST_NODE_OF(dss_block_ctrl_t, bilist_node, syn_meta_node);
        // forbid delay node recycle task recycle node
        if (block_ctrl->type == DSS_BLOCK_TYPE_FT) {
            (void)cm_atomic_inc((atomic_t *)&block_ctrl->bg_task_ref_cnt);
        } else {
            onwer_block_ctrl = dss_get_block_ctrl_by_node((gft_node_t *)block_ctrl->node);
            (void)cm_atomic_inc((atomic_t *)&onwer_block_ctrl->bg_task_ref_cnt);
        }

        int64 syn_meta_ref_cnt = (int64)cm_atomic_get((atomic_t *)&block_ctrl->syn_meta_ref_cnt);

        LOG_DEBUG_INF("try syn meta for fid:%llu, ftid:%llu, file_ver:%llu, type:%u, id:%llu, ref_cnt:%llu",
            block_ctrl->fid, block_ctrl->ftid, block_ctrl->file_ver, (uint32)block_ctrl->type,
            DSS_ID_TO_U64(block_ctrl->block_id), block_ctrl->syn_meta_ref_cnt);

        is_valid = dss_is_block_ctrl_valid(block_ctrl);
        if (!is_valid) {
            if (bilist_node_tail == bilist_node) {
                bilist_node_next = NULL;
            } else {
                bilist_node_next = BINODE_NEXT(bilist_node);
            }
            dss_del_syn_meta(vg_item, block_ctrl, syn_meta_ref_cnt);
            if (block_ctrl->type == DSS_BLOCK_TYPE_FT) {
                (void)cm_atomic_dec((atomic_t *)&block_ctrl->bg_task_ref_cnt);
            } else {
                (void)cm_atomic_dec((atomic_t *)&onwer_block_ctrl->bg_task_ref_cnt);
            }

            bilist_node = bilist_node_next;
            continue;
        }

        dss_syn_meta(vg_item, block_ctrl, block);

        if (bilist_node_tail != bilist_node) {
            bilist_node_next = BINODE_NEXT(bilist_node);
        } else {
            bilist_node_next = NULL;
        }
        dss_del_syn_meta(vg_item, block_ctrl, syn_meta_ref_cnt);

        if (block_ctrl->type == DSS_BLOCK_TYPE_FT) {
            (void)cm_atomic_dec((atomic_t *)&block_ctrl->bg_task_ref_cnt);
        } else {
            (void)cm_atomic_dec((atomic_t *)&onwer_block_ctrl->bg_task_ref_cnt);
        }
        bilist_node = bilist_node_next;
    }

    return cm_bilist_empty(&vg_item->syn_meta_desc.bilist);
}

status_t dss_meta_syn_remote(dss_session_t *session, dss_meta_syn_t *meta_syn, uint32 size, bool32 *ack)
{
    if (!enable_syn_meta || meta_syn2other_nodes_proc == NULL) {
        return CM_SUCCESS;
    }

    *ack = CM_FALSE;

    LOG_DEBUG_INF("notify syn meta file:%llu, file_ver:%llu, vg :%u, block:%llu type:%u, with version:%llu.",
        meta_syn->fid, meta_syn->file_ver, meta_syn->vg_id, meta_syn->meta_block_id, meta_syn->meta_type,
        meta_syn->syn_meta_version);

    dss_vg_info_item_t *vg_item = dss_find_vg_item_by_id(meta_syn->vg_id);
    if (vg_item == NULL) {
        DSS_RETURN_IFERR2(CM_ERROR, LOG_DEBUG_ERR("Failed to find vg:%u", meta_syn->vg_id));
    }

    uint32 meta_len = dss_buffer_cache_get_block_size(meta_syn->meta_type);
    uint32 check_sum = dss_get_checksum(meta_syn->meta, meta_len);
    dss_common_block_t *syn_meta_block = DSS_GET_COMMON_BLOCK_HEAD(meta_syn->meta);
    if (meta_len != meta_syn->meta_len || check_sum != syn_meta_block->checksum) {
        DSS_RETURN_IFERR2(CM_ERROR,
            LOG_DEBUG_ERR(
                "syn meta file:%llu, file_ver:%llu, vg :%u, block: %llu, type:%u, with version:%llu data error skip.",
                meta_syn->fid, meta_syn->file_ver, meta_syn->vg_id, meta_syn->meta_block_id, meta_syn->meta_type,
                meta_syn->syn_meta_version));
    }

    char *block;
    ga_obj_id_t out_obj_id;
    dss_block_id_t meta_block_id;
    dss_set_blockid(&meta_block_id, meta_syn->meta_block_id);
    block = dss_find_block_in_shm_no_refresh_ex(session, vg_item, meta_block_id, &out_obj_id);
    if (block == NULL) {
        LOG_DEBUG_INF(
            "syn meta file:%llu, file_ver:%llu, vg:%u, block:%llu, type:%u, with version:%llu not found node fail.",
            meta_syn->fid, meta_syn->file_ver, meta_syn->vg_id, meta_syn->meta_block_id, meta_syn->meta_type,
            meta_syn->syn_meta_version);
        *ack = CM_TRUE;
        return CM_SUCCESS;
    }

    dss_block_ctrl_t *block_ctrl = dss_buffer_cache_get_block_ctrl(meta_syn->meta_type, block);
    dss_common_block_t *common_block = DSS_GET_COMMON_BLOCK_HEAD(block_ctrl);
    gft_node_t *node = NULL;
    if (common_block->type == DSS_BLOCK_TYPE_FT) {
        node = dss_get_node_by_block_ctrl(block_ctrl, 0);
    }

    dss_lock_shm_meta_x(session, vg_item->vg_latch);
    if ((block_ctrl->fid != meta_syn->fid) ||
        (common_block->type != DSS_BLOCK_TYPE_FT && block_ctrl->file_ver != meta_syn->file_ver) ||
        (common_block->type == DSS_BLOCK_TYPE_FT && block_ctrl->file_ver >= meta_syn->file_ver) ||
        (common_block->version >= meta_syn->syn_meta_version) ||
        (node != NULL && (node->flags & DSS_FT_NODE_FLAG_INVALID_FS_META))) {
        LOG_DEBUG_INF(
            "syn meta file:%llu, file_ver:%llu, vg:%u, block:%llu, type:%u, with version:%llu fid or version skip.",
            meta_syn->fid, meta_syn->file_ver, meta_syn->vg_id, meta_syn->meta_block_id, meta_syn->meta_type,
            meta_syn->syn_meta_version);
    } else {
        errno_t errcode = memcpy_s(block, meta_len, meta_syn->meta, meta_syn->meta_len);
        if (SECUREC_UNLIKELY(errcode != EOK)) {
            dss_unlock_shm_meta_without_stack(session, vg_item->vg_latch);
            DSS_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
            return CM_ERROR;
        }
    }

    dss_unlock_shm_meta_without_stack(session, vg_item->vg_latch);
    *ack = CM_TRUE;
    LOG_DEBUG_INF(
        "syn ack:%u when notify syn meta file:%llu, file_ver:%llu, vg:%u, block:%llu, type:%u, with version:%llu.",
        (uint32)(*ack), meta_syn->fid, meta_syn->file_ver, meta_syn->vg_id, meta_syn->meta_block_id,
        meta_syn->meta_type, meta_syn->syn_meta_version);
    return CM_SUCCESS;
}

status_t dss_invalidate_meta_remote(
    dss_session_t *session, dss_invalidate_meta_msg_t *invalidate_meta_msg, uint32 size, bool32 *invalid_ack)
{
    *invalid_ack = CM_FALSE;

    LOG_DEBUG_INF(" Begin to invalidate meta vg id:%u, meta type:%u, meta id:%llu.", invalidate_meta_msg->vg_id,
        invalidate_meta_msg->meta_type, invalidate_meta_msg->meta_block_id);
    dss_vg_info_item_t *vg_item = dss_find_vg_item_by_id(invalidate_meta_msg->vg_id);
    if (vg_item == NULL) {
        DSS_RETURN_IFERR3(CM_ERROR, DSS_THROW_ERROR(ERR_DSS_INVALID_ID, "invalidate id", invalidate_meta_msg->vg_id),
            LOG_DEBUG_ERR("Failed to find vg id, %u.", invalidate_meta_msg->vg_id));
    }

    dss_lock_shm_meta_x(session, vg_item->vg_latch);

    dss_block_id_t block_id;
    dss_set_auid(&block_id, invalidate_meta_msg->meta_block_id);

    if (invalidate_meta_msg->meta_type == DSS_BLOCK_TYPE_FT) {
        gft_node_t *node = dss_get_ft_node_by_ftid_no_refresh(session, vg_item, block_id);
        if (node != NULL) {
            // just update the local mem if exist
            dss_set_node_flag(session, vg_item, node, CM_FALSE, DSS_FT_NODE_FLAG_INVALID_FS_META);
        }
    } else {
        char *addr = dss_find_block_in_shm_no_refresh(session, vg_item, block_id, NULL);
        if (addr != NULL) {
            LOG_DEBUG_ERR("Success to find block:%s in mem.", dss_display_metaid(block_id));
            dss_block_ctrl_t *block_ctrl = dss_buffer_cache_get_block_ctrl(invalidate_meta_msg->meta_type, addr);
            block_ctrl->fid = 0;
            block_ctrl->ftid = 0;
            block_ctrl->file_ver = 0;
            block_ctrl->node = NULL;
        }
    }

    dss_unlock_shm_meta_without_stack(session, vg_item->vg_latch);

    *invalid_ack = CM_TRUE;
    LOG_DEBUG_INF("End to invalidate meta vg id:%u, meta type:%u, meta id:%llu, ack:%u.", invalidate_meta_msg->vg_id,
        invalidate_meta_msg->meta_type, invalidate_meta_msg->meta_block_id, (uint32)(*invalid_ack));
    return CM_SUCCESS;
}

#ifdef __cplusplus
}
#endif