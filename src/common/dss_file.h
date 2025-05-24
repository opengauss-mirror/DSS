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
 * dss_file.h
 *
 *
 * IDENTIFICATION
 *    src/common/dss_file.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __DSS_FILE_H_
#define __DSS_FILE_H_

#include "dss_file_def.h"
#include "dss_diskgroup.h"
#include "dss_alloc_unit.h"
#include "dss_param.h"
#include "dss_meta_buf.h"
#include "dss_session.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct st_dss_node_data {
    uint64 fid;
    ftid_t ftid;
    int64 offset;
    int64 size;
    int32 mode;
    uint32 vgid;
    char *vg_name;
} dss_node_data_t;

status_t dss_make_dir(dss_session_t *session, const char *parent, const char *dir_name);
status_t dss_open_dir(dss_session_t *session, const char *dir_path, bool32 is_refresh, dss_find_node_t *find_info);
void dss_close_dir(dss_session_t *session, char *vg_name, uint64 ftid);
status_t dss_find_vg_by_dir(const char *dir_path, char *name, dss_vg_info_item_t **vg_item);

void dss_lock_vg_mem_s_and_shm_x(dss_session_t *session, dss_vg_info_item_t *vg_item);
void dss_lock_vg_mem_and_shm_x(dss_session_t *session, dss_vg_info_item_t *vg_item);
bool32 dss_lock_vg_mem_and_shm_timed_x(dss_session_t *session, dss_vg_info_item_t *vg_item, uint32 wait_ticks);
void dss_lock_vg_mem_and_shm_x2ix(dss_session_t *session, dss_vg_info_item_t *vg_item);
void dss_lock_vg_mem_and_shm_ix2x(dss_session_t *session, dss_vg_info_item_t *vg_item);
void dss_lock_vg_mem_and_shm_s(dss_session_t *session, dss_vg_info_item_t *vg_item);
bool32 dss_lock_vg_mem_and_shm_timed_s(dss_session_t *session, dss_vg_info_item_t *vg_item, uint32 wait_ticks);
void dss_lock_vg_mem_and_shm_s_force(dss_session_t *session, dss_vg_info_item_t *vg_item);
void dss_unlock_vg_mem_and_shm(dss_session_t *session, dss_vg_info_item_t *vg_item);
void dss_lock_vg_mem_and_shm_ex_s(dss_session_t *session, char *vg_name);
void dss_unlock_vg_mem_and_shm_ex(dss_session_t *session, char *vg_name);

status_t dss_create_file(dss_session_t *session, const char *parent, const char *name, int32_t flag);
status_t dss_exist_item(dss_session_t *session, const char *item, bool32 *result, gft_item_type_t *output_type);
status_t dss_open_file(dss_session_t *session, const char *file, int32_t flag, dss_find_node_t *find_info);
status_t dss_close_file(dss_session_t *session, dss_vg_info_item_t *vg_item, uint64 ftid);
status_t dss_extend_inner(dss_session_t *session, dss_node_data_t *node_data);
status_t dss_extend(dss_session_t *session, dss_node_data_t *node_data);
status_t dss_do_fallocate(dss_session_t *session, dss_node_data_t *node_data);
status_t dss_truncate(dss_session_t *session, uint64 fid, ftid_t ftid, int64 length, char *vg_name);
status_t dss_refresh_file(dss_session_t *session, uint64 fid, ftid_t ftid, char *vg_name, int64 offset);
status_t dss_refresh_volume(dss_session_t *session, const char *name_str, uint32 vgid, uint32 volumeid);
status_t dss_refresh_ft_block(dss_session_t *session, char *vg_name, uint32 vgid, dss_block_id_t blockid);
status_t dss_create_link(dss_session_t *session, const char *parent, const char *name);
status_t dss_read_link(dss_session_t *session, char *link_path, char *out_filepath, uint32 *out_len);
status_t dss_write_link_file(dss_session_t *session, char *link_path, char *dst_path);
status_t dss_update_file_written_size(
    dss_session_t *session, uint32 vg_id, int64 offset, int64 size, dss_block_id_t ftid, uint64 fid);
status_t dss_get_ftid_by_path(dss_session_t *session, const char *path, ftid_t *ftid, dss_vg_info_item_t **dir_vg_item);
gft_node_t *dss_get_gft_node_by_path(
    dss_session_t *session, dss_vg_info_item_t *vg_item, const char *path, dss_vg_info_item_t **dir_vg_item);
// for dss internal call
status_t dss_alloc_ft_au_when_no_free(
    dss_session_t *session, dss_vg_info_item_t *vg_item, gft_root_t *gft, bool32 *check_version);
void dss_check_ft_node_free(gft_node_t *node);
void dss_check_ft_node_parent(gft_node_t *node, ftid_t parent_id);
gft_node_t *dss_alloc_ft_node(dss_session_t *session, dss_vg_info_item_t *vg_item, gft_node_t *parent_node,
    const char *name, gft_item_type_t type, int32 flag);
status_t dss_alloc_ft_node_when_create_vg(
    dss_vg_info_item_t *vg_item, gft_node_t *parent_node, const char *name, gft_item_type_t type, uint32 flags);

status_t dss_format_ft_node(dss_session_t *session, dss_vg_info_item_t *vg_item, auid_t auid);
void dss_free_ft_node_inner(
    dss_session_t *session, dss_vg_info_item_t *vg_item, gft_node_t *parent_node, gft_node_t *node, bool32 real_del);
void dss_free_ft_node(
    dss_session_t *session, dss_vg_info_item_t *vg_item, gft_node_t *parent_node, gft_node_t *node, bool32 real_del);
void dss_remove_ft_node(dss_session_t *session, dss_vg_info_item_t *vg_item, gft_node_t *parent_node, gft_node_t *node);
gft_node_t *dss_get_next_node(dss_session_t *session, dss_vg_info_item_t *vg_item, gft_node_t *node);
bool32 dss_is_last_tree_node(gft_node_t *node);
gft_node_t *dss_find_ft_node(
    dss_session_t *session, dss_vg_info_item_t *vg_item, gft_node_t *parent_node, const char *name, bool8 skip_del);
gft_node_t *dss_get_ft_node_by_ftid(
    dss_session_t *session, dss_vg_info_item_t *vg_item, ftid_t id, bool32 check_version, bool32 active_refresh);
gft_node_t *dss_get_ft_node_by_ftid_from_disk_and_refresh_shm(
    dss_session_t *session, dss_vg_info_item_t *vg_item, ftid_t id);
gft_node_t *dss_get_ft_node_by_ftid_no_refresh(dss_session_t *session, dss_vg_info_item_t *vg_item, ftid_t id);
status_t dss_update_ft_block_disk(dss_vg_info_item_t *vg_item, dss_ft_block_t *block, ftid_t id);
int64 dss_get_ft_block_offset(dss_vg_info_item_t *vg_item, ftid_t id);
char *dss_get_ft_block_by_ftid(dss_session_t *session, dss_vg_info_item_t *vg_item, ftid_t id);
status_t dss_refresh_root_ft(dss_vg_info_item_t *vg_item, bool32 check_version, bool32 active_refresh);

status_t dss_update_au_disk(
    dss_vg_info_item_t *vg_item, auid_t auid, ga_pool_id_e pool_id, uint32 first, uint32 count, uint32 size);
// for tool or instance
void dss_init_ft_root(dss_ctrl_t *dss_ctrl, gft_node_t **out_node);
status_t dss_update_ft_root(dss_vg_info_item_t *vg_item);
status_t dss_refresh_ft(dss_session_t *session, dss_vg_info_item_t *vg_item);
status_t dss_check_refresh_ft(dss_vg_info_item_t *vg_item);
status_t dss_alloc_ft_au(dss_session_t *session, dss_vg_info_item_t *vg_item, ftid_t *id);

typedef struct st_dss_alloc_fs_block_info {
    bool8 is_extend;
    bool8 is_new_au;
    uint16_t index;
    gft_node_t *node;
} dss_alloc_fs_block_info_t;
void dss_check_fs_block_flags(dss_fs_block_header *block, dss_block_flag_e flags);
void dss_check_fs_block_affiliation(dss_fs_block_header *block, ftid_t id, uint16_t index);
status_t dss_alloc_fs_block(
    dss_session_t *session, dss_vg_info_item_t *vg_item, char **block, dss_alloc_fs_block_info_t *info);
status_t dss_init_file_fs_block(
    dss_session_t *session, dss_vg_info_item_t *vg_item, dss_block_id_t *block_id, gft_node_t *node);
void dss_free_fs_block_addr(dss_session_t *session, dss_vg_info_item_t *vg_item, char *block, ga_obj_id_t obj_id);
int64 dss_get_fs_block_offset(dss_vg_info_item_t *vg_item, dss_block_id_t blockid);
status_t dss_update_fs_bitmap_block_disk(
    dss_vg_info_item_t *item, dss_fs_block_t *block, uint32 size, bool32 had_checksum);
status_t dss_format_bitmap_node(dss_session_t *session, dss_vg_info_item_t *vg_item, auid_t auid);
status_t dss_check_refresh_fs_block(
    dss_vg_info_item_t *vg_item, dss_block_id_t blockid, char *block, bool32 *is_changed);
void dss_init_root_fs_block(dss_ctrl_t *dss_ctrl);
status_t dss_load_fs_block_by_blockid(
    dss_session_t *session, dss_vg_info_item_t *vg_item, dss_block_id_t blockid, int32 size);

void dss_init_fs_block_head(dss_fs_block_t *fs_block);
dss_fs_block_t *dss_find_fs_block(dss_session_t *session, dss_vg_info_item_t *vg_item, gft_node_t *node,
    dss_block_id_t block_id, bool32 check_version, ga_obj_id_t *out_obj_id, uint16 index);

status_t dss_check_rename_path(const char *src_path, const char *dst_path, text_t *dst_name, bool32 *is_cross_dir);
status_t dss_get_name_from_path(const char *path, uint32_t *beg_pos, char *name);
status_t dss_check_dir(dss_session_t *session, const char *dir_path, gft_item_type_t type,
    dss_check_dir_output_t *output_info, bool32 is_throw_err);

dss_env_t *dss_get_env(void);
dss_config_t *dss_get_inst_cfg(void);
status_t dss_get_root_version(dss_vg_info_item_t *vg_item, uint64 *version);
bool32 dss_is_valid_link_path(const char *path);
status_t dss_check_name(const char *name);
status_t dss_check_path(const char *path);
status_t dss_check_volume_path(const char *path);
status_t dss_check_device_path(const char *path);
status_t dss_check_path_both(const char *path);

status_t dss_refresh_vginfo(dss_vg_info_item_t *vg_item);

/* AU is usually NOT serial/continuous within a single file, judged from R/W file behaviors */
status_t dss_get_fs_block_info_by_offset(
    int64 offset, uint64 au_size, uint32 *block_count, uint32 *block_au_count, uint32 *au_offset);
status_t dss_check_open_file_remote(dss_session_t *session, const char *vg_name, uint64 ftid, bool32 *is_open);
void dss_mv_to_specific_dir(
    dss_session_t *session, dss_vg_info_item_t *vg_item, gft_node_t *node, gft_node_t *specific_node);
status_t dss_recycle_empty_file(
    dss_session_t *session, dss_vg_info_item_t *vg_item, gft_node_t *parent_node, gft_node_t *node);
status_t dss_check_file(dss_vg_info_item_t *vg_item);
status_t dss_open_file_check(dss_session_t *session, const char *file, dss_vg_info_item_t **vg_item,
    gft_item_type_t type, gft_node_t **out_node);

status_t dss_check_rm_file(
    dss_session_t *session, dss_vg_info_item_t *vg_item, ftid_t ftid, bool32 *should_rm_file, gft_node_t **file_node);

void dss_set_node_flag(
    dss_session_t *session, dss_vg_info_item_t *vg_item, gft_node_t *node, bool32 is_set, uint32 flags);
void dss_validate_fs_meta(dss_session_t *session, dss_vg_info_item_t *vg_item, gft_node_t *node);
status_t dss_invalidate_fs_meta(dss_session_t *session, dss_vg_info_item_t *vg_item, gft_node_t *node);

static inline bool32 dss_is_node_deleted(gft_node_t *node)
{
    return (node->flags & DSS_FT_NODE_FLAG_DEL);
}

static inline bool32 dss_is_fs_meta_valid(gft_node_t *node)
{
    return !(node->flags & DSS_FT_NODE_FLAG_INVALID_FS_META);
}

static inline bool32 dss_is_fs_block_valid(gft_node_t *node, dss_fs_block_t *fs_block)
{
    dss_block_ctrl_t *block_ctrl = DSS_GET_BLOCK_CTRL_FROM_META(fs_block);
    return ((node->fid == block_ctrl->fid) && (node->file_ver == block_ctrl->file_ver) &&
            (block_ctrl->ftid == DSS_ID_TO_U64(node->id)));
}

static inline bool32 dss_is_fs_block_valid_all(gft_node_t *node, dss_fs_block_t *fs_block, uint16_t index)
{
    bool32 is_valid_shm = dss_is_fs_block_valid(node, fs_block);
    if (is_valid_shm) {
        dss_check_fs_block_affiliation(&fs_block->head, node->id, index);
    }
    return is_valid_shm;
}

static inline void dss_set_fs_block_file_ver(gft_node_t *node, dss_fs_block_t *fs_block)
{
    dss_block_ctrl_t *block_ctrl = DSS_GET_BLOCK_CTRL_FROM_META(fs_block);
    block_ctrl->fid = node->fid;
    block_ctrl->ftid = DSS_ID_TO_U64(node->id);
    block_ctrl->file_ver = node->file_ver;
    block_ctrl->node = (char *)node;
}

static inline uint64 dss_get_fs_block_fid(dss_fs_block_t *fs_block)
{
    dss_block_ctrl_t *block_ctrl = DSS_GET_BLOCK_CTRL_FROM_META(fs_block);
    return block_ctrl->fid;
}

static inline uint64 dss_get_fs_block_file_ver(dss_fs_block_t *fs_block)
{
    dss_block_ctrl_t *block_ctrl = DSS_GET_BLOCK_CTRL_FROM_META(fs_block);
    return block_ctrl->file_ver;
}

static inline int64 dss_get_fsb_offset(uint32 au_size, const dss_block_id_t *id)
{
    return ((int64)id->au * au_size + (int64)DSS_FILE_SPACE_BLOCK_SIZE * id->block);
}

static inline int64 dss_get_ftb_offset(uint32 au_size, const dss_block_id_t *id)
{
    if ((id->au) == 0) {
        return (int64)DSS_CTRL_ROOT_OFFSET;
    }
    return (int64)((uint64)id->au * au_size + (uint64)DSS_BLOCK_SIZE * id->block);
}

static inline int64 dss_get_fab_offset(uint32 au_size, dss_block_id_t block_id)
{
    return (int64)(DSS_FS_AUX_SIZE * block_id.block + au_size * block_id.au);
}

static inline dss_ft_block_t *dss_get_ft_by_node(gft_node_t *node)
{
    CM_ASSERT(node != NULL);

    if ((node->id.au) == 0 && node->id.block == 0) {
        return (dss_ft_block_t *)(((char *)node - sizeof(dss_root_ft_block_t)) - (node->id.item * sizeof(gft_node_t)));
    }

    return (dss_ft_block_t *)(((char *)node - sizeof(dss_ft_block_t)) - (node->id.item * sizeof(gft_node_t)));
}

static inline gft_node_t *dss_get_node_by_ft(dss_ft_block_t *block, uint32 item)
{
    return (gft_node_t *)(((char *)block + sizeof(dss_ft_block_t)) + item * sizeof(gft_node_t));
}

static inline gft_node_t *dss_get_node_by_block_ctrl(dss_block_ctrl_t *block, uint32 item)
{
    dss_ft_block_t *ft_block = DSS_GET_META_FROM_BLOCK_CTRL(dss_ft_block_t, block);
    return (gft_node_t *)((((char *)ft_block) + sizeof(dss_ft_block_t)) + item * sizeof(gft_node_t));
}

static inline bool32 dss_is_ft_block_valid(gft_node_t *node, dss_ft_block_t *ft_block)
{
    dss_block_ctrl_t *block_ctrl = DSS_GET_BLOCK_CTRL_FROM_META(ft_block);
    return ((block_ctrl->node != NULL) && (node->fid == block_ctrl->fid) && (node->file_ver == block_ctrl->file_ver) &&
            (block_ctrl->ftid == DSS_ID_TO_U64(node->id)));
}

static inline void dss_set_ft_block_file_ver(gft_node_t *node, dss_ft_block_t *ft_block)
{
    dss_block_ctrl_t *block_ctrl = DSS_GET_BLOCK_CTRL_FROM_META(ft_block);
    block_ctrl->fid = node->fid;
    block_ctrl->ftid = DSS_ID_TO_U64(node->id);
    block_ctrl->file_ver = node->file_ver;
    block_ctrl->node = (char *)node;
}

static inline uint64 dss_get_ft_block_fid(dss_ft_block_t *ft_block)
{
    dss_block_ctrl_t *block_ctrl = DSS_GET_BLOCK_CTRL_FROM_META(ft_block);
    return block_ctrl->fid;
}

static inline uint64 dss_get_ft_block_file_ver(dss_ft_block_t *ft_block)
{
    dss_block_ctrl_t *block_ctrl = DSS_GET_BLOCK_CTRL_FROM_META(ft_block);
    return block_ctrl->file_ver;
}

static inline bool32 dss_is_block_ctrl_valid(dss_block_ctrl_t *block_ctrl)
{
    gft_node_t *node = NULL;
    if (block_ctrl->type == DSS_BLOCK_TYPE_FT) {
        node = dss_get_node_by_block_ctrl(block_ctrl, 0);
        return (((node->flags & DSS_FT_NODE_FLAG_DEL) == 0) && (node->fid == block_ctrl->fid));
    } else {
        node = (gft_node_t *)block_ctrl->node;
        return ((node != NULL) && ((node->flags & DSS_FT_NODE_FLAG_DEL) == 0) && (node->fid == block_ctrl->fid) &&
                (node->file_ver == block_ctrl->file_ver) && (block_ctrl->ftid == DSS_ID_TO_U64(node->id)));
    }
}

static inline bool32 dss_get_is_refresh_ftid(gft_node_t *node)
{
    dss_ft_block_t *ft_block = dss_get_ft_by_node(node);
    dss_block_ctrl_t *block_ctrl = DSS_GET_BLOCK_CTRL_FROM_META(ft_block);
    return block_ctrl->is_refresh_ftid;
}

static inline void dss_set_is_refresh_ftid(gft_node_t *node, bool32 is_refresh_ftid)
{
    dss_ft_block_t *ft_block = dss_get_ft_by_node(node);
    dss_block_ctrl_t *block_ctrl = DSS_GET_BLOCK_CTRL_FROM_META(ft_block);
    block_ctrl->is_refresh_ftid = is_refresh_ftid;
}

static inline bool32 is_ft_root_block(ftid_t ftid)
{
    return ftid.au == 0 && ftid.block == 0;
}

static inline dss_block_ctrl_t *dss_get_block_ctrl_by_node(gft_node_t *node)
{
    if (is_ft_root_block(node->id)) {
        return NULL;
    }
    dss_ft_block_t *ft_block =
        (dss_ft_block_t *)(((char *)node - node->id.item * sizeof(gft_node_t)) - sizeof(dss_ft_block_t));
    return DSS_GET_BLOCK_CTRL_FROM_META(ft_block);
}

static inline void dss_latch_node_init(gft_node_t *node)
{
    dss_block_ctrl_t *block_ctrl = dss_get_block_ctrl_by_node(node);
    DSS_ASSERT_LOG(block_ctrl != NULL, "block_ctrl is NULL when init latch because node is root block");
    cm_latch_init(&block_ctrl->latch);
}

static inline void dss_latch_s_node(dss_session_t *session, gft_node_t *node, latch_statis_t *stat)
{
    dss_block_ctrl_t *block_ctrl = dss_get_block_ctrl_by_node(node);
    DSS_ASSERT_LOG(block_ctrl != NULL, "block_ctrl is NULL when latch s node because node is root block");
    dss_latch_s2(&block_ctrl->latch, DSS_SESSIONID_IN_LOCK(session->id), CM_FALSE, stat);
}

static inline void dss_latch_x_node(dss_session_t *session, gft_node_t *node, latch_statis_t *stat)
{
    dss_block_ctrl_t *block_ctrl = dss_get_block_ctrl_by_node(node);
    DSS_ASSERT_LOG(block_ctrl != NULL, "block_ctrl is NULL when latch x node because node is root block");
    cm_latch_x(&block_ctrl->latch, DSS_SESSIONID_IN_LOCK(session->id), stat);
}

static inline void dss_unlatch_node(gft_node_t *node)
{
    dss_block_ctrl_t *block_ctrl = dss_get_block_ctrl_by_node(node);
    DSS_ASSERT_LOG(block_ctrl != NULL, "block_ctrl is NULL when unlatch node because node is root block");
    dss_unlatch(&block_ctrl->latch);
}
static inline dss_file_context_t *dss_get_file_context_by_handle(dss_file_run_ctx_t *file_run_ctx, int32 handle)
{
    return &file_run_ctx->files.files_group[handle / DSS_FILE_CONTEXT_PER_GROUP][handle % DSS_FILE_CONTEXT_PER_GROUP];
}
// this is need to re-consturct the code-file-place
typedef status_t (*dss_invalidate_other_nodes_proc_t)(
    dss_vg_info_item_t *vg_item, char *meta_info, uint32 meta_info_size, bool32 *cmd_ack);
void regist_invalidate_other_nodes_proc(dss_invalidate_other_nodes_proc_t proc);
typedef status_t (*dss_broadcast_check_file_open_proc_t)(dss_vg_info_item_t *vg_item, uint64 ftid, bool32 *cmd_ack);
void regist_broadcast_check_file_open_proc(dss_broadcast_check_file_open_proc_t proc);

typedef status_t (*dss_refresh_ft_by_primary_proc_t)(dss_block_id_t blockid, uint32 vgid, char *vg_name);
void regist_refresh_ft_by_primary_proc(dss_refresh_ft_by_primary_proc_t proc);
typedef status_t (*dss_get_node_by_path_remote_proc_t)(dss_session_t *session, const char *dir_path,
    gft_item_type_t type, dss_check_dir_output_t *output_info, bool32 is_throw_err);
void regist_get_node_by_path_remote_proc(dss_get_node_by_path_remote_proc_t proc);

void dss_clean_all_sessions_latch();

status_t dss_block_data_oper(char *op_desc, bool32 is_write, dss_vg_info_item_t *vg_item, dss_block_id_t block_id,
    uint64 offset, char *data_buf, int32 size);
status_t dss_data_oper(char *op_desc, bool32 is_write, dss_vg_info_item_t *vg_item, auid_t auid, uint32 au_offset,
    char *data_buf, int32 size);
status_t dss_write_zero2au(char *op_desc, dss_vg_info_item_t *vg_item, uint64 fid, auid_t auid, uint32 au_offset);
status_t dss_try_write_zero_one_au(
    char *desc, dss_session_t *session, dss_vg_info_item_t *vg_item, gft_node_t *node, int64 offset);
void dss_alarm_check_vg_usage(dss_session_t *session);
status_t dss_check_open_file_local_and_remote(
    dss_session_t *session, dss_vg_info_item_t *vg_item, ftid_t ftid, bool32 *is_open);
status_t dss_calculate_vg_usage(dss_session_t *session, dss_vg_info_item_t *vg_item, uint32 *usage);
#ifdef __cplusplus
}
#endif
#endif
