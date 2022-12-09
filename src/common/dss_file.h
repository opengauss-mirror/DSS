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

status_t dss_make_dir(dss_session_t *session, const char *parent, const char *dir_name);
status_t dss_open_dir(dss_session_t *session, const char *dir_path, bool32 is_refresh);
void dss_close_dir(dss_session_t *session, char *vg_name, uint64 fid);
status_t dss_find_vg_by_dir(const char *dir_path, char *name, dss_vg_info_item_t **vg_item);
void dss_lock_vg_mem_and_shm_x(dss_session_t *session, dss_vg_info_item_t *vg_item);
void dss_lock_vg_mem_and_shm_s(dss_session_t *session, dss_vg_info_item_t *vg_item);
void dss_unlock_vg_mem_and_shm(dss_session_t *session, dss_vg_info_item_t *vg_item);

status_t dss_create_file(dss_session_t *session, const char *parent, const char *name, int32_t flag);
status_t dss_exist_item(dss_session_t *session, const char *item, gft_item_type_t type, bool32 *result);
status_t dss_open_file(dss_session_t *session, const char *file, int32_t flag);
status_t dss_close_file(dss_session_t *session, dss_vg_info_item_t *vg_item, uint64 fid);
status_t dss_extend_inner(
    dss_session_t *session, uint64 fid, ftid_t ftid, int64 offset, char *vg_name, uint32 vgid, bool32 is_read);
status_t dss_extend(
    dss_session_t *session, uint64 fid, ftid_t ftid, int64 offset, char *vg_name, uint32 vgid, bool32 is_read);
status_t dss_truncate(dss_session_t *session, uint64 fid, ftid_t ftid, int64 offset, uint64 length, char *vg_name);
status_t dss_refresh_file(dss_session_t *session, uint64 fid, ftid_t ftid, char *vg_name, dss_block_id_t blockid);
status_t dss_refresh_volume(dss_session_t *session, const char *name_str, uint32 vgid, uint32 volumeid);
status_t dss_refresh_ft_block(dss_session_t *session, char *vg_name, uint32 vgid, dss_block_id_t blockid);
status_t dss_create_link(dss_session_t *session, const char *parent, const char *name);
status_t dss_read_link(dss_session_t *session, char *link_path, char *out_filepath, uint32 *out_len);
status_t dss_write_link_file(dss_session_t *session, char *link_path, char *dst_path);
status_t dss_update_file_written_size(
    dss_session_t *session, char *vg_name, uint64 written_size, dss_block_id_t blockid);
status_t dss_get_ftid_by_path(dss_session_t *session, const char *path, ftid_t *ftid, dss_vg_info_item_t **dir_vg_item);
// for dss internal call
status_t dss_alloc_ft_au_when_no_free(
    dss_session_t *session, dss_vg_info_item_t *vg_item, gft_root_t *gft, bool32 *check_version);
gft_node_t *dss_alloc_ft_node(dss_session_t *session, dss_vg_info_item_t *vg_item, gft_node_t *parent_node,
    const char *name, gft_item_type_t type);
gft_node_t *dss_alloc_ft_node_when_create_vg(
    dss_vg_info_item_t *vg_item, gft_node_t *parent_node, const char *name, gft_item_type_t type, uint32 flags);

status_t dss_format_ft_node(dss_session_t *session, dss_vg_info_item_t *vg_item, auid_t auid);
void dss_free_ft_node_inner(
    dss_session_t *session, dss_vg_info_item_t *vg_item, gft_node_t *parent_node, gft_node_t *node, bool32 real_del);
void dss_free_ft_node(dss_session_t *session, dss_vg_info_item_t *vg_item, gft_node_t *parent_node, gft_node_t *node,
    bool32 real_del, bool32 latch_safe);
gft_node_t *dss_find_ft_node(dss_vg_info_item_t *vg_item, gft_node_t *parent_node, const char *name, bool32 skip_del);
char *dss_find_ft_block_latch(dss_vg_info_item_t *vg_item, ftid_t ftid, ga_obj_id_t *out_obj_id);
gft_node_t *dss_get_ft_node_by_ftid(
    dss_vg_info_item_t *vg_item, ftid_t id, bool32 check_version, bool32 active_refresh);
dss_ft_block_t *dss_get_ft_block_by_node(gft_node_t *node);
status_t dss_update_ft_block_disk(dss_vg_info_item_t *vg_item, dss_ft_block_t *block, ftid_t id);
int64 dss_get_ft_block_offset(dss_vg_info_item_t *vg_item, ftid_t id);
char *dss_get_ft_block_by_ftid(dss_vg_info_item_t *vg_item, ftid_t id);
status_t dss_refresh_root_ft(dss_vg_info_item_t *vg_item, bool32 check_version, bool32 active_refresh);

status_t dss_update_au_disk(
    dss_vg_info_item_t *vg_item, auid_t auid, ga_pool_id_e pool_id, uint32 first, uint32 count, uint32 size);
// for tool or instance
void dss_init_ft_root(dss_ctrl_t *dss_ctrl, gft_node_t **out_node);
status_t dss_update_ft_root(dss_vg_info_item_t *vg_item);
status_t dss_refresh_ft(dss_vg_info_item_t *vg_item);
status_t dss_check_refresh_ft(dss_vg_info_item_t *vg_item);
status_t dss_alloc_ft_au(dss_session_t *session, dss_vg_info_item_t *vg_item, ftid_t *id);

typedef struct st_dss_alloc_fs_block_judge {
    bool8 is_extend;
    bool8 is_new_au;
    bool8 latch_ft_root;
} dss_alloc_fs_block_judge;

status_t dss_alloc_fs_block(dss_session_t *session, dss_vg_info_item_t *vg_item, char **block, ga_obj_id_t *out_obj_id,
    dss_alloc_fs_block_judge *judge);
status_t dss_init_file_fs_block(dss_session_t *session, dss_vg_info_item_t *vg_item, dss_block_id_t *block_id);
void dss_free_fs_block_addr(dss_session_t *session, dss_vg_info_item_t *vg_item, char *block, ga_obj_id_t obj_id);
int64 dss_get_fs_block_offset(dss_vg_info_item_t *vg_item, dss_block_id_t blockid);
status_t dss_update_fs_bitmap_block_disk(
    dss_vg_info_item_t *item, dss_fs_block_t *block, uint32 size, bool32 had_checksum);
status_t dss_format_bitmap_node(dss_session_t *session, dss_vg_info_item_t *vg_item, auid_t auid);
status_t dss_check_refresh_fs_block(
    dss_vg_info_item_t *vg_item, dss_block_id_t blockid, char *block, bool32 *is_changed);
void dss_init_root_fs_block(dss_ctrl_t *dss_ctrl);
status_t dss_load_fs_block_by_blockid(dss_vg_info_item_t *vg_item, dss_block_id_t blockid, int32 size);

void dss_init_fs_block_head(dss_fs_block_t *fs_block);

status_t dss_check_rename_path(dss_session_t *session, const char *src_path, const char *dst_path, text_t *dst_name);
status_t dss_get_name_from_path(const char *path, uint32_t *beg_pos, char *name);
status_t dss_check_dir(
    const char *dir_path, gft_item_type_t type, dss_check_dir_output_t *output_info, bool32 is_throw_err);

dss_env_t *dss_get_env(void);
dss_config_t *dss_get_inst_cfg(void);
status_t dss_get_root_version(dss_vg_info_item_t *vg_item, uint64 *version);
status_t dss_check_name(const char *name);
status_t dss_check_path(const char *path);
status_t dss_check_device_path(const char *path);
status_t dss_check_path_both(const char *path);

status_t dss_refresh_vginfo(dss_vg_info_item_t *vg_item);

/* AU is usually NOT serial/continuous within a single file, judged from R/W file behaviors */
status_t dss_get_fs_block_info_by_offset(
    int64 offset, uint64 au_size, uint32 *block_count, uint32 *block_au_count, uint32 *au_offset);
status_t dss_check_open_file_remote(const char *vg_name, uint64 fid, bool32 *is_open);
void dss_mv_to_recycle_dir(dss_session_t *session, dss_vg_info_item_t *vg_item, gft_node_t *node);
status_t dss_recycle_empty_file(
    dss_session_t *session, dss_vg_info_item_t *vg_item, gft_node_t *parent_node, gft_node_t *node);
status_t dss_check_file(dss_vg_info_item_t *vg_item);
status_t dss_open_file_check(dss_session_t *session, const char *file, dss_vg_info_item_t **vg_item,
    gft_item_type_t type, gft_node_t **out_node);

gft_node_t *dss_find_parent_node_by_node(dss_vg_info_item_t *vg_item, gft_node_t *node);
status_t dss_check_rm_file(dss_vg_info_item_t *vg_item, ftid_t ftid, bool32 *should_rm_file, gft_node_t **file_node);

#ifdef __cplusplus
}
#endif
#endif
