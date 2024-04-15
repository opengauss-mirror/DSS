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
 * dsscmd_showdisk.h
 *
 *
 * IDENTIFICATION
 *    src/cmd/dsscmd_showdisk.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __DSSCMD_SHOWDISK_H__
#define __DSSCMD_SHOWDISK_H__

#include "dss_file_def.h"
#include "dss_session.h"
typedef struct st_dss_show_param {
    uint64 fid;
    uint64 ftid;
    int64 offset;
    int32 size;
    uint32 start_first_fs_index;
    uint32 start_second_fs_index; // fs_entry[start_first_fs_index][start_second_fs_index]
    uint32 end_first_fs_index;
    uint32 end_second_fs_index; // fs_entry[end_first_fs_index][end_second_fs_index]
    gft_node_t *node;
    char path[DSS_FILE_PATH_MAX_LENGTH];
} dss_show_param_t;

static inline void dss_init_show_param(dss_show_param_t *show_param)
{
    show_param->offset = CM_INVALID_INT64;
    show_param->size = CM_INVALID_INT32;
    show_param->start_first_fs_index = CM_INVALID_ID32;
    show_param->end_first_fs_index = CM_INVALID_ID32;
    show_param->start_second_fs_index = CM_INVALID_ID32;
    show_param->end_second_fs_index = CM_INVALID_ID32;
    show_param->node = NULL;
    show_param->path[0] = '\0';
}

#define DSS_MIN_BLOCK_INDEX_ID 0
#define DSS_MAX_FS_BLOCK_INDEX_ID (DSS_FILE_SPACE_BLOCK_SIZE - sizeof(dss_fs_block_t)) / sizeof(dss_block_id_t)
#define DSS_MAX_FT_BLOCK_INDEX_ID (DSS_BLOCK_SIZE - sizeof(dss_ft_block_t)) / sizeof(gft_node_t)

status_t dss_printf_core_ctrl(dss_vg_info_item_t *vg_item, dss_volume_t *volume);
status_t dss_printf_block_with_blockid(dss_session_t *session, dss_vg_info_item_t *vg_item, uint64 block_id, uint64 node_id);
status_t dss_print_gft_node_by_path(dss_session_t *session, dss_vg_info_item_t *vg_item, dss_show_param_t *show_param);
status_t dss_print_gft_node_by_ftid_and_fid(dss_session_t *session, dss_vg_info_item_t *vg_item, dss_show_param_t *show_param);
status_t dss_print_struct_name_inner(
    dss_vg_info_item_t *vg_item, dss_volume_t *volume, const char *struct_name);
status_t dss_print_fsb_by_id_detail(dss_session_t *session, dss_vg_info_item_t *vg_item, uint64 block_id, dss_show_param_t *show_param);
#endif
