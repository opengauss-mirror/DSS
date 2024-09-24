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
 * dss_redo.h
 *
 *
 * IDENTIFICATION
 *    src/common/persist/dss_redo.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __DSS_REDO_H__
#define __DSS_REDO_H__

#include "cm_defs.h"
#include "cm_date.h"
#include "dss_diskgroup.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DSS_LOG_OFFSET OFFSET_OF(dss_ctrl_t, log_buf)

#pragma pack(8)

typedef enum en_dss_redo_type {
    // dss_ctrl
    DSS_RT_UPDATE_CORE_CTRL = 0,  // start with 0, step 1, type id as index of handler array
    // volume
    DSS_RT_ADD_OR_REMOVE_VOLUME,
    DSS_RT_UPDATE_VOLHEAD,
    // ft_block && gft_node
    DSS_RT_FORMAT_AU_FILE_TABLE,
    DSS_RT_ALLOC_FILE_TABLE_NODE,
    DSS_RT_FREE_FILE_TABLE_NODE,
    DSS_RT_RECYCLE_FILE_TABLE_NODE,
    DSS_RT_SET_FILE_SIZE,
    DSS_RT_RENAME_FILE,
    // fs_block
    DSS_RT_FORMAT_AU_FILE_SPACE,
    DSS_RT_ALLOC_FS_BLOCK,
    DSS_RT_FREE_FS_BLOCK,
    DSS_RT_INIT_FILE_FS_BLOCK,
    DSS_RT_SET_FILE_FS_BLOCK,

    // gft_node
    DSS_RT_SET_NODE_FLAG,

    // fs aux
    DSS_RT_FORMAT_FS_AUX,
    DSS_RT_ALLOC_FS_AUX,
    DSS_RT_FREE_FS_AUX,
    DSS_RT_INIT_FS_AUX,
    DSS_RT_SET_FS_BLOCK_BATCH,
    DSS_RT_SET_FS_AUX_BLOCK_BATCH,
    DSS_RT_TRUNCATE_FS_BLOCK_BATCH,
} dss_redo_type_t;

// redo struct allocate file table node
typedef enum st_dss_redo_alloc_ft_node_index {
    DSS_REDO_ALLOC_FT_NODE_SELF_INDEX = 0,
    DSS_REDO_ALLOC_FT_NODE_PREV_INDEX = 1,
    DSS_REDO_ALLOC_FT_NODE_PARENT_INDEX = 2,
    DSS_REDO_ALLOC_FT_NODE_NUM = 3
} dss_redo_alloc_ft_node_index_e;
typedef struct st_dss_redo_alloc_ft_node_t {
    gft_root_t ft_root;
    gft_node_t node[DSS_REDO_ALLOC_FT_NODE_NUM];
} dss_redo_alloc_ft_node_t;

typedef enum st_dss_redo_free_ft_node_index {
    DSS_REDO_FREE_FT_NODE_PARENT_INDEX = 0,
    DSS_REDO_FREE_FT_NODE_PREV_INDEX = 1,
    DSS_REDO_FREE_FT_NODE_NEXT_INDEX = 2,
    DSS_REDO_FREE_FT_NODE_SELF_INDEX = 3,
    DSS_REDO_FREE_FT_NODE_NUM = 4
} dss_redo_free_ft_node_index_e;
typedef struct st_dss_redo_free_ft_node_t {
    gft_root_t ft_root;
    gft_node_t node[DSS_REDO_FREE_FT_NODE_NUM];
} dss_redo_free_ft_node_t;

typedef enum st_dss_redo_recycle_ft_node_index {
    DSS_REDO_RECYCLE_FT_NODE_SELF_INDEX = 0,
    DSS_REDO_RECYCLE_FT_NODE_LAST_INDEX = 1,
    DSS_REDO_RECYCLE_FT_NODE_RECYCLE_INDEX = 2,
    DSS_REDO_RECYCLE_FT_NODE_NUM = 3
} dss_redo_recycle_ft_node_index_e;
typedef struct st_dss_redo_recycle_ft_node_t {
    gft_node_t node[DSS_REDO_RECYCLE_FT_NODE_NUM];
} dss_redo_recycle_ft_node_t;

typedef struct st_dss_redo_format_ft_t {
    auid_t auid;
    uint32 obj_id;
    uint32 count;
    dss_block_id_t old_last_block;
    gft_list_t old_free_list;
} dss_redo_format_ft_t;

typedef struct st_dss_redo_free_fs_block_t {
    char head[DSS_DISK_UNIT_SIZE];
} dss_redo_free_fs_block_t;

typedef struct st_dss_redo_alloc_fs_block_t {
    dss_block_id_t id;
    dss_block_id_t ftid;
    dss_fs_block_root_t root;
    uint16_t index;
    uint16_t reserve;
} dss_redo_alloc_fs_block_t;

typedef struct st_dss_redo_rename_t {
    gft_node_t node;
    char name[DSS_MAX_NAME_LEN];
    char old_name[DSS_MAX_NAME_LEN];
} dss_redo_rename_t;

typedef struct st_dss_redo_volhead_t {
    char head[DSS_DISK_UNIT_SIZE];
    char name[DSS_MAX_NAME_LEN];
} dss_redo_volhead_t;

typedef struct st_dss_redo_volop_t {
    char attr[DSS_DISK_UNIT_SIZE];
    char def[DSS_DISK_UNIT_SIZE];
    bool32 is_add;
    uint32 volume_count;
    uint64 core_version;
    uint64 volume_version;
} dss_redo_volop_t;

typedef struct st_dss_redo_format_fs_t {
    auid_t auid;
    uint32 obj_id;
    uint32 count;
    dss_fs_block_list_t old_free_list;
} dss_redo_format_fs_t;

typedef struct st_dss_redo_init_fs_block_t {
    dss_block_id_t id;
    dss_block_id_t second_id;
    uint16 index;
    uint16 used_num;
    uint16 reserve[2];
} dss_redo_init_fs_block_t;

typedef struct st_dss_redo_set_fs_block_t {
    dss_block_id_t id;
    dss_block_id_t value;
    dss_block_id_t old_value;
    uint16 index;
    uint16 used_num;
    uint16 old_used_num;
    uint16 reserve;
} dss_redo_set_fs_block_t;

typedef struct st_dss_redo_set_fs_block_batch_t {
    dss_block_id_t id;
    uint16 used_num;
    uint16 old_used_num;
    uint16 reserve;
    dss_block_id_t id_set[DSS_FILE_SPACE_BLOCK_BITMAP_COUNT];
} dss_redo_set_fs_block_batch_t;

typedef struct st_dss_redo_set_fs_aux_block_batch_t {
    dss_block_id_t fs_block_id;
    auid_t first_batch_au;
    ftid_t node_id;
    uint16 old_used_num;
    uint16 batch_count;
    dss_fs_block_list_t new_free_list;
    dss_block_id_t id_set[DSS_FILE_SPACE_BLOCK_BITMAP_COUNT];
} dss_redo_set_fs_aux_block_batch_t;

typedef struct st_dss_redo_truncate_fs_block_batch_t {
    dss_block_id_t src_id;
    dss_block_id_t dst_id;
    uint16 src_begin;
    uint16 dst_begin;
    uint16 src_old_used_num;
    uint16 dst_old_used_num;
    uint16 count;
    uint16 reserve;
    dss_block_id_t id_set[DSS_FILE_SPACE_BLOCK_BITMAP_COUNT];
} dss_redo_truncate_fs_block_batch_t;
typedef struct st_dss_redo_set_file_size_t {
    ftid_t ftid;
    uint64 size;
    uint64 oldsize;  // old size
} dss_redo_set_file_size_t;

typedef struct st_dss_redo_set_fs_block_list_t {
    dss_block_id_t id;
    dss_block_id_t next;
    uint16 reserve[4];
} dss_redo_set_fs_block_list_t;

typedef struct st_dss_redo_set_file_flag_t {
    ftid_t ftid;
    uint32 flags;
    uint32 old_flags;
} dss_redo_set_file_flag_t;

typedef struct st_dss_redo_entry {
    dss_redo_type_t type;
    uint32 size;
    char data[0];
} dss_redo_entry_t;

#define DSS_REDO_ENTRY_HEAD_SIZE OFFSET_OF(dss_redo_entry_t, data)

// sizeof(dss_redo_batch_t) should be eight-byte aligned
typedef struct st_dss_redo_batch {
    uint32 size;
    uint32 hash_code;
    date_t time;
    uint64 lsn;
    uint32 count;  // entry count;
    char reverse[4];
    char data[0];
} dss_redo_batch_t;
#pragma pack()

// todo: deleteredo log begin in disk
static inline uint64 dss_get_redo_log_v0_start(dss_ctrl_t *dss_ctrl, uint32 vg_id)
{
    uint64 au_size = dss_get_vg_au_size(dss_ctrl);
    uint64 redo_start = CM_CALC_ALIGN(DSS_VOLUME_HEAD_SIZE, au_size) + vg_id * DSS_INSTANCE_LOG_SPLIT_SIZE;
    return redo_start;
}

#define DSS_REDO_BATCH_HEAD_SIZE OFFSET_OF(dss_redo_batch_t, data)
#define DSS_REDO_PRINT_HEAD "dss redo detail:"

typedef status_t (*dss_replay_proc)(dss_session_t *session, dss_vg_info_item_t *vg_item, dss_redo_entry_t *entry);
typedef status_t (*dss_rollback_proc)(dss_session_t *session, dss_vg_info_item_t *vg_item, dss_redo_entry_t *entry);
typedef status_t (*dss_flush_proc)(dss_session_t *session, dss_vg_info_item_t *vg_item, void *data, uint32 size);
typedef void (*dss_print_proc)(dss_redo_entry_t *entry);

typedef struct st_dss_redo_handler {
    dss_redo_type_t type;
    dss_replay_proc replay;
    dss_rollback_proc rollback;  // only rollback memory operation.
    dss_print_proc print;
} dss_redo_handler_t;

#define DSS_MAX_BLOCK_ADDR_NUM 10
typedef struct st_dss_block_addr_his_t {
    void *addrs[DSS_MAX_BLOCK_ADDR_NUM];
    uint32 count;
} dss_block_addr_his_t;
void rp_init_block_addr_history(dss_block_addr_his_t *addr_his);
void rp_insert_block_addr_history(dss_block_addr_his_t *addr_his, void *block);
bool32 rp_check_block_addr(const dss_block_addr_his_t *addr_his, const void *block);

status_t dss_write_redolog_to_disk(dss_vg_info_item_t *item, uint32 volume_id, int64 offset, char *buf, uint32 size);
void dss_put_log(dss_session_t *session, dss_vg_info_item_t *vg_item, dss_redo_type_t type, void *data, uint32 size);
status_t dss_flush_log(dss_vg_info_item_t *vg_item, char *log_buf);
status_t dss_apply_log(dss_session_t *session, dss_vg_info_item_t *vg_item, char *log_buf);
status_t dss_process_redo_log(dss_session_t *session, dss_vg_info_item_t *vg_item);
status_t dss_reset_log_slot_head(uint32 vg_id, char *log_buf);
void dss_rollback_mem_update(dss_session_t *session, dss_vg_info_item_t *vg_item);
char *dss_get_log_buf_from_vg(dss_session_t *session, dss_vg_info_item_t *vg_item, dss_redo_type_t type);
status_t dss_set_log_buf(const char *vg_name, dss_vg_info_item_t *vg_item);
void rb_redo_clean_resource(
    dss_session_t *session, dss_vg_info_item_t *item, auid_t auid, ga_pool_id_e pool_id, uint32 first, uint32 count);
status_t dss_update_redo_info(dss_vg_info_item_t *vg_item, char *log_buf);
void dss_print_redo_entry(dss_redo_entry_t *entry);

#ifdef __cplusplus
}
#endif

#endif
