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
 *    src/common/dss_redo.h
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
} dss_redo_type_t;

typedef struct st_dss_redo_entry {
    dss_redo_type_t type;
    uint32 vg_id;  // exist operation multi vg
    uint32 size;
    uint64 lsn;
    char data[0];
} dss_redo_entry_t;

#define DSS_REDO_ENTRY_HEAD_SIZE OFFSET_OF(dss_redo_entry_t, data)

// sizeof(dss_redo_batch_t) should be eight-byte aligned
typedef struct st_dss_redo_batch {
    uint32 size;
    uint32 hash_code;
    date_t time;
    bool32 in_recovery;
    uint32 sort_offset;
    uint32 count;  // entry count;
    char reverse[4];
    char data[0];
} dss_redo_batch_t;

typedef struct st_dss_sort_handle {
    uint64 offset;
    uint64 lsn;
} dss_sort_handle_t;

#define DSS_REDO_BATCH_HEAD_SIZE OFFSET_OF(dss_redo_batch_t, data)
#define DSS_REDO_PRINT_HEAD "dss redo detail:"

typedef status_t (*dss_replay_proc)(dss_vg_info_item_t *vg_item, dss_redo_entry_t *entry);
typedef status_t (*dss_rollback_proc)(dss_vg_info_item_t *vg_item, dss_redo_entry_t *entry);
typedef status_t (*dss_flush_proc)(dss_vg_info_item_t *vg_item, void *data, uint32 size);

typedef struct st_dss_redo_handler {
    dss_redo_type_t type;
    dss_replay_proc replay;
    dss_rollback_proc rollback;  // only rollback memory operation.
} dss_redo_handler_t;

#define DSS_MAX_BLOCK_ADDR_NUM 10
typedef struct st_dss_block_addr_his_t {
    void *addrs[DSS_MAX_BLOCK_ADDR_NUM];
    uint32 count;
} dss_block_addr_his_t;
void rp_init_block_addr_history(dss_block_addr_his_t *addr_his);
void rp_insert_block_addr_history(dss_block_addr_his_t *addr_his, void *block);
bool32 rp_check_block_addr(const dss_block_addr_his_t *addr_his, const void *block);

status_t dss_write_redolog_to_disk(dss_vg_info_item_t *item, int64 offset, char *buf, uint32 size);
void dss_put_log(dss_session_t *session, dss_vg_info_item_t *vg_item, dss_redo_type_t type, void *data, uint32 size);
status_t dss_flush_log(int32_t log_split, dss_vg_info_item_t *vg_item, char *log_buf);
status_t dss_recover_when_instance_start(dss_redo_batch_t *batch, bool32 need_check);
status_t dss_recover_ctrlinfo(dss_vg_info_item_t *vg_item);
status_t dss_apply_log(dss_vg_info_item_t *vg_item, char *log_buf);
status_t dss_process_redo_log(dss_session_t *session, dss_vg_info_item_t *vg_item);
status_t dss_reset_log_slot_head(int32_t slot);
bool32 dss_check_redo_log_available(dss_redo_batch_t *batch, dss_vg_info_item_t *vg_item, uint8 slot);
void dss_rollback_mem_update(int32_t log_split, dss_vg_info_item_t *vg_item);
void dss_free_log_slot(dss_session_t *session);
void dss_reset_log_buf(dss_session_t *session, dss_vg_info_item_t *vg_item);
char *dss_get_log_buf_from_instance(dss_session_t *session, dss_vg_info_item_t *vg_item, dss_redo_type_t type);
char *dss_get_total_log_buf(dss_session_t *session, dss_vg_info_item_t *vg_item, dss_redo_type_t type);
status_t dss_set_log_buf_for_first_vg(const char *vg_name, dss_vg_info_item_t *vg_item, dss_volume_t *volume);
status_t dss_set_log_buf(const char *vg_name, dss_vg_info_item_t *vg_item, dss_volume_t *volume);
char *dss_get_log_buf(dss_session_t *session, dss_vg_info_item_t *vg_item);

#ifdef __cplusplus
}
#endif

#endif
