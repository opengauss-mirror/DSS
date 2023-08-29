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
 * dss_diskgroup.h
 *
 *
 * IDENTIFICATION
 *    src/common/dss_diskgroup.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __DSS_DISK_GROUP_H__
#define __DSS_DISK_GROUP_H__

#include "dss_defs.h"
#include "dss_volume.h"
#include "cm_types.h"
#include "dss_hashmap.h"
#include "dss_latch.h"
#include "cm_checksum.h"
#include "dss_file_def.h"
#include "cm_checksum.h"
#include "dss_log.h"
#include "dss_stack.h"
#include "dss_session.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DSS_LOADDISK_BUFFER_SIZE SIZE_K(32)
#define DSS_READ4STANDBY_ERR (int32)3
/*
    1、when the node is standby, just send message to primary to read volume
    2、if the primary is just in recovery or switch, may wait the read request
    3、if read failed, just retry.
    4、may be standby switch to primary, just read volume from self;
    5、may be primary just change to standby, just read volume from new primary;
*/
#define DSS_READ_REMOTE_INTERVAL 50

// for lsvg
typedef struct dss_volume_space_info_t {
    char volume_name[DSS_MAX_VOLUME_PATH_LEN];
    double volume_free;
    double volume_size;
    double volume_used;
} volume_space_info_t;

typedef struct dss_vg_space_info_t {
    double dss_vg_free;
    double dss_vg_size;
} vg_space_info_t;

typedef struct dss_vg_vlm_space_info_t {
    char vg_name[DSS_MAX_NAME_LEN];
    volume_space_info_t volume_space_info[DSS_MAX_VOLUMES];
    vg_space_info_t vg_space_info;
    uint32 volume_count;
} vg_vlm_space_info_t;

typedef struct st_dss_allvg_vlm_space_t {
    vg_vlm_space_info_t volume_group[DSS_MAX_VOLUME_GROUP_NUM];
    uint32_t group_num;
} dss_allvg_vlm_space_t;

typedef handle_t dss_directory_t;  // dss_dir_t

extern dss_share_vg_info_t *g_dss_share_vg_info;
// create vg only use in tool
status_t dss_create_vg(const char *vg_name, const char *volume_name, dss_config_t *inst_cfg, uint32 size);
status_t dss_load_vg_conf_info(dss_vg_info_t **vgs, const dss_config_t *inst_cfg);
void dss_free_vg_info(dss_vg_info_t *vgs_info);
dss_vg_info_item_t *dss_find_vg_item(const char *vg_name);
status_t dss_get_vg_info(dss_share_vg_info_t *share_vg_info, dss_vg_info_t **info);
status_t dss_load_vg_ctrl(dss_vg_info_item_t *vg_item, bool32 is_lock);

status_t dss_load_vg_ctrl_part(dss_vg_info_item_t *vg_item, int64 offset, void *buf, int32 size, bool32 *remote);
status_t dss_check_refresh_core(dss_vg_info_item_t *vg_item);

void dss_lock_vg_mem_x(dss_vg_info_item_t *vg_item);
void dss_lock_vg_mem_x2ix(dss_vg_info_item_t *vg_item);
void dss_lock_vg_mem_ix2x(dss_vg_info_item_t *vg_item);
void dss_lock_vg_mem_s(dss_vg_info_item_t *vg_item);
void dss_lock_vg_mem_s_force(dss_vg_info_item_t *vg_item);
void dss_unlock_vg_mem(dss_vg_info_item_t *vg_item);

status_t dss_file_lock_vg_w(dss_config_t *inst_cfg);
void dss_file_unlock_vg(void);
status_t dss_lock_disk_vg(const char *entry_path, dss_config_t *inst_cfg);
void dss_unlock_vg_raid(dss_vg_info_item_t *vg_item, const char *entry_path, int64 inst_id);
status_t dss_lock_vg_storage_r(dss_vg_info_item_t *vg_item, const char *entry_path, dss_config_t *inst_cfg);
status_t dss_lock_vg_storage_w(dss_vg_info_item_t *vg_item, const char *entry_path, dss_config_t *inst_cfg);
void dss_unlock_vg_storage(dss_vg_info_item_t *vg_item, const char *entry_path, dss_config_t *inst_cfg);
status_t dss_check_lock_instid(dss_vg_info_item_t *vg_item, const char *entry_path, int64 inst_id, bool32 *is_lock);

status_t dss_add_volume(dss_session_t *session, const char *vg_name, const char *volume_name);
status_t dss_remove_volume(dss_session_t *session, const char *vg_name, const char *volume_name);
status_t dss_load_ctrl(dss_session_t *session, const char *vg_name, uint32 index);
status_t dss_refresh_meta_info(dss_session_t *session);
status_t dss_load_volume_ctrl(dss_vg_info_item_t *vg_item, dss_volume_ctrl_t *volume_ctrl);

status_t dss_write_ctrl_to_disk(dss_vg_info_item_t *vg_item, int64 offset, void *buf, uint32 size);
status_t dss_update_core_ctrl_disk(dss_vg_info_item_t *vg_item);
status_t dss_update_volume_ctrl(dss_vg_info_item_t *vg_item);
status_t dss_update_volume_id_info(dss_vg_info_item_t *vg_item, uint32 id);

status_t dss_write_volume_inst(
    dss_vg_info_item_t *vg_item, dss_volume_t *volume, int64 offset, const void *buf, uint32 size);
status_t dss_read_volume_inst(
    dss_vg_info_item_t *vg_item, dss_volume_t *volume, int64 offset, void *buf, int32 size, bool32 *remote);
status_t dss_init_vol_handle(dss_vg_info_item_t *vg_item, int32 flags, dss_vol_handles_t *vol_handles);
void dss_destroy_vol_handle(dss_vg_info_item_t *vg_item, dss_vol_handles_t *vol_handles, uint32 size);
extern dss_vg_info_t *g_vgs_info;
#define VGS_INFO (g_vgs_info)
status_t dss_check_volume(dss_vg_info_item_t *vg_item, uint32 volumeid);
uint32_t dss_find_volume(dss_vg_info_item_t *vg_item, const char *volume_name);
uint32_t dss_find_free_volume_id(const dss_vg_info_item_t *vg_item);
status_t dss_cmp_volume_head(dss_vg_info_item_t *vg_item, const char *volume_name, uint32 id);


static inline dss_vg_info_item_t *dss_get_first_vg_item()
{
    return &g_vgs_info->volume_group[0];
}

// NOTE:has minus checksum field.
static inline uint32 dss_get_checksum(void *data, uint32 len)
{
    char *buf = (char *)data;
    buf = buf + sizeof(uint32);  // checksum field
    CM_ASSERT(len - sizeof(uint32) > 0);
    uint32 size = (uint32)(len - sizeof(uint32));
    return cm_get_checksum(buf, size);
}

static inline void dss_check_checksum(uint32 checksum0, uint32 checksum1)
{
    if (checksum0 != checksum1) {
        LOG_DEBUG_ERR("Failed to check checksum:%u,%u.", checksum0, checksum1);
        cm_panic(0);
    }
}

static inline bool32 dss_read_remote_checksum(void *buf, int32 size)
{
    uint32 sum1 = *(uint32 *)buf;
    uint32 sum2 = dss_get_checksum(buf, (uint32)size);
    return sum1 == sum2;
}

uint64 dss_get_vg_latch_shm_offset(dss_vg_info_item_t *vg_item);

static inline uint64 dss_get_vg_au_size(dss_ctrl_t *ctrl)
{
    return (uint64)(ctrl->core.au_size);
}

static inline void dss_set_vg_au_size(dss_ctrl_t *ctrl, uint32 au_size)
{
    CM_ASSERT(au_size <= DSS_MAX_AU_SIZE);
    ctrl->core.au_size = au_size;
}

static inline bool32 dss_check_volume_is_used(dss_vg_info_item_t *vg_item, uint32 vid)
{
    return (CM_CALC_ALIGN(DSS_VOLUME_HEAD_SIZE, dss_get_vg_au_size(vg_item->dss_ctrl)) <
        vg_item->dss_ctrl->core.volume_attrs[vid].hwm);
}

static inline bool32 dss_compare_version(uint64 disk_version, uint64 mem_version)
{
    return (disk_version > mem_version);
}

uint32 dss_get_master_id();
void dss_set_master_id(uint32 id);
bool32 dss_is_server(void);
bool32 dss_is_readwrite(void);
bool32 dss_is_readonly(void);
void dss_set_server_flag(void);
bool32 dss_need_exec_local(void);
int32 dss_get_server_status_flag();
void dss_set_server_status_flag(int32 dss_status);
status_t dss_load_ctrlinfo(uint32 index);

status_t dss_init_volume(dss_vg_info_item_t *vg_item, dss_volume_ctrl_t *volume);
status_t dss_check_write_volume(dss_vg_info_item_t *vg_item, uint32 volumeid, int64 offset, void *buf, uint32 size);
status_t dss_check_read_volume(
    dss_vg_info_item_t *vg_item, uint32 volumeid, int64 offset, void *buf, int32 size, bool32 *remote);
status_t dss_load_vg_conf_inner(dss_vg_info_t *vgs_info, const dss_config_t *inst_cfg);
typedef status_t (*dss_remote_read_proc_t)(
    const char *vg_name, dss_volume_t *volume, int64 offset, void *buf, int size);
void regist_remote_read_proc(dss_remote_read_proc_t proc);
status_t dss_read_volume_4standby(const char *vg_name, uint32 volume_id, int64 offset, void *buf, uint32 size);
status_t dss_remove_volume_core(dss_session_t *session, dss_vg_info_item_t *vg_item, const char *vg_name,
    const char *volume_name, dss_config_t *inst_cfg);
status_t dss_load_ctrl_core(dss_vg_info_item_t *vg_item, uint32 index);
status_t dss_add_volume_vg_ctrl(
    dss_ctrl_t *vg_ctrl, uint32 id, uint64 vol_size, const char *volume_name, volume_slot_e volume_flag);
status_t dss_gen_volume_head(
    dss_volume_header_t *vol_head, dss_vg_info_item_t *vg_item, const char *volume_name, uint32 id);

#ifdef __cplusplus
}
#endif
#endif
