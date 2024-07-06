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
 * dss_ctrl_def.h
 *
 *
 * IDENTIFICATION
 *    src/common/persist/dss_ctrl_def.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __DSS_CTRL_DEF_H__
#define __DSS_CTRL_DEF_H__

#include "dss_defs.h"
#include "cm_spinlock.h"
#include "dss_hashmap.h"
#include "cm_latch.h"
#include "dss_ga.h"
#include "cm_date.h"
#include "cm_bilist.h"
#include "dss_shm_hashmap.h"
#include "dss_param.h"
#include "dss_stack.h"
#include "dss_shm.h"
#include "ceph_interface.h"
#include "dss_block_ctrl.h"

#define DSS_GET_ROOT_BLOCK(dss_ctrl_p) ((dss_root_ft_block_t *)((dss_ctrl_p)->root))
#define DSS_MAX_FT_AU_NUM 10
#define DSS_GET_FT_AU_LIST(ft_au_list_p) ((dss_ft_au_list_t *)(ft_au_list_p))
#define DSS_GET_FS_BLOCK_ROOT(dss_ctrl_p) ((dss_fs_block_root_t *)((dss_ctrl_p)->core.fs_block_root))
#define DSS_MAX_VOLUME_GROUP_NUM (CM_HASH_SHM_MAX_ID)

#define DSS_VG_CONF_NAME "dss_vg_conf.ini"
#define DSS_RECYLE_DIR_NAME ".recycle"

#define DSS_CTRL_RESERVE_SIZE1 (SIZE_K(727))
#define DSS_CTRL_RESERVE_SIZE2 (SIZE_K(15) - 512)

#define DSS_CTRL_CORE_OFFSET OFFSET_OF(dss_ctrl_t, core_data)
#define DSS_CTRL_VOLUME_OFFSET OFFSET_OF(dss_ctrl_t, volume_data)
#define DSS_CTRL_VG_DATA_OFFSET OFFSET_OF(dss_ctrl_t, vg_data)
#define DSS_CTRL_VG_LOCK_OFFSET OFFSET_OF(dss_ctrl_t, lock)
#define DSS_CTRL_ROOT_OFFSET OFFSET_OF(dss_ctrl_t, root)
#define DSS_CTRL_REDO_OFFSET OFFSET_OF(dss_ctrl_t, redo_ctrl_data)
#define DSS_CLRL_GLOBAL_CTRL_OFFSET OFFSET_OF(dss_ctrl_t, global_data)

#define DSS_CTRL_BAK_ADDR SIZE_M(1)
#define DSS_CTRL_BAK_CORE_OFFSET (DSS_CTRL_BAK_ADDR + DSS_CTRL_CORE_OFFSET)
#define DSS_CTRL_BAK_VOLUME_OFFSET (DSS_CTRL_BAK_ADDR + DSS_CTRL_VOLUME_OFFSET)
#define DSS_CTRL_BAK_VG_DATA_OFFSET (DSS_CTRL_BAK_ADDR + DSS_CTRL_VG_DATA_OFFSET)
#define DSS_CTRL_BAK_VG_LOCK_OFFSET (DSS_CTRL_BAK_ADDR + DSS_CTRL_VG_LOCK_OFFSET)
#define DSS_CTRL_BAK_ROOT_OFFSET (DSS_CTRL_BAK_ADDR + DSS_CTRL_ROOT_OFFSET)
#define DSS_CTRL_BAK_REDO_OFFSET (DSS_CTRL_BAK_ADDR + DSS_CTRL_REDO_OFFSET)
#define DSS_CTRL_BAK_GLOBAL_CTRL_OFFSET (DSS_CTRL_BAK_ADDR + DSS_CLRL_GLOBAL_CTRL_OFFSET)

// Size of the volume header. 2MB is used to store vg_ctrl and its backup. The last 2MB is reserved.
#define DSS_VOLUME_HEAD_SIZE SIZE_M(4)

#define DSS_VG_IS_VALID(ctrl_p) ((ctrl_p)->vg_info.valid_flag == DSS_CTRL_VALID_FLAG)

#define DSS_STANDBY_CLUSTER (g_inst_cfg->params.cluster_run_mode == CLUSTER_STANDBY)
#define DSS_IS_XLOG_VG(VG_ID) (VG_ID == g_inst_cfg->params.xlog_vg_id)
#define DSS_STANDBY_CLUSTER_XLOG_VG(VG_ID) (DSS_STANDBY_CLUSTER && DSS_IS_XLOG_VG(VG_ID))

#define DSS_FS_BLOCK_ROOT_SIZE 64
#define DSS_AU_ROOT_SIZE 64

typedef enum en_vg_info_type {
    DSS_VG_INFO_CORE_CTRL = 1,
    DSS_VG_INFO_VG_HEADER,
    DSS_VG_INFO_VOLUME_CTRL,
    DSS_VG_INFO_ROOT_FT_BLOCK,
    DSS_VG_INFO_GFT_NODE,
    DSS_VG_INFO_REDO_CTRL,
    DSS_VG_INFO_TYPE_END,
} dss_vg_info_type_e;

#ifdef WIN32
typedef HANDLE volume_handle_t;
#else
typedef int32 volume_handle_t;
#endif

#define DSS_VOLUME_DEF_RESVS 112

#define DSS_FS_AUX_ROOT_SIZE 32
#define DSS_GET_FS_AUX_ROOT(dss_ctrl_p) ((dss_fs_aux_root_t *)((dss_ctrl_p)->core.fs_aux_root))
#define DSS_GET_FS_AUX_NUM_IN_AU(dss_ctrl) ((dss_get_vg_au_size(dss_ctrl)) / DSS_FS_AUX_SIZE)
#define DSS_CTRL_RESV_SIZE \
    ((((((DSS_DISK_UNIT_SIZE) - (24)) - (DSS_FS_BLOCK_ROOT_SIZE)) - (DSS_AU_ROOT_SIZE)) - (DSS_FS_AUX_ROOT_SIZE)))

#pragma pack(8)
typedef struct st_dss_volume_def {
    uint64 id : 16;
    uint64 flag : 3;
    uint64 reserve : 45;
    uint64 version;
    char name[DSS_MAX_VOLUME_PATH_LEN];
    char code[DSS_VOLUME_CODE_SIZE];
    char resv[DSS_VOLUME_DEF_RESVS];
} dss_volume_def_t;  // CAUTION:If add/remove field ,please keep 256B total !!! Or modify rp_redo_add_or_remove_volume

typedef enum en_volume_slot {
    VOLUME_FREE = 0,  // free
    VOLUME_OCCUPY = 1,
    VOLUME_PREPARE = 2,  // not registered
    VOLUME_ADD = 3,      // add
    VOLUME_REMOVE = 3,   // remove
    VOLUME_REPLACE = 3,  // replace
} volume_slot_e;

typedef struct st_dss_volume_attr {
    uint64 reverse1 : 1;
    uint64 id : 16;
    uint64 reserve2 : 47;
    uint64 size;
    uint64 hwm;
    uint64 free;
} dss_volume_attr_t;  // CAUTION:If add/remove field ,please keep 32B total !!! Or modify rp_redo_add_or_remove_volume

typedef enum dss_vg_device_Type {
    DSS_VOLUME_TYPE_RAW = 0  // default is raw device
} dss_vg_device_Type_e;

typedef struct st_dss_volume {
    char name[DSS_MAX_VOLUME_PATH_LEN];
    char *name_p;
    dss_volume_attr_t *attr;
    uint32 id;
    volume_handle_t handle;
    volume_handle_t unaligned_handle;
    dss_vg_device_Type_e vg_type;
} dss_volume_t;

typedef struct st_dss_volume_disk {
    dss_volume_def_t def;
    dss_volume_attr_t attr;
    uint32 id;
} dss_volume_disk_t;

typedef struct st_dss_metablock_header_t {
    dss_addr_t free_block_begin;
    dss_addr_t free_block_end;
    dss_addr_t first_block;
} dss_metablock_header_t;

#define DSS_VOLUME_TYPE_NORMAL 0x12345678
#define DSS_VOLUME_TYPE_MANAGER 0x12345679
typedef struct st_dss_volume_type_t {
    uint32 type;
    uint32 id;
    char entry_volume_name[DSS_MAX_VOLUME_PATH_LEN];
} dss_volume_type_t;

typedef enum st_dss_bak_level_e {
    DSS_BAK_LEVEL_0 = 0,  // super block only backed up on first volume, fs and ft do not backup
    DSS_BAK_LEVEL_1,  // super block backed up on some specific volumes, fs and ft backed up at the end of each volume
    DSS_BAK_LEVEL_2,  // super block backed up on all volumes, fs and ft backed up at the end of each volume
} dss_bak_level_e;

typedef enum en_dss_software_version {
    DSS_SOFTWARE_VERSION_0 = 0, /* version 0 */
    DSS_SOFTWARE_VERSION_1 = 1, /* version 1 */
    DSS_SOFTWARE_VERSION_2 = 2, /* version 2 */
} dss_software_version_e;

#define DSS_SOFTWARE_VERSION DSS_SOFTWARE_VERSION_2

#define DSS_CTRL_VALID_FLAG 0x5f3759df
typedef struct st_dss_disk_group_header_t {
    uint32 checksum;
    dss_volume_type_t vol_type;
    char vg_name[DSS_MAX_NAME_LEN];
    uint32 valid_flag;
    uint32 software_version;  // for upgrade
    timeval_t create_time;
    dss_bak_level_e bak_level;
    uint32 ft_node_ratio;  // A backup ft_node is created for every ft_node_ratio bytes of space
    uint64 bak_ft_offset;  // Start position of the backup ft_node array
} dss_vg_header_t;

typedef dss_vg_header_t dss_volume_header_t;

typedef struct st_dss_simple_handle_t {
    uint32 id;
    volume_handle_t handle;
    volume_handle_t unaligned_handle;
    uint64 version;
    dss_vg_device_Type_e vg_type;
} dss_simple_volume_t;

typedef struct st_dss_core_ctrl {
    uint32 checksum;  // NOTE:checksum can not change the position in the struct.dss_get_checksum need.
    uint32 reserve;
    uint64 version;
    uint32 au_size;  // allocation unit size,4M,8M,16M,32M,64M
    uint32 volume_count;
    char fs_block_root[DSS_FS_BLOCK_ROOT_SIZE];  // dss_fs_block_root_t
    char au_root[DSS_AU_ROOT_SIZE];              // 512-24-64,dss_au_root_t, recycle space entry
    char fs_aux_root[DSS_FS_AUX_ROOT_SIZE];      // dss_fs_aux_root_t
    char resv[DSS_CTRL_RESV_SIZE];
    dss_volume_attr_t volume_attrs[DSS_MAX_VOLUMES];
} dss_core_ctrl_t;

typedef struct st_dss_volume_ctrl {
    uint32 checksum;  // NOTE:can not change the position in the struct.
    uint32 rsvd;
    uint64 version;
    char reserve[496];
    dss_volume_def_t defs[DSS_MAX_VOLUMES];
} dss_volume_ctrl_t;

// struct for volume refresh
typedef struct st_refvol_ctrl {  // UNUSED
    dss_core_ctrl_t core;
    dss_volume_ctrl_t volume;
} dss_refvol_ctrl_t;

typedef struct st_dss_group_global_ctrl {
    uint64 cluster_node_info;
} dss_group_global_ctrl_t;

#define DSS_MAX_EXTENDED_COUNT 8
typedef struct st_dss_redo_ctrl {
    uint32 checksum;
    uint32 redo_index;
    uint64 version;
    uint64 offset; // redo offset
    uint64 lsn; // redo lsn
    auid_t redo_start_au[DSS_MAX_EXTENDED_COUNT];
    uint32 redo_size[DSS_MAX_EXTENDED_COUNT]; // except redo_size > 32KB
    uint32 count;
    char reserve[376];
} dss_redo_ctrl_t;

typedef struct st_dss_ctrl {
    union {
        dss_vg_header_t vg_info;
        char vg_data[DSS_VG_DATA_SIZE];
    };
    union {
        dss_core_ctrl_t core;
        char core_data[DSS_CORE_CTRL_SIZE];  // 16K
    };

    union {
        dss_volume_ctrl_t volume;
        char volume_data[DSS_VOLUME_CTRL_SIZE];  // 256K
    };
    char root[DSS_ROOT_FT_DISK_SIZE];  // dss_root_ft_block_t, 8KB
    union {
        dss_redo_ctrl_t redo_ctrl;
        char redo_ctrl_data[DSS_DISK_UNIT_SIZE];
    };
    char reserve1[DSS_CTRL_RESERVE_SIZE1];   // 727K
    char lock[DSS_DISK_LOCK_LEN];     // align with 16K
    char reserve2[DSS_CTRL_RESERVE_SIZE2];
    union {
        dss_group_global_ctrl_t global_ctrl;
        char global_data[DSS_DISK_UNIT_SIZE];  // client disk info, size is 512
    };
} dss_ctrl_t;

static inline void dss_set_software_version(dss_vg_header_t *vg_header, uint32 version)
{
    CM_ASSERT(vg_header != NULL);
    vg_header->software_version = version;
}

static inline uint32 dss_get_software_version(dss_vg_header_t *vg_header)
{
    CM_ASSERT(vg_header != NULL);
    return vg_header->software_version;
}

typedef enum en_dss_vg_status {
    DSS_VG_STATUS_RECOVERY = 1,
    DSS_VG_STATUS_ROLLBACK,
    DSS_VG_STATUS_OPEN,
} dss_vg_status_e;

#define DSS_UNDO_LOG_NUM (DSS_LOG_BUFFER_SIZE / 8)

typedef enum en_latch_type {
    LATCH_VG_HEADER = 0,
    LATCH_CORE_CTRL,
    LATCH_VOLUME_CTRL,
    LATCH_FT_ROOT,
    LATCH_COUNT,  // must be last
} latch_type_t;

typedef struct st_dss_vg_cache_node_t {
    latch_t latch;
    uint64 fid;
    uint64 ftid;
    char *node;
} dss_vg_cache_node_t;

typedef enum en_dss_from_type {
    FROM_SHM = 0,
    FROM_BBOX,
    FROM_DISK,
} dss_from_type_e;

#define DSS_VG_ITEM_CACHE_NODE_MAX 16
typedef struct st_dss_vg_info_item_t {
    uint32 id;
    char vg_name[DSS_MAX_NAME_LEN];
    char entry_path[DSS_MAX_VOLUME_PATH_LEN];  // the manager volume path
    dss_vg_status_e status;
    cm_oamap_t au_map;  // UNUSED
    dss_volume_t volume_handle[DSS_MAX_VOLUMES];
    dss_shared_latch_t *vg_latch;
    dss_ctrl_t *dss_ctrl;
    shm_hashmap_t *buffer_cache;
    char *align_buf;
    dss_stack stack;
    latch_t open_file_latch;
    bilist_t open_file_list;  // open file bilist.
    latch_t disk_latch;       // just for lock vg to lock the local instance.
    latch_t latch[LATCH_COUNT];
    dss_from_type_e from_type;
    dss_block_ctrl_task_desc_t syn_meta_desc;
    dss_vg_cache_node_t vg_cache_node[DSS_VG_ITEM_CACHE_NODE_MAX];
    dss_log_file_ctrl_t log_file_ctrl; // redo log ctrl 
} dss_vg_info_item_t;

typedef struct st_dss_vg_info_t {
    dss_vg_info_item_t volume_group[DSS_MAX_VOLUME_GROUP_NUM];
    uint32_t group_num;
} dss_vg_info_t;

typedef struct st_dss_vol_handles_t {
    dss_simple_volume_t volume_handle[DSS_MAX_VOLUMES];
} dss_vol_handles_t;

typedef struct st_dss_cli_vg_handles_t {
    dss_vol_handles_t vg_vols[DSS_MAX_VOLUME_GROUP_NUM];
    uint32_t group_num;
} dss_cli_vg_handles_t;

typedef struct st_dss_vg_conf_t {
    char vg_name[DSS_MAX_NAME_LEN];
    char entry_path[DSS_MAX_VOLUME_PATH_LEN];  // the manager volume path
} dss_vg_conf_t;

typedef struct st_dss_share_vg_item_t {
    dss_shared_latch_t vg_latch;
    shm_hashmap_t buffer_cache;
    char reserve[440];  // align 512
    dss_ctrl_t dss_ctrl;
} dss_share_vg_item_t;

typedef struct st_dss_share_vg_info_t {
    dss_share_vg_item_t vg[DSS_MAX_VOLUME_GROUP_NUM];
    uint32_t vg_num;
} dss_share_vg_info_t;

#pragma pack()
#endif  // __DSS_CTRL_DEF_H__
