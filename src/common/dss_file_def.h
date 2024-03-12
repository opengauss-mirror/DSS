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
 * dss_file_def.h
 *
 *
 * IDENTIFICATION
 *    src/common/dss_file_def.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __DSS_FILE_DEF_H__
#define __DSS_FILE_DEF_H__

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

// gft_node_t flag
#define DSS_FT_NODE_FLAG_SYSTEM 0x00000001
#define DSS_FT_NODE_FLAG_DEL 0x00000002
#define DSS_FT_NODE_FLAG_NORMAL 0x00000004
#define DSS_FT_NODE_FLAG_INVALID_FS_META 0x00000008

#define DSS_GET_ROOT_BLOCK(dss_ctrl_p) ((dss_root_ft_block_t *)((dss_ctrl_p)->root))
#define DSS_MAX_FT_AU_NUM 10
#define DSS_GET_FT_AU_LIST(ft_au_list_p) ((dss_ft_au_list_t *)(ft_au_list_p))
#define DSS_GET_FS_BLOCK_ROOT(dss_ctrl_p) ((dss_fs_block_root_t *)((dss_ctrl_p)->core.fs_block_root))
#define DSS_MAX_VOLUME_GROUP_NUM (CM_HASH_SHM_MAX_ID)

#define DSS_VG_CONF_NAME "dss_vg_conf.ini"
#define DSS_RECYLE_DIR_NAME ".recycle"

#define DSS_CTRL_RESERVE_SIZE1 (SIZE_K(727) + 512)
#define DSS_CTRL_RESERVE_SIZE2 (SIZE_K(15) -  512)

#define DSS_CTRL_CORE_OFFSET OFFSET_OF(dss_ctrl_t, core_data)
#define DSS_CTRL_VOLUME_OFFSET OFFSET_OF(dss_ctrl_t, volume_data)
#define DSS_CTRL_VG_DATA_OFFSET OFFSET_OF(dss_ctrl_t, vg_data)
#define DSS_CTRL_VG_LOCK_OFFSET OFFSET_OF(dss_ctrl_t, lock)
#define DSS_CTRL_ROOT_OFFSET OFFSET_OF(dss_ctrl_t, root)

#define DSS_CTRL_BAK_ADDR SIZE_M(1)
#define DSS_CTRL_BAK_CORE_OFFSET (DSS_CTRL_BAK_ADDR + DSS_CTRL_CORE_OFFSET)
#define DSS_CTRL_BAK_VOLUME_OFFSET (DSS_CTRL_BAK_ADDR + DSS_CTRL_VOLUME_OFFSET)
#define DSS_CTRL_BAK_VG_DATA_OFFSET (DSS_CTRL_BAK_ADDR + DSS_CTRL_VG_DATA_OFFSET)
#define DSS_CTRL_BAK_VG_LOCK_OFFSET (DSS_CTRL_BAK_ADDR + DSS_CTRL_VG_LOCK_OFFSET)
#define DSS_CTRL_BAK_ROOT_OFFSET (DSS_CTRL_BAK_ADDR + DSS_CTRL_ROOT_OFFSET)
// Size of the volume header. 2MB is used to store vg_ctrl and its backup. The last 2MB is reserved.
#define DSS_VOLUME_HEAD_SIZE SIZE_M(4)

#define DSS_VG_IS_VALID(ctrl_p) ((ctrl_p)->vg_info.valid_flag == DSS_CTRL_VALID_FLAG)

#define DSS_STANDBY_CLUSTER (g_inst_cfg->params.cluster_run_mode == CLUSTER_STANDBY)
#define DSS_IS_XLOG_VG(VG_ID) (VG_ID == g_inst_cfg->params.xlog_vg_id)
#define DSS_STANDBY_CLUSTER_XLOG_VG(VG_ID) (DSS_STANDBY_CLUSTER && DSS_IS_XLOG_VG(VG_ID))

#define DSS_FS_BLOCK_ROOT_SIZE 64
#define DSS_AU_ROOT_SIZE (((DSS_DISK_UNIT_SIZE) - (24)) - (DSS_FS_BLOCK_ROOT_SIZE))

#define DSS_VG_INFO_CORE_CTRL 1
#define DSS_VG_INFO_VG_HEADER 2
#define DSS_VG_INFO_VOLUME_CTRL 3
#define DSS_VG_INFO_ROOT_FT_BLOCK 4
#define DSS_VG_INFO_GFT_NODE 5

#define DSS_GFT_PATH_STR "PATH"
#define DSS_GFT_FILE_STR "FILE"
#define DSS_GFT_LINK_STR "LINK"
#define DSS_GFT_INVALID_STR "INVALID_TYPE"
#ifdef WIN32
typedef HANDLE volume_handle_t;
#else
typedef int32 volume_handle_t;
#endif

#ifdef DSS_TEST
#define DSS_INSTANCE_OPEN_FLAG (O_RDWR | O_SYNC)
#define DSS_CLI_OPEN_FLAG (O_RDWR | O_SYNC)
#else
#define DSS_INSTANCE_OPEN_FLAG (O_RDWR | O_SYNC | O_DIRECT)
#define DSS_CLI_OPEN_FLAG (O_RDWR | O_SYNC | O_DIRECT)
#define DSS_NOD_OPEN_FLAG (O_RDWR | O_SYNC)
#endif

#define DSS_VOLUME_DEF_RESVS 112

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
    VOLUME_PREPARE = 2, // not registered
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
    DSS_BAK_LEVEL_0 = 0, // super block only backed up on first volume, fs and ft do not backup
    DSS_BAK_LEVEL_1,     // super block backed up on some specific volumes, fs and ft backed up at the end of each volume
    DSS_BAK_LEVEL_2,     // super block backed up on all volumes, fs and ft backed up at the end of each volume
} dss_bak_level_e;

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
        char volume_data[DSS_VOLUME_CTRL_SIZE];     // 256K
    };

    char root[DSS_ROOT_FT_DISK_SIZE];  // dss_root_ft_block_t, 8KB
    char reserve1[DSS_CTRL_RESERVE_SIZE1];   // 727K + 512
    char lock[DSS_DISK_LOCK_LEN];     // align with 16K
    char reserve2[DSS_CTRL_RESERVE_SIZE2];
    union {
        dss_group_global_ctrl_t global_ctrl;
        char global_data[DSS_DISK_UNIT_SIZE]; // client disk info, size is 512
    };
} dss_ctrl_t;

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

// GFT mean DSS File Table
typedef enum en_zft_item_type {
    GFT_PATH,  // path
    GFT_FILE,
    GFT_LINK,
    GFT_LINK_TO_PATH,
    GFT_LINK_TO_FILE
} gft_item_type_t;

typedef struct st_zft_list {
    uint32 count;
    ftid_t first;
    ftid_t last;
} gft_list_t;

typedef union st_gft_node {
    struct {
        gft_item_type_t type;
        time_t create_time;
        time_t update_time;
        uint32 software_version;
        uint32 flags;
        atomic_t size;    //Actually uint64, use atomic_get for client read and atomic_set for server modify.
        union {
            dss_block_id_t entry;  // for file and link
            gft_list_t items;      // for dir
        };
        ftid_t id;
        ftid_t next;
        ftid_t prev;
        char name[DSS_MAX_NAME_LEN];
        uint64 fid;
        uint64 written_size;
        ftid_t parent;
        uint64 file_ver; // the current ver of the file, when create, it's zero, when truncate the content of the file
                         // to small size, update it by in old file_ver with step 1
    };
    char ft_node[256];  // to ensure that the structure size is 256
} gft_node_t;

typedef struct st_gft_block_info {
    gft_node_t *ft_node;
} gft_block_info_t;

typedef struct st_dss_check_dir_param_t {
    dss_vg_info_item_t *vg_item;
    gft_node_t *p_node;
    gft_node_t *last_node;
    gft_node_t *link_node;
    bool8 is_skip_delay_file;
    bool8 not_exist_err;
    bool8 is_find_link;
    bool8 last_is_link;
} dss_check_dir_param_t;

typedef struct st_dss_check_dir_output_t {
    gft_node_t **out_node;
    dss_vg_info_item_t **item;
    gft_node_t **parent_node;
    bool8 is_lock_x;
} dss_check_dir_output_t;

#define DSS_GET_COMMON_BLOCK_HEAD(au) ((dss_common_block_t *)((char *)(au)))
#define DSS_GET_FS_BLOCK_FROM_AU(au, block_id) \
    ((dss_fs_block_t *)((char *)(au) + DSS_FILE_SPACE_BLOCK_SIZE * (block_id)))
#define DSS_GET_FT_BLOCK_FROM_AU(au, block_id) ((dss_ft_block_t *)((char *)(au) + DSS_BLOCK_SIZE * (block_id)))
#define DSS_GET_FT_BLOCK_NUM_IN_AU(dss_ctrl) ((dss_get_vg_au_size(dss_ctrl)) / DSS_BLOCK_SIZE)
#define DSS_GET_FS_BLOCK_NUM_IN_AU(dss_ctrl) ((dss_get_vg_au_size(dss_ctrl)) / DSS_FILE_SPACE_BLOCK_SIZE)

typedef enum en_dss_block_type {
    DSS_BLOCK_TYPE_FT,
    DSS_BLOCK_TYPE_FS,
} dss_block_type_t;

typedef enum en_dss_block_flag {
    DSS_BLOCK_FLAG_RESERVE,
    DSS_BLOCK_FLAG_FREE,
    DSS_BLOCK_FLAG_USED,
} dss_block_flag_e;

typedef struct st_dss_common_block_t {
    uint32_t checksum;
    uint32_t type;
    uint64 version;
    dss_block_id_t id;
    uint8_t flags;
    uint8_t reserve[7];
} dss_common_block_t;

typedef struct st_dss_block_ctrl {
    uint64 fid;             // it's the owner's gft_node_t.fid
    uint64 file_ver;        // it's the owner's fgt_node_t.file_ver
    bool32 is_refresh_ftid; // just for dss_ft_block_t
    latch_t latch;
    sh_mem_p hash_next;
    sh_mem_p hash_prev;
    uint32_t hash;
    bool32 has_next;
    bool32 has_prev;
} dss_block_ctrl_t;

typedef union st_dss_ft_block {
    struct {
        dss_common_block_t common;
        uint32_t node_num;
        uint32_t reserve;
        dss_block_id_t next;
    };
    char ft_block[256];  // to ensure that the structure size is 256
} dss_ft_block_t;

typedef struct st_dss_fs_block_list_t {
    uint64 count;
    dss_block_id_t first;
    dss_block_id_t last;
} dss_fs_block_list_t;

typedef struct st_dss_fs_root_t {
    uint64 version;
    dss_fs_block_list_t free;
} dss_fs_block_root_t;

#define DSS_ENTRY_FS_INDEX 0xFFFE
typedef struct st_dss_block_header {
    dss_common_block_t common;
    dss_block_id_t next;
    dss_block_id_t ftid;
    uint16_t used_num;
    uint16_t total_num;
    uint16_t index;
    uint16_t reserve;
} dss_fs_block_header;

// file space block
typedef struct st_dss_fs_block_t {
    dss_fs_block_header head;
    dss_block_id_t bitmap[0];
} dss_fs_block_t;

typedef struct st_gft_root_t {
    gft_list_t free_list;  // free file table node list
    gft_list_t items;      // not used for now
    uint64 fid;            // the current max file id in the system;
    dss_block_id_t first;  // the first allocated block.
    dss_block_id_t last;
} gft_root_t;

typedef struct st_dss_root_ft_header {
    dss_common_block_t common;
    dss_block_id_t id;
    uint32_t node_num;
    uint32_t reserve;
    dss_block_id_t next;
    char reserver2[8];
} dss_root_ft_header_t;

typedef union st_dss_root_ft_block {
    struct {
        dss_root_ft_header_t ft_block;
        gft_root_t ft_root;
    };
    char root_ft_block[256];  // to ensure that the structure size is 256
} dss_root_ft_block_t;

#define DSS_FILE_CONTEXT_FLAG_USED 1
#define DSS_FILE_CONTEXT_FLAG_FREE 0

typedef enum en_dss_file_mode {
    DSS_FILE_MODE_READ = 0x00000001,
    DSS_FILE_MODE_WRITE = 0x00000002,
    DSS_FILE_MODE_RDWR = DSS_FILE_MODE_READ | DSS_FILE_MODE_WRITE,
} dss_file_mode_e;

typedef struct st_dss_file_context {
    latch_t latch;
    gft_node_t *node;
    uint32 next;
    uint32 flag : 2;  // DSS_FILE_CONTEXT_FLAG_USED,DSS_FILE_CONTEXT_FLAG_FREE
    uint32 tid : 22;  // 64-bit OS: pid_max [0, 2^22]
    uint32 reserve : 8;
    int64 offset;
    int64 vol_offset;
    dss_vg_info_item_t *vg_item;
    uint64 fid;
    char vg_name[DSS_MAX_NAME_LEN];
    uint32 vgid;
    uint32 id;
    dss_file_mode_e mode;
} dss_file_context_t;

typedef struct st_dss_ft_au_list_t {
    void *au_addr[DSS_MAX_FT_AU_NUM];
    uint32_t count;
} dss_ft_au_list_t;

typedef struct st_dss_env {
    latch_t latch;
    bool32 initialized;
    uint32 instance_id;
    uint32 max_open_file;
    uint32 has_opened_files;
    uint32 file_free_first;  // the first free file context.
    latch_t conn_latch;
    uint32 conn_count;
    dss_file_context_t *files;
    void *session;
    thread_t thread_heartbeat;
    dss_config_t inst_cfg;
#ifdef ENABLE_DSSTEST
    pid_t inittor_pid;
#endif
} dss_env_t;

typedef struct st_dss_dir_t {
    dss_vg_info_item_t *vg_item;
    uint64 version;
    ftid_t cur_ftid;
    gft_node_t cur_node;
    ftid_t pftid;  // path ftid
} dss_dir_t;

typedef struct st_dss_find_node_t {
    ftid_t ftid;
    char vg_name[DSS_MAX_NAME_LEN];
} dss_find_node_t;

#endif  // __DSS_FILE_DEF_H__
