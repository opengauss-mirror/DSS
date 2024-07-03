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

#include "dss_ctrl_def.h"

// gft_node_t flag
#define DSS_FT_NODE_FLAG_SYSTEM 0x00000001
#define DSS_FT_NODE_FLAG_DEL 0x00000002
#define DSS_FT_NODE_FLAG_NORMAL 0x00000004
#define DSS_FT_NODE_FLAG_INVALID_FS_META 0x00000008
#define DSS_FT_NODE_FLAG_INNER_INITED 0x80000000

#define DSS_IS_FILE_INNER_INITED(flag) ((uint64)(flag)&DSS_FT_NODE_FLAG_INNER_INITED)

#define DSS_GFT_PATH_STR "PATH"
#define DSS_GFT_FILE_STR "FILE"
#define DSS_GFT_LINK_STR "LINK"
#define DSS_GFT_INVALID_STR "INVALID_TYPE"

#ifdef DSS_TEST
#define DSS_INSTANCE_OPEN_FLAG (O_RDWR | O_SYNC)
#define DSS_CLI_OPEN_FLAG (O_RDWR | O_SYNC)
#else
#define DSS_INSTANCE_OPEN_FLAG (O_RDWR | O_SYNC | O_DIRECT)
#define DSS_CLI_OPEN_FLAG (O_RDWR | O_SYNC | O_DIRECT)
#define DSS_NOD_OPEN_FLAG (O_RDWR | O_SYNC)
#endif

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

#define DSS_BLOCK_ID_INIT (uint64)0xFFFFFFFFFFFFFFFE
// used for ft node parent and fs block ftid init,
typedef union st_gft_node {
    struct {
        gft_item_type_t type;
        time_t create_time;
        time_t update_time;
        uint32 software_version;
        uint32 flags;
        atomic_t size;  // Actually uint64, use atomic_get for client read and atomic_set for server modify.
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
        uint64 file_ver;  // the current ver of the file, when create, it's zero, when truncate the content of the file
                          // to small size, update it by in old file_ver with step 1
        uint64 min_inited_size;  // before this ,must has written data
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
#define DSS_FILE_SPACE_BLOCK_BITMAP_COUNT (DSS_FILE_SPACE_BLOCK_SIZE - sizeof(dss_fs_block_header)) / sizeof(auid_t)
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

#define DSS_ENTRY_FS_INDEX 0xFFFD
#define DSS_FS_INDEX_INIT 0xFFFE
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
