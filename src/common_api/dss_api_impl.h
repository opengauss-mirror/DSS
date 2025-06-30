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
 * dss_api_impl.h
 *
 *
 * IDENTIFICATION
 *    src/common_api/dss_api_impl.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __DSS_API_IMPL_H__
#define __DSS_API_IMPL_H__

#include <stdio.h>
#include <stdbool.h>
#include "dss_errno.h"
#include "dss_au.h"
#include "dss_interaction.h"
#include "dss_session.h"
#include "dss_api.h"
#include "dss_hp_defs.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct st_dss_conn dss_conn_t;
typedef struct st_dss_conn_opt dss_conn_opt_t;

typedef enum en_cli_rw_mode {
    DSS_CLIENT_READ = 0,
    DSS_CLIENT_WRITE = 1,
    DSS_CLIENT_APPEND = 2,
} cli_rw_mode_e;

typedef struct st_dss_rw_param {
    dss_conn_t *conn;
    int32 handle;
    dss_env_t *dss_env;
    dss_file_context_t *context;
    int64 offset;
    bool32 atom_oper;
    cli_rw_mode_e rw_mode;
} dss_rw_param_t;

typedef struct st_dss_load_ctrl_info {
    const char *vg_name;
    uint32 index;
} dss_load_ctrl_info_t;

typedef struct st_dss_open_file_info {
    const char *file_path;
    int flag;
} dss_open_file_info_t;

typedef struct st_dss_close_file_info {
    uint64 fid;
    const char *vg_name;
    uint32 vg_id;
    uint64 ftid;
} dss_close_file_info_t;

typedef struct st_dss_create_file_info {
    const char *file_path;
    uint32 flag;
} dss_create_file_info_t;

typedef struct st_dss_open_dir_info {
    const char *dir_path;
    bool32 refresh_recursive;
} dss_open_dir_info_t;

typedef struct st_dss_close_dir_info {
    uint64 pftid;
    const char *vg_name;
    uint32 vg_id;
} dss_close_dir_info_t;

typedef struct st_dss_add_or_remove_info {
    const char *vg_name;
    const char *volume_name;
} dss_add_or_remove_info_t;

typedef struct st_dss_extend_info {
    uint64 fid;
    uint64 ftid;
    int64 offset;
    int64 size;
    const char *vg_name;
    uint32 vg_id;
} dss_extend_info_t;

typedef struct st_dss_rename_file_info {
    const char *src;
    const char *dst;
} dss_rename_file_info_t;

typedef struct st_dss_make_dir_info {
    const char *parent;
    const char *name;
} dss_make_dir_info_t;

typedef struct st_dss_refresh_file_info {
    uint64 fid;
    uint64 ftid;
    const char *vg_name;
    uint32 vg_id;
    int64 offset;
} dss_refresh_file_info_t;

typedef struct st_dss_refresh_volume_info {
    uint32 volume_id;
    const char *vg_name;
    uint32 vg_id;
} dss_refresh_volume_info_t;

typedef struct st_dss_truncate_file_info {
    uint64 fid;
    uint64 ftid;
    uint64 length;
    const char *vg_name;
    uint32 vg_id;
} dss_truncate_file_info_t;

typedef struct st_dss_refresh_file_table_info {
    uint64 block_id;
    const char *vg_name;
    uint32 vg_id;
} dss_refresh_file_table_info_t;

typedef struct st_dss_update_written_size_info {
    uint64 fid;
    uint64 ftid;
    uint32 vg_id;
    uint64 offset;
    uint64 size;
} dss_update_written_size_info_t;

typedef struct st_dss_setcfg_info {
    const char *name;
    const char *value;
    const char *scope;
} dss_setcfg_info_t;

typedef struct st_dss_symlink_info {
    const char *old_path;
    const char *new_path;
} dss_symlink_info_t;

typedef struct st_dss_remove_dir_info {
    const char *name;
    bool recursive;
} dss_remove_dir_info_t;

typedef struct st_dss_get_server_info {
    char *home;
    uint32 objectid;
    uint32 server_pid;
    bool32 isvtable;
} dss_get_server_info_t;

typedef struct st_dss_fallocate_info {
    uint64 fid;
    uint64 ftid;
    int64 offset;
    int64 size;
    uint32 vg_id;
    int32 mode;
} dss_fallocate_info_t;

typedef struct st_dss_exist_recv_info {
    int32 result;
    int32 type;
} dss_exist_recv_info_t;

typedef struct st_dss_hotpatch_cmd_info {
    uint32 operation_cmd;
    const char *patch_path;
} dss_hotpatch_cmd_info_t;

typedef struct st_dss_query_hotpatch_recv_info {
    uint32 total_count;
    uint32 cur_batch_count;
    dss_hp_info_view_t *hp_info_view;  // Location of output buffer must be specified before decoding.
} dss_query_hotpatch_recv_info_t;

#define DSSAPI_BLOCK_SIZE 512
#define DSS_HOME "DSS_HOME"
#define SYS_HOME "HOME"
#define DSS_DEFAULT_UDS_PATH "UDS:/tmp/.dss_unix_d_socket"
#define SESSION_LOCK_TIMEOUT 500  // tickets

status_t dss_load_ctrl_sync(dss_conn_t *conn, const char *vg_name, uint32 index);
status_t dss_add_or_remove_volume(dss_conn_t *conn, const char *vg_name, const char *volume_name, uint8 cmd);
status_t dss_kick_host_sync(dss_conn_t *conn, int64 kick_hostid);
status_t dss_alloc_conn(dss_conn_t **conn);
void dss_free_conn(dss_conn_t *conn);

// NOTE:just for dsscmd because not support many threads in one process.
status_t dss_connect_ex(const char *server_locator, dss_conn_opt_t *options, dss_conn_t *conn);
void dss_disconnect_ex(dss_conn_t *conn);
status_t dss_lock_vg_s(dss_vg_info_item_t *vg_item, dss_session_t *session);
status_t dss_cli_session_lock(dss_conn_t *conn, dss_session_t *session);
status_t dss_make_dir_impl(dss_conn_t *conn, const char *parent, const char *dir_name);
status_t dss_remove_dir_impl(dss_conn_t *conn, const char *dir, bool32 recursive);
dss_dir_t *dss_open_dir_impl(dss_conn_t *conn, const char *dir_path, bool32 refresh_recursive);
gft_node_t *dss_read_dir_impl(dss_conn_t *conn, dss_dir_t *dir, bool32 skip_delete);
status_t dss_close_dir_impl(dss_conn_t *conn, dss_dir_t *dir);
status_t dss_create_file_impl(dss_conn_t *conn, const char *file_path, int flag);
status_t dss_remove_file_impl(dss_conn_t *conn, const char *file_path);
status_t dss_open_file_impl(dss_conn_t *conn, const char *file_path, int flag, int *handle);
status_t dss_close_file_impl(dss_conn_t *conn, int handle);
status_t dss_exist_impl(dss_conn_t *conn, const char *path, bool32 *result, gft_item_type_t *type);
status_t dss_islink_impl(dss_conn_t *conn, const char *name, bool32 *result);
int64 dss_seek_file_impl(dss_conn_t *conn, int handle, int64 offset, int origin);
status_t dss_write_file_impl(dss_conn_t *conn, int handle, const void *buf, int size);
status_t dss_append_file_impl(dss_conn_t *conn, int handle, const void *buf, int size);
status_t dss_read_file_impl(dss_conn_t *conn, int handle, void *buf, int size, int *read_size);
status_t dss_copy_file_impl(dss_conn_t *conn, const char *src, const char *dest);
status_t dss_rename_file_impl(dss_conn_t *conn, const char *src, const char *dst);
status_t dss_truncate_impl(dss_conn_t *conn, int handle, long long int length);
status_t dss_add_volume_impl(dss_conn_t *conn, const char *vg_name, const char *volume_name);
status_t dss_remove_volume_impl(dss_conn_t *conn, const char *vg_name, const char *volume_name);
status_t dss_fstat_impl(dss_conn_t *conn, int handle, dss_stat_info_t item);
status_t dss_set_stat_info(dss_stat_info_t item, gft_node_t *node);

status_t dss_init_vol_handle_sync(dss_conn_t *conn);

void dss_destroy_vol_handle_sync(dss_conn_t *conn);
status_t dss_cli_handshake(dss_conn_t *conn, uint32 max_open_file);
status_t dss_init(uint32 max_open_files, char *home);
void dss_destroy(void);
status_t dss_symlink_impl(dss_conn_t *conn, const char *oldpath, const char *newpath);
status_t dss_unlink_impl(dss_conn_t *conn, const char *link);
status_t dss_readlink_impl(dss_conn_t *conn, const char *dir_path, char *out_str, size_t str_len);
status_t dss_get_fname_impl(int handle, char *fname, int fname_size);

status_t dss_pwrite_file_impl(dss_conn_t *conn, int handle, const void *buf, int size, long long offset);
status_t dss_pread_file_impl(dss_conn_t *conn, int handle, void *buf, int size, long long offset, int *read_size);
status_t dss_get_addr_impl(dss_conn_t *conn, int32 handle, long long offset, char *pool_name, char *image_name,
    char *obj_addr, unsigned int *obj_id, unsigned long int *obj_offset);
gft_node_t *dss_get_node_by_path_impl(dss_conn_t *conn, const char *path);
status_t dss_get_fd_by_offset(dss_conn_t *conn, int handle, long long offset, int32 size,
    cli_rw_mode_e rw_mode, int *fd, int64 *vol_offset, int32 *real_count);
status_t get_au_size_impl(dss_conn_t *conn, int handle, long long *au_size);
status_t dss_compare_size_equal_impl(const char *vg_name, long long *au_size);
status_t dss_setcfg_impl(dss_conn_t *conn, const char *name, const char *value, const char *scope);
status_t dss_getcfg_impl(dss_conn_t *conn, const char *name, char *out_str, size_t str_len);
status_t dss_stop_server_impl(dss_conn_t *conn);
void dss_get_api_volume_error(void);
status_t dss_aio_post_pwrite_file_impl(dss_conn_t *conn, int handle, long long offset, int size);
status_t dss_get_phy_size_impl(dss_conn_t *conn, int handle, long long *size);
status_t dss_msg_interact(dss_conn_t *conn, uint8 cmd, void *send_info, void *ack);
status_t dss_fallocate_impl(dss_conn_t *conn, int handle, int mode, long long int offset, long long int length);
status_t dss_hotpatch_impl(dss_conn_t *conn, const char *hp_cmd_str, const char *patch_path);
status_t dss_query_hotpatch_impl(dss_conn_t *conn, dss_hp_info_view_t *hp_info_view);
status_t dss_kill_session_impl(dss_conn_t *conn, uint32 sid);

void dss_set_conn_wait_event(dss_conn_t *conn, dss_wait_event_e event);
void dss_unset_conn_wait_event(dss_conn_t *conn);
status_t dss_msg_interact_with_stat(dss_conn_t *conn, uint8 cmd, void *send_info, void *ack);

status_t dss_close_file_on_server(dss_conn_t *conn, dss_vg_info_item_t *vg_item, uint64 fid, ftid_t ftid);
status_t dss_get_inst_status_on_server(dss_conn_t *conn, dss_server_status_t *dss_status);
status_t dss_get_time_stat_on_server(dss_conn_t *conn, dss_stats_item_info_t time_stat, uint64 size, int isWsr);
status_t dss_set_main_inst_on_server(dss_conn_t *conn);
status_t dss_disable_grab_lock_on_server(dss_conn_t *conn);
status_t dss_enable_grab_lock_on_server(dss_conn_t *conn);
status_t dss_enable_upgrades_on_server(dss_conn_t *conn);

#define DSS_SET_PTR_VALUE_IF_NOT_NULL(ptr, value) \
    do {                                          \
        if (ptr) {                                \
            (*(ptr) = (value));                   \
        }                                         \
    } while (0)

#define DSS_LOCK_VG_META_S_RETURN_ERROR(vg_item, session)                          \
    do {                                                                           \
        if (SECUREC_UNLIKELY(dss_lock_vg_s((vg_item), (session)) != CM_SUCCESS)) { \
            return CM_ERROR;                                                       \
        }                                                                          \
    } while (0)

#define DSS_LOCK_VG_META_S_RETURN_NULL(vg_item, session)                           \
    do {                                                                           \
        if (SECUREC_UNLIKELY(dss_lock_vg_s((vg_item), (session)) != CM_SUCCESS)) { \
            return NULL;                                                           \
        }                                                                          \
    } while (0)

#define DSS_UNLOCK_VG_META_S(vg_item, session) \
    (void)dss_unlock_shm_meta_s_with_stack((session), (vg_item)->vg_latch, CM_FALSE)

#ifdef __cplusplus
}
#endif

#endif  // __DSS_API_IMPL_H__
