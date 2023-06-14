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
#include "dss_interaction.h"
#include "dss_api.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct st_dss_rw_param {
    dss_conn_t *conn;
    int32 handle;
    dss_env_t *dss_env;
    dss_file_context_t *context;
    int64 offset;
    bool32 atom_oper;
    bool32 is_read;
} dss_rw_param_t;

struct __dss_conn_opt;
typedef struct __dss_conn_opt *dss_conn_opt_t;
typedef struct st_gft_node *dss_dir_item_handle;

#define DSSAPI_BLOCK_SIZE 512
#define DSS_HOME "DSS_HOME"
#define SYS_HOME "HOME"
#define DSS_DEFAULT_UDS_PATH "UDS:/tmp/.dss_unix_d_socket"

status_t dss_alloc_conn(dss_conn_t **conn);
void dss_free_conn(dss_conn_t *conn);
status_t dss_connect(const char *server_locator, dss_conn_opt_t options, char *user_name, dss_conn_t *conn);
void dss_disconnect(dss_conn_t *conn);

// NOTE:just for dsscmd because not support many threads in one process.
status_t dss_connect_ex(const char *server_locator, dss_conn_opt_t options, char *user_name, dss_conn_t *conn);
void dss_disconnect_ex(dss_conn_t *conn);

status_t dss_make_dir_impl(dss_conn_t *conn, const char *parent, const char *dir_name);
status_t dss_remove_dir_impl(dss_conn_t *conn, const char *dir, bool recursive);
dss_dir_t *dss_open_dir_impl(dss_conn_t *conn, const char *dir_path, bool32 refresh_recursive);
dss_dir_item_handle dss_read_dir_impl(dss_conn_t *conn, dss_dir_t *dir, bool32 skip_delete);
status_t dss_close_dir_impl(dss_conn_t *conn, dss_dir_t *dir);
status_t dss_create_file_impl(dss_conn_t *conn, const char *file_path, int flag);
status_t dss_remove_file_impl(dss_conn_t *conn, const char *file_path);
status_t dss_open_file_impl(dss_conn_t *conn, const char *file_path, int flag, int *handle);
status_t dss_close_file_impl(dss_conn_t *conn, int handle);
status_t dss_exist_file_impl(dss_conn_t *conn, const char *name, bool *result);
status_t dss_exist_dir_impl(dss_conn_t *conn, const char *name, bool *result);
status_t dss_islink_impl(dss_conn_t *conn, const char *name, bool *result);
int64 dss_seek_file_impl(dss_conn_t *conn, int handle, int64 offset, int origin);
status_t dss_write_file_impl(dss_conn_t *conn, int handle, const void *buf, int size);
status_t dss_read_file_impl(dss_conn_t *conn, int handle, void *buf, int size, int *read_size);
status_t dss_copy_file_impl(dss_conn_t *conn, const char *src, const char *dest);
status_t dss_rename_file_impl(dss_conn_t *conn, const char *src, const char *dst);
status_t dss_truncate_impl(dss_conn_t *conn, int handle, uint64 length);
status_t dss_add_volume_impl(dss_conn_t *conn, const char *vg_name, const char *volume_name);
status_t dss_remove_volume_impl(dss_conn_t *conn, const char *vg_name, const char *volume_name);
status_t dss_fstat_impl(dss_conn_t *conn, int handle, dss_stat_info_t item);
status_t dss_set_stat_info(dss_stat_info_t item, gft_node_t *node);

status_t dss_set_session_sync(dss_conn_t *conn);
status_t dss_init_vol_handle_sync(dss_conn_t *conn);

void dss_destroy_vol_handle_sync(dss_conn_t *conn);
status_t dss_get_home_sync(dss_conn_t *conn, char **home);
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
status_t dss_get_fd_by_offset(
    dss_conn_t *conn, int handle, long long offset, int32 size, bool32 is_read, int *fd, int64 *vol_offset);
status_t get_au_size_impl(dss_conn_t *conn, int handle, long long *au_size);
status_t dss_compare_size_equal_impl(const char *vg_name, long long *au_size);
status_t dss_setcfg_impl(dss_conn_t *conn, const char *name, const char *value, const char *scope);
status_t dss_getcfg_impl(dss_conn_t *conn, const char *name, char *out_str, size_t str_len);
status_t dss_stop_server_impl(dss_conn_t *conn);
void dss_get_api_volume_error(void);
status_t dss_get_phy_size_impl(dss_conn_t *conn, int handle, long long *size);
status_t dss_aio_post_pwrite_file_impl(dss_conn_t *conn, int handle, long long offset, int size);

#define DSS_SET_PTR_VALUE_IF_NOT_NULL(ptr, value) \
    do {                                          \
        if (ptr) {                                \
            (*(ptr) = (value));                   \
        }                                         \
    } while (0)

#ifdef __cplusplus
}
#endif

#endif  // __DSS_API_IMPL_H__
