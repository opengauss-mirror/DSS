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
 * dss_api.c
 *
 *
 * IDENTIFICATION
 *    src/interface/dss_api.c
 *
 * -------------------------------------------------------------------------
 */

#include "dss_api.h"
#include "cm_types.h"
#include "cm_thread.h"
#include "dss_malloc.h"
#include "dss_api_impl.h"
#include "dss_thv.h"
#include "cm_log.h"
#include "cm_timer.h"

#ifdef _WIN64
#if !defined(__x86_64__)
#define __x86_64__
#endif
#elif defined _WIN32
#if !defined(__i386__)
#define __i386__
#endif
#endif

#ifdef WIN32
typedef struct {
    unsigned long sig[];
} sigset_t;
#endif
#include "libaio.h"
#ifndef WIN32
#include "config.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define HANDLE_VALUE(handle) ((handle) - (DSS_HANDLE_BASE))
#define DB_DSS_DEFAULT_UDS_PATH "UDS:/tmp/.dss_unix_d_socket"
/* A node is deleted only when it fails to be started for 5 consecutive times within 30 seconds.
   Therefore, the startup failure time cannot exceed 6 seconds. */
#define DSS_CONN_DEFAULT_TIME_OUT 3000
char g_dss_inst_path[CM_MAX_PATH_LEN] = {0};
typedef struct st_dss_conn_info {
    // protect connections
    latch_t conn_latch;
    uint32 conn_num;
    bool32 isinit;
    int32 timeout;  // - 1: never time out
} dss_conn_info_t;
static dss_conn_info_t g_dss_conn_info = {{0, 0, 0, 0, 0}, 0, CM_FALSE, DSS_CONN_DEFAULT_TIME_OUT};
status_t dss_conn_create(pointer_t *result);

static void dss_conn_release(pointer_t thv_addr)
{
    dss_conn_t *conn = (dss_conn_t *)thv_addr;
    if (conn->pipe.link.uds.closed != CM_TRUE) {
        dss_destroy_vol_handle_sync(conn);
        dss_disconnect(conn);
        cm_latch_x(&g_dss_conn_info.conn_latch, 1, NULL);
        g_dss_conn_info.conn_num--;
        if (g_dss_conn_info.conn_num == 0) {
            dss_destroy();
        }
        cm_unlatch(&g_dss_conn_info.conn_latch, NULL);
    }
    DSS_FREE_POINT(conn);
}

static char *dss_get_inst_path(void)
{
    if (g_dss_inst_path[0] != '\0') {
        return g_dss_inst_path;
    }
    return DB_DSS_DEFAULT_UDS_PATH;
}

static void dss_clt_env_init(void)
{
    if (g_dss_conn_info.isinit == CM_FALSE) {
        cm_latch_x(&g_dss_conn_info.conn_latch, 1, NULL);
        if (g_dss_conn_info.isinit == CM_FALSE) {
            status_t status = cm_launch_thv(GLOBAL_THV_OBJ0, NULL, dss_conn_create, dss_conn_release);
            if (status != CM_SUCCESS) {
                LOG_RUN_ERR("Dss client initialization failed.");
                cm_unlatch(&g_dss_conn_info.conn_latch, NULL);
                return;
            }
            g_dss_conn_info.isinit = CM_TRUE;
        }
        cm_unlatch(&g_dss_conn_info.conn_latch, NULL);
    }
}

static status_t dss_try_conn(dss_conn_opt_t *options, dss_conn_t *conn)
{
    // establish connection
    status_t status = CM_SUCCESS;
    cm_latch_x(&g_dss_conn_info.conn_latch, 1, NULL);
    do {
        // avoid buffer leak when disconnect
        dss_free_packet_buffer(&conn->pack);
        status = dss_connect(dss_get_inst_path(), options, conn);
        DSS_BREAK_IFERR2(status, LOG_RUN_ERR_INHIBIT(LOG_INHIBIT_LEVEL1, "Dss client connet server failed."));
        char *home = NULL;
        status = dss_get_home_sync(conn, &home);
        DSS_BREAK_IFERR3(status, LOG_RUN_ERR_INHIBIT(LOG_INHIBIT_LEVEL1, "Dss client get home from server failed."), dss_disconnect(conn));

        uint32 max_open_file = DSS_MAX_OPEN_FILES;
        status = dss_init(max_open_file, home);
        DSS_BREAK_IFERR3(status, LOG_RUN_ERR_INHIBIT(LOG_INHIBIT_LEVEL1, "Dss client init failed."), dss_disconnect(conn));

        status = dss_set_session_sync(conn);
        DSS_BREAK_IFERR3(status, LOG_RUN_ERR_INHIBIT(LOG_INHIBIT_LEVEL1, "Dss client failed to initialize session."), dss_disconnect(conn));

        status = dss_init_vol_handle_sync(conn);
        DSS_BREAK_IFERR3(status, LOG_RUN_ERR_INHIBIT(LOG_INHIBIT_LEVEL1, "Dss client init vol handle failed."), dss_disconnect(conn));

        g_dss_conn_info.conn_num++;
    } while (0);
    cm_unlatch(&g_dss_conn_info.conn_latch, NULL);
    return status;
}

status_t dss_conn_create(pointer_t *result)
{
    dss_conn_t *conn = (dss_conn_t *)cm_malloc(sizeof(dss_conn_t));
    if (conn == NULL) {
        DSS_THROW_ERROR(ERR_ALLOC_MEMORY, sizeof(dss_conn_t), "dss_conn_create");
        return CM_ERROR;
    }

    errno_t rc = memset_s(conn, sizeof(dss_conn_t), 0, sizeof(dss_conn_t));
    if (rc != EOK) {
        DSS_THROW_ERROR(ERR_SYSTEM_CALL, rc);
        DSS_FREE_POINT(conn);
        return CM_ERROR;
    }

    // init packet
    dss_init_packet(&conn->pack, conn->pipe.options);
    dss_conn_opt_t options = {.timeout = DSS_CONN_DEFAULT_TIME_OUT};
    if (dss_try_conn(&options, conn) != CM_SUCCESS) {
        DSS_THROW_ERROR(ERR_DSS_CONNECT_FAILED, cm_get_os_error(), strerror(cm_get_os_error()));
        DSS_FREE_POINT(conn);
        return CM_ERROR;
    }
#ifdef ENABLE_DSSTEST
    conn->conn_pid = getpid();
#endif
    *result = conn;
    return CM_SUCCESS;
}

static status_t dss_get_conn(dss_conn_t **conn)
{
    cm_reset_error();
    dss_clt_env_init();
    if (cm_get_thv(GLOBAL_THV_OBJ0, (pointer_t *)conn) != CM_SUCCESS) {
        return CM_ERROR;
    }

#ifdef ENABLE_DSSTEST
    if ((*conn)->flag && (*conn)->conn_pid != getpid()) {
        LOG_RUN_INF("Dss client need re-connect, last conn pid:%llu.", (uint64)(*conn)->conn_pid);
        dss_disconnect(*conn);
        if (dss_try_conn(NULL, *conn) != CM_SUCCESS) {
            LOG_RUN_ERR("[DSS API] ABORT INFO: dss server stoped, application need restart.");
            cm_fync_logfile();
            _exit(1);
        }
        (*conn)->conn_pid = getpid();
    }
#endif

    if ((*conn)->pipe.link.uds.closed) {
        LOG_RUN_ERR("[DSS API] ABORT INFO : dss server stoped, application need restart.");
        cm_fync_logfile();
        _exit(1);
    }
    return CM_SUCCESS;
}

int dss_dmake(const char *dir_name)
{
    dss_conn_t *conn = NULL;
    status_t ret = dss_get_conn(&conn);
    DSS_RETURN_IFERR2(ret, LOG_RUN_ERR("dmake get conn error."));

    text_t text;
    text_t sub;
    cm_str2text((char *)dir_name, &text);
    if (!cm_fetch_rtext(&text, '/', '\0', &sub)) {
        LOG_DEBUG_ERR("not a complete absolute path name(%s %s)", T2S(&sub), T2S(&text));
        return CM_ERROR;
    }

    char parent_str[DSS_FILE_PATH_MAX_LENGTH];
    char name_str[DSS_MAX_NAME_LEN];
    if (text.len >= DSS_MAX_NAME_LEN) {
        LOG_DEBUG_ERR("The length of dir name is more then the max length, name is (%s)", T2S(&text));
        return CM_ERROR;
    }
    if (sub.len >= DSS_FILE_PATH_MAX_LENGTH) {
        LOG_DEBUG_ERR("The length of path is more then the max length, path is (%s)", T2S(&sub));
        return CM_ERROR;
    }
    CM_RETURN_IFERR(cm_text2str(&sub, parent_str, sizeof(parent_str)));
    CM_RETURN_IFERR(cm_text2str(&text, name_str, sizeof(name_str)));

    ret = dss_make_dir_impl(conn, parent_str, name_str);
    dss_get_api_volume_error();
    return (int)ret;
}

int dss_dremove(const char *dir)
{
    dss_conn_t *conn = NULL;
    status_t ret = dss_get_conn(&conn);
    DSS_RETURN_IFERR2(ret, LOG_RUN_ERR("dremove get conn error."));

    ret = dss_remove_dir_impl(conn, dir, false);
    dss_get_api_volume_error();
    return (int)ret;
}

dss_dir_handle dss_dopen(const char *dir_path)
{
    dss_conn_t *conn = NULL;
    status_t ret = dss_get_conn(&conn);
    if (ret != CM_SUCCESS) {
        LOG_RUN_ERR("dopen get conn error.");
        return NULL;
    }
    dss_dir_t *dir = dss_open_dir_impl(conn, dir_path, CM_TRUE);
    dss_get_api_volume_error();
    return (dss_dir_handle)dir;
}

int dss_dread(dss_dir_handle dir, dss_dir_item_t item, dss_dir_item_t *result)
{
    if (item == NULL || result == NULL) {
        DSS_THROW_ERROR(ERR_DSS_INVALID_PARAM, "dss_dir_item_t");
        return DSS_ERROR;
    }
    *result = NULL;
    if (dir == NULL) {
        return DSS_SUCCESS;
    }
    dss_conn_t *conn = NULL;
    status_t ret = dss_get_conn(&conn);
    DSS_RETURN_IFERR2(ret, LOG_RUN_ERR("dread get conn error."));

    gft_node_t *node = dss_read_dir_impl(conn, (dss_dir_t *)dir, CM_TRUE);
    if (node == NULL) {
        return DSS_SUCCESS;
    }
    item->d_type = node->type;

    int32 errcode = memcpy_s(item->d_name, DSS_MAX_NAME_LEN, node->name, DSS_MAX_NAME_LEN);
    if (SECUREC_UNLIKELY(errcode != EOK)) {
        DSS_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
        return DSS_ERROR;
    }
    *result = item;
    return DSS_SUCCESS;
}

int dss_stat(const char *path, dss_stat_info_t item)
{
    if (item == NULL) {
        DSS_THROW_ERROR(ERR_DSS_INVALID_PARAM, "dss_stat_info_t");
        return DSS_ERROR;
    }
    dss_conn_t *conn = NULL;
    status_t status = dss_get_conn(&conn);
    DSS_RETURN_IFERR2(status, LOG_RUN_ERR("stat get conn error."));
    gft_node_t *node = dss_get_node_by_path_impl(conn, path);
    if (node == NULL) {
        return DSS_ERROR;
    }
    if (node->type == GFT_LINK) {
        char dst_path[DSS_FILE_PATH_MAX_LENGTH] = {0};
        if (dss_readlink_impl(conn, path, (char *)dst_path, sizeof(dst_path)) != CM_SUCCESS) {
            LOG_DEBUG_ERR("read link: %s error", path);
            return CM_ERROR;
        }
        node = dss_get_node_by_path_impl(conn, dst_path);
        if (node == NULL) {
            return DSS_ERROR;
        }
    }
    return dss_set_stat_info(item, node);
}

int dss_lstat(const char *path, dss_stat_info_t item)
{
    if (item == NULL) {
        DSS_THROW_ERROR(ERR_DSS_INVALID_PARAM, "dss_stat_info_t");
        return DSS_ERROR;
    }
    dss_conn_t *conn = NULL;
    status_t ret = dss_get_conn(&conn);
    DSS_RETURN_IFERR2(ret, LOG_RUN_ERR("lstat get conn error."));
    gft_node_t *node = dss_get_node_by_path_impl(conn, path);
    if (node == NULL) {
        LOG_DEBUG_INF("lstat get node by path :%s error", path);
        return DSS_ERROR;
    }
    return dss_set_stat_info(item, node);
}

int dss_fstat(int handle, dss_stat_info_t item)
{
    dss_conn_t *conn = NULL;
    if (item == NULL) {
        DSS_THROW_ERROR(ERR_DSS_INVALID_PARAM, "dss_stat_info_t");
        return DSS_ERROR;
    }
    status_t ret = dss_get_conn(&conn);
    DSS_RETURN_IFERR2(ret, LOG_RUN_ERR("fstat get conn error"));
    return dss_fstat_impl(conn, HANDLE_VALUE(handle), item);
}

int dss_dclose(dss_dir_handle dir)
{
    dss_conn_t *conn = NULL;
    status_t ret = dss_get_conn(&conn);
    DSS_RETURN_IFERR2(ret, LOG_RUN_ERR("dclose get conn error"));

    ret = dss_close_dir_impl(conn, (dss_dir_t *)dir);
    dss_get_api_volume_error();
    return (int)ret;
}

int dss_fcreate(const char *name, int flag)
{
    dss_conn_t *conn = NULL;
    status_t ret = dss_get_conn(&conn);
    DSS_RETURN_IFERR2(ret, LOG_RUN_ERR("fcreate get conn error"));

    ret = dss_create_file_impl(conn, name, flag);
    dss_get_api_volume_error();
    return (int)ret;
}

int dss_fremove(const char *file)
{
    dss_conn_t *conn = NULL;
    status_t ret = dss_get_conn(&conn);
    DSS_RETURN_IFERR2(ret, LOG_RUN_ERR("fremove get conn error"));

    ret = dss_remove_file_impl(conn, file);
    dss_get_api_volume_error();
    return (int)ret;
}

int dss_fopen(const char *file, int flag, int *handle)
{
    dss_conn_t *conn = NULL;
    status_t ret = dss_get_conn(&conn);
    DSS_RETURN_IFERR2(ret, LOG_RUN_ERR("fopen get conn error"));

    ret = dss_open_file_impl(conn, file, flag, handle);
    dss_get_api_volume_error();
    *handle += DSS_HANDLE_BASE;
    return (int)ret;
}

int dss_get_inst_status(dss_server_status_t *dss_status)
{
    dss_conn_t *conn = NULL;
    status_t ret = dss_get_conn(&conn);
    DSS_RETURN_IFERR2(ret, LOG_DEBUG_ERR("get conn error when get inst status"));
    return (int)dss_get_inst_status_on_server(conn, dss_status);
}

int dss_set_main_inst(void)
{
    dss_conn_t *conn = NULL;
    status_t ret = dss_get_conn(&conn);
    DSS_RETURN_IFERR2(ret, LOG_DEBUG_ERR("get conn error when set main inst"));
    return (int)dss_set_main_inst_on_server(conn);
}

int dss_fclose(int handle)
{
    dss_conn_t *conn = NULL;
    status_t ret = dss_get_conn(&conn);
    DSS_RETURN_IFERR2(ret, LOG_DEBUG_ERR("fclose get conn error"));

    ret = dss_close_file_impl(conn, HANDLE_VALUE(handle));
    dss_get_api_volume_error();
    return (int)ret;
}

int dss_symlink(const char *oldpath, const char *newpath)
{
    dss_conn_t *conn = NULL;
    status_t ret = dss_get_conn(&conn);
    DSS_RETURN_IFERR2(ret, LOG_RUN_ERR("symlink get conn error."));

    return (int)dss_symlink_impl(conn, oldpath, newpath);
}

int dss_readlink(const char *link_path, char *buf, int bufsize)
{
    if (bufsize <= 0) {
        DSS_THROW_ERROR(ERR_DSS_INVALID_PARAM, "invalid bufsize when get cfg");
        return DSS_ERROR;
    }

    dss_conn_t *conn = NULL;
    status_t ret = dss_get_conn(&conn);
    DSS_RETURN_IFERR2(ret, LOG_RUN_ERR("readlink get conn error."));

    bool32 is_link = false;
    CM_RETURN_IFERR(dss_islink_impl(conn, link_path, &is_link));
    if (!is_link) {
        DSS_THROW_ERROR(ERR_DSS_LINK_READ_NOT_LINK, link_path);
        return CM_ERROR;
    }

    if (dss_readlink_impl(conn, link_path, buf, bufsize) != CM_SUCCESS) {
        return CM_ERROR;
    }

    return (int)strlen(buf);
}

long long dss_fseek(int handle, long long offset, int origin)
{
    dss_conn_t *conn = NULL;
    status_t ret = dss_get_conn(&conn);
    DSS_RETURN_IFERR2(ret, LOG_RUN_ERR("fseek get conn error."));

    long long status = dss_seek_file_impl(conn, HANDLE_VALUE(handle), offset, origin);
    dss_get_api_volume_error();
    return status;
}

int dss_fwrite(int handle, const void *buf, int size)
{
    dss_conn_t *conn = NULL;
    status_t ret = dss_get_conn(&conn);
    DSS_RETURN_IFERR2(ret, LOG_RUN_ERR("fwrite get conn error"));

    ret = dss_write_file_impl(conn, HANDLE_VALUE(handle), buf, size);
    dss_get_api_volume_error();
    return (int)ret;
}

int dss_fread(int handle, void *buf, int size, int *read_size)
{
    dss_conn_t *conn = NULL;
    status_t ret = dss_get_conn(&conn);
    DSS_RETURN_IFERR2(ret, LOG_RUN_ERR("fread get conn error."));

    ret = dss_read_file_impl(conn, HANDLE_VALUE(handle), buf, size, read_size);
    dss_get_api_volume_error();
    return (int)ret;
}

int dss_pwrite(int handle, const void *buf, int size, long long offset)
{
    timeval_t begin_tv;
    dss_begin_stat(&begin_tv);
    if (size < 0) {
        LOG_DEBUG_ERR("File size is invalid:%d.", size);
        DSS_THROW_ERROR(ERR_DSS_INVALID_PARAM, "size must be a positive integer");
        return CM_ERROR;
    }
    if (offset > (int64)DSS_MAX_FILE_SIZE) {
        LOG_DEBUG_ERR("Invalid parameter offset:%lld.", offset);
        DSS_THROW_ERROR(ERR_DSS_INVALID_PARAM, "offset must less than DSS_MAX_FILE_SIZE");
        return CM_ERROR;
    }
    dss_conn_t *conn = NULL;
    status_t ret = dss_get_conn(&conn);
    DSS_RETURN_IFERR2(ret, LOG_RUN_ERR("pwrite get conn error."));

    ret = dss_pwrite_file_impl(conn, HANDLE_VALUE(handle), buf, size, offset);
    dss_get_api_volume_error();
    if (ret == CM_SUCCESS) {
        dss_end_stat(conn->session, &begin_tv, DSS_PWRITE);
    }

    return (int)ret;
}

int dss_pread(int handle, void *buf, int size, long long offset, int *read_size)
{
    timeval_t begin_tv;
    dss_begin_stat(&begin_tv);

    if (read_size == NULL) {
        DSS_THROW_ERROR(ERR_DSS_INVALID_PARAM, "read _size is NULL");
        return CM_ERROR;
    }
    if (size < 0) {
        LOG_DEBUG_ERR("File size is invalid:%d.", size);
        DSS_THROW_ERROR(ERR_DSS_INVALID_PARAM, "size must be a positive integer");
        return CM_ERROR;
    }
    if (offset > (int64)DSS_MAX_FILE_SIZE) {
        LOG_DEBUG_ERR("Invalid parameter offset:%lld.", offset);
        DSS_THROW_ERROR(ERR_DSS_INVALID_PARAM, "offset must less than DSS_MAX_FILE_SIZE");
        return CM_ERROR;
    }
    dss_conn_t *conn = NULL;
    status_t ret = dss_get_conn(&conn);
    DSS_RETURN_IFERR2(ret, LOG_RUN_ERR("pread get conn error."));

    ret = dss_pread_file_impl(conn, HANDLE_VALUE(handle), buf, size, offset, read_size);
    dss_get_api_volume_error();
    if (ret == CM_SUCCESS) {
        dss_end_stat(conn->session, &begin_tv, DSS_PREAD);
    }
    return (int)ret;
}

int dss_get_addr(int handle, long long offset, char *pool_name, char *image_name, char *obj_addr,
    unsigned int *obj_id, unsigned long int *obj_offset)
{
    dss_conn_t *conn = NULL;
    status_t ret = dss_get_conn(&conn);
    DSS_RETURN_IFERR2(ret, LOG_RUN_ERR("get conn error when get ceph address."));

    ret = dss_get_addr_impl(conn, HANDLE_VALUE(handle), offset, pool_name, image_name, obj_addr,
        obj_id, obj_offset);
    dss_get_api_volume_error();
    return (int)ret;
}


int dss_fcopy(const char *src_path, const char *dest_path)
{
    dss_conn_t *conn = NULL;
    status_t ret = dss_get_conn(&conn);
    DSS_RETURN_IFERR2(ret, LOG_RUN_ERR("fcopy get conn error."));

    ret = dss_copy_file_impl(conn, src_path, dest_path);
    dss_get_api_volume_error();
    return (int)ret;
}

int dss_frename(const char *src, const char *dst)
{
    dss_conn_t *conn = NULL;
    status_t ret = dss_get_conn(&conn);
    DSS_RETURN_IFERR2(ret, LOG_RUN_ERR("frename get conn error."));

    ret = dss_rename_file_impl(conn, src, dst);
    dss_get_api_volume_error();
    return (int)ret;
}

int dss_ftruncate(int handle, long long length)
{
    dss_conn_t *conn = NULL;
    status_t ret = dss_get_conn(&conn);
    DSS_RETURN_IFERR2(ret, LOG_RUN_ERR("ftruncate get conn error."));
    ret = dss_truncate_impl(conn, HANDLE_VALUE(handle), (uint64)length);
    dss_get_api_volume_error();
    return (int)ret;
}

int dss_unlink(const char *link)
{
    dss_conn_t *conn = NULL;
    status_t ret = dss_get_conn(&conn);
    DSS_RETURN_IFERR2(ret, LOG_RUN_ERR("unlink get conn error."));

    return (int)dss_unlink_impl(conn, link);
}

int dss_check_size(int size)
{
    if (size % (int)DSS_DEFAULT_AU_SIZE != 0) {
        DSS_THROW_ERROR(ERR_DSS_CHECK_SIZE, size, DSS_DEFAULT_AU_SIZE);
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

int dss_align_size(int size)
{
    return CM_ALIGN_ANY(size, (int)DSS_DEFAULT_AU_SIZE);
}

static void dss_fsize_with_options(const char *fname, long long *fsize, int origin)
{
    int32 handle;
    status_t status;
    *fsize = CM_INVALID_INT64;

    if (fname == NULL) {
        return;
    }

    dss_conn_t *conn = NULL;
    status_t ret = dss_get_conn(&conn);
    if (ret != CM_SUCCESS) {
        LOG_RUN_ERR("fszie with options get conn error.");
        return;
    }

    status = dss_open_file_impl(conn, fname, O_RDONLY, &handle);
    if (status != CM_SUCCESS) {
        LOG_DEBUG_ERR("Open file :%s failed.\n", fname);
        return;
    }

    *fsize = dss_seek_file_impl(conn, handle, 0, origin);
    if (*fsize == CM_INVALID_INT64) {
        LOG_DEBUG_ERR("Seek file :%s failed.\n", fname);
    }

    (void)dss_close_file_impl(conn, handle);
}

int dss_fsize_physical(int handle, long long *fsize)
{
    dss_conn_t *conn = NULL;
    status_t ret = dss_get_conn(&conn);
    DSS_RETURN_IFERR2(ret, LOG_RUN_ERR("get conn error."));

    return dss_get_phy_size_impl(conn, HANDLE_VALUE(handle), fsize);
}

void dss_fsize_maxwr(const char *fname, long long *fsize)
{
    dss_fsize_with_options(fname, fsize, DSS_SEEK_MAXWR);
}

void dss_get_error(int *errcode, const char **errmsg)
{
    cm_get_error(errcode, errmsg);

    if (*errcode == 0) {
        return;
    }

    if (*errcode < ERR_DSS_FLOOR || *errcode > ERR_DSS_CEIL) {
        LOG_DEBUG_ERR("dss_get_error failed, errcode: %d", *errcode);
        *errcode = -1;
        *errmsg = "Failed to get dss errcode";
    }
}

int dss_get_fname(int handle, char *fname, int fname_size)
{
    status_t ret = dss_get_fname_impl(HANDLE_VALUE(handle), fname, fname_size);
    dss_get_api_volume_error();
    return (int)ret;
}

int dss_set_svr_path(const char *conn_path)
{
    if (conn_path == NULL) {
        DSS_THROW_ERROR(ERR_DSS_INVALID_PARAM, "conn path");
        return DSS_ERROR;
    }

    size_t len = strlen(conn_path);
    if (len == 0) {
        DSS_THROW_ERROR(ERR_DSS_FILE_PATH_ILL, conn_path, ", conn path is empty");
        return DSS_ERROR;
    } else if (len > CM_MAX_PATH_LEN) {
        DSS_THROW_ERROR(ERR_DSS_FILE_PATH_ILL, conn_path, ", conn path is too long");
        return DSS_ERROR;
    }
    if (strcpy_s(g_dss_inst_path, CM_MAX_PATH_LEN, conn_path) != EOK) {
        DSS_THROW_ERROR(ERR_DSS_FILE_PATH_ILL, conn_path, ", conn path copy fail");
        return DSS_ERROR;
    }
    return DSS_SUCCESS;
}

void dss_register_log_callback(dss_log_output cb_log_output, unsigned int log_level)
{
    cm_log_param_instance()->log_write = (usr_cb_log_output_t)cb_log_output;
    cm_log_param_instance()->log_level = log_level;
}

void dss_set_log_level(unsigned int log_level)
{
    cm_log_param_instance()->log_level = log_level;
}

int dss_set_conn_timeout(int32 timeout)
{
    if (timeout < 0 && timeout != DSS_CONN_NEVER_TIMEOUT) {
        DSS_THROW_ERROR(ERR_DSS_INVALID_PARAM, "invalid timeout when set connection timeout");
        return CM_ERROR;
    }
    g_dss_conn_info.timeout = timeout;
    return CM_SUCCESS;
}

static int32 init_single_logger_core(log_param_t *log_param, log_type_t log_id, char *file_name, uint32 file_name_len)
{
    int32 ret;
    switch (log_id) {
        case LOG_RUN:
            ret = snprintf_s(file_name, file_name_len, CM_MAX_FILE_NAME_LEN, "%s/DSS/run/%s", log_param->log_home, "dss.rlog");
            break;
        case LOG_DEBUG:
            ret = snprintf_s(file_name, file_name_len, CM_MAX_FILE_NAME_LEN, "%s/DSS/debug/%s", log_param->log_home, "dss.dlog");
            break;
        case LOG_ALARM:
            ret = snprintf_s(file_name, file_name_len, CM_MAX_FILE_NAME_LEN, "%s/DSS/alarm/%s", log_param->log_home, "dss.alog");
            break;
        case LOG_AUDIT:
            ret = snprintf_s(file_name, file_name_len, CM_MAX_FILE_NAME_LEN, "%s/DSS/audit/%s", log_param->log_home, "dss.aud");
            break;
        default:
            ret = 0;
            break;
    }

    return (ret != -1) ? DSS_SUCCESS : ERR_DSS_INIT_LOGGER_FAILED;
}

static int32 init_single_logger(log_param_t *log_param, log_type_t log_id)
{
    char file_name[CM_FILE_NAME_BUFFER_SIZE] = {'\0'};
    CM_RETURN_IFERR(init_single_logger_core(log_param, log_id, file_name, CM_FILE_NAME_BUFFER_SIZE));
    (void)cm_log_init(log_id, (const char *)file_name);
    cm_log_open_compress(log_id, DSS_TRUE);
    return DSS_SUCCESS;
}

void dss_refresh_logger(char *log_field, unsigned long long *value)
{
    if (log_field ==NULL) {
        return;
    }

    if (strcmp(log_field, "LOG_LEVEL") == 0) {
        cm_log_param_instance()->log_level = (uint32)(*value);
    }
    else if (strcmp(log_field, "LOG_MAX_FILE_SIZE") == 0) {
        cm_log_param_instance()->max_log_file_size = (uint64)(*value);
        cm_log_param_instance()->max_audit_file_size = (uint64)(*value);
    }
    else if (strcmp(log_field, "LOG_BACKUP_FILE_COUNT") == 0) {
        cm_log_param_instance()->log_backup_file_count = (uint32)(*value);
        cm_log_param_instance()->audit_backup_file_count = (uint32)(*value);
    }
}

int32 dss_init_logger(char *log_home, unsigned int log_level, unsigned int log_backup_file_count, unsigned long long log_max_file_size)
{
    errno_t ret;
    log_param_t *log_param = cm_log_param_instance();
    ret = memset_s(log_param, sizeof(log_param_t), 0, sizeof(log_param_t));
    if (ret != EOK) {
        return ERR_DSS_INIT_LOGGER_FAILED;
    }

    log_param->log_level = log_level;
    log_param->log_backup_file_count = log_backup_file_count;
    log_param->audit_backup_file_count = log_backup_file_count;
    log_param->max_log_file_size = log_max_file_size;
    log_param->max_audit_file_size = log_max_file_size;
    log_param->log_compressed = DSS_TRUE;
    log_param->log_compress_buf = malloc(CM_LOG_COMPRESS_BUFSIZE);
    if (log_param->log_compress_buf == NULL) {
        return ERR_DSS_INIT_LOGGER_FAILED;
    }
    cm_log_set_file_permissions(600);
    cm_log_set_path_permissions(700);
    (void)cm_set_log_module_name("DSS", sizeof("DSS"));
    ret = strcpy_sp(log_param->instance_name, CM_MAX_NAME_LEN, "DSS");
    if (ret != EOK) {
        return ERR_DSS_INIT_LOGGER_FAILED;
    }

    ret = strcpy_sp(log_param->log_home, CM_MAX_LOG_HOME_LEN, log_home);
    if (ret != EOK) {
        return ERR_DSS_INIT_LOGGER_FAILED;
    }

    CM_RETURN_IFERR(init_single_logger(log_param, LOG_RUN));
    CM_RETURN_IFERR(init_single_logger(log_param, LOG_DEBUG));
    CM_RETURN_IFERR(init_single_logger(log_param, LOG_ALARM));
    CM_RETURN_IFERR(init_single_logger(log_param, LOG_AUDIT));

    if (cm_start_timer(g_timer()) != CM_SUCCESS) {
        return ERR_DSS_INIT_LOGGER_FAILED;
    }
    log_param->log_instance_startup = (bool32)CM_TRUE;

    return DSS_SUCCESS;
}

int dss_aio_prep_pread(void *iocb, int handle, void *buf, size_t count, long long offset)
{
    if (offset > (int64)DSS_MAX_FILE_SIZE) {
        LOG_DEBUG_ERR("Invalid parameter offset:%lld.", offset);
        DSS_THROW_ERROR(ERR_DSS_INVALID_PARAM, "offset must less than DSS_MAX_FILE_SIZE");
        return CM_ERROR;
    }
    dss_conn_t *conn = NULL;
    status_t ret = dss_get_conn(&conn);
    DSS_RETURN_IF_ERROR(ret);

    int dev_fd = DSS_INVALID_HANDLE;
    long long new_offset = 0;
    ret = dss_get_fd_by_offset(conn, HANDLE_VALUE(handle), offset, (int32)count, DSS_TRUE, &dev_fd, &new_offset);
    DSS_RETURN_IF_ERROR(ret);

    io_prep_pread(iocb, dev_fd, buf, count, new_offset);
    return CM_SUCCESS;
}

int dss_aio_prep_pwrite(void *iocb, int handle, void *buf, size_t count, long long offset)
{
    if (offset > (int64)DSS_MAX_FILE_SIZE) {
        LOG_DEBUG_ERR("Invalid parameter offset:%lld.", offset);
        DSS_THROW_ERROR(ERR_DSS_INVALID_PARAM, "offset must less than DSS_MAX_FILE_SIZE");
        return CM_ERROR;
    }
    dss_conn_t *conn = NULL;
    status_t ret = dss_get_conn(&conn);
    DSS_RETURN_IF_ERROR(ret);

    int dev_fd = DSS_INVALID_HANDLE;
    long long new_offset = 0;
    ret = dss_get_fd_by_offset(conn, HANDLE_VALUE(handle), offset, (int32)count, DSS_FALSE, &dev_fd, &new_offset);
    DSS_RETURN_IF_ERROR(ret);

    io_prep_pwrite(iocb, dev_fd, buf, count, new_offset);
    return CM_SUCCESS;
}

int dss_aio_post_pwrite(void *iocb, int handle, size_t count, long long offset)
{
    if (offset > (int64)DSS_MAX_FILE_SIZE) {
        LOG_DEBUG_ERR("Invalid parameter offset:%lld.", offset);
        DSS_THROW_ERROR(ERR_DSS_INVALID_PARAM, "offset must less than DSS_MAX_FILE_SIZE");
        return CM_ERROR;
    }

    dss_conn_t *conn = NULL;
    status_t ret = dss_get_conn(&conn);
    DSS_RETURN_IF_ERROR(ret);

    return (int)dss_aio_post_pwrite_file_impl(conn, HANDLE_VALUE(handle), offset, (int32)count);
}

int dss_get_au_size(int handle, long long *au_size)
{
    dss_conn_t *conn = NULL;
    status_t ret = dss_get_conn(&conn);
    DSS_RETURN_IF_ERROR(ret);

    return get_au_size_impl(conn, HANDLE_VALUE(handle), au_size);
}

int dss_compare_size_equal(const char *vg_name, long long *au_size)
{
    return dss_compare_size_equal_impl(vg_name, au_size);
}


int dss_setcfg(const char *name, const char *value, const char *scope)
{
    if (name == NULL || value == NULL) {
        DSS_THROW_ERROR(ERR_DSS_INVALID_PARAM, "invalid name or value when set cfg");
        return DSS_ERROR;
    }
    if (cm_strcmpi(name, "_LOG_LEVEL") != 0 && cm_strcmpi(name, "_LOG_MAX_FILE_SIZE") != 0 &&
        cm_strcmpi(name, "_LOG_BACKUP_FILE_COUNT") != 0 && cm_strcmpi(name, "_AUDIT_MAX_FILE_SIZE") != 0 &&
        cm_strcmpi(name, "_AUDIT_BACKUP_FILE_COUNT") != 0 && cm_strcmpi(name, "_AUDIT_LEVEL") != 0) {
        DSS_THROW_ERROR(ERR_DSS_INVALID_PARAM, "invalid name when set cfg");
        return DSS_ERROR;
    }

    char *tmp_scope = NULL;
    if (scope == NULL) {
        tmp_scope = (char *)"both";
    } else {
        tmp_scope = (char *)scope;
    }

    dss_conn_t *conn = NULL;
    status_t ret = dss_get_conn(&conn);
    DSS_RETURN_IF_ERROR(ret);

    return (int)dss_setcfg_impl(conn, name, value, tmp_scope);
}

int dss_getcfg(const char *name, char *value, int value_size)
{
    if (name == NULL) {
        DSS_THROW_ERROR(ERR_DSS_INVALID_PARAM, "invalid name when get cfg");
        return DSS_ERROR;
    }
    if (value_size <= 0) {
        DSS_THROW_ERROR(ERR_DSS_INVALID_PARAM, "invalid value_size when get cfg");
        return DSS_ERROR;
    }
    dss_conn_t *conn = NULL;
    status_t ret = dss_get_conn(&conn);
    DSS_RETURN_IFERR2(ret, LOG_RUN_ERR("getcfg get conn error."));

    return (int)dss_getcfg_impl(conn, name, value, (size_t)value_size);
}

int dss_get_lib_version(void)
{
    return DSS_LOCAL_MAJOR_VERSION * DSS_LOCAL_MAJOR_VER_WEIGHT + DSS_LOCAL_MINOR_VERSION * DSS_LOCAL_MINOR_VER_WEIGHT +
           DSS_LOCAL_VERSION;
}

#ifndef WIN32
void dss_show_version(char *version)
{
    if (snprintf_s(version, DSS_VERSION_MAX_LEN, DSS_VERSION_MAX_LEN - 1, "libdss.so %s", (char *)DEF_DSS_VERSION) ==
        -1) {
        cm_panic(0);
    }
}
#endif

#ifdef __cplusplus
}
#endif
