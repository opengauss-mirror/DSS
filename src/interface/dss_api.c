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
#include "cm_log.h"
#include "cm_timer.h"
#include "dss_cli_conn.h"

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


void dss_set_default_conn_timeout(int timeout)
{
    if (timeout <= 0) {
        g_dss_uds_conn_timeout = DSS_CONN_NEVER_TIMEOUT;
        return;
    }
    g_dss_uds_conn_timeout = timeout;
}


int dss_dmake_impl(dss_conn_t *conn, const char *dir_name)
{
    text_t text;
    text_t sub;
    cm_str2text((char *)dir_name, &text);
    if (!cm_fetch_rtext(&text, '/', '\0', &sub)) {
        DSS_THROW_ERROR_EX(ERR_DSS_DIR_CREATE, "Not a complete absolute path name(%s %s)", T2S(&sub), T2S(&text));
        return CM_ERROR;
    }

    char parent_str[DSS_FILE_PATH_MAX_LENGTH];
    char name_str[DSS_MAX_NAME_LEN];
    if (text.len >= DSS_MAX_NAME_LEN) {
        DSS_THROW_ERROR_EX(
            ERR_DSS_DIR_CREATE, "Length of dir name(%s) is too long, maximum is %u.", T2S(&text), DSS_MAX_NAME_LEN);
        return CM_ERROR;
    }
    if (sub.len >= DSS_FILE_PATH_MAX_LENGTH) {
        DSS_THROW_ERROR_EX(
            ERR_DSS_DIR_CREATE, "Length of path(%s) is too long, maximum is %u.", T2S(&sub), DSS_FILE_PATH_MAX_LENGTH);
        return CM_ERROR;
    }
    CM_RETURN_IFERR(cm_text2str(&sub, parent_str, sizeof(parent_str)));
    CM_RETURN_IFERR(cm_text2str(&text, name_str, sizeof(name_str)));
    int ret = dss_make_dir_impl(conn, parent_str, name_str);
    return ret;
}

int dss_dmake(const char *dir_name)
{
    dss_conn_t *conn = NULL;
    status_t ret = dss_enter_api(&conn);
    DSS_RETURN_IFERR2(ret, LOG_RUN_ERR("dmake get conn error."));
    ret = dss_dmake_impl(conn, dir_name);
    dss_leave_api(conn, CM_TRUE);
    return (int)ret;
}

int dss_dremove(const char *dir)
{
    dss_conn_t *conn = NULL;
    status_t ret = dss_enter_api(&conn);
    DSS_RETURN_IFERR2(ret, LOG_RUN_ERR("dremove get conn error."));
    ret = dss_remove_dir_impl(conn, dir, false);
    dss_leave_api(conn, CM_TRUE);
    return (int)ret;
}

dss_dir_handle dss_dopen(const char *dir_path)
{
    dss_conn_t *conn = NULL;
    status_t ret = dss_enter_api(&conn);
    if (ret != CM_SUCCESS) {
        LOG_RUN_ERR("dopen get conn error.");
        return NULL;
    }
    dss_dir_t *dir = dss_open_dir_impl(conn, dir_path, CM_TRUE);
    dss_leave_api(conn, CM_TRUE);
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
    status_t ret = dss_enter_api(&conn);
    DSS_RETURN_IFERR2(ret, LOG_RUN_ERR("dread get conn error."));

    gft_node_t *node = dss_read_dir_impl(conn, (dss_dir_t *)dir, CM_TRUE);
    dss_leave_api(conn, CM_FALSE);
    if (node == NULL) {
        return DSS_SUCCESS;
    }
    item->d_type = (dss_item_type_t)node->type;
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
    timeval_t begin_tv;
    dss_begin_stat(&begin_tv);
    dss_conn_t *conn = NULL;
    status_t status = dss_enter_api(&conn);
    DSS_RETURN_IFERR2(status, LOG_RUN_ERR("stat get conn error."));
    gft_node_t *node = dss_get_node_by_path_impl(conn, path);
    if (node == NULL) {
        dss_leave_api(conn, CM_FALSE);
        return DSS_ERROR;
    }
    if (node->type == GFT_LINK) {
        char dst_path[DSS_FILE_PATH_MAX_LENGTH] = {0};
        if (dss_readlink_impl(conn, path, (char *)dst_path, sizeof(dst_path)) != CM_SUCCESS) {
            LOG_DEBUG_ERR("read link: %s error", path);
            dss_leave_api(conn, CM_FALSE);
            return CM_ERROR;
        }
        node = dss_get_node_by_path_impl(conn, dst_path);
        if (node == NULL) {
            dss_leave_api(conn, CM_FALSE);
            return DSS_ERROR;
        }
    }
    int ret = dss_set_stat_info(item, node);
    dss_session_end_stat(conn->session, &begin_tv, DSS_STAT);
    dss_leave_api(conn, CM_FALSE);
    return ret;
}

int dss_lstat(const char *path, dss_stat_info_t item)
{
    if (item == NULL) {
        DSS_THROW_ERROR(ERR_DSS_INVALID_PARAM, "dss_stat_info_t");
        return DSS_ERROR;
    }
    dss_conn_t *conn = NULL;
    status_t ret = dss_enter_api(&conn);
    DSS_RETURN_IFERR2(ret, LOG_RUN_ERR("lstat get conn error."));
    gft_node_t *node = dss_get_node_by_path_impl(conn, path);
    dss_leave_api(conn, CM_FALSE);
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
    status_t ret = dss_enter_api(&conn);
    DSS_RETURN_IFERR2(ret, LOG_RUN_ERR("fstat get conn error"));
    ret = dss_fstat_impl(conn, HANDLE_VALUE(handle), item);
    dss_leave_api(conn, CM_FALSE);
    return (int)ret;
}

int dss_dclose(dss_dir_handle dir)
{
    dss_conn_t *conn = NULL;
    status_t ret = dss_enter_api(&conn);
    DSS_RETURN_IFERR2(ret, LOG_RUN_ERR("dclose get conn error"));
    ret = dss_close_dir_impl(conn, (dss_dir_t *)dir);
    dss_leave_api(conn, CM_TRUE);
    return (int)ret;
}

int dss_fcreate(const char *name, int flag)
{
    dss_conn_t *conn = NULL;
    status_t ret = dss_enter_api(&conn);
    DSS_RETURN_IFERR2(ret, LOG_RUN_ERR("fcreate get conn error"));
    ret = dss_create_file_impl(conn, name, flag);
    dss_leave_api(conn, CM_TRUE);
    return (int)ret;
}

int dss_fremove(const char *file)
{
    dss_conn_t *conn = NULL;
    status_t ret = dss_enter_api(&conn);
    DSS_RETURN_IFERR2(ret, LOG_RUN_ERR("fremove get conn error"));
    ret = dss_remove_file_impl(conn, file);
    dss_leave_api(conn, CM_TRUE);
    return (int)ret;
}

int dss_fopen(const char *file, int flag, int *handle)
{
    timeval_t begin_tv;
    *handle = -1;

    dss_begin_stat(&begin_tv);
    dss_conn_t *conn = NULL;
    status_t ret = dss_enter_api(&conn);
    DSS_RETURN_IFERR2(ret, LOG_RUN_ERR("fopen get conn error"));

    ret = dss_open_file_impl(conn, file, flag, handle);
    // if open fails, -1 is returned. DB determines based on -1
    if (ret == CM_SUCCESS) {
        *handle += DSS_HANDLE_BASE;
    }
    dss_session_end_stat(conn->session, &begin_tv, DSS_FOPEN);
    dss_leave_api(conn, CM_TRUE);
    return (int)ret;
}

int dss_get_inst_status(dss_server_status_t *dss_status)
{
    dss_conn_t *conn = NULL;
    status_t ret = dss_enter_api(&conn);
    DSS_RETURN_IFERR2(ret, LOG_DEBUG_ERR("get conn error when get inst status"));
    ret = dss_get_inst_status_on_server(conn, dss_status);
    dss_leave_api(conn, CM_FALSE);
    return (int)ret;
}

int dss_is_maintain(unsigned int *is_maintain)
{
    if (is_maintain == NULL) {
        DSS_THROW_ERROR(ERR_DSS_INVALID_PARAM, "expected is_maintain not a null pointer");
        return CM_ERROR;
    }
    dss_server_status_t dss_status = {0};
    status_t ret = dss_get_inst_status(&dss_status);
    DSS_RETURN_IFERR2(ret, LOG_DEBUG_ERR("get error when get inst status"));
    *is_maintain = dss_status.is_maintain;
    return CM_SUCCESS;
}

int dss_set_main_inst(void)
{
    dss_conn_t *conn = NULL;
    status_t ret = dss_enter_api(&conn);
    DSS_RETURN_IFERR2(ret, LOG_DEBUG_ERR("get conn error when set main inst"));
    ret = dss_set_main_inst_on_server(conn);
    dss_leave_api(conn, CM_FALSE);
    return (int)ret;
}

int dss_disable_grab_lock(void)
{
    dss_conn_t *conn = NULL;
    status_t ret = dss_enter_api(&conn);
    DSS_RETURN_IFERR2(ret, LOG_DEBUG_ERR("get conn error when disable grab lock"));
    ret = dss_disable_grab_lock_on_server(conn);
    dss_leave_api(conn, CM_FALSE);
    return (int)ret;
}

int dss_enable_grab_lock(void)
{
    dss_conn_t *conn = NULL;
    status_t ret = dss_enter_api(&conn);
    DSS_RETURN_IFERR2(ret, LOG_DEBUG_ERR("get conn error when enable grab lock"));
    ret = dss_enable_grab_lock_on_server(conn);
    dss_leave_api(conn, CM_FALSE);
    return (int)ret;
}

int dss_fclose(int handle)
{
    dss_conn_t *conn = NULL;
    status_t ret = dss_enter_api(&conn);
    DSS_RETURN_IFERR2(ret, LOG_DEBUG_ERR("fclose get conn error"));

    ret = dss_close_file_impl(conn, HANDLE_VALUE(handle));
    dss_leave_api(conn, CM_TRUE);
    return (int)ret;
}

int dss_symlink(const char *oldpath, const char *newpath)
{
    dss_conn_t *conn = NULL;
    status_t ret = dss_enter_api(&conn);
    DSS_RETURN_IFERR2(ret, LOG_RUN_ERR("symlink get conn error."));
    ret = dss_symlink_impl(conn, oldpath, newpath);
    dss_leave_api(conn, CM_FALSE);
    return (int)ret;
}

status_t dss_readlink_inner(dss_conn_t *conn, const char *link_path, char *buf, int bufsize)
{
    bool32 is_link = false;
    CM_RETURN_IFERR(dss_islink_impl(conn, link_path, &is_link));
    if (!is_link) {
        DSS_THROW_ERROR(ERR_DSS_LINK_READ_NOT_LINK, link_path);
        return CM_ERROR;
    }

    if (dss_readlink_impl(conn, link_path, buf, bufsize) != CM_SUCCESS) {
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

int dss_readlink(const char *link_path, char *buf, int bufsize)
{
    if (bufsize <= 0) {
        DSS_THROW_ERROR(ERR_DSS_INVALID_PARAM, "invalid bufsize when get cfg");
        return DSS_ERROR;
    }
    dss_conn_t *conn = NULL;
    status_t ret = dss_enter_api(&conn);
    DSS_RETURN_IFERR2(ret, LOG_RUN_ERR("readlink get conn error."));
    ret = dss_readlink_inner(conn, link_path, buf, bufsize);
    if (ret != CM_SUCCESS) {
        dss_leave_api(conn, CM_FALSE);
        return ret;
    }
    dss_leave_api(conn, CM_FALSE);
    return (int)strlen(buf);
}

long long dss_fseek(int handle, long long offset, int origin)
{
    dss_conn_t *conn = NULL;
    status_t ret = dss_enter_api(&conn);
    DSS_RETURN_IFERR2(ret, LOG_RUN_ERR("fseek get conn error."));

    long long status = dss_seek_file_impl(conn, HANDLE_VALUE(handle), offset, origin);
    dss_leave_api(conn, CM_TRUE);
    return status;
}

int dss_fwrite(int handle, const void *buf, int size)
{
    timeval_t begin_tv;
    dss_begin_stat(&begin_tv);
    dss_conn_t *conn = NULL;
    status_t ret = dss_enter_api(&conn);
    DSS_RETURN_IFERR2(ret, LOG_RUN_ERR("fwrite get conn error"));

    ret = dss_write_file_impl(conn, HANDLE_VALUE(handle), buf, size);
    if (ret == CM_SUCCESS) {
        dss_session_end_stat(conn->session, &begin_tv, DSS_FWRITE);
    }
    dss_leave_api(conn, CM_TRUE);
    return (int)ret;
}

int dss_append(int handle, const void *buf, int size)
{
    timeval_t begin_tv;
    dss_begin_stat(&begin_tv);
    dss_conn_t *conn = NULL;
    status_t ret = dss_enter_api(&conn);
    DSS_RETURN_IFERR2(ret, LOG_RUN_ERR("fwrite get conn error"));

    ret = dss_append_file_impl(conn, HANDLE_VALUE(handle), buf, size);
    if (ret == CM_SUCCESS) {
        dss_session_end_stat(conn->session, &begin_tv, DSS_FWRITE);
    }
    dss_leave_api(conn, CM_TRUE);
    return (int)ret;
}

int dss_fread(int handle, void *buf, int size, int *read_size)
{
    timeval_t begin_tv;
    dss_begin_stat(&begin_tv);
    dss_conn_t *conn = NULL;
    status_t ret = dss_enter_api(&conn);
    DSS_RETURN_IFERR2(ret, LOG_RUN_ERR("fread get conn error."));

    ret = dss_read_file_impl(conn, HANDLE_VALUE(handle), buf, size, read_size);
    if (ret == CM_SUCCESS) {
        dss_session_end_stat(conn->session, &begin_tv, DSS_FREAD);
    }
    dss_leave_api(conn, CM_TRUE);
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
    status_t ret = dss_enter_api(&conn);
    DSS_RETURN_IFERR2(ret, LOG_RUN_ERR("pwrite get conn error."));

    ret = dss_pwrite_file_impl(conn, HANDLE_VALUE(handle), buf, size, offset);
    if (ret == CM_SUCCESS) {
        dss_session_end_stat(conn->session, &begin_tv, DSS_PWRITE);
    }
    dss_leave_api(conn, CM_TRUE);
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
    status_t ret = dss_enter_api(&conn);
    DSS_RETURN_IFERR2(ret, LOG_RUN_ERR("pread get conn error."));

    ret = dss_pread_file_impl(conn, HANDLE_VALUE(handle), buf, size, offset, read_size);
    if (ret == CM_SUCCESS) {
        dss_session_end_stat(conn->session, &begin_tv, DSS_PREAD);
    }
    dss_leave_api(conn, CM_TRUE);
    return (int)ret;
}

int dss_get_addr(int handle, long long offset, char *pool_name, char *image_name, char *obj_addr, unsigned int *obj_id,
    unsigned long int *obj_offset)
{
    dss_conn_t *conn = NULL;
    status_t ret = dss_enter_api(&conn);
    DSS_RETURN_IFERR2(ret, LOG_RUN_ERR("get conn error when get ceph address."));
    ret = dss_get_addr_impl(conn, HANDLE_VALUE(handle), offset, pool_name, image_name, obj_addr, obj_id, obj_offset);
    dss_leave_api(conn, CM_TRUE);
    return (int)ret;
}

int dss_fcopy(const char *src_path, const char *dest_path)
{
    dss_conn_t *conn = NULL;
    status_t ret = dss_enter_api(&conn);
    DSS_RETURN_IFERR2(ret, LOG_RUN_ERR("fcopy get conn error."));

    ret = dss_copy_file_impl(conn, src_path, dest_path);
    dss_leave_api(conn, CM_TRUE);
    return (int)ret;
}

int dss_frename(const char *src, const char *dst)
{
    dss_conn_t *conn = NULL;
    status_t ret = dss_enter_api(&conn);
    DSS_RETURN_IFERR2(ret, LOG_RUN_ERR("frename get conn error."));

    ret = dss_rename_file_impl(conn, src, dst);
    dss_leave_api(conn, CM_TRUE);
    return (int)ret;
}

int dss_ftruncate(int handle, long long length)
{
    dss_conn_t *conn = NULL;
    status_t ret = dss_enter_api(&conn);
    DSS_RETURN_IFERR2(ret, LOG_RUN_ERR("ftruncate get conn error."));
    ret = dss_truncate_impl(conn, HANDLE_VALUE(handle), length);
    dss_leave_api(conn, CM_TRUE);
    return (int)ret;
}

int dss_unlink(const char *link)
{
    dss_conn_t *conn = NULL;
    status_t ret = dss_enter_api(&conn);
    DSS_RETURN_IFERR2(ret, LOG_RUN_ERR("unlink get conn error."));
    ret = dss_unlink_impl(conn, link);
    dss_leave_api(conn, CM_FALSE);
    return (int)ret;
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
    status_t ret = dss_enter_api(&conn);
    if (ret != CM_SUCCESS) {
        LOG_RUN_ERR("fszie with options get conn error.");
        return;
    }

    status = dss_open_file_impl(conn, fname, O_RDONLY, &handle);
    if (status != CM_SUCCESS) {
        LOG_DEBUG_ERR("Open file :%s failed.\n", fname);
        dss_leave_api(conn, CM_FALSE);
        return;
    }

    *fsize = dss_seek_file_impl(conn, handle, 0, origin);
    if (*fsize == CM_INVALID_INT64) {
        LOG_DEBUG_ERR("Seek file :%s failed.\n", fname);
        dss_leave_api(conn, CM_FALSE);
    }

    (void)dss_close_file_impl(conn, handle);
    dss_leave_api(conn, CM_FALSE);
}

int dss_fsize_physical(int handle, long long *fsize)
{
    dss_conn_t *conn = NULL;
    status_t ret = dss_enter_api(&conn);
    DSS_RETURN_IFERR2(ret, LOG_RUN_ERR("get conn error."));
    ret = dss_get_phy_size_impl(conn, HANDLE_VALUE(handle), fsize);
    dss_leave_api(conn, CM_FALSE);
    return (int)ret;
}

void dss_fsize_maxwr(const char *fname, long long *fsize)
{
    dss_fsize_with_options(fname, fsize, DSS_SEEK_MAXWR);
}

void dss_get_error(int *errcode, const char **errmsg)
{
    cm_get_error(errcode, errmsg);
}

int dss_get_fname(int handle, char *fname, int fname_size)
{
    status_t ret = dss_get_fname_impl(HANDLE_VALUE(handle), fname, fname_size);
    dss_get_api_volume_error();
    return (int)ret;
}

int dss_fallocate(int handle, int mode, long long offset, long long length)
{
    dss_conn_t *conn = NULL;
    status_t ret = dss_enter_api(&conn);
    DSS_RETURN_IFERR2(ret, LOG_RUN_ERR("fallocate get conn error."));
    ret = dss_fallocate_impl(conn, HANDLE_VALUE(handle), mode, offset, length);
    dss_leave_api(conn, CM_TRUE);

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
void dss_register_exit_callback(dss_exit_callback_t dss_exit_proc)
{
    regist_exit_proc((dss_exit_proc_t)dss_exit_proc);
}
void dss_set_log_level(unsigned int log_level)
{
    cm_log_param_instance()->log_level = log_level;
}

static int32 init_single_logger_core(log_param_t *log_param, log_type_t log_id, char *file_name, uint32 file_name_len)
{
    int32 ret;
    switch (log_id) {
        case LOG_RUN:
            ret = snprintf_s(
                file_name, file_name_len, CM_MAX_FILE_NAME_LEN, "%s/DSS/run/%s", log_param->log_home, "dss.rlog");
            break;
        case LOG_DEBUG:
            ret = snprintf_s(
                file_name, file_name_len, CM_MAX_FILE_NAME_LEN, "%s/DSS/debug/%s", log_param->log_home, "dss.dlog");
            break;
        case LOG_ALARM:
            ret = snprintf_s(
                file_name, file_name_len, CM_MAX_FILE_NAME_LEN, "%s/DSS/alarm/%s", log_param->log_home, "dss.alog");
            break;
        case LOG_AUDIT:
            ret = snprintf_s(
                file_name, file_name_len, CM_MAX_FILE_NAME_LEN, "%s/DSS/audit/%s", log_param->log_home, "dss.aud");
            break;
        case LOG_BLACKBOX:
            ret = snprintf_s(
                file_name, file_name_len, CM_MAX_FILE_NAME_LEN, "%s/DSS/blackbox/%s", log_param->log_home, "dss.blog");
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
    if (log_field == NULL) {
        return;
    }

    if (strcmp(log_field, "LOG_LEVEL") == 0) {
        cm_log_param_instance()->log_level = (uint32)(*value);
    } else if (strcmp(log_field, "LOG_MAX_FILE_SIZE") == 0) {
        cm_log_param_instance()->max_log_file_size = (uint64)(*value);
        cm_log_param_instance()->max_audit_file_size = (uint64)(*value);
    } else if (strcmp(log_field, "LOG_BACKUP_FILE_COUNT") == 0) {
        cm_log_param_instance()->log_backup_file_count = (uint32)(*value);
        cm_log_param_instance()->audit_backup_file_count = (uint32)(*value);
    }
}

int dss_init_logger(
    char *log_home, unsigned int log_level, unsigned int log_backup_file_count, unsigned long long log_max_file_size)
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
    if (log_param->log_compress_buf == NULL) {
        log_param->log_compress_buf = malloc(CM_LOG_COMPRESS_BUFSIZE);
        if (log_param->log_compress_buf == NULL) {
            return ERR_DSS_INIT_LOGGER_FAILED;
        }
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
    CM_RETURN_IFERR(init_single_logger(log_param, LOG_BLACKBOX));
    if (cm_start_timer(g_timer()) != CM_SUCCESS) {
        return ERR_DSS_INIT_LOGGER_FAILED;
    }
    log_param->log_instance_startup = (bool32)CM_TRUE;

    return DSS_SUCCESS;
}

int dss_set_conn_timeout(int32 timeout)
{
    if (timeout < 0 && timeout != DSS_CONN_NEVER_TIMEOUT) {
        DSS_THROW_ERROR(ERR_DSS_INVALID_PARAM, "invalid timeout when set connection timeout");
        return CM_ERROR;
    }
    g_dss_uds_conn_timeout = timeout;
    return CM_SUCCESS;
}

int dss_set_thread_conn_timeout(dss_conn_opt_t *thv_opts, int32 timeout)
{
    if (timeout < 0 && timeout != DSS_CONN_NEVER_TIMEOUT) {
        DSS_THROW_ERROR(ERR_DSS_INVALID_PARAM, "invalid timeout when set connection timeout");
        return CM_ERROR;
    }
    thv_opts->timeout = timeout;
    return CM_SUCCESS;
}

int dss_set_conn_opts(dss_conn_opt_key_e key, void *value)
{
    dss_clt_env_init();
    dss_conn_opt_t *thv_opts = NULL;
    if (cm_get_thv(GLOBAL_THV_OBJ1, CM_TRUE, (pointer_t *)&thv_opts) != CM_SUCCESS) {
        return CM_ERROR;
    }
    switch (key) {
        case DSS_CONN_OPT_TIME_OUT:
            return dss_set_thread_conn_timeout(thv_opts, *(int32 *)value);
        default:
            DSS_THROW_ERROR(ERR_DSS_INVALID_PARAM, "invalid key when set connection options");
            return CM_ERROR;
    }
}

int dss_aio_prep_pread(void *iocb, int handle, void *buf, size_t count, long long offset)
{
    if (offset > (int64)DSS_MAX_FILE_SIZE) {
        LOG_DEBUG_ERR("Invalid parameter offset:%lld.", offset);
        DSS_THROW_ERROR(ERR_DSS_INVALID_PARAM, "offset must less than DSS_MAX_FILE_SIZE");
        return CM_ERROR;
    }
    dss_conn_t *conn = NULL;
    status_t ret = dss_enter_api(&conn);
    DSS_RETURN_IF_ERROR(ret);

    int dev_fd = DSS_INVALID_HANDLE;
    long long new_offset = 0;
    int32 real_count = (int32)count;
    ret = dss_get_fd_by_offset(
        conn, HANDLE_VALUE(handle), offset, (int32)count, DSS_TRUE, &dev_fd, &new_offset, &real_count);
    if (ret != CM_SUCCESS) {
        dss_leave_api(conn, CM_FALSE);
        return CM_ERROR;
    }
    io_prep_pread(iocb, dev_fd, buf, (size_t)real_count, new_offset);
    dss_leave_api(conn, CM_FALSE);
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
    status_t ret = dss_enter_api(&conn);
    DSS_RETURN_IF_ERROR(ret);

    int dev_fd = DSS_INVALID_HANDLE;
    long long new_offset = 0;
    ret = dss_get_fd_by_offset(conn, HANDLE_VALUE(handle), offset, (int32)count, DSS_FALSE, &dev_fd, &new_offset, NULL);
    if (ret != CM_SUCCESS) {
        dss_leave_api(conn, CM_FALSE);
        return CM_ERROR;
    }
    io_prep_pwrite(iocb, dev_fd, buf, count, new_offset);
    dss_leave_api(conn, CM_FALSE);
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
    status_t ret = dss_enter_api(&conn);
    DSS_RETURN_IF_ERROR(ret);

    ret = dss_aio_post_pwrite_file_impl(conn, HANDLE_VALUE(handle), offset, (int32)count);
    dss_leave_api(conn, CM_FALSE);
    return (int)ret;
}

int dss_get_au_size(int handle, long long *au_size)
{
    dss_conn_t *conn = NULL;
    status_t ret = dss_enter_api(&conn);
    DSS_RETURN_IF_ERROR(ret);

    ret = get_au_size_impl(conn, HANDLE_VALUE(handle), au_size);
    dss_leave_api(conn, CM_FALSE);
    return (int)ret;
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
    status_t ret = dss_enter_api(&conn);
    DSS_RETURN_IF_ERROR(ret);

    ret = dss_setcfg_impl(conn, name, value, tmp_scope);
    dss_leave_api(conn, CM_FALSE);
    return (int)ret;
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
    status_t ret = dss_enter_api(&conn);
    DSS_RETURN_IFERR2(ret, LOG_RUN_ERR("getcfg get conn error."));

    ret = dss_getcfg_impl(conn, name, value, (size_t)value_size);
    dss_leave_api(conn, CM_FALSE);
    return (int)ret;
}

int dss_get_lib_version(void)
{
    return DSS_LOCAL_MAJOR_VERSION * DSS_LOCAL_MAJOR_VER_WEIGHT + DSS_LOCAL_MINOR_VERSION * DSS_LOCAL_MINOR_VER_WEIGHT +
           DSS_LOCAL_VERSION;
}

void dss_show_version(char *version)
{
#ifndef WIN32
    if (snprintf_s(version, DSS_VERSION_MAX_LEN, DSS_VERSION_MAX_LEN - 1, "libdss.so %s", (char *)DEF_DSS_VERSION) ==
        -1) {
        cm_panic(0);
    }
#endif
}

int dss_enable_upgrades(void)
{
    dss_conn_t *conn = NULL;
    status_t ret = dss_enter_api(&conn);
    DSS_RETURN_IFERR2(ret, LOG_DEBUG_ERR("get conn error when enable upgrades"));
    ret = dss_enable_upgrades_on_server(conn);
    dss_leave_api(conn, CM_FALSE);
    return (int)ret;
}

int dss_reopen_vg_handle(const char *name)
{
    status_t ret = CM_SUCCESS;
#ifdef OPENGAUSS
    dss_conn_t *conn = NULL;
    ret = dss_enter_api(&conn);
    DSS_RETURN_IFERR2(ret, LOG_DEBUG_ERR("refresh vg handle"));
    ret = dss_reopen_vg_handel_impl(conn, name);
    dss_leave_api(conn, CM_FALSE);
#endif
    return (int)ret;
}

#ifdef __cplusplus
}
#endif
