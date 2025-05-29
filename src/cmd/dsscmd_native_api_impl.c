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
 * dsscmd_native_api_impl.c
 *   DSS client native API wrapper.
 *
 *
 * IDENTIFICATION
 *    src/cmd/dsscmd_native_api_impl.c
 *
 * -------------------------------------------------------------------------
 */

#include <dirent.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include "securec.h"
#include "dss_api.h"
#include "dss_errno.h"
#include "dss_defs.h"
#include "dsscmd_native_api.h"
#include "dsscmd_fs_api.h"

#define ALIGNOF_BUFFER 512
#define TYPEALIGN(ALIGNVAL, LEN) (((uintptr_t)(LEN) + ((ALIGNVAL) - 1)) & ~((uintptr_t)((ALIGNVAL) - 1)))
#define BUFFERALIGN(LEN) TYPEALIGN(ALIGNOF_BUFFER, (LEN))
#define INVALID_DEVICE_SIZE 0x7FFFFFFFFFFFFFFF

ssize_t buffer_align(char **unalign_buff, char **buff, size_t size);
ssize_t dss_align_read(int handle, void *buf, size_t size, off_t offset, bool use_p);

bool is_dss_file(const char *name)
{
    return (name[0] == '+') ? true : false;
}

bool is_dss_fd(int handle)
{
    if (handle >= (int)DSS_HANDLE_BASE) {
        return true;
    }

    return false;
}

int parse_errcode_from_errormsg(const char* errormsg)
{
    const char *errcode_str = strstr(errormsg, "errcode:");
    if (errcode_str) {
        errcode_str += strlen("errcode:");
        return atoi(errcode_str);
    }
    return ERR_DSS_PROCESS_REMOTE;
}

void native_set_errno(int *errcode, const char **errmsg)
{
    int errorcode = 0;
    const char *errormsg = NULL;

    dss_get_error(&errorcode, &errormsg);
    if (errorcode == ERR_DSS_PROCESS_REMOTE) {
        errno = parse_errcode_from_errormsg(errormsg);
    } else {
        errno = errorcode;
    }

    if (errcode != NULL) {
        *errcode = errorcode;
    }

    if (errmsg != NULL) {
        *errmsg = errormsg;
    }
}

int native_access_file(const char *file_name, int mode)
{
    struct stat statbuf = {0};
    return native_stat_file(file_name, &statbuf);
}

int native_create_dir(const char *name, mode_t mode)
{
    if (dss_dmake(name) != DSS_SUCCESS) {
        native_set_errno(NULL, NULL);
        return -1;
    }

    return 0;
}

int native_open_dir(const char *name, DIR **dir_handle)
{
    DSS_DIR *dss_dir = NULL;

    /* dss_dir_t will be free in dss_close_dir */
    dss_dir = (DSS_DIR*)malloc(sizeof(DSS_DIR));

    dss_dir->dir_handle = dss_dopen(name);
    if (dss_dir->dir_handle == NULL) {
        native_set_errno(NULL, NULL);
        free(dss_dir);
        return -1;
    }

    dss_dir->magic_head = DSS_MAGIC_NUMBER;
    *dir_handle = (DIR*)dss_dir;
    return 0;
}

int native_read_dir(DIR *dir_handle, struct dirent **result)
{
    dss_dirent_t dirent_t;
    dss_dir_item_t item_t;
    DSS_DIR *dss_dir = (DSS_DIR*)dir_handle;

    *result = NULL;

    if (dss_dread(dss_dir->dir_handle, &dirent_t, &item_t) != DSS_SUCCESS) {
        native_set_errno(NULL, NULL);
        return -1;
    }

    if (item_t == NULL) {
        native_set_errno(NULL, NULL);
        return 0;
    }

    if (strcpy_s(dss_dir->filename, MAX_FILE_NAME_LEN, dirent_t.d_name) != EOK) {
        return -1;
    }

    if (strcpy_s(dss_dir->ret.d_name, MAX_FILE_NAME_LEN, dirent_t.d_name) != EOK) {
        return -1;
    }

    *result = &dss_dir->ret;
    return 0;
}

int native_close_dir(DIR *dir_handle)
{
    DSS_DIR *dss_dir_t = (DSS_DIR*)dir_handle;
    int result = 0;

    if (dss_dclose(dss_dir_t->dir_handle) != DSS_SUCCESS) {
        native_set_errno(NULL, NULL);
        result = -1;
    }

    free(dss_dir_t);
    return result;
}

int native_remove_dir(const char *name)
{
    if (dss_dremove(name) != DSS_SUCCESS) {
        native_set_errno(NULL, NULL);
        return -1;
    }

    return 0;
}

int native_rename_file(const char *src, const char *dst)
{
    if (dss_frename(src, dst) != DSS_SUCCESS) {
        native_set_errno(NULL, NULL);
        return -1;
    }

    return 0;
}

int native_remove_file(const char *name)
{
    if (dss_fremove(name) != DSS_SUCCESS) {
        native_set_errno(NULL, NULL);
        return -1;
    }

    return 0;
}

int native_open_file(const char *name, int flags, mode_t mode, int *handle)
{
    if ((flags & O_CREAT) != 0 && dss_fcreate(name, flags) != DSS_SUCCESS) {
        native_set_errno(NULL, NULL);
        /* file already exists, ignore this error */
        if (errno != ERR_DSS_DIR_CREATE_DUPLICATED) {
            return -1;
        }
        errno = 0;
    }

    if (dss_fopen(name, flags, handle) != DSS_SUCCESS) {
        *handle = -1;
        native_set_errno(NULL, NULL);
        return -1;
    }

    return 0;
}

int native_close_file(int handle)
{
    if (dss_fclose(handle) != DSS_SUCCESS) {
        native_set_errno(NULL, NULL);
        return -1;
    }

    return 0;
}

ssize_t native_read_file(int handle, void *buf, size_t size)
{
    return dss_align_read(handle, buf, size, -1, false);
}

ssize_t native_pread_file(int handle, void *buf, size_t size, off_t offset)
{
    return dss_align_read(handle, buf, size, offset, true);
}

ssize_t dss_align_read(int handle, void *buf, size_t size, off_t offset, bool use_p)
{
    size_t newSize = size;
    char* unalign_buff = NULL;
    char* buff = NULL;
    bool address_align = false;
    int ret = DSS_ERROR;
    int r_size = 0;
    
    if ((((uint64)buf) % ALIGNOF_BUFFER) == 0) {
        address_align = true;
    }

    if ((!address_align) || ((size % ALIGNOF_BUFFER) != 0)) {
        newSize = buffer_align(&unalign_buff, &buff, size);
    } else {
        buff = (char*)buf;
    }

    if (use_p) {
        ret = dss_pread(handle, buff, (int)newSize, offset, &r_size);
    } else {
        ret = dss_fread(handle, buff, (int)newSize, &r_size);
    }

    if (ret != DSS_SUCCESS) {
        native_set_errno(NULL, NULL);

        if (unalign_buff != NULL) {
            free(unalign_buff);
        }
        return -1;
    }

    if (unalign_buff != NULL && size > 0) {
        int move = (int)size - (int)newSize;
        errno_t r = memcpy_s(buf, size, buff, size);
        free(unalign_buff);
        unalign_buff = NULL;
        if (r != EOK) {
            return -1;
        }
        // change current access position to correct point
        if (move < 0 && native_seek_file(handle, move, SEEK_CUR) < 0) {
            return -1;
        }
    }

    if (unalign_buff != NULL) {
        free(unalign_buff);
        unalign_buff = NULL;
    }

    return (((ssize_t)(r_size)) < ((ssize_t)(size)) ? ((ssize_t)(r_size)) : ((ssize_t)(size)));
}

ssize_t native_write_file(int handle, const void *buf, size_t size)
{
    if (dss_fwrite(handle, buf, (int)size) != DSS_SUCCESS) {
        native_set_errno(NULL, NULL);
        return -1;
    }

    return (ssize_t)size;
}

ssize_t native_pwrite_file(int handle, const void *buf, size_t size, off_t offset)
{
    if (dss_pwrite(handle, buf, (int)size, (long long)offset) != DSS_SUCCESS) {
        native_set_errno(NULL, NULL);
        return -1;
    }

    return (ssize_t)size;
}

off_t native_seek_file(int handle, off_t offset, int origin)
{
    off_t size = (off_t)dss_fseek(handle, offset, origin);
    if (size == -1) {
        native_set_errno(NULL, NULL);
    }

    return size;
}

int native_sync_file(int handle)
{
    /* nothing to do, because DSS will enable O_SYNC and O_DIRECT for all IO */
    return 0;
}

int native_truncate_file(int handle, off_t keep_size)
{
    /* not guarantee fill zero */
    if (dss_ftruncate(handle, keep_size) != DSS_SUCCESS) {
        native_set_errno(NULL, NULL);
        return -1;
    }

    return 0;
}

int native_get_file_name(int handle, char *fname, size_t fname_size)
{
    if (dss_get_fname(handle, fname, fname_size) != DSS_SUCCESS) {
        native_set_errno(NULL, NULL);
        return -1;
    }

    return 0;
}

off_t native_get_file_size(const char *fname)
{
    long long fsize = INVALID_DEVICE_SIZE;
    dss_fsize_maxwr(fname, &fsize);
    if (fsize == INVALID_DEVICE_SIZE) {
        native_set_errno(NULL, NULL);
    }

    return (off_t)fsize;
}

int native_fallocate_file(int handle, int mode, off_t offset, off_t len)
{
    return dss_fallocate(handle, mode, offset, len);
}

int native_link(const char *src, const char *dst)
{
    if (dss_symlink(src, dst) != DSS_SUCCESS) {
        native_set_errno(NULL, NULL);
        return -1;
    }

    return 0;
}

int native_unlink_target(const char *name)
{
    if (dss_unlink(name) != DSS_SUCCESS) {
        native_set_errno(NULL, NULL);
        return -1;
    }

    return 0;
}

ssize_t native_read_link(const char *path, char *buf, size_t buf_size)
{
    ssize_t result;
    result = (ssize_t)dss_readlink(path, buf, (int)buf_size);
    if (result == -1) {
        native_set_errno(NULL, NULL);
    }

    return result;
}

int native_stat_file(const char *path, struct stat *buf)
{
    dss_stat_t st;
    if (dss_stat(path, &st) != DSS_SUCCESS) {
        native_set_errno(NULL, NULL);
        return -1;
    }

    // file type and mode
    switch (st.type) {
        case DSS_PATH:
            buf->st_mode = S_IFDIR | 0600;
            buf->st_nlink = 2;
            break;
        case DSS_FILE:
            buf->st_mode = S_IFREG | 0600;
            buf->st_nlink = 1;
            break;
        case DSS_LINK:
        /* fall-through */
        default:
            return -1;
    }
    // total size, in bytes
    buf->st_size = (long)st.written_size;
    buf->st_blksize = DSS_BLOCK_SIZE;
    buf->st_blocks = (buf->st_size + DSS_BLOCK_SIZE - 1) / DSS_BLOCK_SIZE;
    // time of last modification
    buf->st_mtime = st.update_time;
    buf->st_uid = getuid();
    buf->st_gid = getgid();

    return 0;
}

int native_fstat_file(int handle, struct stat *buf)
{
    dss_stat_t st;
    if (dss_fstat(handle, &st) != DSS_SUCCESS) {
        native_set_errno(NULL, NULL);
        return -1;
    }

    // file type and mode
    switch (st.type) {
        case DSS_PATH:
            buf->st_mode = S_IFDIR;
            break;
        case DSS_FILE:
            buf->st_mode = S_IFREG;
            break;
        case DSS_LINK:
        /* fall-through */
        default:
            return -1;
    }
    // total size, in bytes
    buf->st_size = (long)st.written_size;
    // time of last modification
    buf->st_mtime = st.update_time;

    return 0;
}

// return information of link itself when path is link
int native_lstat_file(const char *path, struct stat *buf)
{
    dss_stat_t st;
    if (dss_lstat(path, &st) != DSS_SUCCESS) {
        native_set_errno(NULL, NULL);
        return -1;
    }

    // file type and mode
    switch (st.type) {
        case DSS_PATH:
            buf->st_mode = S_IFDIR;
            break;
        case DSS_FILE:
            buf->st_mode = S_IFREG;
            break;
        case DSS_LINK:
            buf->st_mode = S_IFLNK;
            break;
        default:
            return -1;
    }
    // total size, in bytes
    buf->st_size = (long)st.written_size;
    // time of last modification
    buf->st_mtime = st.update_time;

    return 0;
}

ssize_t buffer_align(char **unalign_buff, char **buff, size_t size)
{
    size_t newSize = size;
    size_t size_mod = ALIGNOF_BUFFER - (newSize % ALIGNOF_BUFFER);
    size_t size_move = 0;

    if ((size % ALIGNOF_BUFFER) != 0) {
        newSize = BUFFERALIGN(size);
        size_move += size_mod;
    }

    size_move += ALIGNOF_BUFFER;

    *unalign_buff = (char*)malloc(size + size_move);
    *buff = (char*)BUFFERALIGN(*unalign_buff);

    return (ssize_t)newSize;
}

int native_remove_dev(const char *name)
{
    struct stat st;
    int ret = lstat_dev(name, &st);
    if (ret == 0 && S_ISREG(st.st_mode)) {
        return native_remove_file(name);
    } else if (ret == 0 && S_ISLNK(st.st_mode)) {
        return native_unlink_target(name);
    } else {
        return 0;
    }
}