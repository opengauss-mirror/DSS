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
 * dsscmd_fs_api.h
 *   DSS client file system API wrapper.
 *
 *
 * IDENTIFICATION
 *    src/cmd/dsscmd_fs_api.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __DSSCMD_FS_API_H__
#define __DSSCMD_FS_API_H__

#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <stdio.h>
#include <unistd.h>
#include <pthread.h>
#include <securectype.h>
#include "string.h"
#include "cm_types.h"
#include "dss_api.h"
#include "dsscmd_native_api.h"

typedef struct st_DSS_DIR {
    uint64 magic_head;
    char filename[MAX_FILE_NAME_LEN];
    dss_dir_handle dir_handle;
    struct dirent ret; /* Used to return to caller */
} DSS_DIR;

static inline int rename_dev(const char *oldpath, const char *newpath)
{
    if (is_dss_file(oldpath)) {
        if (native_rename_file(oldpath, newpath) != 0) {
            return -1;
        }
        return 0;
    } else {
        return rename(oldpath, newpath);
    }
}

static inline int open_dev(const char *pathname, int flags, mode_t mode)
{
    int handle;
    if (is_dss_file(pathname)) {
        if (native_open_file(pathname, flags, mode, &handle) != 0) {
            return -1;
        }
        return handle;
    } else {
        return open(pathname, flags, mode);
    }
}

static inline int close_dev(int fd)
{
    if (is_dss_fd(fd)) {
        if (native_close_file(fd) != 0) {
            return -1;
        }
        return 0;
    } else {
        return close(fd);
    }
}

static inline ssize_t read_dev(int fd, void *buf, size_t count)
{
    ssize_t ret = 0;
    if (is_dss_fd(fd)) {
        ret = native_read_file(fd, buf, count);
    } else {
        ret = read(fd, buf, count);
    }
    return ret;
}

static inline ssize_t pread_dev(int fd, void *buf, size_t count, off_t offset)
{
    ssize_t ret = 0;
    if (is_dss_fd(fd)) {
        ret = native_pread_file(fd, buf, count, offset);
    } else {
        ret = pread(fd, buf, count, offset);
    }
    return ret;
}

static inline ssize_t write_dev(int fd, const void *buf, size_t count)
{
    ssize_t ret = 0;
    if (is_dss_fd(fd)) {
        ret = native_write_file(fd, buf, count);
    } else {
        ret = write(fd, buf, count);
    }
    return ret;
}

static inline ssize_t pwrite_dev(int fd, const void *buf, size_t count, off_t offset)
{
    ssize_t ret = 0;
    if (is_dss_fd(fd)) {
        ret = native_pwrite_file(fd, buf, count, offset);
    } else {
        ret = pwrite(fd, buf, count, offset);
    }
    return ret;
}

static inline off_t lseek_dev(int fd, off_t offset, int whence)
{
    if (is_dss_fd(fd)) {
        return native_seek_file(fd, offset, whence);
    } else {
        return lseek(fd, offset, whence);
    }
}

static inline int fsync_dev(int fd)
{
    if (is_dss_fd(fd)) {
        if (native_sync_file(fd) != 0) {
            return -1;
        }
        return 0;
    } else {
        return fsync(fd);
    }
}

static inline int fallocate_dev(int fd, int mode, off_t offset, off_t len)
{
    if (is_dss_fd(fd)) {
        if (native_fallocate_file(fd, mode, offset, len) != 0) {
            return -1;
        }
        return 0;
    } else {
        return fallocate(fd, mode, offset, len);
    }
}

static inline int access_dev(const char *pathname, int mode)
{
    if (is_dss_file(pathname)) {
        if (native_access_file(pathname, mode) != 0) {
            return -1;
        }
        return 0;
    } else {
        return access(pathname, mode);
    }
}

static inline int mkdir_dev(const char *pathname, mode_t mode)
{
    if (is_dss_file(pathname)) {
        if (native_create_dir(pathname, mode) != 0) {
            return -1;
        }
        return 0;
    } else {
        return mkdir(pathname, mode);
    }
}

static inline int rmdir_dev(const char *pathname)
{
    if (is_dss_file(pathname)) {
        if (native_remove_dir(pathname) != 0) {
            return -1;
        }
        return 0;
    } else {
        return rmdir(pathname);
    }
}

static inline int symlink_dev(const char *target, const char *linkpath)
{
    if (is_dss_file(target)) {
        if (native_link(target, linkpath) != 0) {
            return -1;
        }
        return 0;
    } else {
        return symlink(target, linkpath);
    }
}

static inline ssize_t readlink_dev(const char *pathname, char *buf, size_t bufsiz)
{
    if (is_dss_file(pathname)) {
        struct stat st;
        if (native_lstat_file(pathname, &st) != 0 || !S_ISLNK(st.st_mode)) {
            return -1;
        }

        return native_read_link(pathname, buf, bufsiz);
    } else {
        return readlink(pathname, buf, bufsiz);
    }
}

static inline int unlink_dev(const char *pathname)
{
    if (is_dss_file(pathname)) {
        if (native_remove_dev(pathname) != 0) {
            return -1;
        }
        return 0;
    } else {
        return unlink(pathname);
    }
}

static inline int lstat_dev(const char * pathname, struct stat * statbuf)
{
    if (is_dss_file(pathname)) {
        if (native_lstat_file(pathname, statbuf) != 0) {
            if (errno == ERR_DSS_FILE_NOT_EXIST) {
                errno = ENOENT;
            }
            return -1;
        }
        return 0;
    } else {
        return lstat(pathname, statbuf);
    }
}

static inline int stat_dev(const char *pathname, struct stat *statbuf)
{
    if (is_dss_file(pathname)) {
        if (native_stat_file(pathname, statbuf) != 0) {
            if (errno == ERR_DSS_FILE_NOT_EXIST) {
                errno = ENOENT;
            }
            return -1;
        }
        return 0;
    } else {
        return stat(pathname, statbuf);
    }
}

static inline int fstat_dev(int fd, struct stat *statbuf)
{
    if (is_dss_fd(fd)) {
        return native_fstat_file(fd, statbuf);
    } else {
        return fstat(fd, statbuf);
    }
}

static inline int remove_dev(const char *pathname)
{
    if (is_dss_file(pathname)) {
        if (native_remove_dev(pathname) != 0) {
            return -1;
        }
        return 0;
    } else {
        return remove(pathname);
    }
}

static inline int ftruncate_dev(int fd, off_t length)
{
    if (SECUREC_UNLIKELY(is_dss_fd(fd))) {
        return native_truncate_file(fd, length);
    } else {
        return ftruncate(fd, length);
    }
}

static inline DIR *opendir_dev(const char *name)
{
    if (SECUREC_UNLIKELY(is_dss_file(name))) {
        DIR *dir = NULL;
        if (native_open_dir(name, &dir) != 0) {
            return NULL;
        }
        return dir;
    } else {
        return opendir(name);
    }
}

static inline struct dirent *readdir_dev(DIR *dirp)
{
    DSS_DIR *dss_dir = (DSS_DIR *)dirp;

    if (dirp == NULL) {
        return NULL;
    }

    if (SECUREC_UNLIKELY(dss_dir->magic_head == DSS_MAGIC_NUMBER)) {
        struct dirent *de = NULL;
        (void)native_read_dir(dirp, &de);
        return de;
    } else {
        return readdir(dirp);
    }
}

static inline int closedir_dev(DIR *dirp)
{
    DSS_DIR *dss_dir = (DSS_DIR *)dirp;
    if (SECUREC_UNLIKELY(dss_dir->magic_head == DSS_MAGIC_NUMBER)) {
        if (native_close_dir(dirp) != 0) {
            return -1;
        }
        return 0;
    } else {
        return closedir(dirp);
    }
}

#endif // __DSSCMD_FS_API_H__