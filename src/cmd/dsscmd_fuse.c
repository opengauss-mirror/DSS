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
 * dsscmd_fuse.c
 *  DSS fuse file system implementation.
 *
 * IDENTIFICATION
 *    src/cmd/dsscmd_fuse.c
 *
 * -------------------------------------------------------------------------
 */

#ifndef WIN32
#include "stdio.h"
#include "errno.h"
#include "fcntl.h"
#include "string.h"
#include "time.h"
#include "utime.h"
#include "cm_error.h"
#include "cm_defs.h"
#include "cm_utils.h"
#include "dss_defs.h"
#include "dss_ctrl_def.h"
#include "dss_diskgroup.h"
#include "dsscmd_fs_api.h"

#define DSS_FUSE_PATH_MAX_SIZE 512

#define RET_ENAMETOOLONG (-ENAMETOOLONG)
#define RET_EPERM (-EPERM)
#define RET_EIO (-EIO)
#define RET_ENOENT (-ENOENT)

static time_t startup_time;

/* Compatibility stuff */
struct fuse2_file_info {
    int dummy1;
    unsigned long dummy2;
    int dummy3;
    unsigned int dummy4;
    uint64_t fh;
    uint64_t dummy5;
};

struct fuse3_file_info {
    int dummy1;
    unsigned int dummy2;
    unsigned int dummy3;
    uint64_t fh;
    uint64_t dummy4;
    uint32_t dummy5;
};

typedef int (*fuse2_fill_dir_t)(void *buf, const char *name, const struct stat *stbuf, off_t off);
enum fuse3_flags {
    DUMMY = 0,
};
typedef int (*fuse3_fill_dir_t)(
    void *buf, const char *name, const struct stat *stbuf, off_t off, enum fuse3_flags flags);

struct fuse2_operations {
    int (*getattr2)(const char *, struct stat *);
    void *dummy1[3];
    int (*mkdir2)(const char *, mode_t);
    int (*unlink2)(const char *);
    int (*rmdir2)(const char *);
    int (*symlink2)(const char *, const char *);
    int (*rename2)(const char *, const char *);
    void *dummy2[3];
    int (*truncate2)(const char *, off_t);
    void *dummy3[1];
    int (*open2)(const char *, struct fuse2_file_info *);
    int (*read2)(const char *, char *, size_t, off_t, struct fuse2_file_info *);
    int (*write2)(const char *, const char *, size_t, off_t, struct fuse2_file_info *);
    void *dummy4[2];
    int (*release2)(const char *, struct fuse2_file_info *);
    void *dummy5[5];
    int (*opendir2)(const char *, struct fuse2_file_info *);
    int (*readdir2)(const char *, void *, fuse2_fill_dir_t, off_t, struct fuse2_file_info *);
    int (*releasedir2)(const char *, struct fuse2_file_info *);
    void *dummy6[4];
    int (*create2)(const char *, mode_t, struct fuse2_file_info *);
    void *dummy7[3];
    int (*utimens2)(const char *, const struct timespec tv[2]);
    void *dummy8[1];
    int dummy9;
    void *dummy10[6];
};

struct fuse3_operations {
    int (*getattr3)(const char *, struct stat *, struct fuse3_file_info *fi);
    void *dummy1[2];
    int (*mkdir3)(const char *, mode_t);
    int (*unlink3)(const char *);
    int (*rmdir3)(const char *);
    int (*symlink3)(const char *, const char *);
    int (*rename3)(const char *, const char *, unsigned int flags);
    void *dummy2[3];
    int (*truncate3)(const char *, off_t, struct fuse3_file_info *fi);
    int (*open3)(const char *, struct fuse3_file_info *);
    int (*read3)(const char *, char *, size_t, off_t, struct fuse3_file_info *);
    int (*write3)(const char *, const char *, size_t, off_t, struct fuse3_file_info *);
    void *dummy3[2];
    int (*release3)(const char *, struct fuse3_file_info *);
    void *dummy4[5];
    int (*opendir3)(const char *, struct fuse3_file_info *);
    int (*readdir3)(const char *, void *, fuse3_fill_dir_t, off_t, struct fuse3_file_info *, enum fuse3_flags);
    int (*releasedir3)(const char *, struct fuse3_file_info *);
    void *dummy5[4];
    int (*create3)(const char *, mode_t, struct fuse3_file_info *);
    void *dummy6[1];
    int (*utimens3)(const char *, const struct timespec tv[2], struct fuse3_file_info *fi);
    void *dummy7[8];
};

bool32 convert_to_dss_path(const char *path, char *dss_path, int32 dss_path_size)
{
    if (strcpy_s(dss_path, (size_t)dss_path_size, path) != EOK) {
        return CM_FALSE;
    }
    dss_path[0] = '+';
    return CM_TRUE;
}

bool32 root_dir(const char *path)
{
    if (path[0] == '/' && path[1] == 0) {
        return CM_TRUE;
    }
    return CM_FALSE;
}

bool32 vg_dir(char *dss_path, dss_vg_info_t *vgs_info)
{
    for (uint32_t i = 0; i < vgs_info->group_num; i++) {
        // skip '+'
        if (strcmp(dss_path + 1, vgs_info->volume_group[i].vg_name) == 0) {
            return CM_TRUE;
        }
    }

    return CM_FALSE;
}

int my_create_common(const char *path, mode_t mode, uint64_t *fh)
{
    char dss_path[DSS_FUSE_PATH_MAX_SIZE];
    if (!convert_to_dss_path(path, dss_path, DSS_FUSE_PATH_MAX_SIZE)) {
        return RET_ENAMETOOLONG;
    }
    if (root_dir(path)) {
        return RET_EPERM;
    }
    int fd = open_dev(dss_path, O_CREAT | O_RDWR, mode);
    *fh = (uint64_t)fd;
    return (fd < 0) ? RET_EPERM : 0;
}

int my_create3(const char *path, mode_t mode, struct fuse3_file_info *file_info)
{
    return my_create_common(path, mode, &file_info->fh);
}

int my_create2(const char *path, mode_t mode, struct fuse2_file_info *file_info)
{
    return my_create_common(path, mode, &file_info->fh);
}

int my_release_common(const char *path, uint64_t *fh)
{
    if (close_dev((int)*fh) != 0) {
        return RET_EIO;
    }
    return 0;
}

int my_release3(const char *path, struct fuse3_file_info *file_info)
{
    return my_release_common(path, &file_info->fh);
}

int my_release2(const char *path, struct fuse2_file_info *file_info)
{
    return my_release_common(path, &file_info->fh);
}

int traverse_dir_size(char *dss_path, struct stat *stat_buf)
{
    int ret = 0;
    char child_path[DSS_FUSE_PATH_MAX_SIZE];
    DIR *dir = opendir_dev(dss_path);
    if (dir == NULL) {
        return RET_EIO;
    }

    struct dirent *entry = NULL;
    while ((entry = readdir_dev(dir)) != NULL) {
        struct stat child_stat = { 0 };
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        if (snprintf_s(child_path, DSS_FUSE_PATH_MAX_SIZE, DSS_FUSE_PATH_MAX_SIZE - 1,
            "%s/%s", dss_path, entry->d_name) == -1) {
            ret = RET_ENAMETOOLONG;
            break;
        }

        if (lstat_dev(child_path, &child_stat) != 0) {
            ret = RET_EIO;
            break;
        }

        if (S_ISDIR(child_stat.st_mode)) {
            if ((ret = traverse_dir_size(child_path, &child_stat)) != 0) {
                break;
            }
        }

        stat_buf->st_blksize = DSS_BLOCK_SIZE;
        stat_buf->st_blocks = stat_buf->st_blocks + child_stat.st_blocks;
    }

    (void)closedir_dev(dir);
    return ret;
}

int traverse_root_dir_size(dss_vg_info_t *vgs_info, struct stat *stat_buf)
{
    int ret = 0;
    char child_path[DSS_FUSE_PATH_MAX_SIZE];

    for (uint32 i = 0; i < vgs_info->group_num; i++) {
        if (snprintf_s(child_path, DSS_FUSE_PATH_MAX_SIZE, DSS_FUSE_PATH_MAX_SIZE - 1,
        "+%s", vgs_info->volume_group[i].vg_name) == -1) {
            ret = RET_ENAMETOOLONG;
            break;
        }

        ret = traverse_dir_size(child_path, stat_buf);
        if (ret != 0) {
            break;
        }
    }

    return ret;
}

int get_dir_links(char *dss_path, struct stat *stat_buf)
{
    int ret = 0;
    char child_path[DSS_FUSE_PATH_MAX_SIZE];
    DIR *dir = opendir_dev(dss_path);
    if (dir == NULL) {
        return RET_EIO;
    }

    stat_buf->st_nlink = 2;
    struct dirent *dent = NULL;
    while ((dent = readdir_dev(dir)) != NULL) {
        struct stat child_stat;
        if (strcmp(dent->d_name, ".") == 0 || strcmp(dent->d_name, "..") == 0) {
            continue;
        }

        if (strcpy_s(child_path, DSS_FUSE_PATH_MAX_SIZE, dss_path) != EOK) {
            ret = RET_ENAMETOOLONG;
            break;
        }

        if (strcat_s(child_path, DSS_FUSE_PATH_MAX_SIZE, "/") != EOK) {
            ret = RET_ENAMETOOLONG;
            break;
        }

        if (strcat_s(child_path, DSS_FUSE_PATH_MAX_SIZE, dent->d_name) != EOK) {
            ret = RET_ENAMETOOLONG;
            break;
        }

        if (lstat_dev(child_path, &child_stat) != 0) {
            ret = RET_EIO;
            break;
        }

        if (S_ISDIR(child_stat.st_mode)) {
            stat_buf->st_nlink++;
        }
    }

    (void)closedir_dev(dir);
    return ret;
}

int my_getattr_common(const char *path, struct stat *stat_buf)
{
    char dss_path[DSS_FUSE_PATH_MAX_SIZE];
    if (!convert_to_dss_path(path, dss_path, DSS_FUSE_PATH_MAX_SIZE)) {
        return RET_ENAMETOOLONG;
    }

    if (memset_s(stat_buf, sizeof(struct stat), 0, sizeof(struct stat)) != EOK) {
        return RET_EIO;
    }

    dss_vg_info_t *vgs_info = dss_get_vg_info_ptr();
    if (root_dir(path)) {
        stat_buf->st_mode = S_IFDIR | 0600;
        stat_buf->st_uid = getuid();
        stat_buf->st_gid = getgid();
        stat_buf->st_ctime = time(NULL);
        stat_buf->st_mtime = stat_buf->st_ctime;
        stat_buf->st_atime = stat_buf->st_ctime;
        stat_buf->st_nlink = 2 + vgs_info->group_num;
        return traverse_root_dir_size(vgs_info, stat_buf);
    } else {
        if (stat_dev(dss_path, stat_buf) != 0) {
            return (errno == ENOENT || errno == ERR_DSS_VG_NOT_EXIST) ? RET_ENOENT : 0;
        }

        if (S_ISDIR(stat_buf->st_mode)) {
            int ret = 0;
            if ((ret = get_dir_links(dss_path, stat_buf)) != 0) {
                return ret;
            }
            if ((ret = traverse_dir_size(dss_path, stat_buf)) != 0) {
                return ret;
            }
        } else {
            stat_buf->st_nlink = 1;
        }

        if (vg_dir(dss_path, vgs_info)) {
            stat_buf->st_ctime = startup_time;
            stat_buf->st_mtime = startup_time;
            stat_buf->st_atime = startup_time;
        }
        return 0;
    }
}

int my_getattr3(const char *path, struct stat *stat_buf, struct fuse3_file_info *fi)
{
    return my_getattr_common(path, stat_buf);
}

int my_getattr2(const char *path, struct stat *stat_buf)
{
    return my_getattr_common(path, stat_buf);
}

int my_utimens3(const char *path, const struct timespec tv[2], struct fuse3_file_info *fi)
{
    return 0;
}

int my_utimens2(const char *path, const struct timespec tv[2])
{
    return 0;
}

int my_open_common(const char *path, uint64_t *fh)
{
    char dss_path[DSS_FUSE_PATH_MAX_SIZE];
    if (!convert_to_dss_path(path, dss_path, DSS_FUSE_PATH_MAX_SIZE)) {
        return RET_ENAMETOOLONG;
    }
    int fd = open_dev(dss_path, O_RDWR, 0);
    *fh = (uint64_t)fd;
    return (fd < 0) ? RET_ENOENT : 0;
}

int my_open3(const char *path, struct fuse3_file_info *file_info)
{
    return my_open_common(path, &file_info->fh);
}

int my_open2(const char *path, struct fuse2_file_info *file_info)
{
    return my_open_common(path, &file_info->fh);
}

int my_read_common(const char *path, char *buf, size_t size, off_t offset, uint64_t *fh)
{
    char dss_path[DSS_FUSE_PATH_MAX_SIZE];
    if (!convert_to_dss_path(path, dss_path, DSS_FUSE_PATH_MAX_SIZE)) {
        return RET_ENAMETOOLONG;
    }
    int fd = (int)(*fh);
    int ret = (int)pread_dev(fd, buf, size, offset);
    if (ret < 0) {
        return RET_EIO;
    }
    return ret;
}

int my_read3(const char *path, char *buf, size_t size, off_t offset, struct fuse3_file_info *file_info)
{
    return my_read_common(path, buf, size, offset, &file_info->fh);
}

int my_read2(const char *path, char *buf, size_t size, off_t offset, struct fuse2_file_info *file_info)
{
    return my_read_common(path, buf, size, offset, &file_info->fh);
}

int aligned_write(int fd, const char *buf, size_t size, off_t offset)
{
    if (((uintptr_t)buf) % DSS_ALIGN_SIZE == 0 && (int64)size % (int64)DSS_ALIGN_SIZE == 0 &&
        (int64)offset % (int64)DSS_ALIGN_SIZE == 0) {
        return (int)pwrite_dev(fd, buf, size, offset);
    }

    off_t start = offset;
    off_t end = offset + size;
    off_t new_start = (start % (off_t)DSS_ALIGN_SIZE == 0) ? (start) : (start - start % (off_t)DSS_ALIGN_SIZE);
    off_t new_end =
        (end % (off_t)DSS_ALIGN_SIZE == 0) ? (end) : (end + (off_t)DSS_ALIGN_SIZE - end % (off_t)DSS_ALIGN_SIZE);
    size_t new_size = (size_t)new_end - (size_t)new_start;
    char *real_buf = (char *)malloc(new_size + DSS_ALIGN_SIZE);
    if (real_buf == NULL) {
        return -1;
    }
    char *align_buf = (char *)real_buf + (DSS_ALIGN_SIZE - ((uintptr_t)real_buf) % DSS_ALIGN_SIZE);
    if (start != new_start || end != new_end) {
        if (memset_s(align_buf, new_size, 0, new_size) != EOK) {
            free(real_buf);
            return -1;
        }
        if (pread_dev(fd, align_buf, new_size, new_start) < 0) {
            free(real_buf);
            return -1;
        }
    }
    if (memcpy_s(align_buf + offset - new_start, size, buf, size) != EOK) {
        free(real_buf);
        return -1;
    }
    int ret = pwrite_dev(fd, align_buf, new_size, new_start);
    free(real_buf);
    return (ret > (int)size) ? (int)size : ret;
}

int my_write_common(const char *path, const char *buf, size_t size, off_t offset, uint64_t *fh)
{
    char dss_path[DSS_FUSE_PATH_MAX_SIZE];
    if (!convert_to_dss_path(path, dss_path, DSS_FUSE_PATH_MAX_SIZE)) {
        return RET_ENAMETOOLONG;
    }
    int fd = (int)(*fh);
    int ret = (int)aligned_write(fd, buf, size, offset);
    if (ret < 0) {
        return RET_EIO;
    }
    return ret;
}

int my_write3(const char *path, const char *buf, size_t size, off_t offset, struct fuse3_file_info *file_info)
{
    return my_write_common(path, buf, size, offset, &file_info->fh);
}

int my_write2(const char *path, const char *buf, size_t size, off_t offset, struct fuse2_file_info *file_info)
{
    return my_write_common(path, buf, size, offset, &file_info->fh);
}

int my_truncate_common(const char *path, off_t length)
{
    char dss_path[DSS_FUSE_PATH_MAX_SIZE];
    if (!convert_to_dss_path(path, dss_path, DSS_FUSE_PATH_MAX_SIZE)) {
        return RET_ENAMETOOLONG;
    }
    int32 fd = open_dev(dss_path, O_RDWR, 0);
    if (fd == -1) {
        return RET_ENOENT;
    }

    int32 ret = ftruncate_dev(fd, length);
    (void)close_dev(fd);
    return (ret == 0) ? 0 : RET_EIO;
}

int my_truncate3(const char *path, off_t length, struct fuse3_file_info *fi)
{
    return my_truncate_common(path, length);
}

int my_truncate2(const char *path, off_t length)
{
    return my_truncate_common(path, length);
}

int my_rename_common(const char *oldpath, const char *newpath)
{
    char dss_oldpath[DSS_FUSE_PATH_MAX_SIZE];
    char dss_newpath[DSS_FUSE_PATH_MAX_SIZE];
    if (!convert_to_dss_path(oldpath, dss_oldpath, DSS_FUSE_PATH_MAX_SIZE)) {
        return RET_ENAMETOOLONG;
    }
    if (!convert_to_dss_path(newpath, dss_newpath, DSS_FUSE_PATH_MAX_SIZE)) {
        return RET_ENAMETOOLONG;
    }
    int ret = rename_dev(dss_oldpath, dss_newpath);
    return (ret == 0) ? 0 : RET_EIO;
}

int my_rename3(const char *oldpath, const char *newpath, unsigned int flags)
{
    return my_rename_common(oldpath, newpath);
}

int my_rename2(const char *oldpath, const char *newpath)
{
    return my_rename_common(oldpath, newpath);
}

int my_symlink(const char *target, const char *linkpath)
{
    char dss_target[DSS_FUSE_PATH_MAX_SIZE];
    char dss_linkpath[DSS_FUSE_PATH_MAX_SIZE];
    if (!convert_to_dss_path(target, dss_target, DSS_FUSE_PATH_MAX_SIZE)) {
        return RET_ENAMETOOLONG;
    }
    if (!convert_to_dss_path(linkpath, dss_linkpath, DSS_FUSE_PATH_MAX_SIZE)) {
        return RET_ENAMETOOLONG;
    }
    int ret = symlink_dev(dss_target, dss_linkpath);
    return (ret == 0) ? 0 : RET_EIO;
}

int my_unlink(const char *path)
{
    char dss_path[DSS_FUSE_PATH_MAX_SIZE];
    if (!convert_to_dss_path(path, dss_path, DSS_FUSE_PATH_MAX_SIZE)) {
        return RET_ENAMETOOLONG;
    }
    int ret = unlink_dev(dss_path);
    return (ret == 0) ? 0 : RET_EIO;
}

int my_mkdir(const char *pathname, mode_t mode)
{
    char dss_path[DSS_FUSE_PATH_MAX_SIZE];
    if (!convert_to_dss_path(pathname, dss_path, DSS_FUSE_PATH_MAX_SIZE)) {
        return RET_ENAMETOOLONG;
    }
    int ret = mkdir_dev(dss_path, mode);
    return (ret == 0) ? 0 : RET_EPERM;
}

int my_rmdir(const char *pathname)
{
    char dss_path[DSS_FUSE_PATH_MAX_SIZE];
    if (!convert_to_dss_path(pathname, dss_path, DSS_FUSE_PATH_MAX_SIZE)) {
        return RET_ENAMETOOLONG;
    }
    int ret = rmdir_dev(dss_path);
    return (ret == 0) ? 0 : RET_EIO;
}

int my_opendir_common(const char *path, uint64_t *fh)
{
    char dss_path[DSS_FUSE_PATH_MAX_SIZE];
    if (!convert_to_dss_path(path, dss_path, DSS_FUSE_PATH_MAX_SIZE)) {
        return RET_ENAMETOOLONG;
    }

    *fh = 0;
    if (root_dir(path)) {
        return 0;
    }

    DIR *dir = opendir_dev(dss_path);
    if (dir == NULL) {
        return RET_ENOENT;
    }

    *fh = (uint64_t)dir;
    return 0;
}

int my_opendir3(const char *path, struct fuse3_file_info *file_info)
{
    return my_opendir_common(path, &file_info->fh);
}

int my_opendir2(const char *path, struct fuse2_file_info *file_info)
{
    return my_opendir_common(path, &file_info->fh);
}

void read_root_dir3(void *buf, fuse3_fill_dir_t filler)
{
    filler(buf, ".", NULL, 0, 0);
    filler(buf, "..", NULL, 0, 0);

    char dss_path[DSS_FUSE_PATH_MAX_SIZE];
    dss_vg_info_t *vgs_info = dss_get_vg_info_ptr();
    for (uint32_t i = 0; i < vgs_info->group_num; i++) {
        if (strcpy_s(dss_path, DSS_FUSE_PATH_MAX_SIZE, vgs_info->volume_group[i].vg_name) == EOK) {
            filler(buf, dss_path, NULL, 0, 0);
        }
    }
}

int my_readdir3(const char *path, void *buf, fuse3_fill_dir_t filler, off_t offset, struct fuse3_file_info *file_info,
    enum fuse3_flags flags)
{
    if (root_dir(path)) {
        read_root_dir3(buf, filler);
        return 0;
    }

    filler(buf, ".", NULL, 0, 0);
    filler(buf, "..", NULL, 0, 0);

    char dss_path[DSS_FUSE_PATH_MAX_SIZE];
    if (!convert_to_dss_path(path, dss_path, DSS_FUSE_PATH_MAX_SIZE)) {
        return RET_ENAMETOOLONG;
    }
    DIR *dirp = (DIR *)file_info->fh;
    struct dirent *entry = NULL;
    while ((entry = readdir_dev(dirp)) != NULL) {
        filler(buf, entry->d_name, NULL, 0, 0);
    }

    return 0;
}

void read_root_dir2(void *buf, fuse2_fill_dir_t filler)
{
    filler(buf, ".", NULL, 0);
    filler(buf, "..", NULL, 0);

    char dss_path[DSS_FUSE_PATH_MAX_SIZE];
    dss_vg_info_t *vgs_info = dss_get_vg_info_ptr();
    for (uint32_t i = 0; i < vgs_info->group_num; i++) {
        if (strcpy_s(dss_path, DSS_FUSE_PATH_MAX_SIZE, vgs_info->volume_group[i].vg_name) == EOK) {
            filler(buf, dss_path, NULL, 0);
        }
    }
}

int my_readdir2(const char *path, void *buf, fuse2_fill_dir_t filler, off_t offset, struct fuse2_file_info *file_info)
{
    if (root_dir(path)) {
        read_root_dir2(buf, filler);
        return 0;
    }

    filler(buf, ".", NULL, 0);
    filler(buf, "..", NULL, 0);

    char dss_path[DSS_FUSE_PATH_MAX_SIZE];
    if (!convert_to_dss_path(path, dss_path, DSS_FUSE_PATH_MAX_SIZE)) {
        return RET_ENAMETOOLONG;
    }
    DIR *dirp = (DIR *)file_info->fh;
    struct dirent *entry = NULL;
    while ((entry = readdir_dev(dirp)) != NULL) {
        filler(buf, entry->d_name, NULL, 0);
    }

    return 0;
}

int my_releasedir_common(const char *path, uint64_t *fh)
{
    if (root_dir(path)) {
        return 0;
    }

    DIR *dirp = (DIR *)(*fh);
    if (dirp != NULL) {
        (void)closedir_dev(dirp);
    }
    return 0;
}

int my_releasedir3(const char *path, struct fuse3_file_info *file_info)
{
    return my_releasedir_common(path, &file_info->fh);
}

int my_releasedir2(const char *path, struct fuse2_file_info *file_info)
{
    return my_releasedir_common(path, &file_info->fh);
}

static struct fuse3_operations my_opers3 = {.create3 = my_create3,
    .release3 = my_release3,
    .getattr3 = my_getattr3,
    .utimens3 = my_utimens3,
    .open3 = my_open3,
    .read3 = my_read3,
    .write3 = my_write3,
    .truncate3 = my_truncate3,
    .rename3 = my_rename3,
    .symlink3 = my_symlink,
    .unlink3 = my_unlink,
    .mkdir3 = my_mkdir,
    .rmdir3 = my_rmdir,
    .opendir3 = my_opendir3,
    .readdir3 = my_readdir3,
    .releasedir3 = my_releasedir3};

static struct fuse2_operations my_opers2 = {.create2 = my_create2,
    .release2 = my_release2,
    .getattr2 = my_getattr2,
    .utimens2 = my_utimens2,
    .open2 = my_open2,
    .read2 = my_read2,
    .write2 = my_write2,
    .truncate2 = my_truncate2,
    .rename2 = my_rename2,
    .symlink2 = my_symlink,
    .unlink2 = my_unlink,
    .mkdir2 = my_mkdir,
    .rmdir2 = my_rmdir,
    .opendir2 = my_opendir2,
    .readdir2 = my_readdir2,
    .releasedir2 = my_releasedir2};

typedef int (*dss_fuse2_main_real_t)(
    int argc, char *argv[], const struct fuse2_operations *op, size_t op_size, void *user_data);

typedef int (*dss_fuse3_main_real_t)(
    int argc, char *argv[], const struct fuse3_operations *op, size_t op_size, void *user_data);

typedef struct st_dss_fuse_lib {
    int version;
    void *fuse_handle;
    dss_fuse2_main_real_t dss_fuse2_main_real;
    dss_fuse3_main_real_t dss_fuse3_main_real;
} dss_fuse_lib_t;

#define FUSE_3 3
#define FUSE_2 2
#define DSS_FUSE_ARGS_NUM 4
#define FUSE_ARG_0 0
#define FUSE_ARG_1 1
#define FUSE_ARG_2 2
#define FUSE_ARG_3 3
int my_fuse_main(const char *mount_dir)
{
    int ret = 0;
    startup_time = time(NULL);
    dss_fuse_lib_t fuse_lib = {0};

    if (cm_open_dl(&fuse_lib.fuse_handle, "libfuse.so.2") == CM_SUCCESS) {
        fuse_lib.version = FUSE_2;
    } else if (cm_open_dl(&fuse_lib.fuse_handle, "libfuse3.so.3") == CM_SUCCESS) {
        fuse_lib.version = FUSE_3;
    } else {
        (void)printf("cannot find libfuse.so, please install libfuse [2.9 - 3.16]\n");
        return CM_ERROR;
    }

    if (fuse_lib.version == FUSE_2) {
        ret = cm_load_symbol(fuse_lib.fuse_handle, "fuse_main_real", (void **)&fuse_lib.dss_fuse2_main_real);
    } else {
        ret = cm_load_symbol(fuse_lib.fuse_handle, "fuse_main_real", (void **)&fuse_lib.dss_fuse3_main_real);
    }

    if (ret == CM_SUCCESS) {
        char *fuse_argv[DSS_FUSE_ARGS_NUM];
        fuse_argv[FUSE_ARG_0] = (char *)"dsscmd";
        fuse_argv[FUSE_ARG_1] = (char *)"-o";
        fuse_argv[FUSE_ARG_2] = (char *)"sync,auto_unmount";
        fuse_argv[FUSE_ARG_3] = (char *)mount_dir;
        if (fuse_lib.version == FUSE_3) {
            if (fuse_lib.dss_fuse3_main_real(DSS_FUSE_ARGS_NUM, fuse_argv, &my_opers3, sizeof(my_opers3), NULL) != 0) {
                ret = CM_ERROR;
            }
        } else {
            if (fuse_lib.dss_fuse2_main_real(DSS_FUSE_ARGS_NUM, fuse_argv, &my_opers2, sizeof(my_opers2), NULL) != 0) {
                ret = CM_ERROR;
            }
        }
    } else {
        ret = CM_ERROR;
        (void)printf("cannot find fuse_main_real function, libfuse version should be [2.9 - 3.16]\n");
    }

    cm_close_dl(fuse_lib.fuse_handle);
    return ret;
}

#else
#include "stdio.h"
#include "cm_error.h"
int my_fuse_main(const char *mount_dir)
{
    (void)printf("not support in Windows.");
    return CM_ERROR;
}

#endif // WIN32