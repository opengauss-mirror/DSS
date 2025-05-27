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
 * dsscmd_native_api.h
 *   DSS client native API wrapper.
 *
 *
 * IDENTIFICATION
 *    src/cmd/dsscmd_native_api.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __DSSCMD_NATIVE_API_H__
#define __DSSCMD_NATIVE_API_H__

#include <dirent.h>
#include <sys/stat.h>
#include <stdio.h>

#define DSS_MAGIC_NUMBER 0xFEDCBA9876543210
#define MAX_FILE_NAME_LEN 64

typedef enum en_device_type { DEV_TYPE_FILE = 0, DEV_TYPE_DSS, DEV_TYPE_NUM, DEV_TYPE_INVALID } device_type_t;

bool is_dss_file(const char *name);
bool is_dss_fd(int handle);
void native_set_errno(int *errcode, const char **errmsg);
int native_access_file(const char *file_name, int mode);
int native_create_dir(const char *name, mode_t mode);
int native_open_dir(const char *name, DIR **dir_handle);
int native_read_dir(DIR *dir_handle, struct dirent **result);
int native_close_dir(DIR *dir_handle);
int native_remove_dir(const char *name);
int native_rename_file(const char *src, const char *dst);
int native_remove_file(const char *name);
int native_open_file(const char *name, int flags, mode_t mode, int *handle);
int native_fopen_file(const char *name, const char* mode, FILE **stream);
int native_close_file(int handle);
ssize_t native_read_file(int handle, void *buf, size_t size);
ssize_t native_pread_file(int handle, void *buf, size_t size, off_t offset);
ssize_t native_write_file(int handle, const void *buf, size_t size);
ssize_t native_pwrite_file(int handle, const void *buf, size_t size, off_t offset);
off_t native_seek_file(int handle, off_t offset, int origin);
int native_sync_file(int handle);
int native_truncate_file(int handle, off_t keep_size);
off_t native_get_file_size(const char *fname);
int native_fallocate_file(int handle, int mode, off_t offset, off_t len);
int native_link(const char *src, const char *dst);
int native_unlink_target(const char *name);
ssize_t native_read_link(const char *path, char *buf, size_t buf_size);
int native_stat_file(const char *path, struct stat *buf);
int native_lstat_file(const char *path, struct stat *buf);
int native_fstat_file(int handle, struct stat *buf);
int native_remove_dev(const char *name);
#endif // __DSSCMD_NATIVE_API_H__