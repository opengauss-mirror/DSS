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
 * dss_api.h
 *
 *
 * IDENTIFICATION
 *    src/interface/dss_api.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __DSS_API_H__
#define __DSS_API_H__

#include <stdio.h>
#include <stdbool.h>
#include "dss_errno.h"
#include "time.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef WIN32
#if defined(DSS_EXPORTS)
#define DSS_DECLARE __declspec(dllexport)
#elif defined(DSS_IMPORTS)
#define DSS_DECLARE __declspec(dllimport)
#else
#define DSS_DECLARE
#endif
#else
#define DSS_DECLARE __attribute__((visibility("default")))
#endif

/* handle */
struct __dss_dir;
typedef struct __dss_dir *dss_dir_handle;

typedef enum en_dss_log_level {
    DSS_LOG_LEVEL_ERROR = 0,  // error conditions
    DSS_LOG_LEVEL_WARN,       // warning conditions
    DSS_LOG_LEVEL_INFO,       // informational messages
    DSS_LOG_LEVEL_COUNT,
} dss_log_level_t;

typedef enum en_dss_log_id {
    DSS_LOG_ID_RUN = 0,
    DSS_LOG_ID_DEBUG,
    DSS_LOG_ID_COUNT,
} dss_log_id_t;

#define DSS_SEEK_MAXWR 3                         /* Used for seek actual file size for openGauss */
#define DSS_MAX_NAME_LEN 64                      /* Consistent with dss_defs.h */
#define DSS_FILE_PATH_MAX_LENGTH (SIZE_K(1) + 1) /* Consistent with dss_defs.h */
#define DSS_MAX_VOLUME_PATH_LEN 64               /* Consistent with dss_defs.h */

/* make the dss handle start from this value, to be distinguished from file system handle value */
#define DSS_HANDLE_BASE 0x20000000
#define DSS_CONN_NEVER_TIMEOUT (-1)
#define DSS_VERSION_MAX_LEN 256

typedef enum en_dss_item_type { DSS_PATH, DSS_FILE, DSS_LINK } dss_item_type_t;

typedef struct st_dss_dirent {
    dss_item_type_t d_type;
    char d_name[DSS_MAX_NAME_LEN];
} dss_dirent_t;

typedef enum en_dss_rdwr_type_e {
    DSS_STATUS_NORMAL = 0,
    DSS_STATUS_READONLY,
    DSS_STATUS_READWRITE,
    DSS_SERVER_STATUS_END,
} dss_rdwr_type_e;

typedef enum en_dss_instance_status {
    DSS_STATUS_PREPARE = 0,
    DSS_STATUS_RECOVERY,
    DSS_STATUS_SWITCH,
    DSS_STATUS_OPEN,
    DSS_INSTANCE_STATUS_END,
} dss_instance_status_e;

#define DSS_MAX_STATUS_LEN 16
typedef struct st_dss_server_status_t {
    dss_instance_status_e instance_status_id;
    char instance_status[DSS_MAX_STATUS_LEN];
    dss_rdwr_type_e server_status_id;
    char server_status[DSS_MAX_STATUS_LEN];
    unsigned int local_instance_id;
    unsigned int master_id;
} dss_server_status_t;

typedef struct st_dss_stat {
    unsigned long long size;
    unsigned long long written_size;
    time_t create_time;
    time_t update_time;
    char name[DSS_MAX_NAME_LEN];
    dss_item_type_t type;
} dss_stat_t;

#define DSS_LOCAL_MAJOR_VER_WEIGHT 1000000
#define DSS_LOCAL_MINOR_VER_WEIGHT 1000
#define DSS_LOCAL_MAJOR_VERSION 0
#define DSS_LOCAL_MINOR_VERSION 0
#define DSS_LOCAL_VERSION 5

typedef struct st_dss_dirent *dss_dir_item_t;
typedef struct st_dss_stat *dss_stat_info_t;

typedef void (*dss_log_output)(dss_log_id_t log_type, dss_log_level_t log_level, const char *code_file_name,
    unsigned int code_line_num, const char *module_name, const char *format, ...);

// dir
DSS_DECLARE int dss_dmake(const char *dir_name);
DSS_DECLARE int dss_dremove(const char *dir);
DSS_DECLARE dss_dir_handle dss_dopen(const char *dir_path);
DSS_DECLARE int dss_dread(dss_dir_handle dir, dss_dir_item_t item, dss_dir_item_t *result);
DSS_DECLARE int dss_dclose(dss_dir_handle dir);
DSS_DECLARE int dss_dexist(const char *name, bool *result);
// file
DSS_DECLARE int dss_fcreate(const char *name, int flag);
DSS_DECLARE int dss_fremove(const char *file);
DSS_DECLARE int dss_fopen(const char *file, int flag, int *handle);
DSS_DECLARE int dss_fclose(int handle);
DSS_DECLARE int dss_fexist(const char *name, bool *result);
DSS_DECLARE long long dss_fseek(int handle, long long offset, int origin);
DSS_DECLARE int dss_fwrite(int handle, const void *buf, int size);
DSS_DECLARE int dss_fread(int handle, void *buf, int size, int *read_size);
DSS_DECLARE int dss_fcopy(const char *src_path, const char *dest_path);
DSS_DECLARE int dss_frename(const char *src, const char *dst);
DSS_DECLARE int dss_ftruncate(int handle, long long length);
DSS_DECLARE int dss_fsize_physical(int handle, long long *fsize);
DSS_DECLARE void dss_fsize_maxwr(const char *fname, long long *fsize);
DSS_DECLARE int dss_pwrite(int handle, const void *buf, int size, long long offset);
DSS_DECLARE int dss_pread(int handle, void *buf, int size, long long offset, int *read_size);
DSS_DECLARE int dss_get_addr(int handle, long long offset, char *pool_name, char *image_name, char *obj_addr,
    unsigned int *obj_id, unsigned long int *obj_offset);
DSS_DECLARE int dss_get_fname(int handle, char *fname, int fname_size);
// aio
DSS_DECLARE int dss_aio_prep_pread(void *iocb, int handle, void *buf, size_t count, long long offset);
DSS_DECLARE int dss_aio_prep_pwrite(void *iocb, int handle, void *buf, size_t count, long long offset);
DSS_DECLARE int dss_aio_post_pwrite(void *iocb, int handle, size_t count, long long offset);

// link
DSS_DECLARE int dss_unlink(const char *link);
DSS_DECLARE int dss_islink(const char *name, bool *result);
DSS_DECLARE int dss_readlink(const char *link_path, char *buf, int bufsize);
DSS_DECLARE int dss_symlink(const char *oldpath, const char *newpath);
// au
DSS_DECLARE int dss_check_size(int size);
DSS_DECLARE int dss_align_size(int size);
DSS_DECLARE int dss_get_au_size(int handle, long long *au_size);
DSS_DECLARE int dss_compare_size_equal(const char *vg_name, long long *au_size);
// log
DSS_DECLARE void dss_get_error(int *errcode, const char **errmsg);
DSS_DECLARE void dss_register_log_callback(dss_log_output cb_log_output, unsigned int log_level);
DSS_DECLARE void dss_set_log_level(unsigned int log_level);
DSS_DECLARE int dss_init_logger(char *log_home, unsigned int log_level, unsigned int log_backup_file_count, unsigned long long log_max_file_size);
DSS_DECLARE void dss_refresh_logger(char *log_field, unsigned long long *value);
// connection
DSS_DECLARE int dss_set_svr_path(const char *conn_path);
DSS_DECLARE int dss_set_conn_timeout(int timeout);
// instance param
DSS_DECLARE int dss_set_main_inst(void);
DSS_DECLARE int dss_get_inst_status(dss_server_status_t *dss_status);

DSS_DECLARE int dss_stat(const char *path, dss_stat_info_t item);
DSS_DECLARE int dss_lstat(const char *path, dss_stat_info_t item);
DSS_DECLARE int dss_fstat(int handle, dss_stat_info_t item);

// config
DSS_DECLARE int dss_setcfg(const char *name, const char *value, const char *scope);
DSS_DECLARE int dss_getcfg(const char *name, char *value, int value_size);
// version
DSS_DECLARE int dss_get_lib_version(void);
DSS_DECLARE void dss_show_version(char *version);

#ifdef __cplusplus
}
#endif
#endif
