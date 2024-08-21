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
 * dss_defs.h
 *
 *
 * IDENTIFICATION
 *    src/common/persist/dss_defs.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __DSS_DEFS_H__
#define __DSS_DEFS_H__

#include <sys/stat.h>
#include "cm_date.h"
#include "cm_defs.h"
#include "cm_error.h"
#include "cm_ip.h"
#include "cm_log.h"
#include "cm_thread.h"
#include "cm_timer.h"
#include "dss_log.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DSS_FALSE (uint8)0
#define DSS_TRUE (uint8)1

#define DSS_FILE_NAME_BUFFER_SIZE (uint32)256
#define DSS_FILE_PATH_MAX_LENGTH (SIZE_K(1) + 1)
#define DSS_FKEY_FILENAME "server.key.rand"
#define DSS_MAX_AUDIT_PATH_LENGTH (SIZE_K(2) + 512)
/* invalid id */
#define DSS_INVALID_INT8 ((int8)(-1))
#define DSS_INVALID_ID8 (uint8)0xFF
#define DSS_INVALID_OFFSET16 (uint16)0xFFFF
#define DSS_INVALID_ID16 (uint16)0xFFFF
#define DSS_INVALID_ID24 (uint32)0xFFFFFF
#define DSS_INVALID_ID32 (uint32)0xFFFFFFFF
#define DSS_INVALID_OFFSET32 (uint32)0xFFFFFFFF
#define DSS_INVALID_ID64 (uint64)0xFFFFFFFFFFFFFFFF
#define DSS_INFINITE32 (uint32)0xFFFFFFFF
#define DSS_NULL_VALUE_LEN (uint16)0xFFFF
#define DSS_INVALID_ASN (uint32)0
#define DSS_INVALID_INT32 (uint32)0x7FFFFFFF
#define DSS_INVALID_INT64 (int64)0x7FFFFFFFFFFFFFFF
#define DSS_INVALID_FILEID DSS_INVALID_ID16
#define DSS_INVALID_CHECKSUM (uint16)0

#define DSS_ULL_MAX (uint64)0xFFFFFFFFFFFFFFFF

#ifdef WIN32
#define DSS_INVALID_HANDLE NULL
#else
#define DSS_INVALID_HANDLE (-1)
#endif
// The value of each command type cannot be changed for compatibility reasons.
// If you want to add a command type, add it at the end. Before DSS_CMD_END
typedef enum {
    DSS_CMD_BASE,
    DSS_CMD_BEGIN,
    DSS_CMD_MODIFY_BEGIN = DSS_CMD_BEGIN,
    DSS_CMD_MKDIR = DSS_CMD_MODIFY_BEGIN,
    DSS_CMD_RMDIR,
    DSS_CMD_OPEN_DIR,
    DSS_CMD_CLOSE_DIR,
    DSS_CMD_OPEN_FILE,
    DSS_CMD_CLOSE_FILE,
    DSS_CMD_CREATE_FILE,
    DSS_CMD_DELETE_FILE,
    DSS_CMD_EXTEND_FILE,
    DSS_CMD_ATTACH_FILE,  // 10
    DSS_CMD_DETACH_FILE,
    DSS_CMD_RENAME_FILE,
    DSS_CMD_REFRESH_FILE,
    DSS_CMD_TRUNCATE_FILE,
    DSS_CMD_REFRESH_FILE_TABLE,
    DSS_CMD_FALLOCATE_FILE,
    DSS_CMD_ADD_VOLUME,
    DSS_CMD_REMOVE_VOLUME,
    DSS_CMD_REFRESH_VOLUME,
    DSS_CMD_KICKH,  // 20
    DSS_CMD_LOAD_CTRL,
    DSS_CMD_UPDATE_WRITTEN_SIZE,
    DSS_CMD_STOP_SERVER,
    DSS_CMD_SETCFG,
    DSS_CMD_SYMLINK,
    DSS_CMD_UNLINK,
    DSS_CMD_SET_MAIN_INST,
    DSS_CMD_SWITCH_LOCK,
    DSS_CMD_DISABLE_GRAB_LOCK,
    DSS_CMD_ENABLE_GRAB_LOCK,
    DSS_CMD_MODIFY_END = 127,
    DSS_CMD_QUERY_BEGIN = DSS_CMD_MODIFY_END,
    DSS_CMD_HANDSHAKE = DSS_CMD_QUERY_BEGIN,
    DSS_CMD_EXIST,  // 128
    DSS_CMD_READLINK,
    DSS_CMD_GET_FTID_BY_PATH,
    DSS_CMD_GETCFG,
    DSS_CMD_GET_INST_STATUS,
    DSS_CMD_GET_TIME_STAT,
    DSS_CMD_QUERY_END,
    DSS_CMD_EXEC_REMOTE = DSS_CMD_QUERY_END,
    DSS_CMD_END  // must be the last item
} dss_cmd_type_e;

#define DSS_CMD_TYPE_OFFSET(cmd_id) ((uint32)(cmd_id) - (uint32)DSS_CMD_BEGIN)

static inline bool32 dss_can_cmd_type_no_open(dss_cmd_type_e type)
{
    return ((type == DSS_CMD_GET_INST_STATUS) || (type == DSS_CMD_HANDSHAKE) || (type == DSS_CMD_STOP_SERVER) ||
            (type == DSS_CMD_ENABLE_GRAB_LOCK));
}

#define DSS_DEFAULT_AU_SIZE SIZE_M(8)
#define DSS_MAX_AU_SIZE SIZE_M(64)
#define DSS_MIN_AU_SIZE SIZE_M(2)

#define DSS_MAX_VOLUMES 256
#define DSS_CTRL_SIZE DSS_DEFAULT_AU_SIZE
#define DSS_LOG_BUFFER_SIZE SIZE_K(512)
#define DSS_CORE_CTRL_SIZE SIZE_K(16)
#define DSS_VOLUME_CTRL_SIZE SIZE_K(256)
#define DSS_VG_DATA_SIZE 512
#define DSS_MIN_BUFFER_BLOCKS 32
#define DSS_MIN_SESSIONID 0
#define DSS_MAX_SESSIONS 16320
#define DSS_MIN_SESSIONID_CFG 16  // allow config min sessionid in dss_inst.ini
#define DSS_MIN_INST_ID 0
#define DSS_MAX_INST_ID DSS_MAX_INSTANCES
#define DSS_LOCK_VG_TIMEOUT 1000000  // usecs
#define DSS_LOKC_ALIGN_SIZE_512 512
#define DSS_MIN_LOCK_INTERVAL 1
#define DSS_MAX_LOCK_INTERVAL 600000
#define DSS_MIN_DLOCK_RETRY_COUNT 1
#define DSS_MAX_DLOCK_RETRY_COUNT 500000
#define DSS_MIN_DELAY_CLEAN_INTERVAL 5
#define DSS_MAX_DELAY_CLEAN_INTERVAL 1000000
#define DSS_MIN_SHM_KEY 1
#define DSS_MAX_SHM_KEY 64
#define DSS_MAX_SHM_KEY_BITS 8

#define DSS_MAX_NAME_LEN 64
#define DSS_MAX_VOLUME_PATH_LEN 64

#define DSS_BLOCK_SIZE 512
#define DSS_ROOT_FT_DISK_SIZE SIZE_K(8)
#define DSS_NAME_BUFFER_SIZE (uint32)68
#define DSS_NAME_USER_BUFFER_SIZE (DSS_NAME_BUFFER_SIZE - 16)  // reserve 16 bytes for system
#define DSS_VOLUME_CODE_SIZE 64

#define DSS_DISK_LOCK_LEN 1024

#define DSS_FILE_SPACE_BLOCK_SIZE SIZE_K(16)  // unit:K
#define DSS_BLOCK_CTRL_SIZE 512
#define DSS_META_BITMAP_SIZE (DSS_FILE_SPACE_BLOCK_SIZE / 8)  // UNUSED
#define DSS_LOADDISK_BUFFER_SIZE SIZE_M(1)
#define DSS_MAX_META_BLOCK_SIZE (SIZE_K(16) + 512)

#define DSS_INVALID_64 DSS_INVALID_ID64

#define DSS_DISK_UNIT_SIZE 512

#define DSS_MAX_OPEN_FILES 1000000
#define DSS_DEFAULT_OPEN_FILES_NUM 10000
#define DSS_OPEN_FILES_NUM 100

#define DSS_STATIC_ASSERT(condition) ((void)sizeof(char[1 - 2 * (int32)(!(condition))]))

#define DSS_MAX_BIT_NUM_VOLUME 10
#define DSS_MAX_BIT_NUM_AU 34
#define DSS_MAX_BIT_NUM_BLOCK 17
#define DSS_MAX_BIT_NUM_ITEM 3
#define DSS_MAX_VOLUME_SIZE ((1 << DSS_MAX_BIT_NUM_AU) * DSS_DEFAULT_AU_SIZE)

#define DSS_INIT_HASH_MAP_SIZE SIZE_K(16)

#define DSS_CFG_NAME "dss_inst.ini"

#define DSS_MAX_MEM_BLOCK_SIZE SIZE_M(8)

#define DSS_BLOCK_HASH_SIZE SIZE_M(1)

#define DSS_MAX_FILE_SIZE SIZE_T(8)

#define DSS_USOCKET_PERMSSION (S_IRUSR | S_IWUSR)

#define DSS_ID_TO_U64(id) (*(uint64 *)&(id))

#define DSS_MAX_STACK_BUF_SIZE SIZE_K(512)

#define DSS_CMS_RES_TYPE "dss"

#define DSS_FILE_HASH_SIZE (uint32)5000

#define DSS_MAX_PATH_BUFFER_SIZE (uint32)(DSS_FILE_NAME_BUFFER_SIZE - DSS_NAME_BUFFER_SIZE)

#define DSS_PROTO_CODE *(uint32 *)"\xFE\xDC\xBA\x98"
#define DSS_UNIX_PATH_MAX (uint32)108
#define DSS_MAX_INSTANCES 64
#define DSS_VERSION_MAX_LEN 256
#define DSS_WAIT_TIMEOUT 5

#define DSS_ENV_HOME (char *)"DSS_HOME"

/* file */
#define DSS_MAX_CONFIG_FILE_SIZE SIZE_K(64) /* 64K */
#define DSS_MAX_CONFIG_BUFF_SIZE SIZE_M(1)
#define DSS_MAX_CONFIG_LINE_SIZE SIZE_K(2)
#define DSS_MAX_SQL_FILE_SIZE SIZE_M(2)
#define DSS_MIN_SYSTEM_DATAFILE_SIZE SIZE_M(128)
#define DSS_MIN_USER_DATAFILE_SIZE SIZE_M(1)
#define DSS_DFLT_CTRL_BLOCK_SIZE SIZE_K(16)
#define DSS_DFLT_LOG_BLOCK_SIZE (uint32)512
#define DSS_MAX_ARCH_FILES_SIZE SIZE_T(32)

#define GSDB_UDS_EMERG_CLIENT "gsdb_uds_emerg.client"
#define GSDB_UDS_EMERG_SERVER "gsdb_uds_emerg.server"

#define CM_MAX_UDS_FILE_PERMISSIONS (uint16)777
#define CM_DEF_UDS_FILE_PERMISSIONS (uint16)600

#define DSS_MAX_PACKET_SIZE (uint32)2136 /* sizeof(dss_packet_head_t) + CM_ALIGN4(DSS_FILE_PATH_MAX_LENGTH + 1) */
#define DSS_MAX_PACKET_DATA_SIZE (((DSS_MAX_PACKET_SIZE) - sizeof(dss_packet_head_t)) - sizeof(uint32))

#define DSS_PARAM_BUFFER_SIZE (uint32)1024
#define DSS_ALIGN_SIZE (uint32)512
#define DSS_MIN_PORT (uint32)1024
#define CM_ALIGN_512(size) (((size) + 0x000001FF) & 0xFFFFFE00)
#define DSS_DEFAULT_NULL_VALUE (uint32)0xFFFFFFFF
#define DSS_UDS_CONNECT_TIMEOUT (int32)(30000) /* 30 seconds */
#define DSS_UDS_SOCKET_TIMEOUT (int32)0x4FFFFFFF
#define DSS_SEEK_MAXWR 3 /* Used for seek actual file size for openGauss */

#define DSS_BASE_YEAR 1900
#define DSS_MIN_IOTHREADS_CFG 1
#define DSS_MAX_IOTHREADS_CFG 8
#define DSS_MIN_WORKTHREADS_CFG 16
#define DSS_MAX_WORKTHREADS_CFG 128

#define DSS_RETURN_IF_ERROR(ret)      \
    do {                              \
        int _status_ = (ret);         \
        if (_status_ != CM_SUCCESS) { \
            return _status_;          \
        }                             \
    } while (0)

#define DSS_RETURN_IFERR2(func, hook)                   \
    do {                                                \
        int _status_ = (func);                          \
        if (SECUREC_UNLIKELY(_status_ != CM_SUCCESS)) { \
            hook;                                       \
            return _status_;                            \
        }                                               \
    } while (0)

#define DSS_RETURN_IFERR3(func, hook1, hook2)           \
    do {                                                \
        int _status_ = (func);                          \
        if (SECUREC_UNLIKELY(_status_ != CM_SUCCESS)) { \
            hook1;                                      \
            hook2;                                      \
            return _status_;                            \
        }                                               \
    } while (0)

#define DSS_RETURN_IF_FALSE2(ret, hook)           \
    do {                                          \
        if (SECUREC_UNLIKELY((ret) != CM_TRUE)) { \
            hook;                                 \
            return CM_ERROR;                      \
        }                                         \
    } while (0)

#define DSS_RETURN_IFERR4(func, hook1, hook2, hook3)    \
    do {                                                \
        int _status_ = (func);                          \
        if (SECUREC_UNLIKELY(_status_ != CM_SUCCESS)) { \
            hook1;                                      \
            hook2;                                      \
            hook3;                                      \
            return _status_;                            \
        }                                               \
    } while (0)

#define DSS_RETURN_IF_FALSE3(ret, hook1, hook2)   \
    do {                                          \
        if (SECUREC_UNLIKELY((ret) != CM_TRUE)) { \
            hook1;                                \
            hook2;                                \
            return CM_ERROR;                      \
        }                                         \
    } while (0)

#define DSS_RETURN_IF_SUCCESS(ret)    \
    do {                              \
        int _status_ = (ret);         \
        if (_status_ == CM_SUCCESS) { \
            return _status_;          \
        }                             \
    } while (0)

#define DSS_RETURN_STATUS_IF_TRUE(cond, status) \
    do {                                        \
        int _status_ = (status);                \
        if ((cond) == CM_TRUE) {                \
            return _status_;                    \
        }                                       \
    } while (0)

#define DSS_SECUREC_RETURN_IF_ERROR(err, ret)        \
    {                                                \
        if ((err) != EOK) {                          \
            DSS_THROW_ERROR(ERR_SYSTEM_CALL, (err)); \
            return ret;                              \
        }                                            \
    }

#define DSS_SECUREC_RETURN_IF_ERROR2(err, hook, ret) \
    {                                                \
        if ((err) != EOK) {                          \
            hook;                                    \
            DSS_THROW_ERROR(ERR_SYSTEM_CALL, (err)); \
            return ret;                              \
        }                                            \
    }

#define DSS_SECUREC_SS_RETURN_IF_ERROR(err, ret)     \
    {                                                \
        if ((err) == -1) {                           \
            DSS_THROW_ERROR(ERR_SYSTEM_CALL, (err)); \
            return ret;                              \
        }                                            \
    }

#define DSS_RETURN_IF_NULL(ret) \
    do {                        \
        if ((ret) == NULL) {    \
            return CM_ERROR;    \
        }                       \
    } while (0)

#define DSS_BREAK_IF_ERROR(ret) \
    if ((ret) != CM_SUCCESS) {  \
        break;                  \
    }

#define DSS_BREAK_IFERR2(func, hook)              \
    if (SECUREC_UNLIKELY((func) != CM_SUCCESS)) { \
        hook;                                     \
        break;                                    \
    }

#define DSS_BREAK_IFERR3(func, hook1, hook2)      \
    if (SECUREC_UNLIKELY((func) != CM_SUCCESS)) { \
        hook1;                                    \
        hook2;                                    \
        break;                                    \
    }

#define DSS_RETURN_DRIECT_IFERR(ret) \
    do {                             \
        if ((ret) != CM_SUCCESS) {   \
            return;                  \
        }                            \
    } while (0)

#ifdef WIN32
#define DSS_LOG_WITH_OS_MSG(user_fmt_str, ...)                                                                    \
    do {                                                                                                          \
        char os_errmsg_buf[64];                                                                                   \
        (void)snprintf_s(                                                                                         \
            os_errmsg_buf, sizeof(os_errmsg_buf), sizeof(os_errmsg_buf) - 1, "Unknown error %d", GetLastError()); \
        strerror_s(os_errmsg_buf, sizeof(os_errmsg_buf), GetLastError());                                         \
        LOG_DEBUG_ERR(user_fmt_str ", OS errno=%d, OS errmsg=%s", __VA_ARGS__, GetLastError(), os_errmsg_buf);    \
    } while (0)
#else
#define DSS_LOG_WITH_OS_MSG(user_fmt_str, ...)                                                                        \
    do {                                                                                                              \
        char os_errmsg_buf[64];                                                                                       \
        (void)snprintf_s(os_errmsg_buf, sizeof(os_errmsg_buf), sizeof(os_errmsg_buf) - 1, "Unknown error %d", errno); \
        /* here we use GNU version of strerror_r, make sure _GNU_SOURCE is defined */                                 \
        LOG_DEBUG_ERR(user_fmt_str ", OS errno=%d, OS errmsg=%s", __VA_ARGS__, errno,                                 \
            strerror_r(errno, os_errmsg_buf, sizeof(os_errmsg_buf)));                                                 \
    } while (0)
#endif

#define DSS_ASSERT_LOG(condition, format, ...)                                         \
    do {                                                                               \
        if (SECUREC_UNLIKELY(!(condition))) {                                          \
            LOG_RUN_ERR(format, ##__VA_ARGS__);                                        \
            LOG_RUN_ERR("Assertion throws an exception at line %u", (uint32)__LINE__); \
            cm_fync_logfile();                                                         \
            CM_ASSERT(0);                                                              \
        }                                                                              \
    } while (0)

#pragma pack(8)
typedef struct st_auid_t {  // id of allocation unit, 8 Bytes
    uint64 volume : DSS_MAX_BIT_NUM_VOLUME;
    uint64 au : DSS_MAX_BIT_NUM_AU;
    uint64 block : DSS_MAX_BIT_NUM_BLOCK;
    uint64 item : DSS_MAX_BIT_NUM_ITEM;
} auid_t;
#pragma pack()

typedef auid_t dss_block_id_t;
typedef auid_t ftid_t;

extern auid_t dss_invalid_auid;
#define DSS_INVALID_AUID (dss_invalid_auid)
#define DSS_INVALID_BLOCK_ID (dss_invalid_auid)
#define DSS_INVALID_FTID (dss_invalid_auid)

#define DSS_BYTE_BITS_SIZE 8

// if want change the default, compile the dss with set DSS_PAGE_SIZE=page_size_you_want
#ifndef DSS_PAGE_SIZE
#define DSS_PAGE_SIZE 8192
#endif

#if DSS_PAGE_SIZE != 4096 && DSS_PAGE_SIZE != 8192 && DSS_PAGE_SIZE != 16384 && DSS_PAGE_SIZE != 32768
#error "DSS_PAGE_SIZE only can be one of [4096, 8192, 16384, 32768]"
#endif

#define DSS_FS_AUX_HEAD_SIZE_MAX DSS_DISK_UNIT_SIZE

#define DSS_FS_AUX_BITMAP_SIZE(au_size) (((au_size) / DSS_PAGE_SIZE) / DSS_BYTE_BITS_SIZE)
// default is 1.5k
#define DSS_FS_AUX_SIZE (DSS_FS_AUX_BITMAP_SIZE(DSS_MAX_AU_SIZE) + DSS_FS_AUX_HEAD_SIZE_MAX)

extern auid_t dss_set_inited_mask;
extern auid_t dss_unset_inited_mask;

#define DSS_AU_UNINITED_MARK 0x1
static inline void dss_auid_set_uninit(auid_t *auid)
{
    auid->item |= DSS_AU_UNINITED_MARK;
}

static inline void dss_auid_unset_uninit(auid_t *auid)
{
    auid->item &= ~DSS_AU_UNINITED_MARK;
}

static inline bool32 dss_auid_is_uninit(auid_t *auid)
{
    return ((auid->item & DSS_AU_UNINITED_MARK) != 0);
}

#define DSS_BLOCK_ID_SET_INITED(block_id) ((*(uint64 *)&block_id) & (*(uint64 *)&dss_unset_inited_mask))
#define DSS_BLOCK_ID_SET_UNINITED(block_id) ((*(uint64 *)&block_id) | (*(uint64 *)&dss_set_inited_mask))
#define DSS_BLOCK_ID_IGNORE_UNINITED(block_id) ((*(uint64 *)&block_id) & (*(uint64 *)&dss_unset_inited_mask))
#define DSS_BLOCK_ID_IS_INITED(block_id) (((block_id).item & DSS_AU_UNINITED_MARK) == 0)

#define DSS_BLOCK_ID_SET_AUX(block_id) ((*(uint64 *)&block_id) | (*(uint64 *)&dss_set_inited_mask))
#define DSS_BLOCK_ID_SET_NOT_AUX(block_id) ((*(uint64 *)&block_id) & (*(uint64 *)&dss_unset_inited_mask))
#define DSS_BLOCK_ID_IS_AUX(block_id) (((block_id).item & DSS_AU_UNINITED_MARK) == 1)

#pragma pack(8)
typedef struct st_dss_addr_t {
    uint64 volumeid : 10;
    uint64 offset : 54;
} dss_addr_t;
#pragma pack()

typedef struct st_dss_log_def_t {
    log_type_t log_id;
    char log_filename[DSS_MAX_NAME_LEN];
} dss_log_def_t;

#define DSS_INSTANCE_LOG_BUFFER_SIZE_V0 SIZE_M(8)
#define DSS_LOG_BUF_SLOT_COUNT_V0 16
#define DSS_INSTANCE_LOG_SPLIT_SIZE_V0 ((DSS_INSTANCE_LOG_BUFFER_SIZE_V0) / (DSS_LOG_BUF_SLOT_COUNT_V0))
#define DSS_INSTANCE_LOG_SPLIT_SIZE                                                          \
    ((DSS_INSTANCE_LOG_BUFFER_SIZE_V0) / (DSS_MAX_VOLUME_GROUP_NUM) / (DSS_DISK_UNIT_SIZE) * \
        (DSS_DISK_UNIT_SIZE))  // 126KB
#define DSS_VG_LOG_SPLIT_SIZE SIZE_K(64)
#define DSS_VG_LOG_BUFFER_SIZE SIZE_M(64)

typedef struct st_dss_log_file_ctrl {
    spinlock_t lock;
    char *log_buf;  // global log_buf
    bool8 used;
    uint32 index;
    uint64 offset;
    uint64 lsn;
} dss_log_file_ctrl_t;

typedef struct st_dss_audit_info {
    char *action;
    char resource[DSS_MAX_AUDIT_PATH_LENGTH];
} dss_audit_info_t;

#define DSS_FREE_POINT(pointer)  \
    {                            \
        if ((pointer) != NULL) { \
            free(pointer);       \
            (pointer) = NULL;    \
        }                        \
    }

#define MICROSECS_PER_MIN 60000000U
static inline uint64 cm_day_usec(void)
{
#ifdef WIN32
    uint64 usec;
    SYSTEMTIME sys_time;
    GetLocalTime(&sys_time);

    usec = sys_time.wHour * SECONDS_PER_HOUR * MICROSECS_PER_SECOND;
    usec += sys_time.wMinute * MICROSECS_PER_MIN;
    usec += sys_time.wSecond * MICROSECS_PER_SECOND;
    usec += sys_time.wMilliseconds * MICROSECS_PER_MILLISEC;
#else
    uint64 usec;
    struct timeval tv;
    (void)gettimeofday(&tv, NULL);
    usec = (uint64)(tv.tv_sec * MICROSECS_PER_SECOND);
    usec += (uint64)tv.tv_usec;
#endif

    return usec;
}

static inline struct tm *dss_localtime(const time_t *timep, struct tm *result)
{
#ifdef WIN32
    errno_t err = localtime_s(result, timep);
    if (err != EOK) {
        CM_ASSERT(0);
    }
    return NULL;
#else
    return localtime_r(timep, result);
#endif
}

static inline uint32 dss_get_log_size(uint64 au_size)
{
    if (au_size < DSS_VG_LOG_BUFFER_SIZE && au_size > 0) {
        uint64 m = DSS_VG_LOG_BUFFER_SIZE / au_size;
        uint64 n = DSS_VG_LOG_BUFFER_SIZE % au_size;
        return (n == 0) ? DSS_VG_LOG_BUFFER_SIZE : (m + 1) * au_size;
    }
    return au_size;
}

time_t cm_encode_time(date_detail_t *detail);
void cm_decode_time(time_t time, date_detail_t *detail);
time_t cm_date2time(date_t date);
status_t cm_time2str(time_t time, const char *fmt, char *str, uint32 str_max_size);

void cm_destroy_thread_lock(thread_lock_t *lock);
char *dss_get_cmd_desc(dss_cmd_type_e cmd_type);
char *dss_get_print_tab(uint8 level);

char *dss_display_metaid(auid_t id);

#ifdef __cplusplus
}
#endif

#endif
