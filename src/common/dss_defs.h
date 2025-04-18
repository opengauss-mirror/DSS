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
 *    src/common/dss_defs.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __DSS_DEFS_H__
#define __DSS_DEFS_H__

#include "cm_error.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DSS_FALSE (uint8)0
#define DSS_TRUE (uint8)1

#define DSS_FILE_NAME_BUFFER_SIZE (uint32)256
#define DSS_FILE_PATH_MAX_LENGTH (SIZE_K(1) + 1)
#define DSS_FKEY_FILENAME "server.key.rand"
#define DSS_MAX_AUDIT_PATH_LENGTH (SIZE_K(2) + 512)

#define DSS_VG_ALARM_CHECK_COUNT 10
#define DSS_VG_USAGE_MIN 0
#define DSS_VG_USAGE_MAX 100

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
#define DSS_SESSION_NUM_PER_GROUP 128
#define DSS_MIN_SESSIONID_CFG 16  // allow config min sessionid in dss_inst.ini
#define DSS_MIN_INST_ID 0
#define DSS_MAX_INST_ID DSS_MAX_INSTANCES
#define DSS_LOCK_VG_TIMEOUT 1000000  // usecs
#define DSS_LOCK_VG_TIMEOUT_MS (DSS_LOCK_VG_TIMEOUT / 1000)  // ms
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
#define DSS_MAX_CMD_LEN (512)
#define DSS_MAX_FILE_LEN (256)
#define DSS_MAX_OPEN_VG (DSS_MAX_VOLUME_GROUP_NUM)

#define DSS_BLOCK_SIZE 512
#define DSS_ROOT_FT_DISK_SIZE SIZE_K(8)
#define DSS_LOCK_SHARE_DISK_SIZE (SIZE_K(32) + 512)
#define DSS_INIT_DISK_LATCH_SIZE (SIZE_K(32))

#define DSS_NAME_BUFFER_SIZE (uint32)68
#define DSS_NAME_USER_BUFFER_SIZE (DSS_NAME_BUFFER_SIZE - 16)  // reserve 16 bytes for system
#define DSS_VOLUME_CODE_SIZE 64

#define DSS_DISK_LOCK_LEN 1024

#define DSS_FILE_SPACE_BLOCK_SIZE SIZE_K(16)  // unit:K
#define DSS_BLOCK_CTRL_SIZE 512
#define DSS_LOADDISK_BUFFER_SIZE SIZE_M(1)
#define DSS_MAX_META_BLOCK_SIZE (SIZE_K(16) + 512)

#define DSS_INVALID_64 DSS_INVALID_ID64

#define DSS_DISK_UNIT_SIZE 512

#define DSS_MAX_OPEN_FILES 1000000
#define DSS_DEFAULT_OPEN_FILES_NUM 10000
#define DSS_FILE_CONTEXT_PER_GROUP 1000
#define DSS_MAX_FILE_CONTEXT_GROUP_NUM 1000

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

#define DSS_MIN_IOTHREADS_CFG 1
#define DSS_MAX_IOTHREADS_CFG 8
#define DSS_MIN_WORKTHREADS_CFG 16
#define DSS_MAX_WORKTHREADS_CFG 128

#define DSS_DIR_PARENT ".."
#define DSS_DIR_SELF "."

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

#define DSS_SECUREC_RETURN_IF_ERROR(err, ret)       \
    {                                               \
        if ((err) != EOK) {                         \
            CM_THROW_ERROR(ERR_SYSTEM_CALL, (err)); \
            return ret;                             \
        }                                           \
    }

#define DSS_SECUREC_RETURN_IF_ERROR2(err, hook, ret) \
    {                                                \
        if ((err) != EOK) {                          \
            hook;                                    \
            CM_THROW_ERROR(ERR_SYSTEM_CALL, (err));  \
            return ret;                              \
        }                                            \
    }

#define DSS_SECUREC_SS_RETURN_IF_ERROR(err, ret)    \
    {                                               \
        if ((err) == -1) {                          \
            CM_THROW_ERROR(ERR_SYSTEM_CALL, (err)); \
            return ret;                             \
        }                                           \
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

#define DSS_EXIT_LOG(condition, format, ...)                                           \
    do {                                                                               \
        if (SECUREC_UNLIKELY(!(condition))) {                                          \
            LOG_RUN_ERR(format, ##__VA_ARGS__);                                        \
            LOG_RUN_ERR("Assertion throws an exception at line %u", (uint32)__LINE__); \
            cm_fync_logfile();                                                         \
            exit(-1);                                                                  \
        }                                                                              \
    } while (0)

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
#define DSS_MAX_FS_AUX_BITMAP_SIZE (DSS_FS_AUX_BITMAP_SIZE(DSS_MAX_AU_SIZE))
#define DSS_MIN_FS_AUX_BITMAP_SIZE (DSS_FS_AUX_BITMAP_SIZE(DSS_MIN_AU_SIZE))
// default is 1.5k
#define DSS_FS_AUX_SIZE (DSS_MAX_FS_AUX_BITMAP_SIZE + DSS_FS_AUX_HEAD_SIZE_MAX)

#define DSS_FREE_POINT(pointer)  \
    {                            \
        if ((pointer) != NULL) { \
            free(pointer);       \
            (pointer) = NULL;    \
        }                        \
    }

#ifdef __cplusplus
}
#endif

#endif
