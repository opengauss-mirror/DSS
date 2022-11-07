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
 * dss_log.h
 *
 *
 * IDENTIFICATION
 *    src/common/dss_log.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __DSS_LOG_H__
#define __DSS_LOG_H__
#include "cm_log.h"
#include "cm_text.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct st_dss_config dss_config_t;
typedef struct st_dss_log_def_t dss_log_def_t;

#define DSS_AUDIT_ALL 255

#define DSS_AUDIT_MODIFY 0x00000001
#define DSS_AUDIT_QUERY 0x00000002

typedef struct st_dss_audit_assist {
    char date[CM_MAX_TIME_STRLEN];
    char session_buf[CM_MAX_NUMBER_LEN];
    char return_code_buf[CM_MAX_NUMBER_LEN];
    char os_host[CM_HOST_NAME_BUFFER_SIZE];
    char db_user[CM_NAME_BUFFER_SIZE];

    text_t session_id;
    text_t return_code;

    int32 sid;
    int32 code;
    int32 tz;
} dss_audit_assist_t;

#define DSS_LOG_DEBUG_OP(user_fmt_str, ...)              \
    do {                                                 \
        LOG_DEBUG_INF("[OP]" user_fmt_str, __VA_ARGS__); \
    } while (0)

#define DSS_PRINT_ERROR(fmt, ...)                                                    \
    do {                                                                             \
        (void)printf(fmt, ##__VA_ARGS__);                                            \
        LOG_DEBUG_ERR(fmt, ##__VA_ARGS__);                                           \
        int32 errcode_print;                                                         \
        const char *errmsg_print = NULL;                                             \
        cm_get_error(&errcode_print, &errmsg_print);                                 \
        if (errcode_print != 0) {                                                    \
            (void)printf(" detail reason [%d] : %s\n", errcode_print, errmsg_print); \
            (void)fflush(stdout);                                                    \
        }                                                                            \
        cm_reset_error();                                                            \
    } while (0)

#define DSS_PRINT_INF(fmt, ...)            \
    do {                                   \
        (void)printf(fmt, ##__VA_ARGS__);  \
        (void)fflush(stdout);              \
        LOG_DEBUG_INF(fmt, ##__VA_ARGS__); \
    } while (0)

#define DSS_THROW_ERROR(error_no, ...)                                                                                 \
    do {                                                                                                               \
        if (g_dss_error_desc[error_no] != NULL)                                                                        \
            cm_set_error((char *)__FILE_NAME__, (uint32)__LINE__, (cm_errno_t)error_no, g_dss_error_desc[error_no],    \
                ##__VA_ARGS__);                                                                                        \
        else                                                                                                           \
            cm_set_error(                                                                                              \
                (char *)__FILE_NAME__, (uint32)__LINE__, (cm_errno_t)error_no, g_error_desc[error_no], ##__VA_ARGS__); \
    } while (0)

#define DSS_THROW_ERROR_EX(error_no, format, ...)                                                           \
    do {                                                                                                    \
        cm_set_error((char *)__FILE_NAME__, (uint32)__LINE__, (cm_errno_t)error_no, format, ##__VA_ARGS__); \
    } while (0)

#define DSS_ERROR_COUNT 3000
extern const char *g_dss_error_desc[DSS_ERROR_COUNT];
status_t dss_init_loggers(dss_config_t *inst_cfg, dss_log_def_t *log_def, uint32 log_def_count, char *name);
void sql_record_audit_log(void *sess, status_t status, uint8 cmd_type);

#ifdef __cplusplus
}
#endif
#endif
