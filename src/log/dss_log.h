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
 *    src/log/dss_log.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __DSS_LOG_H__
#define __DSS_LOG_H__
#include "cm_log.h"
#include "cm_text.h"
#include "dss_defs.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct st_dss_config dss_config_t;

#define DSS_AUDIT_ALL 255

#define DSS_AUDIT_MODIFY 0x00000001
#define DSS_AUDIT_QUERY 0x00000002

typedef struct st_dss_log_def_t {
    log_type_t log_id;
    char log_filename[DSS_MAX_NAME_LEN];
} dss_log_def_t;

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

typedef struct st_dss_audit_info {
    char *action;
    char resource[DSS_MAX_AUDIT_PATH_LENGTH];
} dss_audit_info_t;

#define DSS_LOG_DEBUG_OP(user_fmt_str, ...)              \
    do {                                                 \
        LOG_DEBUG_INF("[OP]" user_fmt_str, ##__VA_ARGS__); \
    } while (0)

static inline void dss_print_detail_error()
{
    int32 errcode_print;
    const char *errmsg_print = NULL;
    cm_get_error(&errcode_print, &errmsg_print);
    if (errcode_print != 0) {
        (void)printf(" detail reason [%d] : %s\n", errcode_print, errmsg_print);
        (void)fflush(stdout);
    }
    cm_reset_error();
}
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

#define DSS_PRINT_RUN_ERROR(fmt, ...)                                                \
    do {                                                                             \
        (void)printf(fmt, ##__VA_ARGS__);                                            \
        LOG_RUN_ERR(fmt, ##__VA_ARGS__);                                             \
        int32 errcode_print;                                                         \
        const char *errmsg_print = NULL;                                             \
        cm_get_error(&errcode_print, &errmsg_print);                                 \
        if (errcode_print != 0) {                                                    \
            LOG_RUN_ERR(" detail reason [%d] : %s", errcode_print, errmsg_print);    \
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

/*
 * warning id is composed of source + module + object + code
 * source -- DN(10)/CM(11)/OM(12)/DM(20)/DSS(30)
 * module -- File(01)/Transaction(02)/HA(03)/Log(04)/Buffer(05)/Space(06)/Server(07)
 * object -- Host Resource(01)/Run Environment(02)/Cluster Status(03)/
 *           Instance Status(04)/Database Status(05)/Database Object(06)
 * code   -- 0001 and so on
 */
/*
 * one warn must modify  warn_id_t
 *                       warn_name_t
 *                       g_warn_id
 *                       g_warning_desc
 */
typedef enum dss_warn_id {
    WARN_DSS_SPACEUSAGE_ID = 3006060001,
} dss_warn_id_t;

typedef enum dss_warn_name {
    WARN_DSS_SPACEUSAGE, /* dss vg space */
} dss_warn_name_t;

typedef enum { DSS_VG_SPACE_ALARM_INIT, DSS_VG_SPACE_ALARM_HWM, DSS_VG_SPACE_ALARM_LWM} dss_alarm_type_e;

#define DSS_ERROR_COUNT 3000
extern const char *g_dss_error_desc[DSS_ERROR_COUNT];
extern char *g_dss_warn_desc[];
extern uint32 g_dss_warn_id[];
status_t dss_init_loggers(dss_config_t *inst_cfg, dss_log_def_t *log_def, uint32 log_def_count, char *name);
void sql_record_audit_log(void *sess, status_t status, uint8 cmd_type);
dss_log_def_t *dss_get_instance_log_def();
dss_log_def_t *dss_get_cmd_log_def();
uint32 dss_get_instance_log_def_count();
uint32 dss_get_cmd_log_def_count();

char *dss_get_print_tab(uint8 level);
status_t dss_init_log_home_ex(dss_config_t *inst_cfg, char *log_parm_value, char *log_param_name, char *log_dir);
#ifdef __cplusplus
}
#endif
#endif
