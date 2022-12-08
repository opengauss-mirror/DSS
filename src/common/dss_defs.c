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
 * dss_defs.c
 *
 *
 * IDENTIFICATION
 *    src/common/dss_defs.c
 *
 * -------------------------------------------------------------------------
 */

#include "dss_defs.h"
#include "cm_num.h"
#include "dss_errno.h"

dss_kernel_instance_t g_dss_kernel_instance;

#define DSS_CMD_TYPE_OFFSET(i) ((uint32)(i) - (uint32)DSS_CMD_BEGIN)
static char *g_dss_cmd_desc[DSS_CMD_TYPE_OFFSET(DSS_CMD_END)] = {
    [DSS_CMD_TYPE_OFFSET(DSS_CMD_MKDIR)] = "mkdir",
    [DSS_CMD_TYPE_OFFSET(DSS_CMD_RMDIR)] = "rmdir",
    [DSS_CMD_TYPE_OFFSET(DSS_CMD_OPEN_DIR)] = "open dir",
    [DSS_CMD_TYPE_OFFSET(DSS_CMD_CLOSE_DIR)] = "close dir",
    [DSS_CMD_TYPE_OFFSET(DSS_CMD_OPEN_FILE)] = "open file",
    [DSS_CMD_TYPE_OFFSET(DSS_CMD_CLOSE_FILE)] = "close file",
    [DSS_CMD_TYPE_OFFSET(DSS_CMD_CREATE_FILE)] = "create file",
    [DSS_CMD_TYPE_OFFSET(DSS_CMD_DELETE_FILE)] = "delete file",
    [DSS_CMD_TYPE_OFFSET(DSS_CMD_EXTEND_FILE)] = "extend file",
    [DSS_CMD_TYPE_OFFSET(DSS_CMD_ATTACH_FILE)] = "attach file",
    [DSS_CMD_TYPE_OFFSET(DSS_CMD_DETACH_FILE)] = "detach file",
    [DSS_CMD_TYPE_OFFSET(DSS_CMD_RENAME_FILE)] = "rename file",
    [DSS_CMD_TYPE_OFFSET(DSS_CMD_REFRESH_FILE)] = "refresh file",
    [DSS_CMD_TYPE_OFFSET(DSS_CMD_TRUNCATE_FILE)] = "truncate file",
    [DSS_CMD_TYPE_OFFSET(DSS_CMD_REFRESH_FILE_TABLE)] = "refresh file table",
    [DSS_CMD_TYPE_OFFSET(DSS_CMD_CONSOLE)] = "console",
    [DSS_CMD_TYPE_OFFSET(DSS_CMD_ADD_VOLUME)] = "add volume",
    [DSS_CMD_TYPE_OFFSET(DSS_CMD_REMOVE_VOLUME)] = "remove volume",
    [DSS_CMD_TYPE_OFFSET(DSS_CMD_REFRESH_VOLUME)] = "refresh volume",
    [DSS_CMD_TYPE_OFFSET(DSS_CMD_KICKH)] = "kick off host",
    [DSS_CMD_TYPE_OFFSET(DSS_CMD_LOAD_CTRL)] = "load ctrl",
    [DSS_CMD_TYPE_OFFSET(DSS_CMD_SET_SESSIONID)] = "set session id",
    [DSS_CMD_TYPE_OFFSET(DSS_CMD_UPDATE_WRITTEN_SIZE)] = "update written size",
    [DSS_CMD_TYPE_OFFSET(DSS_CMD_STOP_SERVER)] = "stopserver",
    [DSS_CMD_TYPE_OFFSET(DSS_CMD_SETCFG)] = "setcfg",
    [DSS_CMD_TYPE_OFFSET(DSS_CMD_SET_STATUS)] = "setstatus",
    [DSS_CMD_TYPE_OFFSET(DSS_CMD_SYMLINK)] = "symlink",
    [DSS_CMD_TYPE_OFFSET(DSS_CMD_UNLINK)] = "unlink",
    [DSS_CMD_TYPE_OFFSET(DSS_CMD_GET_HOME)] = "get home",
    [DSS_CMD_TYPE_OFFSET(DSS_CMD_EXIST_FILE)] = "exist file",
    [DSS_CMD_TYPE_OFFSET(DSS_CMD_EXIST_DIR)] = "exist dir",
    [DSS_CMD_TYPE_OFFSET(DSS_CMD_ISLINK)] = "is link",
    [DSS_CMD_TYPE_OFFSET(DSS_CMD_READLINK)] = "readlink",
    [DSS_CMD_TYPE_OFFSET(DSS_CMD_GET_FTID_BY_PATH)] = "get ftid by path",
    [DSS_CMD_TYPE_OFFSET(DSS_CMD_GETCFG)] = "getcfg",
    [DSS_CMD_TYPE_OFFSET(DSS_CMD_EXEC_REMOTE)] = "exec remote",
};

char *dss_get_cmd_desc(dss_cmd_type_e cmd_type)
{
    if (cmd_type < DSS_CMD_BEGIN || cmd_type >= DSS_CMD_END) {
        return "unknown";
    }
    return g_dss_cmd_desc[DSS_CMD_TYPE_OFFSET(cmd_type)];
}

void cm_decode_time(time_t time, date_detail_t *detail)
{
    struct tm now_time;
    (void)dss_localtime(&time, &now_time);
    detail->year = (uint16)now_time.tm_year + DSS_BASE_YEAR;
    detail->mon = (uint8)now_time.tm_mon + 1;
    detail->day = (uint8)now_time.tm_mday;
    detail->hour = (uint8)now_time.tm_hour;
    detail->min = (uint8)now_time.tm_min;
    detail->sec = (uint8)now_time.tm_sec;
    detail->millisec = 0;
    detail->microsec = 0;
    detail->nanosec = 0;
}

time_t cm_encode_time(date_detail_t *detail)
{
    struct tm now_time;

    now_time.tm_year = (int)detail->year - DSS_BASE_YEAR;
    now_time.tm_mon = (int)detail->mon - 1;
    now_time.tm_mday = (int)detail->day;
    now_time.tm_hour = (int)detail->hour;
    now_time.tm_min = (int)detail->min;
    now_time.tm_sec = (int)detail->sec;
    now_time.tm_isdst = 0;

    return mktime(&now_time);
}

time_t cm_date2time(date_t date)
{
    date_detail_t detail;

    cm_decode_date(date, &detail);
    return cm_encode_time(&detail);
}

static status_t cm_time2text(time_t time, text_t *fmt, text_t *text, uint32 text_str_max_size)
{
    date_detail_t detail;
    text_t format_text;

    CM_ASSERT(fmt != NULL);
    CM_ASSERT(text != NULL);
    cm_decode_time(time, &detail);

    if (fmt == NULL || fmt->str == NULL) {
        return CM_ERROR;
    } else {
        format_text = *fmt;
    }

    return cm_detail2text(&detail, &format_text, CM_MAX_DATETIME_PRECISION, text, text_str_max_size);
}

status_t cm_time2str(time_t time, const char *fmt, char *str, uint32 str_max_size)
{
    text_t fmt_text, time_text;
    cm_str2text((char *)fmt, &fmt_text);
    time_text.str = str;
    time_text.len = 0;

    return cm_time2text(time, &fmt_text, &time_text, str_max_size);
}

void cm_destroy_thread_lock(thread_lock_t *lock)
{
    CM_ASSERT(lock != NULL);
#ifdef WIN32
    DeleteCriticalSection(lock);
#else
    (void)pthread_mutex_destroy(lock);
#endif
}

static bool32 dss_is_err(const char *err)
{
    if (err == NULL) {
        return CM_FALSE;
    }

    while (*err != '\0') {
        if (*err != ' ') {
            return CM_TRUE;
        }
        err++;
    }

    return CM_FALSE;
}

static status_t cm_str2real(const char *str, double *value)
{
    char *err = NULL;
    *value = strtod(str, &err);
    if (dss_is_err(err)) {
        CM_THROW_ERROR_EX(ERR_VALUE_ERROR, "Convert double failed, text = %s", str);
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

static status_t cm_text2real(const text_t *text_src, double *value)
{
    char buf[DSS_MAX_REAL_INPUT_STRLEN + 1] = {0};
    text_t text = *text_src;

    cm_trim_text(&text);

    if (text.len > DSS_MAX_REAL_INPUT_STRLEN) {
        CM_THROW_ERROR_EX(ERR_DSS_STRING_TOO_LONG,
            "Convert double failed, the length(%u) of text can't be larger than %u, text = %s", text.len,
            DSS_MAX_REAL_INPUT_STRLEN, T2S(&text));
        return ERR_DSS_STRING_TOO_LONG;
    }
    CM_RETURN_IFERR(cm_text2str(&text, buf, DSS_MAX_REAL_INPUT_STRLEN + 1));

    return cm_str2real(buf, value);
}

status_t cm_text2size(const text_t *text, int64 *value)
{
    text_t num = *text;
    uint64 unit = 1;
    double size;

    if (text->len < 2) {
        *value = 0;
        return CM_SUCCESS;
    }
    switch (CM_TEXT_END(text)) {
        case 'k':
        case 'K':
            unit <<= 10;
            break;

        case 'm':
        case 'M':
            unit <<= 20;
            break;

        case 'g':
        case 'G':
            unit <<= 30;
            break;

        case 't':
        case 'T':
            unit <<= 40;
            break;

        case 'p':
        case 'P':
            unit <<= 50;
            break;

        case 'e':
        case 'E':
            unit <<= 60;
            break;

        default:
        case 'b':
        case 'B':
            break;
    }

    if (unit != 1) {
        num.len--;
    }

    CM_RETURN_IFERR(cm_text2real(&num, &size));
    *value = (int64)(size * unit);
    return CM_SUCCESS;
}

status_t cm_str2size(const char *str, int64 *value)
{
    text_t text;
    cm_str2text((char *)str, &text);
    return cm_text2size(&text, value);
}

status_t cm_str2int(const char *str, int32 *value)
{
    char *err = NULL;
    int64 val_int64 = strtol(str, &err, CM_DEFAULT_DIGIT_RADIX);
    if (dss_is_err(err)) {
        CM_THROW_ERROR_EX(ERR_VALUE_ERROR, "Convert int failed, text = %s", str);
        return CM_ERROR;
    }

    if (val_int64 > INT_MAX || val_int64 < INT_MIN) {
        CM_THROW_ERROR_EX(
            ERR_VALUE_ERROR, "Convert int failed, the number text is not in the range of int, text = %s", str);
        return CM_ERROR;
    }

    *value = (int32)val_int64;
    return CM_SUCCESS;
}

status_t cm_str2bigint(const char *str, int64 *value)
{
    char *err = NULL;
    *value = strtoll(str, &err, CM_DEFAULT_DIGIT_RADIX);
    if (dss_is_err(err)) {
        CM_THROW_ERROR_EX(ERR_VALUE_ERROR, "Convert int64 failed, text = %s", str);
        return CM_ERROR;
    }
    // if str = "9223372036854775808", *value will be LLONG_MAX
    if (*value == LLONG_MAX || *value == LLONG_MIN) {
        if (strcmp(str, (const char *)SIGNED_LLONG_MIN) != 0 && strcmp(str, (const char *)SIGNED_LLONG_MAX) != 0) {
            CM_THROW_ERROR_EX(ERR_VALUE_ERROR,
                "Convert int64 failed, the number text is not in the range of signed long long, text = %s", str);
            return CM_ERROR;
        }
    }

    return CM_SUCCESS;
}

status_t cm_text2bigint(const text_t *text_src, int64 *value)
{
    char buf[CM_MAX_NUMBER_LEN + 1] = {0};  // '00000000000000000000000000000001'
    text_t text = *text_src;

    cm_trim_text(&text);

    if (text.len > CM_MAX_NUMBER_LEN) {
        CM_THROW_ERROR_EX(ERR_SYSTEM_CALL,
            "Convert int64 failed, the length of text can't be larger than %u, text = %s", CM_MAX_NUMBER_LEN,
            T2S(&text));
        return CM_ERROR;
    }

    CM_RETURN_IFERR(cm_text2str(&text, buf, CM_MAX_NUMBER_LEN + 1));
    return cm_str2bigint(buf, value);
}
