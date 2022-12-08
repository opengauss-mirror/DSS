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
 * dss_param_verify.c
 *
 *
 * IDENTIFICATION
 *    src/common/dss_param_verify.c
 *
 * -------------------------------------------------------------------------
 */

#include "cm_num.h"
#include "cm_utils.h"
#include "dss_defs.h"
#include "dss_errno.h"
#include "dss_param.h"
#include "dss_param_verify.h"

#ifdef __cplusplus
extern "C" {
#endif

status_t dss_verify_log_level(void *lex, void *def)
{
    char *value = (char *)lex;
    uint32 num;
    text_t text = {.str = value, .len = (uint32)strlen(value)};
    cm_trim_text(&text);
    status_t status = cm_text2uint32(&text, &num);
    DSS_RETURN_IFERR2(status, CM_THROW_ERROR(ERR_INVALID_PARAM, "_LOG_LEVEL"));

    if (num > MAX_LOG_LEVEL) {
        CM_THROW_ERROR(ERR_INVALID_PARAM, "_LOG_LEVEL");
        return CM_ERROR;
    }

    int32 iret_snprintf =
        snprintf_s(((dss_def_t *)def)->value, CM_PARAM_BUFFER_SIZE, CM_PARAM_BUFFER_SIZE - 1, PRINT_FMT_UINT32, num);
    DSS_SECUREC_SS_RETURN_IF_ERROR(iret_snprintf, CM_ERROR);
    return CM_SUCCESS;
}

status_t dss_notify_log_level(void *se, void *item, char *value)
{
    CM_RETURN_IFERR(cm_str2uint32(value, (uint32 *)&cm_log_param_instance()->log_level));
    return CM_SUCCESS;
}

status_t dss_verify_lock_file_path(char *path)
{
    char input_path_buffer[DSS_UNIX_PATH_MAX];
    char *input_path = NULL;
    uint32 len;
    len = (uint32)strlen(path);
    if (len == 0 || len >= DSS_UNIX_PATH_MAX) {
        DSS_THROW_ERROR(ERR_INVALID_FILE_NAME, path, DSS_UNIX_PATH_MAX);
        return CM_ERROR;
    }

    if (len == 1 && (path[0] == '.' || path[0] == '\t')) {
        DSS_THROW_ERROR(ERR_INVALID_DIR, path);
        return CM_ERROR;
    }

    input_path = input_path_buffer;
    MEMS_RETURN_IFERR(strcpy_s(input_path, DSS_UNIX_PATH_MAX, path));
    if (len > 1 && (CM_IS_QUOTE_STRING(input_path[0], input_path[len - 1]))) {
        input_path++;
        len -= CM_SINGLE_QUOTE_LEN;
    }

    if (len == 0 || input_path[0] == ' ') {
        DSS_THROW_ERROR(ERR_INVALID_DIR, path);
        return CM_ERROR;
    }

    input_path[len] = '\0';
    if (cm_check_exist_special_char(input_path, len)) {
        DSS_THROW_ERROR(ERR_INVALID_DIR, input_path);
        return CM_ERROR;
    }

    char buffer_path[DSS_UNIX_PATH_MAX];
    CM_RETURN_IFERR(realpath_file(input_path, buffer_path, CM_FILE_NAME_BUFFER_SIZE));
    if (!cm_dir_exist(input_path) || (access(buffer_path, W_OK | R_OK) != 0)) {
        DSS_THROW_ERROR(ERR_INVALID_DIR, input_path);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

status_t dss_verify_lsnr_path(char *path)
{
    uint32 len = (uint32)strlen(path);
    if (len == 1 && (path[0] == '.' || path[0] == '\t')) {
        DSS_THROW_ERROR(ERR_INVALID_DIR, path);
        return CM_ERROR;
    }
    uint32 max_len = DSS_UNIX_PATH_MAX - (uint32)strlen(DSS_UNIX_DOMAIN_SOCKET_NAME);
    if (len >= max_len) {
        DSS_THROW_ERROR(ERR_INVALID_FILE_NAME, path, max_len);
        return CM_ERROR;
    }
    char input_path_buffer[DSS_UNIX_PATH_MAX];
    char *input_path = input_path_buffer;
    MEMS_RETURN_IFERR(strcpy_s(input_path_buffer, DSS_UNIX_PATH_MAX, path));
    if (len > 1 && (CM_IS_QUOTE_STRING(input_path[0], input_path[len - 1]))) {
        input_path++;
        len -= CM_SINGLE_QUOTE_LEN;
    }
    if (len == 0 || input_path[0] == ' ') {
        DSS_THROW_ERROR(ERR_INVALID_DIR, input_path);
        return CM_ERROR;
    }
    input_path[len] = '\0';
    if (cm_check_uds_path_special_char(input_path, len)) {
        DSS_THROW_ERROR(ERR_INVALID_DIR, input_path);
        return CM_ERROR;
    }
    char realfile[DSS_UNIX_PATH_MAX];
    CM_RETURN_IFERR(realpath_file(input_path, realfile, DSS_UNIX_PATH_MAX));
    if (!cm_dir_exist((const char *)realfile)) {
        DSS_THROW_ERROR(ERR_INVALID_DIR, input_path);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}
status_t dss_verify_log_file_dir(char *path)
{
    char input_path_buffer[CM_MAX_LOG_HOME_LEN];
    char *input_path = NULL;
    uint32 len;
    len = (uint32)strlen(path);
    if (len == 0 || len >= CM_MAX_LOG_HOME_LEN) {
        DSS_THROW_ERROR(ERR_INVALID_FILE_NAME, path, CM_MAX_LOG_HOME_LEN);
        return CM_ERROR;
    }

    if (len == 1 && (path[0] == '.' || path[0] == '\t')) {
        DSS_THROW_ERROR(ERR_INVALID_DIR, path);
        return CM_ERROR;
    }

    input_path = input_path_buffer;
    MEMS_RETURN_IFERR(strcpy_s(input_path, CM_MAX_LOG_HOME_LEN, path));
    if (len > 1 && (CM_IS_QUOTE_STRING(input_path[0], input_path[len - 1]))) {
        input_path++;
        len -= CM_SINGLE_QUOTE_LEN;
    }

    if (len == 0 || input_path[0] == ' ') {
        DSS_THROW_ERROR(ERR_INVALID_DIR, path);
        return CM_ERROR;
    }

    input_path[len] = '\0';
    if (cm_check_exist_special_char(input_path, len)) {
        DSS_THROW_ERROR(ERR_INVALID_DIR, input_path);
        return CM_ERROR;
    }

    char real_path[CM_MAX_LOG_HOME_LEN] = {0};
    CM_RETURN_IFERR(realpath_file(path, real_path, CM_MAX_LOG_HOME_LEN));
    if (!cm_dir_exist(path)) {
        CM_THROW_ERROR(ERR_INVALID_DIR, path);
        return CM_ERROR;
    }
    if (access(path, W_OK | R_OK) != 0) {
        CM_THROW_ERROR(ERR_INVALID_DIR, path);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

status_t dss_verify_log_file_size(void *lex, void *def)
{
    char *value = (char *)lex;
    uint64 num;
    text_t text = {.str = value, .len = (uint32)strlen(value)};
    cm_trim_text(&text);
    status_t status = cm_text2size(&text, (int64 *)&num);
    DSS_RETURN_IFERR2(status, DSS_THROW_ERROR(ERR_DSS_INVALID_PARAM, "_LOG_MAX_FILE_SIZE"));
    if (num < CM_MIN_LOG_FILE_SIZE || num > CM_MAX_LOG_FILE_SIZE) {
        DSS_THROW_ERROR(ERR_DSS_INVALID_PARAM, "_LOG_MAX_FILE_SIZE");
        return CM_ERROR;
    }

    int32 iret_snprintf =
        snprintf_s(((dss_def_t *)def)->value, CM_PARAM_BUFFER_SIZE, CM_PARAM_BUFFER_SIZE - 1, PRINT_FMT_UINT64, num);
    DSS_SECUREC_SS_RETURN_IF_ERROR(iret_snprintf, CM_ERROR);
    return CM_SUCCESS;
}

status_t dss_notify_log_file_size(void *se, void *item, char *value)
{
    CM_RETURN_IFERR(cm_str2size(value, (int64 *)&cm_log_param_instance()->max_log_file_size));
    return CM_SUCCESS;
}

status_t dss_verify_log_backup_file_count(void *lex, void *def)
{
    char *value = (char *)lex;
    uint32 num;
    text_t text = {.str = value, .len = (uint32)strlen(value)};
    cm_trim_text(&text);
    if (cm_text2uint32(&text, &num) != CM_SUCCESS) {
        DSS_THROW_ERROR(ERR_DSS_INVALID_PARAM, "_LOG_BACKUP_FILE_COUNT");
        return CM_ERROR;
    }
    if (num > CM_MAX_LOG_FILE_COUNT) {
        DSS_THROW_ERROR(ERR_DSS_INVALID_PARAM, "_LOG_BACKUP_FILE_COUNT");
        return CM_ERROR;
    }

    int32 iret_snprintf =
        snprintf_s(((dss_def_t *)def)->value, CM_PARAM_BUFFER_SIZE, CM_PARAM_BUFFER_SIZE - 1, PRINT_FMT_UINT32, num);
    DSS_SECUREC_SS_RETURN_IF_ERROR(iret_snprintf, CM_ERROR);
    return CM_SUCCESS;
}

status_t dss_notify_log_backup_file_count(void *se, void *item, char *value)
{
    CM_RETURN_IFERR(cm_str2uint32(value, (uint32 *)&cm_log_param_instance()->log_backup_file_count));
    return CM_SUCCESS;
}

status_t dss_verify_audit_backup_file_count(void *lex, void *def)
{
    char *value = (char *)lex;
    uint32 num;
    text_t text = {.str = value, .len = (uint32)strlen(value)};
    cm_trim_text(&text);
    status_t status = cm_text2uint32(&text, &num);
    DSS_RETURN_IFERR2(status, DSS_THROW_ERROR(ERR_DSS_INVALID_PARAM, "_AUDIT_BACKUP_FILE_COUNT"));
    if (num > CM_MAX_LOG_FILE_COUNT) {
        DSS_THROW_ERROR(ERR_DSS_INVALID_PARAM, "_AUDIT_BACKUP_FILE_COUNT");
        return CM_ERROR;
    }

    int32 iret_snprintf =
        snprintf_s(((dss_def_t *)def)->value, CM_PARAM_BUFFER_SIZE, CM_PARAM_BUFFER_SIZE - 1, PRINT_FMT_UINT32, num);
    DSS_SECUREC_SS_RETURN_IF_ERROR(iret_snprintf, CM_ERROR);
    return CM_SUCCESS;
}

status_t dss_notify_audit_backup_file_count(void *se, void *item, char *value)
{
    CM_RETURN_IFERR(cm_str2uint32(value, (uint32 *)&cm_log_param_instance()->audit_backup_file_count));
    return CM_SUCCESS;
}

status_t dss_verify_audit_file_size(void *lex, void *def)
{
    char *value = (char *)lex;
    uint64 num;
    text_t text = {.str = value, .len = (uint32)strlen(value)};
    cm_trim_text(&text);
    status_t status = cm_text2size(&text, (int64 *)&num);
    DSS_RETURN_IFERR2(status, DSS_THROW_ERROR(ERR_DSS_INVALID_PARAM, "_AUDIT_MAX_FILE_SIZE"));
    if (num < CM_MIN_LOG_FILE_SIZE || num > CM_MAX_LOG_FILE_SIZE) {
        DSS_THROW_ERROR(ERR_DSS_INVALID_PARAM, "_AUDIT_MAX_FILE_SIZE");
        return CM_ERROR;
    }

    int32 iret_snprintf =
        snprintf_s(((dss_def_t *)def)->value, CM_PARAM_BUFFER_SIZE, CM_PARAM_BUFFER_SIZE - 1, PRINT_FMT_UINT64, num);
    DSS_SECUREC_SS_RETURN_IF_ERROR(iret_snprintf, CM_ERROR);
    return CM_SUCCESS;
}

status_t dss_notify_audit_file_size(void *se, void *item, char *value)
{
    CM_RETURN_IFERR(cm_str2size(value, (int64 *)&cm_log_param_instance()->max_audit_file_size));
    return CM_SUCCESS;
}

status_t dss_verify_audit_level(void *lex, void *def)
{
    char *value = (char *)lex;
    uint32 num;
    text_t text = {.str = value, .len = (uint32)strlen(value)};
    cm_trim_text(&text);
    if (cm_text2uint32(&text, &num) != CM_SUCCESS) {
        CM_THROW_ERROR(ERR_INVALID_PARAM, "_AUDIT_LEVEL");
        return CM_ERROR;
    }

    if (num > DSS_AUDIT_ALL) {
        CM_THROW_ERROR(ERR_INVALID_PARAM, "_AUDIT_LEVEL");
        return CM_ERROR;
    }

    int32 iret_snprintf =
        snprintf_s(((dss_def_t *)def)->value, CM_PARAM_BUFFER_SIZE, CM_PARAM_BUFFER_SIZE - 1, PRINT_FMT_UINT32, num);
    DSS_SECUREC_SS_RETURN_IF_ERROR(iret_snprintf, CM_ERROR);
    return CM_SUCCESS;
}

status_t dss_notify_audit_level(void *se, void *item, char *value)
{
    CM_RETURN_IFERR(cm_str2uint32(value, (uint32 *)&cm_log_param_instance()->audit_level));
    return CM_SUCCESS;
}

#ifdef __cplusplus
}
#endif
