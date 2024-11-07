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
 *    src/params/dss_param_verify.c
 *
 * -------------------------------------------------------------------------
 */

#include "cm_num.h"
#include "cm_utils.h"
#include "dss_defs.h"
#include "dss_errno.h"
#include "dss_param.h"
#include "dss_fault_injection.h"
#include "dss_ga.h"
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
        DSS_RETURN_IFERR2(CM_ERROR, CM_THROW_ERROR(ERR_INVALID_PARAM, "_LOG_LEVEL"));
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

status_t dss_verify_enable_core_state_collect(void *lex, void *def)
{
    char *value = (char *)lex;
    if (!cm_str_equal_ins(value, "TRUE") && !cm_str_equal_ins(value, "FALSE")) {
        DSS_RETURN_IFERR2(CM_ERROR, DSS_THROW_ERROR(ERR_DSS_INVALID_PARAM, "_ENABLE_CORE_STATE_COLLECT"));
    }
    int32 iret_snprintf =
        snprintf_s(((dss_def_t *)def)->value, CM_PARAM_BUFFER_SIZE, CM_PARAM_BUFFER_SIZE - 1, "%s", value);
    DSS_SECUREC_SS_RETURN_IF_ERROR(iret_snprintf, CM_ERROR);
    return CM_SUCCESS;
}

status_t dss_notify_enable_core_state_collect(void *se, void *item, char *value)
{
    return dss_load_enable_core_state_collect_inner(value, g_inst_cfg);
}

status_t dss_verify_blackbox_detail_on(void *lex, void *def)
{
    char *value = (char *)lex;
    if (!cm_str_equal_ins(value, "TRUE") && !cm_str_equal_ins(value, "FALSE")) {
        DSS_RETURN_IFERR2(CM_ERROR, CM_THROW_ERROR(ERR_INVALID_PARAM, "_BLACKBOX_DETAIL_ON"));
    }
    int32 iret_snprintf =
        snprintf_s(((dss_def_t *)def)->value, CM_PARAM_BUFFER_SIZE, CM_PARAM_BUFFER_SIZE - 1, "%s", value);
    DSS_SECUREC_SS_RETURN_IF_ERROR(iret_snprintf, CM_ERROR);
    return CM_SUCCESS;
}

status_t dss_notify_blackbox_detail_on(void *se, void *item, char *value)
{
    return dss_load_blackbox_detail_on_inner(value, g_inst_cfg);
}

status_t dss_verify_delay_clean_interval(void *lex, void *def)
{
    char *value = (char *)lex;
    uint32 delay_clean_interval;

    status_t status = cm_str2uint32(value, &delay_clean_interval);
    DSS_RETURN_IFERR2(status, DSS_THROW_ERROR(ERR_DSS_INVALID_PARAM, "DELAY_CLEAN_INTERVAL"));
    if (delay_clean_interval < DSS_MIN_DELAY_CLEAN_INTERVAL || delay_clean_interval > DSS_MAX_DELAY_CLEAN_INTERVAL) {
        DSS_RETURN_IFERR2(CM_ERROR, DSS_THROW_ERROR(ERR_DSS_INVALID_PARAM, "DELAY_CLEAN_INTERVAL"));
    }

    int32 iret_snprintf = snprintf_s(((dss_def_t *)def)->value, CM_PARAM_BUFFER_SIZE, CM_PARAM_BUFFER_SIZE - 1,
        PRINT_FMT_UINT32, delay_clean_interval);
    DSS_SECUREC_SS_RETURN_IF_ERROR(iret_snprintf, CM_ERROR);
    return CM_SUCCESS;
}

status_t dss_notify_delay_clean_interval(void *se, void *item, char *value)
{
    return dss_load_delay_clean_interval_core(value, g_inst_cfg);
}

status_t dss_verify_lock_file_path(char *path)
{
    char input_path_buffer[DSS_UNIX_PATH_MAX];
    char *input_path = NULL;
    uint32 len;
    len = (uint32)strlen(path);
    if (len == 0 || len >= DSS_UNIX_PATH_MAX) {
        DSS_RETURN_IFERR2(CM_ERROR, DSS_THROW_ERROR(ERR_INVALID_FILE_NAME, path, DSS_UNIX_PATH_MAX));
    }

    if (len == 1 && (path[0] == '.' || path[0] == '\t')) {
        DSS_RETURN_IFERR2(CM_ERROR, DSS_THROW_ERROR(ERR_INVALID_DIR, path));
    }

    input_path = input_path_buffer;
    MEMS_RETURN_IFERR(strcpy_s(input_path, DSS_UNIX_PATH_MAX, path));
    if (len > 1 && (CM_IS_QUOTE_STRING(input_path[0], input_path[len - 1]))) {
        input_path++;
        len -= CM_SINGLE_QUOTE_LEN;
    }

    if (len == 0 || input_path[0] == ' ') {
        DSS_RETURN_IFERR2(CM_ERROR, DSS_THROW_ERROR(ERR_INVALID_DIR, path));
    }

    input_path[len] = '\0';
    if (cm_check_exist_special_char(input_path, len)) {
        DSS_RETURN_IFERR2(CM_ERROR, DSS_THROW_ERROR(ERR_INVALID_DIR, input_path));
    }

    char buffer_path[DSS_UNIX_PATH_MAX];
    CM_RETURN_IFERR(realpath_file(input_path, buffer_path, DSS_UNIX_PATH_MAX));
    if (!cm_dir_exist(input_path) || (access(buffer_path, W_OK | R_OK) != 0)) {
        DSS_RETURN_IFERR2(CM_ERROR, DSS_THROW_ERROR(ERR_INVALID_DIR, input_path));
    }
    return CM_SUCCESS;
}

status_t dss_verify_lsnr_path(char *path)
{
    uint32 len = (uint32)strlen(path);
    if (len == 1 && (path[0] == '.' || path[0] == '\t')) {
        DSS_RETURN_IFERR2(CM_ERROR, DSS_THROW_ERROR(ERR_INVALID_DIR, path));
    }
    uint32 max_len = DSS_MAX_PATH_BUFFER_SIZE - (uint32)strlen(DSS_UNIX_DOMAIN_SOCKET_NAME);
    if (len >= max_len) {
        DSS_RETURN_IFERR2(CM_ERROR, DSS_THROW_ERROR(ERR_INVALID_FILE_NAME, path, max_len));
    }
    char input_path_buffer[DSS_MAX_PATH_BUFFER_SIZE];
    char *input_path = input_path_buffer;
    MEMS_RETURN_IFERR(strcpy_s(input_path_buffer, DSS_MAX_PATH_BUFFER_SIZE, path));
    if (len > 1 && (CM_IS_QUOTE_STRING(input_path[0], input_path[len - 1]))) {
        input_path++;
        len -= CM_SINGLE_QUOTE_LEN;
    }
    if (len == 0 || input_path[0] == ' ') {
        DSS_RETURN_IFERR2(CM_ERROR, DSS_THROW_ERROR(ERR_INVALID_DIR, input_path));
    }
    input_path[len] = '\0';
    if (cm_check_uds_path_special_char(input_path, len)) {
        DSS_RETURN_IFERR2(CM_ERROR, DSS_THROW_ERROR(ERR_INVALID_DIR, input_path));
    }
    char realfile[DSS_MAX_PATH_BUFFER_SIZE];
    CM_RETURN_IFERR(realpath_file(input_path, realfile, DSS_MAX_PATH_BUFFER_SIZE));
    if (!cm_dir_exist((const char *)realfile)) {
        DSS_RETURN_IFERR2(CM_ERROR, DSS_THROW_ERROR(ERR_INVALID_DIR, input_path));
    }
    return CM_SUCCESS;
}
status_t dss_verify_log_file_dir_name(char *path)
{
    char input_path_buffer[CM_MAX_LOG_HOME_LEN];
    char *input_path = NULL;
    uint32 len;
    len = (uint32)strlen(path);
    if (len == 0 || len >= CM_MAX_LOG_HOME_LEN) {
        DSS_RETURN_IFERR2(CM_ERROR, DSS_THROW_ERROR(ERR_INVALID_FILE_NAME, path, CM_MAX_LOG_HOME_LEN));
    }

    if (len == 1 && (path[0] == '.' || path[0] == '\t')) {
        DSS_RETURN_IFERR2(CM_ERROR, DSS_THROW_ERROR(ERR_INVALID_DIR, path));
    }

    input_path = input_path_buffer;
    MEMS_RETURN_IFERR(strcpy_s(input_path, CM_MAX_LOG_HOME_LEN, path));
    if (len > 1 && (CM_IS_QUOTE_STRING(input_path[0], input_path[len - 1]))) {
        input_path++;
        len -= CM_SINGLE_QUOTE_LEN;
    }

    if (len == 0 || input_path[0] == ' ') {
        DSS_RETURN_IFERR2(CM_ERROR, DSS_THROW_ERROR(ERR_INVALID_DIR, path));
    }

    input_path[len] = '\0';
    if (cm_check_exist_special_char(input_path, len)) {
        DSS_RETURN_IFERR2(CM_ERROR, DSS_THROW_ERROR(ERR_INVALID_DIR, input_path));
    }
    return CM_SUCCESS;
}

status_t dss_verify_log_file_real_path(char *path)
{
    char real_path[CM_MAX_LOG_HOME_LEN] = {0};
    CM_RETURN_IFERR(realpath_file(path, real_path, CM_MAX_LOG_HOME_LEN));
    if (!cm_dir_exist(path) && cm_create_dir_ex(path) != CM_SUCCESS) {
        DSS_RETURN_IFERR2(CM_ERROR, CM_THROW_ERROR(ERR_INVALID_DIR, path));
    }
    if (access(path, W_OK | R_OK) != 0) {
        DSS_RETURN_IFERR2(CM_ERROR, CM_THROW_ERROR(ERR_INVALID_DIR, path));
    }
    return CM_SUCCESS;
}

status_t dss_verify_log_file_size(void *lex, void *def)
{
    char *value = (char *)lex;
    uint64 num;
    text_t text = {.str = value, .len = (uint32)strlen(value)};
    cm_trim_text(&text);

    // The last char of _LOG_MAX_FILE_SIZE is size unit, which should not be checked for number.
    char unit = text.str[text.len - 1];
    text.str[text.len - 1] = '\0';
    if (cm_check_is_number(text.str) != CM_SUCCESS) {
        CM_THROW_ERROR_EX(ERR_VALUE_ERROR, "The text for _LOG_MAX_FILE_SIZE is not integer, text = %s", text.str);
        return CM_ERROR;
    }
    text.str[text.len - 1] = unit;

    status_t status = cm_text2size(&text, (int64 *)&num);
    DSS_RETURN_IFERR2(status, DSS_THROW_ERROR(ERR_DSS_INVALID_PARAM, "_LOG_MAX_FILE_SIZE"));
    if (num < CM_MIN_LOG_FILE_SIZE || num > CM_MAX_LOG_FILE_SIZE) {
        DSS_THROW_ERROR(ERR_DSS_INVALID_PARAM, "_LOG_MAX_FILE_SIZE");
        return CM_ERROR;
    }

    int32 iret_snprintf =
        snprintf_s(((dss_def_t *)def)->value, CM_PARAM_BUFFER_SIZE, CM_PARAM_BUFFER_SIZE - 1, "%s", T2S(&text));
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
    status_t status = cm_text2uint32(&text, &num);
    DSS_RETURN_IFERR2(status, DSS_THROW_ERROR(ERR_DSS_INVALID_PARAM, "_LOG_BACKUP_FILE_COUNT"));
#ifdef OPENGAUSS
    if (num > CM_MAX_LOG_FILE_COUNT_LARGER) {
#else
    if (num > CM_MAX_LOG_FILE_COUNT) {
#endif
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
#ifdef OPENGAUSS
    if (num > CM_MAX_LOG_FILE_COUNT_LARGER) {
#else
    if (num > CM_MAX_LOG_FILE_COUNT) {
#endif
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

    // The last char of _AUDIT_FILE_SIZE is size unit, which should not be checked for number.
    char unit = text.str[text.len - 1];
    text.str[text.len - 1] = '\0';
    if (cm_check_is_number(text.str) != CM_SUCCESS) {
        CM_THROW_ERROR_EX(ERR_VALUE_ERROR, "The text for _AUDIT_MAX_FILE_SIZE is not integer, text = %s", text.str);
        return CM_ERROR;
    }
    text.str[text.len - 1] = unit;

    status_t status = cm_text2size(&text, (int64 *)&num);
    DSS_RETURN_IFERR2(status, DSS_THROW_ERROR(ERR_DSS_INVALID_PARAM, "_AUDIT_MAX_FILE_SIZE"));
    if (num < CM_MIN_LOG_FILE_SIZE || num > CM_MAX_LOG_FILE_SIZE) {
        DSS_THROW_ERROR(ERR_DSS_INVALID_PARAM, "_AUDIT_MAX_FILE_SIZE");
        return CM_ERROR;
    }

    int32 iret_snprintf =
        snprintf_s(((dss_def_t *)def)->value, CM_PARAM_BUFFER_SIZE, CM_PARAM_BUFFER_SIZE - 1, "%s", T2S(&text));
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
    status_t status = cm_text2uint32(&text, &num);
    DSS_RETURN_IFERR2(status, CM_THROW_ERROR(ERR_INVALID_PARAM, "_AUDIT_LEVEL"));

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

status_t dss_verify_cluster_run_mode(void *lex, void *def)
{
    char *value = (char *)lex;
    if (cm_strcmpi(value, "cluster_standby") != 0 && cm_strcmpi(value, "cluster_primary") != 0) {
        DSS_THROW_ERROR(ERR_DSS_INVALID_PARAM, "CLUSTER_RUN_MODE");
        return CM_ERROR;
    }

    int32 iret_snprintf =
        snprintf_s(((dss_def_t *)def)->value, CM_PARAM_BUFFER_SIZE, CM_PARAM_BUFFER_SIZE - 1, "%s", value);
    DSS_SECUREC_SS_RETURN_IF_ERROR(iret_snprintf, CM_ERROR);
    return CM_SUCCESS;
}

status_t dss_notify_cluster_run_mode(void *se, void *item, char *value)
{
    if (cm_strcmpi(value, "cluster_standby") == 0) {
        g_inst_cfg->params.cluster_run_mode = CLUSTER_STANDBY;
        LOG_RUN_INF("The cluster_run_mode is cluster_standby.");
    } else if (cm_strcmpi(value, "cluster_primary") == 0) {
        g_inst_cfg->params.cluster_run_mode = CLUSTER_PRIMARY;
        LOG_RUN_INF("The cluster_run_mode is cluster_primary.");
    } else {
        DSS_RETURN_IFERR2(
            CM_ERROR, DSS_THROW_ERROR(ERR_DSS_INVALID_PARAM, "failed to load params, invalid CLUSTER_RUN_MODE"));
    }
    return CM_SUCCESS;
}

#if defined(_DEBUG) || defined(DEBUG) || defined(DB_DEBUG_VERSION)
status_t dss_verify_fi_entity(void *lex, void *def)
{
    char *cfg_value = (char *)lex;
    int32 iret_snprintf =
        snprintf_s(((dss_def_t *)def)->value, CM_PARAM_BUFFER_SIZE, CM_PARAM_BUFFER_SIZE - 1, "%s", cfg_value);
    DSS_SECUREC_SS_RETURN_IF_ERROR(iret_snprintf, CM_ERROR);
    return CM_SUCCESS;
}

status_t dss_notify_fi_packet_loss_entity(void *se, void *item, char *value)
{
    return ddes_fi_parse_and_set_entry_list(DDES_FI_TYPE_PACKET_LOSS, value);
}

status_t dss_notify_fi_net_latency_entity(void *se, void *item, char *value)
{
    return ddes_fi_parse_and_set_entry_list(DDES_FI_TYPE_NET_LATENCY, value);
}

status_t dss_notify_fi_cpu_latency_entity(void *se, void *item, char *value)
{
    return ddes_fi_parse_and_set_entry_list(DDES_FI_TYPE_CPU_LATENCY, value);
}

status_t dss_notify_fi_process_fault_entity(void *se, void *item, char *value)
{
    return ddes_fi_parse_and_set_entry_list(DDES_FI_TYPE_PROCESS_FAULT, value);
}

status_t dss_notify_fi_custom_fault_entity(void *se, void *item, char *value)
{
    return ddes_fi_parse_and_set_entry_list(DDES_FI_TYPE_CUSTOM_FAULT, value);
}

status_t dss_verify_fi_value_base(char *cfg_value, char *cfg_name, unsigned int cfg_max)
{
    uint32 value;
    status_t status = cm_str2uint32(cfg_value, &value);
    DSS_RETURN_IFERR2(status, LOG_DEBUG_ERR("[dss_fi]invalid parameter value of '%s', value:%s.", cfg_name, cfg_value));
    if (cfg_max > 0 && value > cfg_max) {
        DSS_THROW_ERROR_EX(ERR_DSS_INVALID_PARAM,
            "[dss_fi]invalid parameter value of '%s', value:%s more than value:%u.", cfg_name, cfg_value, cfg_max);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

status_t dss_notify_fi_value_base(char *cfg_value, char *cfg_name, unsigned int cfg_type)
{
    uint32 value;
    CM_RETURN_IFERR(cm_str2uint32(cfg_value, (uint32 *)&value));

    status_t status = ddes_fi_set_entry_value(cfg_type, value);
    DSS_RETURN_IFERR2(status, LOG_DEBUG_ERR("[dss_fi]set parameter value of '%s', value:%s fail for type:%u.", cfg_name,
                                  cfg_value, cfg_type));
    return CM_SUCCESS;
}

static status_t dss_verify_fi_value_ex(void *lex, void *def, char *cfg_name, unsigned int cfg_max)
{
    char *cfg_value = (char *)lex;
    status_t status = dss_verify_fi_value_base(cfg_value, cfg_name, cfg_max);
    DSS_RETURN_IF_ERROR(status);

    int32 iret_snprintf =
        snprintf_s(((dss_def_t *)def)->value, CM_PARAM_BUFFER_SIZE, CM_PARAM_BUFFER_SIZE - 1, "%s", cfg_value);
    DSS_SECUREC_SS_RETURN_IF_ERROR(iret_snprintf, CM_ERROR);

    return CM_SUCCESS;
}

status_t dss_verify_fi_packet_loss_value(void *lex, void *def)
{
    return dss_verify_fi_value_ex(lex, def, "SS_FI_PACKET_LOSS_PROB", DSS_FI_MAX_PROBABILTY);
}

status_t dss_notify_fi_packet_loss_value(void *se, void *item, char *value)
{
    return dss_notify_fi_value_base(value, "SS_FI_PACKET_LOSS_PROB", DDES_FI_TYPE_PACKET_LOSS);
}

status_t dss_verify_fi_net_latency_value(void *lex, void *def)
{
    return dss_verify_fi_value_ex(lex, def, "SS_FI_NET_LATENCY_MS", 0);
}

status_t dss_notify_fi_net_latency_value(void *se, void *item, char *value)
{
    return dss_notify_fi_value_base(value, "SS_FI_NET_LATENCY_MS", DDES_FI_TYPE_NET_LATENCY);
}

status_t dss_verify_fi_cpu_latency_value(void *lex, void *def)
{
    return dss_verify_fi_value_ex(lex, def, "SS_FI_CPU_LATENCY_MS", 0);
}

status_t dss_notify_fi_cpu_latency_value(void *se, void *item, char *value)
{
    return dss_notify_fi_value_base(value, "SS_FI_CPU_LATENCY_MS", DDES_FI_TYPE_CPU_LATENCY);
}

status_t dss_verify_fi_process_fault_value(void *lex, void *def)
{
    return dss_verify_fi_value_ex(lex, def, "SS_FI_PROCESS_FAULT_PROB", DSS_FI_MAX_PROBABILTY);
}

status_t dss_notify_fi_process_fault_value(void *se, void *item, char *value)
{
    return dss_notify_fi_value_base(value, "SS_FI_PROCESS_FAULT_PROB", DDES_FI_TYPE_PROCESS_FAULT);
}

status_t dss_verify_fi_custom_fault_value(void *lex, void *def)
{
    return dss_verify_fi_value_ex(lex, def, "SS_FI_CUSTOM_FAULT_PARAM", 0);
}

status_t dss_notify_fi_custom_fault_value(void *se, void *item, char *value)
{
    return dss_notify_fi_value_base(value, "SS_FI_CUSTOM_FAULT_PARAM", DDES_FI_TYPE_CUSTOM_FAULT);
}

// for recycle meta begin
static status_t dss_verify_recycle_meta_pool_range_base(void *lex, void *def, char *cfg_name)
{
    char *value = (char *)lex;
    uint32 num;
    text_t text = {.str = value, .len = (uint32)strlen(value)};
    cm_trim_text(&text);
    status_t status = cm_text2uint32(&text, &num);
    DSS_RETURN_IFERR2(status, CM_THROW_ERROR(ERR_INVALID_PARAM, cfg_name));

    if (num > GA_USAGE_UNIT) {
        CM_THROW_ERROR(ERR_INVALID_PARAM, cfg_name);
        return CM_ERROR;
    }

    int32 iret_snprintf =
        snprintf_s(((dss_def_t *)def)->value, CM_PARAM_BUFFER_SIZE, CM_PARAM_BUFFER_SIZE - 1, PRINT_FMT_UINT32, num);
    DSS_SECUREC_SS_RETURN_IF_ERROR(iret_snprintf, CM_ERROR);
    return CM_SUCCESS;
}

status_t dss_verify_recycle_meta_pool_hwm(void *lex, void *def)
{
    return dss_verify_recycle_meta_pool_range_base(lex, def, "__RECYCLE_META_POOL_HWM");
}

status_t dss_verify_recycle_meta_pool_lwm(void *lex, void *def)
{
    return dss_verify_recycle_meta_pool_range_base(lex, def, "__RECYCLE_META_POOL_LWM");
}

status_t dss_notify_recycle_meta_pool_hwm(void *se, void *item, char *value)
{
    CM_RETURN_IFERR(cm_str2uint32(value, (uint32 *)&g_inst_cfg->params.recyle_meta_pos.hwm));
    LOG_DEBUG_INF("__RECYCLE_META_POOL_HWM new cfg value %u, unit is:0.01", g_inst_cfg->params.recyle_meta_pos.hwm);
    return CM_SUCCESS;
}

status_t dss_notify_recycle_meta_pool_lwm(void *se, void *item, char *value)
{
    CM_RETURN_IFERR(cm_str2uint32(value, (uint32 *)&g_inst_cfg->params.recyle_meta_pos.lwm));
    LOG_DEBUG_INF("__RECYCLE_META_POOL_LWM new cfg value %u, unit is:0.01", g_inst_cfg->params.recyle_meta_pos.lwm);
    return CM_SUCCESS;
}
// for recycle meta end
#endif

status_t dss_verify_mes_wait_timeout(void *lex, void *def)
{
    char *value = (char *)lex;
    uint32 num;
    text_t text = {.str = value, .len = (uint32)strlen(value)};
    cm_trim_text(&text);
    status_t status = cm_text2uint32(&text, &num);
    DSS_RETURN_IFERR2(status, CM_THROW_ERROR(ERR_INVALID_PARAM, "MES_WAIT_TIMEOUT"));

    if (num > DSS_MES_MAX_WAIT_TIMEOUT || num < DSS_MES_MIN_WAIT_TIMEOUT) {
        DSS_RETURN_IFERR2(CM_ERROR, CM_THROW_ERROR(ERR_INVALID_PARAM, "MES_WAIT_TIMEOUT"));
    }

    int32 iret_snprintf =
        snprintf_s(((dss_def_t *)def)->value, CM_PARAM_BUFFER_SIZE, CM_PARAM_BUFFER_SIZE - 1, PRINT_FMT_UINT32, num);
    DSS_SECUREC_SS_RETURN_IF_ERROR(iret_snprintf, CM_ERROR);
    return CM_SUCCESS;
}

status_t dss_notify_mes_wait_timeout(void *se, void *item, char *value)
{
    CM_RETURN_IFERR(cm_str2uint32(value, (uint32 *)&g_inst_cfg->params.mes_wait_timeout));
    return CM_SUCCESS;
}

#ifdef __cplusplus
}
#endif