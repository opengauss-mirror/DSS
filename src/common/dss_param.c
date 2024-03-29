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
 * dss_param.c
 *
 *
 * IDENTIFICATION
 *    src/common/dss_param.c
 *
 * -------------------------------------------------------------------------
 */

#include "dss_errno.h"
#include "cm_num.h"
#include "cm_ip.h"
#include "cm_encrypt.h"
#include "cm_utils.h"
#include "dss_malloc.h"
#include "dss_param_verify.h"
#include "dss_param.h"

#ifdef __cplusplus
extern "C" {
#endif

dss_config_t *g_inst_cfg = NULL;
dss_instance_status_e *g_dss_instance_status = NULL;
// clang-format off
static config_item_t g_dss_params[] = {
    /* name, isdefault, attr, default_value, value, runtime_value, description, range, datatype, comment,
    id, effect, scale, verify, notify, notify_pfile, alias */
    { "SSL_CERT_NOTIFY_TIME", CM_TRUE, CM_FALSE, "30", NULL, NULL, "-", "[7,180]",
        "GS_TYPE_INTEGER", NULL, 0, EFFECT_REBOOT, CFG_INS, NULL, NULL, NULL, NULL},
    { "DSS_CM_SO_NAME",           CM_TRUE, CM_FALSE, "", NULL, NULL, "-", "-",
      "GS_TYPE_VARCHAR", NULL, 1, EFFECT_REBOOT, CFG_INS, NULL, NULL, NULL, NULL },
    { "LSNR_PATH",                 CM_TRUE, CM_FALSE, "/tmp/", NULL, NULL, "-", "-",         "GS_TYPE_VARCHAR", NULL,
        2, EFFECT_REBOOT, CFG_INS, NULL, NULL, NULL, NULL },
    { "LOG_HOME",                  CM_TRUE, CM_TRUE,  "",      NULL, NULL, "-", "-",         "GS_TYPE_VARCHAR", NULL,
        3, EFFECT_REBOOT, CFG_INS, NULL, NULL, NULL, NULL},
    { "_LOG_BACKUP_FILE_COUNT",    CM_TRUE, CM_FALSE, "20",    NULL, NULL, "-", "[0,128]",  "GS_TYPE_INTEGER", NULL,
        4, EFFECT_REBOOT, CFG_INS, dss_verify_log_backup_file_count, dss_notify_log_backup_file_count, NULL, NULL},
    { "_LOG_MAX_FILE_SIZE",        CM_TRUE, CM_FALSE, "256M",   NULL, NULL, "-", "[1M,4G]",     "GS_TYPE_INTEGER", NULL,
        5, EFFECT_REBOOT, CFG_INS, dss_verify_log_file_size, dss_notify_log_file_size, NULL, NULL},
    { "INST_ID",                   CM_TRUE, CM_FALSE, "0",     NULL, NULL, "-", "[0,64)",    "GS_TYPE_INTEGER", NULL,
        6, EFFECT_REBOOT, CFG_INS, NULL, NULL, NULL, NULL},
    { "STORAGE_MODE",              CM_TRUE, CM_FALSE, "DISK",  NULL, NULL, "-", "CLUSTER_RAID,RAID,DISK",
        "GS_TYPE_VARCHAR", NULL, 7, EFFECT_REBOOT, CFG_INS, NULL, NULL, NULL, NULL},
    { "_LOG_LEVEL",                CM_TRUE, CM_FALSE, "519",    NULL, NULL, "-", "[0,4087]",  "GS_TYPE_INTEGER", NULL,
        8, EFFECT_IMMEDIATELY, CFG_INS, dss_verify_log_level, dss_notify_log_level, NULL, NULL},
    { "MAX_SESSION_NUMS",          CM_TRUE, CM_FALSE, "8192",   NULL, NULL, "-", "[16,16320]",    "GS_TYPE_INTEGER",
        NULL, 9, EFFECT_REBOOT, CFG_INS, NULL, NULL, NULL, NULL},
    { "DISK_LOCK_INTERVAL",        CM_TRUE, CM_FALSE, "100",   NULL, NULL, "-", "[1,600000]", "GS_TYPE_INTEGER", NULL,
        10, EFFECT_REBOOT, CFG_INS, NULL, NULL, NULL, NULL},
    { "DLOCK_RETRY_COUNT",         CM_TRUE, CM_FALSE, "50",    NULL, NULL, "-", "[1,500000]", "GS_TYPE_INTEGER", NULL,
        11, EFFECT_REBOOT, CFG_INS, NULL, NULL, NULL, NULL},
    { "_AUDIT_BACKUP_FILE_COUNT",  CM_TRUE, CM_FALSE, "20",    NULL, NULL, "-", "[0,128]",   "GS_TYPE_INTEGER", NULL,
        12, EFFECT_REBOOT, CFG_INS, dss_verify_audit_backup_file_count, dss_notify_audit_backup_file_count, NULL, NULL},
    { "_AUDIT_MAX_FILE_SIZE",      CM_TRUE, CM_FALSE, "256M",   NULL, NULL, "-", "[1M,4G]",   "GS_TYPE_INTEGER", NULL,
        13, EFFECT_REBOOT, CFG_INS, dss_verify_audit_file_size, dss_notify_audit_file_size, NULL, NULL},
    { "_LOG_FILE_PERMISSIONS",     CM_TRUE, CM_FALSE, "600",   NULL, NULL, "-", "[600-777]", "GS_TYPE_INTEGER", NULL,
        14, EFFECT_REBOOT, CFG_INS, NULL, NULL, NULL, NULL},
    { "_LOG_PATH_PERMISSIONS",     CM_TRUE, CM_FALSE, "700",   NULL, NULL, "-", "[700-777]", "GS_TYPE_INTEGER", NULL,
        15, EFFECT_REBOOT, CFG_INS, NULL, NULL, NULL, NULL},
    { "SSL_PWD_CIPHERTEXT", CM_TRUE, CM_FALSE, "", NULL, NULL, "-", "-",
        "GS_TYPE_VARCHAR", NULL, 16, EFFECT_REBOOT, CFG_INS, NULL, NULL, NULL, NULL},
    { "_SHM_KEY", CM_TRUE, CM_FALSE,     "1",         NULL, NULL, "-", "[1,64]",
      "GS_TYPE_INTEGER", NULL, 17, EFFECT_REBOOT,      CFG_INS, NULL, NULL, NULL, NULL},
    { "DSS_NODES_LIST",        CM_TRUE, CM_FALSE,     "0:127.0.0.1:1611", NULL, NULL, "-", "-",
        "GS_TYPE_VARCHAR", NULL, 18,  EFFECT_REBOOT,      CFG_INS, NULL, NULL, NULL, NULL},
    { "INTERCONNECT_TYPE",        CM_TRUE, CM_FALSE,     "TCP",       NULL, NULL, "-", "TCP,RDMA",
        "GS_TYPE_VARCHAR", NULL, 19, EFFECT_REBOOT,      CFG_INS, NULL, NULL, NULL, NULL},
    { "INTERCONNECT_CHANNEL_NUM", CM_TRUE, CM_FALSE,     "2",         NULL, NULL, "-", "[1,32]",
      "GS_TYPE_INTEGER", NULL, 20, EFFECT_REBOOT,      CFG_INS, NULL, NULL, NULL, NULL},
    { "WORK_THREAD_COUNT", CM_TRUE, CM_FALSE,     "2",         NULL, NULL, "-", "[2,64]",
        "GS_TYPE_INTEGER", NULL, 21, EFFECT_REBOOT,      CFG_INS, NULL, NULL, NULL, NULL},
    { "RECV_MSG_POOL_SIZE",            CM_TRUE, CM_FALSE,     "16M",       NULL, NULL, "-", "[1M,1G]",
      "GS_TYPE_INTEGER", NULL, 22, EFFECT_REBOOT,      CFG_INS, NULL, NULL, NULL, NULL},
    { "MES_ELAPSED_SWITCH",       CM_TRUE, CM_FALSE,     "FALSE",     NULL, NULL, "-", "FALSE,TRUE",
      "GS_TYPE_BOOLEAN", NULL, 23, EFFECT_REBOOT,      CFG_INS, NULL, NULL, NULL, NULL},
    { "DISK_LOCK_FILE_PATH",           CM_TRUE, CM_FALSE, "/tmp", NULL, NULL, "-", "-",
        "GS_TYPE_VARCHAR", NULL, 24, EFFECT_REBOOT, CFG_INS, NULL, NULL, NULL, NULL },
    { "SSL_CA", CM_TRUE, CM_FALSE, "", NULL, NULL, "-", "-",
        "GS_TYPE_VARCHAR", NULL, 25, EFFECT_REBOOT, CFG_INS, NULL, NULL, NULL, NULL},
    { "SSL_KEY", CM_TRUE, CM_FALSE, "", NULL, NULL, "-", "-",
        "GS_TYPE_VARCHAR", NULL, 26, EFFECT_REBOOT, CFG_INS, NULL, NULL, NULL, NULL},
    { "SSL_CRL", CM_TRUE, CM_FALSE, "", NULL, NULL, "-", "-",
        "GS_TYPE_VARCHAR", NULL, 27, EFFECT_REBOOT, CFG_INS, NULL, NULL, NULL, NULL},
    { "SSL_CERT", CM_TRUE, CM_FALSE, "", NULL, NULL, "-", "-",
        "GS_TYPE_VARCHAR", NULL, 28, EFFECT_REBOOT, CFG_INS, NULL, NULL, NULL, NULL},
    { "SSL_CIPHER", CM_TRUE, CM_FALSE, "", NULL, NULL, "-", "-",
        "GS_TYPE_VARCHAR", NULL, 29, EFFECT_REBOOT, CFG_INS, NULL, NULL, NULL, NULL},
    { "POOL_NAMES",           CM_TRUE, CM_FALSE, "", NULL, NULL, "-", "-",
        "GS_TYPE_VARCHAR", NULL, 30, EFFECT_REBOOT, CFG_INS, NULL, NULL, NULL, NULL },
    { "IMAGE_NAMES",           CM_TRUE, CM_FALSE, "", NULL, NULL, "-", "-",
        "GS_TYPE_VARCHAR", NULL, 31, EFFECT_REBOOT, CFG_INS, NULL, NULL, NULL, NULL },
    { "CEPH_CONFIG",           CM_TRUE, CM_FALSE, "/etc/ceph/ceph.conf", NULL, NULL, "-", "-",
        "GS_TYPE_VARCHAR", NULL, 32, EFFECT_REBOOT, CFG_INS, NULL, NULL, NULL, NULL },
    { "VOLUME_TYPES",           CM_TRUE, CM_FALSE, "", NULL, NULL, "-", "-",
        "GS_TYPE_VARCHAR", NULL, 33, EFFECT_REBOOT, CFG_INS, NULL, NULL, NULL, NULL },
    { "_AUDIT_LEVEL",           CM_TRUE, CM_FALSE, "1",    NULL, NULL, "-", "[0,255]",  "GS_TYPE_INTEGER", NULL,
        34, EFFECT_IMMEDIATELY, CFG_INS, dss_verify_audit_level, dss_notify_audit_level, NULL, NULL},
    { "SSL_PERIOD_DETECTION", CM_TRUE, CM_FALSE, "7", NULL, NULL, "-", "[1,180]",
        "GS_TYPE_INTEGER", NULL, 35, EFFECT_REBOOT, CFG_INS, NULL, NULL, NULL, NULL},
    { "IO_THREADS",       CM_TRUE, CM_FALSE, "2",   NULL, NULL, "-", "[1,8]",
        "GS_TYPE_INTEGER", NULL, 38, EFFECT_REBOOT, CFG_INS, NULL, NULL, NULL, NULL},
    { "WORK_THREADS",       CM_TRUE, CM_FALSE, "16",   NULL, NULL, "-", "[16,128]",
        "GS_TYPE_INTEGER", NULL, 39, EFFECT_REBOOT, CFG_INS, NULL, NULL, NULL, NULL},
    { "_BLACKBOX_DETAIL_ON",   CM_TRUE, CM_FALSE, "FALSE",  NULL, NULL, "-", "FALSE,TRUE",
       "GS_TYPE_BOOLEAN", NULL, 40, EFFECT_REBOOT,  CFG_INS, NULL, NULL, NULL, NULL},
    { "CLUSTER_RUN_MODE", CM_TRUE, CM_FALSE, "cluster_primary", NULL, NULL, "-", "-", 
        "GS_TYPE_VARCHAR", NULL, 41, EFFECT_REBOOT, CFG_INS, dss_verify_cluster_run_mode, dss_notify_cluster_run_mode, NULL, NULL},
    { "XLOG_VG_ID", CM_TRUE, CM_FALSE, "1", NULL, NULL, "-", "[1,64]",
        "GS_TYPE_INTEGER", NULL, 42, EFFECT_REBOOT, CFG_INS, NULL, NULL, NULL, NULL},
    { "MES_WAIT_TIMEOUT",  CM_TRUE, CM_FALSE, "2000",  NULL, NULL, "-", "[500,10000]",
        "GS_TYPE_INTEGER", NULL, 43, EFFECT_REBOOT, CFG_INS, NULL, NULL, NULL, NULL},
    { "_ENABLE_CORE_STATE_COLLECT",  CM_TRUE, CM_FALSE, "FALSE",    NULL, NULL, "-", "[FALSE,TRUE]",  "GS_TYPE_BOOLEAN", NULL,
        44, EFFECT_IMMEDIATELY, CFG_INS, dss_verify_enable_core_state_collect, dss_notify_enable_core_state_collect, NULL, NULL},
    { "DELAY_CLEAN_INTERVAL",  CM_TRUE, CM_FALSE, "100",    NULL, NULL, "-", "[5,1000000]",  "GS_TYPE_INTEGER", NULL,
        45, EFFECT_IMMEDIATELY, CFG_INS, dss_verify_delay_clean_interval, dss_notify_delay_clean_interval, NULL, NULL},
    { "MASTER_LOCK_TIMEOUT", CM_TRUE, CM_FALSE, "10",     NULL, NULL, "-", "[1,30]",    "GS_TYPE_INTEGER", NULL, 46,
        EFFECT_REBOOT, CFG_INS, NULL, NULL, NULL, NULL},
};

// clang-format on
static const char *g_dss_config_file = (const char *)"dss_inst.ini";
#define DSS_PARAM_COUNT (sizeof(g_dss_params) / sizeof(config_item_t))

static status_t dss_load_threadpool_cfg(dss_config_t *inst_cfg)
{
    char *value = cm_get_config_value(&inst_cfg->config, "IO_THREADS");
    int32 count = 0;
    status_t status = cm_str2int(value, &count);
    DSS_RETURN_IFERR2(status, DSS_THROW_ERROR(ERR_DSS_INVALID_PARAM, "IO_THREADS"));

    if (count < DSS_MIN_IOTHREADS_CFG || count > DSS_MAX_IOTHREADS_CFG) {
        DSS_THROW_ERROR(ERR_DSS_INVALID_PARAM, "IO_THREADS");
        return CM_ERROR;
    }
    inst_cfg->params.iothread_count = (uint32)count;

    value = cm_get_config_value(&inst_cfg->config, "WORK_THREADS");
    status = cm_str2int(value, &count);
    DSS_RETURN_IFERR2(status, DSS_THROW_ERROR(ERR_DSS_INVALID_PARAM, "WORK_THREADS"));
    if (count < DSS_MIN_WORKTHREADS_CFG || count > DSS_MAX_WORKTHREADS_CFG) {
        DSS_THROW_ERROR(ERR_DSS_INVALID_PARAM, "WORK_THREADS");
        return CM_ERROR;
    }
    inst_cfg->params.workthread_count = (uint32)count;

    return CM_SUCCESS;
}

static status_t dss_load_session_cfg(dss_config_t *inst_cfg)
{
    char *value = cm_get_config_value(&inst_cfg->config, "MAX_SESSION_NUMS");
    int32 sessions;
    status_t status = cm_str2int(value, &sessions);
    DSS_RETURN_IFERR2(status, DSS_THROW_ERROR(ERR_DSS_INVALID_PARAM, "MAX_SESSION_NUMS"));

    if (sessions < DSS_MIN_SESSIONID_CFG || sessions > DSS_MAX_SESSIONS) {
        DSS_RETURN_IFERR2(CM_ERROR, DSS_THROW_ERROR(ERR_DSS_INVALID_PARAM, "MAX_SESSION_NUMS"));
    }

    inst_cfg->params.cfg_session_num = (uint32)sessions;
    return CM_SUCCESS;
}

static status_t dss_load_storage_mode(dss_config_t *inst_cfg)
{
    char *value = cm_get_config_value(&inst_cfg->config, "STORAGE_MODE");

    if (cm_str_equal_ins(value, "CLUSTER_RAID")) {
        inst_cfg->params.dss_mode = DSS_MODE_CLUSTER_RAID;
    } else if (cm_str_equal_ins(value, "RAID")) {
        inst_cfg->params.dss_mode = DSS_MODE_RAID;
    } else if (cm_str_equal_ins(value, "DISK")) {
        inst_cfg->params.dss_mode = DSS_MODE_DISK;
    } else {
        DSS_RETURN_IFERR2(CM_ERROR, DSS_THROW_ERROR(ERR_DSS_INVALID_PARAM, value));
    }
    return CM_SUCCESS;
}

static status_t dss_load_mes_pool_size(dss_config_t *inst_cfg)
{
    int64 mes_pool_size;
    char *value = cm_get_config_value(&inst_cfg->config, "RECV_MSG_POOL_SIZE");
    status_t status = cm_str2size(value, &mes_pool_size);
    DSS_RETURN_IFERR2(status, DSS_THROW_ERROR(ERR_DSS_INVALID_PARAM, "RECV_MSG_POOL_SIZE"));

    inst_cfg->params.mes_pool_size = (uint64)mes_pool_size;
    if ((inst_cfg->params.mes_pool_size < DSS_MIN_RECV_MSG_BUFF_SIZE) ||
        (inst_cfg->params.mes_pool_size > DSS_MAX_RECV_MSG_BUFF_SIZE)) {
        DSS_RETURN_IFERR2(CM_ERROR, DSS_THROW_ERROR(ERR_DSS_INVALID_PARAM, "RECV_MSG_POOL_SIZE"));
    }
    LOG_RUN_INF("Cluster Raid mode, mes_pool_size = %lld.", mes_pool_size);
    return CM_SUCCESS;
}

static status_t dss_load_mes_url(dss_config_t *inst_cfg)
{
    char *value = cm_get_config_value(&inst_cfg->config, "DSS_NODES_LIST");
    status_t status = cm_split_mes_urls(inst_cfg->params.nodes, inst_cfg->params.ports, value);
    DSS_RETURN_IFERR2(status, DSS_THROW_ERROR(ERR_DSS_INVALID_PARAM, "DSS_NODES_LIST"));
    int32 node_cnt = 0;
    for (int i = 0; i < DSS_MAX_INSTANCES; i++) {
        if (inst_cfg->params.ports[i] != 0) {
            inst_cfg->params.inst_map |= ((uint64)1 << i);
            node_cnt++;
        }
    }
    inst_cfg->params.inst_cnt = (uint32)node_cnt;
    LOG_RUN_INF("Cluster Raid mode, node count = %d.", node_cnt);
    return CM_SUCCESS;
}

static status_t dss_load_mes_conn_type(dss_config_t *inst_cfg)
{
    char *value = cm_get_config_value(&inst_cfg->config, "INTERCONNECT_TYPE");
    if (cm_str_equal_ins(value, "TCP")) {
        inst_cfg->params.pipe_type = CS_TYPE_TCP;
    } else if (cm_str_equal_ins(value, "RDMA")) {
        inst_cfg->params.pipe_type = CS_TYPE_RDMA;
    } else {
        DSS_RETURN_IFERR2(CM_ERROR, DSS_THROW_ERROR(ERR_DSS_INVALID_PARAM, "INTERCONNECT_TYPE"));
    }
    LOG_RUN_INF("Cluster Raid mode, pipe type = %u.", inst_cfg->params.pipe_type);
    return CM_SUCCESS;
}

static status_t dss_load_mes_channel_num(dss_config_t *inst_cfg)
{
    uint32 channel_num;
    char *value = cm_get_config_value(&inst_cfg->config, "INTERCONNECT_CHANNEL_NUM");
    status_t status = cm_str2uint32(value, &channel_num);
    DSS_RETURN_IFERR2(
        status, DSS_THROW_ERROR(ERR_DSS_INVALID_PARAM, "invalid parameter value of 'INTERCONNECT_CHANNEL_NUM'"));

    if (channel_num < CM_MES_MIN_CHANNEL_NUM || channel_num > CM_MES_MAX_CHANNEL_NUM) {
        DSS_RETURN_IFERR2(CM_ERROR, DSS_THROW_ERROR(ERR_DSS_INVALID_PARAM, "INTERCONNECT_CHANNEL_NUM"));
    }

    inst_cfg->params.channel_num = channel_num;
    LOG_RUN_INF("Cluster Raid mode, channel_num = %u.", inst_cfg->params.channel_num);
    return CM_SUCCESS;
}

static status_t dss_load_mes_work_thread_cnt(dss_config_t *inst_cfg)
{
    uint32 work_thread_cnt;
    char *value = cm_get_config_value(&inst_cfg->config, "WORK_THREAD_COUNT");
    status_t status = cm_str2uint32(value, &work_thread_cnt);
    DSS_RETURN_IFERR2(status, DSS_THROW_ERROR(ERR_DSS_INVALID_PARAM, "invalid parameter value of 'WORK_THREAD_COUNT'"));

    if (work_thread_cnt < DSS_MIN_WORK_THREAD_COUNT || work_thread_cnt > DSS_MAX_WORK_THREAD_COUNT) {
        DSS_RETURN_IFERR2(CM_ERROR, DSS_THROW_ERROR(ERR_DSS_INVALID_PARAM, "WORK_THREAD_COUNT"));
    }

    inst_cfg->params.work_thread_cnt = work_thread_cnt;
    LOG_RUN_INF("Cluster Raid mode, work_thread_cnt = %u.", inst_cfg->params.work_thread_cnt);
    return CM_SUCCESS;
}

static status_t dss_load_mes_elapsed_switch(dss_config_t *inst_cfg)
{
    char *value = cm_get_config_value(&inst_cfg->config, "MES_ELAPSED_SWITCH");
    if (cm_str_equal_ins(value, "TRUE")) {
        inst_cfg->params.elapsed_switch = CM_TRUE;
    } else if (cm_str_equal_ins(value, "FALSE")) {
        inst_cfg->params.elapsed_switch = CM_FALSE;
    } else {
        DSS_RETURN_IFERR2(CM_ERROR, DSS_THROW_ERROR(ERR_DSS_INVALID_PARAM, "MES_ELAPSED_SWITCH"));
    }

    LOG_RUN_INF("Cluster Raid mode, elapsed_switch = %u.", inst_cfg->params.elapsed_switch);
    return CM_SUCCESS;
}

static status_t dss_load_random_file(uchar *value, int32 value_len)
{
    char file_name[CM_FILE_NAME_BUFFER_SIZE];
    char dir_name[CM_FILE_NAME_BUFFER_SIZE];
    int32 handle;
    int32 file_size;
    PRTS_RETURN_IFERR(snprintf_s(
        dir_name, CM_FILE_NAME_BUFFER_SIZE, CM_FILE_NAME_BUFFER_SIZE - 1, "%s/dss_protect", g_inst_cfg->home));
    if (!cm_dir_exist(dir_name)) {
        DSS_THROW_ERROR(ERR_DSS_FILE_NOT_EXIST, "dss_protect", g_inst_cfg->home);
        return CM_ERROR;
    }
    PRTS_RETURN_IFERR(snprintf_s(file_name, CM_FILE_NAME_BUFFER_SIZE, CM_FILE_NAME_BUFFER_SIZE - 1, "%s/dss_protect/%s",
        g_inst_cfg->home, DSS_FKEY_FILENAME));
    DSS_RETURN_IF_ERROR(cs_ssl_verify_file_stat(file_name));
    DSS_RETURN_IF_ERROR(
        cm_open_file_ex(file_name, O_SYNC | O_RDONLY | O_BINARY, S_IRUSR, &handle));
    status_t ret = cm_read_file(handle, value, value_len, &file_size);
    cm_close_file(handle);
    DSS_RETURN_IF_ERROR(ret);
    if (file_size < RANDOM_LEN + 1) {
        LOG_DEBUG_ERR("Random component file %s is invalid, size is %d.", file_name, file_size);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

int32 dss_decrypt_pwd_cb(const char *cipher_text, uint32 cipher_len, char *plain_text, uint32 plain_len)
{
    if (cipher_text == NULL) {
        DSS_RETURN_IFERR3(CM_ERROR, CM_THROW_ERROR(ERR_INVALID_PARAM, "SSL_PWD_CIPHERTEXT"),
            LOG_DEBUG_ERR("[DSS] failed to decrypt SSL cipher: cipher is NULL"));
    }
    if (cipher_len == 0 || cipher_len >= DSS_PARAM_BUFFER_SIZE) {
        DSS_RETURN_IFERR3(CM_ERROR, CM_THROW_ERROR(ERR_INVALID_PARAM, "SSL_PWD_CIPHERTEXT"),
            LOG_DEBUG_ERR("[DSS] failed to decrypt SSL cipher: cipher size [%u] is invalid.", cipher_len));
    }
    if (plain_text == NULL) {
        DSS_RETURN_IFERR3(CM_ERROR, CM_THROW_ERROR(ERR_INVALID_PARAM, "SSL_PWD_CIPHERTEXT"),
            LOG_DEBUG_ERR("[DSS] failed to decrypt SSL cipher: plain is NULL"));
    }
    if (plain_len < CM_PASSWD_MAX_LEN) {
        DSS_RETURN_IFERR3(CM_ERROR, CM_THROW_ERROR(ERR_INVALID_PARAM, "SSL_PWD_CIPHERTEXT"),
            LOG_DEBUG_ERR("[DSS] failed to decrypt SSL cipher: plain len [%u] is invalid.", plain_len));
    }
    cipher_t cipher;
    if (cm_base64_decode(cipher_text, cipher_len, (uchar *)&cipher, (uint32)(sizeof(cipher_t) + 1)) == 0) {
        DSS_RETURN_IFERR3(CM_ERROR, CM_THROW_ERROR(ERR_INVALID_PARAM, "SSL_PWD_CIPHERTEXT"),
            LOG_DEBUG_ERR("[DSS] failed to decode SSL cipher."));
    }
    if (cipher.cipher_len > 0) {
        status_t status = dss_load_random_file(cipher.rand, (int32)sizeof(cipher.rand));
        DSS_RETURN_IFERR2(status, CM_THROW_ERROR(ERR_VALUE_ERROR, "[DSS] load random component failed."));
        status = cm_decrypt_pwd(&cipher, (uchar *)plain_text, &plain_len);
        DSS_RETURN_IFERR2(status, CM_THROW_ERROR(ERR_VALUE_ERROR, "[DSS] failed to decrypt ssl pwd."));
    } else {
        CM_THROW_ERROR(ERR_INVALID_PARAM, "SSL_PWD_CIPHERTEXT");
        LOG_DEBUG_ERR("[DSS] failed to decrypt ssl pwd for the cipher len is invalid.");
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

status_t dss_load_mes_ssl(dss_config_t *inst_cfg)
{
    char *value = cm_get_config_value(&inst_cfg->config, "SSL_CA");
    status_t status = dss_set_ssl_param("SSL_CA", value);
    DSS_RETURN_IFERR2(status, DSS_THROW_ERROR(ERR_DSS_INVALID_PARAM, "SSL_CA"));

    value = cm_get_config_value(&inst_cfg->config, "SSL_KEY");
    status = dss_set_ssl_param("SSL_KEY", value);
    DSS_RETURN_IFERR2(status, DSS_THROW_ERROR(ERR_DSS_INVALID_PARAM, "SSL_KEY"));

    value = cm_get_config_value(&inst_cfg->config, "SSL_CRL");
    status = dss_set_ssl_param("SSL_CRL", value);
    DSS_RETURN_IFERR2(status, DSS_THROW_ERROR(ERR_DSS_INVALID_PARAM, "SSL_CRL"));

    value = cm_get_config_value(&inst_cfg->config, "SSL_CERT");
    status = dss_set_ssl_param("SSL_CERT", value);
    DSS_RETURN_IFERR2(status, DSS_THROW_ERROR(ERR_DSS_INVALID_PARAM, "SSL_CERT"));

    value = cm_get_config_value(&inst_cfg->config, "SSL_CIPHER");
    status = dss_set_ssl_param("SSL_CIPHER", value);
    DSS_RETURN_IFERR2(status, DSS_THROW_ERROR(ERR_DSS_INVALID_PARAM, "SSL_CIPHER"));

    value = cm_get_config_value(&inst_cfg->config, "SSL_CERT_NOTIFY_TIME");
    status = dss_set_ssl_param("SSL_CERT_NOTIFY_TIME", value);
    DSS_RETURN_IFERR2(status, DSS_THROW_ERROR(ERR_DSS_INVALID_PARAM, "SSL_CERT_NOTIFY_TIME"));
    uint32 alert_value;
    status = cm_str2uint32(value, &alert_value);
    DSS_RETURN_IFERR2(status, DSS_THROW_ERROR(ERR_DSS_INVALID_PARAM, "SSL_CERT_NOTIFY_TIME"));
    value = cm_get_config_value(&inst_cfg->config, "SSL_PERIOD_DETECTION");
    status = cm_str2uint32(value, &inst_cfg->params.ssl_detect_day);
    DSS_RETURN_IFERR2(status, DSS_THROW_ERROR(ERR_DSS_INVALID_PARAM, "SSL_PERIOD_DETECTION"));
    if (inst_cfg->params.ssl_detect_day > DSS_MAX_SSL_PERIOD_DETECTION ||
        inst_cfg->params.ssl_detect_day < DSS_MIN_SSL_PERIOD_DETECTION) {
        DSS_THROW_ERROR(ERR_DSS_INVALID_PARAM, "SSL_PERIOD_DETECTION");
        return CM_ERROR;
    }
    if (inst_cfg->params.ssl_detect_day > alert_value) {
        DSS_THROW_ERROR_EX(ERR_DSS_INVALID_PARAM,
            "SSL disabled: the value of SSL_PERIOD_DETECTION which is %u is "
            "bigger than the value of SSL_CERT_NOTIFY_TIME which is %u",
            inst_cfg->params.ssl_detect_day, alert_value);
        return CM_ERROR;
    }
    value = cm_get_config_value(&inst_cfg->config, "SSL_PWD_CIPHERTEXT");
    status = dss_set_ssl_param("SSL_PWD_CIPHERTEXT", value);
    DSS_RETURN_IFERR2(status, DSS_THROW_ERROR(ERR_DSS_INVALID_PARAM, "SSL_PWD_CIPHERTEXT"));

    if (!CM_IS_EMPTY_STR(value)) {
        return mes_register_decrypt_pwd(dss_decrypt_pwd_cb);
    }
    return CM_SUCCESS;
}

static status_t dss_load_mes_wait_timeout(dss_config_t *inst_cfg)
{
    char *value = cm_get_config_value(&inst_cfg->config, "MES_WAIT_TIMEOUT");
    int32 timeout = 0;
    status_t status = cm_str2int(value, &timeout);
    DSS_RETURN_IFERR2(status, DSS_THROW_ERROR(ERR_DSS_INVALID_PARAM, "MES_WAIT_TIMEOUT"));
    if (timeout < DSS_MES_MIN_WAIT_TIMEOUT || timeout > DSS_MES_MAX_WAIT_TIMEOUT) {
        DSS_THROW_ERROR(ERR_DSS_INVALID_PARAM, "MES_WAIT_TIMEOUT");
        return CM_ERROR;
    }
    inst_cfg->params.mes_wait_timeout = (uint32)timeout;
    return CM_SUCCESS;
}

static status_t dss_load_mes_params(dss_config_t *inst_cfg)
{
    CM_RETURN_IFERR(dss_load_mes_url(inst_cfg));
    CM_RETURN_IFERR(dss_load_mes_conn_type(inst_cfg));
    CM_RETURN_IFERR(dss_load_mes_channel_num(inst_cfg));
    CM_RETURN_IFERR(dss_load_mes_work_thread_cnt(inst_cfg));
    CM_RETURN_IFERR(dss_load_mes_pool_size(inst_cfg));
    CM_RETURN_IFERR(dss_load_mes_elapsed_switch(inst_cfg));
    CM_RETURN_IFERR(dss_load_mes_ssl(inst_cfg));
    CM_RETURN_IFERR(dss_load_mes_wait_timeout(inst_cfg));
    return CM_SUCCESS;
}

static status_t dss_load_disk_lock_interval(dss_config_t *inst_cfg)
{
    char *value = cm_get_config_value(&inst_cfg->config, "DISK_LOCK_INTERVAL");
    int32 lock_interval;

    status_t status = cm_str2int(value, &lock_interval);
    DSS_RETURN_IFERR2(status, DSS_THROW_ERROR(ERR_DSS_INVALID_PARAM, "DISK_LOCK_INTERVAL"));

    if (lock_interval < DSS_MIN_LOCK_INTERVAL || lock_interval > DSS_MAX_LOCK_INTERVAL) {
        DSS_RETURN_IFERR2(CM_ERROR, DSS_THROW_ERROR(ERR_DSS_INVALID_PARAM, "DISK_LOCK_INTERVAL"));
    }
    inst_cfg->params.lock_interval = lock_interval;

    return CM_SUCCESS;
}

static status_t dss_load_dlock_retry_count(dss_config_t *inst_cfg)
{
    char *value = cm_get_config_value(&inst_cfg->config, "DLOCK_RETRY_COUNT");
    uint32 dlock_retry_count;

    status_t status = cm_str2uint32(value, &dlock_retry_count);
    DSS_RETURN_IFERR2(status, DSS_THROW_ERROR(ERR_DSS_INVALID_PARAM, "DLOCK_RETRY_COUNT"));

    if (dlock_retry_count < DSS_MIN_DLOCK_RETRY_COUNT || dlock_retry_count > DSS_MAX_DLOCK_RETRY_COUNT) {
        DSS_RETURN_IFERR2(CM_ERROR, DSS_THROW_ERROR(ERR_DSS_INVALID_PARAM, "DLOCK_RETRY_COUNT"));
    }
    inst_cfg->params.dlock_retry_count = dlock_retry_count;

    return CM_SUCCESS;
}

static status_t dss_load_path(dss_config_t *inst_cfg)
{
    int32 ret;
    char *value = cm_get_config_value(&inst_cfg->config, "LSNR_PATH");
    status_t status = dss_verify_lsnr_path(value);
    DSS_RETURN_IFERR2(status, DSS_THROW_ERROR(ERR_DSS_INVALID_PARAM, "failed to load params, invalid LSNR_PATH"));
    ret = snprintf_s(inst_cfg->params.lsnr_path, DSS_MAX_PATH_BUFFER_SIZE, DSS_MAX_PATH_BUFFER_SIZE - 1, "%s/%s", value,
        DSS_UNIX_DOMAIN_SOCKET_NAME);
    if (ret == -1) {
        DSS_RETURN_IFERR2(CM_ERROR, DSS_THROW_ERROR(ERR_DSS_INVALID_PARAM, "failed to load params, invalid LSNR_PATH"));
    }

    return CM_SUCCESS;
}

static status_t dss_load_disk_lock_file_path(dss_config_t *inst_cfg)
{
    int32 ret;
    char *value = cm_get_config_value(&inst_cfg->config, "DISK_LOCK_FILE_PATH");
    status_t status = dss_verify_lock_file_path(value);
    DSS_RETURN_IFERR2(
        status, DSS_THROW_ERROR(ERR_DSS_INVALID_PARAM, "failed to load params, invalid DISK_LOCK_FILE_PATH"));
    ret = snprintf_s(inst_cfg->params.disk_lock_file_path, DSS_UNIX_PATH_MAX, DSS_UNIX_PATH_MAX - 1, "%s", value);
    if (ret == -1) {
        DSS_RETURN_IFERR2(
            CM_ERROR, DSS_THROW_ERROR(ERR_DSS_INVALID_PARAM, "failed to load params, invalid DISK_LOCK_FILE_PATH"));
    }

    return CM_SUCCESS;
}

static status_t dss_load_cluster_run_mode(dss_config_t *inst_cfg)
{
    char *value = cm_get_config_value(&inst_cfg->config, "CLUSTER_RUN_MODE");

    if (strcmp(value, "cluster_standby") == 0) {
        inst_cfg->params.cluster_run_mode = CLUSTER_STANDBY;
        LOG_RUN_INF("The cluster_run_mode is cluster_standby.");
    } else if (strcmp(value, "cluster_primary") == 0) {
        inst_cfg->params.cluster_run_mode = CLUSTER_PRIMARY;
        LOG_RUN_INF("The cluster_run_mode is cluster_primary.");
    } else {
        DSS_RETURN_IFERR2(CM_ERROR, DSS_THROW_ERROR(ERR_DSS_INVALID_PARAM, "failed to load params, invalid CLUSTER_RUN_MODE"));
    }
    return CM_SUCCESS;
}

static status_t dss_load_xlog_vg_id(dss_config_t *inst_cfg)
{
    char *value = cm_get_config_value(&inst_cfg->config, "XLOG_VG_ID");
    int32 xlog_vg_id = 0;
    status_t status = cm_str2int(value, &xlog_vg_id);
    DSS_RETURN_IFERR2(status, DSS_THROW_ERROR(ERR_DSS_INVALID_PARAM, "XLOG_VG_ID"));

    /* the redo log of metadata in vg0, vg0 can not be synchronous copy disk */
    if (xlog_vg_id < 1 || xlog_vg_id > 64) {
        DSS_RETURN_IFERR2(CM_ERROR, DSS_THROW_ERROR(ERR_DSS_INVALID_PARAM, "XLOG_VG_ID"));
    }

    inst_cfg->params.xlog_vg_id = (uint32)xlog_vg_id;
    LOG_RUN_INF("The xlog vg id is %d.", inst_cfg->params.xlog_vg_id);
    return CM_SUCCESS;
}

status_t dss_set_cfg_dir(const char *home, dss_config_t *inst_cfg)
{
    char home_realpath[DSS_MAX_PATH_BUFFER_SIZE];
    bool8 is_home_empty = (home == NULL || home[0] == '\0');
    if (is_home_empty) {
        const char *home_env = getenv(DSS_ENV_HOME);
        if (home_env == NULL || home_env[0] == '\0') {
            DSS_RETURN_IFERR2(CM_ERROR, DSS_THROW_ERROR(ERR_DSS_INVALID_PARAM, "invalid cfg dir"));
        }
        uint32 len = (uint32)strlen(home_env);
        if (len >= DSS_MAX_PATH_BUFFER_SIZE) {
            DSS_RETURN_IFERR2(CM_ERROR, DSS_THROW_ERROR(ERR_DSS_INVALID_PARAM, "invalid cfg dir len"));
        }
        status_t status = realpath_file(home_env, home_realpath, DSS_MAX_PATH_BUFFER_SIZE);
        DSS_RETURN_IFERR2(status, DSS_THROW_ERROR(ERR_DSS_INVALID_PARAM, "invalid cfg dir"));
    } else {
        uint32 len = (uint32)strlen(home);
        if (len >= DSS_MAX_PATH_BUFFER_SIZE) {
            DSS_THROW_ERROR(ERR_DSS_INVALID_PARAM, "invalid cfg dir");
            return CM_ERROR;
        }
    }
    int32 iret_snprintf = snprintf_s(inst_cfg->home, DSS_MAX_PATH_BUFFER_SIZE, DSS_MAX_PATH_BUFFER_SIZE - 1, "%s",
        is_home_empty ? home_realpath : home);
    DSS_SECUREC_SS_RETURN_IF_ERROR(iret_snprintf, CM_ERROR);
    g_inst_cfg = inst_cfg;
    return CM_SUCCESS;
}

static status_t dss_load_instance_id(dss_config_t *inst_cfg)
{
    char *value = cm_get_config_value(&inst_cfg->config, "INST_ID");
    status_t status = cm_str2bigint(value, &inst_cfg->params.inst_id);
    DSS_RETURN_IFERR2(status, DSS_THROW_ERROR(ERR_DSS_INVALID_PARAM, "the value of 'INST_ID' is invalid"));

    if (inst_cfg->params.inst_id < DSS_MIN_INST_ID || inst_cfg->params.inst_id >= DSS_MAX_INST_ID) {
        DSS_RETURN_IFERR2(CM_ERROR, DSS_THROW_ERROR(ERR_DSS_INVALID_PARAM, "the value of 'INST_ID' is invalid"));
    }

    LOG_RUN_INF("The instanceid is %lld.", inst_cfg->params.inst_id);
    return CM_SUCCESS;
}

static status_t dss_load_shm_key(dss_config_t *inst_cfg)
{
    char *value = cm_get_config_value(&inst_cfg->config, "_SHM_KEY");
    // 单个机器上最多允许(1<<DSS_MAX_SHM_KEY_BITS)这么多个用户并发使用dss的范围的ipc key，这样是为了防止重叠
    // key组成为: (((基础_SHM_KEY << DSS_MAX_SHM_KEY_BITS)      + inst_id) << 16) | 实际的业务id，
    // 实际的业务id具体范围现在分为[1,2][3,18],[19,20496]
    status_t status = cm_str2uint32(value, &inst_cfg->params.shm_key);
    DSS_RETURN_IFERR2(status, LOG_DEBUG_ERR("invalid parameter value of '_SHM_KEY', value:%s.", value));

    if (inst_cfg->params.shm_key < DSS_MIN_SHM_KEY || inst_cfg->params.shm_key > DSS_MAX_SHM_KEY) {
        DSS_RETURN_IFERR2(CM_ERROR, DSS_THROW_ERROR(ERR_DSS_INVALID_PARAM, "the value of '_SHM_KEY' is invalid"));
    }
    LOG_RUN_INF("_SHM_KEY is %u.", inst_cfg->params.shm_key);
    return CM_SUCCESS;
}

static status_t dss_load_blackbox_detail_on(dss_config_t *inst_cfg)
{
    char *value = cm_get_config_value(&inst_cfg->config, "_BLACKBOX_DETAIL_ON");
    if (cm_str_equal_ins(value, "TRUE")) {
        inst_cfg->params.blackbox_detail_on = CM_TRUE;
    } else if (cm_str_equal_ins(value, "FALSE")) {
        inst_cfg->params.blackbox_detail_on = CM_FALSE;
    } else {
        DSS_RETURN_IFERR2(CM_ERROR, DSS_THROW_ERROR(ERR_DSS_INVALID_PARAM, "_BLACKBOX_DETAIL_ON"));
    }

    LOG_RUN_INF("_BLACKBOX_DETAIL_ON = %u.", inst_cfg->params.blackbox_detail_on);
    return CM_SUCCESS;
}

static status_t dss_load_enable_core_state_collect(dss_config_t *inst_cfg)
{
    char *value = cm_get_config_value(&inst_cfg->config, "_ENABLE_CORE_STATE_COLLECT");
    return dss_load_enable_core_state_collect_inner(value, inst_cfg);
}

status_t dss_load_delay_clean_interval_core(char *value, dss_config_t *inst_cfg)
{
    uint32 delay_clean_interval;

    status_t status = cm_str2uint32(value, &delay_clean_interval);
    DSS_RETURN_IFERR2(status, DSS_THROW_ERROR(ERR_DSS_INVALID_PARAM, "DELAY_CLEAN_INTERVAL"));

    if (delay_clean_interval < DSS_MIN_DELAY_CLEAN_INTERVAL || delay_clean_interval > DSS_MAX_DELAY_CLEAN_INTERVAL) {
        DSS_RETURN_IFERR2(CM_ERROR, DSS_THROW_ERROR(ERR_DSS_INVALID_PARAM, "DELAY_CLEAN_INTERVAL"));
    }
    inst_cfg->params.delay_clean_interval = delay_clean_interval;
    LOG_RUN_INF("DELAY_CLEAN_INTERVAL = %u.", inst_cfg->params.delay_clean_interval);
    return CM_SUCCESS;
}

static status_t dss_load_delay_clean_interval(dss_config_t *inst_cfg)
{
    char *value = cm_get_config_value(&inst_cfg->config, "DELAY_CLEAN_INTERVAL");
    return dss_load_delay_clean_interval_core(value, inst_cfg);
}

static status_t dss_load_master_lock_timeout(dss_config_t *inst_cfg)
{
    char *value = cm_get_config_value(&inst_cfg->config, "MASTER_LOCK_TIMEOUT");
    status_t status = cm_str2uint32(value, &inst_cfg->params.master_lock_timeout);
    DSS_RETURN_IFERR2(status, LOG_DEBUG_ERR("invalid parameter value of 'MASTER_LOCK_TIMEOUT', value:%s.", value));
    if (inst_cfg->params.master_lock_timeout < DSS_MIN_MASTER_LOCK_TIMEOUT ||
        inst_cfg->params.master_lock_timeout > DSS_MAX_MASTER_LOCK_TIMEOUT) {
        DSS_RETURN_IFERR2(
            CM_ERROR, DSS_THROW_ERROR(ERR_DSS_INVALID_PARAM, "the value of 'MASTER_LOCK_TIMEOUT' is invalid"));
    }
    LOG_RUN_INF("MASTER_LOCK_TIMEOUT is %u.", inst_cfg->params.master_lock_timeout);
    return CM_SUCCESS;
}

status_t dss_load_config(dss_config_t *inst_cfg)
{
    char file_name[DSS_FILE_NAME_BUFFER_SIZE];
    errno_t ret = memset_sp(&inst_cfg->params, sizeof(dss_params_t), 0, sizeof(dss_params_t));
    if (ret != EOK) {
        return CM_ERROR;
    }

    // get config info
    ret = snprintf_s(file_name, DSS_FILE_NAME_BUFFER_SIZE, DSS_FILE_NAME_BUFFER_SIZE - 1, "%s/cfg/%s", inst_cfg->home,
        g_dss_config_file);
    if (ret == -1) {
        DSS_RETURN_IFERR2(
            CM_ERROR, DSS_THROW_ERROR(ERR_DSS_INVALID_PARAM, "failed to load params, invalid config file path"));
    }

    status_t status = cm_load_config(g_dss_params, DSS_PARAM_COUNT, file_name, &inst_cfg->config, CM_FALSE);
    DSS_RETURN_IFERR2(status, DSS_THROW_ERROR(ERR_DSS_INVALID_PARAM, "failed to load config"));

    CM_RETURN_IFERR(dss_load_path(inst_cfg));
    CM_RETURN_IFERR(dss_load_disk_lock_file_path(inst_cfg));
    CM_RETURN_IFERR(dss_load_instance_id(inst_cfg));
    CM_RETURN_IFERR(dss_load_storage_mode(inst_cfg));
    CM_RETURN_IFERR(dss_load_session_cfg(inst_cfg));
    CM_RETURN_IFERR(dss_load_disk_lock_interval(inst_cfg));
    CM_RETURN_IFERR(dss_load_dlock_retry_count(inst_cfg));
    CM_RETURN_IFERR(dss_load_mes_params(inst_cfg));
    CM_RETURN_IFERR(dss_load_shm_key(inst_cfg));
    CM_RETURN_IFERR(dss_load_threadpool_cfg(inst_cfg));
    CM_RETURN_IFERR(dss_load_cephrbd_params(inst_cfg));
    CM_RETURN_IFERR(dss_load_cephrbd_config_file(inst_cfg));
    CM_RETURN_IFERR(dss_load_blackbox_detail_on(inst_cfg));
    CM_RETURN_IFERR(dss_load_cluster_run_mode(inst_cfg));
    CM_RETURN_IFERR(dss_load_xlog_vg_id(inst_cfg));
    CM_RETURN_IFERR(dss_load_enable_core_state_collect(inst_cfg));
    CM_RETURN_IFERR(dss_load_delay_clean_interval(inst_cfg));
    CM_RETURN_IFERR(dss_load_master_lock_timeout(inst_cfg));
    return CM_SUCCESS;
}

status_t dss_set_ssl_param(const char *param_name, const char *param_value)
{
    if (param_name == NULL) {
        DSS_RETURN_IFERR2(CM_ERROR, DSS_THROW_ERROR(ERR_DSS_INVALID_PARAM, "the ssl param name should not be null."));
    }
    if (cm_str_equal(param_name, "SSL_PWD_PLAINTEXT") || cm_str_equal(param_name, "SSL_PWD_CIPHERTEXT")) {
        LOG_RUN_INF("dss set ssl param, param_name=%s param_value=%s", param_name, "***");
    } else {
        LOG_RUN_INF("dss set ssl param, param_name=%s param_value=%s", param_name, param_value);
    }
    cbb_param_t param_type;
    param_value_t out_value;
    CM_RETURN_IFERR(mes_chk_md_param(param_name, param_value, &param_type, &out_value));
    status_t status = mes_set_md_param(param_type, &out_value);
    DSS_RETURN_IFERR2(status, DSS_THROW_ERROR(ERR_DSS_INVALID_PARAM, param_name));
    return CM_SUCCESS;
}

void dss_ssl_ca_cert_expire(void)
{
    if ((int32)(g_timer()->systime / SECONDS_PER_DAY) % g_inst_cfg->params.ssl_detect_day == 0) {
        (void)mes_chk_ssl_cert_expire();
    }
}

static status_t dss_set_cfg_param_core(text_t *text, char *value, dss_def_t *def)
{
    bool32 force = CM_TRUE;
    config_item_t *item = cm_get_config_item(&g_inst_cfg->config, text, CM_TRUE);
    if (item == NULL) {
        DSS_RETURN_IFERR2(CM_ERROR, CM_THROW_ERROR(ERR_INVALID_PARAM, def->name));
    }

    if ((item->verify) && (item->verify((void *)value, (void *)def) != CM_SUCCESS)) {
        return CM_ERROR;
    }

    if (def->scope != CONFIG_SCOPE_DISK) {
        if (item->notify && item->notify(NULL, (void *)item, def->value)) {
            return CM_ERROR;
        }
    } else {
        if (item->notify_pfile && item->notify_pfile(NULL, (void *)item, def->value)) {
            return CM_ERROR;
        }
    }

    if (item->attr & ATTR_READONLY) {
#if defined(_DEBUG) || defined(DEBUG) || defined(DB_DEBUG_VERSION)
        force = CM_TRUE;
#else
        force = CM_FALSE;  // can not alter parameter whose attr is readonly  for release
#endif
    }
    if (cm_alter_config(&g_inst_cfg->config, def->name, def->value, def->scope, force) != CM_SUCCESS) {
        return CM_ERROR;
    }
    LOG_RUN_INF("parameter %s has been changed successfully", def->name);
    return CM_SUCCESS;
}

status_t dss_set_cfg_param(char *name, char *value, char *scope)
{
    CM_ASSERT(name != NULL);
    CM_ASSERT(value != NULL);
    CM_ASSERT(scope != NULL);

    // 1. parse name
    dss_def_t def;
    text_t text = {.str = name, .len = (uint32)strlen(name)};
    if (text.len == 0) {
        DSS_RETURN_IFERR2(CM_ERROR, CM_THROW_ERROR(ERR_INVALID_PARAM, text.str));
    }
    cm_trim_text(&text);
    cm_text_upper(&text);
    CM_RETURN_IFERR(cm_text2str(&text, def.name, CM_PARAM_BUFFER_SIZE));

    // 2. parse scope
    if (strcmp(scope, "memory") == 0) {
        def.scope = CONFIG_SCOPE_MEMORY;
    } else if (strcmp(scope, "pfile") == 0) {
        def.scope = CONFIG_SCOPE_DISK;
    } else {
        def.scope = CONFIG_SCOPE_BOTH;
    }

    return dss_set_cfg_param_core(&text, value, &def);
}

status_t dss_get_cfg_param(const char *name, char **value)
{
    CM_ASSERT(name != NULL);
    dss_def_t def;
    text_t text = {.str = (char *)name, .len = (uint32)strlen(name)};
    if (text.len == 0) {
        DSS_RETURN_IFERR2(CM_ERROR, CM_THROW_ERROR(ERR_INVALID_PARAM, text.str));
    }

    cm_trim_text(&text);
    cm_text_upper(&text);
    CM_RETURN_IFERR(cm_text2str(&text, def.name, CM_NAME_BUFFER_SIZE));

    *value = cm_get_config_value(&g_inst_cfg->config, def.name);
    if (*value == NULL) {
        CM_THROW_ERROR(ERR_INVALID_VALUE, name);
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

#ifdef __cplusplus
}
#endif
