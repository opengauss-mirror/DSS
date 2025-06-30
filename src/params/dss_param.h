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
 * dss_param.h
 *
 *
 * IDENTIFICATION
 *    src/params/dss_param.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __DSS_PARAM_H__
#define __DSS_PARAM_H__

#include "dss_defs.h"
#include "dss_log.h"
#include "cm_config.h"
#include "cs_pipe.h"
#include "ceph_rbd_param.h"
#include "mes_metadata.h"
#include "mes_interface.h"
#include "dss_errno.h"
#include "dss_api.h"
#include "dss_nodes_list.h"
#ifdef __cplusplus
extern "C" {
#endif

#define DSS_MIN_WORK_THREAD_COUNT (2)
#define DSS_MAX_WORK_THREAD_COUNT (64)
// for most time, standby nodes rerad meta from primary
#define DSS_WORK_THREAD_LOAD_DATA_PERCENT 0.5

#define DSS_MES_MAX_WAIT_TIMEOUT 30000  // 30s
#define DSS_MES_MIN_WAIT_TIMEOUT 500    // 500ms

#define DSS_MIN_RECV_MSG_BUFF_SIZE (uint64) SIZE_M(9)
#define DSS_MAX_RECV_MSG_BUFF_SIZE (uint64) SIZE_G(1)

typedef enum en_dss_mode {
    DSS_MODE_UNKNOWN = 0,
    DSS_MODE_CLUSTER_RAID = 1,  // MULTI DATANODE's RAID
    DSS_MODE_SHARE_DISK = 2,    // SHARE DISK LOCK
    DSS_MODE_DISK = 3           // A DATANODE's DISK
} dss_mode_e;

/* use for dorado cluster */
typedef enum cluster_run_mode_t { CLUSTER_PRIMARY = 0, CLUSTER_STANDBY = 1 } cluster_run_mode_t;

typedef enum en_disk_type {
    DISK_NORMAL = 0,
    DISK_VTABLE = 1
} disk_type_e;

#if defined(_DEBUG) || defined(DEBUG) || defined(DB_DEBUG_VERSION)
#define DSS_RECYLE_META_RANGE_MAX 10000U
#endif

typedef struct st_dss_recycle_meta_pos {
    uint32 hwm;  // trigger to recycle, the unit is 0.01%
    uint32 lwm;  // mark to end recycle, the unit is 0.01%
} dss_recycle_meta_pos_t;

typedef struct st_dss_params {
    char *root_name;  // root volume name
    int64 inst_id;
    char lsnr_path[DSS_MAX_PATH_BUFFER_SIZE];
    char disk_lock_file_path[DSS_UNIX_PATH_MAX];
    int32 dss_mode;
    uint32 cfg_session_num;
    int32 lock_interval;
    uint32 dlock_retry_count;

    uint64 mes_pool_size;
    dss_nodes_list_t nodes_list;
    uint32 channel_num;
    uint32 work_thread_cnt;
    cs_pipe_type_t pipe_type;
    bool32 elapsed_switch;
    uint32 shm_key;
    uint32 ssl_detect_day;
    bool32 mes_with_ip;
    bool32 ip_white_list_on;
    uint32 iothread_count;
    uint32 workthread_count;
    uint32 xlog_vg_id;
    rbd_config_params_t rbd_config_params;
    char ceph_config[DSS_FILE_NAME_BUFFER_SIZE];
    bool32 blackbox_detail_on;
    uint32 mes_wait_timeout;
    bool32 enable_core_state_collect;
    uint32 delay_clean_interval;
    cluster_run_mode_t cluster_run_mode;
    dss_recycle_meta_pos_t recyle_meta_pos;
    uint32 space_usage_hwm;
    uint32 space_usage_lwm;
    uint32 delay_clean_search_fragment;
    bool32 linux_multibus;
    char mpathpersist_dss_path[DSS_FILE_PATH_MAX_LENGTH];
    disk_type_e disk_type;
} dss_params_t;

typedef struct st_dss_config {
    char home[DSS_MAX_PATH_BUFFER_SIZE];
    config_t config;
    dss_params_t params;
} dss_config_t;
extern dss_config_t *g_inst_cfg;
dss_config_t *dss_get_g_inst_cfg();

#define DSS_UNIX_DOMAIN_SOCKET_NAME ".dss_unix_d_socket"
#define DSS_MAX_SSL_PERIOD_DETECTION 180
#define DSS_MIN_SSL_PERIOD_DETECTION 1

status_t dss_load_config(dss_config_t *inst_cfg);
status_t dss_set_cfg_dir(const char *home, dss_config_t *inst_cfg);

static inline int32 dss_storage_mode(dss_config_t *inst_cfg)
{
    return inst_cfg->params.dss_mode;
}

static inline bool32 dss_get_linux_multibus(dss_config_t *inst_cfg)
{
    return inst_cfg->params.linux_multibus;
}

static inline char *dss_get_mpathpersist_dss_path(dss_config_t *inst_cfg)
{
    return inst_cfg->params.mpathpersist_dss_path;
}

static inline char *dss_get_cfg_dir(dss_config_t *inst_cfg)
{
    return inst_cfg->home;
}

/*
 * @brief set ssl relevant param
 * @[in] param name(SSL_CA、SSL_KEY、SSL_PWD_PLAINTEXT、SSL_CERT).
 * @[in] param value--ssl cert or ssl key
 * @* @return CM_SUCCESS - success;otherwise: failed
 */
status_t dss_set_ssl_param(const char *param_name, const char *param_value);

/*
 * @brief get ssl relevant param
 * @[in] param name(SSL_CA、SSL_KEY、SSL_PWD_PLAINTEXT、SSL_CERT).
 * @[in]size--ssl cert or ssl key size
 * @[out]param value--ssl cert or ssl key
 * @* @return CM_SUCCESS - success;otherwise: failed
 */
inline status_t dss_get_ssl_param(const char *param_name, char *param_value, uint32 size)
{
    if (param_name == NULL) {
        DSS_THROW_ERROR(ERR_DSS_INVALID_PARAM, "the ssl param name should not be null.");
        return CM_ERROR;
    }
    return mes_get_md_param_by_name(param_name, param_value, size);
}
void dss_ssl_ca_cert_expire(void);

status_t dss_set_cfg_param(char *name, char *value, char *scope);
status_t dss_get_cfg_param(const char *name, char **value);
status_t dss_load_delay_clean_interval_core(char *value, dss_config_t *inst_cfg);
status_t dss_load_delay_clean_search_fragment_core(char *value, dss_config_t *inst_cfg);
static inline status_t dss_load_blackbox_detail_on_inner(char *value, dss_config_t *inst_cfg)
{
    if (cm_str_equal_ins(value, "TRUE")) {
        inst_cfg->params.blackbox_detail_on = CM_TRUE;
    } else if (cm_str_equal_ins(value, "FALSE")) {
        inst_cfg->params.blackbox_detail_on = CM_FALSE;
    } else {
        DSS_THROW_ERROR(ERR_DSS_INVALID_PARAM, "_BLACKBOX_DETAIL_ON");
        return CM_ERROR;
    }
    LOG_RUN_INF("_BLACKBOX_DETAIL_ON = %u.", inst_cfg->params.blackbox_detail_on);
    return CM_SUCCESS;
}

static inline status_t dss_load_enable_core_state_collect_inner(char *value, dss_config_t *inst_cfg)
{
    if (cm_str_equal_ins(value, "TRUE")) {
        inst_cfg->params.enable_core_state_collect = CM_TRUE;
    } else if (cm_str_equal_ins(value, "FALSE")) {
        inst_cfg->params.enable_core_state_collect = CM_FALSE;
    } else {
        DSS_THROW_ERROR(ERR_DSS_INVALID_PARAM, "_ENABLE_CORE_STATE_COLLECT");
        return CM_ERROR;
    }
    LOG_RUN_INF("_ENABLE_CORE_STATE_COLLECT = %u.", inst_cfg->params.enable_core_state_collect);
    return CM_SUCCESS;
}

static inline bool32 dss_is_cfg_inst_solo()
{
    return (g_inst_cfg->params.nodes_list.inst_cnt <= 1);
}

#if defined(_DEBUG) || defined(DEBUG) || defined(DB_DEBUG_VERSION)
status_t dss_load_fi_params(dss_config_t *inst_cfg);
#endif

#ifdef __cplusplus
}
#endif

#endif
