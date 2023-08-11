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
 *    src/common/dss_param.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __DSS_PARAM_H__
#define __DSS_PARAM_H__

#include "dss_defs.h"
#include "cm_config.h"
#include "cs_pipe.h"
#include "ceph_rbd_param.h"
#include "mes_metadata.h"
#include "mes.h"
#include "dss_errno.h"
#ifdef __cplusplus
extern "C" {
#endif

#define DSS_MIN_WORK_THREAD_COUNT (2)
#define DSS_MAX_WORK_THREAD_COUNT (64)
#define DSS_MIN_RECV_MSG_BUFF_SIZE (uint64) SIZE_M(1)
#define DSS_MAX_RECV_MSG_BUFF_SIZE (uint64) SIZE_G(1)

typedef enum en_dss_mode {
    DSS_MODE_UNKNOWN = 0,
    DSS_MODE_CLUSTER_RAID = 1,  // MULTI DATANODE's RAID
    DSS_MODE_RAID = 2,          // A DATANODE's RAID
    DSS_MODE_DISK = 3           // A DATANODE's DISK
} dss_mode_e;

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
    uint32 inst_cnt;
    uint64 inst_map;
    char nodes[DSS_MAX_INSTANCES][CM_MAX_IP_LEN];
    uint16 ports[DSS_MAX_INSTANCES];
    uint32 channel_num;
    uint32 work_thread_cnt;
    cs_pipe_type_t pipe_type;
    bool32 elapsed_switch;
    uint32 shm_key;
    uint32 ssl_detect_day;
    uint32 iothread_count;
    uint32 workthread_count;
    rbd_config_params_t rbd_config_params;
    char ceph_config[DSS_FILE_NAME_BUFFER_SIZE];
} dss_params_t;

typedef struct st_dss_config {
    char home[DSS_MAX_PATH_BUFFER_SIZE];
    config_t config;
    dss_params_t params;
} dss_config_t;
extern dss_config_t *g_inst_cfg;

typedef enum en_dss_instance_status {
    DSS_STATUS_PREPARE = 0,
    DSS_STATUS_RECOVERY,
    DSS_STATUS_SWITCH,
    DSS_STATUS_OPEN,
} dss_instance_status_e;
extern dss_instance_status_e *g_dss_instance_status;

#define DSS_UNIX_DOMAIN_SOCKET_NAME ".dss_unix_d_socket"
#define DSS_MAX_SSL_PERIOD_DETECTION 180
#define DSS_MIN_SSL_PERIOD_DETECTION 1

status_t dss_load_config(dss_config_t *inst_cfg);
status_t dss_set_cfg_dir(const char *home, dss_config_t *inst_cfg);

static inline int32 dss_storage_mode(dss_config_t *inst_cfg)
{
    return inst_cfg->params.dss_mode;
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

#ifdef __cplusplus
}
#endif

#endif
