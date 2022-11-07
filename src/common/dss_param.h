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
#ifdef ENABLE_GLOBAL_CACHE
#include "ceph_rbd_param.h"
#endif
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
    char lsnr_path[DSS_UNIX_PATH_MAX];
    char disk_lock_file_path[DSS_UNIX_PATH_MAX];
    int32 dss_mode;
    uint32 cfg_session_num;
    int32 lock_interval;
    uint32 dlock_retry_count;

    uint64 mes_pool_size;
    uint32 inst_cnt;
    char nodes[DSS_MAX_INSTANCES][CM_MAX_IP_LEN];
    uint16 ports[DSS_MAX_INSTANCES];
    uint32 channel_num;
    uint32 work_thread_cnt;
    cs_pipe_type_t pipe_type;
    uint64 inst_map;
    uint64 inst_work_status_map;  // one bit , on inst, if 1 inst be ok, 0 inst not ok
    uint64 inst_out_of_work_cnt;  // count of inst, whose status is ok, if not the inst_cnt, the brocast will not send
    bool32 elapsed_switch;
    uint32 shm_key;
#ifdef ENABLE_GLOBAL_CACHE
    rbd_config_params_t rbd_config_params;
    char ceph_config[DSS_FILE_NAME_BUFFER_SIZE];
    void *rados_handle;
    void *rbd_handle;
#endif
} dss_params_t;

typedef struct st_dss_config {
    char home[DSS_MAX_PATH_BUFFER_SIZE];
    config_t config;
    dss_params_t params;
} dss_config_t;

extern dss_config_t *g_inst_cfg;

#define DSS_UNIX_DOMAIN_SOCKET_NAME ".dss_unix_d_socket"

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

static inline uint64 dss_get_inst_work_status(void)
{
    return (uint64)cm_atomic_get((atomic_t *)&g_inst_cfg->params.inst_work_status_map);
}

static inline void dss_set_inst_work_status(uint64 cur_inst_map)
{
    (void)cm_atomic_set((atomic_t *)&g_inst_cfg->params.inst_work_status_map, (int64)cur_inst_map);
}

static inline uint64 dss_get_inst_out_of_work_cnt(void)
{
    return (uint64)cm_atomic_get((atomic_t *)&g_inst_cfg->params.inst_out_of_work_cnt);
}

static inline void dss_set_inst_out_of_work_cnt(uint64 inst_out_of_work_cnt)
{
    (void)cm_atomic_set((atomic_t *)&g_inst_cfg->params.inst_out_of_work_cnt, (int64)inst_out_of_work_cnt);
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
status_t inline dss_get_ssl_param(const char *param_name, char *param_value, uint32 size)
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
