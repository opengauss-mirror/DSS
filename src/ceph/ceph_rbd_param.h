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
 * ceph_rbd_param.h
 *
 *
 * IDENTIFICATION
 *    src/gcache/ceph_rbd_param.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __DSS_CEPH_RBD_PARAM_H__
#define __DSS_CEPH_RBD_PARAM_H__

#include "cm_config.h"
#include "dss_defs.h"
#include "ceph_interface.h"

#ifdef __cplusplus
extern "C" {
#endif

// ceph rbd config parameters(with globalcache)
typedef struct rbd_config_param_t {
    char vg_name[DSS_MAX_NAME_LEN];
    char pool_name[DSS_MAX_NAME_LEN];
    char image_name[DSS_MAX_NAME_LEN];
    char entry_path[DSS_MAX_NAME_LEN];
    uint16 vg_type;
    rados_cluster cluster;
    ceph_client_ctx *rados_handle;
    image_handle *rbd_handle;
} rbd_config_param;

typedef enum RBD_CONFIG_VALUE_TYPE {
    RBD_CONFIG_TYPE_VG = 0,
    RBD_CONFIG_TYPE_POOL,
    RBD_CONFIG_TYPE_IMAGE
} RBD_CONFIG_VALUE_TYPE;

typedef struct rbd_config_params_t {
    uint16 num;
    rbd_config_param rbd_config[8];
} rbd_config_params_t;

status_t dss_load_cephrbd_params(dss_config_t *inst_cfg);

status_t dss_load_cephrbd_config_file(dss_config_t *inst_cfg);

rbd_config_param *ceph_parse_rbd_configs(const char *name);

void open_global_rbd_handle();

#ifdef __cplusplus
}
#endif

#endif
