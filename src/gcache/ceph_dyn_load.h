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
 * ceph_dyn_load.h
 *
 *
 * IDENTIFICATION
 *    src/gcache/ceph_dyn_load.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __DSS_CEPH_DYN_LOAD_H__
#define __DSS_CEPH_DYN_LOAD_H__

#ifdef ENABLE_GLOBAL_CACHE

#include <stdbool.h>
#include "cm_config.h"
#ifndef ENABLE_GCOV
#include "rados/librados.h"
#include "rbd/librbd.h"
#else
typedef void *rados_t;
typedef void *rados_ioctx_t;
typedef void *rbd_image_t;
#define RBD_FEATURE_LAYERING 10
#endif  // ENABLE_GCOV

#ifdef __cplusplus
extern "C" {
#endif

void *dss_dlopen(char *filename);

void *dss_dlsym(void *handle, char *funcname);

void dss_dlclose(void *handle);

void load_rbd_rados_library();

void destroy_loaded_library();

status_t dyn_rados_create(rados_t *cluster, const char *uid);

status_t dyn_rados_conf_read_file(rados_t cluster, const char *conf);

status_t dyn_rados_connect(rados_t cluster);

status_t dyn_rados_ioctx_create(rados_t cluster, const char *pool_name, rados_ioctx_t *ioctx);

status_t dyn_rados_shutdown(rados_t cluster);

void dyn_rados_ioctx_destroy(rados_ioctx_t ioctx);

status_t dyn_rbd_create2(rados_ioctx_t ioctx, const char *name, uint64_t size, uint64_t features, int *order);

status_t dyn_rbd_open(rados_ioctx_t io, const char *name, rbd_image_t *image, const char *snap_name);

status_t dyn_rbd_close(rbd_image_t image);

int32_t dyn_rbd_write(rbd_image_t image, uint64_t ofs, int32_t len, const char *buf);

int32_t dyn_rbd_read(rbd_image_t image, uint64_t ofs, int32_t len, char *buf);

status_t dyn_rbd_get_size(rbd_image_t image, int64_t *size);

void dyn_rados_conf_set(rados_t cluster, const char *option, const char *value);

#ifdef __cplusplus
}
#endif
#endif  // ENABLE_GLOBAL_CACHE
#endif  // __DSS_CEPH_DYN_LOAD_H__
