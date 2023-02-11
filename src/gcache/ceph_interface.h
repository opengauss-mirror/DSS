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
 * ceph_interface.h
 *
 *
 * IDENTIFICATION
 *    src/gcache/ceph_interface.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __DSS_CEPH_INTERFACE_H__
#define __DSS_CEPH_INTERFACE_H__

#include <stdint.h>
#include "cm_types.h"
#include "cm_defs.h"

typedef void *rados_cluster;
typedef void *ceph_client_ctx;
typedef void *image_handle;
#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    RBD_LOCK_NONE = 0,
    RBD_LOCK_EXCLUSIVE = 1,
    RBD_LOCK_SHARED = 2,
} LockType;

/* client keepalive deadline, a client should be kicked of */
#define CEPH_CLIENT_KEEPALIVE_TIMEOUT 30

/* image rbd modify time update interval */
#define RBD_MTIME_UPDATE_INTERVAL "10"

/* image rbd access time update interval */
#define RBD_ATIME_UPDATE_INTERVAL "10"

/**
 * before pool operation should init operation context
 * ctx	handler of pool operation
 * poolName ceph pool name
 * conf  path pf ceph cluster conf
 * timeout client keepalive timeout
 * return 0 sucess, !0 failed;
 */
int ceph_client_ctx_init(rados_cluster *cluster, ceph_client_ctx *ctx, char *pool_name, char *conf, uint64_t timeout);

/**
 * close rados cluster handle
 * return void 
 */
void ceph_client_rados_shutdown(rados_cluster cluster);

/**
 * finish pool operation should close context
 * ctx handle of pool operation
 * return void
 */
void ceph_client_ctx_close(ceph_client_ctx ctx);

/**
 * open a image
 * ctx	handler of pool operation
 * imageName image name
 * fd image_handle
 * return 0 sucess, !0 failed
 */
int ceph_client_create_open(ceph_client_ctx ctx, char *image_name, image_handle *fd);

/**
 * close image
 * return void
 */
void ceph_client_create_close(image_handle fd);

/**
 * write data to image
 * fd image operation handler
 * offset write data to offset
 * buf data buf
 * size buf size
 * return 0 sucess, !0 failed
 */
int32_t ceph_client_create_write(image_handle fd, uint64_t offset, char *buf, int32_t size);

/**
 * read data from image
 * fd image operation handler
 * offset read from image offset
 * buf read data buf
 * size read data size
 * return  read size;
 */
int32_t ceph_client_create_read(image_handle fd, uint64_t offset, char *buf, int32_t size);

/**
 * read image size
 * fd image operation handler
 * return image size;
 */
int64_t ceph_client_read_size(image_handle fd);

#ifdef __cplusplus
}
#endif
#endif
