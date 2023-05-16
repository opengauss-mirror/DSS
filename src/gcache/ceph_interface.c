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
 * ceph_interface.c
 *
 *
 * IDENTIFICATION
 *    src/gcache/ceph_interface.c
 *
 * -------------------------------------------------------------------------
 */

#include <sys/types.h>
#include "cm_error.h"
#include "ceph_dyn_load.h"
#include "ceph_interface.h"

#ifdef __cplusplus
extern "C" {
#endif

int ceph_client_ctx_init(rados_cluster *rds_cluster, ceph_client_ctx *ctx, char *pool_name, char *conf, uint64_t timeout)
{
#ifdef ENABLE_GLOBAL_CACHE
    rados_t cluster;
    rados_ioctx_t iocxt;
    load_rbd_rados_library();
    if (dyn_rados_create(&cluster, "admin") < 0) {
        goto out;
    }
    if (dyn_rados_conf_read_file(cluster, conf) < 0) {
        goto out;
    }
    dyn_rados_conf_set(cluster, "rbd_mtime_update_interval", RBD_MTIME_UPDATE_INTERVAL);
    dyn_rados_conf_set(cluster, "rbd_atime_update_interval", RBD_ATIME_UPDATE_INTERVAL);
    if (dyn_rados_connect(cluster) < 0) {
        goto out;
    }
    if (dyn_rados_ioctx_create(cluster, pool_name, &iocxt) < 0) {
        goto out;
    }
    *ctx = (ceph_client_ctx *)iocxt;
    *rds_cluster = (rados_cluster *)cluster;
    return CM_SUCCESS;

out:
    dyn_rados_shutdown(cluster);
    destroy_loaded_library();
    return CM_ERROR;
#else
    return CM_ERROR;
#endif
}

void ceph_client_rados_shutdown(rados_cluster cluster)
{
#ifdef ENABLE_GLOBAL_CACHE
    dyn_rados_shutdown((rados_t *)cluster);
#endif
}

void ceph_client_ctx_close(ceph_client_ctx ctx)
{
#ifdef ENABLE_GLOBAL_CACHE
    dyn_rados_ioctx_destroy((rados_ioctx_t *)ctx);
    ctx = NULL;
#endif
}

int ceph_client_create_open(ceph_client_ctx ctx, char *image_name, image_handle *fd)
{
#ifdef ENABLE_GLOBAL_CACHE
    rbd_image_t image;
    if (dyn_rbd_open((rados_ioctx_t *)ctx, image_name, &image, NULL) < 0) {
        return CM_ERROR;
    }
    *fd = (image_handle *)(image);
#endif
    return CM_SUCCESS;
}

void ceph_client_create_close(image_handle fd)
{
#ifdef ENABLE_GLOBAL_CACHE
    (void)dyn_rbd_close((rbd_image_t *)fd);
    fd = NULL;
#endif
}

int32_t ceph_client_create_write(image_handle fd, uint64_t offset, char *buf, int32_t size)
{
    int32_t ret = -1;
#ifdef ENABLE_GLOBAL_CACHE
    ret = dyn_rbd_write((rbd_image_t *)fd, offset, size, buf);
#endif
    return ret;
}

int32_t ceph_client_create_read(image_handle fd, uint64_t offset, char *buf, int32_t size)
{
    int32_t ret = -1;
#ifdef ENABLE_GLOBAL_CACHE
    ret = dyn_rbd_read((rbd_image_t *)fd, offset, size, buf);
#endif
    return ret;
}

int64_t ceph_client_read_size(image_handle fd)
{
    int64_t size = -1;
#ifdef ENABLE_GLOBAL_CACHE
    dyn_rbd_get_size((rbd_image_t *)fd, &size);
#endif
    return size;
}

void ceph_client_get_data_addr(image_handle fd, ceph_client_ctx ctx, uint64_t offset, uint64_t *obj_offset,
    char *obj_addr, uint32_t *obj_id)
{
#ifdef ENABLE_GLOBAL_CACHE
    dyn_rbd_get_data_addr((rbd_image_t *)fd, ctx, offset, obj_offset, obj_addr, obj_id);
#endif
}

void ceph_client_get_object_size(image_handle fd, long long *obj_size)
{
#ifdef ENABLE_GLOBAL_CACHE
    rbd_image_info_t info;
    dyn_rbd_stat((rbd_image_t *)fd, &info, 0);
    *obj_size = info.obj_size;
#endif
}

#ifdef __cplusplus
}
#endif
