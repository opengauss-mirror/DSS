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
 * ceph_dyn_load.c
 *
 *
 * IDENTIFICATION
 *    src/gcache/ceph_dyn_load.c
 *
 * -------------------------------------------------------------------------
 */

#ifdef ENABLE_GLOBAL_CACHE
#include <dlfcn.h>
#include "ceph_dyn_load.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CEPH_LIB_RBD "librbd.so"
#define CEPH_LIB_RADOS "librados.so"

#define DYN_LOAD_FUNC_RTN_ERROR(func) \
    do {                              \
        if (NULL == func) {           \
            return CM_ERROR;          \
        }                             \
    } while (0)

static void *g_rados_handle;
static void *g_rbd_handle;
static bool g_is_loaded_library = false;

void *dss_dlopen(char *filename)
{
    return dlopen(filename, RTLD_NOW | RTLD_GLOBAL);
}

void dss_dlclose(void *handle)
{
    dlclose(handle);
}

void *dss_dlsym(void *handle, char *funcname)
{
    return dlsym(handle, funcname);
}

char *dss_dlerror(void)
{
    return dlerror();
}

void *dynamic_load_library(char *library)
{
    void *handle = dss_dlopen(library);
    char *error = NULL;
    if (NULL == handle) {
        error = dss_dlerror();
        printf("dynamic load library [%s] failed: %s\n", library, error);
    }
    return handle;
}

void load_rbd_rados_library()
{
    if (g_is_loaded_library) {
        return;
    }
    g_rados_handle = dynamic_load_library(CEPH_LIB_RADOS);
    g_rbd_handle = dynamic_load_library(CEPH_LIB_RBD);
    if (!g_rados_handle || !g_rbd_handle) {
        printf("Load ceph library failed. Please check if library file exists. \n");
        return;
    }
    g_is_loaded_library = true;
}

void destroy_loaded_library()
{
    if (!g_is_loaded_library) {
        return;
    }
    if (g_rbd_handle) {
        dss_dlclose(g_rbd_handle);
    }
    if (g_rados_handle) {
        dss_dlclose(g_rados_handle);
    }
}

status_t dyn_rados_create(rados_t *cluster, const char *uid)
{
    status_t (*func)() = dss_dlsym(g_rados_handle, "rados_create");
    DYN_LOAD_FUNC_RTN_ERROR(func);
    return (*func)(cluster, uid);
}

status_t dyn_rados_conf_read_file(rados_t cluster, const char *conf)
{
    status_t (*func)() = dss_dlsym(g_rados_handle, "rados_conf_read_file");
    DYN_LOAD_FUNC_RTN_ERROR(func);
    return (*func)(cluster, conf);
}

status_t dyn_rados_connect(rados_t cluster)
{
    status_t (*func)() = dss_dlsym(g_rados_handle, "rados_connect");
    DYN_LOAD_FUNC_RTN_ERROR(func);
    return (*func)(cluster);
}

status_t dyn_rados_ioctx_create(rados_t cluster, const char *pool_name, rados_ioctx_t *ioctx)
{
    status_t (*func)() = dss_dlsym(g_rados_handle, "rados_ioctx_create");
    DYN_LOAD_FUNC_RTN_ERROR(func);
    return (*func)(cluster, pool_name, ioctx);
}

status_t dyn_rados_shutdown(rados_t cluster)
{
    status_t (*func)() = dss_dlsym(g_rados_handle, "rados_shutdown");
    DYN_LOAD_FUNC_RTN_ERROR(func);
    return (*func)(cluster);
}

void dyn_rados_ioctx_destroy(rados_ioctx_t ioctx)
{
    status_t (*func)() = dss_dlsym(g_rados_handle, "rados_ioctx_destroy");
    (*func)(ioctx);
}

status_t dyn_rbd_create2(rados_ioctx_t ioctx, const char *name, uint64_t size, uint64_t features, int *order)
{
    status_t (*func)() = dss_dlsym(g_rbd_handle, "rbd_create2");
    DYN_LOAD_FUNC_RTN_ERROR(func);
    return (*func)(ioctx, name, size, features, order);
}

status_t dyn_rbd_open(rados_ioctx_t ioctx, const char *name, rbd_image_t *image, const char *snap_name)
{
    status_t (*func)() = dss_dlsym(g_rbd_handle, "rbd_open");
    DYN_LOAD_FUNC_RTN_ERROR(func);
    return (*func)(ioctx, name, image, snap_name);
}

status_t dyn_rbd_close(rbd_image_t image)
{
    status_t (*func)() = dss_dlsym(g_rbd_handle, "rbd_close");
    DYN_LOAD_FUNC_RTN_ERROR(func);
    return (*func)(image);
}

int32_t dyn_rbd_write(rbd_image_t image, uint64_t ofs, int32_t len, const char *buf)
{
    status_t (*func)() = dss_dlsym(g_rbd_handle, "rbd_write");
    DYN_LOAD_FUNC_RTN_ERROR(func);
    return (*func)(image, ofs, len, buf);
}

int32_t dyn_rbd_read(rbd_image_t image, uint64_t ofs, int32_t len, char *buf)
{
    status_t (*func)() = dss_dlsym(g_rbd_handle, "rbd_read");
    DYN_LOAD_FUNC_RTN_ERROR(func);
    return (*func)(image, ofs, len, buf);
}

status_t dyn_rbd_get_size(rbd_image_t image, int64_t *size)
{
    status_t (*func)() = dss_dlsym(g_rbd_handle, "rbd_get_size");
    DYN_LOAD_FUNC_RTN_ERROR(func);
    return (*func)(image, size);
}

void dyn_rados_conf_set(rados_t cluster, const char *option, const char *value)
{
    status_t (*func)() = dss_dlsym(g_rbd_handle, "rados_conf_set");
    (void)(*func)(cluster, option, value);
}

#ifdef __cplusplus
}
#endif
#endif  // ENABLE_GLOBAL_CACHE
