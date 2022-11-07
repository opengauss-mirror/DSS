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
 * cm_thv.c
 *
 *
 * IDENTIFICATION
 *    src/common/cm_thv.c
 *
 * -------------------------------------------------------------------------
 */

#include "cm_thread.h"
#include "cm_error.h"
#include "dss_log.h"
#include "cm_log.h"
#include "dss_thv.h"
#ifndef WIN32
#include <sys/time.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#ifndef WIN32
/* ****Thread variable defined begin.**** */
// THV --> THREAD VARIANT
// Thread variable control function.
static thv_ctrl_t g_thv_ctrl_func[MAX_THV_TYPE];

// Thread variant address, it will be created in function create_var_func and released in function release_var_func.
static __thread pointer_t g_thv_addr[MAX_THV_TYPE] = {0};
// Thread variant is call pthread_setspcific
static __thread bool32 g_thv_spec = CM_FALSE;
static pthread_key_t g_thv_key;

// destroy all thread variable content when thread exit
static void cm_destroy_thv(pointer_t thread_var)
{
    if (thread_var == NULL) {
        return;
    }
    pointer_t *curr_thread_var = (pointer_t *)thread_var;
    for (uint32 i = 0; i < MAX_THV_TYPE; i++) {
        if (curr_thread_var[i] != NULL) {
            if (g_thv_ctrl_func[i].release != NULL) {
                g_thv_ctrl_func[i].release(curr_thread_var[i]);
            }
            curr_thread_var[i] = NULL;
        }
    }
}

status_t cm_create_thv_ctrl(void)
{
    int32 ret = pthread_key_create(&g_thv_key, cm_destroy_thv);
    if (ret != EOK) {
        DSS_THROW_ERROR(ERR_SYSTEM_CALL, "g_thv_key", ret, "call pthread_key_create failed");
        return CM_ERROR;
    }
    errno_t errcode =
        memset_s(g_thv_ctrl_func, sizeof(thv_ctrl_t) * MAX_THV_TYPE, 0, sizeof(thv_ctrl_t) * MAX_THV_TYPE);
    securec_check_ret(errcode);
    return CM_SUCCESS;
}

status_t cm_set_thv_args_by_id(
    thv_type_e var_type, init_thv_func init, create_thv_func create, release_thv_func release)
{
    if (var_type >= MAX_THV_TYPE) {
        DSS_THROW_ERROR(ERR_SYSTEM_CALL, "g_thv_key", var_type, "Invalid var type");
        return CM_ERROR;
    }

    g_thv_ctrl_func[var_type].init = init;

    if (create == NULL) {
        DSS_THROW_ERROR(ERR_SYSTEM_CALL, "g_thv_ctrl_func.create", -1, "create_thv_func cannot be null");
        return CM_ERROR;
    }
    g_thv_ctrl_func[var_type].create = create;
    g_thv_ctrl_func[var_type].release = release;

    return CM_SUCCESS;
}

void cm_init_thv(void)
{
    for (uint32 var_type = 0; var_type < MAX_THV_TYPE; var_type++) {
        if (g_thv_ctrl_func[var_type].init != NULL) {
            g_thv_ctrl_func[var_type].init();
        }
    }
}

status_t cm_get_thv(thv_type_e var_type, pointer_t *result)
{
    if (g_thv_addr[var_type] == NULL) {
        int32 ret = g_thv_ctrl_func[var_type].create(&g_thv_addr[var_type]);
        if (ret != EOK) {
            DSS_THROW_ERROR(ERR_SYSTEM_CALL, "g_thv_ctrl_func.create", var_type, "create thread variable failed");
            return CM_ERROR;
        }
        if (!g_thv_spec) {
            ret = pthread_setspecific(g_thv_key, g_thv_addr);
            if (ret != EOK) {
                DSS_THROW_ERROR(ERR_SYSTEM_CALL, "g_thv_key", ret, "call pthread_setspecific failed");
                return CM_ERROR;
            }
            g_thv_spec = CM_TRUE;
        }
    }

    *result = g_thv_addr[var_type];
    return CM_SUCCESS;
}

status_t cm_launch_thv(thv_type_e var_type, init_thv_func init, create_thv_func create, release_thv_func release)
{
    // now begin init thread variant
    if (cm_create_thv_ctrl() != CM_SUCCESS) {
        return CM_ERROR;
    }

    if (cm_set_thv_args_by_id(GLOBAL_THV_OBJ0, init, create, release) != CM_SUCCESS) {
        return CM_ERROR;
    }

    cm_init_thv();

    return CM_SUCCESS;
}

/* ****Thread variable defined end.**** */
#else

status_t cm_create_thv_ctrl(void)
{
    return CM_SUCCESS;
}

status_t cm_set_thv_args_by_id(
    thv_type_e var_type, init_thv_func init, create_thv_func create, release_thv_func release)
{
    return CM_SUCCESS;
}

void cm_init_thv(void)
{}

status_t cm_get_thv(thv_type_e var_type, pointer_t *result)
{
    return CM_ERROR;
}

status_t cm_launch_thv(thv_type_e var_type, init_thv_func init, create_thv_func create, release_thv_func release)
{
    return CM_SUCCESS;
}

#endif

#ifdef __cplusplus
}
#endif
