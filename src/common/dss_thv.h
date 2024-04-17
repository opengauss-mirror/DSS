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
 * dss_thv.h
 *
 *
 * IDENTIFICATION
 *    src/common/dss_thv.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __DSS_THV_H__
#define __DSS_THV_H__

#include "cm_atomic.h"
#include "cm_defs.h"
#include "cm_error.h"

#ifdef WIN32
#else
#include <pthread.h>
#include <sys/resource.h>
#include <sys/prctl.h>
#include <sched.h>
#include <sys/eventfd.h>
#include <sys/epoll.h>
#endif

#ifndef WIN32
#include <sys/types.h>
#include <sys/syscall.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* ****Thread variable defined begin.**** */
#define DB_MAX_THV_OBJ_NUM 3

typedef enum tag_thv_type {
    GLOBAL_THV_OBJ0 = 0,  // had been occupied by dss connection
    GLOBAL_THV_OBJ1 = 1,  // dss connection options
    GLOBAL_THV_OBJ2 = 2,
    // add more here, notice modify DB_MAX_THV_OBJ_NUM
    MAX_THV_TYPE
} thv_type_e;

typedef handle_t (*init_thv_func)(void);
typedef status_t (*create_thv_func)(pointer_t *result);
typedef void (*release_thv_func)(pointer_t thv_addr);

typedef struct tag_thv_ctrl {
    // It will be called one time for a process.
    init_thv_func init;
    // It will be called one time for per thread when use it.
    create_thv_func create;
    // It will be called when thread_var_addr isn't null and the thread whill exit.
    release_thv_func release;
} thv_ctrl_t;

// create thread variant storages
// NOTICE: all release operation will mount in release_thv_func
status_t cm_create_thv_ctrl(void);

status_t cm_set_thv_args_by_id(
    thv_type_e var_type, init_thv_func init, create_thv_func create, release_thv_func release);
// initialize all thread variant，call it after cm_set_thv_args_by_id
void cm_init_thv(void);

status_t cm_get_thv(thv_type_e var_type, bool32 is_create, pointer_t *result);

status_t cm_launch_thv(thv_ctrl_t *thv_ctrls, uint32 thv_ctrl_cnt);

uint32 dss_get_current_thread_id();
#ifdef __cplusplus
}
#endif

#endif  // __DSS_THV_H__
