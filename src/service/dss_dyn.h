/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
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
 * dss_dyn.h
 *
 *
 * IDENTIFICATION
 *    src/service/dss_dyn.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __DSS_DYN_H__
#define __DSS_DYN_H__
#ifndef _WIN32

#include "cm_thread.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DSS_LOCK_TIMEOUT_FOR_DYN 100
#define DSS_DYN_SIG_WAIT_TIME_NS 400000000
void dss_dyn_log_proc(thread_t *thread);

#ifdef __cplusplus
}
#endif
#endif
#endif