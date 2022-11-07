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
 * dss_signal.h
 *
 *
 * IDENTIFICATION
 *    src/common/dss_signal.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __DSS_SIGNAL_H_
#define __DSS_SIGNAL_H_
#ifndef WIN32
#include <execinfo.h>
#include "cm_signal.h"
#ifdef __cplusplus
extern "C" {
#endif

status_t dss_signal_proc(void);
void dss_output_current_bt(void);

#ifdef __cplusplus
}
#endif

#endif
#endif
