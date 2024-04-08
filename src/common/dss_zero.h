/*
 * Copyright (c) 2024 Huawei Technologies Co.,Ltd.
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
 * dss_zero.h
 *
 *
 * IDENTIFICATION
 *    src/common/dss_zero.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __DSS_ZERO_H
#define __DSS_ZERO_H

#include "dss_defs.h"

#ifdef __cplusplus
extern "C" {
#endif

status_t dss_init_zero_buf();
void dss_uninit_zero_buf();
char *dss_get_zero_buf();
uint32 dss_get_zero_buf_len();

#ifdef __cplusplus
}
#endif

#endif