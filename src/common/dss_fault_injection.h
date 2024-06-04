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
 * dss_fault_injection.h
 * the ways to perform fault injection:
 * compile DEBUG, which registers all FI triggers at cfg para SS_FI_
 *
 * -------------------------------------------------------------------------
 */
#ifndef DSS_FAULT_INJECTION_H
#define DSS_FAULT_INJECTION_H

#include "ddes_fault_injection.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DSS_FI_MAX_PROBABILTY (uint32)100

typedef enum en_dss_fi_point_name {
    DSS_FI_ENTRY_BEGIN = 4000,
    DSS_FI_MES_PROC_ENTER = DSS_FI_ENTRY_BEGIN,
    DSS_FI_ENTRY_END = 6000,
} dss_fi_point_name_e;

#ifdef __cplusplus
}
#endif

#endif  // DSS_FAULT_INJECTION_H