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

    // for vg lock
    DSS_FI_VGLOCK_FILE_LOCK_R = 4001,
    DSS_FI_VGLOCK_FILE_LOCK_W = 4002,
    DSS_FI_VGLOCK_LOCK_DISK = 4003,
    DSS_FI_VGLOCK_LOCK_SHARE_DISK = 4004,
    DSS_FI_VGLOCK_LOCK_SCSI_DISK = 4005,

    // for shm lock
    DSS_FI_SHM_LOCK_LATCH_STACK_UNSET = 4006,
    DSS_FI_SHM_LOCK_LATCH_STACK_SET = 4007,
    DSS_FI_SHM_LOCK_LATCH_SPIN_LOCK_SET = 4008,
    DSS_FI_SHM_LOCK_LATCH_S_STAT_SET = 4009,
    DSS_FI_SHM_LOCK_LATCH_S_SHARED_COUNT_SET = 4010,
    DSS_FI_SHM_LOCK_LATCH_STACK_TOP_SET = 4011,
    DSS_FI_SHM_LOCK_LATCH_SPIN_UNLOCK_SET = 4012,

    DSS_FI_SHM_LOCK_LATCH_S_SHARED_COUNT_SET2 = 4013,
    DSS_FI_SHM_LOCK_LATCH_STACK_TOP_SET2 = 4014,
    DSS_FI_SHM_LOCK_LATCH_SPIN_UNLOCK_SET2 = 4015,
    DSS_FI_SHM_LOCK_LATCH_SPIN_UNLOCK_SET3 = 4016,

    DSS_FI_SHM_LOCK_UNLATCH_SPIN_LOCK_UNSET = 4017,
    DSS_FI_SHM_LOCK_UNLATCH_SPIN_LOCK_SET = 4018,
    DSS_FI_SHM_LOCK_UNLATCH_SPIN_LOCK_SET2 = 4019,
    DSS_FI_SHM_LOCK_UNLATCH_S_SHARED_COUNT_SET = 4020,
    DSS_FI_SHM_LOCK_UNLATCH_S_STAT_SET = 4021,
    DSS_FI_SHM_LOCK_UNLATCH_SPIN_UNLOCK_SET = 4022,
    DSS_FI_SHM_LOCK_UNLATCH_STACK_SET = 4023,
    DSS_FI_SHM_LOCK_UNLATCH_STACK_TOP_SET = 4024,

    DSS_FI_BEFORE_LOG_FLUSH = 4025,
    DSS_FI_AFTER_LOG_FLUSH = 4026,
    DSS_FI_ENTRY_END = 6000,
} dss_fi_point_name_e;

typedef enum en_dss_fi_scope_e {
    DSS_FI_SCOPE_CLI = 0,
    DSS_FI_SCOPE_SERVER = 1,
    DSS_FI_SCOPE_ALL = 2,
} dss_fi_scope_e;

#if defined(_DEBUG) || defined(DEBUG) || defined(DB_DEBUG_VERSION)
#define DSS_FAULT_INJECTION_ACTION_TRIGGER_CUSTOM(fi_scope, point, action)                       \
    do {                                                                                         \
        if (((fi_scope == DSS_FI_SCOPE_ALL) || ((uint32)fi_scope) == (uint32)dss_is_server()) && \
            ddes_fi_entry_custom_valid(point) && ddes_fi_get_tls_trigger_custom() == CM_FALSE) { \
            ddes_fi_set_tls_trigger_custom(CM_TRUE);                                             \
            LOG_DEBUG_INF("[dss_fi] fi cust action happens at %s", __FUNCTION__);                 \
            action;                                                                              \
        }                                                                                        \
    } while (0)
#else
#define DSS_FAULT_INJECTION_ACTION_TRIGGER_CUSTOM(fi_scope, point, action)
#endif

#ifdef __cplusplus
}
#endif

#endif  // DSS_FAULT_INJECTION_H