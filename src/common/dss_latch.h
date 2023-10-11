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
 * dss_latch.h
 *
 *
 * IDENTIFICATION
 *    src/common/dss_latch.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __DSS_LATCH_H__
#define __DSS_LATCH_H__

#include "cm_latch.h"

typedef enum en_dss_latch_mode {
    LATCH_MODE_SHARE = 0,
    LATCH_MODE_EXCLUSIVE = 1
} dss_latch_mode_e;
#define SPIN_SLEEP_TIME 500
#define SPIN_WAIT_FOREVER (-1)
#define DSS_CLIENT_TIMEOUT_COUNT 30
#define DSS_CLIENT_TIMEOUT 1000  // ms

#define DSS_DEFAULT_SESSIONID (uint16)0xFFFF
#define DSS_SESSIONID_IN_LOCK(sid) ((sid) + 1)

typedef bool32 (*latch_should_exit)(void);

void dss_latch_s(latch_t *latch);
void dss_latch_x(latch_t *latch);
void dss_unlatch(latch_t *latch);
void dss_latch_x2(latch_t *latch, uint32 sid);
static inline void dss_latch(latch_t *latch, dss_latch_mode_e latch_mode, uint32 sid)
{
    latch_mode == LATCH_MODE_SHARE ? cm_latch_s(latch, sid, CM_FALSE, NULL) : cm_latch_x(latch, sid, NULL);
}

void dss_latch_s2(latch_t *latch, uint32 sid, bool32 is_force, latch_statis_t *stat);
void dss_latch_x2ix(latch_t *latch, uint32 sid, latch_statis_t *stat);
void dss_latch_ix2x(latch_t *latch, uint32 sid, latch_statis_t *stat);

#endif