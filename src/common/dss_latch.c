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
 * dss_latch.c
 *
 *
 * IDENTIFICATION
 *    src/common/dss_latch.c
 *
 * -------------------------------------------------------------------------
 */

#include "dss_latch.h"
#include "dss_shm.h"
#include "cm_utils.h"

void dss_latch_s(latch_t *latch)
{
    cm_latch_s(latch, DSS_DEFAULT_SESSIONID, CM_FALSE, NULL);
}

void dss_latch_x(latch_t *latch)
{
    cm_latch_x(latch, DSS_DEFAULT_SESSIONID, NULL);
}

void dss_unlatch(latch_t *latch)
{
    cm_unlatch(latch, NULL);
}

void dss_latch_x2(latch_t *latch, uint32 sid)
{
    cm_latch_x(latch, sid, NULL);
}

void dss_latch_s2(latch_t *latch, uint32 sid, bool32 is_force, latch_statis_t *stat)
{
    cm_latch_s(latch, sid, is_force, stat);
}

void dss_latch_x2ix(latch_t *latch, uint32 sid, latch_statis_t *stat)
{
    cm_latch_x2ix(latch, sid, stat);
}

void dss_latch_ix2x(latch_t *latch, uint32 sid, latch_statis_t *stat)
{
    cm_latch_ix2x(latch, sid, stat);
}

void dss_set_latch_extent(dss_latch_extent_t *latch_extent, uint16 stat, uint16 shared_count)
{
    latch_extent->stat_bak = stat;
    latch_extent->shared_count_bak = shared_count;
    latch_extent->shared_sid_count_bak = latch_extent->shared_sid_count;
}