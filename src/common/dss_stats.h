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
 * dss_stats.h
 *
 *
 * IDENTIFICATION
 *    src/common/dss_stats.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __DSS_STATS_H__
#define __DSS_STATS_H__

#include "cm_defs.h"
#include "cm_date.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum en_dss_wait_event {
    DSS_PREAD = 0,
    DSS_PWRITE,
    DSS_PREAD_SYN_META,
    DSS_PWRITE_SYN_META,
    DSS_PREAD_DISK,
    DSS_PWRITE_DISK,
    DSS_FOPEN,
    DSS_STAT,
    DSS_FIND_FT_ON_SERVER,
    DSS_EVT_COUNT,
} dss_wait_event_e;

typedef struct st_dss_stat_item {
    atomic_t total_wait_time;
    atomic_t max_single_time;
    atomic_t wait_count;
} dss_stat_item_t;

typedef struct st_dss_stat_ctx {
    bool32 enable_stat;
    dss_wait_event_e wait_event;
} dss_stat_ctx_t;

static inline void dss_begin_stat(timeval_t *begin_tv)
{
    (void)cm_gettimeofday(begin_tv);
}

static inline void dss_end_stat_base(dss_stat_item_t *stat_item, timeval_t *begin_tv)
{
    timeval_t end_tv;
    uint64 usecs;

    (void)cm_gettimeofday(&end_tv);
    usecs = (uint64)TIMEVAL_DIFF_US(begin_tv, &end_tv);
    (void)cm_atomic_add(&stat_item->total_wait_time, (int64)usecs);
    (void)cm_atomic_set(&stat_item->max_single_time, (int64)MAX((uint64)stat_item->max_single_time, usecs));
    (void)cm_atomic_inc(&stat_item->wait_count);
}

static inline void dss_end_stat_ex(dss_stat_ctx_t *stat_ctx, dss_stat_item_t *stat_item, timeval_t *begin_tv)
{
    if(stat_ctx->enable_stat) {
        dss_end_stat_base(stat_item, begin_tv);
    }
}

static inline void dss_set_stat(dss_stat_ctx_t *stat_ctx, dss_wait_event_e event)
{
    stat_ctx->enable_stat = CM_TRUE;
    stat_ctx->wait_event = event;
}

static inline void dss_unset_stat(dss_stat_ctx_t *stat_ctx)
{
    stat_ctx->enable_stat = CM_FALSE;
}

const char *dss_get_stat_event(dss_wait_event_e event);

#ifdef __cplusplus
}
#endif

#endif
