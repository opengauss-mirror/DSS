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
 * dssaio.c
 *
 *
 * IDENTIFICATION
 *    src/dssaio/dssaio.c
 *
 * -------------------------------------------------------------------------
 */
#include "cm_error.h"
#include "dssaio_impl.h"
#include "dssaio.h"

int dssaio_setup(int maxevents, dssaio_context_t **ctxp, int threads)
{
    return dssaio_start(maxevents, ctxp, threads);
}

int dssaio_destroy(dssaio_context_t *ctx)
{
    return dssaio_stop(ctx);
}

int dssaio_submit(dssaio_context_t *ctx, long nr, void *ios[])
{
    return dssaio_submit_impl(ctx, nr, ios);
}

int dssaio_cancel(dssaio_context_t *ctx, void *iocb, void *evt)
{
    return CM_SUCCESS;
}

int dssaio_getevents(dssaio_context_t *ctx, long min_nr, long nr, void *events, struct timespec *timeout)
{
    return dssaio_getresults(ctx, min_nr, nr, events, timeout);
}
