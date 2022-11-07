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
 * dssaio.h
 *
 *
 * IDENTIFICATION
 *    src/dssaio/dssaio.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __DSS_AIO_H__
#define __DSS_AIO_H__

#include <stdio.h>
#include "time.h"
#ifdef __cplusplus
extern "C" {
#endif

#ifdef WIN32
#if defined(DSSAIO_EXPORTS)
#define DSSAIO_DECLARE __declspec(dllexport)
#elif defined(DSSAIO_IMPORTS)
#define DSSAIO_DECLARE __declspec(dllimport)
#else
#define DSSAIO_DECLARE
#endif
#else
#define DSSAIO_DECLARE __attribute__((visibility("default")))
#endif

typedef enum dssaio_cmd {
    DSSAIO_CMD_PREAD = 0,
    DSSAIO_CMD_PWRITE = 1,
    DSSAIO_CMD_FSYNC = 2,
    DSSAIO_CMD_FDSYNCE = 3,
} dssaio_cmd_t;

typedef struct dssaio_context dssaio_context_t;

DSSAIO_DECLARE int dssaio_setup(int maxevents, dssaio_context_t **ctxp, int threads);
DSSAIO_DECLARE int dssaio_destroy(dssaio_context_t *ctx);
DSSAIO_DECLARE int dssaio_submit(dssaio_context_t *ctx, long nr, void *ios[]);
DSSAIO_DECLARE int dssaio_cancel(dssaio_context_t *ctx, void *iocb, void *evt);
DSSAIO_DECLARE int dssaio_getevents(
    dssaio_context_t *ctx, long min_nr, long nr, void *events, struct timespec *timeout);

#ifdef __cplusplus
}
#endif

#endif
