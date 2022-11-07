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
 * dssaio_impl.h
 *
 *
 * IDENTIFICATION
 *    src/dssaio/dssaio_impl.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __DSS_AIO_IMPL_H__
#define __DSS_AIO_IMPL_H__

#include "cm_thread_pool.h"
#include "cm_var_chan.h"
#include "dssaio.h"
#ifdef _WIN64
#if !defined(__x86_64__)
#define __x86_64__
#endif
#elif defined _WIN32
#if !defined(__i386__)
#define __i386__
#endif
#endif

#ifdef WIN32
typedef struct {
    unsigned long sig[];
} sigset_t;
#endif
#include "libaio.h"

#define DSSAIO_MAX_EVENTS 4096
#define DSSAIO_DEFAUT_PAR_THREADS 64
#define DSSAIO_MAX_PAR_THREADS 128
#define DSSAIO_DEFAUT_THREAD_STACK (2 * 1024 * 1024)
#define DSSAIO_QUEUE_TIMEOUT 50
#define DSSAIO_MERGE_MAXPAGE 128
#define DSSAIO_PAR_SUBMIT_FILES 128
#define DSSAIO_MAX_MERGE_BUFFER SIZE_M(1)
#define DSSAIO_BLOCK_ALIGN_SIZE 512
#define DSSAIO_SLEEP_INT 50

struct dssaio_common {
    void *buf;
    size_t nbytes;
    long long offset;
    unsigned flags;
    unsigned resfd;
};

struct dssaiocb {
    void *data;
    void *org_obj;
    unsigned key;
    short opcode;
    short reqprio;
    int fildes;
    struct dssaio_common com;
};

struct dssaio_event {
    void *data;      // the data field from the dssaiocb
    void *obj;       // what iocb this event came from
    long long res;   // result code for this event
    long long res2;  // secondary result
};
typedef struct st_iocb_task {
    uint32 seq;
    uint32 mergetotal;
    struct dssaiocb iocb;
    struct dssaiocb **ios;
    dssaio_context_t *ctx;
} iocb_task_t;

typedef struct st_dssaio_thread_ctx {
    void *processer;
    pooling_thread_t *thread_obj;
    iocb_task_t iocb_param;
    thread_task_t task;
} dssaio_thread_ctx_t;

typedef struct st_dssaio_handler {
    cm_thread_pool_t aio_thread_pool;
    dssaio_thread_ctx_t *thread_ctx;
    uint32 startthreads;
    var_chan_t *task_queue;
    uint32 dssaio_ctx_ref;
    spinlock_t proc_lock;
} dssaio_handler_t;

typedef struct st_dssaio_merge_buf {
    uint32 size;
    uint32 curpos;
    char *buf;
    char *allocaddr;
    uint32 ref;
} dssaio_merge_buf_t;

typedef struct st_dssaio_merge_helper {
    uint32 seq;
    uint32 mergetotal;
    struct dssaiocb iocb;
    bool32 allocbuf;
} dssaio_merge_helper_t;

typedef struct st_dssaio_page_merge {
    dssaio_merge_helper_t *merges;
    dssaio_merge_buf_t mergebuf;
} dssaio_page_merge_t;

typedef struct dssaio_context {
    bool32 started;
    uint32 maxevents;
    spinlock_t ctx_lock;
    var_chan_t *results_queue;
    dssaio_handler_t *processer;
    dssaio_page_merge_t merger;
} dssaio_context_t;

status_t dssaio_start(int maxevents, dssaio_context_t **ctx, int threads);
status_t dssaio_stop(dssaio_context_t *ctx);
status_t dssaio_submit_impl(dssaio_context_t *ctx, long nr, void **iocbs);
int32 dssaio_getresults(dssaio_context_t *ctx, long min_nr, long nr, struct io_event *events, struct timespec *timeout);

#endif  // __DSS_AIO_IMPL_H__
