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
 * dssaio_impl.c
 *
 *
 * IDENTIFICATION
 *    src/dssaio/dssaio_impl.c
 *
 * -------------------------------------------------------------------------
 */
#include <time.h>
#include "cm_error.h"
#include "cm_log.h"
#include "cm_var_chan.h"
#include "dss_api.h"
#include "dssaio.h"
#include "dssaio_impl.h"

#define DSSAIO_MERGEBUF_SIZE SIZE_K(128)
#define IOCBS_MAX_NUM 1024

dssaio_handler_t g_processer = {.dssaio_ctx_ref = 0, .proc_lock = 0};
static status_t dssaio_merge_init(dssaio_context_t *ctx)
{
    if (ctx->merger.mergebuf.buf == NULL) {
        cm_spin_lock(&ctx->ctx_lock, NULL);
        if (ctx->merger.mergebuf.buf == NULL) {
            ctx->merger.mergebuf.size = DSSAIO_MAX_MERGE_BUFFER;
#ifdef WIN32
            ctx->merger.mergebuf.buf = (char *)malloc(ctx->merger.mergebuf.size);
#else
            int ret =
                posix_memalign((void **)&ctx->merger.mergebuf.buf, DSSAIO_BLOCK_ALIGN_SIZE, ctx->merger.mergebuf.size);
            if (ret) {
                cm_spin_unlock(&ctx->ctx_lock);
                return CM_ERROR;
            }
#endif
            if (ctx->merger.mergebuf.buf == NULL) {
                CM_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)ctx->merger.mergebuf.size, "alloc merge buffer");
                cm_spin_unlock(&ctx->ctx_lock);
                return CM_ERROR;
            }

            ctx->merger.mergebuf.allocaddr = ctx->merger.mergebuf.buf;
            ctx->merger.mergebuf.curpos = 0;

            ctx->merger.merges = (dssaio_merge_helper_t *)malloc(ctx->maxevents * sizeof(dssaio_merge_helper_t));
            if (ctx->merger.merges == NULL) {
                cm_spin_unlock(&ctx->ctx_lock);
                return CM_ERROR;
            }
        }
        cm_spin_unlock(&ctx->ctx_lock);
    }

    return CM_SUCCESS;
}

static char *dssaio_alloc_mergebuf(dssaio_context_t *ctx, uint32 bytes)
{
    char *addr = NULL;
    cm_spin_lock(&ctx->ctx_lock, NULL);
    if (ctx->merger.mergebuf.buf == NULL) {
        cm_spin_unlock(&ctx->ctx_lock);
        return NULL;
    }

    if (bytes > (ctx->merger.mergebuf.size - ctx->merger.mergebuf.curpos)) {
        cm_spin_unlock(&ctx->ctx_lock);
        return NULL;
    }

    ctx->merger.mergebuf.allocaddr = ctx->merger.mergebuf.buf + ctx->merger.mergebuf.curpos;
    ctx->merger.mergebuf.curpos += bytes;
    addr = ctx->merger.mergebuf.allocaddr;
    ctx->merger.mergebuf.ref++;
    cm_spin_unlock(&ctx->ctx_lock);

    return addr;
}

static inline void dssaio_reset_mergebuf(dssaio_context_t *ctx, char *buf)
{
    cm_spin_lock(&ctx->ctx_lock, NULL);
    ctx->merger.mergebuf.ref--;
    if (ctx->merger.mergebuf.ref == 0) {
        ctx->merger.mergebuf.allocaddr = ctx->merger.mergebuf.buf;
        ctx->merger.mergebuf.curpos = 0;
    }
    cm_spin_unlock(&ctx->ctx_lock);
}

static void dssaio_release_merger(dssaio_context_t *ctx)
{
    cm_spin_lock(&ctx->ctx_lock, NULL);
    if (ctx->merger.mergebuf.allocaddr != NULL) {
        CM_FREE_PTR(ctx->merger.mergebuf.buf);
        ctx->merger.mergebuf.allocaddr = NULL;
        ctx->merger.mergebuf.curpos = 0;
        ctx->merger.mergebuf.size = 0;
        ctx->merger.mergebuf.ref = 0;
    }

    if (ctx->merger.merges != NULL) {
        CM_FREE_PTR(ctx->merger.merges);
    }

    cm_spin_unlock(&ctx->ctx_lock);
}

static void dssaio_set_mergeresults(dssaio_context_t *ctx, iocb_task_t *iocb_param, int32 ret, size_t nbytes)
{
    struct dssaio_event result;
    uint32 seq = iocb_param->seq;
    for (uint32 pos = 0; pos < iocb_param->mergetotal; pos++) {
        result.data = iocb_param->ios[++seq]->data;
        result.obj = iocb_param->ios[seq]->org_obj;
        result.res2 = ret;
        result.res = (long long)iocb_param->ios[seq]->com.nbytes;

        if (cm_var_chan_send(ctx->results_queue, &result, sizeof(struct dssaio_event)) != CM_SUCCESS) {
            return;
        }
    }

    dssaio_reset_mergebuf(ctx, iocb_param->iocb.com.buf);
    return;
}

static void dssaio_set_result(dssaio_context_t *ctx, iocb_task_t *iocb_param, int32 ret, size_t nbytes)
{
    struct dssaio_event result;
    result.data = iocb_param->iocb.data;
    result.obj = iocb_param->iocb.org_obj;
    result.res2 = ret;
    result.res = (long long)((iocb_param->mergetotal != 0) ? iocb_param->ios[iocb_param->seq]->com.nbytes : nbytes);

    if (cm_var_chan_send(ctx->results_queue, &result, sizeof(struct dssaio_event)) != CM_SUCCESS) {
        return;
    }

    if (iocb_param->mergetotal != 0) {
        dssaio_set_mergeresults(ctx, iocb_param, ret, nbytes);
    }
}

static void dssaio_executing(dssaio_thread_ctx_t *thread_ctx)
{
    int32 ret = CM_ERROR;
    size_t ressize = 0;
    struct dssaiocb *iocb = &thread_ctx->iocb_param.iocb;

    if (iocb->opcode == DSSAIO_CMD_PREAD) {
        ret = dss_pread(iocb->fildes, iocb->com.buf, (int)iocb->com.nbytes, iocb->com.offset, (int *)&ressize);
    } else if (iocb->opcode == DSSAIO_CMD_PWRITE) {
        ret = dss_pwrite(iocb->fildes, iocb->com.buf, (int)iocb->com.nbytes, iocb->com.offset);
        if (ret == CM_SUCCESS) {
            ressize = iocb->com.nbytes;
        }
    }

    dssaio_set_result(thread_ctx->iocb_param.ctx, &thread_ctx->iocb_param, ret, ressize);
}

static void dssaio_proc(void *param)
{
    errno_t err;
    uint32 len = 0;
    status_t ret = CM_SUCCESS;
    dssaio_thread_ctx_t *thread_ctx = (dssaio_thread_ctx_t *)param;
    CM_POINTER3(thread_ctx, thread_ctx->dssaio_ctx, thread_ctx->thread_obj);
    pooling_thread_t *thread_obj = thread_ctx->thread_obj;
    dssaio_handler_t *proc = (dssaio_handler_t *)(thread_ctx->processer);

    while (thread_obj->status == THREAD_STATUS_PROCESSSING) {
        err = memset_s(&thread_ctx->iocb_param, sizeof(iocb_task_t), 0, sizeof(iocb_task_t));
        if (err != EOK) {
            break;
        }
        ret = cm_var_chan_recv_timeout(proc->task_queue, &thread_ctx->iocb_param, &len, DSSAIO_QUEUE_TIMEOUT);
        if ((ret == CM_TIMEDOUT) && (thread_obj->status == THREAD_STATUS_PROCESSSING)) {
            continue;
        }

        if ((ret == CM_SUCCESS) && (thread_obj->status == THREAD_STATUS_PROCESSSING)) {
            dssaio_executing(thread_ctx);
        } else {
            break;
        }
    };

    return;
}

static void dssaio_dispatch(dssaio_handler_t *processer)
{
    status_t stats = CM_ERROR;
    pooling_thread_t *thread_obj = NULL;

    for (uint32 i = 0; i < processer->startthreads; i++) {
        stats = cm_get_idle_pooling_thread(&processer->aio_thread_pool, &thread_obj);
        if (stats != CM_SUCCESS) {
            return;
        }
        (processer->thread_ctx[i]).processer = processer;
        (processer->thread_ctx[i]).thread_obj = thread_obj;
        (processer->thread_ctx[i]).task.action = dssaio_proc;
        (processer->thread_ctx[i]).task.param = &(processer->thread_ctx[i]);

        cm_dispatch_pooling_thread(thread_obj, &(processer->thread_ctx[i]).task);
    }
}

static status_t dssaio_init_proc_core(dssaio_handler_t *proc, uint32 maxevents, uint32 threads)
{
    if (threads == 0) {
        proc->startthreads = DSSAIO_DEFAUT_PAR_THREADS;
    } else {
        proc->startthreads = (threads > DSSAIO_MAX_PAR_THREADS) ? DSSAIO_MAX_PAR_THREADS : threads;
    }
    // init task queue
    uint32 queue_len = maxevents * (uint32)sizeof(iocb_task_t) + (uint32)sizeof(int32);
    proc->task_queue = cm_var_chan_new(queue_len);
    CM_RETURN_IF_FALSE(proc->task_queue != NULL);

    // init thread pool
    cm_init_thread_pool(&proc->aio_thread_pool);
    CM_RETURN_IFERR(cm_create_thread_pool(&proc->aio_thread_pool, DSSAIO_DEFAUT_THREAD_STACK, proc->startthreads));

    // init execute thread context
    uint32 size = proc->startthreads * (uint32)sizeof(dssaio_thread_ctx_t);
    proc->thread_ctx = (dssaio_thread_ctx_t *)malloc(size);
    if (proc->thread_ctx == NULL) {
        CM_THROW_ERROR(ERR_ALLOC_MEMORY, size, "threads context");
        return CM_ERROR;
    }

    errno_t err = memset_s(proc->thread_ctx, size, 0, size);
    if (err != EOK) {
        CM_THROW_ERROR(ERR_SYSTEM_CALL, err);
        return CM_ERROR;
    }

    dssaio_dispatch(proc);

    return CM_SUCCESS;
}

static status_t dssaio_init_proc(dssaio_handler_t *proc, uint32 maxevents, uint32 threads)
{
    status_t ret = CM_SUCCESS;
    cm_spin_lock(&proc->proc_lock, NULL);
    if (proc->dssaio_ctx_ref == 0) {
        ret = dssaio_init_proc_core(proc, maxevents, DSSAIO_DEFAUT_PAR_THREADS);
    }
    if (ret == CM_SUCCESS) {
        proc->dssaio_ctx_ref++;
    }
    cm_spin_unlock(&proc->proc_lock);

    return ret;
}

static status_t dssaio_init_ctx(dssaio_context_t *dssaio_ctx, uint32 threads)
{
    // init results queue
    uint32 queue_len = DSSAIO_MAX_EVENTS * sizeof(struct dssaio_event) + sizeof(int32);
    dssaio_ctx->results_queue = cm_var_chan_new(queue_len);
    CM_RETURN_IF_FALSE(dssaio_ctx->results_queue != NULL);

    dssaio_ctx->processer = &g_processer;

    // init dssaio processer
    return dssaio_init_proc(dssaio_ctx->processer, dssaio_ctx->maxevents, threads);
}

static void dssaio_destroy_proc(dssaio_handler_t *proc)
{
    cm_spin_lock(&proc->proc_lock, NULL);
    if (proc->dssaio_ctx_ref == 0) {
        cm_spin_unlock(&proc->proc_lock);
        return;
    }
    proc->dssaio_ctx_ref--;
    if (proc->dssaio_ctx_ref != 0) {
        cm_spin_unlock(&proc->proc_lock);
        return;
    }
    cm_spin_unlock(&proc->proc_lock);

    for (uint32 i = 0; i < proc->startthreads; ++i) {
        cm_release_pooling_thread(proc->thread_ctx[i].thread_obj);
    }

    if (proc->task_queue != NULL) {
        cm_chan_close(&proc->task_queue->ori_chan);
        cm_var_chan_free(&proc->task_queue);
    }

    cm_destroy_thread_pool(&proc->aio_thread_pool);
    CM_FREE_PTR(proc->thread_ctx);
}

static void dssaio_destroy_ctx(dssaio_context_t *ctx)
{
    if (ctx == NULL) {
        return;
    }

    while (cm_var_chan_empty(ctx->processer->task_queue) != CM_TRUE) {
        cm_sleep(DSSAIO_SLEEP_INT);
    }

    dssaio_destroy_proc(ctx->processer);

    if (ctx->results_queue != NULL) {
        cm_chan_close(&ctx->results_queue->ori_chan);
        cm_var_chan_free(&ctx->results_queue);
    }
    dssaio_release_merger(ctx);
}

status_t dssaio_start(int maxevents, dssaio_context_t **ctx, int threads)
{
    *ctx = NULL;
    if (maxevents <= 0 || maxevents > DSSAIO_MAX_EVENTS) {
        return CM_ERROR;
    }

    dssaio_context_t *dssaio_ctx = (dssaio_context_t *)malloc(sizeof(dssaio_context_t));
    if (dssaio_ctx == NULL) {
        return CM_ERROR;
    }
    errno_t err = memset_s(dssaio_ctx, sizeof(dssaio_context_t), 0, sizeof(dssaio_context_t));
    if (err != EOK) {
        CM_FREE_PTR(dssaio_ctx);
        return CM_ERROR;
    }

    dssaio_ctx->maxevents = (uint32)maxevents;

    status_t stats = dssaio_init_ctx(dssaio_ctx, (uint32)threads);
    if (stats != CM_SUCCESS) {
        dssaio_destroy_ctx(dssaio_ctx);
        CM_FREE_PTR(dssaio_ctx);
        return stats;
    }

    *ctx = dssaio_ctx;
    dssaio_ctx->started = CM_TRUE;

    return CM_SUCCESS;
}

status_t dssaio_stop(dssaio_context_t *ctx)
{
    if ((ctx != NULL) && (ctx->started == CM_TRUE)) {
        dssaio_destroy_ctx(ctx);
        CM_FREE_PTR(ctx);
    }

    return CM_SUCCESS;
}

static bool32 dssaio_merge_enable(dssaio_context_t *ctx, dssaio_merge_helper_t *left, struct dssaiocb *right)
{
    char *mgrbuf = NULL;
    if ((left->iocb.fildes != right->fildes) ||
        ((long long)(left->iocb.com.offset + left->iocb.com.nbytes) != right->com.offset) ||
        (left->iocb.opcode != DSSAIO_CMD_PWRITE) || (right->opcode != DSSAIO_CMD_PWRITE)) {
        return CM_FALSE;
    }

    if ((left->iocb.com.nbytes + right->com.nbytes) > DSSAIO_MERGEBUF_SIZE) {
        return CM_FALSE;
    }

    errno_t ret;
    if (left->allocbuf == CM_FALSE) {
        mgrbuf = dssaio_alloc_mergebuf(ctx, DSSAIO_MERGEBUF_SIZE);
        if (mgrbuf == NULL) {
            return CM_FALSE;
        }
        ret = memcpy_s(mgrbuf, left->iocb.com.nbytes, left->iocb.com.buf, left->iocb.com.nbytes);
        if (ret != EOK) {
            return CM_FALSE;
        }
        ret = memcpy_s(mgrbuf + left->iocb.com.nbytes, right->com.nbytes, right->com.buf, right->com.nbytes);
        if (ret != EOK) {
            return CM_FALSE;
        }
        left->iocb.com.buf = mgrbuf;
        left->allocbuf = CM_TRUE;
    } else {
        ret = memcpy_s(
            (char *)(left->iocb.com.buf) + left->iocb.com.nbytes, right->com.nbytes, right->com.buf, right->com.nbytes);
        if (ret != EOK) {
            return CM_FALSE;
        }
    }
    left->iocb.com.nbytes += right->com.nbytes;
    return CM_TRUE;
}

static status_t dssaio_merge_submit(dssaio_context_t *ctx, long nr, struct dssaiocb *ios[])
{
    uint32 right = 0;
    uint32 mergelen = 0;

    if (dssaio_merge_init(ctx) != CM_SUCCESS) {
        return CM_ERROR;
    }

    ctx->merger.merges[mergelen].iocb = *(ios[0]);
    ctx->merger.merges[mergelen].seq = 0;
    ctx->merger.merges[mergelen].mergetotal = 0;
    ctx->merger.merges[mergelen].allocbuf = CM_FALSE;
    mergelen++;
    while (right < (nr - 1)) {
        right++;
        if (dssaio_merge_enable(ctx, &ctx->merger.merges[mergelen - 1], ios[right]) == CM_TRUE) {
            ctx->merger.merges[mergelen - 1].mergetotal++;
        } else {
            ctx->merger.merges[mergelen].iocb = *(ios[right]);
            ctx->merger.merges[mergelen].seq = right;
            ctx->merger.merges[mergelen].mergetotal = 0;
            ctx->merger.merges[mergelen].allocbuf = CM_FALSE;
            mergelen++;
        }
    }

    iocb_task_t task;
    for (uint32 i = 0; i < mergelen; ++i) {
        task.seq = ctx->merger.merges[i].seq;
        task.mergetotal = ctx->merger.merges[i].mergetotal;
        task.ios = ios;
        task.iocb = ctx->merger.merges[i].iocb;
        task.ctx = ctx;
        if (cm_var_chan_send(ctx->processer->task_queue, &task, sizeof(iocb_task_t)) != CM_SUCCESS) {
            return CM_ERROR;
        }
    }

    return CM_SUCCESS;
}

static inline bool32 dssaio_check_merge(dssaio_context_t *ctx, long nr, struct dssaiocb *ios[])
{
    if ((ios[0]->opcode != DSSAIO_CMD_PWRITE) || (nr <= 1)) {
        return CM_FALSE;
    }

    return CM_TRUE;
}

status_t dssaio_submit_impl(dssaio_context_t *ctx, long nr, void **iocbs)
{
    if ((ctx == NULL) || (ctx->started != CM_TRUE) || (nr > DSSAIO_MAX_EVENTS)) {
        return CM_ERROR;
    }

    if (nr > ctx->maxevents) {
        return CM_ERROR;
    }
    struct iocb **ios = (struct iocb **)iocbs;
    struct dssaiocb iocb[IOCBS_MAX_NUM];
    struct dssaiocb *iocbptr[IOCBS_MAX_NUM];

    errno_t err =
        memset_sp(iocb, (sizeof(struct dssaiocb) * IOCBS_MAX_NUM), 0, (sizeof(struct dssaiocb) * IOCBS_MAX_NUM));
    if (err != EOK) {
        CM_THROW_ERROR(ERR_SYSTEM_CALL, (err));
        return CM_ERROR;
    }

    for (int pos = 0; pos < nr; ++pos) {
        iocbptr[pos] = &iocb[pos];
        iocbptr[pos]->org_obj = ios[pos];
        iocbptr[pos]->data = ios[pos]->data;
        iocbptr[pos]->fildes = ios[pos]->aio_fildes;
        iocbptr[pos]->opcode = ios[pos]->aio_lio_opcode;
        iocbptr[pos]->com.buf = ios[pos]->u.c.buf;
        iocbptr[pos]->com.nbytes = ios[pos]->u.c.nbytes;
        iocbptr[pos]->com.offset = ios[pos]->u.c.offset;
    }

    if (dssaio_check_merge(ctx, nr, iocbptr) == CM_TRUE) {
        return dssaio_merge_submit(ctx, nr, iocbptr);
    }

    iocb_task_t task;
    for (uint32 i = 0; i < nr; ++i) {
        task.seq = i;
        task.mergetotal = 0;
        task.ios = iocbptr;
        task.iocb = *(iocbptr[i]);
        task.ctx = ctx;
        if (cm_var_chan_send(ctx->processer->task_queue, &task, sizeof(iocb_task_t)) != CM_SUCCESS) {
            return CM_ERROR;
        }
    }

    return CM_SUCCESS;
}

static inline time_t dssaio_timespec2mssec(const struct timespec *timeout)
{
    time_t mssec = (timeout->tv_sec * 1000 + timeout->tv_nsec / 1000000);
    if ((mssec == 0) && (timeout->tv_nsec != 0)) {
        mssec = 1;
    }

    return mssec;
}

int32 dssaio_getresults(dssaio_context_t *ctx, long min_nr, long nr, struct io_event *events, struct timespec *timeout)
{
    int32 restotal = 0;
    uint32 len = 0;
    status_t ret = CM_ERROR;

    if ((ctx == NULL) || (ctx->started == CM_FALSE)) {
        return CM_ERROR;
    }

    while (restotal < nr) {
        ret = cm_var_chan_recv_timeout(ctx->results_queue, &events[restotal], &len, 0);
        if (ret == CM_TIMEDOUT) {
            if (restotal >= min_nr) {
                return restotal;
            }
            ret = cm_var_chan_recv_timeout(
                ctx->results_queue, &events[restotal], &len, (uint32)dssaio_timespec2mssec(timeout));
            if (ret != CM_SUCCESS) {
                break;
            }
        } else if (ret != CM_SUCCESS) {
            break;
        }
        restotal++;
    }

    return restotal;
}
