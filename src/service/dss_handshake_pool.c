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
 * dss_handshake_pool.c
 *
 *
 * IDENTIFICATION
 *    src/service/dss_handshake_pool.c
 *
 * -------------------------------------------------------------------------
 */

#include "dss_handshake_pool.h"
#include "dss_log.h"
#include "dss_service.h"
#include "cm_spinlock.h"
#include "cm_thread.h"

typedef struct st_dss_connect_queue {
    cs_pipe_t items[DSS_CONNECT_POOL_QUEUE_SIZE];
    uint32 head;
    uint32 tail;
    uint32 count;
    spinlock_t lock;
} dss_connect_queue_t;

typedef struct st_dss_connect_pool {
    dss_connect_queue_t queue;
    thread_t *workers;
    uint32 worker_num;
    bool32 started;
    bool32 stopping;
} dss_connect_pool_t;

typedef struct st_dss_handshake_pool {
    dss_connect_queue_t queue;
    thread_t workers[DSS_HANDSHAKE_POOL_WORKER_NUM];
    bool32 started;
    bool32 stopping;
    dss_handshake_worker_fn worker_fn;
} dss_handshake_pool_t;

static dss_connect_pool_t g_ack_pool;
static thread_t g_ack_workers[DSS_ACK_POOL_WORKER_NUM];
static dss_handshake_pool_t g_handshake_pool;

static status_t dss_handshake_pool_submit_inner(const cs_pipe_t *pipe);
static bool32 dss_connect_queue_dequeue(dss_connect_queue_t *queue, cs_pipe_t *pipe);

static void dss_connect_queue_reset(dss_connect_queue_t *queue)
{
    queue->head = 0;
    queue->tail = 0;
    queue->count = 0;
}

static void dss_connect_queue_drain_disconnect(dss_connect_queue_t *queue, const char *pool_name)
{
    cs_pipe_t pipe;
    uint32 drained = 0;

    while (dss_connect_queue_dequeue(queue, &pipe)) {
        LOG_RUN_INF("[DSS_CONNECT] %s stop: disconnect queued conn_sock=%d", pool_name, (int)pipe.link.uds.sock);
        cs_disconnect(&pipe);
        drained++;
    }
    if (drained > 0) {
        LOG_RUN_INF("[DSS_CONNECT] %s stop: drained %u queued connection(s)", pool_name, drained);
    }
}

static bool32 dss_connect_queue_dequeue(dss_connect_queue_t *queue, cs_pipe_t *pipe)
{
    cm_spin_lock(&queue->lock, NULL);
    if (queue->count == 0) {
        cm_spin_unlock(&queue->lock);
        return CM_FALSE;
    }

    *pipe = queue->items[queue->head];
    queue->head = (queue->head + 1) % DSS_CONNECT_POOL_QUEUE_SIZE;
    queue->count--;
    cm_spin_unlock(&queue->lock);
    return CM_TRUE;
}

static status_t dss_connect_queue_enqueue(dss_connect_queue_t *queue, const cs_pipe_t *pipe, const char *pool_name,
    uint32 backlog_warn_workers)
{
    cm_spin_lock(&queue->lock, NULL);
    if (queue->count >= DSS_CONNECT_POOL_QUEUE_SIZE) {
        cm_spin_unlock(&queue->lock);
        LOG_RUN_ERR("[DSS_CONNECT] %s queue full, conn_sock=%d", pool_name, (int)pipe->link.uds.sock);
        return CM_ERROR;
    }

    queue->items[queue->tail] = *pipe;
    queue->tail = (queue->tail + 1) % DSS_CONNECT_POOL_QUEUE_SIZE;
    queue->count++;
    uint32 queue_len = queue->count;
    cm_spin_unlock(&queue->lock);

    if (backlog_warn_workers > 0 && queue_len > backlog_warn_workers) {
        LOG_RUN_WAR("[DSS_CONNECT] ack pool backlog, conn_sock=%d, queue_len=%u, workers=%u",
            (int)pipe->link.uds.sock, queue_len, backlog_warn_workers);
    }
    return CM_SUCCESS;
}

static void dss_handshake_pool_worker(thread_t *thread)
{
    dss_handshake_pool_t *pool = &g_handshake_pool;
    cs_pipe_t pipe;

    (void)thread;
    cm_set_thread_name("hs-pool");
    LOG_RUN_INF("handshake pool worker started");

    while (!thread->closed) {
        if (!dss_connect_queue_dequeue(&pool->queue, &pipe)) {
            if (pool->stopping) {
                break;
            }
            cm_sleep(1);
            continue;
        }

        if (pool->worker_fn != NULL) {
            (void)pool->worker_fn(&pipe);
        }
    }

    LOG_RUN_INF("handshake pool worker closed");
}

static void dss_ack_pool_worker(thread_t *thread)
{
    cs_pipe_t pipe;
    cs_pipe_t local;

    (void)thread;
    cm_set_thread_name("ack-pool");
    LOG_RUN_INF("ack pool worker started");

    while (!thread->closed) {
        if (!dss_connect_queue_dequeue(&g_ack_pool.queue, &pipe)) {
            if (g_ack_pool.stopping) {
                break;
            }
            cm_sleep(1);
            continue;
        }

        local = pipe;
        local.socket_timeout = DSS_CONNECT_ACK_IO_TIMEOUT;
        if (dss_link_ready_ack(&local) != CM_SUCCESS) {
            LOG_RUN_ERR("[DSS_CONNECT] ack pool link_ready_ack failed, conn_sock=%d, err_code=%d, errno=%d",
                (int)pipe.link.uds.sock, cm_get_error_code(), cm_get_os_error());
            cs_disconnect(&local);
            continue;
        }

        if (dss_handshake_pool_submit_inner(&local) != CM_SUCCESS) {
            cs_disconnect(&local);
        }
    }

    LOG_RUN_INF("ack pool worker closed");
}

static status_t dss_handshake_pool_submit_inner(const cs_pipe_t *pipe)
{
    return dss_connect_queue_enqueue(&g_handshake_pool.queue, pipe, "handshake pool", 0);
}

static status_t dss_connect_pool_start_workers(dss_connect_pool_t *pool, thread_entry_t entry, uint32 worker_num,
    const char *pool_name)
{
    pool->workers = g_ack_workers;
    pool->worker_num = worker_num;
    for (uint32 i = 0; i < worker_num; i++) {
        if (cm_create_thread(entry, SIZE_K(512), pool, &pool->workers[i]) != CM_SUCCESS) {
            LOG_RUN_ERR("[DSS_CONNECT] failed to create %s worker %u, errno %d", pool_name, i, cm_get_os_error());
            pool->stopping = CM_TRUE;
            for (uint32 j = 0; j < i; j++) {
                cm_close_thread(&pool->workers[j]);
            }
            return CM_ERROR;
        }
    }
    return CM_SUCCESS;
}

static void dss_connect_pool_stop_workers(dss_connect_pool_t *pool)
{
    pool->stopping = CM_TRUE;
    dss_connect_queue_drain_disconnect(&pool->queue, "ack pool");
    for (uint32 i = 0; i < pool->worker_num; i++) {
        cm_close_thread(&pool->workers[i]);
    }
    pool->started = CM_FALSE;
    pool->stopping = CM_FALSE;
    dss_connect_queue_reset(&pool->queue);
}

static void dss_handshake_pool_stop_workers(void)
{
    dss_handshake_pool_t *pool = &g_handshake_pool;

    pool->stopping = CM_TRUE;
    dss_connect_queue_drain_disconnect(&pool->queue, "handshake pool");
    for (uint32 i = 0; i < DSS_HANDSHAKE_POOL_WORKER_NUM; i++) {
        cm_close_thread(&pool->workers[i]);
    }
    pool->started = CM_FALSE;
    pool->stopping = CM_FALSE;
    pool->worker_fn = NULL;
    dss_connect_queue_reset(&pool->queue);
}

status_t dss_handshake_pool_start(dss_handshake_worker_fn worker)
{
    dss_handshake_pool_t *pool = &g_handshake_pool;
    dss_connect_pool_t *ack_pool = &g_ack_pool;
    errno_t err;

    if (pool->started) {
        return CM_SUCCESS;
    }

    err = memset_s(pool, sizeof(dss_handshake_pool_t), 0, sizeof(dss_handshake_pool_t));
    if (err != EOK) {
        CM_THROW_ERROR(ERR_SYSTEM_CALL, err);
        return CM_ERROR;
    }
    err = memset_s(ack_pool, sizeof(dss_connect_pool_t), 0, sizeof(dss_connect_pool_t));
    if (err != EOK) {
        CM_THROW_ERROR(ERR_SYSTEM_CALL, err);
        return CM_ERROR;
    }

    pool->worker_fn = worker;
    pool->started = CM_TRUE;
    for (uint32 i = 0; i < DSS_HANDSHAKE_POOL_WORKER_NUM; i++) {
        if (cm_create_thread(dss_handshake_pool_worker, SIZE_K(512), pool, &pool->workers[i]) != CM_SUCCESS) {
            LOG_RUN_ERR("[DSS_CONNECT] failed to create handshake pool worker %u, errno %d", i, cm_get_os_error());
            pool->stopping = CM_TRUE;
            for (uint32 j = 0; j < i; j++) {
                cm_close_thread(&pool->workers[j]);
            }
            pool->started = CM_FALSE;
            pool->worker_fn = NULL;
            return CM_ERROR;
        }
    }

    if (dss_connect_pool_start_workers(ack_pool, dss_ack_pool_worker, DSS_ACK_POOL_WORKER_NUM, "ack pool") !=
        CM_SUCCESS) {
        dss_handshake_pool_stop_workers();
        return CM_ERROR;
    }
    ack_pool->started = CM_TRUE;

    LOG_RUN_INF("[DSS_CONNECT] connect pools started, ack_workers=%u, hs_workers=%u, queue_size=%u",
        DSS_ACK_POOL_WORKER_NUM, DSS_HANDSHAKE_POOL_WORKER_NUM, DSS_CONNECT_POOL_QUEUE_SIZE);
    return CM_SUCCESS;
}

void dss_handshake_pool_stop(void)
{
    if (g_ack_pool.started) {
        dss_connect_pool_stop_workers(&g_ack_pool);
        LOG_RUN_INF("[DSS_CONNECT] ack pool stopped");
    }
    if (g_handshake_pool.started) {
        dss_handshake_pool_stop_workers();
        LOG_RUN_INF("[DSS_CONNECT] handshake pool stopped");
    }
}

status_t dss_handshake_pool_submit(const cs_pipe_t *pipe)
{
    if (!g_ack_pool.started || pipe == NULL) {
        return CM_ERROR;
    }
    return dss_connect_queue_enqueue(&g_ack_pool.queue, pipe, "ack pool", DSS_ACK_POOL_WORKER_NUM);
}
