/*
 * Copyright (c) 2023 Huawei Technologies Co.,Ltd.
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
 * dss_reactor.c
 *
 *
 * IDENTIFICATION
 *    src/service/dss_reactor.c
 *
 * -------------------------------------------------------------------------
 */
#include "cm_epoll.h"
#include "dss_reactor.h"
#include "dss_instance.h"
#include "dss_service.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DSS_REACTOR_WAIT_TIME 50

status_t dss_reactor_set_oneshot(dss_session_t *session)
{
    struct epoll_event ev;
    int fd = (int)session->pipe.link.uds.sock;

    ev.events = EPOLLIN | EPOLLONESHOT;
    ev.data.ptr = session;
    reactor_t *reactor = (reactor_t *)(session->reactor);
    if (epoll_ctl(reactor->epollfd, EPOLL_CTL_MOD, fd, &ev) != 0) {
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static dss_workthread_t *dss_reactor_get_workthread(dss_workthread_t *workthread_ctx, uint32 workthread_cnt)
{
    uint32 pos = 0;
    for (pos = 0; pos < workthread_cnt; pos++) {
        if (workthread_ctx[pos].status == THREAD_STATUS_IDLE && workthread_ctx[pos].thread_obj->task == NULL) {
            break;
        }
    }

    if (pos == workthread_cnt) {
        return NULL;
    }

    workthread_ctx[pos].status = THREAD_STATUS_PROCESSSING;
    return &workthread_ctx[pos];
}

static void dss_reactor_disconnect_msg_proc(void *param)
{
    dss_workthread_t *workthread_ctx = (dss_workthread_t *)param;
    pooling_thread_t *thread_obj = workthread_ctx->thread_obj;
    dss_session_t *session = (dss_session_t *)workthread_ctx->current_session;
    LOG_DEBUG_INF("session %u with disconnector %u begin.", session->id, thread_obj->spid);
    dss_clean_reactor_session(session);
    LOG_DEBUG_WAR("session %u is closed.", session->id);
}

static void dss_reactor_session_entry(void *param)
{
    dss_workthread_t *workthread_ctx = (dss_workthread_t *)param;
    pooling_thread_t *thread_obj = workthread_ctx->thread_obj;
    dss_session_t *session = (dss_session_t *)workthread_ctx->current_session;
    LOG_DEBUG_INF("session %u with workthread %u begin.", session->id, thread_obj->spid);

    if (session->is_closed) {
        dss_clean_reactor_session(session);
        LOG_DEBUG_WAR("session %u is closed.", session->id);
        return;
    }
    dss_init_packet(&session->recv_pack, CM_FALSE);
    dss_init_packet(&session->send_pack, CM_FALSE);
    session->pipe.socket_timeout = (int32)CM_SOCKET_TIMEOUT;
    (void)dss_process_single_cmd(&session);
    // do NOT add any code after here, and can not use any data of dss_workthread_t from here
    if (session != NULL) {
        if (dss_reactor_set_oneshot(session) != CM_SUCCESS) {
            LOG_RUN_ERR("[reactor] set oneshot flag of socket failed, session %u, reactor %u, os error %d", session->id,
                ((reactor_t *)session->reactor)->id, cm_get_sock_error());
        }
    }
}

static bool32 dss_reactor_need_quit_waiting(reactor_t *reactor, struct epoll_event *event)
{
    dss_session_t *session = (dss_session_t *)event->data.ptr;
    if (reactor->status != REACTOR_STATUS_RUNNING || reactor->iothread.closed) {
        LOG_DEBUG_WAR("[reactor] reactor is not running, quit and set oneshot for session %u", session->id);
        if (dss_reactor_set_oneshot(session) != CM_SUCCESS) {
            LOG_RUN_ERR("[reactor] set oneshot flag of socket failed, session %u, events %u, reactor %u, os error %d",
                session->id, event->events, ((reactor_t *)session->reactor)->id, cm_get_sock_error());
        }
        return CM_TRUE;
    }
    if (cm_event_timedwait(&reactor->idle_evnt, DSS_REACTOR_WAIT_TIME) != CM_SUCCESS) {
        LOG_DEBUG_ERR("[reactor] workthreads are busy, quit and set oneshot for session %u", session->id);
        if (dss_reactor_set_oneshot(session) != CM_SUCCESS) {
            LOG_RUN_ERR("[reactor] set oneshot flag of socket failed, session %u, events %u, reactor %u, os error %d",
                session->id, event->events, ((reactor_t *)session->reactor)->id, cm_get_sock_error());
        }
        return CM_TRUE;
    }
    return CM_FALSE;
}

void dss_reactor_attach_workthread_for_disconnection_msg(struct epoll_event *event)
{
    dss_session_t *session = (dss_session_t *)event->data.ptr;
    reactor_t *reactor = (reactor_t *)session->reactor;
    if (reactor == NULL) {
        return;
    }
    while (CM_TRUE) {
        cm_thread_lock(&reactor->lock);
        dss_workthread_t *workthread_ctx = dss_reactor_get_workthread(reactor->disconnector_ctx, DSS_DISCONNECTOR_NUM);
        if (workthread_ctx == NULL) {
            // If disconnector_pool is busy, try from workthread_pool.
            workthread_ctx = dss_reactor_get_workthread(reactor->workthread_ctx, reactor->workthread_count);
        }
        if (workthread_ctx != NULL) {
            workthread_ctx->task.action = dss_reactor_disconnect_msg_proc;
            workthread_ctx->current_session = session;
            workthread_ctx->task.param = workthread_ctx;
            session->workthread_ctx = workthread_ctx;
            cm_dispatch_pooling_thread(workthread_ctx->thread_obj, &workthread_ctx->task);
            LOG_DEBUG_INF("[reactor] attach workthread %u to session %u sucessfully, active_sessions is %lld.",
                workthread_ctx->thread_obj->spid, session->id, g_dss_instance.active_sessions);
            cm_thread_unlock(&reactor->lock);
            return;
        }
        cm_thread_unlock(&reactor->lock);
        // Judge whether to try again or not.
        if (dss_reactor_need_quit_waiting(reactor, event)) {
            return;
        }
    }
}

static inline void dss_reset_workthread_ctx(dss_workthread_t *workthread_ctx)
{
    workthread_ctx->task.action = NULL;
    workthread_ctx->current_session = NULL;
    workthread_ctx->task.param = NULL;
    workthread_ctx->status = THREAD_STATUS_IDLE;
}

static inline void dss_session_detach_workthread_inner(dss_session_t *session)
{
    dss_workthread_t *workthread_ctx = (dss_workthread_t *)session->workthread_ctx;
    session->workthread_ctx = NULL;
    session->status = DSS_SESSION_STATUS_IDLE;
    LOG_DEBUG_INF("[reactor] detach workthread %u to session %u sucessfully, active_sessions is %lld.",
        workthread_ctx->thread_obj->spid, session->id, g_dss_instance.active_sessions);
    return;
}

void dss_session_detach_workthread(dss_session_t *session)
{
    dss_workthread_t *workthread_ctx = (dss_workthread_t *)session->workthread_ctx;
    reactor_t *reactor = (reactor_t *)session->reactor;
    dss_session_detach_workthread_inner(session);
    cm_thread_lock(&reactor->lock);
    dss_reset_workthread_ctx(workthread_ctx);
    cm_thread_unlock(&reactor->lock);
    cm_event_notify(&reactor->idle_evnt);
}

static void dss_reactor_peek_disconnection_msgs(
    reactor_t *reactor, struct epoll_event *evs, bool32 *processed, uint32 ev_cnt)
{
    for (uint32 i = 0; i < ev_cnt; ++i) {
        if (evs[i].events & EPOLLHUP) {
            processed[i] = CM_TRUE;
            dss_reactor_attach_workthread_for_disconnection_msg(&evs[i]);
        } else {
            processed[i] = CM_FALSE;
        }
    }
}

// return CM_TRUE: This event has been processed or neglected.
// return CM_FALSE: This event cannot be processed because of exhaustation of workthread_pool.
static bool32 dss_reactor_try_attach_workthread(struct epoll_event *ev)
{
    dss_session_t *session = (dss_session_t *)ev->data.ptr;
    reactor_t *reactor = (reactor_t *)session->reactor;
    cm_thread_lock(&reactor->lock);
    dss_workthread_t *workthread_ctx = dss_reactor_get_workthread(reactor->workthread_ctx, reactor->workthread_count);
    if (workthread_ctx == NULL) {
        cm_thread_unlock(&reactor->lock);
        return CM_FALSE;
    }
    workthread_ctx->task.action = dss_reactor_session_entry;
    workthread_ctx->current_session = session;
    workthread_ctx->task.param = workthread_ctx;
    session->workthread_ctx = workthread_ctx;
    cm_dispatch_pooling_thread(workthread_ctx->thread_obj, &workthread_ctx->task);
    LOG_DEBUG_INF("[reactor] attach workthread %u to session %u successfully, active_sessions is %lld.",
        workthread_ctx->thread_obj->spid, session->id, g_dss_instance.active_sessions);
    cm_thread_unlock(&reactor->lock);
    return CM_TRUE;
}

static void dss_reactor_process_events(reactor_t *reactor, struct epoll_event *evs, uint32 ev_cnt)
{
    bool32 processed[DSS_EV_WAIT_NUM];
    // Firstly peek disconnection msgs.
    dss_reactor_peek_disconnection_msgs(reactor, evs, processed, ev_cnt);
    uint32 loop = 0;
    while (loop < ev_cnt && (!reactor->iothread.closed)) {
        // Some events might have already been processed in dss_reactor_peek_disconnection_msgs.
        if (processed[loop]) {
            ++loop;
            continue;
        }
        if (dss_reactor_try_attach_workthread(&evs[loop])) {
            processed[loop] = CM_TRUE;
            ++loop;
            continue;
        }
        if (dss_reactor_need_quit_waiting(reactor, &evs[loop])) {
            processed[loop] = CM_TRUE;
            ++loop;
            continue;
        }
    }
}

static void dss_reactor_routine(reactor_t *reactor)
{
    if (reactor->status != REACTOR_STATUS_RUNNING) {
        return;
    }
    struct epoll_event events[DSS_EV_WAIT_NUM];
    int nfds = epoll_wait(reactor->epollfd, events, DSS_EV_WAIT_NUM, DSS_EV_WAIT_TIMEOUT);
    if (nfds == -1) {
        if (errno != EINTR) {
            LOG_RUN_ERR("Failed to wait for connection request, OS error:%d", cm_get_os_error());
        }
        return;
    }

    if (nfds == 0) {
        return;
    }

    dss_reactor_process_events(reactor, events, (uint32)nfds);
}

static void dss_reactor_entry(thread_t *thread)
{
    reactor_t *reactor = (reactor_t *)thread->argument;
    cm_set_thread_name("reactor");
    LOG_RUN_INF("reactor thread[%d] started.", reactor->id);
    while (!thread->closed) {
        dss_reactor_routine(reactor);
        if (reactor->status == REACTOR_STATUS_PAUSING) {
            reactor->status = REACTOR_STATUS_PAUSED;
        }
    }
    LOG_RUN_INF("reactor thead[%d] closed.", reactor->id);
    (void)epoll_close(reactor->epollfd);
}

static status_t dss_init_workthread_pool(dss_workthread_t *ctx, cm_thread_pool_t *pool, uint32 count)
{
    cm_init_thread_pool(pool);
    status_t ret = cm_create_thread_pool(pool, SIZE_K(512), count);
    if (ret != CM_SUCCESS) {
        LOG_RUN_ERR("[reactor] failed to create reactor work thread pool, errno %d", cm_get_os_error());
        return ret;
    }

    pooling_thread_t *poolingthread = NULL;
    for (uint32 pos = 0; pos < count; pos++) {
        if (cm_get_idle_pooling_thread(pool, &poolingthread) != CM_SUCCESS) {
            LOG_RUN_ERR("[reactor] failed to get idle work thread pool, errno %d", cm_get_os_error());
            return CM_ERROR;
        }
        ctx[pos].thread_obj = poolingthread;
        ctx[pos].status = THREAD_STATUS_IDLE;
        ctx[pos].task.action = NULL;
        ctx[pos].task.param = NULL;
    }
    return CM_SUCCESS;
}

static status_t dss_reactor_start_threadpool(reactor_t *reactor)
{
    cm_init_thread_lock(&reactor->lock);
    status_t ret =
        dss_init_workthread_pool(reactor->workthread_ctx, &reactor->workthread_pool, reactor->workthread_count);
    if (ret != CM_SUCCESS) {
        LOG_RUN_ERR("[reactor] failed to init workthread_pool.");
        return ret;
    }
    ret = dss_init_workthread_pool(reactor->disconnector_ctx, &reactor->disconnector_pool, DSS_DISCONNECTOR_NUM);
    if (ret != CM_SUCCESS) {
        LOG_RUN_ERR("[reactor] failed to init disconnector_pool.");
        return ret;
    }
    return CM_SUCCESS;
}

static status_t dss_reactors_start()
{
    reactor_t *reactor = NULL;
    reactors_t *pool = &g_dss_instance.reactors;
    for (uint32 i = 0; i < pool->reactor_count; i++) {
        reactor = &pool->reactor_arr[i];
        reactor->id = i;
        reactor->workthread_count = g_dss_instance.inst_cfg.params.workthread_count;
        if (cm_event_init(&reactor->idle_evnt) != CM_SUCCESS) {
            LOG_RUN_ERR("[reactor] failed to init reactor idle event, errno %d", cm_get_os_error());
            return CM_ERROR;
        }
        if (dss_reactor_start_threadpool(reactor) != CM_SUCCESS) {
            return CM_ERROR;
        }
        reactor->epollfd = epoll_create1(0);
        if (reactor->epollfd == -1) {
            LOG_RUN_ERR("[reactor] failed to create epoll fd, errno %d", cm_get_os_error());
            return CM_ERROR;
        }
        reactor->status = REACTOR_STATUS_RUNNING;
        if (cm_create_thread(dss_reactor_entry, SIZE_K(512), reactor, &reactor->iothread) != CM_SUCCESS) {
            LOG_RUN_ERR("[reactor] failed to create reactor thread, errno %d", cm_get_os_error());
            return CM_ERROR;
        }
    }
    return CM_SUCCESS;
}

status_t dss_create_reactors()
{
    reactors_t *pool = &g_dss_instance.reactors;
    (void)cm_atomic_set(&pool->roudroubin, 0);
    pool->reactor_count = g_dss_instance.inst_cfg.params.iothread_count;
    size_t size = sizeof(reactor_t) * pool->reactor_count;
    if ((size == 0) || (size / sizeof(reactor_t) != pool->reactor_count)) {
        CM_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)0, "creating reactors");
        return CM_ERROR;
    }

    pool->reactor_arr = (reactor_t *)malloc(size);
    if (pool->reactor_arr == NULL) {
        CM_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)size, "creating reactors");
        return CM_ERROR;
    }

    errno_t err = memset_s(pool->reactor_arr, size, 0, size);
    if (err != EOK) {
        CM_FREE_PTR(pool->reactor_arr);
        CM_THROW_ERROR(ERR_SYSTEM_CALL, (err));
        return CM_ERROR;
    }
    if (dss_reactors_start() != CM_SUCCESS) {
        dss_destroy_reactors();
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

void dss_pause_reactors()
{
    reactors_t *pool = &g_dss_instance.reactors;
    reactor_t *reactor = NULL;
    if (pool->reactor_arr == NULL) {
        return;
    }
    for (uint32 i = 0; i < pool->reactor_count; i++) {
        reactor = &pool->reactor_arr[i];
        reactor->status = REACTOR_STATUS_PAUSING;
        while (reactor->status != REACTOR_STATUS_PAUSED && !reactor->iothread.closed) {
            cm_sleep(5);
        }
    }
}

void dss_continue_reactors()
{
    reactors_t *pool = &g_dss_instance.reactors;
    reactor_t *reactor = NULL;
    if (pool->reactor_arr == NULL) {
        return;
    }

    for (uint32 i =0; i < pool->reactor_count; i++) {
        reactor = &pool->reactor_arr[i];
        reactor->status = REACTOR_STATUS_RUNNING;
    }
}

void dss_destroy_reactors()
{
    reactor_t *reactor = NULL;
    reactors_t *pool = &g_dss_instance.reactors;
    if (pool->reactor_arr == NULL) {
        return;
    }
    for (uint32 pos = 0; pos < pool->reactor_count; pos++) {
        reactor = &pool->reactor_arr[pos];
        (void)epoll_close(reactor->epollfd);
        if (reactor->iothread.closed == CM_FALSE) {
            cm_close_thread(&reactor->iothread);
        }
        reactor->status = REACTOR_STATUS_STOPPED;
        cm_destroy_thread_pool(&reactor->workthread_pool);
        cm_destroy_thread_pool(&reactor->disconnector_pool);
    }
    pool->reactor_count = 0;
    CM_FREE_PTR(pool->reactor_arr);
}

status_t dss_reactors_add_session(dss_session_t *session)
{
    reactors_t *pool = &g_dss_instance.reactors;
    uint32_t reactor_idx = cm_atomic_inc(&pool->roudroubin) % pool->reactor_count;
    reactor_t *reactor = &pool->reactor_arr[reactor_idx];
    session->reactor = reactor;
    struct epoll_event ev;
    int fd = (int)session->pipe.link.uds.sock;

    (void)cm_atomic32_inc(&reactor->session_count);
    ev.events = EPOLLIN | EPOLLONESHOT;
    ev.data.ptr = session;
    if (epoll_ctl(reactor->epollfd, EPOLL_CTL_ADD, fd, &ev) != 0) {
        LOG_RUN_ERR("[reactor] add session to reactor failed, session %u, reactor %u, os error %d", session->id,
            reactor->id, cm_get_sock_error());
        (void)cm_atomic32_dec(&reactor->session_count);
        return CM_ERROR;
    }

    session->reactor_added = CM_TRUE;
    LOG_DEBUG_INF("[reactor] add session %u to reactor %u sucessfully, current session count %d", session->id,
        reactor->id, reactor->session_count);
    return CM_SUCCESS;
}

void dss_reactors_del_session(dss_session_t *session)
{
    int fd = (int)session->pipe.link.uds.sock;
    reactor_t *reactor = (reactor_t *)session->reactor;
    (void)epoll_ctl(reactor->epollfd, EPOLL_CTL_DEL, fd, NULL);

    (void)cm_atomic32_dec(&reactor->session_count);
    session->reactor_added = CM_FALSE;
    session->reactor = NULL;
    LOG_DEBUG_INF("[reactor] delete session %u to reactor %u sucessfully, current session count %d", session->id,
        reactor->id, reactor->session_count);
}

void dss_clean_reactor_session(dss_session_t *session)
{
    dss_workthread_t *workthread_ctx = (dss_workthread_t *)session->workthread_ctx;
    dss_reactors_del_session(session);
    dss_session_detach_workthread_inner(session);
    dss_release_session_res(session);
    // must be the last step
    dss_reset_workthread_ctx(workthread_ctx);
}

#ifdef __cplusplus
}
#endif