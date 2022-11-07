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
 * dss_lsnr.c
 *
 *
 * IDENTIFICATION
 *    src/service/dss_lsnr.c
 *
 * -------------------------------------------------------------------------
 */
#include "cm_file.h"
#include "dss_log.h"
#include "dss_param.h"
#include "dss_lsnr.h"

static void cs_close_uds_socks(uds_lsnr_t *lsnr)
{
    uint32 loop;
    for (loop = 0; loop < lsnr->sock_count; ++loop) {
        if (lsnr->socks[loop] != CS_INVALID_SOCKET) {
            cs_uds_socket_close(&lsnr->socks[loop]);
        }
    }
    lsnr->sock_count = 0;
}

static bool32 cs_uds_create_link(socket_t sock_ready, cs_pipe_t *pipe)
{
    uds_link_t *link = &pipe->link.uds;

    link->local.salen = (socklen_t)sizeof(link->local.addr);
    (void)cs_uds_getsockname(sock_ready, &link->local);

    link->remote.salen = (socklen_t)sizeof(link->remote.addr);
    link->sock = (socket_t)accept(sock_ready, SOCKADDR(&link->remote), &link->remote.salen);

    if (link->sock == CS_INVALID_SOCKET) {
        LOG_RUN_INF("Failed to accept connection request, OS error:%d", cm_get_os_error());
        return CM_FALSE;
    }

    /* set default options of sock */
    cs_set_io_mode(link->sock, CM_FALSE, CM_FALSE);
    cs_set_buffer_size(link->sock, CM_TCP_DEFAULT_BUFFER_SIZE, CM_TCP_DEFAULT_BUFFER_SIZE);
    cs_set_keep_alive(link->sock, CM_TCP_KEEP_IDLE, CM_TCP_KEEP_INTERVAL, CM_TCP_KEEP_COUNT);
    cs_set_linger(link->sock, 1, 1);
    link->closed = CM_FALSE;
    return CM_TRUE;
}

static void cs_try_uds_accept(uds_lsnr_t *lsnr, cs_pipe_t *pipe)
{
    bool32 is_emerg = CM_FALSE;
    socket_t sock_ready;
    int32 ret;
    int32 loop = 0;
    struct epoll_event evnts[CM_MAX_LSNR_HOST_COUNT];

    ret = epoll_wait(lsnr->epoll_fd, evnts, (int)lsnr->sock_count, (int)CM_POLL_WAIT);
    if (ret == 0) {
        return;
    }

    if (ret < 0) {
        if (cm_get_os_error() != EINTR) {
            LOG_RUN_ERR("Failed to wait for connection request, OS error:%d", cm_get_os_error());
        }
        return;
    }

    for (loop = 0; loop < ret; loop++) {
        sock_ready = evnts[loop].data.fd;
        if (!cs_uds_create_link(sock_ready, pipe)) {
            continue;
        }
        if (lsnr->status != LSNR_STATUS_RUNNING) {
            LOG_RUN_ERR("cs_try_uds_accept error :%u\n", lsnr->status);
            cs_uds_disconnect(&pipe->link.uds);
            continue;
        }
        is_emerg = (sock_ready == lsnr->socks[0]);
        (void)lsnr->action(is_emerg, lsnr, pipe);
    }
}

static void cs_uds_lsnr_proc(thread_t *thread)
{
    cs_pipe_t pipe;
    uds_lsnr_t *lsnr = NULL;

    CM_ASSERT(thread != NULL);
    lsnr = (uds_lsnr_t *)thread->argument;
    /* thread entry function, str */
    (void)memset_s(&pipe, sizeof(cs_pipe_t), 0, sizeof(cs_pipe_t));

    pipe.type = CS_TYPE_DOMAIN_SCOKET;
    cm_set_thread_name("uds-lsnr");
    LOG_RUN_INF("uds-lsnr thread started");

    while (!thread->closed) {
        if (lsnr->status == LSNR_STATUS_RUNNING) {
            cs_try_uds_accept(lsnr, &pipe);
        } else if (lsnr->status == LSNR_STATUS_PAUSING) {
            lsnr->status = LSNR_STATUS_PAUSED;
        }
    }

    LOG_RUN_INF("uds-lsnr thread closed");
}

static status_t cs_uds_lsnr_init_epoll_fd(uds_lsnr_t *lsnr)
{
    struct epoll_event ev;
    uint32 loop;

    lsnr->epoll_fd = epoll_create1(0);
    if (lsnr->epoll_fd == -1) {
        DSS_THROW_ERROR(ERR_SOCKET_LISTEN, "create epoll fd for listener", cm_get_os_error());
        return CM_ERROR;
    }

    for (loop = 0; loop < lsnr->sock_count; loop++) {
        ev.events = EPOLLIN;
        ev.data.fd = (int)lsnr->socks[loop];
        if (epoll_ctl(lsnr->epoll_fd, EPOLL_CTL_ADD, ev.data.fd, &ev) != 0) {
            cm_close_file(lsnr->epoll_fd);
            DSS_THROW_ERROR(ERR_SOCKET_LISTEN, "add socket for listening to epool fd", cm_get_os_error());
            return CM_ERROR;
        }
    }

    return CM_SUCCESS;
}

static status_t cs_create_uds_socks(uds_lsnr_t *lsnr)
{
    char(*name)[CM_UNIX_PATH_MAX] = lsnr->names;

    lsnr->sock_count = 0;
    for (uint32 loop = 0; loop < CM_MAX_LSNR_HOST_COUNT; loop++) {
        if (name[loop][0] == '\0') {
            continue;
        }
        if (cs_uds_create_listener(lsnr->names[loop], &lsnr->socks[loop], (uint16)lsnr->permissions) != CM_SUCCESS) {
            cs_close_uds_socks(lsnr);
            return CM_ERROR;
        }
        (void)cm_atomic_inc(&lsnr->sock_count);
    }

    return CM_SUCCESS;
}

void cs_pause_uds_lsnr(uds_lsnr_t *lsnr)
{
    if (lsnr->thread.id == 0) {
        return;
    }
    lsnr->status = LSNR_STATUS_PAUSING;
    while (lsnr->status != LSNR_STATUS_PAUSED && !lsnr->thread.closed) {
        cm_sleep(1);
    }
}

void cs_stop_uds_lsnr(uds_lsnr_t *lsnr)
{
    cm_close_thread(&lsnr->thread);
    cs_close_uds_socks(lsnr);
    (void)epoll_close(lsnr->epoll_fd);
}

status_t cs_start_uds_lsnr(uds_lsnr_t *lsnr, uds_connect_action_t action)
{
    CM_ASSERT(lsnr != NULL);
    status_t status;
    lsnr->status = LSNR_STATUS_STOPPED;
    lsnr->action = action;

    for (uint32 loop = 0; loop < CM_MAX_LSNR_HOST_COUNT; loop++) {
        lsnr->socks[loop] = CS_INVALID_SOCKET;
    }

    status = cs_create_uds_socks(lsnr);
    if (status != CM_SUCCESS) {
        LOG_RUN_ERR("create domain socket failed. error code is %d.", cm_get_os_error());
        return CM_ERROR;
    }

    if (cs_uds_lsnr_init_epoll_fd(lsnr) != CM_SUCCESS) {
        cs_close_uds_socks(lsnr);
        LOG_RUN_ERR("failed to init epoll fd");
        return CM_ERROR;
    }

    lsnr->status = LSNR_STATUS_RUNNING;
    if (cm_create_thread(cs_uds_lsnr_proc, 0, lsnr, &lsnr->thread) != CM_SUCCESS) {
        cs_close_uds_socks(lsnr);
        (void)epoll_close(lsnr->epoll_fd);

        lsnr->status = LSNR_STATUS_STOPPED;
        LOG_RUN_ERR("failed to create accept thread");
        return CM_ERROR;
    }
    return CM_SUCCESS;
}
