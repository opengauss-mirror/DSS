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
 * dss_lsnr.h
 *
 *
 * IDENTIFICATION
 *    src/service/dss_lsnr.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __DSS_LSNR_H__
#define __DSS_LSNR_H__

#include "cs_listener.h"
#include "dss_defs.h"

typedef struct st_uds_lsnr uds_lsnr_t;
typedef status_t (*uds_connect_action_t)(bool32 is_emerg, uds_lsnr_t *lsnr, cs_pipe_t *pipe);
typedef struct st_uds_lsnr {
    lsnr_type_t type;
    thread_t thread;
    int epoll_fd;
    lsnr_status_t status;
    char names[CM_MAX_LSNR_HOST_COUNT][DSS_UNIX_PATH_MAX];
    socket_t socks[CM_MAX_LSNR_HOST_COUNT];
    uint32 permissions;
    atomic_t sock_count;          // may listen on multiple uds file
    uds_connect_action_t action;  // action when a connect accepted
} uds_lsnr_t;

status_t cs_start_uds_lsnr(uds_lsnr_t *lsnr, uds_connect_action_t action);
void cs_pause_uds_lsnr(uds_lsnr_t *lsnr);
void cs_stop_uds_lsnr(uds_lsnr_t *lsnr);
#endif
