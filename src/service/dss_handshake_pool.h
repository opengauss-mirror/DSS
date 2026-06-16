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
 * dss_handshake_pool.h
 *
 *
 * IDENTIFICATION
 *    src/service/dss_handshake_pool.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __DSS_HANDSHAKE_POOL_H__
#define __DSS_HANDSHAKE_POOL_H__

#include "cs_listener.h"
#include "dss_defs.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ack worker recv proto 超时（ms），应短于客户端 connect_timeout */
#define DSS_CONNECT_ACK_IO_TIMEOUT (int32)(2000)

#define DSS_ACK_POOL_WORKER_NUM 128
#define DSS_HANDSHAKE_POOL_WORKER_NUM 64
#define DSS_CONNECT_POOL_QUEUE_SIZE 512

typedef status_t (*dss_handshake_worker_fn)(const cs_pipe_t *pipe);

status_t dss_handshake_pool_start(dss_handshake_worker_fn worker);
void dss_handshake_pool_stop(void);
status_t dss_handshake_pool_submit(const cs_pipe_t *pipe);

#ifdef __cplusplus
}
#endif

#endif
