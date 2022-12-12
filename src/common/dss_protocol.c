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
 * dss_protocol.c
 *
 *
 * IDENTIFICATION
 *    src/common/dss_protocol.c
 *
 * -------------------------------------------------------------------------
 */

#include "dss_errno.h"
#include "dss_log.h"
#include "dss_protocol.h"

typedef status_t (*recv_func_t)(void *link, char *buf, uint32 size, int32 *recv_size);
typedef status_t (*recv_timed_func_t)(void *link, char *buf, uint32 size, uint32 timeout);
typedef status_t (*send_timed_func_t)(void *link, const char *buf, uint32 size, uint32 timeout);
typedef status_t (*wait_func_t)(void *link, uint32 wait_for, int32 timeout, bool32 *ready);

typedef struct st_vio {
    recv_func_t vio_recv;
    wait_func_t vio_wait;
    recv_timed_func_t vio_recv_timed;
    send_timed_func_t vio_send_timed;
} vio_t;

static const vio_t g_vio_list[] = {
    {NULL, NULL, NULL, NULL},

    // TCP io functions
    {(recv_func_t)cs_tcp_recv, (wait_func_t)cs_tcp_wait, (recv_timed_func_t)cs_tcp_recv_timed,
        (send_timed_func_t)cs_tcp_send_timed},

    // IPC not implemented
    {NULL, NULL, NULL, NULL},

    // UDS io functions
    {(recv_func_t)cs_uds_recv, (wait_func_t)cs_uds_wait, (recv_timed_func_t)cs_uds_recv_timed,
        (send_timed_func_t)cs_uds_send_timed},

    // SSL io functions
    {(recv_func_t)cs_ssl_recv, (wait_func_t)cs_ssl_wait, (recv_timed_func_t)cs_ssl_recv_timed,
        (send_timed_func_t)cs_ssl_send_timed},

    // CS_TYPE_EMBEDDED not implemented
    {NULL, NULL, NULL, NULL},

    // CS_TYPE_DIRECT not implemented
    {NULL, NULL, NULL, NULL},
};

/*
  Macro definitions for pipe I/O operations
  @note
    Performance sensitive, the pipe->type should be guaranteed by the caller.
      e.g. CS_TYPE_TCP, CS_TYPE_SSL, CS_TYPE_DOMAIN_SOCKET
*/
#define GET_VIO(pipe) (&g_vio_list[(pipe)->type])

#define VIO_SEND_TIMED(pipe, buf, size, timeout) GET_VIO(pipe)->vio_send_timed(&(pipe)->link, buf, size, timeout)

#define VIO_RECV(pipe, buf, size, len) GET_VIO(pipe)->vio_recv(&(pipe)->link, buf, size, len)

#define VIO_RECV_TIMED(pipe, buf, size, timeout) GET_VIO(pipe)->vio_recv_timed(&(pipe)->link, buf, size, timeout)

#define VIO_WAIT(pipe, ev, timeout, ready) GET_VIO(pipe)->vio_wait(&(pipe)->link, ev, timeout, ready)

status_t dss_put_text(dss_packet_t *pack, text_t *text)
{
    errno_t errcode;
    CM_ASSERT(pack != NULL);
    CM_ASSERT(text != NULL);

    /* put the length of text */
    (void)dss_put_int32(pack, text->len);
    if (text->len == 0) {
        return CM_SUCCESS;
    }
    /* put the string of text, and append the terminated sign */
    errcode = memcpy_s(DSS_WRITE_ADDR(pack), DSS_REMAIN_SIZE(pack), text->str, text->len);
    DSS_SECUREC_RETURN_IF_ERROR(errcode, CM_ERROR);

    pack->head->size += CM_ALIGN4(text->len);
    return CM_SUCCESS;
}

status_t dss_put_str_with_cutoff(dss_packet_t *pack, const char *str)
{
    uint32 size;
    char *addr = NULL;
    errno_t errcode = 0;

    CM_ASSERT(pack != NULL);
    CM_ASSERT(str != NULL);
    size = (uint32)strlen(str);
    addr = DSS_WRITE_ADDR(pack);
    if (size != 0) {
        // for such as err msg , len max is 2K, too long for dss packet, which is fixed len at present, so cut it off
        // for '\0'
        if (DSS_REMAIN_SIZE(pack) <= 1) {
            size = 0;
        } else if (size >= DSS_REMAIN_SIZE(pack)) {
            // for '\0'
            size = DSS_REMAIN_SIZE(pack) - 1;
        }
        errcode = memcpy_s(addr, DSS_REMAIN_SIZE(pack), str, size);
        DSS_SECUREC_RETURN_IF_ERROR(errcode, CM_ERROR);
    }
    DSS_WRITE_ADDR(pack)[size] = '\0';
    pack->head->size += CM_ALIGN4(size + 1);

    return CM_SUCCESS;
}

status_t dss_write_packet(cs_pipe_t *pipe, dss_packet_t *pack)
{
    if (pack->head->size > DSS_MAX_PACKET_SIZE) {
        DSS_RETURN_IFERR2(CM_ERROR, CM_THROW_ERROR(ERR_BUFFER_OVERFLOW, "PACKET BUFFER OVERFLOW"));
    }

    status_t status = VIO_SEND_TIMED(pipe, pack->buf, pack->head->size, DSS_DEFAULT_NULL_VALUE);
    DSS_RETURN_IFERR2(
        status, CM_THROW_ERROR(ERR_PACKET_SEND, pack->buf_size, pack->head->size, DSS_DEFAULT_NULL_VALUE));

    return CM_SUCCESS;
}

status_t dss_write(cs_pipe_t *pipe, dss_packet_t *pack)
{
    CM_ASSERT(pipe != NULL);
    CM_ASSERT(pack != NULL);
    pack->options = pipe->options;

    return dss_write_packet(pipe, pack);
}

/* before call cs_read_tcp_packet(), cs_tcp_wait() is called */
static status_t dss_read_packet(cs_pipe_t *pipe, dss_packet_t *pack, bool32 cs_client)
{
    int32 remain_size, offset, recv_size;
    bool32 ready = CM_FALSE;

    offset = 0;
    status_t status;
    char *cs_mes = cs_client ? "read wait for server response" : "read wait for client request";
    for (;;) {
        status = VIO_RECV(pipe, pack->buf + offset, (uint32)(pack->buf_size - offset), &recv_size);
        DSS_RETURN_IFERR2(status, DSS_THROW_ERROR(ERR_TCP_RECV, "Receive protocol failed."));
        offset += recv_size;
        if (offset >= (int32)sizeof(dss_packet_head_t)) {
            break;
        }
        status = VIO_WAIT(pipe, CS_WAIT_FOR_READ, CM_NETWORK_IO_TIMEOUT, &ready);
        DSS_RETURN_IFERR2(status, DSS_THROW_ERROR(ERR_TCP_TIMEOUT, cs_mes));
        if (!ready) {
            DSS_RETURN_IFERR2(CM_ERROR, DSS_THROW_ERROR(ERR_DSS_TCP_TIMEOUT_REMAIN, (uint32)(sizeof(uint32) - offset)));
        }
    }

    if (pack->head->size > pack->buf_size) {
        DSS_RETURN_IFERR2(CM_ERROR, DSS_THROW_ERROR(ERR_TCP_RECV, "Receive protocol failed."));
    }

    remain_size = (int32)pack->head->size - offset;
    if (remain_size <= 0) {
        return CM_SUCCESS;
    }

    status = VIO_WAIT(pipe, CS_WAIT_FOR_READ, CM_NETWORK_IO_TIMEOUT, &ready);
    DSS_RETURN_IFERR2(status, DSS_THROW_ERROR(ERR_TCP_TIMEOUT, cs_mes));

    if (!ready) {
        DSS_RETURN_IFERR2(CM_ERROR, DSS_THROW_ERROR(ERR_TCP_TIMEOUT, cs_mes));
    }

    status = VIO_RECV_TIMED(pipe, pack->buf + offset, (uint32)remain_size, CM_NETWORK_IO_TIMEOUT);
    DSS_RETURN_IFERR2(status, DSS_THROW_ERROR(ERR_TCP_RECV, "Receive protocol failed."));

    return CM_SUCCESS;
}

status_t dss_read(cs_pipe_t *pipe, dss_packet_t *pack, bool32 cs_client)
{
    CM_ASSERT(pipe != NULL);
    CM_ASSERT(pack != NULL);
    pack->options = pipe->options;

    return dss_read_packet(pipe, pack, cs_client);
}

static status_t dss_call_base(cs_pipe_t *pipe, dss_packet_t *req, dss_packet_t *ack)
{
    bool32 ready = CM_FALSE;

    if (dss_write(pipe, req) != CM_SUCCESS) {
        return CM_ERROR;
    }

    if (cs_wait(pipe, CS_WAIT_FOR_READ, pipe->socket_timeout, &ready) != CM_SUCCESS) {
        return CM_ERROR;
    }

    if (!ready) {
        DSS_RETURN_IFERR2(
            CM_ERROR, DSS_THROW_ERROR(ERR_SOCKET_TIMEOUT, pipe->socket_timeout / (int32)CM_TIME_THOUSAND_UN));
    }

    return dss_read(pipe, ack, CM_TRUE);
}

status_t dss_call_ex(cs_pipe_t *pipe, dss_packet_t *req, dss_packet_t *ack)
{
    status_t ret = dss_call_base(pipe, req, ack);
    if (ret != CM_SUCCESS) {
        LOG_RUN_ERR("[DSS] ABORT INFO: dss call server failed, ack command type:%d, application exit.", ack->head->cmd);
        cs_disconnect(pipe);
        cm_fync_logfile();
        _exit(1);
    }
    return ret;
}
