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
 * dss_protocol.h
 *
 *
 * IDENTIFICATION
 *    src/common/dss_protocol.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __DSS_PROTOCOL_H__
#define __DSS_PROTOCOL_H__
#include "cm_base.h"
#ifndef WIN32
#include <string.h>
#endif

#include "cm_defs.h"
#include "cs_packet.h"
#include "cs_pipe.h"
#include "dss_defs.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct st_dss_packet_head {
    uint32 size;
    uint8 cmd;    /* command in request packet */
    uint8 result; /* code in response packet, success(0) or error(1) */
    uint16 flags;
    uint8 version;
    uint8 minor_version;
    uint8 major_version;
    uint8 reserved;
    uint32 serial_number;
} dss_packet_head_t;

typedef enum en_dss_packet_version {
    CS_VERSION_0 = 0, /* version 0 */
} cs_packet_version_t;

#define CS_LOCAL_MAJOR_VER_WEIGHT 1000000
#define CS_LOCAL_MINOR_VER_WEIGHT 1000
#define CS_LOCAL_MAJOR_VERSION 0
#define CS_LOCAL_MINOR_VERSION 0

#define DSS_PACKET_SIZE(pack) ((pack)->head->size)
#define DSS_WRITE_ADDR(pack) ((pack)->buf + (pack)->head->size)
#define DSS_REMAIN_SIZE(pack) ((pack)->buf_size - ((pack)->head->size))
#define DSS_READ_ADDR(pack) ((pack)->buf + (pack)->offset)

typedef struct st_dss_packet {
    uint32 offset;   // for reading
    uint32 options;  // options
    dss_packet_head_t *head;
    uint32 max_buf_size;  // MAX_ALLOWED_PACKET
    uint32 buf_size;
    char *buf;
    char init_buf[DSS_MAX_PACKET_SIZE];
} dss_packet_t;

static inline void dss_init_packet(dss_packet_t *pack, uint32 options)
{
    CM_ASSERT(pack != NULL);
    pack->offset = 0;
    pack->max_buf_size = DSS_MAX_PACKET_SIZE;
    pack->buf_size = DSS_MAX_PACKET_SIZE;
    pack->buf = pack->init_buf;
    pack->head = (dss_packet_head_t *)pack->buf;
    pack->options = options;
}

static inline void dss_set_version(dss_packet_t *pack, uint32 version)
{
    CM_ASSERT(pack != NULL);
    pack->head->version = (uint8)(version % CS_LOCAL_MINOR_VER_WEIGHT);
    pack->head->minor_version = (uint8)((version % CS_LOCAL_MAJOR_VER_WEIGHT) / CS_LOCAL_MINOR_VER_WEIGHT);
    pack->head->major_version = (uint8)(version / CS_LOCAL_MAJOR_VER_WEIGHT);
}

static inline uint32 dss_get_version(dss_packet_t *pack)
{
    CM_ASSERT(pack != NULL);
    return pack->head->version + pack->head->minor_version * CS_LOCAL_MINOR_VER_WEIGHT +
           pack->head->major_version * CS_LOCAL_MAJOR_VER_WEIGHT;
}

static inline void dss_init_get(dss_packet_t *pack)
{
    if (pack == NULL) {
        return;
    }
    pack->offset = (uint32)sizeof(dss_packet_head_t);
}

static inline void dss_init_set(dss_packet_t *pack)
{
    if (pack == NULL) {
        return;
    }

    pack->head->size = (uint32)sizeof(dss_packet_head_t);
    pack->head->result = 0;
    pack->head->flags = 0;
    dss_set_version(pack, CS_LOCAL_VERSION);

    pack->head->reserved = 0;
}

static inline status_t dss_put_str(dss_packet_t *pack, const char *str)
{
    uint32 size;
    char *addr = NULL;
    errno_t errcode = 0;

    CM_ASSERT(pack != NULL);
    CM_ASSERT(str != NULL);
    size = (uint32)strlen(str);
    addr = DSS_WRITE_ADDR(pack);
    if (size != 0) {
        errcode = memcpy_s(addr, DSS_REMAIN_SIZE(pack), str, size);
        DSS_SECUREC_RETURN_IF_ERROR(errcode, CM_ERROR);
    }
    DSS_WRITE_ADDR(pack)[size] = '\0';
    pack->head->size += CM_ALIGN4(size + 1);

    return CM_SUCCESS;
}

static inline status_t dss_put_data(dss_packet_t *pack, const void *data, uint32 size)
{
    errno_t errcode = 0;

    CM_ASSERT(pack != NULL);
    CM_ASSERT(data != NULL);

    if (size != 0) {
        errcode = memcpy_s(DSS_WRITE_ADDR(pack), DSS_REMAIN_SIZE(pack), data, size);
        DSS_SECUREC_RETURN_IF_ERROR(errcode, CM_ERROR);
    }
    pack->head->size += CM_ALIGN4(size);
    return CM_SUCCESS;
}

static inline status_t dss_put_int64(dss_packet_t *pack, uint64 value)
{
    CM_ASSERT(pack != NULL);

    *(uint64 *)DSS_WRITE_ADDR(pack) = (CS_DIFFERENT_ENDIAN(pack->options) != 0) ? cs_reverse_int64(value) : value;
    pack->head->size += (uint32)sizeof(uint64);
    return CM_SUCCESS;
}

static inline status_t dss_put_int32(dss_packet_t *pack, uint32 value)
{
    CM_ASSERT(pack != NULL);

    *(uint32 *)DSS_WRITE_ADDR(pack) = (CS_DIFFERENT_ENDIAN(pack->options) != 0) ? cs_reverse_int32(value) : value;
    pack->head->size += (uint32)sizeof(uint32);
    return CM_SUCCESS;
}

static inline status_t dss_pack_check_len(dss_packet_t *pack, uint32 inc)
{
    if ((pack->offset + inc) > pack->head->size) {
        CM_THROW_ERROR(ERR_BUFFER_OVERFLOW, "PACKET OVERFLOW");
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

static inline status_t dss_get_data(dss_packet_t *pack, uint32 size, void **buf)
{
    int64 len;
    char *temp_buf = NULL;
    CM_ASSERT(pack != NULL);

    CM_RETURN_IFERR(dss_pack_check_len(pack, 0));
    len = (int64)CM_ALIGN4(size);
    TO_UINT32_OVERFLOW_CHECK(len, int64);
    temp_buf = DSS_READ_ADDR(pack);
    pack->offset += CM_ALIGN4(size);
    if (buf != NULL) {
        *buf = (void *)temp_buf;
    }
    return CM_SUCCESS;
}

static inline status_t dss_get_packet_strlen(dss_packet_t *pack, char *str, size_t *str_len)
{
    uint32 rem_len = (pack->head->size - pack->offset) - 1;
    while (str[*str_len] != '\0') {
        if ((*str_len)++ > rem_len) {
            CM_THROW_ERROR(ERR_TYPE_OVERFLOW, "UNSIGNED STRING");
            return CM_ERROR;
        }
    }
    (*str_len)++;
    return CM_SUCCESS;
}

static inline status_t dss_get_str(dss_packet_t *pack, char **buf)
{
    char *str = NULL;
    int64 len;
    size_t str_len = 0;
    CM_ASSERT(pack != NULL);

    CM_RETURN_IFERR(dss_pack_check_len(pack, 0));
    str = DSS_READ_ADDR(pack);
    CM_RETURN_IFERR(dss_get_packet_strlen(pack, str, &str_len));
    len = (int64)CM_ALIGN4(str_len);
    TO_UINT32_OVERFLOW_CHECK(len, int64);
    pack->offset += (uint32)len;
    if (buf != NULL) {
        *buf = str;
    }
    return CM_SUCCESS;
}

static inline status_t dss_get_int64(dss_packet_t *pack, int64 *value)
{
    int64 temp_value;
    CM_ASSERT(pack != NULL);

    CM_RETURN_IFERR(dss_pack_check_len(pack, sizeof(int64)));

    temp_value = *(int64 *)DSS_READ_ADDR(pack);
    temp_value = (CS_DIFFERENT_ENDIAN(pack->options) != 0) ? (int64)cs_reverse_int64((uint64)temp_value) : temp_value;
    pack->offset += (uint32)sizeof(int64);
    if (value != NULL) {
        *value = temp_value;
    }
    return CM_SUCCESS;
}

static inline status_t dss_get_int32(dss_packet_t *pack, int32 *value)
{
    int32 temp_value;
    CM_ASSERT(pack != NULL);

    CM_RETURN_IFERR(dss_pack_check_len(pack, sizeof(int32)));

    temp_value = *(int32 *)DSS_READ_ADDR(pack);
    pack->offset += (uint32)sizeof(int32);
    temp_value = (CS_DIFFERENT_ENDIAN(pack->options) != 0) ? (int32)cs_reverse_int32((uint32)temp_value) : temp_value;
    if (value != NULL) {
        *value = temp_value;
    }
    return CM_SUCCESS;
}

static inline status_t dss_get_text(dss_packet_t *pack, text_t *text)
{
    CM_ASSERT(pack != NULL);
    CM_ASSERT(text != NULL);

    CM_RETURN_IFERR(dss_get_int32(pack, (int32 *)&text->len));
    if ((text->len > DSS_MAX_PACKET_SIZE) || (text->len == 0)) {
        CM_THROW_ERROR(ERR_BUFFER_OVERFLOW, "PACKET OVERFLOW");
        return CM_ERROR;
    }

    return dss_get_data(pack, text->len, (void **)&(text->str));
}

static inline void dss_free_packet_buffer(dss_packet_t *pack)
{
    if (pack->buf != pack->init_buf) {
        if (pack->buf != NULL) {
            free(pack->buf);
            pack->buf = NULL;
        }

        dss_init_packet(pack, 0);
    }
}

status_t dss_put_text(dss_packet_t *pack, text_t *text);
status_t dss_put_str_with_cutoff(dss_packet_t *pack, const char *str);
status_t dss_write_packet(cs_pipe_t *pipe, dss_packet_t *pack);
status_t dss_write(cs_pipe_t *pipe, dss_packet_t *pack);
status_t dss_read(cs_pipe_t *pipe, dss_packet_t *pack, bool32 cs_client);
status_t dss_call_ex(cs_pipe_t *pipe, dss_packet_t *req, dss_packet_t *ack);

#ifdef __cplusplus
}
#endif

#endif  // __DSS_PROTOCOL_H__
