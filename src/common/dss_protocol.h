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

// The value of each command type cannot be changed for compatibility reasons.
// If you want to add a command type, add it at the end. Before DSS_CMD_END
typedef enum {
    DSS_CMD_BASE,
    DSS_CMD_BEGIN,
    DSS_CMD_MODIFY_BEGIN = DSS_CMD_BEGIN,
    DSS_CMD_MKDIR = DSS_CMD_MODIFY_BEGIN,
    DSS_CMD_RMDIR,
    DSS_CMD_OPEN_DIR,
    DSS_CMD_CLOSE_DIR,
    DSS_CMD_OPEN_FILE,
    DSS_CMD_CLOSE_FILE,
    DSS_CMD_CREATE_FILE,
    DSS_CMD_DELETE_FILE,
    DSS_CMD_EXTEND_FILE,
    DSS_CMD_ATTACH_FILE,  // 10
    DSS_CMD_DETACH_FILE,
    DSS_CMD_RENAME_FILE,
    DSS_CMD_REFRESH_FILE,
    DSS_CMD_TRUNCATE_FILE,
    DSS_CMD_REFRESH_FILE_TABLE,
    DSS_CMD_FALLOCATE_FILE,
    DSS_CMD_ADD_VOLUME,
    DSS_CMD_REMOVE_VOLUME,
    DSS_CMD_REFRESH_VOLUME,
    DSS_CMD_KICKH,  // 20
    DSS_CMD_LOAD_CTRL,
    DSS_CMD_UPDATE_WRITTEN_SIZE,
    DSS_CMD_STOP_SERVER,
    DSS_CMD_SETCFG,
    DSS_CMD_SYMLINK,
    DSS_CMD_UNLINK,
    DSS_CMD_SET_MAIN_INST,
    DSS_CMD_SWITCH_LOCK,
    DSS_CMD_DISABLE_GRAB_LOCK,
    DSS_CMD_ENABLE_GRAB_LOCK,
    DSS_CMD_HOTPATCH,
    DSS_CMD_ENABLE_UPGRADES,
    DSS_CMD_MODIFY_END = 127,
    DSS_CMD_QUERY_BEGIN = DSS_CMD_MODIFY_END,
    DSS_CMD_HANDSHAKE = DSS_CMD_QUERY_BEGIN,
    DSS_CMD_EXIST,  // 128
    DSS_CMD_READLINK,
    DSS_CMD_GET_FTID_BY_PATH,
    DSS_CMD_GETCFG,
    DSS_CMD_GET_INST_STATUS,
    DSS_CMD_GET_TIME_STAT,
    DSS_CMD_EXEC_REMOTE,
    DSS_CMD_QUERY_HOTPATCH,
    DSS_CMD_QUERY_END,
    DSS_CMD_END  // must be the last item
} dss_cmd_type_e;

#define DSS_CMD_TYPE_OFFSET(cmd_id) ((uint32)(cmd_id) - (uint32)DSS_CMD_BEGIN)

char *dss_get_cmd_desc(dss_cmd_type_e cmd_type);

static inline bool32 dss_can_cmd_type_no_open(dss_cmd_type_e type)
{
    return ((type == DSS_CMD_GET_INST_STATUS) || (type == DSS_CMD_HANDSHAKE) || (type == DSS_CMD_STOP_SERVER) ||
            (type == DSS_CMD_ENABLE_GRAB_LOCK) || (type == DSS_CMD_SETCFG) || (type == DSS_CMD_GETCFG));
}

typedef struct st_dss_packet_head {
    uint32 version;
    uint32 client_version;
    uint32 size;
    uint8 cmd;    /* command in request packet */
    uint8 result; /* code in response packet, success(0) or error(1) */
    uint16 flags;
    uint32 serial_number;
    uint8 reserve[60];
} dss_packet_head_t;

typedef enum en_dss_packet_version {
    DSS_VERSION_0 = 0, /* version 0 */
    DSS_VERSION_1 = 1, /* version 1 */
    DSS_VERSION_2 = 2, /* version 2 */
} dss_packet_version_e;

#define DSS_PROTO_VERSION DSS_VERSION_2
#define DSS_INVALID_VERSION (int32)0x7FFFFFFF

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

static inline void dss_set_client_version(dss_packet_t *pack, uint32 version)
{
    CM_ASSERT(pack != NULL);
    pack->head->client_version = version;
}

static inline void dss_set_version(dss_packet_t *pack, uint32 version)
{
    CM_ASSERT(pack != NULL);
    pack->head->version = version;
}

static inline uint32 dss_get_client_version(dss_packet_t *pack)
{
    CM_ASSERT(pack != NULL);
    return pack->head->client_version;
}

static inline uint32 dss_get_version(dss_packet_t *pack)
{
    CM_ASSERT(pack != NULL);
    return pack->head->version;
}

static inline void dss_init_get(dss_packet_t *pack)
{
    if (pack == NULL) {
        return;
    }
    pack->offset = (uint32)sizeof(dss_packet_head_t);
}

static inline void dss_init_set(dss_packet_t *pack, uint32 proto_version)
{
    if (pack == NULL) {
        return;
    }
    (void)memset_s(pack->head, sizeof(dss_packet_head_t), 0, sizeof(dss_packet_head_t));
    pack->head->size = (uint32)sizeof(dss_packet_head_t);
    dss_set_version(pack, proto_version);
    dss_set_client_version(pack, DSS_PROTO_VERSION);
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
    uint32 estimated_size = pack->head->size + CM_ALIGN4(size + 1);
    if (estimated_size > pack->buf_size) {
        CM_THROW_ERROR(ERR_BUFFER_OVERFLOW, estimated_size, pack->buf_size);
        return CM_ERROR;
    }
    if (size != 0) {
        errcode = memcpy_s(addr, DSS_REMAIN_SIZE(pack), str, size);
        DSS_SECUREC_RETURN_IF_ERROR(errcode, CM_ERROR);
    }
    DSS_WRITE_ADDR(pack)[size] = '\0';
    pack->head->size = estimated_size;

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

static inline status_t dss_reserv_text_buf(dss_packet_t *pack, uint32 size, char **data_buf)
{
    CM_ASSERT(pack != NULL);
    CM_ASSERT(data_buf != NULL);
    if (CM_ALIGN4(size) >= DSS_REMAIN_SIZE(pack) - sizeof(uint32)) {
        CM_THROW_ERROR(ERR_BUFFER_OVERFLOW, size, DSS_REMAIN_SIZE(pack) - 1);
        return CM_ERROR;
    }

    // record the size first
    *(uint32 *)DSS_WRITE_ADDR(pack) = (CS_DIFFERENT_ENDIAN(pack->options) != 0) ? cs_reverse_int32(size) : size;
    pack->head->size += (uint32)sizeof(uint32);

    *data_buf = DSS_WRITE_ADDR(pack);
    pack->head->size += CM_ALIGN4(size);
    return CM_SUCCESS;
}

static inline status_t dss_pack_check_len(dss_packet_t *pack, uint32 inc)
{
    if ((pack->offset + inc) > pack->head->size) {
        CM_THROW_ERROR(ERR_BUFFER_OVERFLOW, (pack->offset + inc), pack->head->size);
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

static inline status_t dss_get_data(dss_packet_t *pack, uint32 size, void **buf)
{
    int64 len;
    char *temp_buf = NULL;
    CM_ASSERT(pack != NULL);

    len = (int64)CM_ALIGN4(size);
    TO_UINT32_OVERFLOW_CHECK(len, int64);
    CM_RETURN_IFERR(dss_pack_check_len(pack, len));
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

    CM_RETURN_IFERR(dss_pack_check_len(pack, 1));
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
