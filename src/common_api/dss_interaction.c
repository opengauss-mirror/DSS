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
 * dss_interaction.c
 *
 *
 * IDENTIFICATION
 *    src/common_api/dss_interaction.c
 *
 * -------------------------------------------------------------------------
 */

#include "dss_interaction.h"

#ifdef __cplusplus
extern "C" {
#endif

void dss_cli_get_err(dss_packet_t *pack, int32 *errcode, char **errmsg)
{
    dss_init_get(pack);
    (void)dss_get_int32(pack, errcode);
    (void)dss_get_str(pack, errmsg);
}

status_t dss_open_file_on_server(dss_conn_t *conn, const char *file_path, int flag)
{
    int32 errcode;
    char *errmsg = NULL;

    dss_init_packet(&conn->pack, conn->pipe.options);
    dss_init_set(&conn->pack);
    dss_packet_t *send_pack = &conn->pack;
    send_pack->head->cmd = DSS_CMD_OPEN_FILE;
    send_pack->head->flags = 0;

    /* 1. file name */
    DSS_RETURN_IF_ERROR(dss_put_str(send_pack, file_path));
    /* 2. flag */
    DSS_RETURN_IF_ERROR(dss_put_int32(send_pack, (uint32)flag));

    dss_packet_t *ack_pack = &conn->pack;
    DSS_RETURN_IF_ERROR(dss_call_ex(&conn->pipe, send_pack, ack_pack));

    if (ack_pack->head->result != CM_SUCCESS) {
        dss_cli_get_err(ack_pack, &errcode, &errmsg);
        DSS_THROW_ERROR_EX(errcode, "%s", errmsg);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

status_t dss_get_inst_status_on_server(dss_conn_t *conn, dss_server_status_t *dss_status)
{
    int32 errcode;
    char *errmsg = NULL;
    if (dss_status == NULL) {
        DSS_THROW_ERROR(ERR_DSS_INVALID_PARAM, "dss_dir_item_t");
        return CM_ERROR;
    }
    dss_init_packet(&conn->pack, conn->pipe.options);
    dss_init_set(&conn->pack);
    dss_packet_t *send_pack = &conn->pack;
    send_pack->head->cmd = DSS_CMD_GET_INST_STATUS;
    send_pack->head->flags = 0;

    dss_packet_t *ack_pack = &conn->pack;
    DSS_RETURN_IF_ERROR(dss_call_ex(&conn->pipe, send_pack, ack_pack));

    if (ack_pack->head->result != CM_SUCCESS) {
        dss_cli_get_err(ack_pack, &errcode, &errmsg);
        DSS_THROW_ERROR_EX(errcode, "%s", errmsg);
        return CM_ERROR;
    }
    text_t extra_info = CM_NULL_TEXT;
    dss_init_get(ack_pack);
    if (dss_get_text(ack_pack, &extra_info) != CM_SUCCESS) {
        DSS_THROW_ERROR(ERR_DSS_CLI_EXEC_FAIL, dss_get_cmd_desc(DSS_CMD_GET_INST_STATUS), "get inst status error");
        LOG_DEBUG_ERR("get inst status error");
        return CM_ERROR;
    }
    if (extra_info.len != sizeof(dss_server_status_t)) {
        DSS_THROW_ERROR(
            ERR_DSS_CLI_EXEC_FAIL, dss_get_cmd_desc(DSS_CMD_GET_INST_STATUS), "get inst status length error");
        LOG_DEBUG_ERR("get inst status length error");
        return CM_ERROR;
    }
    *dss_status = *(dss_server_status_t *)extra_info.str;
    return CM_SUCCESS;
}

status_t dss_get_time_stat_on_server(dss_conn_t * conn, dss_session_stat_t * time_stat, uint64 size)
{
    int32 errcode;
    char *errmsg = NULL;

    dss_init_packet(&conn->pack, conn->pipe.options);
    dss_init_set(&conn->pack);
    dss_packet_t *send_pack = &conn->pack;
    send_pack->head->cmd = DSS_CMD_GET_TIME_STAT;
    send_pack->head->flags = 0;

    dss_packet_t *ack_pack = &conn->pack;
    DSS_RETURN_IF_ERROR(dss_call_ex(&conn->pipe, send_pack, ack_pack));

    if (ack_pack->head->result != CM_SUCCESS) {
        dss_cli_get_err(ack_pack, &errcode, &errmsg);
        DSS_THROW_ERROR_EX(errcode, "%s", errmsg);
        return CM_ERROR;
    }
    text_t stat_info = CM_NULL_TEXT;
    dss_init_get(ack_pack);
    if (dss_get_text(ack_pack, &stat_info) != CM_SUCCESS) {
        DSS_THROW_ERROR(ERR_DSS_CLI_EXEC_FAIL, dss_get_cmd_desc(DSS_CMD_GET_TIME_STAT), "get time stat error");
        LOG_DEBUG_ERR("get time stat error");
        return CM_ERROR;
    }
    for (uint64 i = 0; i < DSS_EVT_COUNT; i++) {
        time_stat[i] = *(dss_session_stat_t *)(stat_info.str + i * (uint64)sizeof(dss_session_stat_t));
    }
    return CM_SUCCESS;
}

status_t dss_set_main_inst_on_server(dss_conn_t *conn)
{
    int32 errcode;
    char *errmsg = NULL;

    dss_init_packet(&conn->pack, conn->pipe.options);
    dss_init_set(&conn->pack);
    dss_packet_t *send_pack = &conn->pack;
    send_pack->head->cmd = DSS_CMD_SET_MAIN_INST;
    send_pack->head->flags = 0;

    dss_packet_t *ack_pack = &conn->pack;
    DSS_RETURN_IF_ERROR(dss_call_ex(&conn->pipe, send_pack, ack_pack));

    if (ack_pack->head->result != CM_SUCCESS) {
        dss_cli_get_err(ack_pack, &errcode, &errmsg);
        DSS_THROW_ERROR_EX(errcode, "%s", errmsg);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

status_t dss_close_file_on_server(dss_conn_t *conn, dss_vg_info_item_t *vg_item, uint64 fid, ftid_t ftid)
{
    int32 errcode;
    char *errmsg = NULL;

    dss_init_set(&conn->pack);
    dss_packet_t *send_pack = &conn->pack;
    send_pack->head->cmd = DSS_CMD_CLOSE_FILE;
    send_pack->head->flags = 0;

    DSS_RETURN_IF_ERROR(dss_put_int64(send_pack, fid));
    DSS_RETURN_IF_ERROR(dss_put_str(send_pack, vg_item->vg_name));
    DSS_RETURN_IF_ERROR(dss_put_int32(send_pack, vg_item->id));
    DSS_RETURN_IF_ERROR(dss_put_int64(send_pack, *(uint64 *)&ftid));

    dss_packet_t *ack_pack = &conn->pack;
    DSS_RETURN_IF_ERROR(dss_call_ex(&conn->pipe, send_pack, ack_pack));
    if (ack_pack->head->result != CM_SUCCESS) {
        dss_cli_get_err(ack_pack, &errcode, &errmsg);
        DSS_THROW_ERROR_EX(errcode, "%s", errmsg);
        LOG_DEBUG_ERR("exec close file on server failed.server return errcode:%d,errmsg:%s", errcode, errmsg);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

#ifdef __cplusplus
}
#endif
