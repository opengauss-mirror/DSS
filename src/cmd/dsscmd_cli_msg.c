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
 * dsscmd_cli_msg.c
 *
 *
 * IDENTIFICATION
 *    src/cmd/dsscmd_cli_msg.c
 *
 * -------------------------------------------------------------------------
 */

#include "dss_file.h"
#include "dsscmd_cli_msg.h"

static status_t dsscmd_add_or_remove_volumn(dss_conn_t *conn, const char *vg_name, const char *volume_name, uint8 cmd)
{
    dss_packet_t *send_pack;
    dss_packet_t *ack_pack;
    int32 errcode = -1;
    char *errmsg = NULL;

    // make up packet
    dss_init_set(&conn->pack);

    send_pack = &conn->pack;
    send_pack->head->cmd = cmd;
    send_pack->head->flags = 0;

    // 1. vg_name
    DSS_RETURN_IF_ERROR(dss_check_name(vg_name));
    DSS_RETURN_IF_ERROR(dss_put_str(send_pack, vg_name));
    // 2. volume_name
    DSS_RETURN_IF_ERROR(dss_check_path(volume_name));
    DSS_RETURN_IF_ERROR(dss_put_str(send_pack, volume_name));

    // send it and wait for ack
    ack_pack = &conn->pack;
    DSS_RETURN_IF_ERROR(dss_call_ex(&conn->pipe, send_pack, ack_pack));

    // check return state
    if (ack_pack->head->result != CM_SUCCESS) {
        dss_cli_get_err(ack_pack, &errcode, &errmsg);
        DSS_THROW_ERROR_EX(errcode, "%s", errmsg);
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

status_t dsscmd_adv_impl(dss_conn_t *conn, const char *vg_name, const char *volume_name)
{
    return dsscmd_add_or_remove_volumn(conn, vg_name, volume_name, DSS_CMD_ADD_VOLUME);
}

status_t dsscmd_rmv_impl(dss_conn_t *conn, const char *vg_name, const char *volume_name)
{
    return dsscmd_add_or_remove_volumn(conn, vg_name, volume_name, DSS_CMD_REMOVE_VOLUME);
}

status_t dss_kick_host_sync(dss_conn_t *connection, int64 kick_hostid)
{
    dss_packet_t *send_pack;
    dss_packet_t *ack_pack;
    int32 errcode = -1;
    char *errmsg = NULL;
    // make up packet
    dss_init_set(&connection->pack);
    send_pack = &connection->pack;
    send_pack->head->cmd = DSS_CMD_KICKH;
    send_pack->head->flags = 0;
    // 1. kick host id
    DSS_RETURN_IF_ERROR(dss_put_int64(send_pack, (uint64)kick_hostid));
    // send it and wait for ack
    ack_pack = &connection->pack;
    DSS_RETURN_IF_ERROR(dss_call_ex(&connection->pipe, send_pack, ack_pack));
    // check return state
    if (ack_pack->head->result != CM_SUCCESS) {
        dss_cli_get_err(ack_pack, &errcode, &errmsg);
        DSS_THROW_ERROR_EX(errcode, "%s", errmsg);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}
