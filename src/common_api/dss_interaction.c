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
#include "dss_thv.h"
#include "dss_cli_conn.h"

#ifdef __cplusplus
extern "C" {
#endif

status_t dss_cli_get_err(dss_packet_t *pack, int32 *errcode, char **errmsg)
{
    dss_init_get(pack);
    if (dss_get_int32(pack, errcode) != CM_SUCCESS) {
        LOG_RUN_ERR("[DSS API] Failed to parse errcode from server error ack.");
        return CM_ERROR;
    }
    if (dss_get_str(pack, errmsg) != CM_SUCCESS) {
        LOG_RUN_ERR("[DSS API] Failed to parse errmsg from server error ack, errcode:%d.", *errcode);
        return CM_ERROR;
    }
    if (*errcode == ERR_DSS_MES_ILL) {
        const char *safe_errmsg = (*errmsg == NULL) ? "" : *errmsg;
        LOG_RUN_ERR("[DSS API] ABORT INFO : server broadcast failed, errcode:%d, errmsg:%s.", *errcode, safe_errmsg);
        cm_fync_logfile();
        dss_exit(1);
    }
    return CM_SUCCESS;
}

int32 dss_get_pack_err(dss_conn_t *conn, dss_packet_t *pack)
{
    int32 errcode = -1;
    char *errmsg = NULL;
    if (dss_cli_get_err(pack, &errcode, &errmsg) != CM_SUCCESS) {
        LOG_RUN_ERR("[DSS API] Invalid error ack from server, disconnect.");
        cs_disconnect(&conn->pipe);
        return CM_ERROR;
    }
    if (errcode == ERR_DSS_VERSION_NOT_MATCH) {
        conn->server_version = dss_get_version(pack);
        uint32 new_proto_version = MIN(DSS_PROTO_VERSION, conn->server_version);
        LOG_RUN_INF(
            "[CHECK_PROTO]The client protocol version need be changed, old protocol version is %hhu, new protocol version is %hhu.",
            conn->proto_version, new_proto_version);
        conn->proto_version = new_proto_version;
        // if msg version has changed, you need to put new version msg;
        // if msg version has not changed, just change the proto_version and try again.
        dss_set_version(&conn->pack, conn->proto_version);
        dss_set_client_version(&conn->pack, DSS_PROTO_VERSION);
        return errcode;
    }
    DSS_THROW_ERROR_EX(errcode, "%s", (errmsg == NULL) ? "" : errmsg);
    return CM_ERROR;
}

#ifdef __cplusplus
}
#endif
