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
 * dss_interaction.h
 *
 *
 * IDENTIFICATION
 *    src/common_api/dss_interaction.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __DSS_INTERACTION_H__
#define __DSS_INTERACTION_H__

#include <stdio.h>
#include "dss_errno.h"
#include "dss_file_def.h"
#include "dss_protocol.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct st_dss_conn {
    dss_packet_t pack;  // for sending
    cs_pipe_t pipe;
    void *cli_vg_handles;
    bool32 flag;
    void *session;
} dss_conn_t;

void dss_cli_get_err(dss_packet_t *pack, int32 *errcode, char **errmsg);
status_t dss_open_file_on_server(dss_conn_t *conn, const char *file_path, int flag);
status_t dss_close_file_on_server(dss_conn_t *conn, dss_vg_info_item_t *vg_item, uint64 fid, ftid_t ftid);
status_t dss_get_inst_status_on_server(dss_conn_t *conn, int *status);
status_t dss_set_main_inst_on_server(dss_conn_t *conn);
#ifdef __cplusplus
}
#endif

#endif  // __DSS_INTERACTION_H__
