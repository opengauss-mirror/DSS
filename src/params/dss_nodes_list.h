/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
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
 * dss_nodes_list.h
 *
 *
 * IDENTIFICATION
 *    src/params/dss_nodes_list.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __DSS_NODES_LIST_H__
#define __DSS_NODES_LIST_H__

#include "cm_types.h"
#include "cm_defs.h"
#include "dss_defs.h"

typedef struct st_dss_nodes_list {
    uint32 inst_cnt;
    uint64 inst_map;
    char nodes[DSS_MAX_INSTANCES][CM_MAX_IP_LEN];
    uint16 ports[DSS_MAX_INSTANCES];
} dss_nodes_list_t;

status_t dss_extract_nodes_list(char *nodes_list_str, dss_nodes_list_t *nodes_list);
status_t dss_verify_nodes_list(void *lex, void *def);
status_t dss_notify_dss_nodes_list(void *se, void *item, char *value);

typedef void (*dss_regist_mes_func_t)();
void dss_notify_regist_mes_func(dss_regist_mes_func_t dss_regist_mes_func);

#endif