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
 * dss_nodes_list.c
 *
 *
 * IDENTIFICATION
 *    src/params/dss_nodes_list.c
 *
 * -------------------------------------------------------------------------
 */

#include "dss_nodes_list.h"
#include "cm_log.h"
#include "cm_ip.h"
#include "cm_defs.h"
#include "cm_config.h"
#include "mes_interface.h"
#include "dss_param.h"
#include "dss_param_verify.h"
#include "dss_malloc.h"
#include "dss_errno.h"
#include "dss_log.h"
#include "dss_diskgroup.h"

status_t dss_extract_nodes_list(char *nodes_list_str, dss_nodes_list_t *nodes_list)
{
    status_t status = cm_split_mes_urls(nodes_list->nodes, nodes_list->ports, nodes_list_str);
    DSS_RETURN_IFERR2(status, DSS_THROW_ERROR(ERR_DSS_INVALID_PARAM, "DSS_NODES_LIST format is wrong"));
    int32 node_cnt = 0;
    for (int i = 0; i < DSS_MAX_INSTANCES; i++) {
        if (nodes_list->ports[i] != 0) {
            nodes_list->inst_map |= ((uint64)1 << i);
            node_cnt++;
        }
    }
    nodes_list->inst_cnt = (uint32)node_cnt;
    LOG_RUN_INF("There are %d instances in incoming DSS_NODES_LIST.", node_cnt);
    return CM_SUCCESS;
}

static status_t dss_alloc_and_extract_inst_addrs(char *nodes_list_str, uint32 *inst_cnt, mes_addr_t **inst_addrs)
{
    dss_nodes_list_t nodes_list;
    securec_check_ret(memset_sp(&nodes_list, sizeof(dss_nodes_list_t), 0, sizeof(dss_nodes_list_t)));
    CM_RETURN_IFERR(dss_extract_nodes_list(nodes_list_str, &nodes_list));
    size_t mes_addrs_size = nodes_list.inst_cnt * sizeof(mes_addr_t);
    *inst_addrs = (mes_addr_t *)cm_malloc(mes_addrs_size);
    if (*inst_addrs == NULL) {
        DSS_THROW_ERROR(ERR_ALLOC_MEMORY, mes_addrs_size, "dss_extract_inst_addrs");
        return CM_ERROR;
    }
    errno_t err = memset_sp(*inst_addrs, mes_addrs_size, 0, mes_addrs_size);
    if (err != 0) {
        CM_FREE_PTR(*inst_addrs);
        CM_THROW_ERROR(ERR_SYSTEM_CALL, err);
        return CM_ERROR;
    }
    mes_addr_t *inst_addr = &((*inst_addrs)[0]);
    for (uint32 i = 0; i < DSS_MAX_INSTANCES; ++i) {
        if (nodes_list.ports[i] != 0) {
            inst_addr->inst_id = i;
            err = strcpy_sp(inst_addr->ip, sizeof(inst_addr->ip), nodes_list.nodes[i]);
            if (err != EOK) {
                CM_THROW_ERROR(ERR_SYSTEM_CALL, err);
                CM_FREE_PTR(*inst_addrs);
                return CM_ERROR;
            }
            inst_addr->port = nodes_list.ports[i];
            inst_addr->need_connect = CM_TRUE;
            ++inst_addr;
        }
    }
    *inst_cnt = nodes_list.inst_cnt;
    return CM_SUCCESS;
}

status_t dss_verify_nodes_list(void *lex, void *def)
{
    const char *nodes_list_str = (const char *)lex;
    size_t len = strlen(nodes_list_str);
    for (size_t i = 0; i < len; ++i) {
        if ((nodes_list_str[i] != '|') && (!(CM_IS_DIGIT(nodes_list_str[i]))) && (nodes_list_str[i] != '.') &&
            (nodes_list_str[i] != ',')) {
            DSS_THROW_ERROR(ERR_DSS_INVALID_PARAM, "DSS_NODES_LIST contains invalid characters");
            return CM_ERROR;
        }
    }

    securec_check_ret(strcpy_sp(((dss_def_t *)def)->value, CM_PARAM_BUFFER_SIZE, nodes_list_str));
    return CM_SUCCESS;
}

// addition or deletion of new instances is not allowed.
// only replacement of old instances is allowed.
static status_t check_nodes_list_validity(uint32 inst_cnt, const mes_addr_t *inst_addrs)
{
    if (inst_cnt != g_inst_cfg->params.nodes_list.inst_cnt) {
        DSS_THROW_ERROR(
            ERR_DSS_INVALID_PARAM, "instance_ids in DSS_NODES_LIST are not allowed to be changed dynamically");
        return CM_ERROR;
    }
    for (uint32 i = 0; i < inst_cnt; ++i) {
        uint32 inst_id = inst_addrs[i].inst_id;
        if (inst_addrs[i].port == 0) {
            DSS_THROW_ERROR(ERR_DSS_INVALID_PARAM, "IP ports in DSS_NODES_LIST cannot be zero");
            return CM_ERROR;
        }
        // If some instance's IP port in params is 0, it doesnot exist in this cluster.
        // Meantime, IP port of this instance in the new DSS_NODES_LIST is not zero, which means
        // the user is trying to add new instances.
        if (g_inst_cfg->params.nodes_list.ports[inst_id] == 0) {
            DSS_THROW_ERROR(
                ERR_DSS_INVALID_PARAM, "instance_ids in DSS_NODES_LIST are not allowed to be changed dynamically");
            return CM_ERROR;
        }
    }
    LOG_RUN_INF("the user-inputted DSS_NODES_LIST is valid.");
    return CM_SUCCESS;
}

static status_t modify_ips_in_params(uint32 inst_cnt, const mes_addr_t *inst_addrs)
{
    for (uint32 i = 0; i < inst_cnt; ++i) {
        uint32 inst_id = inst_addrs[i].inst_id;
        g_inst_cfg->params.nodes_list.ports[inst_id] = inst_addrs[i].port;
        if (strcmp(g_inst_cfg->params.nodes_list.nodes[inst_id], inst_addrs[i].ip) != 0) {
            securec_check_ret(strcpy_sp(g_inst_cfg->params.nodes_list.nodes[inst_id], CM_MAX_IP_LEN, inst_addrs[i].ip));
        }
    }
    return CM_SUCCESS;
}

status_t dss_update_local_nodes_list(char *nodes_list_str)
{
    uint32 inst_cnt = 0;
    mes_addr_t *inst_addrs = NULL;
    CM_RETURN_IFERR(dss_alloc_and_extract_inst_addrs(nodes_list_str, &inst_cnt, &inst_addrs));
    CM_RETURN_IFERR(check_nodes_list_validity(inst_cnt, inst_addrs));
    status_t status = mes_update_instance(inst_cnt, inst_addrs);
    if (status != CM_SUCCESS) {
        LOG_RUN_ERR("Failed to update local mes connections.");
        CM_FREE_PTR(inst_addrs);
        return status;
    }
    CM_RETURN_IFERR(modify_ips_in_params(inst_cnt, inst_addrs));
    LOG_RUN_INF("Success to update local mes connections.");
    CM_FREE_PTR(inst_addrs);
    return CM_SUCCESS;
}

status_t dss_notify_dss_nodes_list(void *se, void *item, char *value)
{
    return dss_update_local_nodes_list(value);
}