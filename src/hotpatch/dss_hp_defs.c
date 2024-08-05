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
 * dss_hp_defs.c
 *
 *
 * IDENTIFICATION
 *    src/hotpatch/dss_hp_defs.c
 *
 * -------------------------------------------------------------------------
 */

#include "dss_hp_defs.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct st_dss_hp_str_to_operation {
    const char *operation_str;
    dss_hp_operation_cmd_e operation_enum;
} dss_hp_str_to_operation_t;

dss_hp_operation_cmd_e dss_hp_str_to_operation(const char *operation_str)
{
    static const dss_hp_str_to_operation_t operation_map[] = {{DSS_HP_OPERATION_LOAD, DSS_HP_OP_LOAD},
        {DSS_HP_OPERATION_ACTIVE, DSS_HP_OP_ACTIVE}, {DSS_HP_OPERATION_DEACTIVE, DSS_HP_OP_DEACTIVE},
        {DSS_HP_OPERATION_UNLOAD, DSS_HP_OP_UNLOAD}, {DSS_HP_OPERATION_REFRESH, DSS_HP_OP_REFRESH}};
    if (operation_str == NULL) {
        return DSS_HP_OP_INVALID;
    }
    for (size_t i = 0; i < sizeof(operation_map) / sizeof(dss_hp_str_to_operation_t); ++i) {
        if (strcmp(operation_str, operation_map[i].operation_str) == 0) {
            return operation_map[i].operation_enum;
        }
    }
    return DSS_HP_OP_INVALID;
}

const char *dss_hp_state_to_str(dss_hp_state_e state)
{
    switch (state) {
        case DSS_HP_STATE_UNKNOWN:
            return DSS_HP_STATUS_UNKNOWN;
        case DSS_HP_STATE_UNLOAD:
            return DSS_HP_STATUS_UNLOAD;
        case DSS_HP_STATE_DEACTIVE:
            return DSS_HP_STATUS_DEACTIVE;
        case DSS_HP_STATE_ACTIVED:
            return DSS_HP_STATUS_ACTIVED;
        default:
            return DSS_HP_STATUS_UNKNOWN;
    }
}

#ifdef __cplusplus
}
#endif