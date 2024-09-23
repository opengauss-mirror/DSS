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
 * dss_hp_defs.h
 *
 *
 * IDENTIFICATION
 *    src/hotpatch/dss_hp_defs.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __DSS_HP_DEFS_H__
#define __DSS_HP_DEFS_H__

#include "cm_error.h"
#include "cm_types.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DSS_HOT_PATCH_FOLDER "hotpatch"
#define DSS_MAX_HOT_PATCH_NUMBER 99

#define DSS_HP_STATE_BUFFER_SIZE 32
#define DSS_HP_VERSION_BUFFER_SIZE (uint32)32

#define DSS_HP_FILE_PATH_MAX_LEN (uint32)256

#define DSS_HP_OPERATION_LOAD "load"
#define DSS_HP_OPERATION_ACTIVE "active"
#define DSS_HP_OPERATION_DEACTIVE "deactive"
#define DSS_HP_OPERATION_UNLOAD "unload"
#define DSS_HP_OPERATION_REFRESH "refresh"

typedef enum en_dss_hp_operation_cmd {
    DSS_HP_OP_LOAD = 1,
    DSS_HP_OP_ACTIVE = 2,
    DSS_HP_OP_DEACTIVE = 3,
    DSS_HP_OP_UNLOAD = 4,
    DSS_HP_OP_REFRESH = 5,
    DSS_HP_OP_INVALID = 6
} dss_hp_operation_cmd_e;

dss_hp_operation_cmd_e dss_hp_str_to_operation(const char *operation_str);

static inline bool32 dss_hp_cmd_need_patch_file(dss_hp_operation_cmd_e operation)
{
    return operation == DSS_HP_OP_LOAD || operation == DSS_HP_OP_ACTIVE || operation == DSS_HP_OP_DEACTIVE ||
           operation == DSS_HP_OP_UNLOAD;
}

#define DSS_HP_STATUS_UNKNOWN "UNKNOWN"
#define DSS_HP_STATUS_UNLOAD "UNLOAD"
#define DSS_HP_STATUS_DEACTIVE "DEACTIVE"
#define DSS_HP_STATUS_ACTIVED "ACTIVED"

typedef enum en_dss_hp_state {
    DSS_HP_STATE_UNKNOWN,
    DSS_HP_STATE_UNLOAD,
    DSS_HP_STATE_DEACTIVE,
    DSS_HP_STATE_ACTIVED,
} dss_hp_state_e;
const char *dss_hp_state_to_str(dss_hp_state_e state);

typedef struct st_dss_hp_info_view_row {
    uint32 patch_number;
    char patch_name[DSS_HP_FILE_PATH_MAX_LEN + 1];
    dss_hp_state_e patch_state;
    char patch_lib_state[DSS_HP_STATE_BUFFER_SIZE];
    char patch_commit[DSS_HP_VERSION_BUFFER_SIZE];
    char patch_bin_version[DSS_HP_VERSION_BUFFER_SIZE];
} dss_hp_info_view_row_t;

typedef struct st_dss_hp_info_view {
    uint32 count;
    dss_hp_info_view_row_t info_list[DSS_MAX_HOT_PATCH_NUMBER];
} dss_hp_info_view_t;

#ifdef __cplusplus
}
#endif

#endif