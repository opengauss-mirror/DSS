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
 * dss_hp_interfaces_stub.c
 *
 *
 * IDENTIFICATION
 *    src/hotpatch/dss_hp_interfaces_stub.c
 *
 * -------------------------------------------------------------------------
 */

#include "dss_hp_interface.h"
#include "dss_errno.h"
#include "dss_log.h"

#ifdef __cplusplus
extern "C" {
#endif

bool32 dss_hp_is_inited()
{
    return CM_FALSE;
}

status_t dss_hp_check_is_inited()
{
    DSS_THROW_ERROR(ERR_DSS_HP_NOT_SUPPORT);
    return CM_ERROR;
}

status_t dss_hp_init(const char *hotpatch_dir)
{
    return CM_SUCCESS;
}

status_t dss_hp_patched_load(void)
{
    DSS_THROW_ERROR(ERR_DSS_HP_NOT_SUPPORT);
    return CM_ERROR;
}

status_t dss_hp_load(const char *file_name)
{
    DSS_THROW_ERROR(ERR_DSS_HP_NOT_SUPPORT);
    return CM_ERROR;
}

status_t dss_hp_active(const char *file_name)
{
    DSS_THROW_ERROR(ERR_DSS_HP_NOT_SUPPORT);
    return CM_ERROR;
}

status_t dss_hp_deactive(const char *file_name)
{
    DSS_THROW_ERROR(ERR_DSS_HP_NOT_SUPPORT);
    return CM_ERROR;
}

status_t dss_hp_unload(const char *file_name)
{
    DSS_THROW_ERROR(ERR_DSS_HP_NOT_SUPPORT);
    return CM_ERROR;
}

status_t dss_hp_refresh_patch_info(void)
{
    DSS_THROW_ERROR(ERR_DSS_HP_NOT_SUPPORT);
    return CM_ERROR;
}

status_t dss_hp_get_patch_count(uint32 *count, bool32 *is_same_version)
{
    DSS_THROW_ERROR(ERR_DSS_HP_NOT_SUPPORT);
    return CM_ERROR;
}

status_t dss_hp_get_patch_info_row(uint32 number, dss_hp_info_view_row_t *row_info)
{
    DSS_THROW_ERROR(ERR_DSS_HP_NOT_SUPPORT);
    return CM_ERROR;
}

void dss_hp_latch_x(uint32 session_id)
{
    return;
}

void dss_hp_latch_s(uint32 session_id)
{
    return;
}

void dss_hp_unlatch(uint32 session_id)
{
    return;
}

#ifdef __cplusplus
}
#endif