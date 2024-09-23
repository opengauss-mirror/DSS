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
 * dss_hp_interface.h
 *
 *
 * IDENTIFICATION
 *    src/hotpatch/dss_hp_interface.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __HP_INTERFACES_H__
#define __HP_INTERFACES_H__

#include "cm_defs.h"
#include "cm_error.h"
#include "dss_hp_defs.h"

#ifdef __cplusplus
extern "C" {
#endif

bool32 dss_hp_is_inited();
status_t dss_hp_check_is_inited(void);
status_t dss_hp_init(const char *hotpatch_dr);
status_t dss_hp_patched_load(void);
status_t dss_hp_load(const char *file_name);
status_t dss_hp_active(const char *file_name);
status_t dss_hp_deactive(const char *file_name);
status_t dss_hp_unload(const char *file_name);
status_t dss_hp_refresh_patch_info(void);
status_t dss_hp_get_patch_count(uint32 *count, bool32 *is_same_version);
status_t dss_hp_get_patch_info_row(uint32 number, dss_hp_info_view_row_t *row_info);

void dss_hp_latch_x(uint32 session_id);
void dss_hp_latch_s(uint32 session_id);
void dss_hp_unlatch(uint32 session_id);

#ifdef __cplusplus
}
#endif

#endif