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
 * dsscmd_inq.h
 *
 *
 * IDENTIFICATION
 *    src/cmd/dsscmd_inq.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __DSSCMD_INQ_H__
#define __DSSCMD_INQ_H__

#include "dss_file_def.h"

#ifdef __cplusplus
extern "C" {
#endif

status_t dss_inq_lun(const char *home);
status_t dss_inq_reg(const char *home);
status_t dss_check_volume_register(char *entry_path, int64 host_id, bool32 *is_reg, int64 *iofence_key);
status_t dss_unreghl_core(const char *home, bool32 is_lock);
status_t dss_reghl_core(const char *home);
status_t dss_inq_reg_core(const char *home, int64 host_id);
bool32 is_register(iof_reg_in_t *reg, int64 host_id, int64 *iofence_key);
status_t dss_clean_vg_lock(const char *home, int64 inst_id);
status_t dss_kickh_core(const char *home, int64 host_id);

#ifdef __cplusplus
}
#endif

#endif
