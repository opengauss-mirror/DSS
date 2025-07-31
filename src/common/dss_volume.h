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
 * dss_volume.h
 *
 *
 * IDENTIFICATION
 *    src/common/dss_volume.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __DSS_VOLUME_H__
#define __DSS_VOLUME_H__

#include "dss_defs.h"
#include "cm_date.h"
#include "dss_file_def.h"
#include "ceph_rbd_param.h"

#ifdef __cplusplus
extern "C" {
#endif
extern uint64 g_log_offset;
status_t dss_open_volume(const char *name, const char *code, int flags, dss_volume_t *volume);
void dss_close_volume(dss_volume_t *volume);
status_t dss_read_volume(dss_volume_t *volume, int64 offset, void *buf, int32 size);
status_t dss_write_volume(dss_volume_t *volume, int64 offset, const void *buf, int32 size);
status_t dss_append_volume(dss_volume_t *volume, int64 offset, const void *buf, int32 size);
uint64 dss_get_volume_size(dss_volume_t *volume);

status_t dss_open_simple_volume(const char *name, int flags, dss_simple_volume_t *volume);
void dss_close_simple_volume(dss_simple_volume_t *simple_volume);

#ifdef __cplusplus
}
#endif

#endif
