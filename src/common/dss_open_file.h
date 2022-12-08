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
 * dss_open_file.h
 *
 *
 * IDENTIFICATION
 *    src/common/dss_open_file.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __DSS_OPEN_FILE_H__
#define __DSS_OPEN_FILE_H__

#include "dss_diskgroup.h"
#include "dss_file_def.h"
#include "dss_session.h"

typedef struct st_dss_open_file_info_t {
    uint64 ftid;
    uint64 pid;
    uint64 ref;
    int64 start_time;
} dss_open_file_info_t;

status_t dss_init_open_file_index(dss_vg_info_item_t *vg_item);
void dss_destroy_open_file_index(dss_vg_info_item_t *vg_item);

status_t dss_insert_open_file_index(dss_vg_info_item_t *vg_item, uint64 ftid, uint64 pid, int64 start_time);
status_t dss_delete_open_file_index(dss_vg_info_item_t *vg_item, uint64 ftid, uint64 pid, int64 start_time);
status_t dss_check_open_file(dss_vg_info_item_t *vg_item, uint64 fid, bool32 *is_open);

#endif
