/*
 * Copyright (c) 2024 Huawei Technologies Co.,Ltd.
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
 * dss_redo_recovery.h
 *
 *
 * IDENTIFICATION
 *    src/common/persist/dss_redo_recovery.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __DSS_REDO_RECOVERY_H__
#define __DSS_REDO_RECOVERY_H__

#include "dss_redo.h"

#ifdef __cplusplus
extern "C" {
#endif

status_t dss_recover_ctrlinfo(dss_vg_info_item_t *vg_item);
status_t dss_check_recover_redo_log(dss_vg_info_item_t *vg_item, bool8 *recover_redo);
bool32 dss_check_redo_batch_complete(dss_redo_batch_t *batch, dss_redo_batch_t *tail, bool32 check_hash);
status_t dss_recover_from_offset_inner(dss_session_t *session, dss_vg_info_item_t *vg_item, char *log_buf);
status_t dss_recover_from_slot_inner(dss_session_t *session, dss_vg_info_item_t *vg_item, char *log_buf);
status_t dss_load_log_buffer_from_offset(dss_vg_info_item_t *vg_item, bool8 *need_recovery);
status_t dss_load_log_buffer_from_slot(dss_vg_info_item_t *vg_item, bool8 *need_recovery);
status_t dss_read_redolog_from_disk(dss_vg_info_item_t *vg_item, uint32 volume_id, int64 offset, char *buf, int32 size);
status_t dss_recover_redo_log_with_range(dss_session_t *session, uint32 vg_beg, uint32 vg_end);

#ifdef __cplusplus
}
#endif

#endif
