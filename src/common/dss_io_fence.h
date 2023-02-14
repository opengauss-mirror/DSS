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
 * dss_io_fence.h
 *
 *
 * IDENTIFICATION
 *    src/common/dss_io_fence.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __DSS_IO_FENCE_H__
#define __DSS_IO_FENCE_H__

#include "dss_defs.h"
#include "dss_session.h"
#include "dss_file.h"
#include "cm_scsi.h"
#include "cm_iofence.h"
#include "cm_list.h"

#ifdef __cplusplus
extern "C" {
#endif
typedef struct st_dev_info {
    char *dev;
    inquiry_data_t data;
} dev_info_t;

// kick/reg host with all devs
status_t dss_iof_kick_all_volumes(dss_vg_info_t *dss_vg_info, int64 rk, int64 rk_kick, ptlist_t *reg_list);
status_t dss_iof_sync_all_vginfo(dss_session_t *session, dss_vg_info_t *dss_vg_info);
status_t dss_iof_kick_all(dss_vg_info_t *vg_info, dss_config_t *inst_cfg, int64 rk, int64 rk_kick);
status_t dss_iof_register_core(int64 rk, dss_vg_info_t *dss_vg_info);
status_t dss_iof_unregister_core(int64 rk, dss_vg_info_t *dss_vg_info);
status_t dss_iof_register_all(int64 rk, bool32 is_server);
status_t dss_iof_unregister_all(int64 rk, bool32 is_server);

// inquire lun info
status_t dss_inquiry_luns_from_ctrl(dss_vg_info_item_t *item, ptlist_t *lunlist);
status_t dss_inquiry_luns(ptlist_t *lunlist, bool32 is_server);
status_t dss_inquiry_lun(dev_info_t *dev_info);

// read keys and reservations
status_t dss_iof_inql_regs_core(ptlist_t *reglist, dss_vg_info_item_t *item);
status_t dss_iof_inql_regs(dss_vg_info_t *vg_info, ptlist_t *reglist);

status_t dss_iof_unregister_single(int64 rk, char *dev);
status_t dss_iof_register_single(int64 rk, char *dev);

#ifdef __cplusplus
}
#endif
#endif
