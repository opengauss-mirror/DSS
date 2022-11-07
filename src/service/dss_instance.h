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
 * dss_instance.h
 *
 *
 * IDENTIFICATION
 *    src/service/dss_instance.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __DSS_INSTANCE_H__
#define __DSS_INSTANCE_H__

#include "cm_spinlock.h"
#include "cs_listener.h"
#include "dss_defs.h"
#include "dss_volume.h"
#include "dss_redo.h"
#include "dss_file.h"
#include "dss_session.h"
#include "dss_diskgroup.h"
#include "dss_param.h"
#include "dss_lsnr.h"
#include "cm_res_mgr.h"  // for cm_res_mgr_t

#ifdef __cplusplus
extern "C" {
#endif

#define DSS_MAX_INSTANCE_OPEN_FILES 1
#define DSS_LOGFILE_SIZE 10000
#define DSS_LOG_LEVEL 0xffffffff
#define DSS_INS_SIZE (sizeof(dss_share_vg_info_t))

typedef enum en_zfs_instance_status {
    ZFS_STATUS_OPEN = 1,
    ZFS_STATUS_RECOVERY,
} dss_instance_status_t;

typedef struct st_dss_cm_res {
    spinlock_t init_lock;
    bool8 is_init;
    bool8 is_valid;
    cm_res_mgr_t mgr;
} dss_cm_res;

typedef struct st_dss_instance {
    int32 lock_fd;
    spinlock_t lock;
    dss_config_t inst_cfg;  // instance config
    dss_instance_status_t status;
    uds_lsnr_t lsnr;
    // HYJ: reform_ctx_t rf_ctx;
    thread_t *threads;
    int64 thread_cnt;
    bool32 abort_status;
    dss_cm_res cm_res;
    dss_kernel_instance_t *kernel_instance;
} dss_instance_t;

status_t dss_lock_instance(void);
status_t dss_startup(dss_instance_t *inst, char *home);

extern dss_instance_t g_dss_instance;
#define ZFS_INST (&g_dss_instance)
#define ZFS_CFG (&g_dss_instance.inst_cfg)

status_t dss_start_lsnr(dss_instance_t *inst);
void dss_uninit_cm(dss_instance_t *inst);
void dss_check_peer_inst(dss_instance_t *inst);
void dss_free_log_ctrl(dss_instance_t *inst);
status_t dss_get_instance_log_buf_and_recover(dss_instance_t *inst);
status_t dss_load_log_buffer(dss_redo_batch_t *batch);
status_t dss_alloc_instance_log_buf(dss_instance_t *inst);
status_t dss_recover_from_instance(dss_instance_t *inst);

#ifdef __cplusplus
}
#endif

#endif
