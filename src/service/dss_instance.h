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
#include "dss_reactor.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DSS_MAX_INSTANCE_OPEN_FILES 1
#define DSS_LOGFILE_SIZE 10000
#define DSS_LOG_LEVEL 0xffffffff
#define DSS_INS_SIZE (sizeof(dss_share_vg_info_t))

typedef enum {
    CM_RES_SUCCESS = 0,
    CM_RES_CANNOT_DO = 1,
    CM_RES_DDB_FAILED = 2,
    CM_RES_VERSION_WRONG = 3,
    CM_RES_CONNECT_ERROR = 4,
    CM_RES_TIMEOUT = 5,
    CM_RES_NO_LOCK_OWNER = 6,
} cm_err_code;

#define DSS_CM_LOCK "dss cm lock"
#define DSS_MAX_FAIL_TIME_WITH_CM 30
#define DSS_GET_CM_LOCK_LONG_SLEEP cm_sleep(500)

typedef struct st_dss_cm_res {
    spinlock_t init_lock;
    bool8 is_init;
    bool8 is_valid;
    cm_res_mgr_t mgr;
} dss_cm_res;

typedef struct st_dss_srv_args {
    char dss_home[DSS_MAX_PATH_BUFFER_SIZE];
    bool is_maintain;
} dss_srv_args_t;

typedef struct st_dss_instance {
    int32 lock_fd;
    spinlock_t switch_lock;
    dss_config_t inst_cfg;
    dss_instance_status_e status;
    uds_lsnr_t lsnr;
    reactors_t reactors;
    thread_t *threads;
    int64 active_sessions;
    bool32 abort_status;
    dss_cm_res cm_res;
    uint64 inst_work_status_map; // one bit one inst, bit value is 1 means inst ok, 0 means inst not ok
    spinlock_t inst_work_lock;
    dss_kernel_instance_t *kernel_instance;
    int32 cluster_proto_vers[DSS_MAX_INSTANCES];
    bool8 is_maintain;
    uint8 reserve[3];
    bool32 is_join_cluster;
} dss_instance_t;

status_t dss_lock_instance(void);
status_t dss_startup(dss_instance_t *inst, dss_srv_args_t dss_args);

extern dss_instance_t g_dss_instance;
#define ZFS_INST (&g_dss_instance)
#define ZFS_CFG (&g_dss_instance.inst_cfg)

status_t dss_start_lsnr(dss_instance_t *inst);
void dss_uninit_cm(dss_instance_t *inst);
void dss_check_peer_inst(dss_instance_t *inst, uint64 inst_id);
void dss_free_log_ctrl(dss_instance_t *inst);
status_t dss_get_instance_log_buf(dss_instance_t *inst);
status_t dss_load_log_buffer(dss_redo_batch_t *batch);
status_t dss_alloc_instance_log_buf(dss_instance_t *inst);
status_t dss_recover_from_instance(dss_instance_t *inst);
void dss_check_peer_by_inst(dss_instance_t *inst, uint64 inst_id);
uint64 dss_get_inst_work_status(void);
void dss_set_inst_work_status(uint64 cur_inst_map);
uint32 dss_get_cm_lock_owner(dss_instance_t *inst, bool32 *grab_lock, bool32 try_lock);
status_t dss_get_cm_res_lock_owner(dss_cm_res *cm_res, uint32 *master_id);
void dss_get_cm_lock_and_recover(thread_t *thread);
bool32 dss_check_join_cluster();
void dss_check_unreg_volume(void);

#ifdef __cplusplus
}
#endif

#endif
