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
 * dss_dhb.h
 *
 * Disk-based HeartBeat (DHB) mechanism to replace CM dependency.
 * Features:
 *   1. Leader election using disk lock (cm_disklock)
 *   2. Node heartbeat for online status detection
 *
 * IDENTIFICATION
 *    src/common/dss_dhb.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __DSS_DHB_H__
#define __DSS_DHB_H__

#include "cm_types.h"
#include "cm_defs.h"
#include "cm_disklock.h"
#include "dss_defs.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Constants
 * ============================================================================ */

/* Heartbeat area layout in VG header (first 1MB):
 * - vg_header:     512B
 * - core_ctrl:     16KB  
 * - volume_ctrl:   256KB
 * - root_ft:       8KB
 * - redo_ctrl:     512B
 * - reserve1:      663KB  <- heartbeat area
 * - disk_latch:    32KB   <- leader lock area
 */
#define DSS_DHB_AREA_OFFSET     (SIZE_K(281))
#define DSS_DHB_BLOCK_SIZE      512
#define DSS_DHB_AREA_SIZE       (DSS_DHB_BLOCK_SIZE * DSS_MAX_INSTANCES)
#define DSS_DHB_MAGIC           0xDEADBEEF12345678ULL

/* Timing configuration */
#define DSS_DHB_TIMEOUT_SEC     2
#define DSS_DHB_INTERVAL_SEC    1
#define DSS_DHB_LEASE_SEC       5
#define DSS_DHB_LOCK_OFFSET     (SIZE_K(944))

/* Retry configuration */
#define DSS_DHB_CHECK_MAX_RETRIES       3
#define DSS_DHB_CHECK_RETRY_INTERVAL_MS 1000

/* ============================================================================
 * Types
 * ============================================================================ */

typedef enum en_dss_dhb_status {
    DSS_DHB_UNKNOWN = 0,
    DSS_DHB_ONLINE = 1,
    DSS_DHB_OFFLINE = 2,
    DSS_DHB_STARTING = 3,
} dss_dhb_status_e;

#pragma pack(1)
typedef struct st_dss_dhb_node {
    uint64 magic;
    uint64 inst_id;
    uint64 hb_time;
    uint64 sequence;
    uint32 status;
    uint32 checksum;
    char reserved[472];
} dss_dhb_node_t;
#pragma pack()

typedef struct st_dss_dhb_ctx {
    char volume_path[DSS_MAX_VOLUME_PATH_LEN];
    int fd;
    uint64 hb_offset;
    uint32 inst_id;
    uint32 timeout_sec;
    uint32 interval_sec;
    uint64 last_hb_time;
    uint64 sequence;
    uint32 lock_id;
    bool32 is_leader;
    bool32 is_inited;
    dss_dhb_node_t nodes[DSS_MAX_INSTANCES];
    uint64 online_map;
} dss_dhb_ctx_t;

extern dss_dhb_ctx_t g_dss_dhb_ctx;

/* ============================================================================
 * Cluster management
 * ============================================================================ */

status_t dss_dhb_cluster_init_with_path(const char *volume_path, uint32 inst_id);
void dss_dhb_cluster_uninit(void);

/* ============================================================================
 * Peer status
 * ============================================================================ */

void dss_dhb_check_peer(void *inst);
bool32 dss_dhb_is_online(uint32 inst_id);
uint64 dss_dhb_get_online_map(void);

/* ============================================================================
 * Leader election
 * ============================================================================ */

status_t dss_dhb_get_lock_owner(uint32 *master_id);
status_t dss_dhb_try_lock(bool32 *grab_lock);
status_t dss_dhb_unlock(void);
status_t dss_dhb_trans_lock(uint32 target_inst_id);

/* ============================================================================
 * Broadcast failure handling
 * ============================================================================ */

status_t dss_dhb_check_failed_insts(uint64 failed_map, uint64 *updated_map);

#ifdef __cplusplus
}
#endif

#endif /* __DSS_DHB_H__ */
