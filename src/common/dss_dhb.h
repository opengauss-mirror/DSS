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
 * dss_dhb.h
 *
 * Disk Heartbeat (DHB) module for DSS leader election.
 * 
 * Layout in reserve1 area (663K starting at 281K):
 *   DHB LOCK (8K @ 288K) - Leader election lock (8K aligned for cm_disklock)
 *   Heartbeat Area (from 296K) - Per-node heartbeat blocks (512B each)
 *
 * Logic:
 *   1. Background thread writes heartbeat + reads all heartbeats
 *   2. If master heartbeat dies (offline), try to grab DHB LOCK
 *   3. Whoever grabs the lock becomes the new master
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
#include "dss_defs.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Configuration Constants
 * ============================================================================
 * 
 * Timing parameters:
 * - HEARTBEAT_INTERVAL: 500ms - write heartbeat frequency
 * - HEARTBEAT_TIMEOUT:  5s - time before node is considered dead
 * - LEASE_TIMEOUT:      5s - leader lock lease duration
 * 
 * RTO (Recovery Time Objective) = TIMEOUT = 5 seconds
 * When master heartbeat stops, standby detects it after ~5s and grabs lock.
 */
#define DSS_DHB_HEARTBEAT_INTERVAL_MS   500     /* 500ms heartbeat write interval */
#define DSS_DHB_HEARTBEAT_TIMEOUT_MS    5000    /* 5 seconds before node is dead */
#define DSS_DHB_LEASE_TIMEOUT_MS        5000    /* 5 seconds lock lease */

/* ============================================================================
 * Disk Layout (in reserve1 area, starting at SIZE_K(281))
 * ============================================================================
 * 
 * reserve1 area: 663K from offset SIZE_K(281)
 * 
 *   Offset           Size    Content
 *   SIZE_K(288)      8K      DHB LOCK - leader election (8K aligned)
 *   SIZE_K(296)      32K     Heartbeat blocks (64 nodes * 512B each)
 * 
 * cm_disklock requires 8K alignment, so we start lock at 288K (288*1024 = 36*8192).
 */
#define DSS_DHB_LOCK_OFFSET     (SIZE_K(288))   /* DHB LOCK area (8K aligned) */
#define DSS_DHB_LOCK_SIZE       (SIZE_K(8))     /* Lock area size (8KB) */
#define DSS_DHB_AREA_OFFSET     (SIZE_K(296))   /* Heartbeat area (after lock) */
#define DSS_DHB_BLOCK_SIZE      512             /* Each node's heartbeat block */
#define DSS_DHB_AREA_SIZE       (DSS_DHB_BLOCK_SIZE * DSS_MAX_INSTANCES)

/* Magic number for heartbeat validation */
#define DSS_DHB_MAGIC           0xDEADBEEF12345678ULL

/* ============================================================================
 * Node Status
 * ============================================================================ */

typedef enum {
    DSS_DHB_NODE_OFFLINE = 0,
    DSS_DHB_NODE_ONLINE = 1
} dss_dhb_node_status_e;

/* Heartbeat block structure (512 bytes, aligned to disk sector) */
typedef struct st_dss_dhb_heartbeat {
    uint64 magic;           /* Magic number for validation */
    uint32 inst_id;         /* Instance ID */
    uint32 status;          /* Node status (online/offline) */
    uint64 timestamp_ns;    /* Last heartbeat timestamp (nanoseconds) */
    uint64 sequence;        /* Monotonically increasing sequence number */
    char reserved[480];     /* Padding to 512 bytes */
} dss_dhb_heartbeat_t;

/* ============================================================================
 * Public Interface
 * ============================================================================ */

/**
 * Initialize DHB module
 * Call this during DSS instance startup after VG info is loaded
 * 
 * @param volume_path Path to the first volume (for heartbeat and lock storage)
 * @param inst_id     Current instance ID
 * @return CM_SUCCESS on success, CM_ERROR on failure
 */
status_t dss_dhb_init(const char *volume_path, uint32 inst_id);

/**
 * Cleanup DHB module
 * Call this during DSS instance shutdown
 */
void dss_dhb_uninit(void);

/**
 * Get current lock owner (master ID)
 * 
 * @param master_id Output: current master instance ID, or DSS_INVALID_ID32 if none
 * @return CM_SUCCESS on success, CM_ERROR on failure
 */
status_t dss_dhb_get_lock_owner(uint32 *master_id);

/**
 * Try to acquire leader lock
 * 
 * @param got_lock Output: CM_TRUE if lock acquired, CM_FALSE otherwise
 * @return CM_SUCCESS on success (check got_lock for result), CM_ERROR on failure
 */
status_t dss_dhb_try_lock(bool32 *got_lock);

/**
 * Release leader lock
 * 
 * @return CM_SUCCESS on success, CM_ERROR on failure
 */
status_t dss_dhb_unlock(void);

/**
 * Transfer lock to another instance (planned switchover)
 * 
 * @param target_inst_id Target instance ID to transfer lock to
 * @return CM_SUCCESS on success, CM_ERROR on failure
 */
status_t dss_dhb_trans_lock(uint32 target_inst_id);

/**
 * Check if a specific instance is online (based on heartbeat)
 * 
 * @param inst_id Instance ID to check
 * @return CM_TRUE if online, CM_FALSE if offline
 */
bool32 dss_dhb_is_online(uint32 inst_id);

/**
 * Check if current instance is the leader
 * 
 * @return CM_TRUE if this instance holds the leader lock
 */
bool32 dss_dhb_is_leader(void);

/**
 * Get online instance bitmap
 * 
 * @return Bitmap where bit N is set if instance N is online
 */
uint64 dss_dhb_get_online_map(void);

/**
 * Update peer connections based on heartbeat status
 * Called periodically by recovery thread
 * 
 * @param inst Pointer to dss_instance (for compatibility, can be NULL)
 */
void dss_dhb_check_peer(void *inst);

/**
 * Check failed instances for broadcast retry decisions
 * 
 * @param failed_insts Bitmap of instances that failed in broadcast
 * @return CM_TRUE if any failed instance is actually online (retry needed)
 */
bool32 dss_dhb_check_failed_insts(uint64 failed_insts);

/**
 * Set instance count for heartbeat scanning
 * 
 * @param inst_cnt Number of instances in the cluster
 */
void dss_dhb_set_inst_count(uint32 inst_cnt);

#ifdef __cplusplus
}
#endif

#endif /* __DSS_DHB_H__ */
