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
 * dss_dhb.c
 *
 * Disk Heartbeat (DHB) module - Leader election via disk lock + heartbeat.
 *
 * Design:
 *   1. DHB LOCK (8K @ 288K) - Leader election lock
 *   2. Heartbeat Area (from 296K) - Per-node heartbeat blocks
 *
 * Logic:
 *   - Background thread writes heartbeat + reads all heartbeats
 *   - If master heartbeat dies (offline), try to grab DHB LOCK
 *   - Whoever grabs the lock becomes the new master
 *
 * IDENTIFICATION
 *    src/common/dss_dhb.c
 *
 * -------------------------------------------------------------------------
 */

#include "dss_dhb.h"
#include "dss_log.h"
#include "cm_disklock.h"
#include "cm_timer.h"
#include "cm_spinlock.h"
#include "securec.h"

#ifndef WIN32
#include <sys/time.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#endif

/* 
 * Note: MES connection management is handled by the caller (dss_instance.c)
 * after calling dss_dhb_check_peer() or dss_dhb_get_online_map().
 */

/* ============================================================================
 * Internal Data Structures
 * ============================================================================ */

/* Local heartbeat tracker - records when we last saw a sequence number change */
typedef struct st_dhb_local_tracker {
    uint64 last_sequence;       /* Last seen sequence number */
    uint64 last_change_ns;      /* Local time when sequence last changed (MONOTONIC) */
} dhb_local_tracker_t;

typedef struct st_dss_dhb_ctx {
    /* Initialization state */
    bool32 is_inited;
    uint32 inst_id;
    uint32 inst_cnt;
    char volume_path[DSS_MAX_PATH_BUFFER_SIZE];
    
    /* File descriptor for heartbeat I/O */
    int32 fd;
    
    /* Disk lock handle for leader election */
    uint32 lock_id;
    
    /* Heartbeat data */
    uint64 sequence;
    uint64 online_map;
    spinlock_t map_lock;
    dss_dhb_heartbeat_t nodes[DSS_MAX_INSTANCES];
    
    /* Local tracker for each node - uses LOCAL monotonic time */
    dhb_local_tracker_t local_tracker[DSS_MAX_INSTANCES];
    
    /* Current known master (from lock) */
    uint32 current_master;
    
    /* Background thread */
    thread_t thread;
    volatile bool32 thread_running;
} dss_dhb_ctx_t;

static dss_dhb_ctx_t g_dhb_ctx;

/* ============================================================================
 * Time Utilities
 * ============================================================================ */

/* Wall clock time - for writing timestamps to disk */
static inline uint64 dhb_now_ns(void)
{
    struct timeval tv;
    (void)gettimeofday(&tv, NULL);
    return (uint64)tv.tv_sec * 1000000000ULL + (uint64)tv.tv_usec * 1000ULL;
}

/* Monotonic time - for LOCAL timeout calculation (never goes back) */
static inline uint64 dhb_monotonic_ns(void)
{
    struct timespec ts;
    (void)clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64)ts.tv_sec * 1000000000ULL + (uint64)ts.tv_nsec;
}

/* ============================================================================
 * Heartbeat I/O
 * ============================================================================ */

static status_t dhb_write_heartbeat(void)
{
    dss_dhb_ctx_t *ctx = &g_dhb_ctx;
    
    if (ctx->fd <= 0) {
        return CM_ERROR;
    }
    
    /* Prepare heartbeat data */
    dss_dhb_heartbeat_t hb;
    errno_t err = memset_s(&hb, sizeof(hb), 0, sizeof(hb));
    if (err != EOK) {
        return CM_ERROR;
    }
    
    hb.magic = DSS_DHB_MAGIC;
    hb.inst_id = ctx->inst_id;
    hb.status = DSS_DHB_NODE_ONLINE;
    hb.timestamp_ns = dhb_now_ns();
    hb.sequence = ++ctx->sequence;
    
    /* Write to disk at heartbeat area (offset = 296K + inst_id * 512) */
    int64 offset = DSS_DHB_AREA_OFFSET + (int64)ctx->inst_id * DSS_DHB_BLOCK_SIZE;
    ssize_t written = pwrite(ctx->fd, &hb, DSS_DHB_BLOCK_SIZE, offset);
    
    if (written != DSS_DHB_BLOCK_SIZE) {
        LOG_DEBUG_WAR("[DHB] Write heartbeat failed: written=%zd, offset=%lld, errno=%d", 
            written, (long long)offset, errno);
        return CM_ERROR;
    }
    
    return CM_SUCCESS;
}

static status_t dhb_read_all_heartbeats(uint64 *new_online_map)
{
    dss_dhb_ctx_t *ctx = &g_dhb_ctx;
    
    if (ctx->fd <= 0 || new_online_map == NULL) {
        return CM_ERROR;
    }
    
    /* Read all heartbeat blocks */
    char buf[DSS_DHB_AREA_SIZE];
    ssize_t read_size = pread(ctx->fd, buf, DSS_DHB_AREA_SIZE, DSS_DHB_AREA_OFFSET);
    
    if (read_size != DSS_DHB_AREA_SIZE) {
        LOG_DEBUG_WAR("[DHB] Read heartbeats failed: read=%zd, errno=%d", read_size, errno);
        return CM_ERROR;
    }
    
    /* Use LOCAL monotonic time for timeout calculation */
    uint64 now_mono_ns = dhb_monotonic_ns();
    uint64 timeout_ns = (uint64)DSS_DHB_HEARTBEAT_TIMEOUT_MS * 1000000ULL;
    *new_online_map = 0;
    
    /* Process each node's heartbeat using SEQUENCE NUMBER change detection */
    for (uint32 i = 0; i < ctx->inst_cnt && i < DSS_MAX_INSTANCES; i++) {
        dss_dhb_heartbeat_t *hb = (dss_dhb_heartbeat_t *)(buf + i * DSS_DHB_BLOCK_SIZE);
        dhb_local_tracker_t *tracker = &ctx->local_tracker[i];
        
        /* Validate magic number */
        if (hb->magic != DSS_DHB_MAGIC || hb->inst_id != i) {
            continue;
        }
        
        /* Save heartbeat data */
        ctx->nodes[i] = *hb;
        
        /* Skip if node status is offline */
        if (hb->status != DSS_DHB_NODE_ONLINE) {
            continue;
        }
        
        /* 
         * Detect sequence number CHANGE, not timestamp comparison!
         * This works correctly even if clocks are not synchronized.
         */
        if (hb->sequence != tracker->last_sequence) {
            /* Sequence changed - node is alive */
            tracker->last_sequence = hb->sequence;
            tracker->last_change_ns = now_mono_ns;
            *new_online_map |= ((uint64)1 << i);
        } else if (tracker->last_change_ns == 0) {
            /* First time seeing this node */
            tracker->last_sequence = hb->sequence;
            tracker->last_change_ns = now_mono_ns;
            *new_online_map |= ((uint64)1 << i);
        } else {
            /* Sequence unchanged - check if timeout exceeded */
            uint64 elapsed_ns = now_mono_ns - tracker->last_change_ns;
            if (elapsed_ns < timeout_ns) {
                *new_online_map |= ((uint64)1 << i);
            }
            /* else: timeout exceeded, node is offline */
        }
    }
    
    /* Always mark self as online */
    *new_online_map |= ((uint64)1 << ctx->inst_id);
    
    return CM_SUCCESS;
}

/* ============================================================================
 * Lock Operations (called from background thread when master goes offline)
 * ============================================================================ */

static status_t dhb_get_lock_owner_internal(uint32 *master_id)
{
    dss_dhb_ctx_t *ctx = &g_dhb_ctx;
    
    if (master_id == NULL) {
        return CM_ERROR;
    }
    
    *master_id = DSS_INVALID_ID32;
    
    if (ctx->lock_id == CM_INVALID_LOCK_ID) {
        return CM_ERROR;
    }
    
    unsigned long long owner_id = CM_INVALID_INST_ID;
    int ret = cm_dl_getowner(ctx->lock_id, &owner_id);
    
    if (ret != CM_SUCCESS) {
        return CM_ERROR;
    }
    
    if (owner_id != CM_INVALID_INST_ID && owner_id < DSS_MAX_INSTANCES) {
        *master_id = (uint32)owner_id;
    }
    
    return CM_SUCCESS;
}

static status_t dhb_try_acquire_lock(bool32 *got_lock)
{
    dss_dhb_ctx_t *ctx = &g_dhb_ctx;
    
    if (got_lock == NULL) {
        return CM_ERROR;
    }
    
    *got_lock = CM_FALSE;
    
    if (ctx->lock_id == CM_INVALID_LOCK_ID) {
        return CM_ERROR;
    }
    
    /* Try to acquire the lock with no wait */
    int ret = cm_dl_lock(ctx->lock_id, 0);
    
    if (ret == CM_SUCCESS) {
        *got_lock = CM_TRUE;
        LOG_RUN_INF("[DHB] Acquired leader lock: inst_id=%u", ctx->inst_id);
    }
    
    return CM_SUCCESS;
}

/* ============================================================================
 * Background Thread
 * 
 * Logic:
 *   1. Write heartbeat
 *   2. Read all heartbeats, update online_map
 *   3. If current master went offline, try to grab the lock
 * ============================================================================ */

static void dhb_thread_entry(thread_t *thread)
{
    LOG_RUN_INF("[DHB] Background thread started, inst_id=%u", g_dhb_ctx.inst_id);
    
    dss_dhb_ctx_t *ctx = &g_dhb_ctx;
    uint32 interval_ms = DSS_DHB_HEARTBEAT_INTERVAL_MS;
    
    while (ctx->thread_running) {
        /* Step 1: Write our heartbeat */
        (void)dhb_write_heartbeat();
        
        /* Step 2: Read all heartbeats and compute online_map */
        uint64 new_online_map = 0;
        if (dhb_read_all_heartbeats(&new_online_map) == CM_SUCCESS) {
            /* Update online_map */
            uint64 old_map;
            cm_spin_lock(&ctx->map_lock, NULL);
            old_map = ctx->online_map;
            ctx->online_map = new_online_map;
            cm_spin_unlock(&ctx->map_lock);
            
            /* Log changes */
            if (old_map != new_online_map) {
                uint64 went_offline = old_map & ~new_online_map;
                uint64 went_online = ~old_map & new_online_map;
                LOG_RUN_INF("[DHB] Online map: 0x%llx -> 0x%llx (offline: 0x%llx, online: 0x%llx)", 
                    (unsigned long long)old_map, 
                    (unsigned long long)new_online_map,
                    (unsigned long long)went_offline,
                    (unsigned long long)went_online);
            }
            
            /* Step 3: Check current master status */
            uint32 lock_owner = DSS_INVALID_ID32;
            (void)dhb_get_lock_owner_internal(&lock_owner);
            
            /* Update current_master */
            if (lock_owner != ctx->current_master) {
                LOG_RUN_INF("[DHB] Master changed: %u -> %u", ctx->current_master, lock_owner);
                ctx->current_master = lock_owner;
            }
            
            /* Step 4: If master is offline (heartbeat died), try to grab lock */
            if (lock_owner != DSS_INVALID_ID32 && lock_owner != ctx->inst_id) {
                /* Check if master's heartbeat is still alive */
                bool32 master_online = (new_online_map & ((uint64)1 << lock_owner)) != 0;
                
                if (!master_online) {
                    LOG_RUN_INF("[DHB] Master %u heartbeat died, attempting to grab lock", lock_owner);
                    
                    bool32 got_lock = CM_FALSE;
                    (void)dhb_try_acquire_lock(&got_lock);
                    
                    if (got_lock) {
                        ctx->current_master = ctx->inst_id;
                        LOG_RUN_INF("[DHB] Became new master after %u failed", lock_owner);
                    }
                }
            } else if (lock_owner == DSS_INVALID_ID32) {
                /* No master, try to acquire lock */
                LOG_RUN_INF("[DHB] No master detected, attempting to grab lock");
                
                bool32 got_lock = CM_FALSE;
                (void)dhb_try_acquire_lock(&got_lock);
                
                if (got_lock) {
                    ctx->current_master = ctx->inst_id;
                    LOG_RUN_INF("[DHB] Became master (no previous owner)");
                }
            } else if (lock_owner == ctx->inst_id) {
                /* We are the master, renew lease */
                int ret = cm_dl_lock(ctx->lock_id, 0);
                if (ret != CM_SUCCESS) {
                    LOG_RUN_WAR("[DHB] Failed to renew lock lease: ret=%d", ret);
                }
            }
        }
        
        cm_sleep(interval_ms);
    }
    
    LOG_RUN_INF("[DHB] Background thread stopped");
}

static status_t dhb_start_thread(void)
{
    dss_dhb_ctx_t *ctx = &g_dhb_ctx;
    ctx->thread_running = CM_TRUE;
    
    status_t status = cm_create_thread(dhb_thread_entry, 0, NULL, &ctx->thread);
    if (status != CM_SUCCESS) {
        ctx->thread_running = CM_FALSE;
        LOG_RUN_ERR("[DHB] Failed to create background thread");
        return CM_ERROR;
    }
    
    return CM_SUCCESS;
}

static void dhb_stop_thread(void)
{
    dss_dhb_ctx_t *ctx = &g_dhb_ctx;
    
    if (!ctx->thread_running) {
        return;
    }
    
    ctx->thread_running = CM_FALSE;
    cm_close_thread(&ctx->thread);
}

/* ============================================================================
 * Public Interface - Initialization
 * ============================================================================ */

status_t dss_dhb_init(const char *volume_path, uint32 inst_id)
{
    dss_dhb_ctx_t *ctx = &g_dhb_ctx;
    
    if (ctx->is_inited) {
        LOG_RUN_INF("[DHB] Already initialized");
        return CM_SUCCESS;
    }
    
    if (volume_path == NULL || strlen(volume_path) == 0) {
        LOG_RUN_ERR("[DHB] Invalid volume path");
        return CM_ERROR;
    }
    
    LOG_RUN_INF("[DHB] Initializing: volume=%s, inst_id=%u", volume_path, inst_id);
    LOG_RUN_INF("[DHB] Layout: LOCK @ 0x%llx (8K), Heartbeat @ 0x%llx", 
        (unsigned long long)DSS_DHB_LOCK_OFFSET, 
        (unsigned long long)DSS_DHB_AREA_OFFSET);
    
    /* Clear context */
    errno_t err = memset_s(ctx, sizeof(dss_dhb_ctx_t), 0, sizeof(dss_dhb_ctx_t));
    if (err != EOK) {
        LOG_RUN_ERR("[DHB] memset failed");
        return CM_ERROR;
    }
    
    ctx->inst_id = inst_id;
    ctx->inst_cnt = DSS_MAX_INSTANCES;
    ctx->lock_id = CM_INVALID_LOCK_ID;
    ctx->fd = -1;
    ctx->map_lock = 0;
    ctx->current_master = DSS_INVALID_ID32;
    
    err = strcpy_s(ctx->volume_path, sizeof(ctx->volume_path), volume_path);
    if (err != EOK) {
        LOG_RUN_ERR("[DHB] Failed to copy volume path");
        return CM_ERROR;
    }
    
    /* Open volume for heartbeat I/O (O_SYNC ensures data persistence) */
    ctx->fd = open(volume_path, O_RDWR | O_SYNC);
    if (ctx->fd <= 0) {
        LOG_RUN_ERR("[DHB] Failed to open volume: %s, errno=%d", volume_path, errno);
        return CM_ERROR;
    }
    
    LOG_RUN_INF("[DHB] Volume opened: fd=%d", ctx->fd);
    
    /* Allocate disk lock at DHB_LOCK_OFFSET (288K) */
    uint32 lease_sec = DSS_DHB_LEASE_TIMEOUT_MS / 1000;
    if (lease_sec < 1) {
        lease_sec = 1;
    }
    
    LOG_RUN_INF("[DHB] Allocating disk lock: offset=0x%llx, inst_id=%u, lease=%u sec",
        (unsigned long long)DSS_DHB_LOCK_OFFSET, inst_id, lease_sec);
    
    ctx->lock_id = cm_dl_alloc_lease(volume_path, DSS_DHB_LOCK_OFFSET, 
        (unsigned long long)inst_id, lease_sec);
    if (ctx->lock_id == CM_INVALID_LOCK_ID) {
        LOG_RUN_ERR("[DHB] Failed to alloc disk lock");
        close(ctx->fd);
        ctx->fd = -1;
        return CM_ERROR;
    }
    
    LOG_RUN_INF("[DHB] Disk lock allocated: lock_id=%u", ctx->lock_id);
    
    /* Write initial heartbeat */
    (void)dhb_write_heartbeat();
    
    /* Read existing heartbeats */
    uint64 initial_online_map = 0;
    (void)dhb_read_all_heartbeats(&initial_online_map);
    ctx->online_map = initial_online_map;
    
    /* Get current lock owner */
    (void)dhb_get_lock_owner_internal(&ctx->current_master);
    
    LOG_RUN_INF("[DHB] Initial state: online_map=0x%llx, current_master=%u",
        (unsigned long long)ctx->online_map, ctx->current_master);
    
    /* Start background thread */
    if (dhb_start_thread() != CM_SUCCESS) {
        cm_dl_dealloc(ctx->lock_id);
        close(ctx->fd);
        ctx->fd = -1;
        return CM_ERROR;
    }
    
    ctx->is_inited = CM_TRUE;
    LOG_RUN_INF("[DHB] Initialized successfully");
    
    return CM_SUCCESS;
}

void dss_dhb_uninit(void)
{
    dss_dhb_ctx_t *ctx = &g_dhb_ctx;
    
    if (!ctx->is_inited) {
        return;
    }
    
    LOG_RUN_INF("[DHB] Uninitializing: inst_id=%u", ctx->inst_id);
    
    /* Stop background thread first */
    dhb_stop_thread();
    
    /* Release disk lock */
    if (ctx->lock_id != CM_INVALID_LOCK_ID) {
        (void)cm_dl_unlock(ctx->lock_id);
        (void)cm_dl_dealloc(ctx->lock_id);
        ctx->lock_id = CM_INVALID_LOCK_ID;
    }
    
    /* Close file descriptor */
    if (ctx->fd > 0) {
        close(ctx->fd);
        ctx->fd = -1;
    }
    
    ctx->is_inited = CM_FALSE;
    LOG_RUN_INF("[DHB] Uninitialized");
}

/* ============================================================================
 * Public Interface - Lock Operations
 * ============================================================================ */

status_t dss_dhb_get_lock_owner(uint32 *master_id)
{
    if (master_id == NULL) {
        return CM_ERROR;
    }
    
    *master_id = DSS_INVALID_ID32;
    
    dss_dhb_ctx_t *ctx = &g_dhb_ctx;
    if (!ctx->is_inited) {
        LOG_RUN_WAR("[DHB] get_lock_owner: not initialized");
        return CM_ERROR;
    }
    
    return dhb_get_lock_owner_internal(master_id);
}

status_t dss_dhb_try_lock(bool32 *got_lock)
{
    if (got_lock == NULL) {
        return CM_ERROR;
    }
    
    *got_lock = CM_FALSE;
    
    dss_dhb_ctx_t *ctx = &g_dhb_ctx;
    if (!ctx->is_inited || ctx->lock_id == CM_INVALID_LOCK_ID) {
        LOG_RUN_ERR("[DHB] try_lock: not initialized");
        return CM_ERROR;
    }
    
    /* Check current lock owner */
    uint32 current_owner = DSS_INVALID_ID32;
    (void)dhb_get_lock_owner_internal(&current_owner);
    
    /* If we already hold the lock, just renew lease */
    if (current_owner == ctx->inst_id) {
        int ret = cm_dl_lock(ctx->lock_id, 0);
        if (ret == CM_SUCCESS) {
            *got_lock = CM_TRUE;
            LOG_DEBUG_INF("[DHB] Renewed lock lease: inst_id=%u", ctx->inst_id);
            return CM_SUCCESS;
        }
        LOG_RUN_WAR("[DHB] Failed to renew lock: ret=%d", ret);
    }
    
    /* If there's another valid owner, check if they're online */
    if (current_owner != DSS_INVALID_ID32 && current_owner != ctx->inst_id) {
        bool32 owner_online = dss_dhb_is_online(current_owner);
        if (owner_online) {
            /* Owner is online - use short timeout (non-blocking) for switch scenarios */
            /* The old master should release lock soon if this is a planned switch */
            LOG_DEBUG_INF("[DHB] Lock held by online inst %u, trying quick acquire", current_owner);
            int ret = cm_dl_lock(ctx->lock_id, 100);  /* 100ms short timeout */
            if (ret == CM_SUCCESS) {
                *got_lock = CM_TRUE;
                ctx->current_master = ctx->inst_id;
                LOG_RUN_INF("[DHB] Acquired leader lock from online inst %u", current_owner);
            }
            return CM_SUCCESS;
        }
        /* Owner is offline, we can try to take the lock with longer timeout */
        LOG_RUN_INF("[DHB] Lock owner %u is offline, attempting takeover", current_owner);
    }
    
    /* Try to acquire the lock - use shorter timeout for responsiveness */
    /* If owner is offline, lock should be available after lease expires */
    int timeout_ms = (current_owner == DSS_INVALID_ID32) ? 100 : 1000;
    int ret = cm_dl_lock(ctx->lock_id, timeout_ms);
    
    if (ret == CM_SUCCESS) {
        *got_lock = CM_TRUE;
        ctx->current_master = ctx->inst_id;
        LOG_RUN_INF("[DHB] Acquired leader lock: inst_id=%u", ctx->inst_id);
    } else if (ret == CM_DL_ERR_OCCUPIED) {
        (void)dhb_get_lock_owner_internal(&current_owner);
        LOG_DEBUG_INF("[DHB] Lock already held by inst %u", current_owner);
    } else if (ret == CM_DL_ERR_TIMEOUT) {
        LOG_DEBUG_INF("[DHB] Lock acquire timeout (waited %dms)", timeout_ms);
    } else {
        LOG_RUN_WAR("[DHB] Lock acquire failed: ret=%d", ret);
    }
    
    return CM_SUCCESS;
}

status_t dss_dhb_unlock(void)
{
    dss_dhb_ctx_t *ctx = &g_dhb_ctx;
    
    if (!ctx->is_inited || ctx->lock_id == CM_INVALID_LOCK_ID) {
        return CM_SUCCESS;
    }
    
    /* Verify we are the current owner before unlocking */
    uint32 current_owner = DSS_INVALID_ID32;
    (void)dhb_get_lock_owner_internal(&current_owner);
    
    if (current_owner != ctx->inst_id) {
        LOG_RUN_WAR("[DHB] Not lock owner (owner=%u, self=%u), cannot unlock", 
            current_owner, ctx->inst_id);
        return CM_ERROR;
    }
    
    int ret = cm_dl_unlock(ctx->lock_id);
    if (ret == CM_SUCCESS) {
        ctx->current_master = DSS_INVALID_ID32;
        LOG_RUN_INF("[DHB] Released leader lock: inst_id=%u", ctx->inst_id);
        return CM_SUCCESS;
    }
    
    LOG_RUN_ERR("[DHB] Failed to unlock: ret=%d", ret);
    return CM_ERROR;
}

/*
 * Lock block structure (must match cm_disklock.c dl_stat_t)
 * Each instance has a 512-byte block at offset + 512 * (inst_id + 1)
 */
#define DHB_LOCK_BLOCK_SIZE     512
#define DHB_LOCK_MAGIC          0xFEDCBA9801234567ULL
#define DHB_LOCK_PROC_VER       1
#define DHB_LOCK_STATUS_NONE    0
#define DHB_LOCK_STATUS_PRE     1
#define DHB_LOCK_STATUS_LOCKED  2

typedef struct {
    uint64 magic;
    uint64 proc_ver;
    uint64 inst_id;
    uint64 locked;
    uint64 lock_time;
    uint64 unlock_time;
    char   reserved[DHB_LOCK_BLOCK_SIZE - 48];
} dhb_lock_block_t;

status_t dss_dhb_trans_lock(uint32 target_inst_id)
{
    dss_dhb_ctx_t *ctx = &g_dhb_ctx;
    
    if (!ctx->is_inited) {
        return CM_ERROR;
    }
    
    /* Verify we are the current owner */
    uint32 current_owner = DSS_INVALID_ID32;
    (void)dhb_get_lock_owner_internal(&current_owner);
    
    if (current_owner != ctx->inst_id) {
        LOG_RUN_ERR("[DHB] Not lock owner (owner=%u, self=%u), cannot transfer", 
            current_owner, ctx->inst_id);
        return CM_ERROR;
    }
    
    /* Check target is online */
    if (!dss_dhb_is_online(target_inst_id)) {
        LOG_RUN_ERR("[DHB] Target inst %u is not online, cannot transfer", target_inst_id);
        return CM_ERROR;
    }
    
    LOG_RUN_INF("[DHB] Atomic lock transfer: %u -> %u", ctx->inst_id, target_inst_id);
    
    /*
     * Atomic transfer strategy:
     * 1. Write target's lock block with LOCKED status (as if target acquired it)
     * 2. Clear our own lock block
     * Target node only needs to renew the lock, no acquisition needed.
     */
    
    /* Step 1: Write target's lock block directly */
    dhb_lock_block_t target_block;
    (void)memset_s(&target_block, sizeof(target_block), 0, sizeof(target_block));
    target_block.magic = DHB_LOCK_MAGIC;
    target_block.proc_ver = DHB_LOCK_PROC_VER;
    target_block.inst_id = target_inst_id;
    target_block.locked = DHB_LOCK_STATUS_LOCKED;
    target_block.lock_time = dhb_monotonic_ns();  /* Use local monotonic time */
    target_block.unlock_time = 0;
    
    off_t target_offset = (off_t)(DSS_DHB_LOCK_OFFSET + DHB_LOCK_BLOCK_SIZE * (target_inst_id + 1));
    ssize_t written = pwrite(ctx->fd, &target_block, DHB_LOCK_BLOCK_SIZE, target_offset);
    if (written != DHB_LOCK_BLOCK_SIZE) {
        LOG_RUN_ERR("[DHB] Failed to write target lock block: written=%zd, errno=%d", written, errno);
        return CM_ERROR;
    }
    
    LOG_RUN_INF("[DHB] Wrote lock for target %u at offset 0x%llx", 
        target_inst_id, (unsigned long long)target_offset);
    
    /* Step 2: Clear our own lock block */
    dhb_lock_block_t self_block;
    (void)memset_s(&self_block, sizeof(self_block), 0, sizeof(self_block));
    self_block.magic = DHB_LOCK_MAGIC;
    self_block.proc_ver = DHB_LOCK_PROC_VER;
    self_block.inst_id = ctx->inst_id;
    self_block.locked = DHB_LOCK_STATUS_NONE;
    self_block.lock_time = 0;
    self_block.unlock_time = dhb_monotonic_ns();
    
    off_t self_offset = (off_t)(DSS_DHB_LOCK_OFFSET + DHB_LOCK_BLOCK_SIZE * (ctx->inst_id + 1));
    written = pwrite(ctx->fd, &self_block, DHB_LOCK_BLOCK_SIZE, self_offset);
    if (written != DHB_LOCK_BLOCK_SIZE) {
        LOG_RUN_ERR("[DHB] Failed to clear self lock block: written=%zd, errno=%d", written, errno);
        /* Target already has lock, this is not fatal */
    }
    
    /* Also notify cm_disklock that we released (for internal state consistency) */
    (void)cm_dl_unlock(ctx->lock_id);
    
    /* Update local state */
    ctx->current_master = target_inst_id;
    LOG_RUN_INF("[DHB] Lock transferred atomically to inst %u", target_inst_id);
    
    return CM_SUCCESS;
}

/* ============================================================================
 * Public Interface - Status Query
 * ============================================================================ */

bool32 dss_dhb_is_online(uint32 inst_id)
{
    if (inst_id >= DSS_MAX_INSTANCES) {
        return CM_FALSE;
    }
    
    dss_dhb_ctx_t *ctx = &g_dhb_ctx;
    
    cm_spin_lock(&ctx->map_lock, NULL);
    bool32 is_online = (ctx->online_map & ((uint64)1 << inst_id)) != 0;
    cm_spin_unlock(&ctx->map_lock);
    
    return is_online;
}

bool32 dss_dhb_is_leader(void)
{
    dss_dhb_ctx_t *ctx = &g_dhb_ctx;
    
    if (!ctx->is_inited) {
        return CM_FALSE;
    }
    
    return (ctx->current_master == ctx->inst_id);
}

uint64 dss_dhb_get_online_map(void)
{
    dss_dhb_ctx_t *ctx = &g_dhb_ctx;
    
    cm_spin_lock(&ctx->map_lock, NULL);
    uint64 map = ctx->online_map;
    cm_spin_unlock(&ctx->map_lock);
    
    return map;
}

/* ============================================================================
 * Public Interface - Peer Management
 * ============================================================================ */

void dss_dhb_check_peer(void *inst)
{
    (void)inst;
    
    if (!g_dhb_ctx.is_inited) {
        return;
    }
    
    /* Force a fresh read of heartbeats */
    uint64 online_map = 0;
    (void)dhb_read_all_heartbeats(&online_map);
    
    cm_spin_lock(&g_dhb_ctx.map_lock, NULL);
    g_dhb_ctx.online_map = online_map;
    cm_spin_unlock(&g_dhb_ctx.map_lock);
    
    /* 
     * Note: Caller should update MES connections using:
     *   dss_check_mes_conn(dss_dhb_get_online_map());
     * (dss_check_mes_conn internally updates work_status)
     */
}

bool32 dss_dhb_check_failed_insts(uint64 failed_insts)
{
    if (!g_dhb_ctx.is_inited) {
        return CM_FALSE;
    }
    
    uint64 online_map = dss_dhb_get_online_map();
    uint64 online_failures = failed_insts & online_map;
    
    if (online_failures != 0) {
        LOG_DEBUG_INF("[DHB] Some failed insts are online: failed=0x%llx, online=0x%llx",
            (unsigned long long)failed_insts,
            (unsigned long long)online_map);
    }
    
    return (online_failures != 0);
}

void dss_dhb_set_inst_count(uint32 inst_cnt)
{
    if (inst_cnt > 0 && inst_cnt <= DSS_MAX_INSTANCES) {
        g_dhb_ctx.inst_cnt = inst_cnt;
        LOG_RUN_INF("[DHB] Instance count set to %u", inst_cnt);
    }
}
