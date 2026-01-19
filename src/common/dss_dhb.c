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
#include <stdlib.h>  /* for posix_memalign, free */
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
    uint32 timeout_count;       /* Consecutive timeout count for jitter tolerance */
} dhb_local_tracker_t;

/* Consecutive timeout threshold before marking node offline */
#define DHB_OFFLINE_THRESHOLD 3

/* Alignment for O_DIRECT I/O (must be multiple of 512) */
#define DHB_IO_ALIGN 512

typedef struct st_dss_dhb_ctx {
    /* Initialization state */
    bool32 is_inited;
    uint32 inst_id;
    uint32 inst_cnt;
    char volume_path[DSS_MAX_PATH_BUFFER_SIZE];
    
    /* 
     * Dedicated file descriptors for DHB I/O (separate from DSS main I/O)
     * - fd_write: O_SYNC for write persistence
     * - fd_read:  O_DIRECT to bypass cache and read fresh data from other nodes
     */
    int32 fd_write;
    int32 fd_read;
    
    /* Aligned buffers for O_DIRECT I/O */
    char *write_buf;    /* Aligned buffer for heartbeat write */
    char *read_buf;     /* Aligned buffer for heartbeat read */
    
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
    uint32 master_lost_count;  /* Jitter tolerance: consecutive times master read as invalid */
    
    /* Lock transfer state - prevents DHB thread from grabbing lock during transfer */
    volatile bool32 lock_transfer_in_progress;
    uint32 lock_transfer_target;
    uint64 lock_transfer_start_ns;
    
    /* Failover detection - wait for lease expiry before grabbing lock */
    uint64 failover_detected_ns;  /* When we first detected master heartbeat died */
    
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
    
    if (ctx->fd_write <= 0 || ctx->write_buf == NULL) {
        return CM_ERROR;
    }
    
    /* Prepare heartbeat data in aligned buffer */
    dss_dhb_heartbeat_t *hb = (dss_dhb_heartbeat_t *)ctx->write_buf;
    errno_t err = memset_s(hb, DSS_DHB_BLOCK_SIZE, 0, DSS_DHB_BLOCK_SIZE);
    if (err != EOK) {
        return CM_ERROR;
    }
    
    hb->magic = DSS_DHB_MAGIC;
    hb->inst_id = ctx->inst_id;
    hb->status = DSS_DHB_NODE_ONLINE;
    hb->timestamp_ns = dhb_now_ns();
    hb->sequence = ++ctx->sequence;
    
    /* Write to disk using dedicated write fd (O_SYNC) */
    int64 offset = DSS_CTRL_DHB_HEARTBEAT_OFFSET + (int64)ctx->inst_id * DSS_DHB_BLOCK_SIZE;
    ssize_t written = pwrite(ctx->fd_write, hb, DSS_DHB_BLOCK_SIZE, offset);
    
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
    
    if (ctx->fd_read <= 0 || ctx->read_buf == NULL || new_online_map == NULL) {
        return CM_ERROR;
    }
    
    /* Read all heartbeat blocks using dedicated read fd (O_DIRECT bypasses cache) */
    ssize_t read_size = pread(ctx->fd_read, ctx->read_buf, DSS_DHB_AREA_SIZE, DSS_CTRL_DHB_HEARTBEAT_OFFSET);
    
    if (read_size != DSS_DHB_AREA_SIZE) {
        LOG_DEBUG_WAR("[DHB] Read heartbeats failed: read=%zd, errno=%d", read_size, errno);
        return CM_ERROR;
    }
    
    /* Use LOCAL monotonic time for timeout calculation */
    uint64 now_mono_ns = dhb_monotonic_ns();
    uint64 timeout_ns = (uint64)DSS_DHB_HEARTBEAT_TIMEOUT_MS * 1000000ULL;
    *new_online_map = 0;
    
    /* Process each node's heartbeat using SEQUENCE NUMBER change detection */
    /* Always iterate all possible instances, invalid ones are skipped by magic check */
    for (uint32 i = 0; i < DSS_MAX_INSTANCES; i++) {
        dss_dhb_heartbeat_t *hb = (dss_dhb_heartbeat_t *)(ctx->read_buf + i * DSS_DHB_BLOCK_SIZE);
        dhb_local_tracker_t *tracker = &ctx->local_tracker[i];
        
        /* Validate magic number */
        if (hb->magic != DSS_DHB_MAGIC || hb->inst_id != i) {
            tracker->timeout_count = 0;  /* Reset for invalid entries */
            continue;
        }
        
        /* Save heartbeat data */
        ctx->nodes[i] = *hb;
        
        /* Skip if node status is offline */
        if (hb->status != DSS_DHB_NODE_ONLINE) {
            tracker->timeout_count = 0;
            continue;
        }
        
        /* 
         * Detect sequence number CHANGE, not timestamp comparison!
         * This works correctly even if clocks are not synchronized.
         */
        if (hb->sequence != tracker->last_sequence) {
            /* Sequence changed - node is alive, reset timeout counter */
            tracker->last_sequence = hb->sequence;
            tracker->last_change_ns = now_mono_ns;
            tracker->timeout_count = 0;
            *new_online_map |= ((uint64)1 << i);
        } else if (tracker->last_change_ns == 0) {
            /* First time seeing this node */
            tracker->last_sequence = hb->sequence;
            tracker->last_change_ns = now_mono_ns;
            tracker->timeout_count = 0;
            *new_online_map |= ((uint64)1 << i);
        } else {
            /* Sequence unchanged - check if timeout exceeded */
            uint64 elapsed_ns = now_mono_ns - tracker->last_change_ns;
            if (elapsed_ns < timeout_ns) {
                *new_online_map |= ((uint64)1 << i);
            } else {
                /* Timeout exceeded - use threshold to avoid jitter */
                tracker->timeout_count++;
                if (tracker->timeout_count < DHB_OFFLINE_THRESHOLD) {
                    /* Not yet reached threshold, still consider online */
                    *new_online_map |= ((uint64)1 << i);
                    LOG_DEBUG_INF("[DHB] Node %u timeout count %u/%u", 
                        i, tracker->timeout_count, DHB_OFFLINE_THRESHOLD);
                }
                /* else: threshold reached, node is offline */
            }
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
            
            /* Step 3: Check current master status with jitter tolerance
             * 
             * During lock renewal, cm_dl_lock writes LS_PRE_LOCK first, then LS_LOCKED.
             * If we read during this window, cm_dl_getowner returns INVALID_ID.
             * Use jitter tolerance to avoid false master-lost detection.
             */
            uint32 lock_owner = DSS_INVALID_ID32;
            (void)dhb_get_lock_owner_internal(&lock_owner);
            
            /* Handle jitter tolerance for master status */
            if (lock_owner == DSS_INVALID_ID32 && ctx->current_master != DSS_INVALID_ID32) {
                /* Master read as invalid, but we had a valid master before */
                /* This might be due to renewal window - apply jitter tolerance */
                ctx->master_lost_count++;
                
                if (ctx->master_lost_count < DHB_OFFLINE_THRESHOLD) {
                    /* Not enough consecutive failures, keep current master */
                    LOG_DEBUG_INF("[DHB] Master %u read as invalid, jitter count %u/%u",
                        ctx->current_master, ctx->master_lost_count, DHB_OFFLINE_THRESHOLD);
                    lock_owner = ctx->current_master;  /* Keep old value */
                } else {
                    /* Threshold reached, master is really gone */
                    LOG_RUN_INF("[DHB] Master %u confirmed lost after %u consecutive invalid reads",
                        ctx->current_master, ctx->master_lost_count);
                    ctx->master_lost_count = 0;
                }
            } else if (lock_owner != DSS_INVALID_ID32) {
                /* Valid owner read, reset jitter counter */
                if (ctx->master_lost_count > 0) {
                    LOG_DEBUG_INF("[DHB] Master %u recovered, resetting jitter count", lock_owner);
                }
                ctx->master_lost_count = 0;
            }
            
            /* Update current_master only when truly changed */
            if (lock_owner != ctx->current_master) {
                LOG_RUN_INF("[DHB] Master changed: %u -> %u", ctx->current_master, lock_owner);
                ctx->current_master = lock_owner;
                
                /* Clear lock transfer flag if someone acquired the lock */
                if (ctx->lock_transfer_in_progress && lock_owner != DSS_INVALID_ID32) {
                    LOG_RUN_INF("[DHB] Lock transfer completed, new master=%u", lock_owner);
                    ctx->lock_transfer_in_progress = CM_FALSE;
                }
            }
            
            /* Step 4: Try to grab lock ONLY if:
             * - There's a known master whose heartbeat died (failover)
             * - OR there's no master at all (initial startup)
             * NEVER grab lock if current master is still online!
             */
            if (lock_owner != DSS_INVALID_ID32 && lock_owner != ctx->inst_id) {
                /* There's a master, check if their heartbeat is still alive */
                bool32 master_online = (new_online_map & ((uint64)1 << lock_owner)) != 0;
                
                if (master_online) {
                    /* Master is alive - DO NOT attempt to grab lock */
                    LOG_DEBUG_INF("[DHB] Master %u is online, not attempting failover", lock_owner);
                    /* Reset failover tracking when master comes back online */
                    ctx->failover_detected_ns = 0;
                } else {
                    /* 
                     * Master heartbeat died - attempt to grab lock.
                     * 
                     * SAFETY NOTE: We rely on cm_disklock lease mechanism for safety.
                     * cm_dl_lock will block until the lease expires, ensuring the original
                     * master has truly stopped writing. No additional wait needed here.
                     * 
                     * Timeline:
                     * - Master stops at T=0 (stops heartbeat + stops renewing lease)
                     * - Lease expires at T=LEASE_TIMEOUT (e.g., T=5s)
                     * - Heartbeat timeout detected at T=HEARTBEAT_TIMEOUT (e.g., T=5s)
                     * - At this point, lease is already expired, cm_dl_lock can succeed
                     * 
                     * Since HEARTBEAT_TIMEOUT >= LEASE_TIMEOUT, by the time we detect
                     * heartbeat timeout, the lease should already be expired or about to.
                     */
                    if (ctx->failover_detected_ns == 0) {
                        /* First detection - log and attempt immediately */
                        ctx->failover_detected_ns = dhb_monotonic_ns();
                        LOG_RUN_WAR("[DHB] Master %u heartbeat died, attempting failover (lease should be expired)", 
                            lock_owner);
                    }
                    
                    /* Try to acquire lock - cm_disklock will handle lease safety */
                    bool32 got_lock = CM_FALSE;
                    (void)dhb_try_acquire_lock(&got_lock);
                    
                    if (got_lock) {
                        ctx->current_master = ctx->inst_id;
                        ctx->failover_detected_ns = 0;  /* Reset for next time */
                        LOG_RUN_INF("[DHB] Became new master after %u failed", lock_owner);
                    } else {
                        uint64 elapsed_ns = dhb_monotonic_ns() - ctx->failover_detected_ns;
                        LOG_DEBUG_INF("[DHB] Failover attempt for master %u, elapsed %llu ms, waiting...",
                            lock_owner, (unsigned long long)(elapsed_ns / 1000000ULL));
                    }
                }
            } else if (lock_owner == DSS_INVALID_ID32) {
                /* No master exists - check if this is due to lock transfer */
                if (ctx->lock_transfer_in_progress) {
                    /* Lock transfer in progress - check for timeout or completion */
                    uint64 elapsed_ns = dhb_monotonic_ns() - ctx->lock_transfer_start_ns;
                    uint64 timeout_ns = 10ULL * 1000000000ULL;  /* 10 seconds timeout */
                    
                    if (elapsed_ns > timeout_ns) {
                        LOG_RUN_WAR("[DHB] Lock transfer timeout, clearing flag");
                        ctx->lock_transfer_in_progress = CM_FALSE;
                    } else {
                        LOG_DEBUG_INF("[DHB] Lock transfer in progress, not grabbing lock");
                    }
                } else {
                    /* Initial cluster startup - try to become master */
                    LOG_RUN_INF_INHIBIT(LOG_INHIBIT_LEVEL4, 
                        "[DHB] No master detected, attempting to become master");
                    
                    bool32 got_lock = CM_FALSE;
                    (void)dhb_try_acquire_lock(&got_lock);
                    
                    if (got_lock) {
                        ctx->current_master = ctx->inst_id;
                        LOG_RUN_INF("[DHB] Became master (initial election)");
                    }
                }
            } else if (lock_owner == ctx->inst_id) {
                /* We are the master, renew lease */
                /* Use 1 second timeout to handle IO latency */
                int ret = cm_dl_lock(ctx->lock_id, 1000);
                if (ret != CM_SUCCESS) {
                    LOG_RUN_WAR("[DHB] Failed to renew lock lease: ret=%d", ret);
                } else {
                    LOG_DEBUG_INF("[DHB] Lock lease renewed successfully");
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

/* Helper: allocate aligned memory for O_DIRECT I/O */
static char *dhb_alloc_aligned(size_t size, size_t align)
{
    void *ptr = NULL;
    if (posix_memalign(&ptr, align, size) != 0) {
        return NULL;
    }
    return (char *)ptr;
}

/* Helper: cleanup resources on init failure */
static void dhb_cleanup_resources(dss_dhb_ctx_t *ctx)
{
    if (ctx->write_buf != NULL) {
        free(ctx->write_buf);
        ctx->write_buf = NULL;
    }
    if (ctx->read_buf != NULL) {
        free(ctx->read_buf);
        ctx->read_buf = NULL;
    }
    if (ctx->lock_id != CM_INVALID_LOCK_ID) {
        (void)cm_dl_dealloc(ctx->lock_id);
        ctx->lock_id = CM_INVALID_LOCK_ID;
    }
    if (ctx->fd_write > 0) {
        close(ctx->fd_write);
        ctx->fd_write = -1;
    }
    if (ctx->fd_read > 0) {
        close(ctx->fd_read);
        ctx->fd_read = -1;
    }
}

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
    LOG_RUN_INF("[DHB] Layout: LOCK @ 0x%llx (8K), Heartbeat @ 0x%llx (using dss_ctrl_t offsets)", 
        (unsigned long long)DSS_CTRL_DHB_LOCK_OFFSET, 
        (unsigned long long)DSS_CTRL_DHB_HEARTBEAT_OFFSET);
    
    /* Clear context */
    errno_t err = memset_s(ctx, sizeof(dss_dhb_ctx_t), 0, sizeof(dss_dhb_ctx_t));
    if (err != EOK) {
        LOG_RUN_ERR("[DHB] memset failed");
        return CM_ERROR;
    }
    
    ctx->inst_id = inst_id;
    ctx->inst_cnt = DSS_MAX_INSTANCES;
    ctx->lock_id = CM_INVALID_LOCK_ID;
    ctx->fd_write = -1;
    ctx->fd_read = -1;
    ctx->write_buf = NULL;
    ctx->read_buf = NULL;
    ctx->map_lock = 0;
    ctx->current_master = DSS_INVALID_ID32;
    ctx->master_lost_count = 0;
    ctx->lock_transfer_in_progress = CM_FALSE;
    ctx->lock_transfer_target = DSS_INVALID_ID32;
    ctx->lock_transfer_start_ns = 0;
    ctx->failover_detected_ns = 0;
    
    err = strcpy_s(ctx->volume_path, sizeof(ctx->volume_path), volume_path);
    if (err != EOK) {
        LOG_RUN_ERR("[DHB] Failed to copy volume path");
        return CM_ERROR;
    }
    
    /* 
     * Allocate aligned buffers for O_DIRECT I/O 
     * - write_buf: single heartbeat block (512B)
     * - read_buf:  all heartbeat blocks (32KB)
     */
    ctx->write_buf = dhb_alloc_aligned(DSS_DHB_BLOCK_SIZE, DHB_IO_ALIGN);
    if (ctx->write_buf == NULL) {
        LOG_RUN_ERR("[DHB] Failed to allocate write buffer");
        return CM_ERROR;
    }
    
    ctx->read_buf = dhb_alloc_aligned(DSS_DHB_AREA_SIZE, DHB_IO_ALIGN);
    if (ctx->read_buf == NULL) {
        LOG_RUN_ERR("[DHB] Failed to allocate read buffer");
        dhb_cleanup_resources(ctx);
        return CM_ERROR;
    }
    
    LOG_RUN_INF("[DHB] Allocated aligned buffers: write=%p, read=%p", 
        ctx->write_buf, ctx->read_buf);
    
    /* 
     * Open dedicated file descriptors for DHB I/O:
     * - fd_write: O_SYNC ensures write persistence
     * - fd_read:  O_DIRECT bypasses page cache, reads fresh data from disk
     * 
     * This separation ensures that:
     * 1. Our writes are persisted (O_SYNC)
     * 2. Our reads see other nodes' latest writes (O_DIRECT bypasses cache)
     */
    ctx->fd_write = open(volume_path, O_RDWR | O_SYNC);
    if (ctx->fd_write <= 0) {
        LOG_RUN_ERR("[DHB] Failed to open write fd: %s, errno=%d", volume_path, errno);
        dhb_cleanup_resources(ctx);
        return CM_ERROR;
    }
    
    ctx->fd_read = open(volume_path, O_RDONLY | O_DIRECT);
    if (ctx->fd_read <= 0) {
        LOG_RUN_WAR("[DHB] O_DIRECT not supported, falling back to O_SYNC for read");
        ctx->fd_read = open(volume_path, O_RDONLY | O_SYNC);
        if (ctx->fd_read <= 0) {
            LOG_RUN_ERR("[DHB] Failed to open read fd: %s, errno=%d", volume_path, errno);
            dhb_cleanup_resources(ctx);
            return CM_ERROR;
        }
    }
    
    LOG_RUN_INF("[DHB] Dedicated fds opened: fd_write=%d, fd_read=%d", 
        ctx->fd_write, ctx->fd_read);
    
    /* Allocate disk lock using structure offset */
    uint32 lease_sec = DSS_DHB_LEASE_TIMEOUT_MS / 1000;
    if (lease_sec < 1) {
        lease_sec = 1;
    }
    
    LOG_RUN_INF("[DHB] Allocating disk lock: offset=0x%llx, inst_id=%u, lease=%u sec",
        (unsigned long long)DSS_CTRL_DHB_LOCK_OFFSET, inst_id, lease_sec);
    
    ctx->lock_id = cm_dl_alloc_lease(volume_path, DSS_CTRL_DHB_LOCK_OFFSET, 
        (unsigned long long)inst_id, lease_sec);
    if (ctx->lock_id == CM_INVALID_LOCK_ID) {
        LOG_RUN_ERR("[DHB] Failed to alloc disk lock");
        dhb_cleanup_resources(ctx);
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
        dhb_cleanup_resources(ctx);
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
    
    /* Close dedicated file descriptors */
    if (ctx->fd_write > 0) {
        close(ctx->fd_write);
        ctx->fd_write = -1;
    }
    if (ctx->fd_read > 0) {
        close(ctx->fd_read);
        ctx->fd_read = -1;
    }
    
    /* Free aligned buffers */
    if (ctx->write_buf != NULL) {
        free(ctx->write_buf);
        ctx->write_buf = NULL;
    }
    if (ctx->read_buf != NULL) {
        free(ctx->read_buf);
        ctx->read_buf = NULL;
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
        /* Use 1 second timeout for renewal to handle IO latency */
        int ret = cm_dl_lock(ctx->lock_id, 1000);
        if (ret == CM_SUCCESS) {
            *got_lock = CM_TRUE;
            LOG_DEBUG_INF("[DHB] Renewed lock lease: inst_id=%u", ctx->inst_id);
        } else {
            LOG_RUN_WAR("[DHB] Failed to renew lock: ret=%d", ret);
        }
        /* Always return here - we either renewed or failed, don't try to grab again */
        return CM_SUCCESS;
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
        /* Owner is offline - wait for lease expiry with adequate timeout */
        LOG_RUN_INF("[DHB] Lock owner %u is offline, waiting for lease expiry", current_owner);
    }
    
    /* 
     * Try to acquire the lock:
     * - If no owner: short timeout (lock should be free)
     * - If owner offline: wait for lease to expire (LEASE_TIMEOUT + buffer)
     * 
     * cm_disklock guarantees that the lock cannot be acquired until the
     * current owner's lease expires. This is the safety boundary.
     */
    int timeout_ms;
    if (current_owner == DSS_INVALID_ID32) {
        timeout_ms = 100;  /* No owner, should be quick */
    } else {
        /* Owner offline - need to wait for lease expiry */
        /* Add 1 second buffer for clock drift and I/O latency */
        timeout_ms = DSS_DHB_LEASE_TIMEOUT_MS + 1000;
    }
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
    
    LOG_RUN_INF("[DHB] Lock transfer: %u -> %u", ctx->inst_id, target_inst_id);
    
    /*
     * Safe transfer strategy using cm_disklock API:
     * 1. Set transfer flag to prevent DHB thread from grabbing lock
     * 2. Release our lock via cm_dl_unlock
     * 3. Target will acquire lock when it receives the MES response
     * 4. Transfer flag will be cleared when new master is detected
     * 
     * Note: The caller (dss_process_switch_lock_inner) has already:
     * - Paused all sessions
     * - Set status to READONLY
     * - Paused background tasks
     * This ensures data safety before lock transfer.
     */
    
    /* Set transfer flag to prevent DHB thread from grabbing lock back */
    ctx->lock_transfer_target = target_inst_id;
    ctx->lock_transfer_start_ns = dhb_monotonic_ns();
    ctx->lock_transfer_in_progress = CM_TRUE;
    
    /* Release our lock */
    int ret = cm_dl_unlock(ctx->lock_id);
    if (ret != CM_SUCCESS) {
        LOG_RUN_ERR("[DHB] Failed to release lock for transfer: ret=%d", ret);
        ctx->lock_transfer_in_progress = CM_FALSE;
        return CM_ERROR;
    }
    
    /* Update local state */
    ctx->current_master = DSS_INVALID_ID32;
    LOG_RUN_INF("[DHB] Lock released for transfer to inst %u", target_inst_id);
    
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
