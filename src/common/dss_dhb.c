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
 * dss_dhb.c
 *
 * Disk-based HeartBeat (DHB) mechanism implementation.
 *
 * IDENTIFICATION
 *    src/common/dss_dhb.c
 *
 * -------------------------------------------------------------------------
 */

#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <stddef.h>
#include <stdlib.h>
#include "securec.h"
#include "cm_log.h"
#include "cm_thread.h"
#include "cm_timer.h"
#include "cm_spinlock.h"
#include "cm_defs.h"
#include "dss_dhb.h"
#include "dss_errno.h"

#define NANOSECS_PER_SECOND_LL 1000000000LL

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Weak symbols for non-server builds
 * ============================================================================ */

__attribute__((weak)) void dss_set_inst_work_status(uint64 cur_inst_map) 
{ 
    (void)cur_inst_map;
}

__attribute__((weak)) void dss_check_mes_conn(uint64 cur_inst_map) 
{ 
    (void)cur_inst_map;
}

/* ============================================================================
 * Module state
 * ============================================================================ */

dss_dhb_ctx_t g_dss_dhb_ctx = {0};

static thread_t g_dhb_thread;
static volatile bool32 g_dhb_running = CM_FALSE;
static spinlock_t g_dhb_lock = 0;

/* ============================================================================
 * Internal utilities
 * ============================================================================ */

static inline uint64 dss_dhb_now_ns(void)
{
    struct timespec tv;
    (void)clock_gettime(CLOCK_REALTIME, &tv);
    return (uint64)tv.tv_sec * NANOSECS_PER_SECOND_LL + (uint64)tv.tv_nsec;
}

static uint32 dss_dhb_calc_checksum(const dss_dhb_node_t *hb)
{
    const uint8 *data = (const uint8 *)hb;
    uint32 sum = 0;
    for (size_t i = 0; i < offsetof(dss_dhb_node_t, checksum); i++) {
        sum += data[i];
    }
    return sum;
}

static bool32 dss_dhb_verify(const dss_dhb_node_t *hb)
{
    if (hb->magic != DSS_DHB_MAGIC) {
        return CM_FALSE;
    }
    return hb->checksum == dss_dhb_calc_checksum(hb);
}

/* ============================================================================
 * Internal heartbeat operations
 * ============================================================================ */

static status_t dss_dhb_write(void)
{
    dss_dhb_ctx_t *ctx = &g_dss_dhb_ctx;
    
    if (ctx->fd <= 0) {
        LOG_DEBUG_ERR("[DHB] Not initialized");
        return CM_ERROR;
    }

    dss_dhb_node_t *hb = NULL;
    if (posix_memalign((void **)&hb, DSS_DHB_BLOCK_SIZE, DSS_DHB_BLOCK_SIZE) != 0) {
        LOG_RUN_ERR("[DHB] Failed to allocate aligned buffer");
        return CM_ERROR;
    }

    (void)memset_s(hb, DSS_DHB_BLOCK_SIZE, 0, DSS_DHB_BLOCK_SIZE);
    
    hb->magic = DSS_DHB_MAGIC;
    hb->inst_id = ctx->inst_id;
    hb->hb_time = dss_dhb_now_ns();
    hb->sequence = ++ctx->sequence;
    hb->status = DSS_DHB_ONLINE;
    hb->checksum = dss_dhb_calc_checksum(hb);

    off_t offset = (off_t)(ctx->hb_offset + ctx->inst_id * DSS_DHB_BLOCK_SIZE);

    ssize_t written = pwrite(ctx->fd, hb, DSS_DHB_BLOCK_SIZE, offset);
    if (written != DSS_DHB_BLOCK_SIZE) {
        LOG_RUN_ERR("[DHB] Write failed: written=%zd, errno=%d", written, errno);
        free(hb);
        return CM_ERROR;
    }

    ctx->last_hb_time = hb->hb_time;
    LOG_DEBUG_INF("[DHB] Written: inst=%u, seq=%llu", ctx->inst_id, ctx->sequence);

    free(hb);
    return CM_SUCCESS;
}

static status_t dss_dhb_read_all(void)
{
    dss_dhb_ctx_t *ctx = &g_dss_dhb_ctx;
    
    if (ctx->fd <= 0) {
        LOG_DEBUG_ERR("[DHB] Not initialized");
        return CM_ERROR;
    }

    size_t buf_size = DSS_DHB_BLOCK_SIZE * DSS_MAX_INSTANCES;
    void *buf = NULL;
    if (posix_memalign(&buf, DSS_DHB_BLOCK_SIZE, buf_size) != 0) {
        LOG_RUN_ERR("[DHB] Failed to allocate read buffer");
        return CM_ERROR;
    }

    off_t offset = (off_t)ctx->hb_offset;
    ssize_t read_size = pread(ctx->fd, buf, buf_size, offset);
    if (read_size != (ssize_t)buf_size) {
        LOG_RUN_ERR("[DHB] Read failed: read=%zd, expected=%zu, errno=%d", read_size, buf_size, errno);
        free(buf);
        return CM_ERROR;
    }

    uint64 now = dss_dhb_now_ns();
    uint64 timeout_ns = (uint64)ctx->timeout_sec * NANOSECS_PER_SECOND_LL;
    uint64 new_online_map = 0;

    cm_spin_lock(&g_dhb_lock, NULL);

    for (uint32 i = 0; i < DSS_MAX_INSTANCES; i++) {
        dss_dhb_node_t *node_hb = (dss_dhb_node_t *)((char *)buf + i * DSS_DHB_BLOCK_SIZE);
        
        if (!dss_dhb_verify(node_hb)) {
            continue;
        }

        ctx->nodes[i] = *node_hb;

        if (node_hb->status == DSS_DHB_ONLINE) {
            uint64 elapsed = now - node_hb->hb_time;
            if (elapsed < timeout_ns) {
                new_online_map |= ((uint64)1 << i);
            } else {
                LOG_DEBUG_INF("[DHB] Node %u timeout: elapsed=%llu ns", i, elapsed);
            }
        }
    }

    new_online_map |= ((uint64)1 << ctx->inst_id);

    if (ctx->online_map != new_online_map) {
        LOG_RUN_INF("[DHB] Online map changed: 0x%llx -> 0x%llx", ctx->online_map, new_online_map);
    }
    ctx->online_map = new_online_map;

    cm_spin_unlock(&g_dhb_lock);

    free(buf);
    return CM_SUCCESS;
}

static status_t dss_dhb_try_leader(void)
{
    dss_dhb_ctx_t *ctx = &g_dss_dhb_ctx;
    
    if (ctx->lock_id == CM_INVALID_LOCK_ID) {
        LOG_DEBUG_WAR("[DHB] Leader lock not initialized");
        return CM_ERROR;
    }

    int ret = cm_dl_lock(ctx->lock_id, 0);
    if (ret == CM_SUCCESS) {
        ctx->is_leader = CM_TRUE;
        LOG_RUN_INF("[DHB] Became leader: inst_id=%u", ctx->inst_id);
        return CM_SUCCESS;
    } else if (ret == CM_DL_ERR_OCCUPIED) {
        ctx->is_leader = CM_FALSE;
        LOG_DEBUG_INF("[DHB] Leader lock occupied");
        return CM_ERROR;
    } else {
        LOG_RUN_ERR("[DHB] Leader lock failed: ret=%d", ret);
        return CM_ERROR;
    }
}

static status_t dss_dhb_release_leader(void)
{
    dss_dhb_ctx_t *ctx = &g_dss_dhb_ctx;
    
    if (ctx->lock_id == CM_INVALID_LOCK_ID) {
        return CM_SUCCESS;
    }

    int ret = cm_dl_unlock(ctx->lock_id);
    if (ret == CM_SUCCESS) {
        ctx->is_leader = CM_FALSE;
        LOG_RUN_INF("[DHB] Released leader: inst_id=%u", ctx->inst_id);
    }
    return (ret == CM_SUCCESS) ? CM_SUCCESS : CM_ERROR;
}

/* ============================================================================
 * Background thread
 * ============================================================================ */

static void dss_dhb_thread_entry(thread_t *thread)
{
    LOG_RUN_INF("[DHB] Thread started");
    
    dss_dhb_ctx_t *ctx = &g_dss_dhb_ctx;
    uint32 interval_ms = ctx->interval_sec * 1000;

    while (g_dhb_running) {
        if (dss_dhb_write() != CM_SUCCESS) {
            LOG_RUN_WAR("[DHB] Failed to write heartbeat");
        }

        if (dss_dhb_read_all() != CM_SUCCESS) {
            LOG_RUN_WAR("[DHB] Failed to read heartbeats");
        }

        if (ctx->is_leader && ctx->lock_id != CM_INVALID_LOCK_ID) {
            (void)cm_dl_lock(ctx->lock_id, 0);  /* Renew lease */
        }

        cm_sleep(interval_ms);
    }

    LOG_RUN_INF("[DHB] Thread stopped");
}

static status_t dss_dhb_start_thread(void)
{
    if (g_dhb_running) {
        LOG_RUN_WAR("[DHB] Thread already running");
        return CM_SUCCESS;
    }

    g_dhb_running = CM_TRUE;
    
    if (cm_create_thread(dss_dhb_thread_entry, 0, NULL, &g_dhb_thread) != CM_SUCCESS) {
        g_dhb_running = CM_FALSE;
        LOG_RUN_ERR("[DHB] Failed to create thread");
        return CM_ERROR;
    }

    LOG_RUN_INF("[DHB] Thread started");
    return CM_SUCCESS;
}

static void dss_dhb_stop_thread(void)
{
    if (!g_dhb_running) {
        return;
    }

    g_dhb_running = CM_FALSE;
    cm_close_thread(&g_dhb_thread);
    LOG_RUN_INF("[DHB] Thread stopped");
}

/* ============================================================================
 * Cluster management (public)
 * ============================================================================ */

status_t dss_dhb_cluster_init_with_path(const char *volume_path, uint32 inst_id)
{
    if (volume_path == NULL || strlen(volume_path) == 0) {
        LOG_RUN_ERR("[DHB] Invalid volume path");
        return CM_ERROR;
    }

    if (inst_id >= DSS_MAX_INSTANCES) {
        LOG_RUN_ERR("[DHB] Invalid instance ID: %u", inst_id);
        return CM_ERROR;
    }

    dss_dhb_ctx_t *ctx = &g_dss_dhb_ctx;
    
    errno_t err = strcpy_s(ctx->volume_path, DSS_MAX_VOLUME_PATH_LEN, volume_path);
    if (err != EOK) {
        LOG_RUN_ERR("[DHB] Failed to copy volume path");
        return CM_ERROR;
    }

    ctx->fd = open(volume_path, O_RDWR | O_DIRECT | O_SYNC);
    if (ctx->fd < 0) {
        LOG_RUN_ERR("[DHB] Failed to open volume %s: errno=%d", volume_path, errno);
        return CM_ERROR;
    }

    ctx->inst_id = inst_id;
    ctx->hb_offset = DSS_DHB_AREA_OFFSET;
    ctx->timeout_sec = DSS_DHB_TIMEOUT_SEC;
    ctx->interval_sec = DSS_DHB_INTERVAL_SEC;
    ctx->sequence = 0;
    ctx->is_leader = CM_FALSE;
    ctx->online_map = 0;
    ctx->lock_id = CM_INVALID_LOCK_ID;

    ctx->lock_id = cm_dl_alloc_lease(volume_path, DSS_DHB_LOCK_OFFSET, inst_id, DSS_DHB_LEASE_SEC);
    if (ctx->lock_id == CM_INVALID_LOCK_ID) {
        LOG_RUN_ERR("[DHB] Failed to allocate leader lock");
        close(ctx->fd);
        ctx->fd = 0;
        return CM_ERROR;
    }

    (void)memset_s(ctx->nodes, sizeof(ctx->nodes), 0, sizeof(ctx->nodes));

    status_t ret = dss_dhb_start_thread();
    if (ret != CM_SUCCESS) {
        LOG_RUN_ERR("[DHB] Failed to start thread");
        (void)cm_dl_dealloc(ctx->lock_id);
        close(ctx->fd);
        ctx->fd = 0;
        return ret;
    }

    (void)dss_dhb_write();
    (void)dss_dhb_read_all();

    ctx->is_inited = CM_TRUE;
    
    uint64 online_map = ctx->online_map;
    LOG_RUN_INF("[DHB] Initialized: volume=%s, inst_id=%u, online_map=0x%llx", 
        volume_path, inst_id, online_map);
    
    dss_set_inst_work_status(0);
    dss_check_mes_conn(online_map);
    
    return CM_SUCCESS;
}

void dss_dhb_cluster_uninit(void)
{
    dss_dhb_ctx_t *ctx = &g_dss_dhb_ctx;
    
    if (!ctx->is_inited) {
        return;
    }

    dss_dhb_stop_thread();

    if (ctx->lock_id != CM_INVALID_LOCK_ID) {
        (void)cm_dl_unlock(ctx->lock_id);
        (void)cm_dl_dealloc(ctx->lock_id);
        ctx->lock_id = CM_INVALID_LOCK_ID;
    }

    if (ctx->fd > 0) {
        close(ctx->fd);
        ctx->fd = 0;
    }

    ctx->is_inited = CM_FALSE;
    LOG_RUN_INF("[DHB] Uninitialized");
}

/* ============================================================================
 * Peer status (public)
 * ============================================================================ */

void dss_dhb_check_peer(void *inst)
{
    dss_dhb_ctx_t *ctx = &g_dss_dhb_ctx;
    
    if (!ctx->is_inited) {
        LOG_DEBUG_WAR("[DHB] Not initialized");
        dss_check_mes_conn(DSS_INVALID_ID64);
        return;
    }

    if (dss_dhb_read_all() != CM_SUCCESS) {
        LOG_DEBUG_WAR("[DHB] Failed to read heartbeats");
        return;
    }

    uint64 online_map = ctx->online_map;
    LOG_RUN_INF_INHIBIT(LOG_INHIBIT_LEVEL5, "[DHB] Peer check: online_map=0x%llx", online_map);

    dss_set_inst_work_status(online_map);
    dss_check_mes_conn(online_map);
}

bool32 dss_dhb_is_online(uint32 inst_id)
{
    if (inst_id >= DSS_MAX_INSTANCES) {
        return CM_FALSE;
    }
    return (g_dss_dhb_ctx.online_map & ((uint64)1 << inst_id)) != 0;
}

uint64 dss_dhb_get_online_map(void)
{
    return g_dss_dhb_ctx.online_map;
}

/* ============================================================================
 * Leader election (public)
 * ============================================================================ */

status_t dss_dhb_get_lock_owner(uint32 *master_id)
{
    if (master_id == NULL) {
        return CM_ERROR;
    }

    *master_id = CM_INVALID_ID32;

    dss_dhb_ctx_t *ctx = &g_dss_dhb_ctx;
    if (!ctx->is_inited) {
        LOG_RUN_INF_INHIBIT(LOG_INHIBIT_LEVEL5, "[DHB] Not initialized");
        return CM_ERROR;
    }

    if (ctx->lock_id == CM_INVALID_LOCK_ID) {
        LOG_RUN_INF_INHIBIT(LOG_INHIBIT_LEVEL5, "[DHB] Leader lock not available");
        return CM_ERROR;
    }

    unsigned long long owner_inst_id = CM_INVALID_INST_ID;
    int ret = cm_dl_getowner(ctx->lock_id, &owner_inst_id);
    if (ret != CM_SUCCESS) {
        LOG_RUN_INF_INHIBIT(LOG_INHIBIT_LEVEL5, "[DHB] cm_dl_getowner failed: ret=%d", ret);
        return CM_ERROR;
    }

    if (owner_inst_id != CM_INVALID_INST_ID) {
        *master_id = (uint32)owner_inst_id;
        LOG_RUN_INF_INHIBIT(LOG_INHIBIT_LEVEL5, "[DHB] Lock owner: inst_id=%u", *master_id);
    } else {
        LOG_RUN_INF_INHIBIT(LOG_INHIBIT_LEVEL5, "[DHB] No lock owner yet");
    }

    return CM_SUCCESS;
}

status_t dss_dhb_try_lock(bool32 *grab_lock)
{
    if (grab_lock == NULL) {
        return CM_ERROR;
    }

    *grab_lock = CM_FALSE;

    if (!g_dss_dhb_ctx.is_inited) {
        LOG_DEBUG_WAR("[DHB] Not initialized");
        return CM_ERROR;
    }

    status_t ret = dss_dhb_try_leader();
    if (ret == CM_SUCCESS) {
        *grab_lock = CM_TRUE;
        LOG_RUN_INF("[DHB] Grabbed leader lock");
    }

    return CM_SUCCESS;
}

status_t dss_dhb_unlock(void)
{
    if (!g_dss_dhb_ctx.is_inited) {
        return CM_SUCCESS;
    }
    return dss_dhb_release_leader();
}

status_t dss_dhb_trans_lock(uint32 target_inst_id)
{
    dss_dhb_ctx_t *ctx = &g_dss_dhb_ctx;
    
    if (!ctx->is_inited) {
        LOG_RUN_ERR("[DHB] Not initialized, cannot transfer lock");
        return CM_ERROR;
    }

    if (!ctx->is_leader) {
        LOG_RUN_WAR("[DHB] Trans lock: not the current leader");
        return CM_SUCCESS;
    }

    if (!dss_dhb_is_online(target_inst_id)) {
        LOG_RUN_ERR("[DHB] Cannot transfer lock: target inst %u is not online", target_inst_id);
        return CM_ERROR;
    }

    LOG_RUN_INF("[DHB] Transferring lock from inst %u to inst %u", ctx->inst_id, target_inst_id);

    status_t ret = dss_dhb_release_leader();
    if (ret != CM_SUCCESS) {
        LOG_RUN_ERR("[DHB] Failed to release leader lock during transfer");
        return CM_ERROR;
    }

    LOG_RUN_INF("[DHB] Lock released, target inst %u can now acquire it", target_inst_id);
    return CM_SUCCESS;
}

/* ============================================================================
 * Broadcast failure handling (public)
 * ============================================================================ */

status_t dss_dhb_check_failed_insts(uint64 failed_map, uint64 *updated_map)
{
    if (updated_map == NULL) {
        return CM_ERROR;
    }

    *updated_map = 0;

    if (!g_dss_dhb_ctx.is_inited) {
        LOG_DEBUG_WAR("[DHB] Not initialized");
        return CM_ERROR;
    }

    uint64 new_online_map = 0;
    uint64 still_online = 0;
    
    for (uint32 retry = 0; retry < DSS_DHB_CHECK_MAX_RETRIES; retry++) {
        if (dss_dhb_read_all() != CM_SUCCESS) {
            LOG_RUN_WAR("[DHB] Failed to refresh heartbeat on retry %u", retry);
            cm_sleep(DSS_DHB_CHECK_RETRY_INTERVAL_MS);
            continue;
        }

        new_online_map = g_dss_dhb_ctx.online_map;
        *updated_map = new_online_map;

        still_online = failed_map & new_online_map;
        
        if (still_online == 0) {
            LOG_RUN_INF("[DHB] Failed instances 0x%llx went offline after %u retries", failed_map, retry);
            dss_set_inst_work_status(new_online_map);
            dss_check_mes_conn(new_online_map);
            return CM_SUCCESS;
        }
        
        LOG_RUN_INF("[DHB] Check retry %u: failed=0x%llx, online=0x%llx, still_online=0x%llx",
            retry, failed_map, new_online_map, still_online);
        
        if (retry < DSS_DHB_CHECK_MAX_RETRIES - 1) {
            cm_sleep(DSS_DHB_CHECK_RETRY_INTERVAL_MS);
        }
    }
    
    LOG_RUN_ERR("[DHB] Check failed: after %u retries, failed=0x%llx still online",
        DSS_DHB_CHECK_MAX_RETRIES, still_online);
    
    dss_set_inst_work_status(new_online_map);
    dss_check_mes_conn(new_online_map);
    
    return CM_ERROR;
}

#ifdef __cplusplus
}
#endif
