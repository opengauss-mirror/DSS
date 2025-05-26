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
 * dss_session.c
 *
 *
 * IDENTIFICATION
 *    src/common/dss_session.c
 *
 * -------------------------------------------------------------------------
 */

#include "dss_session.h"
#include "cm_utils.h"
#include "dss_diskgroup.h"
#include "dss_malloc.h"
#include "dss_file.h"
#include "dss_redo.h"
#include "cm_system.h"
#include "dss_thv.h"
#include "dss_hp_interface.h"
#include "dss_fault_injection.h"

#ifdef __cplusplus
extern "C" {
#endif

dss_session_ctrl_t g_dss_session_ctrl = {0};

status_t dss_extend_session(uint32 extend_num)
{
    uint32 objectid;
    uint32_t old_alloc_sessions = g_dss_session_ctrl.alloc_sessions;
    uint32_t new_alloc_sessions = g_dss_session_ctrl.alloc_sessions + extend_num;
    if (new_alloc_sessions > g_dss_session_ctrl.total) {
        LOG_RUN_ERR("Failed to extend session, expect new alloc sessions %u, but max is %u.", new_alloc_sessions,
            g_dss_session_ctrl.total);
        DSS_THROW_ERROR(ERR_DSS_SESSION_EXTEND, "expect new alloc sessions %u, but max is %u.", new_alloc_sessions,
            g_dss_session_ctrl.total);
        return CM_ERROR;
    }
    for (uint32_t i = old_alloc_sessions; i < new_alloc_sessions; i++) {
        objectid = ga_alloc_object(GA_SESSION_POOL, DSS_INVALID_ID32);
        if (objectid == DSS_INVALID_ID32) {
            LOG_RUN_ERR("Failed to alloc object for session %u.", i);
            DSS_THROW_ERROR(ERR_DSS_SESSION_EXTEND, "Failed to alloc object for session %u.", i);
            return CM_ERROR;
        }
        LOG_DEBUG_INF("Alloc object %u for session %u.", objectid, i);
        g_dss_session_ctrl.sessions[i] = (dss_session_t *)ga_object_addr(GA_SESSION_POOL, objectid);
        g_dss_session_ctrl.sessions[i]->id = i;
        g_dss_session_ctrl.sessions[i]->is_used = CM_FALSE;
        g_dss_session_ctrl.sessions[i]->is_closed = CM_TRUE;
        g_dss_session_ctrl.sessions[i]->put_log = CM_FALSE;
        g_dss_session_ctrl.sessions[i]->objectid = objectid;
        g_dss_session_ctrl.sessions[i]->audit_info.is_forced = CM_FALSE;
        g_dss_session_ctrl.sessions[i]->is_holding_hotpatch_latch = CM_FALSE;
        g_dss_session_ctrl.sessions[i]->is_killed = CM_FALSE;
        g_dss_session_ctrl.alloc_sessions++;
    }
    LOG_RUN_INF("Succeed to extend sessions to %u.", g_dss_session_ctrl.alloc_sessions);
    return CM_SUCCESS;
}

status_t dss_init_session_pool(uint32 max_session_num)
{
    uint32 dss_session_size = (uint32)(max_session_num * sizeof(dss_session_t *));
    g_dss_session_ctrl.sessions = cm_malloc(dss_session_size);
    if (g_dss_session_ctrl.sessions == NULL) {
        return ERR_DSS_GA_INIT;
    }
    errno_t errcode = memset_s(g_dss_session_ctrl.sessions, dss_session_size, 0, dss_session_size);
    securec_check_ret(errcode);
    g_dss_session_ctrl.alloc_sessions = 0;
    uint32 extend_num = max_session_num >= DSS_SESSION_NUM_PER_GROUP ? DSS_SESSION_NUM_PER_GROUP : max_session_num;
    g_dss_session_ctrl.total = max_session_num;
    status_t status = dss_extend_session(extend_num);
    if (status != CM_SUCCESS) {
        return status;
    }
    g_dss_session_ctrl.is_inited = CM_TRUE;
    return CM_SUCCESS;
}

dss_session_ctrl_t *dss_get_session_ctrl(void)
{
    return &g_dss_session_ctrl;
}

uint32 dss_get_udssession_startid(void)
{
    dss_config_t *inst_cfg = dss_get_inst_cfg();
    uint32 start_sid = (uint32)DSS_BACKGROUND_TASK_NUM;
    start_sid = start_sid + inst_cfg->params.channel_num + inst_cfg->params.work_thread_cnt;
    return start_sid;
}

uint32 dss_get_max_total_session_cnt(void)
{
    dss_config_t *inst_cfg = dss_get_inst_cfg();
    return dss_get_udssession_startid() + inst_cfg->params.cfg_session_num;
}

uint32 dss_get_recover_task_idx(void)
{
    return (dss_get_udssession_startid() - (uint32)DSS_BACKGROUND_TASK_NUM);
}

uint32 dss_get_delay_clean_task_idx(void)
{
    return (dss_get_udssession_startid() - (uint32)DSS_BACKGROUND_TASK_NUM) + DSS_DELAY_CLEAN_BACKGROUND_TASK;
}

uint32 dss_get_hashmap_dynamic_extend_task_idx(void)
{
    return (dss_get_udssession_startid() - (uint32)DSS_BACKGROUND_TASK_NUM) + DSS_HASHMAP_DYNAMIC_EXTEND_TASK;
}

uint32 dss_get_bg_task_set_idx(uint32 task_id_base, uint32 idx)
{
    return (dss_get_udssession_startid() - (uint32)DSS_BACKGROUND_TASK_NUM) + task_id_base + idx;
}

uint32 dss_get_meta_syn_task_idx(uint32 idx)
{
    return dss_get_bg_task_set_idx(DSS_META_SYN_BG_TASK_BASE, idx);
}

uint32 dss_get_recycle_meta_task_idx(uint32 idx)
{
    return dss_get_bg_task_set_idx(DSS_RECYCLE_META_TASK_BASE, idx);
}

uint32 dss_get_alarm_check_task_idx(void)
{
    return (dss_get_udssession_startid() - (uint32)DSS_BACKGROUND_TASK_NUM) + DSS_ALARM_CHECK_TASK;
}

uint32 dss_get_dyn_log_task_idx(void)
{
    return (dss_get_udssession_startid() - (uint32)DSS_BACKGROUND_TASK_NUM) + DSS_DYN_LOG_TASK;
}

static status_t dss_init_session(dss_session_t *session, const cs_pipe_t *pipe)
{
    dss_latch_stack_t *latch_stack = &session->latch_stack;
    errno_t errcode = memset_s(latch_stack, sizeof(dss_latch_stack_t), 0, sizeof(dss_latch_stack_t));
    securec_check_ret(errcode);
    session->is_direct = CM_TRUE;
    session->connected = CM_FALSE;
    if (pipe != NULL) {
        session->pipe = *pipe;
        session->connected = CM_TRUE;
    }
    session->is_closed = CM_FALSE;
    session->proto_type = PROTO_TYPE_UNKNOWN;
    session->status = DSS_SESSION_STATUS_IDLE;
    session->client_version = DSS_PROTO_VERSION;
    session->proto_version = DSS_PROTO_VERSION;
    session->audit_info.is_forced = CM_FALSE;
    errcode = memset_s(
        session->dss_session_stat, DSS_EVT_COUNT * sizeof(dss_stat_item_t), 0, DSS_EVT_COUNT * sizeof(dss_stat_item_t));
    securec_check_ret(errcode);
    session->is_holding_hotpatch_latch = CM_FALSE;
    session->is_killed = CM_FALSE;
    return CM_SUCCESS;
}

dss_session_t *dss_get_reserv_session(uint32 idx)
{
    dss_session_ctrl_t *session_ctrl = dss_get_session_ctrl();
    dss_session_t *session = session_ctrl->sessions[idx];
    return session;
}

status_t dss_create_session(const cs_pipe_t *pipe, dss_session_t **session)
{
    uint32 i, id;

    *session = NULL;
    id = DSS_INVALID_ID32;
    cm_spin_lock(&g_dss_session_ctrl.lock, NULL);

    uint32 start_sid = dss_get_udssession_startid();
    uint32 end_sid = dss_get_max_total_session_cnt();
    status_t status;
    for (i = start_sid; i < end_sid; i++) {
        if (i >= g_dss_session_ctrl.alloc_sessions) {
            uint32 extend_num =
                g_dss_session_ctrl.total - g_dss_session_ctrl.alloc_sessions >= DSS_SESSION_NUM_PER_GROUP ?
                    DSS_SESSION_NUM_PER_GROUP :
                    g_dss_session_ctrl.total - g_dss_session_ctrl.alloc_sessions;
            status = dss_extend_session(extend_num);
            if (status != CM_SUCCESS) {
                cm_spin_unlock(&g_dss_session_ctrl.lock);
                return status;
            }
        }
        if (g_dss_session_ctrl.sessions[i]->is_used == CM_FALSE) {
            id = i;
            break;
        }
    }
    if (id == DSS_INVALID_ID32) {
        LOG_DEBUG_INF("No sessions are available.");
        cm_spin_unlock(&g_dss_session_ctrl.lock);
        return ERR_DSS_SESSION_CREATE;
    }
    *session = g_dss_session_ctrl.sessions[i];
    LOG_DEBUG_INF("Session[%u] is available.", id);
    cm_spin_lock(&(*session)->lock, NULL);
    g_dss_session_ctrl.used_count++;
    (*session)->is_used = CM_TRUE;
    cm_spin_unlock(&(*session)->lock);
    cm_spin_unlock(&g_dss_session_ctrl.lock);
    DSS_RETURN_IF_ERROR(dss_init_session(*session, pipe));
    return CM_SUCCESS;
}

status_t dss_session_check_killed(dss_session_t *session)
{
    // If the error code ERR_DSS_SESSION_KILLED has been throwed in previous sub-routine,
    // just return CM_ERROR directly without throwing it again.
    if (cm_get_error_code() == ERR_DSS_SESSION_KILLED) {
        return CM_ERROR;
    }
    if (session->is_killed) {
        DSS_THROW_ERROR(ERR_DSS_SESSION_KILLED, session->id);
        LOG_RUN_ERR("[DSS Kill Session] Session %u is killed.", session->id);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static void dss_clean_session_status(dss_session_t *session)
{
    if (!session->is_used) {
        return;
    }
    dss_session_ctrl_t *session_ctrl = dss_get_session_ctrl();

    for (uint32 j = 0; j < DSS_EVT_COUNT; j++) {
        int64 count = (int64)session->dss_session_stat[j].wait_count;
        int64 total_time = (int64)session->dss_session_stat[j].total_wait_time;
        int64 max_sgl_time = (int64)session->dss_session_stat[j].max_single_time;

        (void)cm_atomic_add(&session_ctrl->stat_g[j].wait_count, count);
        (void)cm_atomic_add(&session_ctrl->stat_g[j].total_wait_time, total_time);
        if (max_sgl_time > session_ctrl->stat_g[j].max_single_time) {
            (void)cm_atomic_cas(
                &session_ctrl->stat_g[j].max_single_time, session_ctrl->stat_g[j].max_single_time, max_sgl_time);
            session_ctrl->stat_g[j].max_date = session->dss_session_stat[j].max_date;
        }

        (void)cm_atomic_add(&session->dss_session_stat[j].wait_count, -count);
        (void)cm_atomic_add(&session->dss_session_stat[j].total_wait_time, -total_time);
        (void)cm_atomic_cas(&session->dss_session_stat[j].max_single_time, max_sgl_time, 0);
        session->dss_session_stat[j].max_date = 0;
    }
}

void dss_destroy_session_inner(dss_session_t *session)
{
    if (session->connected == CM_TRUE) {
        cs_disconnect(&session->pipe);
        session->connected = CM_FALSE;
    }
    g_dss_session_ctrl.used_count--;
    dss_clean_session_status(session);
    session->is_closed = CM_TRUE;
    session->is_used = CM_FALSE;
    errno_t ret = memset_sp(&session->cli_info, sizeof(session->cli_info), 0, sizeof(session->cli_info));
    securec_check_panic(ret);
    session->client_version = DSS_PROTO_VERSION;
    session->proto_version = DSS_PROTO_VERSION;
    session->put_log = CM_FALSE;
    session->is_holding_hotpatch_latch = CM_FALSE;
    session->is_killed = CM_FALSE;
    session->audit_info.is_forced = CM_FALSE;
}

void dss_destroy_session(dss_session_t *session)
{
    cm_spin_lock(&g_dss_session_ctrl.lock, NULL);
    cm_spin_lock(&session->shm_lock, NULL);
    LOG_DEBUG_INF("Succeed to lock session %u shm lock", session->id);
    dss_destroy_session_inner(session);
    cm_spin_unlock(&session->shm_lock);
    LOG_DEBUG_INF("Succeed to unlock session %u shm lock", session->id);
    cm_spin_unlock(&g_dss_session_ctrl.lock);
}

dss_session_t *dss_get_session(uint32 sid)
{
    if (sid >= g_dss_session_ctrl.alloc_sessions || sid >= g_dss_session_ctrl.total) {
        return NULL;
    }
    return g_dss_session_ctrl.sessions[sid];
}

static bool32 dss_is_timeout(int32 timeout, int32 sleep_times, int32 sleeps)
{
    if ((timeout == SPIN_WAIT_FOREVER) || (sleeps == 0)) {
        return CM_FALSE;
    }

    /* ms --> us, and translate to times */
    return (bool32)(((timeout * 1000) / (sleeps)) < sleep_times);
}

status_t dss_lock_shm_meta_s_without_stack(
    dss_session_t *session, dss_shared_latch_t *shared_latch, bool32 is_force, int32 timeout)
{
    cm_panic_log(dss_is_server(), "can not op shared latch without session latch stack in client");
    int32 sleep_times = 0;
    latch_statis_t *stat = NULL;
    uint32 count = 0;
    uint32 sid = DSS_SESSIONID_IN_LOCK(session->id);
    do {
        cm_spin_lock_by_sid(sid, &shared_latch->latch.lock, (stat != NULL) ? &stat->s_spin : NULL);
        if (shared_latch->latch.stat == LATCH_STATUS_IDLE) {
            shared_latch->latch.stat = LATCH_STATUS_S;
            shared_latch->latch.shared_count = 1;
            shared_latch->latch.sid = (uint16)sid;
            shared_latch->latch_extent.shared_sid_count += sid;
            cm_spin_unlock(&shared_latch->latch.lock);
            cm_latch_stat_inc(stat, count);
            return CM_SUCCESS;
        }
        if ((shared_latch->latch.stat == LATCH_STATUS_S) || (shared_latch->latch.stat == LATCH_STATUS_IX && is_force)) {
            shared_latch->latch.shared_count++;
            shared_latch->latch_extent.shared_sid_count += sid;
            cm_spin_unlock(&shared_latch->latch.lock);
            cm_latch_stat_inc(stat, count);
            return CM_SUCCESS;
        }

        cm_spin_unlock(&shared_latch->latch.lock);
        if (stat != NULL) {
            stat->misses++;
        }
        while (shared_latch->latch.stat != LATCH_STATUS_IDLE && shared_latch->latch.stat != LATCH_STATUS_S) {
            count++;
            if (count < GS_SPIN_COUNT) {
                continue;
            }

            SPIN_STAT_INC(stat, s_sleeps);
            cm_usleep(SPIN_SLEEP_TIME);
            sleep_times++;

            if (dss_is_timeout(timeout, sleep_times, SPIN_SLEEP_TIME)) {
                return CM_ERROR;
            }
            count = 0;
        }
    } while (1);
    return CM_SUCCESS;
}

// only used by api-client
status_t dss_lock_shm_meta_s_with_stack(
    dss_session_t *session, dss_latch_offset_t *offset, dss_shared_latch_t *shared_latch, int32 timeout)
{
    cm_panic_log(!(dss_is_server()), "can not op shared latch with session latch stack in server");
    DSS_ASSERT_LOG(session != NULL, "session ptr is NULL");
    DSS_ASSERT_LOG(session->latch_stack.stack_top < DSS_MAX_LATCH_STACK_DEPTH, "latch_stack overflow");

    DSS_FAULT_INJECTION_ACTION_TRIGGER_CUSTOM(
        DSS_FI_SCOPE_CLI, DSS_FI_SHM_LOCK_LATCH_STACK_UNSET, DSS_EXIT_LOG(CM_FALSE, "lock shm latch stack unset fail"));
    session->latch_stack.stack_top_bak = session->latch_stack.stack_top;
    session->latch_stack.op = LATCH_SHARED_OP_LATCH_S;
    session->latch_stack.latch_offset_stack[session->latch_stack.stack_top] = *offset;
    DSS_FAULT_INJECTION_ACTION_TRIGGER_CUSTOM(
        DSS_FI_SCOPE_CLI, DSS_FI_SHM_LOCK_LATCH_STACK_SET, DSS_EXIT_LOG(CM_FALSE, "lock shm latch stack fail"));

    int32 sleep_times = 0;
    latch_statis_t *stat = NULL;
    uint32 count = 0;
    uint32 sid = DSS_SESSIONID_IN_LOCK(session->id);
    bool32 is_force = CM_FALSE;
    do {
        cm_spin_lock_by_sid(sid, &shared_latch->latch.lock, (stat != NULL) ? &stat->s_spin : NULL);
        DSS_FAULT_INJECTION_ACTION_TRIGGER_CUSTOM(DSS_FI_SCOPE_CLI, DSS_FI_SHM_LOCK_LATCH_SPIN_LOCK_SET,
            DSS_EXIT_LOG(CM_FALSE, "lock shm latch spin lock set fail"));

        // for shared latch in shm, need to backup first
        dss_set_latch_extent(&shared_latch->latch_extent, shared_latch->latch.stat, shared_latch->latch.shared_count);

        if (shared_latch->latch.stat == LATCH_STATUS_IDLE) {
            session->latch_stack.op = LATCH_SHARED_OP_LATCH_S_BEG;

            shared_latch->latch.stat = LATCH_STATUS_S;
            DSS_FAULT_INJECTION_ACTION_TRIGGER_CUSTOM(DSS_FI_SCOPE_CLI, DSS_FI_SHM_LOCK_LATCH_S_STAT_SET,
                DSS_EXIT_LOG(CM_FALSE, "lock shm latch stat set fail"));

            shared_latch->latch.shared_count = 1;
            DSS_FAULT_INJECTION_ACTION_TRIGGER_CUSTOM(DSS_FI_SCOPE_CLI, DSS_FI_SHM_LOCK_LATCH_S_SHARED_COUNT_SET,
                DSS_EXIT_LOG(CM_FALSE, "lock shm latch share count set fail"));

            shared_latch->latch.sid = (uint16)sid;
            shared_latch->latch_extent.shared_sid_count += sid;

            // put this before the unlock to make sure: whn error happen, no one else can change the status of this
            // latch
            session->latch_stack.stack_top++;
            DSS_FAULT_INJECTION_ACTION_TRIGGER_CUSTOM(DSS_FI_SCOPE_CLI, DSS_FI_SHM_LOCK_LATCH_STACK_TOP_SET,
                DSS_EXIT_LOG(CM_FALSE, "lock shm latch top set fail"));

            session->latch_stack.op = LATCH_SHARED_OP_LATCH_S_END;

            cm_spin_unlock(&shared_latch->latch.lock);
            DSS_FAULT_INJECTION_ACTION_TRIGGER_CUSTOM(DSS_FI_SCOPE_CLI, DSS_FI_SHM_LOCK_LATCH_SPIN_UNLOCK_SET,
                DSS_EXIT_LOG(CM_FALSE, "lock shm latch spin unlock set fail"));

            cm_latch_stat_inc(stat, count);
            return CM_SUCCESS;
        }
        if ((shared_latch->latch.stat == LATCH_STATUS_S) || (shared_latch->latch.stat == LATCH_STATUS_IX && is_force)) {
            session->latch_stack.op = LATCH_SHARED_OP_LATCH_S_BEG;

            shared_latch->latch.shared_count++;
            DSS_FAULT_INJECTION_ACTION_TRIGGER_CUSTOM(DSS_FI_SCOPE_CLI, DSS_FI_SHM_LOCK_LATCH_S_SHARED_COUNT_SET2,
                DSS_EXIT_LOG(CM_FALSE, "lock shm latch share count set fail"));

            shared_latch->latch_extent.shared_sid_count += sid;

            // put this before the unlock to make sure: whn error happen, no one else can change the status of this
            // latch
            session->latch_stack.stack_top++;
            DSS_FAULT_INJECTION_ACTION_TRIGGER_CUSTOM(DSS_FI_SCOPE_CLI, DSS_FI_SHM_LOCK_LATCH_STACK_TOP_SET2,
                DSS_EXIT_LOG(CM_FALSE, "lock shm latch top set fail"));

            session->latch_stack.op = LATCH_SHARED_OP_LATCH_S_END;

            cm_spin_unlock(&shared_latch->latch.lock);
            DSS_FAULT_INJECTION_ACTION_TRIGGER_CUSTOM(DSS_FI_SCOPE_CLI, DSS_FI_SHM_LOCK_LATCH_SPIN_UNLOCK_SET2,
                DSS_EXIT_LOG(CM_FALSE, "lock shm latch spin unlock set2 fail"));

            cm_latch_stat_inc(stat, count);
            return CM_SUCCESS;
        }

        cm_spin_unlock(&shared_latch->latch.lock);
        DSS_FAULT_INJECTION_ACTION_TRIGGER_CUSTOM(DSS_FI_SCOPE_CLI, DSS_FI_SHM_LOCK_LATCH_SPIN_UNLOCK_SET3,
            DSS_EXIT_LOG(CM_FALSE, "lock shm latch spin unlock set3 fail"));

        if (stat != NULL) {
            stat->misses++;
        }
        while (shared_latch->latch.stat != LATCH_STATUS_IDLE && shared_latch->latch.stat != LATCH_STATUS_S) {
            count++;
            if (count < GS_SPIN_COUNT) {
                continue;
            }

            SPIN_STAT_INC(stat, s_sleeps);
            cm_usleep(SPIN_SLEEP_TIME);
            sleep_times++;

            if (dss_is_timeout(timeout, sleep_times, SPIN_SLEEP_TIME)) {
                if (session != NULL) {
                    session->latch_stack.latch_offset_stack[session->latch_stack.stack_top].type =
                        DSS_LATCH_OFFSET_INVALID;
                    session->latch_stack.op = LATCH_SHARED_OP_NONE;
                }

                return CM_ERROR;
            }
            count = 0;
        }
    } while (1);
    return CM_SUCCESS;
}

status_t dss_lock_shm_meta_bucket_s(dss_session_t *session, uint32 id, dss_shared_latch_t *shared_latch)
{
    CM_ASSERT(session != NULL);
    if (dss_is_server()) {
        return dss_lock_shm_meta_s_without_stack(session, shared_latch, CM_FALSE, SPIN_WAIT_FOREVER);
    }
    dss_latch_offset_t latch_offset;
    latch_offset.type = DSS_LATCH_OFFSET_SHMOFFSET;
    cm_shm_key_t key = ga_object_key(GA_SEGMENT_POOL, id);
    latch_offset.offset.shm_offset = cm_trans_shm_offset(key, &shared_latch->latch);
    return dss_lock_shm_meta_s_with_stack(session, &latch_offset, shared_latch, SPIN_WAIT_FOREVER);
}

status_t dss_cli_lock_shm_meta_s(
    dss_session_t *session, dss_latch_offset_t *offset, dss_shared_latch_t *shared_latch, latch_should_exit should_exit)
{
    for (int i = 0; i < DSS_CLIENT_TIMEOUT_COUNT; i++) {
        if (session->is_closed) {
            DSS_THROW_ERROR(ERR_DSS_SHM_LOCK, "uds connection is closed.");
            LOG_RUN_ERR("[DSS] ABORT INFO: Failed to lock vg share memery because uds connection is closed.");
            cm_fync_logfile();
            dss_exit(1);
        }
        if (dss_lock_shm_meta_s_with_stack(session, offset, shared_latch, SPIN_WAIT_FOREVER) == CM_SUCCESS) {
            return CM_SUCCESS;
        }

        if (should_exit && should_exit()) {
            LOG_RUN_ERR("Caller want to exit when waiting for shared_latch!!");
            return ERR_DSS_LOCK_TIMEOUT;
        }
    }
    LOG_RUN_ERR("The client want to lock meta timeout.");
    return ERR_DSS_LOCK_TIMEOUT;
}

void dss_lock_shm_meta_x(const dss_session_t *session, dss_shared_latch_t *shared_latch)
{
    CM_ASSERT(session != NULL);
    cm_panic_log(dss_is_server(), "can not op x latch in client");
    latch_statis_t *stat = NULL;
    uint32 count = 0;
    uint32 sid = DSS_SESSIONID_IN_LOCK(session->id);

    do {
        cm_spin_lock_by_sid(sid, &shared_latch->latch.lock, (stat != NULL) ? &stat->x_spin : NULL);
        if (shared_latch->latch.stat == LATCH_STATUS_IDLE) {
            shared_latch->latch.sid = (uint16)sid;
            shared_latch->latch.stat = LATCH_STATUS_X;
            cm_spin_unlock(&shared_latch->latch.lock);
            cm_latch_stat_inc(stat, count);
            return;
        }
        if (shared_latch->latch.stat == LATCH_STATUS_S) {
            shared_latch->latch.stat = LATCH_STATUS_IX;
            cm_spin_unlock(&shared_latch->latch.lock);
            cm_latch_ix2x(&shared_latch->latch, sid, stat);
            return;
        }
        cm_spin_unlock(&shared_latch->latch.lock);
        if (stat != NULL) {
            stat->misses++;
        }
        while (shared_latch->latch.stat != LATCH_STATUS_IDLE && shared_latch->latch.stat != LATCH_STATUS_S) {
            count++;
            if (count >= GS_SPIN_COUNT) {
                SPIN_STAT_INC(stat, x_sleeps);
                cm_spin_sleep();
                count = 0;
            }
        }
    } while (CM_TRUE);
}

bool32 dss_lock_shm_meta_timed_x(const dss_session_t *session, dss_shared_latch_t *shared_latch, uint32 wait_ticks)
{
    CM_ASSERT(session != NULL);
    cm_panic_log(dss_is_server(), "can not op x latch in client");
    latch_statis_t *stat = NULL;
    uint32 count = 0;
    uint32 sid = DSS_SESSIONID_IN_LOCK(session->id);
    uint32 actual_ticks = 0;
    do {
        cm_spin_lock_by_sid(sid, &shared_latch->latch.lock, (stat != NULL) ? &stat->x_spin : NULL);
        if (shared_latch->latch.stat == LATCH_STATUS_IDLE) {
            shared_latch->latch.sid = (uint16)sid;
            shared_latch->latch.stat = LATCH_STATUS_X;
            cm_spin_unlock(&shared_latch->latch.lock);
            cm_latch_stat_inc(stat, count);
            return CM_TRUE;
        }
        if (shared_latch->latch.stat == LATCH_STATUS_S) {
            shared_latch->latch.stat = LATCH_STATUS_IX;
            cm_spin_unlock(&shared_latch->latch.lock);
            if (!cm_latch_timed_ix2x(&shared_latch->latch, sid, wait_ticks, stat)) {
                cm_spin_lock_by_sid(sid, &shared_latch->latch.lock, (stat != NULL) ? &stat->x_spin : NULL);
                shared_latch->latch.stat = shared_latch->latch.shared_count > 0 ? LATCH_STATUS_S : LATCH_STATUS_IDLE;
                cm_spin_unlock(&shared_latch->latch.lock);
                return CM_FALSE;
            }
            return CM_TRUE;
        }
        cm_spin_unlock(&shared_latch->latch.lock);
        if (stat != NULL) {
            stat->misses++;
        }
        while (shared_latch->latch.stat != LATCH_STATUS_IDLE && shared_latch->latch.stat != LATCH_STATUS_S) {
            if (actual_ticks >= wait_ticks) {
                return CM_FALSE;
            }
            count++;
            if (count >= GS_SPIN_COUNT) {
                SPIN_STAT_INC(stat, x_sleeps);
                cm_spin_sleep();
                count = 0;
                actual_ticks++;
            }
        }
    } while (CM_TRUE);
    return CM_FALSE;
}

void dss_lock_shm_meta_x2ix(dss_session_t *session, dss_shared_latch_t *shared_latch)
{
    CM_ASSERT(session != NULL);
    cm_panic_log(dss_is_server(), "can not op x latch in client");
    CM_ASSERT(shared_latch->latch.stat == LATCH_STATUS_X);
    latch_statis_t *stat = NULL;
    uint32 sid = DSS_SESSIONID_IN_LOCK(session->id);
    dss_latch_x2ix(&shared_latch->latch, sid, stat);
}

void dss_lock_shm_meta_ix2x(dss_session_t *session, dss_shared_latch_t *shared_latch)
{
    CM_ASSERT(session != NULL);
    cm_panic_log(dss_is_server(), "can not op x latch in client");
    CM_ASSERT(shared_latch->latch.stat == LATCH_STATUS_IX);
    latch_statis_t *stat = NULL;
    uint32 sid = DSS_SESSIONID_IN_LOCK(session->id);
    dss_latch_ix2x(&shared_latch->latch, sid, stat);
}

void dss_lock_shm_meta_degrade(dss_session_t *session, dss_shared_latch_t *shared_latch)
{
    CM_ASSERT(session != NULL);
    cm_panic_log(dss_is_server(), "can not op x latch degradation in client.");
    uint32 sid = (session == NULL) ? DSS_DEFAULT_SESSIONID : DSS_SESSIONID_IN_LOCK(session->id);
    cm_panic_log(sid == shared_latch->latch.sid && shared_latch->latch.stat == LATCH_STATUS_X,
        "Invalid degradation: sid:%u, sid on latch:%u, latch status:%u.", sid, shared_latch->latch.sid,
        shared_latch->latch.stat);
    cm_spin_lock_by_sid(sid, &shared_latch->latch.lock, NULL);
    shared_latch->latch.stat = LATCH_STATUS_S;
    shared_latch->latch.shared_count = 1;
    shared_latch->latch_extent.shared_sid_count += sid;
    cm_spin_unlock(&shared_latch->latch.lock);
}

void dss_lock_shm_meta_bucket_x(dss_session_t *session, dss_shared_latch_t *shared_latch)
{
    CM_ASSERT(session != NULL);
    dss_lock_shm_meta_x(session, shared_latch);
}

// only used by dssserver
void dss_unlock_shm_meta_without_stack(dss_session_t *session, dss_shared_latch_t *shared_latch)
{
    CM_ASSERT(session != NULL);
    cm_panic_log(dss_is_server(), "can not op shared latch without session latch stack in client");
    CM_ASSERT(shared_latch->latch.stat != LATCH_STATUS_IDLE);
    spin_statis_t *stat_spin = NULL;
    uint32 sid = DSS_SESSIONID_IN_LOCK(session->id);
    cm_spin_lock_by_sid(sid, &shared_latch->latch.lock, stat_spin);

    if (shared_latch->latch.stat == LATCH_STATUS_S || shared_latch->latch.stat == LATCH_STATUS_IX) {
        CM_ASSERT(shared_latch->latch.shared_count > 0);
        shared_latch->latch.shared_count--;
        if (shared_latch->latch.shared_count == 0) {
            if (shared_latch->latch.stat == LATCH_STATUS_S) {
                shared_latch->latch.stat = LATCH_STATUS_IDLE;
            }
            shared_latch->latch.sid = 0;
        }
        shared_latch->latch_extent.shared_sid_count -= sid;
    } else if (shared_latch->latch.stat == LATCH_STATUS_X) {
        CM_ASSERT(shared_latch->latch.shared_count == 0);
        shared_latch->latch.stat = LATCH_STATUS_IDLE;
        shared_latch->latch.sid = 0;
    }
    cm_spin_unlock(&shared_latch->latch.lock);
}

// only used by api-client or by clean
bool32 dss_unlock_shm_meta_s_with_stack(dss_session_t *session, dss_shared_latch_t *shared_latch, bool32 is_try_lock)
{
    CM_ASSERT(session != NULL);
    // can not call checkcm_paninc_log with dss_is_server
    CM_ASSERT(shared_latch->latch.stat != LATCH_STATUS_IDLE);

    session->latch_stack.stack_top_bak = session->latch_stack.stack_top;
    session->latch_stack.op = LATCH_SHARED_OP_UNLATCH;
    DSS_FAULT_INJECTION_ACTION_TRIGGER_CUSTOM(DSS_FI_SCOPE_CLI, DSS_FI_SHM_LOCK_UNLATCH_SPIN_LOCK_UNSET,
        DSS_EXIT_LOG(CM_FALSE, "lock shm unlatch spin lock unset fail"));

    spin_statis_t *stat_spin = NULL;
    uint32 sid = DSS_SESSIONID_IN_LOCK(session->id);
    if (!is_try_lock) {
        cm_spin_lock_by_sid(sid, &shared_latch->latch.lock, stat_spin);
        DSS_FAULT_INJECTION_ACTION_TRIGGER_CUSTOM(DSS_FI_SCOPE_CLI, DSS_FI_SHM_LOCK_UNLATCH_SPIN_LOCK_SET,
            DSS_EXIT_LOG(CM_FALSE, "lock shm unlatch spin lock set fail"));

    } else {
        bool32 is_locked = cm_spin_try_lock(&shared_latch->latch.lock);
        DSS_FAULT_INJECTION_ACTION_TRIGGER_CUSTOM(DSS_FI_SCOPE_CLI, DSS_FI_SHM_LOCK_UNLATCH_SPIN_LOCK_SET2,
            DSS_EXIT_LOG(CM_FALSE, "lock shm unlatch spin lock set2 fail"));
        if (!is_locked) {
            return CM_FALSE;
        }
    }
    // for shared latch in shm, need to backup first
    dss_set_latch_extent(&shared_latch->latch_extent, shared_latch->latch.stat, shared_latch->latch.shared_count);

    // begin to change latch
    session->latch_stack.op = LATCH_SHARED_OP_UNLATCH_BEG;

    CM_ASSERT(shared_latch->latch.shared_count > 0);
    shared_latch->latch.shared_count--;
    DSS_FAULT_INJECTION_ACTION_TRIGGER_CUSTOM(DSS_FI_SCOPE_CLI, DSS_FI_SHM_LOCK_UNLATCH_S_SHARED_COUNT_SET,
        DSS_EXIT_LOG(CM_FALSE, "lock shm unlatch share count set fail"));

    if (shared_latch->latch.shared_count == 0) {
        if (shared_latch->latch.stat == LATCH_STATUS_S) {
            shared_latch->latch.stat = LATCH_STATUS_IDLE;
        }
        DSS_FAULT_INJECTION_ACTION_TRIGGER_CUSTOM(DSS_FI_SCOPE_CLI, DSS_FI_SHM_LOCK_UNLATCH_S_STAT_SET,
            DSS_EXIT_LOG(CM_FALSE, "lock shm unlatch stat set fail"));

        shared_latch->latch.sid = 0;
    }
    shared_latch->latch_extent.shared_sid_count -= sid;

    cm_spin_unlock(&shared_latch->latch.lock);
    DSS_FAULT_INJECTION_ACTION_TRIGGER_CUSTOM(DSS_FI_SCOPE_CLI, DSS_FI_SHM_LOCK_UNLATCH_SPIN_UNLOCK_SET,
        DSS_EXIT_LOG(CM_FALSE, "lock shm unlatch spin unlock set fail"));

    // put this after the unlock to make sure:when error happen after unlock, do NOT op the unlatch-ed latch
    // begin to change stack
    CM_ASSERT(session->latch_stack.stack_top);
    // in the normal, should be stack_top-- first, then set [stack_top].typ = DSS_LATCH_OFFSET_INVALID
    // but may NOT do [stack_top].typ = DSS_LATCH_OFFSET_INVALID when some error happen,
    // so leave the stack_top-- on the second step
    session->latch_stack.latch_offset_stack[session->latch_stack.stack_top - 1].type = DSS_LATCH_OFFSET_INVALID;
    DSS_FAULT_INJECTION_ACTION_TRIGGER_CUSTOM(
        DSS_FI_SCOPE_CLI, DSS_FI_SHM_LOCK_UNLATCH_STACK_SET, DSS_EXIT_LOG(CM_FALSE, "lock shm unlatch stack set fail"));

    session->latch_stack.stack_top--;
    DSS_FAULT_INJECTION_ACTION_TRIGGER_CUSTOM(DSS_FI_SCOPE_CLI, DSS_FI_SHM_LOCK_UNLATCH_STACK_TOP_SET,
        DSS_EXIT_LOG(CM_FALSE, "lock shm unlatch stack top set fail"));

    session->latch_stack.op = LATCH_SHARED_OP_UNLATCH_END;
    return CM_TRUE;
}

void dss_unlock_shm_meta_bucket(dss_session_t *session, dss_shared_latch_t *shared_latch)
{
    CM_ASSERT(session != NULL);
    if (dss_is_server()) {
        dss_unlock_shm_meta_without_stack(session, shared_latch);
        return;
    } else {
        (void)dss_unlock_shm_meta_s_with_stack(session, shared_latch, CM_FALSE);
    }
}

static void dss_clean_latch_s_without_bak(dss_session_t *session, dss_shared_latch_t *shared_latch)
{
    LOG_DEBUG_INF("Clean sid:%u latch_stack old stack_top:%u.", DSS_SESSIONID_IN_LOCK(session->id),
        session->latch_stack.stack_top);
    session->latch_stack.latch_offset_stack[session->latch_stack.stack_top].type = DSS_LATCH_OFFSET_INVALID;
    LOG_DEBUG_INF("Clean sid:%u latch_stack new stack_top:%u.", DSS_SESSIONID_IN_LOCK(session->id),
        session->latch_stack.stack_top);
}

static void dss_clean_latch_s_with_bak(dss_session_t *session, dss_shared_latch_t *shared_latch)
{
    LOG_DEBUG_INF("Clean sid:%u shared_latch old count:%hu, old stat:%u.", DSS_SESSIONID_IN_LOCK(session->id),
        shared_latch->latch.shared_count, shared_latch->latch.stat);

    // do not care about the new value, just using the shared_count_bak
    shared_latch->latch.shared_count = shared_latch->latch_extent.shared_count_bak;
    shared_latch->latch.stat = shared_latch->latch_extent.stat_bak;
    shared_latch->latch_extent.shared_sid_count = shared_latch->latch_extent.shared_sid_count_bak;

    if (shared_latch->latch.shared_count == 0) {
        if (shared_latch->latch.stat == LATCH_STATUS_S) {
            shared_latch->latch.stat = LATCH_STATUS_IDLE;
        }
        shared_latch->latch.sid = 0;
    }

    LOG_DEBUG_INF("Clean sid:%u latch_stack old stack_top:%u.", DSS_SESSIONID_IN_LOCK(session->id),
        session->latch_stack.stack_top);

    LOG_DEBUG_INF("Clean sid:%u shared_latch new count:%hu, new stat:%u.", DSS_SESSIONID_IN_LOCK(session->id),
        shared_latch->latch.shared_count, shared_latch->latch.stat);

    // not sure last latch finish, so using the stack_top_bak
    session->latch_stack.stack_top = session->latch_stack.stack_top_bak;
    // when latch first, and not finish, the stack_top may be zero
    if (session->latch_stack.stack_top > 0) {
        session->latch_stack.latch_offset_stack[session->latch_stack.stack_top - 1].type = DSS_LATCH_OFFSET_INVALID;
        session->latch_stack.stack_top--;
    } else {
        session->latch_stack.latch_offset_stack[session->latch_stack.stack_top].type = DSS_LATCH_OFFSET_INVALID;
    }
    LOG_DEBUG_INF("Clean sid:%u latch_stack new stack_top:%u.", DSS_SESSIONID_IN_LOCK(session->id),
        session->latch_stack.stack_top);
}

static void dss_clean_unlatch_without_bak(dss_session_t *session, dss_shared_latch_t *shared_latch)
{
    LOG_DEBUG_INF("Clean sid:%u unlatch shared_latch without bak, old count:%hu, old stat:%u.",
        DSS_SESSIONID_IN_LOCK(session->id), shared_latch->latch.shared_count, shared_latch->latch.stat);

    CM_ASSERT(shared_latch->latch.shared_count > 0);
    shared_latch->latch.shared_count--;
    shared_latch->latch_extent.shared_sid_count -= DSS_SESSIONID_IN_LOCK(session->id);

    if (shared_latch->latch.shared_count == 0) {
        if (shared_latch->latch.stat == LATCH_STATUS_S) {
            shared_latch->latch.stat = LATCH_STATUS_IDLE;
        }
        shared_latch->latch.sid = 0;
    }

    LOG_DEBUG_INF("Clean sid:%u shared_latch new count:%hu, new stat:%u.", DSS_SESSIONID_IN_LOCK(session->id),
        shared_latch->latch.shared_count, shared_latch->latch.stat);

    LOG_DEBUG_INF("Clean sid:%u latch_stack old stack_top:%u.", DSS_SESSIONID_IN_LOCK(session->id),
        session->latch_stack.stack_top);
    CM_ASSERT(session->latch_stack.stack_top > 0);
    session->latch_stack.latch_offset_stack[session->latch_stack.stack_top - 1].type = DSS_LATCH_OFFSET_INVALID;
    session->latch_stack.stack_top--;
    LOG_DEBUG_INF("Clean sid:%u latch_stack new stack_top:%u.", DSS_SESSIONID_IN_LOCK(session->id),
        session->latch_stack.stack_top);
}

static void dss_clean_unlatch_with_bak(dss_session_t *session, dss_shared_latch_t *shared_latch)
{
    LOG_DEBUG_INF("Clean sid:%u unlatch shared_latch with bak, old count:%hu, old stat:%u.",
        DSS_SESSIONID_IN_LOCK(session->id), shared_latch->latch.shared_count, shared_latch->latch.stat);
    // not sure last unlatch finsh, using the shared_count_bak first
    shared_latch->latch.shared_count = shared_latch->latch_extent.shared_count_bak;
    shared_latch->latch.stat = shared_latch->latch_extent.stat_bak;
    shared_latch->latch_extent.shared_sid_count = shared_latch->latch_extent.shared_sid_count_bak;

    CM_ASSERT(shared_latch->latch.shared_count > 0);
    shared_latch->latch.shared_count--;
    shared_latch->latch_extent.shared_sid_count -= DSS_SESSIONID_IN_LOCK(session->id);

    if (shared_latch->latch.shared_count == 0) {
        if (shared_latch->latch.stat == LATCH_STATUS_S) {
            shared_latch->latch.stat = LATCH_STATUS_IDLE;
        }
        shared_latch->latch.sid = 0;
    }
    LOG_DEBUG_INF("Clean sid:%u shared_latch new count:%hu, new stat:%u.", DSS_SESSIONID_IN_LOCK(session->id),
        shared_latch->latch.shared_count, shared_latch->latch.stat);

    LOG_DEBUG_INF("Clean sid:%u latch_stack old stack_top:%u.", DSS_SESSIONID_IN_LOCK(session->id),
        session->latch_stack.stack_top);
    // not sure last unlatch finish, so using the stack_top_bak
    session->latch_stack.stack_top = session->latch_stack.stack_top_bak;
    CM_ASSERT(session->latch_stack.stack_top > 0);
    session->latch_stack.latch_offset_stack[session->latch_stack.stack_top - 1].type = DSS_LATCH_OFFSET_INVALID;
    session->latch_stack.stack_top--;
    LOG_DEBUG_INF("Clean sid:%u latch_stack new stack_top:%u.", DSS_SESSIONID_IN_LOCK(session->id),
        session->latch_stack.stack_top);
}

static void dss_clean_last_op_with_lock(dss_session_t *session, dss_shared_latch_t *shared_latch)
{
    CM_ASSERT(DSS_SESSIONID_IN_LOCK(session->id) == shared_latch->latch.lock);

    LOG_DEBUG_INF("Clean sid:%u last op with lock latch_stack op:%u, stack_top_bak:%hu.",
        DSS_SESSIONID_IN_LOCK(session->id), session->latch_stack.op, session->latch_stack.stack_top_bak);

    LOG_DEBUG_INF("Clean sid:%u latch_extent stat_bak:%hu, shared_count_bak:%hu.", DSS_SESSIONID_IN_LOCK(session->id),
        shared_latch->latch_extent.stat_bak, shared_latch->latch_extent.shared_count_bak);

    // step 1, try to clean
    // no backup, no change
    if (session->latch_stack.op == LATCH_SHARED_OP_LATCH_S) {
        dss_clean_latch_s_without_bak(session, shared_latch);
        // when latch with backup, undo the latch witch backup
    } else if (session->latch_stack.op == LATCH_SHARED_OP_LATCH_S_BEG ||
               session->latch_stack.op == LATCH_SHARED_OP_LATCH_S_END) {
        dss_clean_latch_s_with_bak(session, shared_latch);
        // when unlatch, no backup, no change, redo the unlatch without backup
    } else if (session->latch_stack.op == LATCH_SHARED_OP_UNLATCH) {
        dss_clean_unlatch_without_bak(session, shared_latch);
        // when unlatch not finish with backup, redo unlatch with backup
    } else if (session->latch_stack.op == LATCH_SHARED_OP_UNLATCH_BEG) {
        dss_clean_unlatch_with_bak(session, shared_latch);
    }

    session->latch_stack.op = LATCH_SHARED_OP_UNLATCH_END;
    // step2
    cm_spin_unlock(&shared_latch->latch.lock);
}

static void dss_clean_last_op_without_lock(dss_session_t *session, dss_shared_latch_t *shared_latch)
{
    if (session->latch_stack.op == LATCH_SHARED_OP_NONE || session->latch_stack.op == LATCH_SHARED_OP_LATCH_S) {
        session->latch_stack.latch_offset_stack[session->latch_stack.stack_top].type = DSS_LATCH_OFFSET_INVALID;
        session->latch_stack.op = LATCH_SHARED_OP_UNLATCH_END;
        LOG_DEBUG_INF("Clean sid:%u reset to latch_stack op:%u, stack_top:%hu.", DSS_SESSIONID_IN_LOCK(session->id),
            session->latch_stack.op, session->latch_stack.stack_top);
        // LATCH_SHARED_OP_UNLATCH_BEG and not in lock, means has finished to unlatch the latch,
        // but not finished to set lack_stack[stack_top].type
    } else if (session->latch_stack.op == LATCH_SHARED_OP_UNLATCH_BEG) {
        CM_ASSERT(session->latch_stack.stack_top > 0);
        session->latch_stack.latch_offset_stack[session->latch_stack.stack_top - 1].type = DSS_LATCH_OFFSET_INVALID;
        session->latch_stack.stack_top--;
        session->latch_stack.op = LATCH_SHARED_OP_UNLATCH_END;
        LOG_DEBUG_INF("Clean sid:%u reset to latch_stack op:%u, stack_top:%hu.", DSS_SESSIONID_IN_LOCK(session->id),
            session->latch_stack.op, session->latch_stack.stack_top);
    }
}

static bool32 dss_clean_lock_for_shm_meta(dss_session_t *session, dss_shared_latch_t *shared_latch, bool32 is_daemon)
{
    LOG_DEBUG_INF("Clean sid:%u latch_stack op:%u, stack_top:%hu.", DSS_SESSIONID_IN_LOCK(session->id),
        session->latch_stack.op, session->latch_stack.stack_top);
    // last op between lock & unlock for this latch not finish
    if (DSS_SESSIONID_IN_LOCK(session->id) == shared_latch->latch.lock) {
        dss_clean_last_op_with_lock(session, shared_latch);
        // if last op not happen, or latch not begin
    } else if (session->latch_stack.op == LATCH_SHARED_OP_NONE || session->latch_stack.op == LATCH_SHARED_OP_LATCH_S ||
               session->latch_stack.op == LATCH_SHARED_OP_UNLATCH_BEG) {
        dss_clean_last_op_without_lock(session, shared_latch);
        // otherwise unlatch the latch
    } else {
        // may exist other session lock but dead after last check the lsat->spin_lock, so if it's daemon, do lock with
        // try this
        if (is_daemon) {
            LOG_DEBUG_INF("Clean sid:%u latch_stack op:%u, stack_top:%hu wait next try.",
                DSS_SESSIONID_IN_LOCK(session->id), session->latch_stack.op, session->latch_stack.stack_top);
            return dss_unlock_shm_meta_s_with_stack(session, shared_latch, CM_TRUE);
        }
        (void)dss_unlock_shm_meta_s_with_stack(session, shared_latch, CM_FALSE);
    }
    return CM_TRUE;
}

static bool32 dss_need_clean_session_latch(dss_session_t *session, uint64 cli_pid, int64 start_time)
{
    if (cli_pid == 0 || !session->is_used || !session->connected || cm_sys_process_alived(cli_pid, start_time)) {
        return CM_FALSE;
    }
    return CM_TRUE;
}

void dss_clean_session_latch(dss_session_t *session, bool32 is_daemon)
{
    int32 i = 0;
    sh_mem_p offset;
    int32 latch_place;
    dss_latch_offset_type_e offset_type;
    dss_shared_latch_t *shared_latch = NULL;
    if (!session->is_direct) {
        LOG_DEBUG_INF("Clean sid:%u is not direct.", DSS_SESSIONID_IN_LOCK(session->id));
        return;
    }
    uint64 cli_pid = session->cli_info.cli_pid;
    int64 start_time = session->cli_info.start_time;
    if (is_daemon && !dss_need_clean_session_latch(session, cli_pid, start_time)) {
        LOG_RUN_INF("[CLEAN_LATCH]session id %u, pid %llu, start_time %lld, process name:%s need check next time.",
            session->id, cli_pid, start_time, session->cli_info.process_name);
        return;
    }
    LOG_RUN_INF("[CLEAN_LATCH]session id %u, pid %llu, start_time %lld, process name:%s in lock.", session->id, cli_pid,
        start_time, session->cli_info.process_name);
    LOG_DEBUG_INF("Clean sid:%u latch_stack op:%u, stack_top:%hu.", DSS_SESSIONID_IN_LOCK(session->id),
        session->latch_stack.op, session->latch_stack.stack_top);
    for (i = (int32)session->latch_stack.stack_top; i >= DSS_MAX_LATCH_STACK_BOTTON; i--) {
        // the stack_top may NOT be moveed to the right place
        if (i == DSS_MAX_LATCH_STACK_DEPTH) {
            latch_place = i - 1;
        } else {
            latch_place = i;
        }
        offset_type = session->latch_stack.latch_offset_stack[latch_place].type;
        // the stack_top may be the right invalid or latch not finish to set offset_type
        // or unlatch not over, just finish unlatch the latch, but not set offset_type
        if (offset_type != DSS_LATCH_OFFSET_SHMOFFSET) {
            LOG_DEBUG_ERR("Clean sid:%u shared_latch offset type is invalid %u,latch_place:%d.",
                DSS_SESSIONID_IN_LOCK(session->id), session->latch_stack.latch_offset_stack[latch_place].type,
                latch_place);
            if (session->latch_stack.op == LATCH_SHARED_OP_UNLATCH_BEG && i != (int32)session->latch_stack.stack_top) {
                session->latch_stack.stack_top = latch_place;
                session->latch_stack.op = LATCH_SHARED_OP_UNLATCH_END;
            }
            LOG_DEBUG_INF("Clean sid:%u reset to latch_stack op:%u, stack_top:%hu.", DSS_SESSIONID_IN_LOCK(session->id),
                session->latch_stack.op, session->latch_stack.stack_top);
            continue;
        } else {
            offset = session->latch_stack.latch_offset_stack[latch_place].offset.shm_offset;
            CM_ASSERT(offset != SHM_INVALID_ADDR);
            shared_latch = (dss_shared_latch_t *)OFFSET_TO_ADDR(offset);
            LOG_DEBUG_INF("Clean sid:%u shared_latch,latch_place:%d, offset:%llu.", DSS_SESSIONID_IN_LOCK(session->id),
                latch_place, (uint64)offset);
        }
        // the lock is locked by this session in the dead-client,
        if (is_daemon && shared_latch->latch.lock != 0 &&
            DSS_SESSIONID_IN_LOCK(session->id) != shared_latch->latch.lock) {
            LOG_DEBUG_INF("Clean sid:%u daemon wait next time to clean.", DSS_SESSIONID_IN_LOCK(session->id));
            return;
        } else {
            bool32 is_clean = dss_clean_lock_for_shm_meta(session, shared_latch, is_daemon);
            if (!is_clean) {
                LOG_DEBUG_INF("Clean sid:%u daemon wait next time to clean.", DSS_SESSIONID_IN_LOCK(session->id));
                return;
            }
        }
    }
    session->latch_stack.op = LATCH_SHARED_OP_NONE;
    session->latch_stack.stack_top = DSS_MAX_LATCH_STACK_BOTTON;
}

void dss_server_session_lock(dss_session_t *session)
{
    // session->lock to contrl the concurrency of cleaning session latch thread
    cm_spin_lock(&session->lock, NULL);
    while (!cm_spin_timed_lock(&session->shm_lock, DSS_SERVER_SESS_TIMEOUT)) {
        bool32 alived = cm_sys_process_alived(session->cli_info.cli_pid, session->cli_info.start_time);
        if (!alived) {
            // unlock if the client goes offline
            LOG_DEBUG_INF("Process:%s is not alive, pid:%llu, start_time:%lld.", session->cli_info.process_name,
                session->cli_info.cli_pid, session->cli_info.start_time);
            cm_spin_unlock(&session->shm_lock);
            LOG_DEBUG_INF("Succeed to unlock session %u shm lock", session->id);
            continue;
        }
        LOG_DEBUG_INF("Process:%s is alive, pid:%llu, start_time:%lld.", session->cli_info.process_name,
            session->cli_info.cli_pid, session->cli_info.start_time);
        cm_sleep(CM_SLEEP_500_FIXED);
    }
    LOG_DEBUG_INF("Succeed to lock session %u shm lock", session->id);
}

void dss_server_session_unlock(dss_session_t *session)
{
    cm_spin_unlock(&session->shm_lock);
    LOG_DEBUG_INF("Succeed to unlock session %u shm lock", session->id);
    cm_spin_unlock(&session->lock);
    LOG_DEBUG_INF("Succeed to unlock session %u lock", session->id);
}

#ifdef __cplusplus
}
#endif
