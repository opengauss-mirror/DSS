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

#include "cm_utils.h"
#include "dss_diskgroup.h"
#include "dss_malloc.h"
#include "dss_file.h"
#include "dss_redo.h"
#include "dss_session.h"

#ifdef __cplusplus
extern "C" {
#endif

dss_session_ctrl_t g_dss_session_ctrl = {0, 0, 0, 0, NULL};
int dss_init_session(uint32 max_session_num)
{
    uint32 objectid;
    objectid = ga_alloc_object(GA_SESSION_POOL, DSS_INVALID_ID32);
    if (objectid == DSS_INVALID_ID32) {
        return ERR_DSS_GA_INIT;
    }

    g_dss_session_ctrl.sessions = (dss_session_t *)ga_object_addr(GA_SESSION_POOL, objectid);
    if (g_dss_share_vg_info == NULL) {
        return ERR_DSS_GA_INIT;
    }

    uint32 dss_session_size = (uint32)(max_session_num * sizeof(dss_session_t));
    errno_t errcode = memset_s(g_dss_session_ctrl.sessions, dss_session_size, 0, dss_session_size);
    securec_check_ret(errcode);
    for (uint32 i = 0; i < max_session_num; ++i) {
        g_dss_session_ctrl.sessions[i].id = i;
        g_dss_session_ctrl.sessions[i].is_used = CM_FALSE;
        g_dss_session_ctrl.sessions[i].is_closed = CM_TRUE;
        g_dss_session_ctrl.sessions[i].log_split = DSS_INVALID_SLOT;
    }
    g_dss_session_ctrl.total = max_session_num;
    g_dss_session_ctrl.is_inited = CM_TRUE;
    return CM_SUCCESS;
}

dss_session_ctrl_t *dss_get_session_ctrl(void)
{
    return &g_dss_session_ctrl;
}

status_t dss_create_session(const cs_pipe_t *pipe, dss_session_t **session)
{
    uint32 i, id;

    *session = NULL;
    id = DSS_INVALID_ID32;
    dss_config_t *inst_cfg = dss_get_inst_cfg();
    cm_spin_lock(&g_dss_session_ctrl.lock, NULL);

    uint32 start_sid = 0;
    if (inst_cfg->params.inst_cnt > 1) {
        start_sid = inst_cfg->params.channel_num + inst_cfg->params.work_thread_cnt;
    }
    uint32 end_sid = start_sid + inst_cfg->params.cfg_session_num;

    for (i = start_sid; i < end_sid; i++) {
        if (g_dss_session_ctrl.sessions[i].is_used == CM_FALSE) {
            id = i;
            break;
        }
    }

    if (id == DSS_INVALID_ID32) {
        cm_spin_unlock(&g_dss_session_ctrl.lock);
        return ERR_DSS_SESSION_CREATE;
    }
    g_dss_session_ctrl.used_count++;
    g_dss_session_ctrl.sessions[id].is_used = CM_TRUE;
    cm_spin_unlock(&g_dss_session_ctrl.lock);
    errno_t errcode;
    dss_latch_stack_t *latch_stack = &g_dss_session_ctrl.sessions[id].latch_stack;
    errcode = memset_s(latch_stack, sizeof(dss_latch_stack_t), 0, sizeof(dss_latch_stack_t));
    securec_check_ret(errcode);

    g_dss_session_ctrl.sessions[id].is_direct = CM_TRUE;
    g_dss_session_ctrl.sessions[id].pipe = *pipe;
    g_dss_session_ctrl.sessions[id].is_closed = CM_FALSE;
    *session = &g_dss_session_ctrl.sessions[id];
    return CM_SUCCESS;
}

void dss_destroy_session(dss_session_t *session)
{
    uint32 id = session->id;
    cs_disconnect(&session->pipe);
    cm_spin_lock(&g_dss_session_ctrl.lock, NULL);
    g_dss_session_ctrl.used_count--;
    g_dss_session_ctrl.sessions[id].is_closed = CM_TRUE;
    g_dss_session_ctrl.sessions[id].is_used = CM_FALSE;
    if (g_dss_session_ctrl.sessions[id].log_split != DSS_INVALID_SLOT) {
        dss_free_log_slot(&g_dss_session_ctrl.sessions[id]);
    }
    cm_spin_unlock(&g_dss_session_ctrl.lock);
}

static void dss_count_session_latch_core(const dss_session_ctrl_t *session_ctrl, dss_session_t *scan_session,
    const dss_latch_offset_t *latch_offset, uint32 *count, uint32 used_count)
{
    uint32 stack_top = scan_session->latch_stack.stack_top;
    for (uint32 i = 0; i < stack_top; i++) {
        dss_latch_offset_t *scan_latch_offset = &scan_session->latch_stack.latch_offset_stack[i];
        if (latch_offset->type != scan_latch_offset->type) {
            continue;
        }
        if (latch_offset->type == DSS_LATCH_OFFSET_UNIQ_ID) {
            if (latch_offset->offset.unique_id == scan_latch_offset->offset.unique_id) {
                *count += 1;
            }
            continue;
        }
        if (latch_offset->type == DSS_LATCH_OFFSET_SHMOFFSET) {
            if (latch_offset->offset.shm_offset == scan_latch_offset->offset.shm_offset) {
                *count += 1;
            }
            continue;
        }
        if (used_count >= session_ctrl->used_count) {
            break;
        }
    }
}

static void dss_count_session_latch(dss_session_ctrl_t *session_ctrl, const dss_session_t *session,
    const dss_latch_offset_t *latch_offset, uint32 *count)
{
    uint32 used_count = 0;
    CM_ASSERT(session_ctrl != NULL);
    CM_ASSERT(session != NULL);
    CM_ASSERT(latch_offset != NULL);
    CM_ASSERT(count != NULL);

    *count = 0;

    cm_spin_lock(&session_ctrl->lock, NULL);

    for (uint32 id = 0; id < session_ctrl->total; id++) {
        dss_session_t *scan_session = &session_ctrl->sessions[id];
        if (scan_session->is_used == CM_FALSE) {
            continue;
        }

        used_count++;
        if (scan_session->id == session->id) {
            if (used_count >= session_ctrl->used_count) {
                break;
            }
            continue;
        }
        dss_count_session_latch_core(session_ctrl, scan_session, latch_offset, count, used_count);
        if (used_count >= session_ctrl->used_count) {
            break;
        }
    }

    cm_spin_unlock(&session_ctrl->lock);
}

void dss_clean_session_latch(dss_session_ctrl_t *session_ctrl, dss_session_t *session)
{
    uint32 count = 0;
    int32 i = 0;
    sh_mem_p offset;
    int32 stack_top;
    latch_t *latch = NULL;

    CM_ASSERT(session != NULL);

    if (!session->is_direct) {
        LOG_DEBUG_ERR("session is not direct.");
        return;
    }

    stack_top = (int32)session->latch_stack.stack_top;

    for (i = stack_top; i >= DSS_MAX_LATCH_STACK_BOTTON; i--) {
        dss_latch_offset_type_e offset_type = session->latch_stack.latch_offset_stack[i].type;
        if ((i == stack_top) && (offset_type == DSS_LATCH_OFFSET_INVALID)) {
            continue;
        }

        if (offset_type == DSS_LATCH_OFFSET_SHMOFFSET) {
            offset = session->latch_stack.latch_offset_stack[i].offset.shm_offset;
            CM_ASSERT(offset != SHM_INVALID_ADDR);
            latch = (latch_t *)OFFSET_TO_ADDR(offset);
            LOG_DEBUG_INF("Clean session latch,i:%d, offset:%llu.", i, (uint64)offset);
        } else {
            LOG_DEBUG_ERR("latch offset type is invalid %u,i:%d.", session->latch_stack.latch_offset_stack[i].type, i);
            continue;
        }

        if (DSS_SESSIONID_IN_LOCK(session->id) != latch->lock) {
            cm_spin_lock_by_sid(DSS_SESSIONID_IN_LOCK(session->id), &latch->lock, NULL);
        }

        dss_count_session_latch(session_ctrl, session, &session->latch_stack.latch_offset_stack[i], &count);
        LOG_DEBUG_INF("Clean session latch, old count:%hu, new count:%u.", latch->shared_count, count);
        latch->shared_count = (uint16)count;
        session->latch_stack.latch_offset_stack[i].type = DSS_LATCH_OFFSET_INVALID;
        cm_spin_unlock(&latch->lock);
    }

    session->latch_stack.stack_top = DSS_MAX_LATCH_STACK_BOTTON;
}

static bool32 dss_is_timeout(int32 timeout, int32 sleep_times, int32 sleeps)
{
    if ((timeout == SPIN_WAIT_FOREVER) || (sleeps == 0)) {
        return CM_FALSE;
    }

    /* ms --> us, and translate to times */
    return (bool32)(((timeout * 1000) / (sleeps)) < sleep_times);
}

status_t dss_lock_shm_meta_s(dss_session_t *session, const dss_latch_offset_t *offset, latch_t *latch, int32 timeout)
{
    CM_ASSERT(session->latch_stack.stack_top < DSS_MAX_LATCH_STACK_DEPTH);
    session->latch_stack.latch_offset_stack[session->latch_stack.stack_top] = *offset;
    uint32 sid = DSS_SESSIONID_IN_LOCK(session->id);

    int32 sleep_times = 0;
    latch_statis_t *stat = NULL;
    uint32 count = 0;
    bool32 is_force = CM_FALSE;

    do {
        cm_spin_lock_by_sid(sid, &latch->lock, (stat != NULL) ? &stat->s_spin : NULL);

        if (latch->stat == LATCH_STATUS_IDLE) {
            latch->stat = LATCH_STATUS_S;
            latch->shared_count = 1;
            latch->sid = (uint16)sid;
            session->latch_stack.stack_top++;
            cm_spin_unlock(&latch->lock);
            cm_latch_stat_inc(stat, count);
            return CM_SUCCESS;
        }
        if ((latch->stat == LATCH_STATUS_S) || (latch->stat == LATCH_STATUS_IX && is_force)) {
            latch->shared_count++;
            session->latch_stack.stack_top++;
            cm_spin_unlock(&latch->lock);
            cm_latch_stat_inc(stat, count);
            return CM_SUCCESS;
        }
        cm_spin_unlock(&latch->lock);
        if (stat != NULL) {
            stat->misses++;
        }
        while (latch->stat != LATCH_STATUS_IDLE && latch->stat != LATCH_STATUS_S) {
            count++;
            if (count < GS_SPIN_COUNT) {
                continue;
            }

            SPIN_STAT_INC(stat, s_sleeps);
            cm_usleep(SPIN_SLEEP_TIME);
            sleep_times++;
            if (dss_is_timeout(timeout, sleep_times, SPIN_SLEEP_TIME)) {
                session->latch_stack.latch_offset_stack[session->latch_stack.stack_top].type = DSS_LATCH_OFFSET_INVALID;
                return CM_ERROR;
            }
            count = 0;
        }
    } while (1);
    return CM_SUCCESS;
}

status_t dss_cli_lock_shm_meta_s(
    dss_session_t *session, dss_latch_offset_t *offset, latch_t *latch, latch_should_exit should_exit)
{
    for (int i = 0; i < DSS_CLIENT_TIMEOUT_COUNT; i++) {
        if (dss_lock_shm_meta_s(session, offset, latch, DSS_CLIENT_TIMEOUT) == CM_SUCCESS) {
            return CM_SUCCESS;
        }

        if (should_exit && should_exit()) {
            LOG_RUN_ERR("Caller want to exit when waiting for latch!!");
            return ERR_DSS_LOCK_TIMEOUT;
        }
    }
    LOG_RUN_ERR("The client want to lock meta timeout.");
    return ERR_DSS_LOCK_TIMEOUT;
}

void dss_lock_shm_meta_x(const dss_session_t *session, latch_t *latch)
{
    latch_statis_t *stat = NULL;
    uint32 count = 0;
    uint32 sid = DSS_SESSIONID_IN_LOCK(session->id);

    do {
        cm_spin_lock_by_sid(sid, &latch->lock, (stat != NULL) ? &stat->x_spin : NULL);
        if (latch->stat == LATCH_STATUS_IDLE) {
            latch->sid = (uint16)sid;
            latch->stat = LATCH_STATUS_X;
            cm_spin_unlock(&latch->lock);
            cm_latch_stat_inc(stat, count);
            return;
        }
        if (latch->stat == LATCH_STATUS_S) {
            latch->stat = LATCH_STATUS_IX;
            cm_spin_unlock(&latch->lock);
            cm_latch_ix2x(latch, sid, stat);
            return;
        }
        cm_spin_unlock(&latch->lock);
        if (stat != NULL) {
            stat->misses++;
        }
        while (latch->stat != LATCH_STATUS_IDLE && latch->stat != LATCH_STATUS_S) {
            count++;
            if (count >= GS_SPIN_COUNT) {
                SPIN_STAT_INC(stat, x_sleeps);
                cm_spin_sleep();
                count = 0;
            }
        }
    } while (CM_TRUE);
}

void dss_unlock_shm_meta(dss_session_t *session, latch_t *latch)
{
    spin_statis_t *stat_spin = NULL;
    uint32 sid = DSS_SESSIONID_IN_LOCK(session->id);

    cm_spin_lock_by_sid(sid, &latch->lock, stat_spin);

    if (latch->shared_count > 0) {
        latch->shared_count--;
        CM_ASSERT(session->latch_stack.stack_top != DSS_MAX_LATCH_STACK_BOTTON);
        session->latch_stack.stack_top--;
    }

    if ((latch->stat == LATCH_STATUS_S || latch->stat == LATCH_STATUS_X) && (latch->shared_count == 0)) {
        latch->stat = LATCH_STATUS_IDLE;
    }

    cm_spin_unlock(&latch->lock);
    session->latch_stack.latch_offset_stack[session->latch_stack.stack_top].type = DSS_LATCH_OFFSET_INVALID;
}

#ifdef __cplusplus
}
#endif
