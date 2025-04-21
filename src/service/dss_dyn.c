/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
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
 * dss_dyn.c
 *
 *
 * IDENTIFICATION
 *    src/service/dss_dyn.c
 *
 * -------------------------------------------------------------------------
 */
#ifndef WIN32
#include "cm_signal.h"
#include "mes_func.h"
#include "dss_ctrl_def.h"
#include "dss_diskgroup.h"
#include "dss_file.h"
#include "dss_open_file.h"
#include "dss_reactor.h"
#include "dss_instance.h"
#include "dss_session.h"
#include "dss_blackbox.h"
#include "dss_mes.h"
#include "dss_dyn.h"

#ifdef __cplusplus
extern "C" {
#endif

void dss_print_latch_info()
{
    LOG_DYNAMIC_INF("\n===============================latch info===============================\n");
    for (uint32 i = 0; i < g_vgs_info->group_num; i++) {
        dss_vg_info_item_t *vg = &g_vgs_info->volume_group[i];
        dss_shared_latch_t *vg_latch = vg->vg_latch;
        LOG_DYNAMIC_INF("vg_latch info of vg %s:\n", vg->vg_name);
        LOG_DYNAMIC_INF(
            "shared_count %hu, stat %hu, sid %hu, shared_count_bak %hu, stat_bak %hu, shared_sid_count %llu,"
            " shared_sid_count_bak %llu\n",
            vg_latch->latch.shared_count, vg_latch->latch.stat, vg_latch->latch.sid,
            vg_latch->latch_extent.shared_count_bak, vg_latch->latch_extent.stat_bak,
            vg_latch->latch_extent.shared_sid_count, vg_latch->latch_extent.shared_sid_count_bak);
        latch_t disk_latch = vg->disk_latch;
        LOG_DYNAMIC_INF("disk_latch info of vg %s:\n", vg->vg_name);
        LOG_DYNAMIC_INF(
            "shared_count %hu, stat %hu, sid %hu.\n", disk_latch.shared_count, disk_latch.stat, disk_latch.sid);
    }
    latch_t switch_latch = g_dss_instance.switch_latch;
    LOG_DYNAMIC_INF(
        "switch_latch info:\nshared_count %hu, stat %hu, sid %hu.\n", switch_latch.shared_count, switch_latch.stat, switch_latch.sid);
}

void dss_print_shm_pool_info()
{
    LOG_DYNAMIC_INF("\n===============================shm pool info===============================\n");
    for (uint32 pool_id = GA_INSTANCE_POOL; pool_id <= GA_SEGMENT_POOL; pool_id++) {
        ga_pool_t *pool = &g_app_pools[GA_POOL_IDX(pool_id)];
        if (pool == NULL) {
            LOG_DYNAMIC_INF("Failed to get ga pool, pool_id is %u.\n", pool_id);
            return;
        }
        uint32 object_cost = pool->ctrl->def.object_size + (uint32)sizeof(ga_object_map_t);
        uint64 ex_pool_size = (uint64)object_cost * pool->ctrl->def.object_count;
        uint64 total_size = pool->capacity + ex_pool_size * pool->ctrl->ex_count;
        LOG_DYNAMIC_INF("pool_id %u, ex_count %u, object_size %u, total size %llu\n", pool_id, pool->ctrl->ex_count,
            pool->ctrl->def.object_size, total_size);
    }
}

void dss_print_open_file_info()
{
    LOG_DYNAMIC_INF("\n===============================open file info===============================\n");
    for (uint32 i = 0; i < g_vgs_info->group_num; i++) {
        dss_vg_info_item_t *vg = &g_vgs_info->volume_group[i];
        bilist_t *open_file_list = &vg->open_file_list;
        if (!dss_latch_timed_s(&vg->open_file_latch, DSS_LOCK_TIMEOUT_FOR_DYN)) {
            LOG_DYNAMIC_INF("No need to print vg %s open file info for lock timeout.\n", vg->vg_name);
            continue;
        }
        dss_open_file_info_t *open_file = NULL;
        bilist_node_t *node = cm_bilist_head(open_file_list);
        if (node == NULL) {
            LOG_DYNAMIC_INF("No open file list of vg %s.\n", vg->vg_name);
            dss_unlatch(&vg->open_file_latch);
            continue;
        }
        LOG_DYNAMIC_INF("open file list of vg %s, count %u.\n", vg->vg_name, open_file_list->count);
        for (; node != NULL; node = BINODE_NEXT(node)) {
            open_file = BILIST_NODE_OF(dss_open_file_info_t, node, link);
            LOG_DYNAMIC_INF("ftid %llu, pid %llu, ref %llu, start_time %lld\n", open_file->ftid, open_file->pid,
                open_file->ref, open_file->start_time);
        }
        dss_unlatch(&vg->open_file_latch);
    }
}

void dss_print_vg_usage_info(dss_session_t *session)
{
    LOG_DYNAMIC_INF("\n===============================vg usage===============================\n");
    if (dss_need_exec_local() && dss_is_readwrite() && (get_instance_status_proc() == DSS_STATUS_OPEN)) {
        for (uint32 i = 0; i < g_vgs_info->group_num; i++) {
            // check inst status, avoid affecting switchover
            if (get_instance_status_proc() != DSS_STATUS_OPEN) {
                LOG_DYNAMIC_INF("No need to print vg usage for instance is not open.\n");
                return;
            }
            dss_vg_info_item_t *vg = &g_vgs_info->volume_group[i];
            uint32 usage = 0;
            if (!dss_lock_vg_mem_and_shm_timed_s(session, vg, DSS_LOCK_TIMEOUT_FOR_DYN)) {
                LOG_DYNAMIC_INF("No need to print vg %s usage for lock timeout.\n", vg->vg_name);
                continue;
            }
            status_t status = dss_calculate_vg_usage(session, vg, &usage);
            if (status == CM_ERROR) {
                dss_unlock_vg_mem_and_shm(session, vg);
                LOG_DYNAMIC_INF("Failed to print vg %s usage.\n", vg->vg_name);
                break;
            }
            LOG_DYNAMIC_INF("vg %s usage is %u%%.\n", vg->vg_name, usage);
            dss_unlock_vg_mem_and_shm(session, vg);
        }
    } else {
        LOG_DYNAMIC_INF("No need to print vg usage for standby dss.\n");
    }
}

void dss_print_session_info()
{
    uint32 start_sid = dss_get_udssession_startid();
    uint32 end_sid = g_dss_session_ctrl.alloc_sessions;
    LOG_DYNAMIC_INF("\n===============================session info===============================\n");
    LOG_DYNAMIC_INF("session start_sid %u, end_sid %u.\n", start_sid, end_sid);
    for (uint32 i = start_sid; i < end_sid; i++) {
        dss_session_t *session = g_dss_session_ctrl.sessions[i];
        if (!session->is_used) {
            continue;
        }
        LOG_DYNAMIC_INF("session id %u, object id %u, is_closed %u, connected %u, reactor_added %u, client_version %u, "
                        "proto_version %u.\n",
            session->id, session->objectid, session->is_closed, session->connected, session->reactor_added,
            session->client_version, session->proto_version);
    }
}

void dss_print_reactor_info()
{
    reactors_t *pool = &g_dss_instance.reactors;
    reactor_t *reactor = NULL;
    LOG_DYNAMIC_INF("\n===============================reactor info===============================\n");
    LOG_DYNAMIC_INF("reactor count is %u.\n", pool->reactor_count);
    for (uint32 i = 0; i < pool->reactor_count; i++) {
        reactor = &pool->reactor_arr[i];
        if (reactor->status != REACTOR_STATUS_RUNNING) {
            LOG_DYNAMIC_INF("reactor(%u) status is %u, no need to print detail info.\n", i, reactor->status);
            continue;
        }
        LOG_DYNAMIC_INF("reactor id %u, epollfd %d, session_count %u, status %u, workthread_count %u.\n", reactor->id,
            reactor->epollfd, reactor->session_count, reactor->status, reactor->workthread_count);
        for (uint32 j = 0; j < reactor->workthread_count; j++) {
            if (reactor->workthread_ctx[j].status == THREAD_STATUS_IDLE) {
                continue;
            }
            LOG_DYNAMIC_INF("\tworkthread_ctx id %u, status %u.\n", j, reactor->workthread_ctx[j].status);
        }
    }
}

void dss_print_mes_message()
{
    mes_task_priority_info_t info;
    LOG_DYNAMIC_INF("\n===============================mes buffer pool===============================\n");
    for (uint32 prio = 0; prio < DSS_MES_PRIO_CNT; prio++) {
        status_t ret = mes_get_worker_priority_info(prio, &info);
        if (ret != CM_SUCCESS) {
            LOG_DYNAMIC_INF("Failed to get prio %u work info.\n", prio);
            continue;
        }
        LOG_DYNAMIC_INF("prio %u work info, worker_num %d, inqueue_msgitem_num %llu, finished_msgitem_num %llu.\n",
            prio, info.worker_num, info.inqueue_msgitem_num, info.finished_msgitem_num);
    }
}

static void dss_dyn_log_sign_func(dss_session_t *session, siginfo_t *siginfo)
{
    char date[CM_MAX_TIME_STRLEN] = {0};
    (void)cm_date2str(g_timer()->now, "yyyy-mm-dd hh24:mi:ss.ff3", date, CM_MAX_TIME_STRLEN);
    LOG_DYNAMIC_INF("begin one record, time: %s", date);
    LOG_DYNAMIC_INF("\n===============================threads backtrace===============================\n");
    dss_sig_collect_all_backtrace(CM_LOG_DYNAMIC);
    dss_print_global_variable(CM_LOG_DYNAMIC);
    dss_print_effect_param(CM_LOG_DYNAMIC);
    dss_print_latch_info();
    dss_print_shm_pool_info();
    dss_print_open_file_info();
    dss_print_session_info();
    dss_print_reactor_info();
    dss_print_vg_usage_info(session);
    dss_print_mes_message();
    dss_write_shm_memory(CM_LOG_DYNAMIC);
    (void)cm_date2str(g_timer()->now, "yyyy-mm-dd hh24:mi:ss.ff3", date, CM_MAX_TIME_STRLEN);
    LOG_DYNAMIC_INF("end one record, time: %s.\n\n", date);
}

void dss_dyn_log_proc(thread_t *thread)
{
    cm_set_thread_name("dyn_log");
    uint32 work_idx = dss_get_dyn_log_task_idx();
    dss_session_ctrl_t *session_ctrl = dss_get_session_ctrl();
    dss_session_t *session = session_ctrl->sessions[work_idx];
    siginfo_t sig_info;
    sigset_t dyn_log_signal;
    sigemptyset(&dyn_log_signal);
    sigaddset(&dyn_log_signal, SIG_DYN_LOG);
    uid_t uid = getuid();
    struct timespec timeout = {0, DSS_DYN_SIG_WAIT_TIME_NS};
    status_t ret;
    while (!thread->closed) {
        ret = sigtimedwait(&dyn_log_signal, &sig_info, &timeout);
        if (ret != -1) {
            if (sig_info.si_code > 0 || uid != sig_info.si_uid) {
                LOG_DEBUG_INF("[DYN] cannot record dyn log, si_code:%d, si_uid:%d", sig_info.si_code, sig_info.si_uid);
                continue;
            }
            dss_dyn_log_sign_func(session, &sig_info);
        } else {
            if (errno != EAGAIN && errno != EINTR) {
                LOG_DEBUG_INF("[DYN] waiting for dyn log signal failed, errno: %d(%s)", errno, strerror(errno));
            }
        }
    }
    LOG_RUN_INF("[DYN] dyn log thread closed");
}

#ifdef __cplusplus
}
#endif

#endif