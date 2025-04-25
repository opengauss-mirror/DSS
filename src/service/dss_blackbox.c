/*
 * Copyright (c) 2023 Huawei Technologies Co.,Ltd.
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
 * dss_blackbox.c
 *
 *
 * IDENTIFICATION
 *    src/service/dss_blackbox.c
 *
 * -------------------------------------------------------------------------
 */
#ifndef WIN32
#include <cm_signal.h>
#include <mes_func.h>
#include <cm_backtrace.h>
#include "dss_file_def.h"
#include "dss_session.h"
#include "dss_instance.h"
#include "dss_diskgroup.h"
#include "dss_ga.h"
#include "dss_blackbox.h"
#include "config.h"

#ifdef __cplusplus
extern "C" {
#endif

int32 g_sign_array[] = {SIGHUP, SIGINT, SIGQUIT, SIGILL, SIGTRAP, SIGABRT, SIGBUS, SIGFPE, SIGSEGV, SIGUSR2, SIGALRM,
    SIGTERM, SIGSTKFLT, SIGTSTP, SIGTTIN, SIGTTOU, SIGXCPU, SIGXFSZ, SIGVTALRM, SIGPROF, SIGIO, SIGPWR, SIGSYS};

box_excp_item_t g_excep_info = {0};
static const char *g_core_state_file = "dss.core.state";
char g_dss_state_file[CM_FILE_NAME_BUFFER_SIZE] = {0};

sig_info_t g_known_signal_info[] = {
    {"Signal 0", TERMINATE_SIG},
    {"Hang up controlling terminal or process", TERMINATE_SIG},
    {"Interrupt from keyboard, Control-C", TERMINATE_SIG},
    {"Quit from keyboard, Control-\\", DUMP_SIG},
    {"Illegal instruction", DUMP_SIG},
    {"Breakpoint for debugging", DUMP_SIG},
    {"Abnormal termination", DUMP_SIG},
    {"Bus error", DUMP_SIG},
    {"Floating-point exception", DUMP_SIG},
    {"Forced-process termination", TERMINATE_SIG},
    {"User use", STOP_SIG},
    {"Invalid memory reference", DUMP_SIG},
    {"Available to processes", TERMINATE_SIG},
    {"Write to pipe with no readers", TERMINATE_SIG},
    {"Real-timer clock", TERMINATE_SIG},
    {"Process termination", TERMINATE_SIG},
    {"Coprocessor stack error", TERMINATE_SIG},
    {"Child process stopped or terminated", IGNORE_SIG},
    {"Resume execution, if stopped", CONTINUE_SIG},
    {"Stop process execution, Ctrl-Z", STOP_SIG},
    {"Stop process issued from tty", STOP_SIG},
    {"Background process requires input", STOP_SIG},
    {"Background process requires output", STOP_SIG},
    {"Urgent condition on socket", IGNORE_SIG},
    {"CPU time limit exceeded", DUMP_SIG},
    {"File size limit exceeded", DUMP_SIG},
    {"Virtual timer clock", TERMINATE_SIG},
    {"Profile timer clock", TERMINATE_SIG},
    {"Window resizing", IGNORE_SIG},
    {"I/O now possible", TERMINATE_SIG},
    {"Power supply failure", TERMINATE_SIG},
    {"Bad system call", DUMP_SIG},
};

static inline bool8 need_dump(int signum)
{
    if (signum >= 0 && signum < __SIGRTMIN) {
        return g_known_signal_info[signum].action == DUMP_SIG;
    }
    return CM_FALSE;
}

const char *const g_other_signal_format = "Real-time signal %d";
const char *const g_unknown_signal_format = "Unknown signal %d";

void dss_get_signal_info(int signum, char *buf, uint32 buf_size)
{
    int len;
    sig_info_t *sig_info = NULL;
    if (signum >= 0 && signum < __SIGRTMIN) {
        sig_info = &g_known_signal_info[signum];
        len = sprintf_s(buf, buf_size, "%s", sig_info->comment);
        if (len < 0) {
            buf[0] = 0x00;
        }
        return;
    }
#ifdef SIGRTMIN
    if (signum >= SIGRTMIN && signum <= SIGRTMAX) {
        len = snprintf_s(buf, buf_size, buf_size - 1, g_other_signal_format, signum - SIGRTMIN);
        if (len < 0) {
            buf[0] = 0x00;
        }
        return;
    }
#endif
}

static void dss_sig_collect_uds_lsnr_bt(uint32 log_id)
{
    uds_lsnr_t *lsnr = &g_dss_instance.lsnr;
    if (lsnr->status == LSNR_STATUS_RUNNING) {
        cm_sig_collect_backtrace(log_id, &lsnr->thread, "uds_lsnr");
    }
}

static void dss_sig_collect_timer_bt(uint32 log_id)
{
    gs_timer_t *timer = g_timer();
    if (!timer->init) {
        return;
    }
    cm_sig_collect_backtrace(log_id, &timer->thread, "timer");
}

static void dss_sig_collect_recovery_bt(uint32 log_id)
{
    uint32 recovery_thread_id = dss_get_udssession_startid() - (uint32)DSS_BACKGROUND_TASK_NUM;
    cm_sig_collect_backtrace(log_id, &(g_dss_instance.threads[recovery_thread_id]), "recovery");
}

static void dss_sig_collect_hashmap_dynamic_extend_and_redistribute_bt(uint32 log_id)
{
    uint32 hashmap_extend_idx = dss_get_hashmap_dynamic_extend_task_idx();
    cm_sig_collect_backtrace(
        log_id, &(g_dss_instance.threads[hashmap_extend_idx]), "hashmap_dynamic_extend_and_redistribute");
}

static void dss_sig_collect_alarm_check_bt(uint32 log_id)
{
    uint32 vg_usage_thread_id = dss_get_alarm_check_task_idx();
    cm_sig_collect_backtrace(log_id, &(g_dss_instance.threads[vg_usage_thread_id]), "alarm_check");
}

static void dss_sig_collect_delay_clean_bt(uint32 log_id)
{
    uint32 delay_clean_thread_id = dss_get_delay_clean_task_idx();
    cm_sig_collect_backtrace(log_id, &(g_dss_instance.threads[delay_clean_thread_id]), "delay_clean");
}

static void dss_sig_collect_recycle_meta_task_bt(uint32 log_id)
{
    uint32 task_num = g_vgs_info->group_num;
    if (task_num > DSS_RECYLE_META_TASK_NUM_MAX) {
        task_num = DSS_RECYLE_META_TASK_NUM_MAX;
    }
    for (uint32 i = 0; i < task_num; i++) {
        uint32 work_idx = dss_get_recycle_meta_task_idx(i);
        cm_sig_collect_backtrace(log_id, &(g_dss_instance.threads[work_idx]), "recycle_meta %u", i);
    }
}

static void dss_sig_collect_meta_syn_bt(uint32 log_id)
{
    uint32 task_num = g_vgs_info->group_num;
    if (task_num > DSS_META_SYN_BG_TASK_NUM_MAX) {
        task_num = DSS_META_SYN_BG_TASK_NUM_MAX;
    }
    for (uint32 i = 0; i < task_num; i++) {
        uint32 work_idx = dss_get_meta_syn_task_idx(i);
        cm_sig_collect_backtrace(log_id, &(g_dss_instance.threads[work_idx]), "meta_syn %u", i);
    }
}
static void dss_sig_collect_mes_task_bt(uint32 log_id)
{
    uint32 count = mes_get_started_task_count(CM_FALSE);
    for (uint32 i = 0; i < count; i++) {
        cm_sig_collect_backtrace(log_id, &MES_GLOBAL_INST_MSG.recv_mq.tasks[i].thread, "mes task %d", i);
    }
}

static void dss_sig_collect_mes_listener_bt(uint32 log_id)
{
    mes_lsnr_t *lsnr = &MES_GLOBAL_INST_MSG.mes_ctx.lsnr;
    if (MES_GLOBAL_INST_MSG.profile.pipe_type == MES_TYPE_TCP) {
        tcp_lsnr_t *tcp_lsnr = &lsnr->tcp;
        cm_sig_collect_backtrace(log_id, &tcp_lsnr->thread, "tcp lsnr");
    }
}

static void dss_sig_collect_reactor_bt(uint32 log_id)
{
    reactor_t *reactor = NULL;
    reactors_t *pool = &g_dss_instance.reactors;
    for (uint32 i = 0; i < pool->reactor_count; i++) {
        reactor = &pool->reactor_arr[i];
        if (reactor->status != REACTOR_STATUS_RUNNING) {
            continue;
        }
        cm_sig_collect_backtrace(log_id, &reactor->iothread, "reactor %d", i);
    }
}

static void dss_sig_collect_background_bt(uint32 log_id)
{
    dss_sig_collect_mes_task_bt(log_id);
    dss_sig_collect_mes_listener_bt(log_id);
    dss_sig_collect_recovery_bt(log_id);
    dss_sig_collect_hashmap_dynamic_extend_and_redistribute_bt(log_id);
    dss_sig_collect_delay_clean_bt(log_id);
    dss_sig_collect_alarm_check_bt(log_id);
    dss_sig_collect_meta_syn_bt(log_id);
    dss_sig_collect_recycle_meta_task_bt(log_id);
    dss_sig_collect_uds_lsnr_bt(log_id);
    dss_sig_collect_timer_bt(log_id);
    dss_sig_collect_reactor_bt(log_id);
}

static void dss_sig_collect_work_session_bt(uint32 log_id)
{
    dss_session_ctrl_t *session_ctrl = dss_get_session_ctrl();
    for (uint32 i = 0; i < session_ctrl->alloc_sessions; i++) {
        dss_session_t *session = session_ctrl->sessions[i];
        if (session == NULL || session->is_closed) {
            continue;
        }
        dss_workthread_t *workthread_ctx = (dss_workthread_t *)session->workthread_ctx;
        if (workthread_ctx != NULL && workthread_ctx->status == THREAD_STATUS_PROCESSSING) {
            cm_sig_collect_backtrace(log_id, &workthread_ctx->thread_obj->thread, "session %d", session->id);
        }
    }
}

void dss_sig_collect_all_backtrace(uint32 log_id)
{
    dss_sig_collect_work_session_bt(log_id);
    dss_sig_collect_background_bt(log_id);
}

void dss_print_global_variable(uint32 log_id)
{
    DSS_LOG_BLACKBOX_OR_DYNAMIC_INF(log_id, "\n===============================global variable===============================\n");
    DSS_LOG_BLACKBOX_OR_DYNAMIC_INF(log_id, "g_is_dss_read_write is %u\n", dss_get_server_status_flag());
    DSS_LOG_BLACKBOX_OR_DYNAMIC_INF(log_id, "g_master_instance_id is %u\n", dss_get_master_id());
    DSS_LOG_BLACKBOX_OR_DYNAMIC_INF(log_id, "dss_instance status is %u, is_maintain is %u.\n",
        (uint32)g_dss_instance.status, (uint32)g_dss_instance.is_maintain);
    dss_config_t *cfg = dss_get_inst_cfg();
    dss_nodes_list_t nodes_list = cfg->params.nodes_list;
    DSS_LOG_BLACKBOX_OR_DYNAMIC_INF(log_id, "inst cnt is %u, inst_map is %llu, inst_work_status_map is %llu.\n",
        nodes_list.inst_cnt, nodes_list.inst_map, g_dss_instance.inst_work_status_map);
    for (uint32 i = 0; i < DSS_MAX_INSTANCES; i++) {
        if (nodes_list.ports[i] != 0) {
            DSS_LOG_BLACKBOX_OR_DYNAMIC_INF(
                log_id, "%u: node_ip is %s, port is %hu.\n", i, nodes_list.nodes[i], nodes_list.ports[i]);
        }
    }
}

void dss_print_effect_param(uint32 log_id)
{
    uint32 audit_level = cm_log_param_instance()->audit_level;
    uint32 log_level = cm_log_param_instance()->log_level;
    DSS_LOG_BLACKBOX_OR_DYNAMIC_INF(
        log_id, "\n===============================key param===============================\n");
    DSS_LOG_BLACKBOX_OR_DYNAMIC_INF(log_id, "_LOG_LEVEL is %u.\n", log_level);
    DSS_LOG_BLACKBOX_OR_DYNAMIC_INF(log_id, "_AUDIT_LEVEL is %u.\n", audit_level);
}

void dss_write_block_pool(uint32 log_id, int32 handle, int64 *length, ga_pool_id_e pool_id)
{
    ga_pool_t *pool = &g_app_pools[GA_POOL_IDX((uint32)pool_id)];
    if (pool == NULL) {
        DSS_LOG_BLACKBOX_OR_DYNAMIC_INF(log_id, "Failed to get ga pool\n.");
        return;
    }
    if (pool->ctrl->ex_count > GA_MAX_EXTENDED_POOLS) {
        LOG_RUN_ERR("Invalid pool info[id=%u]: ex_count is %u, larger than maximum %u", pool_id, pool->ctrl->ex_count,
            GA_MAX_EXTENDED_POOLS);
        return;
    }
    uint32 object_cost = pool->ctrl->def.object_size + (uint32)sizeof(ga_object_map_t);
    uint64 ex_pool_size = (uint64)object_cost * pool->ctrl->def.object_count;
    uint64 total_size = pool->capacity + ex_pool_size * pool->ctrl->ex_count;
    status_t ret = dss_write_shm_memory_file_inner(handle, length, &total_size, sizeof(uint64));
    if (ret != CM_SUCCESS) {
        DSS_LOG_BLACKBOX_OR_DYNAMIC_INF(log_id, "Failed to write ga pool size, pool id is %u\n.", (uint32)pool_id);
    }
    ret = dss_write_shm_memory_file_inner(handle, length, (char *)pool->addr, (int32)pool->capacity);
    if (ret != CM_SUCCESS) {
        DSS_LOG_BLACKBOX_OR_DYNAMIC_INF(log_id, "Failed to write init ga pool, pool id is %u\n.", (uint32)pool_id);
    }
    for (uint32 i = 0; i < pool->ctrl->ex_count; i++) {
        ret = dss_write_shm_memory_file_inner(handle, length, pool->ex_pool_addr[i], (int32)ex_pool_size);
        if (ret != CM_SUCCESS) {
            DSS_LOG_BLACKBOX_OR_DYNAMIC_INF(
                log_id, "Failed to write extend ga pool, pool id is %u, ex_num is %u\n.", (uint32)pool_id, i);
        }
    }
}

static void dss_update_shm_memory_length(uint32 log_id, int32 handle, int64 length, int64 begin)
{
    int64 end = cm_seek_file(handle, 0, SEEK_CUR);
    if (end == -1) {
        DSS_LOG_BLACKBOX_OR_DYNAMIC_INF(log_id, "Failed to seek file %d", handle);
        return;
    }
    int64 offset = cm_seek_file(handle, begin, SEEK_SET);
    if (offset == -1) {
        DSS_LOG_BLACKBOX_OR_DYNAMIC_INF(log_id, "Failed to seek file %d", handle);
        return;
    }
    status_t ret = cm_write_file(handle, &length, sizeof(int64));
    if (ret != CM_SUCCESS) {
        DSS_LOG_BLACKBOX_OR_DYNAMIC_INF(log_id, "Failed to update length %lld\n.", length);
    }
    offset = cm_seek_file(handle, end, SEEK_SET);
    if (offset == -1) {
        DSS_LOG_BLACKBOX_OR_DYNAMIC_INF(log_id, "Failed to seek file %d", handle);
    }
}

// length| vg_num| software_version|vg_name|dss_ctrl|software_version|vg_name|dss_ctrl|...
void dss_write_share_vg_info(uint32 log_id, int32 handle)
{
    int64 length = 0;
    int64 begin = cm_seek_file(handle, 0, SEEK_CUR);
    if (begin == -1) {
        DSS_LOG_BLACKBOX_OR_DYNAMIC_INF(log_id, "Failed to seek file %d", handle);
    }
    status_t status = dss_write_shm_memory_file_inner(handle, &length, &length, sizeof(int64));
    if (status != CM_SUCCESS) {
        DSS_LOG_BLACKBOX_OR_DYNAMIC_INF(log_id, "Failed to write length %lld\n.", length);
    }
    status = dss_write_shm_memory_file_inner(handle, &length, &g_vgs_info->group_num, sizeof(uint32_t));
    if (status != CM_SUCCESS) {
        DSS_LOG_BLACKBOX_OR_DYNAMIC_INF(log_id, "Failed to write vg num %u\n.", g_vgs_info->group_num);
    }
    for (uint32 i = 0; i < g_vgs_info->group_num; i++) {
        dss_vg_info_item_t *vg = &g_vgs_info->volume_group[i];
        uint32 software_version = dss_get_software_version(&vg->dss_ctrl->vg_info);
        status = dss_write_shm_memory_file_inner(handle, &length, &software_version, sizeof(uint32_t));
        if (status != CM_SUCCESS) {
            DSS_LOG_BLACKBOX_OR_DYNAMIC_INF(log_id, "Failed to write software version %u.\n", software_version);
        }
        status = dss_write_shm_memory_file_inner(handle, &length, vg->dss_ctrl->vg_info.vg_name, DSS_MAX_NAME_LEN);
        if (status != CM_SUCCESS) {
            DSS_LOG_BLACKBOX_OR_DYNAMIC_INF(log_id, "Failed to write vg name %s\n.", vg->dss_ctrl->vg_info.vg_name);
        }
        status = dss_write_shm_memory_file_inner(handle, &length, vg->dss_ctrl, sizeof(dss_ctrl_t));
        if (status != CM_SUCCESS) {
            DSS_LOG_BLACKBOX_OR_DYNAMIC_INF(log_id, "Failed to write ctrl info of vg %u\n.", i);
        }
    }
    dss_update_shm_memory_length(log_id, handle, length, begin);
}

// length|
// vg_num|vg_name|size|dirs|vg_name|size|dirs|...|pool_size|pool->addr|pool->ex_pool_addr[0]|...|pool->ex_pool_addr[excount-1]|...
void dss_write_hashmap_and_pool_info(uint32 log_id, int32 handle)
{
    int64 length = 0;
    int64 begin = cm_seek_file(handle, 0, SEEK_CUR);
    if (begin == -1) {
        DSS_LOG_BLACKBOX_OR_DYNAMIC_INF(log_id, "Failed to seek file %d", handle);
    }
    status_t ret = dss_write_shm_memory_file_inner(handle, &length, &length, sizeof(int64));
    if (ret != CM_SUCCESS) {
        DSS_LOG_BLACKBOX_OR_DYNAMIC_INF(log_id, "Failed to write length %lld\n.", length);
    }
    ret = dss_write_shm_memory_file_inner(handle, &length, &g_vgs_info->group_num, sizeof(uint32_t));
    if (ret != CM_SUCCESS) {
        DSS_LOG_BLACKBOX_OR_DYNAMIC_INF(log_id, "Failed to write vg num %u\n.", g_vgs_info->group_num);
    }
    uint64 dir_size = DSS_MAX_SEGMENT_NUM * (uint32)sizeof(uint32_t);
    for (uint32 i = 0; i < g_vgs_info->group_num; i++) {
        dss_vg_info_item_t *vg = &g_vgs_info->volume_group[i];
        ret = dss_write_shm_memory_file_inner(handle, &length, vg->dss_ctrl->vg_info.vg_name, DSS_MAX_NAME_LEN);
        if (ret != CM_SUCCESS) {
            DSS_LOG_BLACKBOX_OR_DYNAMIC_INF(log_id, "Failed to write vg name %s\n.", vg->dss_ctrl->vg_info.vg_name);
        }
        ret = dss_write_shm_memory_file_inner(handle, &length, vg->buffer_cache, sizeof(shm_hashmap_t));
        if (ret != CM_SUCCESS) {
            DSS_LOG_BLACKBOX_OR_DYNAMIC_INF(
                log_id, "Failed to write vg buffer cache %s\n.", vg->dss_ctrl->vg_info.vg_name);
        }
        shm_hash_ctrl_t *hash_ctrl = &vg->buffer_cache->hash_ctrl;
        uint32 *dirs = (uint32 *)OFFSET_TO_ADDR(hash_ctrl->dirs);
        ret = dss_write_shm_memory_file_inner(handle, &length, (char *)dirs, (int32)dir_size);
        if (ret != CM_SUCCESS) {
            DSS_LOG_BLACKBOX_OR_DYNAMIC_INF(log_id, "Failed to write hashmap dir of vg %u\n.", i);
        }
    }
    dss_write_block_pool(log_id, handle, &length, GA_8K_POOL);
    dss_write_block_pool(log_id, handle, &length, GA_16K_POOL);
    dss_write_block_pool(log_id, handle, &length, GA_FS_AUX_POOL);
    dss_write_block_pool(log_id, handle, &length, GA_SEGMENT_POOL);
    dss_update_shm_memory_length(log_id, handle, length, begin);
}

void dss_write_shm_memory(uint32 log_id)
{
    dss_config_t *inst_cfg = dss_get_inst_cfg();
    bool32 blackbox_detail_on = inst_cfg->params.blackbox_detail_on;
    if (!blackbox_detail_on) {
        DSS_LOG_BLACKBOX_OR_DYNAMIC_INF(log_id, "_BLACKBOX_DETAIL_ON is FALSE, no need to print shm_memory.\n.");
        return;
    }
    int32 handle = 0;
    char timestamp[CM_MAX_NAME_LEN] = {0};
    char file_name[CM_FILE_NAME_BUFFER_SIZE] = {0};
    date_detail_t detail = g_timer()->detail;
    errno_t errcode = snprintf_s(timestamp, CM_MAX_NAME_LEN, CM_MAX_NAME_LEN - 1, "%4u%02u%02u%02u%02u%02u%03u",
        detail.year, detail.mon, detail.day, detail.hour, detail.min, detail.sec, detail.millisec);
    if (SECUREC_UNLIKELY(errcode == -1)) {
        DSS_LOG_BLACKBOX_OR_DYNAMIC_INF(log_id, "print dss_shm_file failed.");
        return;
    }
    if (log_id == CM_LOG_BLACKBOX) {
        errcode = snprintf_s(file_name, CM_FILE_NAME_BUFFER_SIZE, CM_FILE_NAME_BUFFER_SIZE - 1, "%s/%s/%s_%s",
            cm_log_param_instance()->log_home, "blackbox", "dss_shm", timestamp);
    } else {
        errcode = snprintf_s(file_name, CM_FILE_NAME_BUFFER_SIZE, CM_FILE_NAME_BUFFER_SIZE - 1, "%s/%s/%s_%s",
            cm_log_param_instance()->log_home, "dyn", "dss_shm", timestamp);
    }
    
    if (SECUREC_UNLIKELY(errcode == -1)) {
        DSS_LOG_BLACKBOX_OR_DYNAMIC_INF(log_id, "printf dss_shm_file failed.");
        return;
    }
    log_file_handle_t *log_file_handle = cm_log_logger_file(log_id);
    if (log_file_handle->file_handle == CM_INVALID_FD) {
        cm_log_create_dir(log_file_handle);
    }
    if (cm_open_file_ex(file_name, O_SYNC | O_CREAT | O_RDWR | O_TRUNC | O_BINARY, S_IRUSR | S_IWUSR, &handle) !=
        CM_SUCCESS) {
        DSS_LOG_BLACKBOX_OR_DYNAMIC_INF(log_id, "open %s failed.", file_name);
        return;
    }
    dss_write_share_vg_info(log_id, handle);
    dss_write_hashmap_and_pool_info(log_id, handle);
    cm_close_file(handle);
}
static void sig_print_excep_info(box_excp_item_t *excep_info, int32 sig_num, siginfo_t *siginfo, void *context)
{
    cm_reset_error();
    cm_proc_sig_get_header(excep_info, sig_num, siginfo, context);
    char signal_name[CM_NAME_BUFFER_SIZE];
    signal_name[0] = 0x00;
    dss_get_signal_info(sig_num, signal_name, sizeof(signal_name) - 1);
    int ret = strncpy_s(excep_info->sig_name, CM_NAME_BUFFER_SIZE, signal_name, strlen(signal_name));
    securec_check_panic(ret);
    cm_proc_get_register_info(&(excep_info->reg_info), (ucontext_t *)context);
    cm_print_sig_info(excep_info, (void *)&(excep_info->reg_info));
    cm_print_reg(&(excep_info->reg_info));
    cm_print_assembly(&(excep_info->reg_info));
    cm_print_call_link(&(excep_info->reg_info));
    cm_save_proc_maps_file(excep_info);
    cm_save_proc_meminfo_file();
    LOG_BLACKBOX_INF("\n===============================threads backtrace===============================\n");
    dss_sig_collect_all_backtrace(CM_LOG_BLACKBOX);
    dss_print_global_variable(CM_LOG_BLACKBOX);
    dss_print_effect_param(CM_LOG_BLACKBOX);
    dss_write_shm_memory(CM_LOG_BLACKBOX);
}

uint32 g_sign_mutex = 0;
void dss_exit_proc(int32 exit_code)
{
    while (CM_TRUE) {
        CM_MFENCE;
        if (g_sign_mutex == 0) {
            _exit(exit_code);
        }
        cm_sleep(CM_SLEEP_500_FIXED);
    }
    _exit(exit_code);
}

void dss_proc_sign_func_core(int32 sig_num, siginfo_t *sig_info, void *context, bool32 *dump)
{
    box_excp_item_t *excep_info = &g_excep_info;
    uint64 loc_id = 0;
    sigset_t sign_old_mask;
    sigset_t sign_mask;
    char signal_name[CM_NAME_BUFFER_SIZE] = {0};
    char date[CM_MAX_TIME_STRLEN] = {0};
    if (g_sign_mutex != 0) {
        return;
    }
    g_sign_mutex = 1;
    CM_MFENCE;
    (void)sigprocmask(0, NULL, &sign_old_mask);
    (void)sigfillset(&sign_mask);
    (void)sigprocmask(SIG_SETMASK, &sign_mask, NULL);
    if (!need_dump(sig_num)) {
        loc_id = excep_info->loc_id;
        dss_get_signal_info(sig_num, signal_name, sizeof(signal_name) - 1);
        (void)cm_date2str(g_timer()->now, "yyyy-mm-dd hh24:mi:ss.ff3", date, CM_MAX_TIME_STRLEN);
        LOG_BLACKBOX_INF("Location[0x%016llx] has been terminated, signum : %d, signal name : %s, current data : %s\n",
            loc_id, sig_num, signal_name, date);
        cm_fync_logfile();
        g_sign_mutex = 0;
        (void)sigprocmask(SIG_SETMASK, &sign_old_mask, NULL);
        return;
    }
    status_t ret = dss_update_state_file(CM_TRUE);
    if (ret != CM_SUCCESS) {
        LOG_RUN_WAR("Failed to update core state file.");
        cm_reset_error();
    }
    if (excep_info != NULL) {
        sig_print_excep_info(excep_info, sig_num, sig_info, context);
    }
    cm_fync_logfile();
    *dump = CM_TRUE;
}

void dss_proc_sign_func(int32 sig_num, siginfo_t *sig_info, void *context)
{
    bool32 need_dump = CM_FALSE;
    dss_proc_sign_func_core(sig_num, sig_info, context, &need_dump);
    if (need_dump) {
        (void)signal(SIGABRT, SIG_DFL);
        abort();
    }
}

status_t dss_update_state_file(bool32 coredump)
{
    if (strlen(g_dss_state_file) == 0) {
        PRTS_RETURN_IFERR(snprintf_s(g_dss_state_file, CM_FILE_NAME_BUFFER_SIZE, CM_FILE_NAME_BUFFER_SIZE - 1, "%s/%s",
            g_inst_cfg->home, g_core_state_file));
    }
    if (!g_inst_cfg->params.enable_core_state_collect || !coredump) {
        if (cm_file_exist(g_dss_state_file)) {
            (void)cm_remove_file(g_dss_state_file);
        }
        return CM_SUCCESS;
    }
    FILE *fp;
    CM_RETURN_IFERR(cm_fopen(g_dss_state_file, "w+", S_IRUSR | S_IWUSR, &fp));
    int32 size = fprintf(fp, "%u", (uint32)coredump);
    (void)fflush(stdout);
    if (size < 0) {
        LOG_DEBUG_ERR("write core state failed, write size is %d.", size);
        (void)fclose(fp);
        return CM_ERROR;
    }
    (void)fclose(fp);
    return CM_SUCCESS;
}

static status_t dss_sigcap_reg_proc(int32 sig_num)
{
    status_t ret = cm_regist_signal_restart(sig_num, dss_proc_sign_func);
    if (ret != CM_SUCCESS) {
        LOG_DEBUG_ERR("Register the signal cap failed:%d", sig_num);
        return CM_ERROR;
    }
    LOG_DEBUG_INF("Register the signal cap success:%d", sig_num);
    return CM_SUCCESS;
}

static status_t dss_sig_reg_backtrace()
{
    status_t ret = cm_regist_signal_restart(SIG_BACKTRACE, cm_sig_backtrace_func);
    if (ret != CM_SUCCESS) {
        LOG_DEBUG_ERR("Register the signal backtrace failed");
        return CM_ERROR;
    }
    LOG_DEBUG_INF("Register the signal backtrace success");
    return CM_SUCCESS;
}

static status_t dss_proc_sign_init()
{
    if (cm_proc_sign_init(&g_excep_info) != CM_SUCCESS) {
        return CM_ERROR;
    }
    cm_proc_sig_get_fixed_header(&g_excep_info);
    char *version = (char *)DEF_DSS_VERSION;
    errno_t errcode = strncpy_s(g_excep_info.version, BOX_VERSION_LEN, version, strlen(version));
    if (errcode != EOK) {
        CM_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

// 37 is occupied by hotpatch
#define SIG_HOTPATCH (37)

status_t dss_sigcap_handle_reg()
{
    cm_init_backtrace_handle();
    if (dss_proc_sign_init() != CM_SUCCESS) {
        return CM_ERROR;
    }
    for (uint32 sig_num = 0; sig_num < ARRAY_NUM(g_sign_array); sig_num++) {
        if (dss_sigcap_reg_proc(g_sign_array[sig_num]) != CM_SUCCESS) {
            return CM_ERROR;
        }
    }
    for (uint32 sig_num = SIGRTMIN; sig_num <= SIGRTMAX; sig_num++) {
        if (sig_num == SIG_BACKTRACE || sig_num == SIG_HOTPATCH || sig_num == SIG_DYN_LOG) {
            continue;
        }
        if (dss_sigcap_reg_proc(sig_num) != CM_SUCCESS) {
            return CM_ERROR;
        }
    }
    return dss_sig_reg_backtrace();
}

#ifdef __cplusplus
}
#endif

#endif