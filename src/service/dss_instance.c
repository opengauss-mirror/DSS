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
 * dss_instance.c
 *
 *
 * IDENTIFICATION
 *    src/service/dss_instance.c
 *
 * -------------------------------------------------------------------------
 */

#include "dss_ga.h"
#include "dss_shm.h"
#include "cm_timer.h"
#include "cm_error.h"
#include "dss_errno.h"
#include "dss_defs.h"
#include "dss_file.h"
#include "dss_malloc.h"
#include "dss_mes.h"
#include "dss_lsnr.h"
#include "dss_redo.h"
#include "dss_service.h"
#include "dss_signal.h"
#include "dss_instance.h"

dss_instance_t g_dss_instance;

static const char *const g_dss_lock_file = "dss.lck";

dss_log_def_t g_dss_instance_log[] = {
    {LOG_DEBUG, "debug/dssinstance.dlog"},
    {LOG_OPER, "oper/dssinstance.olog"},
    {LOG_RUN, "run/dssinstance.rlog"},
    {LOG_ALARM, "alarm/dssinstance.alog"},
    {LOG_AUDIT, "audit/dssinstance.aud"},
};

static void instance_set_pool_def(ga_pool_id_e pool_id, uint32 obj_count, uint32 obj_size, uint32 ex_max)
{
    ga_pool_def_t pool_def;

    CM_ASSERT(ex_max <= ((uint32)GA_MAX_EXTENDED_POOLS));
    pool_def.object_count = obj_count;
    pool_def.object_size = obj_size;
    pool_def.ex_max = ex_max;

    ga_set_pool_def(pool_id, &pool_def);
}

status_t dss_lock_instance(void)
{
    char file_name[CM_FILE_NAME_BUFFER_SIZE];
    int iret_snprintf;

    iret_snprintf = snprintf_s(file_name, CM_FILE_NAME_BUFFER_SIZE, CM_FILE_NAME_BUFFER_SIZE - 1, "%s/%s",
        g_dss_instance.inst_cfg.home, g_dss_lock_file);
    DSS_SECUREC_SS_RETURN_IF_ERROR(iret_snprintf, CM_ERROR);

    if (cm_open_file(file_name, O_CREAT | O_RDWR | O_BINARY, &g_dss_instance.lock_fd) != CM_SUCCESS) {
        return CM_ERROR;
    }

    if (cm_lock_fd(g_dss_instance.lock_fd) != CM_SUCCESS) {
        cm_close_file(g_dss_instance.lock_fd);
        g_dss_instance.lock_fd = CM_INVALID_INT32;
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

static status_t instance_init_ga(dss_instance_t *inst)
{
    int32 ret;
    uint32 sess_cnt = inst->inst_cfg.params.cfg_session_num + inst->inst_cfg.params.work_thread_cnt +
                      inst->inst_cfg.params.channel_num;
    uint32 dss_session_size = (uint32)(sess_cnt * sizeof(dss_session_t));
    ga_destroy_global_area();
    instance_set_pool_def(GA_INSTANCE_POOL, 1, DSS_INS_SIZE, 0);
    instance_set_pool_def(GA_SESSION_POOL, 1, dss_session_size, 0);
    instance_set_pool_def(GA_8K_POOL, DSS_MAX_MEM_BLOCK_SIZE / (DSS_BLOCK_SIZE + DSS_BLOCK_CTRL_SIZE),
        DSS_BLOCK_SIZE + DSS_BLOCK_CTRL_SIZE, GA_MAX_8K_EXTENDED_POOLS);
    instance_set_pool_def(GA_16K_POOL, DSS_MAX_MEM_BLOCK_SIZE / (DSS_FILE_SPACE_BLOCK_SIZE + DSS_BLOCK_CTRL_SIZE),
        DSS_FILE_SPACE_BLOCK_SIZE + DSS_BLOCK_CTRL_SIZE, GA_MAX_EXTENDED_POOLS);

    ret = ga_create_global_area();
    DSS_RETURN_IF_ERROR(ret);
    LOG_RUN_INF("Init GA pool and area successfully.");
    return CM_SUCCESS;
}

static status_t dss_init_thread(dss_instance_t *inst)
{
    uint32 cfg_session_num = inst->inst_cfg.params.cfg_session_num;
    inst->threads = (thread_t *)cm_malloc(cfg_session_num * (uint32)sizeof(thread_t));
    if (inst->threads == NULL) {
        return CM_ERROR;
    }
    errno_t errcode = memset_s(inst->threads, (cfg_session_num * (uint32)sizeof(thread_t)), 0x00,
        (cfg_session_num * (uint32)sizeof(thread_t)));
    securec_check_ret(errcode);
    return CM_SUCCESS;
}

status_t dss_load_log_buffer_sort_and_recover_direct(dss_redo_batch_t *batch, dss_redo_batch_t *tmp_batch)
{
    dss_vg_info_item_t *vg_item = &g_vgs_info->volume_group[0];
    int64 offset = (int64)dss_get_vg_au_size(vg_item->dss_ctrl);
    uint32 load_size = CM_CALC_ALIGN(tmp_batch->size + sizeof(dss_redo_batch_t), DSS_DISK_UNIT_SIZE);
    LOG_RUN_INF("Begin to load recovery log buf direct whose size is %u.", load_size);
    status_t status = dss_load_vg_ctrl_part(vg_item, offset, batch, (int32)load_size);
    DSS_RETURN_IFERR2(status, LOG_RUN_ERR("Failed to load recovery log buf."));
    return dss_recover_when_instance_start(batch, CM_TRUE);
}

status_t dss_load_log_buffer(dss_redo_batch_t *batch)
{
    dss_vg_info_item_t *vg_item = &g_vgs_info->volume_group[0];
    int64 base_offset = (int64)dss_get_vg_au_size(vg_item->dss_ctrl);
    int64 offset = 0;
    dss_redo_batch_t *tmp_batch = NULL;
    uint32 data_size;
    status_t status;
    char *tmp_log_buf = (char *)cm_malloc_align(DSS_DISK_UNIT_SIZE, DSS_INSTANCE_LOG_SPLIT_SIZE);
    if (tmp_log_buf == NULL) {
        DSS_RETURN_IFERR2(CM_ERROR, DSS_THROW_ERROR(ERR_ALLOC_MEMORY, DSS_DISK_UNIT_SIZE, "log_buf"));
    }
    for (uint8 i = 0; i < DSS_LOG_BUF_SLOT_COUNT; i++) {
        offset = base_offset + i * DSS_INSTANCE_LOG_SPLIT_SIZE;
        LOG_RUN_INF("begin to load log buf, offset:%lld, size:%u.", offset, DSS_DISK_UNIT_SIZE);
        status = dss_load_vg_ctrl_part(vg_item, offset, tmp_log_buf, DSS_DISK_UNIT_SIZE);
        DSS_BREAK_IFERR2(status, LOG_RUN_ERR("Failed to load log_buf from first vg ctrl when recover."));
        tmp_batch = (dss_redo_batch_t *)tmp_log_buf;
        if (tmp_batch->size == 0) {
            LOG_RUN_INF("size of log slot %u is 0, ignore.", i);
            continue;
        }
        LOG_RUN_INF("There are redo logs, size:%u, log_slot is %u.", tmp_batch->size, i);
        if (i == 0 && tmp_batch->in_recovery == CM_TRUE) {
            status = dss_load_log_buffer_sort_and_recover_direct(batch, tmp_batch);
            if (status != CM_SUCCESS) {
                LOG_RUN_ERR("Failed to load redo log.");
            }
            break;
        }
        uint32 load_size = CM_CALC_ALIGN(tmp_batch->size + sizeof(dss_redo_batch_t), DSS_DISK_UNIT_SIZE);
        if (load_size > DSS_INSTANCE_LOG_SPLIT_SIZE) {
            // invalid log ,ignored it.
            LOG_RUN_INF("Redo log slot %u is invalid, ignored it. size is %u, which is greater than %u", i, load_size,
                DSS_INSTANCE_LOG_SPLIT_SIZE);
            (void)dss_reset_log_slot_head(i);
            continue;
        }
        if (load_size > DSS_DISK_UNIT_SIZE) {
            status = dss_load_vg_ctrl_part(vg_item, offset, tmp_batch, (int32)load_size);
            DSS_BREAK_IFERR2(status, LOG_RUN_ERR("Failed to load redo log."));
        }
        if (!dss_check_redo_log_available(tmp_batch, vg_item, i)) {
            LOG_RUN_INF("Reset log when find uncompleted redo data, log slot is %u.", i);
            continue;
        }
        data_size = tmp_batch->size - DSS_REDO_BATCH_HEAD_SIZE;
        errno_t rc = memcpy_s(
            (char *)batch + batch->size, DSS_INSTANCE_LOG_BUFFER_SIZE - batch->size, tmp_batch->data, data_size);
        if (rc != EOK) {
            LOG_RUN_ERR("Failed to memcpy when recover.");
            status = CM_ERROR;
            break;
        }
        batch->size += data_size;
        batch->count += tmp_batch->count;
    }
    DSS_FREE_POINT(tmp_log_buf);
    return status;
}

status_t dss_check_vg_ctrl_valid(dss_vg_info_item_t *vg_item)
{
    dss_ctrl_t *dss_ctrl = vg_item->dss_ctrl;
    if (!DSS_VG_IS_VALID(dss_ctrl)) {
        DSS_RETURN_IFERR2(CM_ERROR, DSS_THROW_ERROR(ERR_DSS_VG_CHECK_NOT_INIT));
    }
    return CM_SUCCESS;
}

status_t dss_alloc_instance_log_buf(dss_instance_t *inst)
{
    LOG_RUN_INF("Begin to get instance log buf.");
    char *log_buf = (char *)cm_malloc_align(DSS_ALIGN_SIZE, DSS_INSTANCE_LOG_BUFFER_SIZE);
    if (log_buf == NULL) {
        DSS_RETURN_IFERR2(
            CM_ERROR, DSS_THROW_ERROR(ERR_ALLOC_MEMORY, DSS_INSTANCE_LOG_BUFFER_SIZE, "global log buffer"));
    }
    errno_t rc = memset_s(log_buf, sizeof(dss_redo_batch_t), 0, sizeof(dss_redo_batch_t));
    if (rc != EOK) {
        DSS_RETURN_IFERR3(CM_ERROR, LOG_RUN_ERR("Memset failed."), DSS_FREE_POINT(log_buf));
    }
    inst->kernel_instance->log_ctrl.log_buf = log_buf;
    return CM_SUCCESS;
}

status_t dss_recover_from_instance(dss_instance_t *inst)
{
    char *log_buf = inst->kernel_instance->log_ctrl.log_buf;
    dss_redo_batch_t *batch = (dss_redo_batch_t *)log_buf;
    batch->size = sizeof(dss_redo_batch_t);
    dss_vg_info_item_t *vg_item = &g_vgs_info->volume_group[0];
    if (dss_check_vg_ctrl_valid(vg_item) != CM_SUCCESS) {
        DSS_FREE_POINT(batch);
        inst->kernel_instance->log_ctrl.log_buf = NULL;
        return CM_ERROR;
    }
    LOG_RUN_INF("Try to load log buf head judge in use, sort and recover");
    if (dss_load_log_buffer(batch) != CM_SUCCESS) {
        DSS_FREE_POINT(batch);
        inst->kernel_instance->log_ctrl.log_buf = NULL;
        return CM_ERROR;
    }
    if (batch->size == 0 || batch->size == sizeof(dss_redo_batch_t)) {
        LOG_RUN_INF("No redo log need recover or log has been recovered and cleaned");
        return CM_SUCCESS;
    }
    LOG_RUN_INF(
        "Flush assemble log, whose size is %u, maybe greater than %u in recovery", batch->size, DSS_LOG_BUFFER_SIZE);
    if (dss_flush_log(0, vg_item, log_buf) != CM_SUCCESS) {
        LOG_RUN_ERR("Flush log failed.");
        DSS_FREE_POINT(batch);
        inst->kernel_instance->log_ctrl.log_buf = NULL;
        return CM_ERROR;
    }

    status_t status = dss_recover_when_instance_start(batch, CM_FALSE);
    if (status != CM_SUCCESS) {
        DSS_FREE_POINT(batch);
        inst->kernel_instance->log_ctrl.log_buf = NULL;
    }
    return status;
}

/*
   1、when create first vg, init global log buffer;
   2、when dss_server start up, load log_buf, if nouse, ignore; if inuse, sort by lsn and recover;
   3、when session execute, allocate log split and record redo log;
*/
status_t dss_get_instance_log_buf_and_recover(dss_instance_t *inst)
{
#ifndef OPENGAUSS
    return CM_SUCCESS;
#endif
    status_t ret = dss_alloc_instance_log_buf(inst);
    if (ret != CM_SUCCESS) {
        return ret;
    }
    return dss_recover_from_instance(inst);
}

static status_t instance_init_core(dss_instance_t *inst, uint32 objectid)
{
    g_dss_share_vg_info = (dss_share_vg_info_t *)ga_object_addr(GA_INSTANCE_POOL, objectid);
    if (g_dss_share_vg_info == NULL) {
        DSS_RETURN_IFERR2(
            CM_ERROR, DSS_THROW_ERROR(ERR_DSS_GA_INIT, "DSS instance failed to get instance object address!"));
    }

    status_t status = dss_get_vg_info(g_dss_share_vg_info, NULL);
    DSS_RETURN_IFERR2(status, DSS_THROW_ERROR(ERR_DSS_GA_INIT, "DSS instance failed to get vg info"));
    errno_t errcode = memset_s(&g_dss_kernel_instance, sizeof(g_dss_kernel_instance), 0, sizeof(g_dss_kernel_instance));
    securec_check_ret(errcode);
    inst->kernel_instance = &g_dss_kernel_instance;
    status = dss_get_instance_log_buf_and_recover(inst);
    DSS_RETURN_IFERR2(status, DSS_THROW_ERROR(ERR_DSS_GA_INIT, "DSS instance failed to get log buf"));
    uint32 sess_cnt = inst->inst_cfg.params.cfg_session_num + inst->inst_cfg.params.work_thread_cnt +
                      inst->inst_cfg.params.channel_num;
    status = dss_init_session(sess_cnt);
    DSS_RETURN_IFERR2(status, DSS_THROW_ERROR(ERR_DSS_GA_INIT, "DSS instance failed to initialize sessions."));
    status = dss_init_thread(inst);
    DSS_RETURN_IFERR2(status, DSS_THROW_ERROR(ERR_DSS_GA_INIT, "DSS instance failed to initialize thread."));
    status = dss_startup_mes();
    DSS_RETURN_IFERR2(status, DSS_THROW_ERROR(ERR_DSS_GA_INIT, "DSS instance failed to startup mes"));
    status = dss_start_lsnr(inst);
    DSS_RETURN_IFERR2(status, LOG_RUN_ERR("DSS instance failed to start lsnr!"));
    return CM_SUCCESS;
}

static status_t instance_init(dss_instance_t *inst)
{
    status_t status = dss_lock_instance();
    DSS_RETURN_IFERR2(status, LOG_RUN_ERR("Another dssinstance is running"));
    uint32 shm_key =
        (uint32)(inst->inst_cfg.params.shm_key << (uint8)DSS_MAX_SHM_KEY_BITS) + (uint32)inst->inst_cfg.params.inst_id;
    status = cm_init_shm(shm_key);
    DSS_RETURN_IFERR2(status, LOG_RUN_ERR("DSS instance failed to initialize shared memory!"));

    status = instance_init_ga(inst);
    DSS_RETURN_IFERR3(status, cm_destroy_shm(), LOG_RUN_ERR("DSS instance failed to initialize ga!"));

    uint32 objectid = ga_alloc_object(GA_INSTANCE_POOL, CM_INVALID_ID32);
    if (objectid == CM_INVALID_ID32) {
        DSS_RETURN_IFERR4(CM_ERROR, ga_detach_area(), cm_destroy_shm(),
            DSS_THROW_ERROR(ERR_DSS_GA_INIT, "DSS instance failed to alloc instance object!"));
    }

    status = instance_init_core(inst, objectid);
    DSS_RETURN_IFERR3(status, ga_detach_area(), cm_destroy_shm());
    LOG_RUN_INF("DSS instance begin to run.");
    return CM_SUCCESS;
}

status_t dss_startup(dss_instance_t *inst, char *home)
{
    status_t status;
    errno_t errcode = memset_s(inst, sizeof(dss_instance_t), 0, sizeof(dss_instance_t));
    securec_check_ret(errcode);
    inst->lock_fd = CM_INVALID_INT32;
    dss_set_server_flag();
    status = dss_set_cfg_dir(home, &inst->inst_cfg);
    DSS_RETURN_IFERR2(status, (void)printf("Environment variant DSS_HOME not found!\n"));
    status = dss_load_config(&inst->inst_cfg);
    DSS_RETURN_IFERR2(status, (void)printf("%s\nFailed to load parameters!\n", cm_get_errormsg(cm_get_error_code())));
    status = cm_start_timer(g_timer());
    DSS_RETURN_IFERR2(status, (void)printf("Aborted due to starting timer thread.\n"));
    status = dss_init_loggers(
        &inst->inst_cfg, g_dss_instance_log, sizeof(g_dss_instance_log) / sizeof(dss_log_def_t), "dssserver");
    DSS_RETURN_IFERR2(status, (void)printf("%s\nDSS init loggers failed!\n", cm_get_errormsg(cm_get_error_code())));
    LOG_RUN_INF("DSS instance begin to initialize.");
    status = instance_init(inst);
    DSS_RETURN_IFERR2(status, LOG_RUN_ERR("DSS instance failed to initialized!"));
    cm_set_shm_ctrl_flag(CM_SHM_CTRL_FLAG_TRUE);
    inst->abort_status = CM_FALSE;
    return CM_SUCCESS;
}

static status_t dss_lsnr_proc(bool32 is_emerg, uds_lsnr_t *lsnr, cs_pipe_t *pipe)
{
    dss_session_t *session = NULL;
    status_t status;
    status = dss_create_session(pipe, &session);
    DSS_RETURN_IFERR3(
        status, LOG_RUN_ERR("dss_lsnr_proc create session failed.\n"), cs_uds_disconnect(&pipe->link.uds));
    LOG_DEBUG_INF("create client server thread.");
    status = cm_create_thread(dss_session_entry, SIZE_K(512), session, &(g_dss_instance.threads[session->id]));
    DSS_RETURN_IFERR3(status, dss_destroy_session(session),
        LOG_RUN_ERR("Session:%u socket:%u closed.", session->id, pipe->link.uds.sock));
    return CM_SUCCESS;
}

status_t dss_start_lsnr(dss_instance_t *inst)
{
    errno_t ret;
    ret = snprintf_s(inst->lsnr.names[0], CM_UNIX_PATH_MAX, CM_UNIX_PATH_MAX - 1, inst->inst_cfg.params.lsnr_path);
    if (ret == -1) {
        DSS_THROW_ERROR(ERR_DSS_INVALID_PARAM, "invalid DSS lsnr host");
        return CM_ERROR;
    }
    inst->lsnr.permissions = DSS_USOCKET_PERMSSION;
    return cs_start_uds_lsnr(&inst->lsnr, dss_lsnr_proc);
}

status_t dss_init_cm(dss_instance_t *inst)
{
    inst->cm_res.is_valid = CM_FALSE;
    inst->inst_work_status_map = 0;
    dss_config_t *inst_cfg = dss_get_inst_cfg();
    char *value = cm_get_config_value(&inst_cfg->config, "DSS_CM_SO_NAME");
    if (value == NULL || strlen(value) == 0) {
        LOG_RUN_INF("dss cm config of DSS_CM_SO_NAME is empty.");
        // if no cm, treat all nodes be ok
        return CM_SUCCESS;
    }

    status_t status = cm_res_mgr_init(value, &inst->cm_res.mgr, NULL);
    DSS_RETURN_IF_ERROR(status);
    status =
        (status_t)cm_res_init(&inst->cm_res.mgr, (unsigned int)inst->inst_cfg.params.inst_id, DSS_CMS_RES_TYPE, NULL);
    DSS_RETURN_IFERR2(status, cm_res_mgr_uninit(&inst->cm_res.mgr));
    inst->cm_res.is_valid = CM_TRUE;
    return CM_SUCCESS;
}

void dss_uninit_cm(dss_instance_t *inst)
{
    if (inst->cm_res.is_valid) {
        cm_res_mgr_uninit(&inst->cm_res.mgr);
        inst->cm_res.is_valid = CM_FALSE;
    }
}

void dss_free_log_ctrl(dss_instance_t *inst)
{
    if (inst->kernel_instance != NULL && inst->kernel_instance->log_ctrl.log_buf != NULL) {
        DSS_FREE_POINT(inst->kernel_instance->log_ctrl.log_buf);
    }
}

void dss_check_peer_by_inst(dss_instance_t *inst, uint64 inst_id)
{
    dss_config_t *inst_cfg = dss_get_inst_cfg();
    // Can't be myself
    if (inst_id == (uint64)inst_cfg->params.inst_id) {
        return;
    }

    // Not cfg the inst
    uint64 inst_mask = ((uint64)0x1 << inst_id);
    if ((inst_cfg->params.inst_map & inst_mask) == 0) {
        return;
    }

    uint64 cur_inst_map = dss_get_inst_work_status();
    // Has connection
    if ((cur_inst_map & inst_mask) != 0) {
        return;
    }

    dss_check_peer_inst(inst, inst_id);
}

bool32 dss_check_inst_workstatus(uint32 instid)
{
    dss_instance_t *inst = &g_dss_instance;
    cm_spin_lock(&inst->inst_work_lock, NULL);
    cm_res_stat_ptr_t res = cm_res_get_stat(&inst->cm_res.mgr);
    if (res == NULL) {
        cm_spin_unlock(&inst->inst_work_lock);
        return CM_FALSE;
    }
    int insttotal = cm_res_get_instance_count(&inst->cm_res.mgr, res);
    for (int idx = 0; idx < insttotal; idx++) {
        const cm_res_inst_info_ptr_t inst_res = cm_res_get_instance_info(&inst->cm_res.mgr, res, (unsigned int)idx);
        if (inst_res == NULL) {
            cm_res_free_stat(&inst->cm_res.mgr, res);
            cm_spin_unlock(&inst->inst_work_lock);
            return CM_FALSE;
        }

        int resid = cm_res_get_inst_instance_id(&inst->cm_res.mgr, inst_res);
        int workstatus = cm_res_get_inst_is_work_member(&inst->cm_res.mgr, inst_res);
        if ((workstatus != 0) && ((uint32)resid == instid)) {
            cm_res_free_stat(&inst->cm_res.mgr, res);
            cm_spin_unlock(&inst->inst_work_lock);
            return CM_TRUE;
        }
        
        if (workstatus == 0) {
            LOG_RUN_INF("dss instance [%d] is not work member. May be kicked off by cm.", resid);
            if ((uint32)resid == instid) {
                cm_res_free_stat(&inst->cm_res.mgr, res);
                cm_spin_unlock(&inst->inst_work_lock);
                return CM_FALSE;
            }
        }
    }

    LOG_RUN_INF("dss instance [%d] is not work member. May be kicked off by cm.", instid);
    cm_res_free_stat(&inst->cm_res.mgr, res);
    cm_spin_unlock(&inst->inst_work_lock);
    return CM_FALSE;
}

static void dss_check_peer_by_cm(dss_instance_t *inst)
{
    cm_res_stat_ptr_t res = cm_res_get_stat(&inst->cm_res.mgr);
    if (res == NULL) {
        return;
    }
    dss_config_t *inst_cfg = dss_get_inst_cfg();
    uint64 cur_inst_map = 0;
    int insttotal = cm_res_get_instance_count(&inst->cm_res.mgr, res);
    for (int32_t idx = 0; idx < insttotal; idx++) {
        const cm_res_inst_info_ptr_t inst_res = cm_res_get_instance_info(&inst->cm_res.mgr, res, (unsigned int)idx);
        if (inst_res == NULL) {
            cm_res_free_stat(&inst->cm_res.mgr, res);
            return;
        }

        int res_instance_id = cm_res_get_inst_instance_id(&inst->cm_res.mgr, inst_res);
        int is_work_member = cm_res_get_inst_is_work_member(&inst->cm_res.mgr, inst_res);
        if (is_work_member == 0) {
            LOG_RUN_INF("dss instance [%d] is not work member. May be kicked off by cm.", res_instance_id);
            continue;
        }

        uint64_t inst_mask = ((uint64)0x1 << res_instance_id);
        if ((inst_cfg->params.inst_map & inst_mask) == 0) {
            LOG_RUN_INF("dss instance [%d] is not in mes nodes cfg lists.", res_instance_id);
            continue;
        }

        int stat = cm_res_get_inst_stat(&inst->cm_res.mgr, inst_res);
        if (stat != CM_RES_STATUS_ONLINE) {
            LOG_RUN_INF("dss instance [%d] work stat [%d] not online.", res_instance_id, stat);
        }
        cur_inst_map |= ((uint64)0x1 << res_instance_id);
    }

    dss_check_mes_conn(cur_inst_map);
    cm_res_free_stat(&inst->cm_res.mgr, res);
}

static void dss_check_peer_default(void)
{
    dss_check_mes_conn(DSS_INVALID_64);
}

void dss_init_cm_res(dss_instance_t *inst)
{
    dss_cm_res *cm_res = &inst->cm_res;
    cm_spin_lock(&cm_res->init_lock, NULL);
    if (cm_res->is_init) {
        cm_spin_unlock(&cm_res->init_lock);
        return;
    }
    status_t status = dss_init_cm(inst);
    if (status == CM_SUCCESS) {
        cm_res->is_init = CM_TRUE;
    }
    cm_spin_unlock(&cm_res->init_lock);
    return;
}

static void dss_check_peer_inst_inner(dss_instance_t *inst)
{
    /**
     * During installation initialization, db_init depends on the DSS server. However, the CMS is not started.
     * Therefore, cm_init cannot be invoked during the DSS server startup.
     * Here, cm_init is invoked before the CM interface is invoked at first time.
     */
    if (SECUREC_UNLIKELY(!inst->cm_res.is_init)) {
        dss_init_cm_res(inst);
    }
    if (inst->cm_res.is_valid) {
        dss_check_peer_by_cm(inst);
        return;
    }
    dss_check_peer_default();
}

void dss_check_peer_inst(dss_instance_t *inst, uint64 inst_id)
{
    dss_config_t *inst_cfg = dss_get_inst_cfg();
    if (inst_cfg->params.inst_cnt <= 1) {
        return;
    }

    uint64 inst_mask = ((uint64)0x1 << inst_id);
    cm_spin_lock(&inst->inst_work_lock, NULL);

    // after lock, check again, other thed may get the lock, and init the map before
    uint64 cur_inst_map = dss_get_inst_work_status();
    // has connection
    if (inst_id != DSS_INVALID_64 && (cur_inst_map & inst_mask) != 0) {
        cm_spin_unlock(&inst->inst_work_lock);
        return;
    }

    dss_check_peer_inst_inner(inst);
    cm_spin_unlock(&inst->inst_work_lock);
}

uint64 dss_get_inst_work_status(void)
{
    return (uint64)cm_atomic_get((atomic_t *)&g_dss_instance.inst_work_status_map);
}

void dss_set_inst_work_status(uint64 cur_inst_map)
{
    (void)cm_atomic_set((atomic_t *)&g_dss_instance.inst_work_status_map, (int64)cur_inst_map);
}