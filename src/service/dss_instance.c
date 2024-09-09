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
#include "cm_iofence.h"
#include "dss_errno.h"
#include "dss_defs.h"
#include "dss_api.h"
#include "dss_file.h"
#include "dss_malloc.h"
#include "dss_mes.h"
#include "dss_lsnr.h"
#include "dss_redo.h"
#include "dss_service.h"
#include "dss_instance.h"
#include "dss_reactor.h"
#include "dss_service.h"
#include "dss_zero.h"
#include "cm_utils.h"
#include "dss_thv.h"
#ifdef ENABLE_DSSTEST
#include "dss_simulation_cm.h"
#endif
#include "dss_fault_injection.h"

#define DSS_MAINTAIN_ENV "DSS_MAINTAIN"
dss_instance_t g_dss_instance;

static const char *const g_dss_lock_file = "dss.lck";

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

    if (cm_lock_fd(g_dss_instance.lock_fd, SPIN_SLEEP_TIME) != CM_SUCCESS) {
        cm_close_file(g_dss_instance.lock_fd);
        g_dss_instance.lock_fd = CM_INVALID_INT32;
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

static status_t instance_init_ga(dss_instance_t *inst)
{
    int32 ret;
    uint32 sess_cnt = dss_get_max_total_session_cnt();
    uint32 dss_session_size = (uint32)(sess_cnt * sizeof(dss_session_t));
    ga_destroy_global_area();
    instance_set_pool_def(GA_INSTANCE_POOL, 1, DSS_INS_SIZE, 0);
    instance_set_pool_def(GA_SESSION_POOL, 1, dss_session_size, 0);
    instance_set_pool_def(GA_8K_POOL, DSS_MAX_MEM_BLOCK_SIZE / (DSS_BLOCK_SIZE + DSS_BLOCK_CTRL_SIZE),
        DSS_BLOCK_SIZE + DSS_BLOCK_CTRL_SIZE, GA_MAX_8K_EXTENDED_POOLS);
    instance_set_pool_def(GA_16K_POOL, DSS_MAX_MEM_BLOCK_SIZE / (DSS_FILE_SPACE_BLOCK_SIZE + DSS_BLOCK_CTRL_SIZE),
        DSS_FILE_SPACE_BLOCK_SIZE + DSS_BLOCK_CTRL_SIZE, GA_MAX_EXTENDED_POOLS);
    instance_set_pool_def(GA_FS_AUX_POOL, DSS_MAX_MEM_BLOCK_SIZE / (DSS_FS_AUX_SIZE + DSS_BLOCK_CTRL_SIZE),
        DSS_FS_AUX_SIZE + DSS_BLOCK_CTRL_SIZE, GA_MAX_EXTENDED_POOLS);

    ret = ga_create_global_area();
    DSS_RETURN_IF_ERROR(ret);
    LOG_RUN_INF("Init GA pool and area successfully.");
    return CM_SUCCESS;
}

static status_t dss_init_thread(dss_instance_t *inst)
{
    uint32 size = dss_get_udssession_startid();
    inst->threads = (thread_t *)cm_malloc(size * (uint32)sizeof(thread_t));
    if (inst->threads == NULL) {
        return CM_ERROR;
    }
    errno_t errcode =
        memset_s(inst->threads, (size * (uint32)sizeof(thread_t)), 0x00, (size * (uint32)sizeof(thread_t)));
    securec_check_ret(errcode);
    return CM_SUCCESS;
}

status_t dss_check_vg_ctrl_valid(dss_vg_info_item_t *vg_item)
{
    dss_ctrl_t *dss_ctrl = vg_item->dss_ctrl;
    if (!DSS_VG_IS_VALID(dss_ctrl)) {
        DSS_RETURN_IFERR2(CM_ERROR, DSS_THROW_ERROR(ERR_DSS_VG_CHECK_NOT_INIT));
    }
    return CM_SUCCESS;
}

status_t dss_recover_from_offset(dss_vg_info_item_t *vg_item)
{
    bool8 need_recovery = CM_FALSE;
    /* 1、load offset batch 2、check batch valid 3、if batch valid, used 4、if batch invalid,just end */
    LOG_RUN_INF("[RECOVERY]Try to load log buf to recover");
    if (dss_load_log_buffer_from_offset(vg_item, &need_recovery) != CM_SUCCESS) {
        return CM_ERROR;
    }
    if (need_recovery) {
        char *log_buf = vg_item->log_file_ctrl.log_buf;
        status_t status = dss_recover_from_offset_inner(vg_item, log_buf);
        if (status != CM_SUCCESS) {
            return CM_ERROR;
        }
    }
    return CM_SUCCESS;
}

status_t dss_recover_from_slot(dss_vg_info_item_t *vg_item)
{
    bool8 need_recovery = CM_FALSE;
    if (dss_load_log_buffer_from_slot(vg_item, &need_recovery) != CM_SUCCESS) {
        return CM_ERROR;
    }
    if (need_recovery) {
        char *log_buf = vg_item->log_file_ctrl.log_buf;
        status_t status = dss_recover_from_slot_inner(vg_item, log_buf);
        if (status != CM_SUCCESS) {
            return CM_ERROR;
        }
        return status;
    }
    return CM_SUCCESS;
}

status_t dss_recover_from_instance(dss_instance_t *inst)
{
    status_t status;
    for (uint32 i = 0; i < g_vgs_info->group_num; i++) {
        dss_vg_info_item_t *vg_item = &g_vgs_info->volume_group[i];
        if (dss_check_vg_ctrl_valid(vg_item) != CM_SUCCESS) {
            LOG_RUN_ERR("[RECOVERY]Failed to check valid of vg %s.", vg_item->vg_name);
            return CM_ERROR;
        }
        uint32 software_version = dss_get_software_version(&vg_item->dss_ctrl->vg_info);
        if (software_version < DSS_SOFTWARE_VERSION_2) {
            status = dss_recover_from_slot(vg_item);
            if (status != CM_SUCCESS) {
                LOG_RUN_ERR("[RECOVERY]Failed to recover from vg %s.", vg_item->vg_name);
                return CM_ERROR;
            }
        } else {
            status = dss_load_redo_ctrl(vg_item);
            if (status != CM_SUCCESS) {
                LOG_RUN_ERR("[RECOVERY]Failed to load redo ctrl of vg %s.", vg_item->vg_name);
                return CM_ERROR;
            }
            status = dss_recover_from_offset(vg_item);
            if (status != CM_SUCCESS) {
                LOG_RUN_ERR("[RECOVERY]Failed to recover from vg %s.", vg_item->vg_name);
                return CM_ERROR;
            }
        }
    }
    return status;
}

bool32 dss_config_cm()
{
    dss_config_t *inst_cfg = dss_get_inst_cfg();
    char *value = cm_get_config_value(&inst_cfg->config, "DSS_CM_SO_NAME");
    if (value == NULL || strlen(value) == 0 || strlen(value) >= DSS_MAX_NAME_LEN) {
        LOG_RUN_INF("dss cm config of DSS_CM_SO_NAME is empty.");
        return CM_FALSE;
    }
    return CM_TRUE;
}

static status_t dss_init_inst_handle_session(dss_instance_t *inst)
{
    status_t status = dss_create_session(NULL, &inst->handle_session);
    DSS_RETURN_IFERR2(status, LOG_RUN_ERR("DSS instance init create handle session fail!"));
    return CM_SUCCESS;
}

static status_t instance_init_core(dss_instance_t *inst, uint32 objectid)
{
    g_dss_share_vg_info = (dss_share_vg_info_t *)ga_object_addr(GA_INSTANCE_POOL, objectid);
    if (g_dss_share_vg_info == NULL) {
        DSS_RETURN_IFERR2(
            CM_ERROR, DSS_THROW_ERROR(ERR_DSS_GA_INIT, "DSS instance failed to get instance object address!"));
    }
    status_t status = dss_get_vg_info(g_dss_share_vg_info, NULL);
    DSS_RETURN_IFERR2(status, DSS_THROW_ERROR(ERR_DSS_GA_INIT, "DSS instance failed to get vg info."));
    status = dss_init_session(dss_get_max_total_session_cnt());
    DSS_RETURN_IFERR2(status, DSS_THROW_ERROR(ERR_DSS_GA_INIT, "DSS instance failed to initialize sessions."));
    status = dss_init_thread(inst);
    DSS_RETURN_IFERR2(status, DSS_THROW_ERROR(ERR_DSS_GA_INIT, "DSS instance failed to initialize thread."));
    status = dss_startup_mes();
    DSS_RETURN_IFERR2(status, DSS_THROW_ERROR(ERR_DSS_GA_INIT, "DSS instance failed to startup mes"));
    status = dss_create_reactors();
    DSS_RETURN_IFERR2(status, LOG_RUN_ERR("DSS instance failed to start reactors!"));
    status = dss_start_lsnr(inst);
    DSS_RETURN_IFERR2(status, LOG_RUN_ERR("DSS instance failed to start lsnr!"));
    status = dss_init_inst_handle_session(inst);
    DSS_RETURN_IFERR2(status, LOG_RUN_ERR("DSS instance int handle session!"));
    return CM_SUCCESS;
}

static void dss_init_maintain(dss_instance_t *inst, dss_srv_args_t dss_args)
{
    if (dss_args.is_maintain) {
        inst->is_maintain = true;
    } else {
        char *maintain_env = getenv(DSS_MAINTAIN_ENV);
        inst->is_maintain = (maintain_env != NULL && cm_strcmpi(maintain_env, "TRUE") == 0);
    }

    if (inst->is_maintain) {
        LOG_RUN_INF("DSS_MAINTAIN is TRUE");
    } else {
        LOG_RUN_INF("DSS_MAINTAIN is FALSE");
    }
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
    DSS_RETURN_IFERR4(status, (void)del_shm_by_key(CM_SHM_CTRL_KEY), cm_destroy_shm(),
        LOG_RUN_ERR("DSS instance failed to initialize ga!"));

    uint32 objectid = ga_alloc_object(GA_INSTANCE_POOL, CM_INVALID_ID32);
    if (objectid == CM_INVALID_ID32) {
        (void)del_shm_by_key(CM_SHM_CTRL_KEY);
        ga_detach_area();
        cm_destroy_shm();
        DSS_THROW_ERROR(ERR_DSS_GA_INIT, "DSS instance failed to alloc instance object!");
        return CM_ERROR;
    }

    status = instance_init_core(inst, objectid);
    DSS_RETURN_IFERR4(status, (void)del_shm_by_key(CM_SHM_CTRL_KEY), ga_detach_area(), cm_destroy_shm());
    LOG_RUN_INF("DSS instance begin to run.");
    return CM_SUCCESS;
}

static void dss_init_cluster_proto_ver(dss_instance_t *inst)
{
    for (uint32 i = 0; i < DSS_MAX_INSTANCES; i++) {
        inst->cluster_proto_vers[i] = DSS_INVALID_VERSION;
    }
}

dss_instance_status_e dss_get_instance_status(void)
{
    return g_dss_instance.status;
}

#if defined(_DEBUG) || defined(DEBUG) || defined(DB_DEBUG_VERSION)
static status_t dss_init_fi_ctx(dss_instance_t *inst)
{
    int32 fi_ctx_size = ddes_fi_get_context_size();
    if (fi_ctx_size <= 0) {
        LOG_RUN_ERR("Failed to get fi context size.");
        return CM_ERROR;
    }
    inst->fi_run_ctx = malloc((uint32)fi_ctx_size);
    if (inst->fi_run_ctx == NULL) {
        LOG_RUN_ERR("Failed to alloc fi context.");
        return CM_ERROR;
    }
    ddes_fi_set_and_init_context(inst->fi_run_ctx);
    return CM_SUCCESS;
}
#endif

static status_t dss_save_process_pid(dss_config_t *inst_cfg)
{
#ifndef WIN32
    char file_name[CM_FILE_NAME_BUFFER_SIZE] = {0};
    char dir_name[CM_FILE_NAME_BUFFER_SIZE] = {0};
    PRTS_RETURN_IFERR(
        snprintf_s(dir_name, CM_FILE_NAME_BUFFER_SIZE, CM_FILE_NAME_BUFFER_SIZE - 1, "%s/process", inst_cfg->home));
    if (!cm_dir_exist(dir_name)) {
        DSS_RETURN_IF_ERROR(cm_create_dir(dir_name));
    }
    PRTS_RETURN_IFERR(snprintf_s(
        file_name, CM_FILE_NAME_BUFFER_SIZE, CM_FILE_NAME_BUFFER_SIZE - 1, "%s/%s", dir_name, "dss.process"));
    pid_t pid = getpid();
    if (strlen(file_name) == 0) {
        LOG_RUN_ERR("dssserver process path not existed");
        return CM_ERROR;
    }
    FILE *fp;
    CM_RETURN_IFERR(cm_fopen(file_name, "w+", S_IRUSR | S_IWUSR, &fp));
    (void)cm_truncate_file(fp->_fileno, 0);
    (void)cm_seek_file(fp->_fileno, 0, SEEK_SET);
    int32 size = fprintf(fp, "%d", pid);
    (void)fflush(stdout);
    if (size < 0) {
        LOG_RUN_ERR("write dssserver process failed, write size is %d.", size);
        (void)fclose(fp);
        return CM_ERROR;
    }
    (void)fclose(fp);
#endif
    return CM_SUCCESS;
}

status_t dss_startup(dss_instance_t *inst, dss_srv_args_t dss_args)
{
    status_t status;
    errno_t errcode = memset_s(inst, sizeof(dss_instance_t), 0, sizeof(dss_instance_t));
    securec_check_ret(errcode);

    status = dss_init_zero_buf();
    DSS_RETURN_IFERR2(status, (void)printf("Dss init zero buf fail.\n"));

#if defined(_DEBUG) || defined(DEBUG) || defined(DB_DEBUG_VERSION)
    status = dss_init_fi_ctx(inst);
    DSS_RETURN_IFERR2(status, (void)printf("Dss init fi ctx fail.\n"));
#endif

    dss_init_cluster_proto_ver(inst);
    inst->lock_fd = CM_INVALID_INT32;
    dss_set_server_flag();
    regist_get_instance_status_proc(dss_get_instance_status);
    status = dss_set_cfg_dir(dss_args.dss_home, &inst->inst_cfg);
    DSS_RETURN_IFERR2(status, (void)printf("Environment variant DSS_HOME not found!\n"));
    status = cm_start_timer(g_timer());
    DSS_RETURN_IFERR2(status, (void)printf("Aborted due to starting timer thread.\n"));
    status = dss_load_config(&inst->inst_cfg);
    DSS_RETURN_IFERR2(status, (void)printf("%s\nFailed to load parameters!\n", cm_get_errormsg(cm_get_error_code())));
    status = dss_save_process_pid(&inst->inst_cfg);
    DSS_RETURN_IFERR2(status, (void)printf("Save dssserver pid failed!\n"));
#ifdef DISABLE_SYN_META
    dss_set_syn_meta_enable(CM_FALSE);
#endif
    dss_init_maintain(inst, dss_args);
    LOG_RUN_INF("DSS instance begin to initialize.");
    status = instance_init(inst);
    DSS_RETURN_IFERR2(status, LOG_RUN_ERR("DSS instance failed to initialized!"));
    cm_set_shm_ctrl_flag(CM_SHM_CTRL_FLAG_TRUE);
    inst->abort_status = CM_FALSE;
    return CM_SUCCESS;
}

static status_t dss_handshake_core(dss_session_t *session)
{
    dss_init_packet(&session->recv_pack, CM_FALSE);
    dss_init_packet(&session->send_pack, CM_FALSE);
    session->pipe.socket_timeout = (int32)CM_NETWORK_IO_TIMEOUT;
    status_t status = dss_process_handshake_cmd(session, DSS_CMD_HANDSHAKE);
    return status;
}

static status_t dss_handshake(dss_session_t *session)
{
    LOG_RUN_INF("[DSS_CONNECT]session %u begin check protocal type.", session->id);
    /* fetch protocol type */
    status_t status = dss_diag_proto_type(session);
    if (status != CM_SUCCESS) {
        LOG_RUN_ERR("[DSS_CONNECT]Failed to get protocol type!");
        return CM_ERROR;
    }
    status = dss_handshake_core(session);
    if (status != CM_SUCCESS) {
        LOG_RUN_ERR("[DSS_CONNECT]Failed to process get server info!");
        return CM_ERROR;
    }
    return status;
}

static status_t dss_lsnr_proc(bool32 is_emerg, uds_lsnr_t *lsnr, cs_pipe_t *pipe)
{
    dss_session_t *session = NULL;
    status_t status;
    status = dss_create_session(pipe, &session);
    DSS_RETURN_IFERR2(status, LOG_RUN_ERR("[DSS_CONNECT] create session failed.\n"));
    // process_handshake
    status = dss_handshake(session);
    DSS_RETURN_IFERR3(status, LOG_RUN_ERR("[DSS_CONNECT] create session failed.\n"), dss_destroy_session(session));
    status = dss_reactors_add_session(session);
    DSS_RETURN_IFERR3(status,
        LOG_RUN_ERR("[DSS_CONNECT]Session:%u socket:%u closed.", session->id, pipe->link.uds.sock),
        dss_destroy_session(session));
    LOG_RUN_INF("[DSS_CONNECT]The client has connected, session %u.", session->id);
    return CM_SUCCESS;
}

status_t dss_start_lsnr(dss_instance_t *inst)
{
    errno_t ret;
    ret = snprintf_s(
        inst->lsnr.names[0], DSS_MAX_PATH_BUFFER_SIZE, DSS_MAX_PATH_BUFFER_SIZE - 1, inst->inst_cfg.params.lsnr_path);
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
        return CM_SUCCESS;
    }

    if (strlen(value) >= DSS_MAX_NAME_LEN) {
        LOG_RUN_ERR("dss cm config of DSS_CM_SO_NAME is exceeds the max len %u.", DSS_MAX_NAME_LEN - 1);
        return CM_ERROR;
    }
#ifdef ENABLE_DSSTEST
    DSS_RETURN_IF_ERROR(dss_simulation_cm_res_mgr_init(value, &inst->cm_res.mgr, NULL));
#else
    DSS_RETURN_IF_ERROR(cm_res_mgr_init(value, &inst->cm_res.mgr, NULL));
#endif
    status_t status =
        (status_t)cm_res_init(&inst->cm_res.mgr, (unsigned int)inst->inst_cfg.params.inst_id, DSS_CMS_RES_TYPE, NULL);
#ifdef ENABLE_DSSTEST
    DSS_RETURN_IFERR2(status, dss_simulation_cm_res_mgr_uninit(&inst->cm_res.mgr));
#else
    DSS_RETURN_IFERR2(status, cm_res_mgr_uninit(&inst->cm_res.mgr));
#endif
    inst->cm_res.is_valid = CM_TRUE;
    return CM_SUCCESS;
}

void dss_uninit_cm(dss_instance_t *inst)
{
    if (inst->cm_res.is_valid) {
#ifdef ENABLE_DSSTEST
        dss_simulation_cm_res_mgr_uninit(&inst->cm_res.mgr);
#else
        cm_res_mgr_uninit(&inst->cm_res.mgr);
#endif
        inst->cm_res.is_valid = CM_FALSE;
    }
}

void dss_free_log_ctrl()
{
    if (g_vgs_info == NULL) {
        return;
    }
    for (uint32 i = 0; i < g_vgs_info->group_num; i++) {
        dss_vg_info_item_t *vg_item = &g_vgs_info->volume_group[i];
        if (vg_item != NULL && vg_item->log_file_ctrl.log_buf != NULL) {
            DSS_FREE_POINT(vg_item->log_file_ctrl.log_buf);
        }
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

static void dss_check_peer_by_cm(dss_instance_t *inst)
{
    cm_res_mem_ctx_t res_mem_ctx;
    if (cm_res_init_memctx(&res_mem_ctx) != CM_SUCCESS) {
        return;
    }
    cm_res_stat_ptr_t res = cm_res_get_stat(&inst->cm_res.mgr, &res_mem_ctx);
    if (res == NULL) {
        cm_res_uninit_memctx(&res_mem_ctx);
        return;
    }
    dss_config_t *inst_cfg = dss_get_inst_cfg();
    uint64 cur_inst_map = 0;
    uint32 instance_count = 0;
    if (cm_res_get_instance_count(&instance_count, &inst->cm_res.mgr, res) != CM_SUCCESS) {
        cm_res_free_stat(&inst->cm_res.mgr, res);
        cm_res_uninit_memctx(&res_mem_ctx);
        return;
    }
    for (uint32_t idx = 0; idx < instance_count; idx++) {
        const cm_res_inst_info_ptr_t inst_res = cm_res_get_instance_info(&inst->cm_res.mgr, res, idx);
        if (inst_res == NULL) {
            cm_res_free_stat(&inst->cm_res.mgr, res);
            cm_res_uninit_memctx(&res_mem_ctx);
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
    cm_res_uninit_memctx(&res_mem_ctx);
}

#ifdef ENABLE_DSSTEST
static void dss_check_peer_by_simulation_cm(dss_instance_t *inst)
{
    if (g_simulation_cm.simulation) {
        char *bitmap_online = inst->cm_res.mgr.cm_get_res_stat();
        uint64 cur_inst_map = 0;
        (void)cm_str2bigint(bitmap_online, (int64 *)&cur_inst_map);
        dss_check_mes_conn(cur_inst_map);
        return;
    }
    dss_check_peer_by_cm(inst);
    return;
}
#endif

static void dss_check_peer_default()
{
    dss_check_mes_conn(DSS_INVALID_ID64);
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

#ifdef ENABLE_DSSTEST
status_t dss_get_cm_res_lock_owner(dss_cm_res *cm_res, uint32 *master_id)
{
    if (g_simulation_cm.simulation) {
        int ret = cm_res_get_lock_owner(&cm_res->mgr, DSS_CM_LOCK, master_id);
        if (ret != CM_SUCCESS) {
            return ret;
        }
    } else {
        dss_config_t *inst_cfg = dss_get_inst_cfg();
        for (int i = 0; i < DSS_MAX_INSTANCES; i++) {
            if (inst_cfg->params.ports[i] != 0) {
                *master_id = i;
                LOG_RUN_INF_INHIBIT(LOG_INHIBIT_LEVEL5, "Set min id %u as master id.", i);
                break;
            }
        }
        LOG_RUN_INF_INHIBIT(LOG_INHIBIT_LEVEL5, "master_id is %u when get cm lock.", *master_id);
    }
    return CM_SUCCESS;
}
#else
status_t dss_get_cm_res_lock_owner(dss_cm_res *cm_res, uint32 *master_id)
{
    int ret = cm_res_get_lock_owner(&cm_res->mgr, DSS_CM_LOCK, master_id);
    if (ret == CM_RES_TIMEOUT) {
        LOG_RUN_ERR("Try to get lock owner failed, cm error : %d.", ret);
        return CM_ERROR;
    } else if (ret == CM_RES_SUCCESS) {
        return CM_SUCCESS;
    } else {
        *master_id = CM_INVALID_ID32;
        LOG_RUN_ERR("Try to get lock owner failed, cm error : %d.", ret);
    }
    return CM_SUCCESS;
}
#endif
// get cm lock owner, if no owner, try to become.master_id can not be DSS_INVALID_ID32.
status_t dss_get_cm_lock_owner(dss_instance_t *inst, bool32 *grab_lock, bool32 try_lock, uint32 *master_id)
{
    dss_config_t *inst_cfg = dss_get_inst_cfg();
    *master_id = DSS_INVALID_ID32;
    if (inst->is_maintain || inst->inst_cfg.params.inst_cnt <= 1) {
        *grab_lock = CM_TRUE;
        LOG_RUN_INF_INHIBIT(LOG_INHIBIT_LEVEL5,
            "[RECOVERY]Set curr_id %u to be primary when dssserver is maintain or just one inst.",
            (uint32)inst_cfg->params.inst_id);
        *master_id = (uint32)inst_cfg->params.inst_id;
        return CM_SUCCESS;
    }
    dss_cm_res *cm_res = &inst->cm_res;
    if (!cm_res->is_init) {
        return CM_SUCCESS;
    }
    status_t ret = CM_SUCCESS;
    ret = dss_get_cm_res_lock_owner(cm_res, master_id);
    DSS_RETURN_IFERR2(ret, LOG_RUN_WAR("Failed to get cm lock owner, if DSS is normal open ignore the log."));
    if (*master_id == DSS_INVALID_ID32) {
        if (!try_lock) {
            return CM_ERROR;
        }
        if (inst->no_grab_lock) {
            LOG_RUN_INF_INHIBIT(LOG_INHIBIT_LEVEL5, "[RECOVERY]No need to grab lock when inst %u is set no grab lock.",
                (uint32)inst_cfg->params.inst_id);
            dss_set_master_id(DSS_INVALID_ID32);
            return CM_ERROR;
        }
        ret = cm_res_lock(&cm_res->mgr, DSS_CM_LOCK);
        *grab_lock = ((int)ret == CM_RES_SUCCESS);
        if (*grab_lock) {
            *master_id = (uint32)inst->inst_cfg.params.inst_id;
            LOG_RUN_INF("[RECOVERY]inst id %u succeed to get lock owner.", *master_id);
            return CM_SUCCESS;
        }
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

void dss_recovery_when_primary(dss_instance_t *inst, uint32 curr_id, bool32 grab_lock)
{
    bool32 first_start = CM_FALSE;
    if (!grab_lock) {
        first_start = (inst->status == DSS_STATUS_PREPARE);
    }
    if (first_start) {
        LOG_RUN_INF("[RECOVERY]inst %u is old main inst to do recovery.", curr_id);
    } else {
        LOG_RUN_INF("[RECOVERY]master_id is %u when get cm lock to do recovery.", curr_id);
    }

    dss_instance_status_e old_status = inst->status;
    inst->status = DSS_STATUS_RECOVERY;
    CM_MFENCE;

    if (old_status == DSS_STATUS_PREPARE) {
        status_t status = dss_load_vg_info_and_recover(CM_TRUE);
        if (status != CM_SUCCESS) {
            LOG_RUN_ERR("[RECOVERY]ABORT INFO: Failed to get vg info when instance start.");
            cm_fync_logfile();
            _exit(1);
        }
    }

    if (old_status == DSS_STATUS_OPEN && !first_start) {
        dss_wait_session_pause(inst);
    }
    dss_wait_background_pause(inst);
    status_t ret = dss_recover_from_instance(inst);
    if (ret != CM_SUCCESS) {
        LOG_RUN_ERR("[RECOVERY]ABORT INFO: Recover failed when get cm lock.");
        cm_fync_logfile();
        _exit(1);
    }
    if (!first_start) {
        dss_session_t *session = NULL;
        if (dss_create_session(NULL, &session) != CM_SUCCESS) {
            LOG_RUN_ERR("[RECOVERY]ABORT INFO: Refresh meta info failed when create session.");
            cm_fync_logfile();
            _exit(1);
        }
        if (dss_refresh_meta_info(session) != CM_SUCCESS) {
            LOG_RUN_ERR("[RECOVERY]ABORT INFO: Refresh meta info failed after recovery.");
            cm_fync_logfile();
            _exit(1);
        }
        dss_destroy_session(session);
        dss_set_session_running(inst);
    }

    // when current node is standby, and will change to primary, the status is from DSS_STATUS_OPEN to
    // DSS_STATUS_RECOVERY, need to set the master id after the status finish
    dss_set_master_id(curr_id);
    dss_set_server_status_flag(DSS_STATUS_READWRITE);
    LOG_RUN_INF("[RECOVERY]inst %u set status flag %u when get cm lock.", curr_id, DSS_STATUS_READWRITE);
    // when primary, no need to check result
    g_dss_instance.is_join_cluster = CM_TRUE;
    inst->status = DSS_STATUS_OPEN;
}

void dss_recovery_when_standby(dss_instance_t *inst, uint32 curr_id, uint32 master_id)
{
    uint32 old_master_id = dss_get_master_id();
    int32 old_status = dss_get_server_status_flag();
    if (old_master_id != master_id) {
        dss_set_master_id(master_id);
        dss_set_server_status_flag(DSS_STATUS_READONLY);
        LOG_RUN_INF("[RECOVERY]inst %u set status flag %u when not get cm lock.", curr_id, DSS_STATUS_READONLY);
    }
    if (!dss_check_join_cluster()) {
        dss_set_master_id(old_master_id);
        dss_set_server_status_flag(old_status);
        LOG_RUN_INF("[RECOVERY]inst %u reset status flag %d and master_id %u when join failed.", curr_id, old_status,
            old_master_id);
        return;
    }
    if (inst->status == DSS_STATUS_PREPARE) {
        status_t status = dss_load_vg_info_and_recover(CM_FALSE);
        if (status != CM_SUCCESS) {
            dss_set_master_id(old_master_id);
            dss_set_server_status_flag(old_status);
            g_dss_instance.is_join_cluster = CM_FALSE;
            LOG_RUN_INF("[RECOVERY]inst %u reset status flag %d and master_id %u and join cluster when load failed.",
                curr_id, old_status, old_master_id);
            LOG_RUN_ERR("[RECOVERY]Just try again to load dss ctrl.");
            return;
        }
    }
    inst->status = DSS_STATUS_OPEN;
}
/*
    1、old_master_id == master_id, just return;
    2、old_master_id != master_id, just indicates that the master has been reselected.so to judge whether recover.
*/
void dss_get_cm_lock_and_recover_inner(dss_instance_t *inst)
{
    cm_latch_x(&g_dss_instance.switch_latch, DSS_DEFAULT_SESSIONID, LATCH_STAT(LATCH_SWITCH));
    uint32 old_master_id = dss_get_master_id();
    bool32 grab_lock = CM_FALSE;
    uint32 master_id = DSS_INVALID_ID32;
    status_t status = dss_get_cm_lock_owner(inst, &grab_lock, CM_TRUE, &master_id);
    if (status != CM_SUCCESS) {
        cm_unlatch(&g_dss_instance.switch_latch, LATCH_STAT(LATCH_SWITCH));
        return;
    }
    if (master_id == DSS_INVALID_ID32) {
        LOG_RUN_WAR("[RECOVERY]cm is not init, just try again.");
        cm_unlatch(&g_dss_instance.switch_latch, LATCH_STAT(LATCH_SWITCH));
        return;
    }
    dss_config_t *inst_cfg = dss_get_inst_cfg();
    uint32 curr_id = (uint32)inst_cfg->params.inst_id;
    // master no change
    if (old_master_id == master_id) {
        // primary, no need check
        if (master_id == curr_id) {
            cm_unlatch(&g_dss_instance.switch_latch, LATCH_STAT(LATCH_SWITCH));
            return;
        }
        if (inst->is_join_cluster) {
            cm_unlatch(&g_dss_instance.switch_latch, LATCH_STAT(LATCH_SWITCH));
            return;
        }
    }
    // standby is started or masterid has been changed
    if (master_id != curr_id) {
        dss_recovery_when_standby(inst, curr_id, master_id);
        cm_unlatch(&g_dss_instance.switch_latch, LATCH_STAT(LATCH_SWITCH));
        return;
    }
    /*1、grab lock success 2、set main,other switch lock 3、restart, lock no transfer*/
    dss_set_recover_thread_id(dss_get_current_thread_id());
    dss_recovery_when_primary(inst, curr_id, grab_lock);
    dss_set_recover_thread_id(0);
    cm_unlatch(&g_dss_instance.switch_latch, LATCH_STAT(LATCH_SWITCH));
}

#define DSS_RECOVER_INTERVAL 500
#define DSS_SHORT_RECOVER_INTERVAL 100
void dss_get_cm_lock_and_recover(thread_t *thread)
{
    cm_set_thread_name("recovery");
    dss_instance_t *inst = (dss_instance_t *)thread->argument;
    while (!thread->closed) {
        dss_get_cm_lock_and_recover_inner(inst);
        if (inst->status == DSS_STATUS_PREPARE) {
            LOG_RUN_WAR("[RECOVERY]Try to sleep when in prepare status.\n");
            cm_sleep(DSS_SHORT_RECOVER_INTERVAL);
        } else {
            cm_sleep(DSS_RECOVER_INTERVAL);
        }
    }
}

void dss_delay_clean_proc(thread_t *thread)
{
    cm_set_thread_name("delay_clean");
    uint32 work_idx = dss_get_delay_clean_task_idx();
    dss_session_ctrl_t *session_ctrl = dss_get_session_ctrl();
    dss_session_t *session = &session_ctrl->sessions[work_idx];
    dss_config_t *inst_cfg = dss_get_inst_cfg();
    uint32 sleep_times = 0;
    while (!thread->closed) {
        if (sleep_times < inst_cfg->params.delay_clean_interval) {
            cm_sleep(CM_SLEEP_1000_FIXED);
            sleep_times++;
            continue;
        }
        g_dss_instance.is_cleaning = CM_TRUE;
        // DSS_STATUS_OPEN for control with switchover
        if (dss_need_exec_local() && dss_is_readwrite() && (g_dss_instance.status == DSS_STATUS_OPEN)) {
            dss_delay_clean_all_vg(session);
        }
        g_dss_instance.is_cleaning = CM_FALSE;
        sleep_times = 0;
    }
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
#ifdef ENABLE_DSSTEST
        dss_check_peer_by_simulation_cm(inst);
#else
        dss_check_peer_by_cm(inst);
#endif
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
    if (inst_id != DSS_INVALID_ID64 && (cur_inst_map & inst_mask) != 0) {
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

bool32 dss_check_join_cluster()
{
    if (g_dss_instance.is_join_cluster) {
        return CM_TRUE;
    }

    if (dss_get_master_id() == g_dss_instance.inst_cfg.params.inst_id) {
        g_dss_instance.is_join_cluster = CM_TRUE;
        LOG_RUN_INF("Join cluster success by primary.");
    } else {
        // try register to new master to join
        bool32 join_succ = CM_FALSE;
        status_t status = dss_join_cluster(&join_succ);
        if (status != CM_SUCCESS) {
            LOG_RUN_ERR("Join cluster fail, wait next try.");
            cm_reset_error();
            return CM_FALSE;
        }
        LOG_DEBUG_INF("Join cluster result [%u].", (uint32)join_succ);
        if (!join_succ) {
            return CM_FALSE;
        }
        g_dss_instance.is_join_cluster = CM_TRUE;
        LOG_RUN_INF("Join cluster success by standby.");
    }

    return CM_TRUE;
}

static bool32 dss_find_unreg_volume(dss_session_t *session, char **dev, uint8 *vg_idx, uint8 *volume_id)
{
    for (uint32 i = 0; i < g_vgs_info->group_num; i++) {
        for (uint32 j = 0; j < DSS_MAX_VOLUMES; j++) {
            if (g_vgs_info->volume_group[i].dss_ctrl->volume.defs[j].flag != VOLUME_PREPARE) {
                continue;
            }
            dss_lock_vg_mem_and_shm_s(session, &g_vgs_info->volume_group[i]);
            if (g_vgs_info->volume_group[i].dss_ctrl->volume.defs[j].flag != VOLUME_PREPARE) {
                dss_unlock_vg_mem_and_shm(session, &g_vgs_info->volume_group[i]);
                continue;
            }
            *dev = g_vgs_info->volume_group[i].dss_ctrl->volume.defs[j].name;
            *vg_idx = (uint8)i;
            *volume_id = (uint8)j;
            dss_unlock_vg_mem_and_shm(session, &g_vgs_info->volume_group[i]);
            return CM_TRUE;
        }
    }
    return CM_FALSE;
}

static bool32 dss_is_register(iof_reg_in_t *reg_info, int64 host_id)
{
    for (int32 i = 0; i < reg_info->key_count; i++) {
        if (reg_info->reg_keys[i] == host_id + 1) {
            return CM_TRUE;
        }
    }
    return CM_FALSE;
}

void dss_check_unreg_volume(dss_session_t *session)
{
    uint8 vg_idx, volume_id;
    iof_reg_in_t reg_info;
    (void)memset_s(&reg_info, sizeof(reg_info), 0, sizeof(reg_info));

    bool32 is_unreg = dss_find_unreg_volume(session, &reg_info.dev, &vg_idx, &volume_id);
    if (!is_unreg) {
        return;
    }
    status_t ret = cm_iof_inql(&reg_info);
    if (ret != CM_SUCCESS) {
        return;
    }
    bool32 remote = CM_FALSE;
    dss_vg_info_item_t *vg_item = &g_vgs_info->volume_group[0];
    if (dss_lock_vg_storage_r(vg_item, vg_item->entry_path, g_inst_cfg) != CM_SUCCESS) {
        return;
    }
    dss_lock_vg_mem_and_shm_s(session, vg_item);
    ret = dss_load_vg_ctrl_part(vg_item, (int64)(DSS_VOLUME_HEAD_SIZE - DSS_DISK_UNIT_SIZE),
        &vg_item->dss_ctrl->global_ctrl, DSS_DISK_UNIT_SIZE, &remote);
    dss_unlock_vg_mem_and_shm(session, vg_item);
    dss_unlock_vg_storage(vg_item, vg_item->entry_path, g_inst_cfg);
    if (ret != CM_SUCCESS) {
        return;
    }

    bool32 is_reg = CM_FALSE;
    for (uint8 i = 0; i < DSS_MAX_INSTANCES; i++) {
        is_reg = cm_bitmap64_exist(&vg_item->dss_ctrl->global_ctrl.cluster_node_info, i);
        if (is_reg && !dss_is_register(&reg_info, i)) {
            return;
        }
    }

    vg_item = &g_vgs_info->volume_group[vg_idx];
    dss_lock_vg_mem_and_shm_x(session, vg_item);
    if (vg_item->dss_ctrl->volume.defs[volume_id].flag == VOLUME_FREE) {
        dss_unlock_vg_mem_and_shm(session, vg_item);
        return;
    }
    vg_item->dss_ctrl->volume.defs[volume_id].flag = VOLUME_OCCUPY;
    ret = dss_update_volume_ctrl(vg_item);
    dss_unlock_vg_mem_and_shm(session, vg_item);
    if (ret != CM_SUCCESS) {
        return;
    }
}

void dss_meta_syn_proc(thread_t *thread)
{
    cm_set_thread_name("meta_syn");
    dss_bg_task_info_t *bg_task_info = (dss_bg_task_info_t *)(thread->argument);
    uint32 work_idx = dss_get_meta_syn_task_idx(bg_task_info->my_task_id);
    dss_session_ctrl_t *session_ctrl = dss_get_session_ctrl();
    dss_session_t *session = &session_ctrl->sessions[work_idx];
    while (!thread->closed) {
        // DSS_STATUS_OPEN for control with switchover
        if (g_dss_instance.status == DSS_STATUS_OPEN) {
            (void)dss_meta_syn(session, bg_task_info);
        }
        cm_sleep(CM_SLEEP_10_FIXED);
    }
}