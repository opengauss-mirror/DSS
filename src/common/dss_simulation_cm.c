/*
 * Copyright (c) 2023Huawei Technologies Co.,Ltd.
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
 * dss_simulation_cm.c
 *
 *
 * IDENTIFICATION
 *    src/common/dss_simulation_cm.c
 *
 * -------------------------------------------------------------------------
 */

#include "dss_errno.h"
#include "cm_num.h"
#include "cm_utils.h"
#include "cm_res_mgr.h"
#include "dss_malloc.h"
#include "dss_file.h"
#include "dss_simulation_cm.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef ENABLE_DSSTEST
simulation_cm_t g_simulation_cm;
static config_item_t g_cm_params[] = {
    { CM_REFORMER_ID, CM_TRUE, CM_FALSE, "0", NULL, NULL, "-", "[0, 63]", "INTEGER", NULL, CM_PARAM_REFORMER_ID,
        EFFECT_REBOOT, CFG_INS, NULL, NULL, NULL, NULL },
    { CM_BITMAP_ONLINE, CM_TRUE, CM_FALSE, "3", NULL, NULL, "-", "-", "BIG INTEGER", NULL, CM_PARAM_BITMAP_ONLINE,
        EFFECT_REBOOT, CFG_INS, NULL, NULL, NULL, NULL },
};

static void dss_simulation_init()
{
    g_simulation_cm.params.reformer_id = CM_INVALID_ID32;
    g_simulation_cm.params.bitmap_online = 0;
    GS_INIT_SPIN_LOCK(g_simulation_cm.lock);
}

void dss_simulation_cm_refresh(void)
{
    char *value = cm_get_config_value(&g_simulation_cm.config, CM_REFORMER_ID);
    if (cm_str2uint32(value, &g_simulation_cm.params.reformer_id) != CM_SUCCESS) {
        LOG_DEBUG_ERR("[DSS][simulation_cm]fail to get REFORMER_ID");
        return;
    }
    if (g_simulation_cm.params.reformer_id < DSS_MIN_INST_ID || g_simulation_cm.params.reformer_id >= DSS_MAX_INST_ID) {
        LOG_DEBUG_ERR("[DSS][simulation_cm]the value of 'REFORMER_ID' is invalid");
        return;
    }
    value = cm_get_config_value(&g_simulation_cm.config, CM_BITMAP_ONLINE);
    if (cm_str2uint64(value, &g_simulation_cm.params.bitmap_online) != CM_SUCCESS) {
        LOG_DEBUG_ERR("[DSS][simulation_cm]fail to get BITMAP_ONLINE");
        return;
    }
}

// load config and refresh global variables
static void dss_simulation_cm_thread(thread_t *thread)
{
    char *cm_config_path = getenv(CM_CONFIG_PATH);
    char cm_config_realpath[CM_MAX_PATH_LEN];
    if (cm_config_path == NULL) {
        LOG_DEBUG_ERR("[DSS][simulation_cm]fail to get CM_CONFIG_PATH");
        return;
    }

    int status = realpath_file(cm_config_path, cm_config_realpath, CM_MAX_PATH_LEN);
    if (status != CM_SUCCESS) {
        LOG_DEBUG_ERR("[DSS]invalid cfg dir");
        return;
    }

    cm_set_thread_name("simulation_cm");
    LOG_DEBUG_INF("[DSS][simulation_cm]dss_simulation_cm thread started");
    dss_simulation_init();

    while (!thread->closed) {
        cm_spin_lock(&g_simulation_cm.lock, NULL);
        status = cm_load_config(g_cm_params, CM_PARAM_COUNT, cm_config_realpath, &g_simulation_cm.config, CM_FALSE);
        if (status != CM_SUCCESS) {
            cm_spin_unlock(&g_simulation_cm.lock);
            LOG_DEBUG_ERR("[DSS][simulation_cm]fail to load cm simulation");
            cm_sleep(DSS_LONG_TIMEOUT);
            continue;
        }
        dss_simulation_cm_refresh();
        cm_spin_unlock(&g_simulation_cm.lock);
        cm_sleep(DSS_LONG_TIMEOUT);
    }
}

void dss_simulation_cm_lsnr(void)
{
    char *cm_config_path = getenv(CM_CONFIG_PATH);
    char cm_config_realpath[CM_MAX_PATH_LEN];
    if (cm_config_path == NULL) {
        LOG_DEBUG_ERR("[DSS][simulation_cm]fail to get CM_CONFIG_PATH");
        return;
    }

    status_t status = (status_t)realpath_file(cm_config_path, cm_config_realpath, CM_MAX_PATH_LEN);
    if (status != CM_SUCCESS) {
        LOG_DEBUG_ERR("[DSS]invalid cfg dir");
        return;
    }

    int ret = cm_create_thread(dss_simulation_cm_thread, 0, NULL, &g_simulation_cm.thread);
    if (ret != CM_SUCCESS) {
        LOG_DEBUG_ERR("[DSS][simulation_cm]fail to create dss_simulation_cm_thread");
    }
}

status_t dss_refresh_cm_config_reformer_id(unsigned int inst_id)
{
    status_t status = CM_SUCCESS;
    char buf[CM_BUFLEN_32];
    char cm_config_realpath[CM_MAX_PATH_LEN];

    char *cm_config_path = getenv(CM_CONFIG_PATH);
    if (cm_config_path == NULL) {
        LOG_DEBUG_ERR("[DSS][simulation_cm]fail to get CM_CONFIG_PATH");
        return CM_ERROR;
    }
    status = (status_t)realpath_file(cm_config_path, cm_config_realpath, CM_MAX_PATH_LEN);
    if (status != CM_SUCCESS) {
        LOG_DEBUG_ERR("[DSS][simulation_cm]invalid cfg dir");
        return CM_ERROR;
    }
    int ret = sprintf_s(buf, CM_BUFLEN_32, "%d", (int)inst_id);
    if (ret == -1) {
        LOG_DEBUG_ERR("[DSS][simulation_cm]fail to copy inst_id");
        return CM_ERROR;
    }
    cm_spin_lock(&g_simulation_cm.lock, NULL);
    status = cm_alter_config(&g_simulation_cm.config, CM_REFORMER_ID, buf, CONFIG_SCOPE_BOTH, CM_TRUE);
    if (status != CM_SUCCESS) {
        cm_spin_unlock(&g_simulation_cm.lock);
        LOG_DEBUG_ERR("[DSS][simulation_cm]fail to modify REFORMER_ID");
        return CM_ERROR;
    }
    status = cm_load_config(g_cm_params, CM_PARAM_COUNT, cm_config_realpath, &g_simulation_cm.config, CM_FALSE);
    if (status != CM_SUCCESS) {
        cm_spin_unlock(&g_simulation_cm.lock);
        LOG_DEBUG_ERR("[DSS][simulation_cm]fail to load cm simulation");
        return CM_ERROR;
    }
    dss_simulation_cm_refresh();
    cm_spin_unlock(&g_simulation_cm.lock);
    return CM_SUCCESS;
}

status_t dss_simulation_cm_init(unsigned int instance_id, const char *res_name, cm_notify_func_t func)
{
    dss_simulation_cm_lsnr();
    LOG_DEBUG_INF("[DSS][simulation_cm]cm_res_init success");
    return CM_SUCCESS;
}

 char *dss_simulation_cm_get_res_stat(void)
 {
    uint64 bitmap_online = g_simulation_cm.params.bitmap_online;
    char *result = (char *)malloc(CM_MAX_INT64_STRLEN + 1);
    if (result == NULL) {
        LOG_DEBUG_ERR("[DSS][simulation_cm]fail to malloc bitmap online.");
        return NULL;
    }
    int ret = 
        snprintf_s(result, CM_MAX_INT64_STRLEN + 1, CM_MAX_INT64_STRLEN, PRINT_FMT_BIGINT, (long long)bitmap_online);
    if (ret == -1) {
        DSS_THROW_ERROR(ERR_SYSTEM_CALL, ret);
        return NULL;
    }
    return result;
 }
    
void dss_simulation_cm_free_res_stat(char *res_stat)
{
    if (res_stat != NULL) {
        cm_free(res_stat);
        res_stat = NULL;
    }
}

status_t dss_simulation_cm_res_lock(const char *lock_name)
{
    dss_config_t *inst_cfg = dss_get_inst_cfg();
    uint32 curr_id = (uint32)inst_cfg->params.inst_id;
    LOG_DEBUG_INF("Simulate to lock %s.", lock_name);
    if (g_simulation_cm.params.reformer_id == CM_INVALID_ID32) {
        return dss_refresh_cm_config_reformer_id(curr_id);
    }
    return CM_SUCCESS;
}

status_t dss_simulation_cm_res_unlock(const char *lock_name)
{
    dss_config_t *inst_cfg = dss_get_inst_cfg();
    uint32 curr_id = (uint32)inst_cfg->params.inst_id;
    LOG_DEBUG_INF("Simulate to unlock %s.", lock_name);
    if (g_simulation_cm.params.reformer_id == curr_id) {
        return dss_refresh_cm_config_reformer_id(CM_INVALID_ID32);
    }
    return CM_SUCCESS;
}

status_t dss_simulation_cm_res_get_lock_owner(const char *lock_name, unsigned int *inst_id)
{
    *inst_id = g_simulation_cm.params.reformer_id;
    LOG_RUN_INF_INHIBIT(LOG_INHIBIT_LEVEL4, "master id is %u when get cm lock %s.", *inst_id, lock_name);
    return CM_SUCCESS;
}

status_t dss_simulation_cm_res_trans_lock(const char *lock_name, unsigned int inst_id)
{
    LOG_DEBUG_INF("Simulate to trans lock %s.", lock_name);
    return dss_refresh_cm_config_reformer_id(inst_id);
}

void dss_simulation_cm_uninit(void)
{
    cm_close_thread(&g_simulation_cm.thread);
}

#define CM_SIMULATION_PATH_LEN 10
status_t dss_simulation_cm_res_mgr_init(const char *so_lib_path, cm_res_mgr_t *cm_res_mgr, cm_allocator_t *alloc)
{
    if (so_lib_path == NULL || strlen(so_lib_path) == 0) {
        cm_res_mgr->so_hanle = NULL;
        return CM_SUCCESS;
    }
    if (strcmp("simulation", so_lib_path) != 0) {
        g_simulation_cm.simulation = CM_FALSE;
        return cm_res_mgr_init(so_lib_path, cm_res_mgr, alloc);
    }
    LOG_DEBUG_INF("Start simulate cm.");
    char *cm_simulation_path = (char *)malloc(CM_SIMULATION_PATH_LEN + 1);
    if (cm_simulation_path == NULL) {
        CM_THROW_ERROR(ERR_ALLOC_MEMORY, CM_SIMULATION_PATH_LEN + 1, "simulation cm");
        return CM_ERROR;
    }
    errno_t errcode = strcpy_s(cm_simulation_path, CM_SIMULATION_PATH_LEN + 1, so_lib_path);
    securec_check_ret(errcode);
    g_simulation_cm.simulation = CM_TRUE;
    cm_res_mgr->so_hanle = (char *)cm_simulation_path;
    cm_res_mgr->cm_init = dss_simulation_cm_init;
    cm_res_mgr->cm_get_res_stat = dss_simulation_cm_get_res_stat;
    cm_res_mgr->cm_free_res_stat = dss_simulation_cm_free_res_stat;
    cm_res_mgr->cm_res_lock = dss_simulation_cm_res_lock;
    cm_res_mgr->cm_res_unlock = dss_simulation_cm_res_unlock;
    cm_res_mgr->cm_res_get_lock_owner = dss_simulation_cm_res_get_lock_owner;
    cm_res_mgr->cm_res_trans_lock = dss_simulation_cm_res_trans_lock;
    return CM_SUCCESS;
}

void dss_simulation_cm_res_mgr_uninit(cm_res_mgr_t *cm_res_mgr)
{
    if (cm_res_mgr->so_hanle != NULL) {
        if (g_simulation_cm.simulation) {
            cm_free(cm_res_mgr->so_hanle);
            cm_res_mgr->so_hanle = NULL;
            return;
        }
        cm_res_mgr_uninit(cm_res_mgr);
    }
}
#endif

#ifdef __cplusplus
}
#endif
