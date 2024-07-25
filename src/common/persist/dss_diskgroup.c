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
 * dss_diskgroup.c
 *
 *
 * IDENTIFICATION
 *    src/common/persist/dss_diskgroup.c
 *
 * -------------------------------------------------------------------------
 */

#include "dss_api.h"
#include "dss_alloc_unit.h"
#include "dss_file.h"
#include "dss_malloc.h"
#include "dss_redo.h"
#include "cm_dlock.h"
#include "dss_io_fence.h"
#include "dss_open_file.h"
#include "dss_diskgroup.h"

#ifndef WIN32
#include <sys/file.h>
#endif
#include "dss_meta_buf.h"
#include "dss_fs_aux.h"
#include "dss_syn_meta.h"
#include "dss_thv.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef WIN32
#define DSS_MAX_CMD_LEN (512)
#define DSS_MAX_FILE_LEN (256)
#define DSS_SIMUFILE_NAME "dss_vglock"
#define DSS_MAX_OPEN_VG (DSS_MAX_VOLUME_GROUP_NUM)
#define DSS_FP_FREE (0)
#define DSS_FP_INUSE (1)
typedef struct st_vglock_fp {
    uint32 state;
    char file_name[DSS_MAX_FILE_LEN];
    FILE *fp;  // each process has itself fp
} vglock_fp_t;

vglock_fp_t g_fp_list[DSS_MAX_OPEN_VG];
#endif

dss_vg_info_t *g_vgs_info = NULL;
dss_share_vg_info_t *g_dss_share_vg_info = NULL;

bool32 g_is_dss_server = DSS_FALSE;
static dss_rdwr_type_e g_is_dss_readwrite = DSS_STATUS_NORMAL;
static uint32 g_master_instance_id = DSS_INVALID_ID32;
static const char *const g_dss_lock_vg_file = "dss_vg.lck";
static int32 g_dss_lock_vg_fd = CM_INVALID_INT32;
static uint32 g_dss_recover_thread_id = 0;

// CAUTION: dss_admin manager command just like dss_create_vg,cannot call it,
bool32 dss_is_server(void)
{
    return g_is_dss_server;
}

bool32 dss_is_readwrite(void)
{
    return g_is_dss_readwrite == DSS_STATUS_READWRITE;
}

bool32 dss_is_readonly(void)
{
    return g_is_dss_readwrite == DSS_STATUS_READONLY;
}

uint32 dss_get_master_id()
{
    return g_master_instance_id;
}

void dss_set_master_id(uint32 id)
{
    g_master_instance_id = id;
    LOG_RUN_INF("set master id is %u.", id);
}

void dss_set_server_flag(void)
{
    g_is_dss_server = DSS_TRUE;
}

int32 dss_get_server_status_flag(void)
{
    return (int32)g_is_dss_readwrite;
}

void dss_set_server_status_flag(int32 dss_status)
{
    g_is_dss_readwrite = dss_status;
}

void dss_set_recover_thread_id(uint32 thread_id)
{
    g_dss_recover_thread_id = thread_id;
}

uint32 dss_get_recover_thread_id(void)
{
    return g_dss_recover_thread_id;
}

dss_get_instance_status_proc_t get_instance_status_proc = NULL;
void regist_get_instance_status_proc(dss_get_instance_status_proc_t proc)
{
    get_instance_status_proc = proc;
}
void dss_checksum_vg_ctrl(dss_vg_info_item_t *vg_item);

void vg_destroy_env(dss_vg_info_item_t *vg_item)
{
    cm_oamap_destroy(&vg_item->au_map);
}

status_t dss_read_vg_config_file(const char *file_name, char *buf, uint32 *buf_len, bool32 read_only)
{
    int32 file_fd;
    status_t status;
    uint32 mode = (read_only) ? (O_RDONLY | O_BINARY) : (O_CREAT | O_RDWR | O_BINARY);

    if (!cm_file_exist(file_name)) {
        DSS_THROW_ERROR(ERR_DSS_FILE_NOT_EXIST, file_name, "config");
        return CM_ERROR;
    }

    DSS_RETURN_IF_ERROR(cm_open_file(file_name, mode, &file_fd));

    int64 size = cm_file_size(file_fd);
    bool32 result = (bool32)(size != -1);
    DSS_RETURN_IF_FALSE3(result, cm_close_file(file_fd), DSS_THROW_ERROR(ERR_SEEK_FILE, 0, SEEK_END, errno));

    result = (bool32)(size <= (int64)(*buf_len));
    DSS_RETURN_IF_FALSE3(result, cm_close_file(file_fd), DSS_THROW_ERROR(ERR_DSS_CONFIG_FILE_OVERSIZED, file_name));

    result = (bool32)(cm_seek_file(file_fd, 0, SEEK_SET) == 0);
    DSS_RETURN_IF_FALSE3(result, cm_close_file(file_fd), DSS_THROW_ERROR(ERR_SEEK_FILE, 0, SEEK_SET, errno));

    status = cm_read_file(file_fd, buf, (int32)size, (int32 *)buf_len);
    cm_close_file(file_fd);
    return status;
}

status_t dss_parse_vg_config(dss_vg_info_t *config, char *buf, uint32 buf_len);
status_t dss_load_vg_conf_inner(dss_vg_info_t *vgs_info, const dss_config_t *inst_cfg)
{
    char vg_config_path[DSS_FILE_PATH_MAX_LENGTH];
    char file_buf[DSS_MAX_CONFIG_FILE_SIZE];
    status_t status;

    int32 errcode = sprintf_s(vg_config_path, DSS_FILE_PATH_MAX_LENGTH, "%s/cfg/%s", inst_cfg->home, DSS_VG_CONF_NAME);
    bool32 result = (bool32)(errcode != -1);
    DSS_RETURN_IF_FALSE2(result, CM_THROW_ERROR(ERR_SYSTEM_CALL, errcode));

    uint32_t len = DSS_MAX_CONFIG_FILE_SIZE;
    status = dss_read_vg_config_file(vg_config_path, file_buf, &len, DSS_TRUE);
    if (status != CM_SUCCESS) {
        return status;
    }

    status = dss_parse_vg_config(vgs_info, file_buf, len);
    return status;
}

status_t dss_load_vg_conf_info(dss_vg_info_t **vgs, const dss_config_t *inst_cfg)
{
    status_t status;
    dss_vg_info_t *vgs_info = (dss_vg_info_t *)cm_malloc(sizeof(dss_vg_info_t));
    bool32 result = (bool32)(vgs_info != NULL);
    DSS_RETURN_IF_FALSE2(result, DSS_THROW_ERROR(ERR_ALLOC_MEMORY, sizeof(dss_vg_info_t), "dss_load_vg_conf_info"));

    errno_t errcode = memset_s(vgs_info, sizeof(dss_vg_info_t), 0, sizeof(dss_vg_info_t));
    result = (bool32)(errcode == EOK);
    DSS_RETURN_IF_FALSE3(result, DSS_FREE_POINT(vgs_info), CM_THROW_ERROR(ERR_SYSTEM_CALL, errcode));

    status = dss_load_vg_conf_inner(vgs_info, inst_cfg);
    if (status != CM_SUCCESS) {
        DSS_FREE_POINT(vgs_info);
        return CM_ERROR;
    }

    for (uint32 i = 0; i < vgs_info->group_num; i++) {
        for (size_t j = 0; j < DSS_MAX_VOLUMES; j++) {
            vgs_info->volume_group[i].id = i;
            vgs_info->volume_group[i].volume_handle[j].handle = DSS_INVALID_HANDLE;
            vgs_info->volume_group[i].volume_handle[j].unaligned_handle = DSS_INVALID_HANDLE;
        }
    }
    *vgs = vgs_info;
    return CM_SUCCESS;
}

void dss_free_vg_info()
{
    LOG_RUN_INF("free g_vgs_info.");
    DSS_FREE_POINT(g_vgs_info);
}

dss_vg_info_item_t *dss_find_vg_item(const char *vg_name)
{
    for (uint32_t i = 0; i < g_vgs_info->group_num; i++) {
        if (strcmp(g_vgs_info->volume_group[i].vg_name, vg_name) == 0) {
            return &g_vgs_info->volume_group[i];
        }
    }
    return NULL;
}

dss_vg_info_item_t *dss_find_vg_item_by_id(uint32 vg_id)
{
    if (vg_id > g_vgs_info->group_num) {
        return NULL;
    }
    return &g_vgs_info->volume_group[vg_id];
}

status_t dss_load_ctrlinfo(dss_vg_info_item_t *vg_item)
{
    dss_config_t *inst_cfg = dss_get_inst_cfg();
    status_t status = dss_lock_vg_storage_w(vg_item, vg_item->entry_path, inst_cfg);
    if (status != CM_SUCCESS) {
        LOG_DEBUG_ERR("Failed to lock vg:%s.", vg_item->entry_path);
        return status;
    }
    if (dss_recover_ctrlinfo(vg_item) != CM_SUCCESS) {
        dss_unlock_vg_storage(vg_item, vg_item->entry_path, inst_cfg);
        LOG_DEBUG_ERR("dss ctrl of %s is invalid when instance init.", vg_item->vg_name);
        return CM_ERROR;
    }
    dss_unlock_vg_storage(vg_item, vg_item->entry_path, inst_cfg);
    return status;
}

status_t dss_init_vol_handle(dss_vg_info_item_t *vg_item, int32 flags, dss_vol_handles_t *vol_handles)
{
    status_t status;
    dss_volume_t *vol = NULL;
    dss_volume_t volume;
    for (uint32 vid = 0; vid < DSS_MAX_VOLUMES; vid++) {
        if (vg_item->dss_ctrl->volume.defs[vid].flag == VOLUME_FREE) {
            continue;
        }
        if ((vg_item->volume_handle[vid].handle != DSS_INVALID_HANDLE && !vol_handles) &&
            (vg_item->volume_handle[vid].unaligned_handle != DSS_INVALID_HANDLE && !vol_handles)) {
            continue;
        }
        if (vol_handles) {
            if (!dss_check_volume_is_used(vg_item, vid)) {
                continue;
            }
            if (vol_handles->volume_handle[vid].handle != DSS_INVALID_HANDLE &&
                vol_handles->volume_handle[vid].unaligned_handle != DSS_INVALID_HANDLE) {
                continue;
            }
            vol = &volume;
        } else {
            vol = &vg_item->volume_handle[vid];
        }
        vol->id = vid;
        status = dss_open_volume(vg_item->dss_ctrl->volume.defs[vid].name, NULL, flags, vol);
        if (status == CM_SUCCESS) {
            if (vol_handles != NULL) {
                vol_handles->volume_handle[vid].handle = vol->handle;
                vol_handles->volume_handle[vid].unaligned_handle = vol->unaligned_handle;
                vol_handles->volume_handle[vid].id = vol->id;
                vol_handles->volume_handle[vid].vg_type = vol->vg_type;
                vol_handles->volume_handle[vid].version = vg_item->dss_ctrl->volume.defs[vid].version;
            }
            continue;
        }
        dss_destroy_vol_handle(vg_item, vol_handles, vid);
        LOG_DEBUG_ERR("open volume %s failed.", vg_item->dss_ctrl->volume.defs[vid].name);
        return status;
    }
    return CM_SUCCESS;
}

void dss_destroy_vol_handle(dss_vg_info_item_t *vg_item, dss_vol_handles_t *vol_handles, uint32 size)
{
    dss_volume_t *vol = NULL;

    for (uint32 vid = 0; vid < size; vid++) {
        if (vol_handles != NULL) {
            if (vol_handles->volume_handle[vid].handle == DSS_INVALID_HANDLE &&
                vol_handles->volume_handle[vid].unaligned_handle == DSS_INVALID_HANDLE) {
                continue;
            }
            dss_close_simple_volume(&vol_handles->volume_handle[vid]);
        } else {
            if (vg_item->volume_handle[vid].handle == DSS_INVALID_HANDLE &&
                vg_item->volume_handle[vid].unaligned_handle == DSS_INVALID_HANDLE) {
                continue;
            }
            vol = &vg_item->volume_handle[vid];
            dss_close_volume(vol);
        }
    }
    return;
}

status_t dss_checksum_vg_ctrl_remote(dss_vg_info_item_t *vg_item)
{
    LOG_RUN_INF("Begin to checksum vg:%s ctrl loaded from remote.", vg_item->vg_name);
    char *buf = vg_item->dss_ctrl->vg_data;
    uint32 checksum = dss_get_checksum(buf, DSS_VG_DATA_SIZE);
    uint32 old_checksum = vg_item->dss_ctrl->vg_info.checksum;
    if (checksum != old_checksum) {
        LOG_RUN_ERR("Failed to check checksum of vg data:%u,%u", checksum, old_checksum);
        return CM_ERROR;
    }
    buf = vg_item->dss_ctrl->root;
    checksum = dss_get_checksum(buf, DSS_BLOCK_SIZE);
    dss_common_block_t *block = (dss_common_block_t *)buf;
    old_checksum = block->checksum;
    if (checksum != old_checksum) {
        LOG_RUN_ERR("Failed to check checksum of vg root:%u,%u", checksum, old_checksum);
        return CM_ERROR;
    }
    buf = vg_item->dss_ctrl->volume_data;
    checksum = dss_get_checksum(buf, DSS_VOLUME_CTRL_SIZE);
    old_checksum = vg_item->dss_ctrl->volume.checksum;
    if (checksum != old_checksum) {
        LOG_RUN_ERR("Failed to check checksum of vg volume:%u,%u", checksum, old_checksum);
        return CM_ERROR;
    }
    LOG_RUN_INF("Succeed to checksum vg:%s ctrl loaded from remote.", vg_item->vg_name);
    return CM_SUCCESS;
}

status_t dss_load_vg_info_and_recover_core(uint32 i, bool8 need_recovery)
{
    int flags = DSS_INSTANCE_OPEN_FLAG;
    status_t status = dss_load_vg_ctrl(&g_vgs_info->volume_group[i], need_recovery);
    if (status != CM_SUCCESS) {
        LOG_RUN_ERR("DSS instance failed to load vg:%s ctrl!", g_vgs_info->volume_group[i].vg_name);
        return status;
    }
    if (need_recovery) {
        status = dss_load_ctrlinfo(&g_vgs_info->volume_group[i]);
        if (status != CM_SUCCESS) {
            LOG_RUN_ERR("DSS instance failed to load dss ctrl of vg:%s!", g_vgs_info->volume_group[i].vg_name);
            return status;
        }
        dss_checksum_vg_ctrl(&g_vgs_info->volume_group[i]);
    } else {
        status = dss_checksum_vg_ctrl_remote(&g_vgs_info->volume_group[i]);
        if (status != CM_SUCCESS) {
            return status;
        }
    }
    status = dss_init_vol_handle(&g_vgs_info->volume_group[i], flags, NULL);
    if (status != CM_SUCCESS) {
        LOG_RUN_ERR("DSS instance failed to init volume handle vg:%s!", g_vgs_info->volume_group[i].vg_name);
        return status;
    }
    LOG_RUN_INF("DSS succeed to load vgs, open volume count is %d, flag is 0x%x, 0x%x, is direct:0x%x.", 0,
        DSS_INSTANCE_OPEN_FLAG, O_DIRECT, DSS_INSTANCE_OPEN_FLAG & O_DIRECT);
    return CM_SUCCESS;
}

status_t dss_load_vg_info_and_recover(bool8 need_recovery)
{
    for (uint32_t i = 0; i < g_vgs_info->group_num; i++) {
        status_t status = dss_load_vg_info_and_recover_core(i, need_recovery);
        if (status != CM_SUCCESS) {
            LOG_RUN_ERR("DSS instance failed to load vg:%s!", g_vgs_info->volume_group[i].vg_name);
            return status;
        }
    }
    return CM_SUCCESS;
}

static void dss_free_shm_hashmap_memory(dss_share_vg_info_t *share_vg_info, uint32 num)
{
    for (uint32 i = 0; i <= num; i++) {
        shm_hashmap_destroy(&share_vg_info->vg[i].buffer_cache, i);
    }
}

status_t dss_alloc_vg_item_redo_log_buf(dss_vg_info_item_t *vg_item)
{
    LOG_RUN_INF("Begin to alloc redo log buf of vg %s.", vg_item->vg_name);
    char *log_buf = (char *)cm_malloc_align(DSS_ALIGN_SIZE, DSS_VG_LOG_SPLIT_SIZE);
    if (log_buf == NULL) {
        DSS_RETURN_IFERR2(
            CM_ERROR, DSS_THROW_ERROR(ERR_ALLOC_MEMORY, DSS_VG_LOG_SPLIT_SIZE, "global log buffer"));
    }
    errno_t rc = memset_s(log_buf, DSS_DISK_UNIT_SIZE, 0, DSS_DISK_UNIT_SIZE);
    if (rc != EOK) {
        DSS_RETURN_IFERR3(CM_ERROR, LOG_RUN_ERR("Memset failed."), DSS_FREE_POINT(log_buf));
    }
    vg_item->log_file_ctrl.log_buf = log_buf;
    return CM_SUCCESS;
}

status_t dss_get_vg_info(dss_share_vg_info_t *share_vg_info, dss_vg_info_t **info)
{
    bool32 is_server = dss_is_server();
    dss_config_t *inst_cfg = dss_get_inst_cfg();

    // initialize g_vgs_info
    status_t status = dss_load_vg_conf_info(&g_vgs_info, inst_cfg);
    DSS_RETURN_IF_ERROR(status);

    for (uint32 i = 0; i < g_vgs_info->group_num; i++) {
        g_vgs_info->volume_group[i].buffer_cache = &share_vg_info->vg[i].buffer_cache;
        g_vgs_info->volume_group[i].dss_ctrl = &share_vg_info->vg[i].dss_ctrl;
        g_vgs_info->volume_group[i].vg_latch = &share_vg_info->vg[i].vg_latch;
        if (!is_server) {
            continue;
        }
        g_vgs_info->volume_group[i].stack.buff = (char *)cm_malloc_align(DSS_ALIGN_SIZE, DSS_MAX_STACK_BUF_SIZE);
        bool32 result = (bool32)(g_vgs_info->volume_group[i].stack.buff != NULL);
        DSS_RETURN_IF_FALSE2(result,
            LOG_DEBUG_ERR("malloc stack failed, align size:%u, size:%u.", DSS_ALIGN_SIZE, DSS_MAX_STACK_BUF_SIZE));

        g_vgs_info->volume_group[i].stack.size = DSS_MAX_STACK_BUF_SIZE;
        int32 ret =
            shm_hashmap_init(&share_vg_info->vg[i].buffer_cache, DSS_BLOCK_HASH_SIZE, i, dss_buffer_cache_key_compare);
        if (ret != CM_SUCCESS) {
            if (i != 0) {
                dss_free_shm_hashmap_memory(share_vg_info, i - 1);
            }
            DSS_FREE_POINT(g_vgs_info->volume_group[i].stack.buff);
            LOG_RUN_ERR("DSS instance failed to initialize buffer cache, %d!", ret);
            DSS_THROW_ERROR(ret);
            return CM_ERROR;
        }
        cm_bilist_init(&g_vgs_info->volume_group[i].open_file_list);
        cm_bilist_init(&g_vgs_info->volume_group[i].syn_meta_desc.bilist);
        status = dss_alloc_vg_item_redo_log_buf(&g_vgs_info->volume_group[i]);
        if (status != CM_SUCCESS) {
            if (i != 0) {
                dss_free_shm_hashmap_memory(share_vg_info, i - 1);
            }
            DSS_FREE_POINT(g_vgs_info->volume_group[i].stack.buff);
            return CM_ERROR;
        }
    }
    if (info) {
        *info = g_vgs_info;
    }
    LOG_RUN_INF("DSS succeed to init vgs in memory.");
    return status;
}

bool32 dss_check_dup_vg(text_t *name, text_t *entry_path, dss_vg_info_t *config, uint32 vg_no)
{
    uint32 name_len, path_len;
    for (uint32 i = 0; i < vg_no; i++) {
        name_len = (uint32)strlen(config->volume_group[i].vg_name);
        if (name_len == name->len) {
            if (cm_strcmpni(name->str, config->volume_group[i].vg_name, name_len) == 0) {
                return DSS_TRUE;
            }
        }
        path_len = (uint32)strlen(config->volume_group[i].entry_path);
        if (path_len == entry_path->len) {
            if (cm_strcmpni(entry_path->str, config->volume_group[i].entry_path, path_len) == 0) {
                return DSS_TRUE;
            }
        }
    }

    return CM_FALSE;
}

status_t dss_parse_vg_config(dss_vg_info_t *config, char *buf, uint32 buf_len)
{
    uint32 line_no;
    text_t text, line, comment, name, value;
    uint32 vg_no;
    CM_ASSERT(config != NULL);

    text.len = buf_len;
    text.str = buf;

    comment.str = text.str;
    comment.len = 0;
    line_no = 0;
    vg_no = 0;
    while (cm_fetch_text(&text, '\n', '\0', &line)) {
        if (line.len == 0) {
            continue;
        }

        line_no++;
        cm_trim_text(&line);
        if (line.len >= DSS_MAX_CONFIG_LINE_SIZE) {
            DSS_THROW_ERROR(ERR_DSS_CONFIG_LINE_OVERLONG, line_no);
            return CM_ERROR;
        }

        if (*line.str == '#' || line.len == 0) { /* commentted line */
            continue;
        }

        comment.len = (uint32)(line.str - comment.str);

        cm_split_text(&line, ':', '\0', &name, &value);

        cm_trim_text(&name);
        cm_trim_text(&value);
        cm_trim_text(&comment);

        if (vg_no >= DSS_MAX_VOLUME_GROUP_NUM) {
            DSS_THROW_ERROR(ERR_DSS_CONFIG_LOAD, "volume group num exceed max vg num %u.", DSS_MAX_VOLUME_GROUP_NUM);
            return CM_ERROR;
        }
        if (name.len == 0 || value.len == 0) {
            DSS_THROW_ERROR(ERR_DSS_CONFIG_LOAD, "volume group name or entry-path cannot be empty.");
            return CM_ERROR;
        }

        if (dss_check_dup_vg(&name, &value, config, vg_no)) {
            DSS_THROW_ERROR(ERR_DSS_CONFIG_LOAD, "more than one volume group name or more than one entry-paths.");
            return CM_ERROR;
        }
        CM_RETURN_IFERR(cm_text2str(&name, config->volume_group[vg_no].vg_name, DSS_MAX_NAME_LEN));
        CM_RETURN_IFERR(cm_text2str(&value, config->volume_group[vg_no].entry_path, DSS_MAX_VOLUME_PATH_LEN));
        vg_no++;

        comment.str = text.str;
        comment.len = 0;
    }
    config->group_num = vg_no;
    return CM_SUCCESS;
}

// NOTE:called after load vg ctrl and recovery.
void dss_checksum_vg_ctrl(dss_vg_info_item_t *vg_item)
{
    LOG_RUN_INF("Begin to checksum vg:%s ctrl.", vg_item->vg_name);
    char *buf = vg_item->dss_ctrl->vg_data;
    uint32 checksum = dss_get_checksum(buf, DSS_VG_DATA_SIZE);
    uint32 old_checksum = vg_item->dss_ctrl->vg_info.checksum;
    dss_check_checksum(checksum, old_checksum);

    buf = vg_item->dss_ctrl->root;
    checksum = dss_get_checksum(buf, DSS_BLOCK_SIZE);
    dss_common_block_t *block = (dss_common_block_t *)buf;
    old_checksum = block->checksum;
    dss_check_checksum(checksum, old_checksum);
    LOG_RUN_INF("Succeed to checksum vg:%s ctrl.", vg_item->vg_name);
}

// NOTE:only called initializing.no check redo and recovery.
status_t dss_load_vg_ctrl(dss_vg_info_item_t *vg_item, bool32 is_lock)
{
    CM_ASSERT(vg_item != NULL);
    bool32 remote = CM_FALSE;
    dss_config_t *inst_cfg = dss_get_inst_cfg();

    if (vg_item->vg_name[0] == '\0' || vg_item->entry_path[0] == '\0') {
        LOG_RUN_ERR("Failed to load vg ctrl, input parameter is invalid.");
        return CM_ERROR;
    }
    LOG_RUN_INF("Begin to load vg %s ctrl.", vg_item->vg_name);
    status_t status;
    if (is_lock) {
        if (dss_lock_vg_storage_r(vg_item, vg_item->entry_path, inst_cfg) != CM_SUCCESS) {
            LOG_RUN_ERR("Failed to lock vg:%s.", vg_item->entry_path);
            return CM_ERROR;
        }
    }
    status = dss_load_vg_ctrl_part(vg_item, 0, vg_item->dss_ctrl, (int32)sizeof(dss_ctrl_t), &remote);
    if (status != CM_SUCCESS) {
        if (is_lock) {
            dss_unlock_vg_storage(vg_item, vg_item->entry_path, inst_cfg);
        }
        LOG_RUN_ERR("Failed to read volume %s.", vg_item->entry_path);
        return status;
    }
    if (is_lock) {
        dss_unlock_vg_storage(vg_item, vg_item->entry_path, inst_cfg);
    }
    if (!DSS_VG_IS_VALID(vg_item->dss_ctrl)) {
        DSS_THROW_ERROR(ERR_DSS_VG_CHECK_NOT_INIT);
        LOG_RUN_ERR("Invalid vg %s ctrl", vg_item->vg_name);
        return CM_ERROR;
    }

    date_t date = cm_timeval2date(vg_item->dss_ctrl->vg_info.create_time);
    time_t time = cm_date2time(date);
    char create_time[512];
    status = cm_time2str(time, "YYYY-MM-DD HH24:mi:ss", create_time, sizeof(create_time));
    LOG_RUN_INF("The vg:%s info, create time:%s.", vg_item->vg_name, create_time);

    return status;
}

status_t dss_load_vg_ctrl_part(dss_vg_info_item_t *vg_item, int64 offset, void *buf, int32 size, bool32 *remote)
{
    CM_ASSERT(vg_item != NULL);
    CM_ASSERT(buf != NULL);

    if (vg_item->volume_handle[0].handle == DSS_INVALID_HANDLE) {
        if (dss_open_volume(vg_item->entry_path, NULL, DSS_INSTANCE_OPEN_FLAG, &vg_item->volume_handle[0]) !=
            CM_SUCCESS) {
            LOG_RUN_ERR("Failed to open volume %s.", vg_item->entry_path);
            return CM_ERROR;
        }
    }
    LOG_DEBUG_INF(
        "Begin to read volume %s when load vg ctrl part, offset:%lld,size:%d.", vg_item->entry_path, offset, size);
    if (dss_read_volume_inst(vg_item, &vg_item->volume_handle[0], offset, buf, size, remote) != CM_SUCCESS) {
        LOG_RUN_ERR("Failed to read volume %s,offset:%lld,size:%d.", vg_item->entry_path, offset, size);
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

void dss_lock_vg_mem_x(dss_vg_info_item_t *vg_item)
{
    dss_latch_x(&vg_item->disk_latch);
}

void dss_lock_vg_mem_x2ix(dss_vg_info_item_t *vg_item)
{
    latch_statis_t *stat = NULL;
    dss_latch_x2ix(&vg_item->disk_latch, DSS_DEFAULT_SESSIONID, stat);
}

void dss_lock_vg_mem_ix2x(dss_vg_info_item_t *vg_item)
{
    latch_statis_t *stat = NULL;
    dss_latch_ix2x(&vg_item->disk_latch, DSS_DEFAULT_SESSIONID, stat);
}

void dss_lock_vg_mem_s(dss_vg_info_item_t *vg_item)
{
    dss_latch_s(&vg_item->disk_latch);
}

void dss_lock_vg_mem_s_force(dss_vg_info_item_t *vg_item)
{
    dss_latch_s2(&vg_item->disk_latch, DSS_DEFAULT_SESSIONID, CM_TRUE, NULL);
}

void dss_unlock_vg_mem(dss_vg_info_item_t *vg_item)
{
    dss_unlatch(&vg_item->disk_latch);
}

#ifdef WIN32
status_t dss_file_lock_vg_w(dss_config_t *inst_cfg)
{
    return CM_SUCCESS;
}

void dss_file_unlock_vg(void)
{}

status_t dss_lock_vg_storage_core(dss_vg_info_item_t *vg_item, const char *entry_path, dss_config_t *inst_cfg)
{
    return CM_SUCCESS;
}

status_t dss_lock_vg_storage_r(dss_vg_info_item_t *vg_item, const char *entry_path, dss_config_t *inst_cfg)
{
    return CM_SUCCESS;
}

status_t dss_lock_vg_storage_w(dss_vg_info_item_t *vg_item, const char *entry_path, dss_config_t *inst_cfg)
{
    return CM_SUCCESS;
}

status_t dss_lock_disk_vg(const char *entry_path, dss_config_t *inst_cfg)
{
    return CM_SUCCESS;
}

void dss_unlock_vg_raid(dss_vg_info_item_t *vg_item, const char *entry_path, int64 inst_id)
{}

void dss_unlock_vg_storage_core(dss_vg_info_item_t *vg_item, const char *entry_path, dss_config_t *inst_cfg)
{}

void dss_unlock_vg_storage(dss_vg_info_item_t *vg_item, const char *entry_path, dss_config_t *inst_cfg)
{}

status_t dss_check_lock_instid(dss_vg_info_item_t *vg_item, const char *entry_path, int64 inst_id, bool32 *is_lock)
{
    return CM_SUCCESS;
}
#else

static void dss_free_vglock_fp(const char *lock_file, FILE *fp)
{
    int32 i;
    for (i = 0; i < DSS_MAX_OPEN_VG; i++) {
        if (g_fp_list[i].state == DSS_FP_FREE) {
            continue;
        }
        if (g_fp_list[i].fp != fp) {
            continue;
        }
        if (strcmp(g_fp_list[i].file_name, lock_file) == 0) {
            g_fp_list[i].state = DSS_FP_FREE;
            g_fp_list[i].fp = NULL;
            g_fp_list[i].file_name[0] = '\0';
        }
    }
}

static FILE *dss_get_vglock_fp(const char *lock_file, bool32 need_new)
{
    int32 i;
    int32 ifree = -1;
    for (i = 0; i < DSS_MAX_OPEN_VG; i++) {
        if (g_fp_list[i].state == DSS_FP_FREE) {
            ifree = (ifree == -1) ? i : ifree;
            continue;
        }
        if (strcmp(g_fp_list[i].file_name, lock_file) == 0) {
            return g_fp_list[i].fp;
        }
    }

    if (!need_new) {
        return NULL;
    }

    if (ifree == -1) {
        return NULL;
    }

    uint32 len = (uint32)strlen(lock_file);
    int32 ret = memcpy_sp(g_fp_list[ifree].file_name, DSS_MAX_FILE_LEN, lock_file, len);
    DSS_SECUREC_RETURN_IF_ERROR(ret, NULL);
    g_fp_list[ifree].file_name[len] = '\0';
    g_fp_list[ifree].fp = fopen(lock_file, "w");
    if (g_fp_list[ifree].fp == NULL) {
        char cmd[DSS_MAX_CMD_LEN];
        ret = snprintf_s(cmd, DSS_MAX_CMD_LEN, DSS_MAX_CMD_LEN - 1, "touch %s", lock_file);
        DSS_SECUREC_SS_RETURN_IF_ERROR(ret, NULL);
        (void)system(cmd);
        g_fp_list[ifree].fp = fopen(lock_file, "w");
    }

    if (g_fp_list[ifree].fp == NULL) {
        return NULL;
    }
    g_fp_list[ifree].state = DSS_FP_INUSE;
    return g_fp_list[ifree].fp;
}

static status_t dss_pre_lockfile_name(const char *entry_path, char *lock_file, dss_config_t *inst_cfg)
{
    char *home = inst_cfg->params.disk_lock_file_path;
    char superblock[DSS_MAX_FILE_LEN];
    text_t pname, sub;
    pname.len = (uint32)strlen(entry_path);
    pname.str = (char *)entry_path;
    if (!cm_fetch_rtext(&pname, '/', '\0', &sub)) {
        pname = sub;
    }

    int32 iret_snprintf;
    if (pname.len == 0) {
        iret_snprintf = snprintf_s(lock_file, DSS_MAX_FILE_LEN, DSS_MAX_FILE_LEN - 1, "%s/%s", home, DSS_SIMUFILE_NAME);
        DSS_SECUREC_SS_RETURN_IF_ERROR(iret_snprintf, CM_ERROR);
    } else {
        if (cm_text2str(&pname, superblock, DSS_MAX_FILE_LEN) != CM_SUCCESS) {
            return CM_ERROR;
        }

        iret_snprintf = snprintf_s(
            lock_file, DSS_MAX_FILE_LEN, DSS_MAX_FILE_LEN - 1, "%s/%s_%s", home, DSS_SIMUFILE_NAME, superblock);
        DSS_SECUREC_SS_RETURN_IF_ERROR(iret_snprintf, CM_ERROR);
    }
    return CM_SUCCESS;
}

status_t dss_file_lock_vg(dss_config_t *inst_cfg, struct flock *lk)
{
    char file_name[CM_FILE_NAME_BUFFER_SIZE];
    int iret_snprintf;

    iret_snprintf = snprintf_s(
        file_name, CM_FILE_NAME_BUFFER_SIZE, CM_FILE_NAME_BUFFER_SIZE - 1, "%s/%s", inst_cfg->home, g_dss_lock_vg_file);
    DSS_SECUREC_SS_RETURN_IF_ERROR(iret_snprintf, CM_ERROR);

    if (cm_open_file(file_name, O_CREAT | O_RDWR | O_BINARY, &g_dss_lock_vg_fd) != CM_SUCCESS) {
        return CM_ERROR;
    }

    if (cm_fcntl(g_dss_lock_vg_fd, F_SETLK, lk, CM_WAIT_FOREVER) != CM_SUCCESS) {
        cm_close_file(g_dss_lock_vg_fd);
        g_dss_lock_vg_fd = CM_INVALID_INT32;
        CM_THROW_ERROR(ERR_LOCK_FILE, errno);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

status_t dss_file_lock_vg_w(dss_config_t *inst_cfg)
{
    struct flock lk;
    lk.l_type = F_WRLCK;
    lk.l_whence = SEEK_SET;
    lk.l_start = lk.l_len = 0;
    if (dss_file_lock_vg(inst_cfg, &lk) != CM_SUCCESS) {
        LOG_DEBUG_ERR("Failed to file write lock vg.");
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

status_t dss_file_lock_vg_r(dss_config_t *inst_cfg)
{
    struct flock lk;
    lk.l_type = F_RDLCK;
    lk.l_whence = SEEK_SET;
    lk.l_start = lk.l_len = 0;
    if (dss_file_lock_vg(inst_cfg, &lk) != CM_SUCCESS) {
        LOG_DEBUG_ERR("Failed to file read lock vg.");
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

void dss_file_unlock_vg(void)
{
    if (g_dss_lock_vg_fd != CM_INVALID_INT32) {
        (void)cm_unlock_fd(g_dss_lock_vg_fd);
        cm_close_file(g_dss_lock_vg_fd);
        g_dss_lock_vg_fd = CM_INVALID_INT32;
    }
}

status_t dss_lock_disk_vg(const char *entry_path, dss_config_t *inst_cfg)
{
    dlock_t lock;
    status_t status;

    status = cm_alloc_dlock(&lock, DSS_CTRL_VG_LOCK_OFFSET, inst_cfg->params.inst_id);
    if (status != CM_SUCCESS) {
        LOG_DEBUG_ERR("Failed to alloc lock.");
        return CM_ERROR;
    }

    // if get the timeout(ERR_SCSI_LOCK_OCCUPIED) error from scsi lock, we'll try lock vg again
    for (;;) {
        status = cm_init_dlock(&lock, DSS_CTRL_VG_LOCK_OFFSET, inst_cfg->params.inst_id);
        DSS_RETURN_IFERR3(status, cm_destory_dlock(&lock), LOG_DEBUG_ERR("Failed to init lock."));

        status = cm_disk_timed_lock_s(
            &lock, entry_path, DSS_LOCK_VG_TIMEOUT, inst_cfg->params.lock_interval, inst_cfg->params.dlock_retry_count);
        if (status == CM_SUCCESS) {
            LOG_DEBUG_INF("Lock vg succ, entry path %s.", entry_path);
            cm_destory_dlock(&lock);
            return CM_SUCCESS;
        }
        if (status == CM_TIMEDOUT) {
            LOG_DEBUG_INF("Lock vg timeout, get current lock info, entry_path %s.", entry_path);
            // get old lock info from disk
            status_t ret = cm_get_dlock_info_s(&lock, entry_path);
            DSS_RETURN_IFERR3(
                ret, cm_destory_dlock(&lock), LOG_DEBUG_ERR("Failed to get old lock info, entry path %s.", entry_path));

            // Get the status of the instance that owns the lock
            LOG_DEBUG_INF("The node that owns the lock is online, inst_id(disk) %lld, inst_id(lock) %lld.",
                LOCKR_INST_ID(lock), LOCKW_INST_ID(lock));
            if (dss_is_server()) {
                continue;
            }
        }
        LOG_DEBUG_ERR("Failed to lock %s, status %d.", entry_path, status);
        cm_destory_dlock(&lock);
        return status;
    }
}

status_t dss_lock_vg_storage_core(dss_vg_info_item_t *vg_item, const char *entry_path, dss_config_t *inst_cfg)
{
    LOG_DEBUG_INF("Lock vg storage, lock vg:%s.", entry_path);
    int32 dss_mode = dss_storage_mode(inst_cfg);
    if (dss_mode == DSS_MODE_DISK) {
        char lock_file[DSS_MAX_FILE_LEN];
        if (dss_pre_lockfile_name(entry_path, lock_file, inst_cfg) != CM_SUCCESS) {
            return CM_ERROR;
        }

        FILE *vglock_fp = dss_get_vglock_fp(lock_file, DSS_TRUE);
        if (vglock_fp == NULL) {
            DSS_THROW_ERROR(ERR_DSS_VG_LOCK, entry_path);
            return CM_ERROR;
        }
        flock(vglock_fp->_fileno, LOCK_EX);  // use flock to exclusive
        LOG_DEBUG_INF("DISK MODE, lock vg:%s, lock file:%s.", entry_path, lock_file);
    } else {
        /* in standby cluster, we do not need try to lock(scsi3) xlog vg, xlog vg is a read only disk */
        if (DSS_STANDBY_CLUSTER_XLOG_VG(vg_item->id)) {
            return CM_SUCCESS;
        }
        if (dss_lock_disk_vg(entry_path, inst_cfg) != CM_SUCCESS) {
            DSS_THROW_ERROR(ERR_DSS_VG_LOCK, entry_path);
            LOG_DEBUG_ERR("Failed to lock vg, entry path %s.", entry_path);
            return CM_ERROR;
        }
    }
    return CM_SUCCESS;
}

status_t dss_lock_vg_storage_r(dss_vg_info_item_t *vg_item, const char *entry_path, dss_config_t *inst_cfg)
{
    if (dss_file_lock_vg_r(inst_cfg) != CM_SUCCESS) {
        LOG_RUN_ERR("Failed to file read lock vg.");
        return CM_ERROR;
    }
    if (dss_lock_vg_storage_core(vg_item, entry_path, inst_cfg) != CM_SUCCESS) {
        LOG_RUN_ERR("Failed to lock vg, entry path %s.", entry_path);
        dss_file_unlock_vg();
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

status_t dss_lock_vg_storage_w(dss_vg_info_item_t *vg_item, const char *entry_path, dss_config_t *inst_cfg)
{
    if (dss_file_lock_vg_w(inst_cfg) != CM_SUCCESS) {
        return CM_ERROR;
    }
    if (dss_lock_vg_storage_core(vg_item, entry_path, inst_cfg) != CM_SUCCESS) {
        dss_file_unlock_vg();
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

void dss_unlock_vg_raid(dss_vg_info_item_t *vg_item, const char *entry_path, int64 inst_id)
{
    dlock_t lock;
    status_t status;

    status = cm_alloc_dlock(&lock, DSS_CTRL_VG_LOCK_OFFSET, inst_id);
    if (status != CM_SUCCESS) {
        return;
    }
    status = cm_disk_unlock_s(&lock, entry_path);
    if (status != CM_SUCCESS) {
        LOG_DEBUG_ERR("Failed to unlock %s.", entry_path);
        cm_destory_dlock(&lock);
        return;
    }
    LOG_DEBUG_INF("unLock vg succ, entry path %s.", entry_path);
    cm_destory_dlock(&lock);
}

void dss_unlock_vg_storage_core(dss_vg_info_item_t *vg_item, const char *entry_path, dss_config_t *inst_cfg)
{
    LOG_DEBUG_INF("Unlock vg storage, lock vg:%s.", entry_path);
    int32 dss_mode = dss_storage_mode(inst_cfg);
    if (dss_mode == DSS_MODE_DISK) {
        char lock_file[DSS_MAX_FILE_LEN];
        if (dss_pre_lockfile_name(entry_path, lock_file, inst_cfg) != CM_SUCCESS) {
            LOG_DEBUG_ERR("Failed to get lock file %s.", entry_path);
            cm_assert(0);
            return;
        }

        FILE *vglock_fp = dss_get_vglock_fp(lock_file, CM_FALSE);
        if (vglock_fp == NULL) {
            LOG_DEBUG_ERR("Failed to get vglock fp %s.", lock_file);
            cm_assert(0);
            return;
        }

        flock(vglock_fp->_fileno, LOCK_UN);
        dss_free_vglock_fp(lock_file, vglock_fp);
        fclose(vglock_fp);
        LOG_DEBUG_INF("ulock vg:%s, lock file:%s.", entry_path, lock_file);
    } else {
        dss_unlock_vg_raid(vg_item, entry_path, inst_cfg->params.inst_id);
    }
    return;
}

void dss_unlock_vg_storage(dss_vg_info_item_t *vg_item, const char *entry_path, dss_config_t *inst_cfg)
{
    dss_unlock_vg_storage_core(vg_item, entry_path, inst_cfg);
    dss_file_unlock_vg();
}

status_t dss_check_lock_instid(dss_vg_info_item_t *vg_item, const char *entry_path, int64 inst_id, bool32 *is_lock)
{
    int32 fd = 0;
    dlock_t lock;
    *is_lock = CM_FALSE;

    dss_latch_x(&vg_item->disk_latch);
    status_t status = cm_alloc_dlock(&lock, DSS_CTRL_VG_LOCK_OFFSET, inst_id);
    if (status != CM_SUCCESS) {
        dss_unlatch(&vg_item->disk_latch);
        return CM_ERROR;
    }

    fd = open(entry_path, O_RDWR | O_DIRECT | O_SYNC);
    if (fd < 0) {
        cm_destory_dlock(&lock);
        dss_unlatch(&vg_item->disk_latch);
        return CM_ERROR;
    }

    status = cm_get_dlock_info(&lock, fd);
    if (status != CM_SUCCESS) {
        (void)close(fd);
        cm_destory_dlock(&lock);
        dss_unlatch(&vg_item->disk_latch);
        return CM_ERROR;
    }

    if (LOCKR_INST_ID(lock) == 0) {
        (void)close(fd);
        cm_destory_dlock(&lock);
        dss_unlatch(&vg_item->disk_latch);
        LOG_DEBUG_INF("there is no lock on disk.");
        return CM_SUCCESS;
    }

    if (LOCKR_INST_ID(lock) != LOCKW_INST_ID(lock)) {
        (void)close(fd);
        LOG_DEBUG_INF("another inst_id(disk) %lld, curr inst_id(lock) %lld.", LOCKR_INST_ID(lock), LOCKW_INST_ID(lock));
        cm_destory_dlock(&lock);
        dss_unlatch(&vg_item->disk_latch);
        return CM_SUCCESS;
    }

    *is_lock = CM_TRUE;
    (void)close(fd);
    cm_destory_dlock(&lock);
    dss_unlatch(&vg_item->disk_latch);
    return CM_SUCCESS;
}
#endif

status_t dss_write_ctrl_to_disk(dss_vg_info_item_t *vg_item, int64 offset, void *buf, uint32 size)
{
    CM_ASSERT(vg_item != NULL);
    CM_ASSERT(buf != NULL);
    status_t status;

    if (vg_item->volume_handle[0].handle != DSS_INVALID_HANDLE) {
        return dss_write_volume_inst(vg_item, &vg_item->volume_handle[0], offset, buf, size);
    }

    dss_volume_t volume;
    status = dss_open_volume(vg_item->entry_path, NULL, DSS_INSTANCE_OPEN_FLAG, &volume);
    if (status != CM_SUCCESS) {
        return status;
    }
    status = dss_write_volume_inst(vg_item, &volume, offset, buf, size);
    if (status != CM_SUCCESS) {
        LOG_DEBUG_ERR("Failed to read write file, offset:%lld, size:%u.", offset, size);
        return status;
    }

    vg_item->volume_handle[0] = volume;

    return CM_SUCCESS;
}

status_t dss_update_core_ctrl_disk(dss_vg_info_item_t *vg_item)
{
    status_t status;
    vg_item->dss_ctrl->core.version++;
    vg_item->dss_ctrl->core.checksum = dss_get_checksum(&vg_item->dss_ctrl->core, DSS_CORE_CTRL_SIZE);
    LOG_DEBUG_INF(
        "[REDO]Try to update vg core:%s, version:%llu to disk.", vg_item->vg_name, vg_item->dss_ctrl->core.version);
    int64 offset = (int64)DSS_CTRL_CORE_OFFSET;
    status = dss_write_ctrl_to_disk(vg_item, offset, &vg_item->dss_ctrl->core, DSS_CORE_CTRL_SIZE);
    if (status == CM_SUCCESS) {
        // write to backup area
        status = dss_write_ctrl_to_disk(
            vg_item, (int64)DSS_CTRL_BAK_CORE_OFFSET, &vg_item->dss_ctrl->core, DSS_CORE_CTRL_SIZE);
        LOG_DEBUG_INF(
            "[REDO]End to update vg core:%s, version:%llu to disk.", vg_item->vg_name, vg_item->dss_ctrl->core.version);
    }
    return status;
}

status_t dss_update_volume_ctrl(dss_vg_info_item_t *vg_item)
{
    status_t status;
    vg_item->dss_ctrl->volume.version++;
    vg_item->dss_ctrl->volume.checksum = dss_get_checksum(&vg_item->dss_ctrl->volume, DSS_VOLUME_CTRL_SIZE);
    status = dss_write_ctrl_to_disk(
        vg_item, (int64)DSS_CTRL_VOLUME_OFFSET, &vg_item->dss_ctrl->volume, DSS_VOLUME_CTRL_SIZE);
    if (status == CM_SUCCESS) {
        // write to backup area
        status = dss_write_ctrl_to_disk(
            vg_item, (int64)DSS_CTRL_BAK_VOLUME_OFFSET, &vg_item->dss_ctrl->volume, DSS_VOLUME_CTRL_SIZE);
    }
    return status;
}

status_t dss_update_redo_ctrl(dss_vg_info_item_t *vg_item, uint32 index, uint64 offset, uint64 lsn)
{
    status_t status;
    dss_redo_ctrl_t *redo_ctrl = &vg_item->dss_ctrl->redo_ctrl;
    redo_ctrl->redo_index = index;
    redo_ctrl->offset = offset;
    redo_ctrl->lsn = lsn;
    redo_ctrl->version++;
    redo_ctrl->checksum = dss_get_checksum(redo_ctrl, DSS_DISK_UNIT_SIZE);
    status = dss_write_ctrl_to_disk(vg_item, (int64)DSS_CTRL_REDO_OFFSET, redo_ctrl, DSS_DISK_UNIT_SIZE);
    if (status == CM_SUCCESS) {
        // write to backup area
        status = dss_write_ctrl_to_disk(vg_item, (int64)DSS_CTRL_BAK_REDO_OFFSET, redo_ctrl, DSS_DISK_UNIT_SIZE);
    }
    return status;
}

status_t dss_update_volume_id_info(dss_vg_info_item_t *vg_item, uint32 id)
{
    DSS_RETURN_IF_ERROR(dss_update_core_ctrl_disk(vg_item));
    DSS_RETURN_IF_ERROR(dss_update_volume_ctrl(vg_item) != CM_SUCCESS);

    uint64 attr_offset = id * sizeof(dss_volume_attr_t);
    char *align_buf =
        (char *)vg_item->dss_ctrl->core.volume_attrs + (attr_offset / DSS_DISK_UNIT_SIZE) * DSS_DISK_UNIT_SIZE;
    int64 offset = align_buf - (char *)vg_item->dss_ctrl;
    if (dss_write_ctrl_to_disk(vg_item, offset, align_buf, DSS_DISK_UNIT_SIZE) != CM_SUCCESS) {
        return CM_ERROR;
    }
    // write to backup area
    DSS_RETURN_IF_ERROR(dss_write_ctrl_to_disk(vg_item, DSS_CTRL_BAK_ADDR + offset, align_buf, DSS_DISK_UNIT_SIZE));

    attr_offset = id * sizeof(dss_volume_def_t);
    align_buf = (char *)vg_item->dss_ctrl->volume.defs + (attr_offset / DSS_DISK_UNIT_SIZE) * DSS_DISK_UNIT_SIZE;
    offset = align_buf - (char *)vg_item->dss_ctrl;
    DSS_RETURN_IF_ERROR(dss_write_ctrl_to_disk(vg_item, offset, align_buf, DSS_DISK_UNIT_SIZE));
    // write to backup area
    return dss_write_ctrl_to_disk(vg_item, DSS_CTRL_BAK_ADDR + offset, align_buf, DSS_DISK_UNIT_SIZE);
}

status_t dss_write_volume_inst(
    dss_vg_info_item_t *vg_item, dss_volume_t *volume, int64 offset, const void *buf, uint32 size)
{
    void *temp_buf = (void *)buf;
    CM_ASSERT(offset % DSS_DISK_UNIT_SIZE == 0);
    CM_ASSERT(size % DSS_DISK_UNIT_SIZE == 0);
    if (((uint64)temp_buf) % DSS_DISK_UNIT_SIZE != 0 && size <= DSS_FILE_SPACE_BLOCK_SIZE) {
#ifndef WIN32
        char align_buf[DSS_FILE_SPACE_BLOCK_SIZE] __attribute__((__aligned__(DSS_DISK_UNIT_SIZE)));
#else
        char align_buf[DSS_FILE_SPACE_BLOCK_SIZE];
#endif
        // some redo logs about free can not align. rp_redo_free_fs_block
        errno_t errcode = memcpy_s(align_buf, size, buf, size);
        securec_check_ret(errcode);
        return dss_write_volume(volume, offset, align_buf, (int32)size);
    }
    CM_ASSERT(((uint64)temp_buf) % DSS_DISK_UNIT_SIZE == 0);
    return dss_write_volume(volume, offset, temp_buf, (int32)size);
}

uint32_t dss_find_free_volume_id(const dss_vg_info_item_t *vg_item)
{
    for (uint32_t i = 0; i < DSS_MAX_VOLUMES; i++) {
        if (vg_item->dss_ctrl->volume.defs[i].flag == VOLUME_FREE) {
            return i;
        }
    }
    return CM_INVALID_ID32;
}

status_t dss_gen_volume_head(
    dss_volume_header_t *vol_head, dss_vg_info_item_t *vg_item, const char *volume_name, uint32 id)
{
    vol_head->vol_type.id = id;
    errno_t errcode = strcpy_s(vol_head->vol_type.entry_volume_name, DSS_MAX_VOLUME_PATH_LEN, volume_name);
    DSS_SECUREC_SS_RETURN_IF_ERROR(errcode, CM_ERROR);
    vol_head->vol_type.type = DSS_VOLUME_TYPE_NORMAL;
    vol_head->valid_flag = DSS_CTRL_VALID_FLAG;
    errcode = strcpy_s(vol_head->vg_name, DSS_MAX_NAME_LEN, vg_item->vg_name);
    DSS_SECUREC_SS_RETURN_IF_ERROR(errcode, CM_ERROR);
    dss_set_software_version((dss_vg_header_t *)vol_head, (uint32)DSS_SOFTWARE_VERSION);
    (void)cm_gettimeofday(&vol_head->create_time);
    vol_head->checksum = dss_get_checksum((char *)vol_head, DSS_VG_DATA_SIZE);
    return CM_SUCCESS;
}

status_t dss_cmp_volume_head(dss_vg_info_item_t *vg_item, const char *volume_name, uint32 id)
{
#ifndef WIN32
    char buf[DSS_ALIGN_SIZE] __attribute__((__aligned__(DSS_DISK_UNIT_SIZE)));
#else
    char buf[DSS_ALIGN_SIZE];
#endif
    status_t status = CM_ERROR;
    dss_volume_header_t *vol_cmp_head = (dss_volume_header_t *)buf;
    do {
        DSS_BREAK_IF_ERROR(dss_read_volume(&vg_item->volume_handle[id], 0, vol_cmp_head, (int32)DSS_ALIGN_SIZE));
        if (vol_cmp_head->valid_flag == DSS_CTRL_VALID_FLAG) {
            // cannot add a exists volume
            DSS_THROW_ERROR(
                ERR_DSS_VOLUME_ADD, volume_name, "please check volume is used in cluster, if not need to dd manually");
            break;
        }
        status = CM_SUCCESS;
    } while (0);
    return status;
}

status_t dss_add_volume_vg_ctrl(
    dss_ctrl_t *vg_ctrl, uint32 id, uint64 vol_size, const char *volume_name, volume_slot_e volume_flag)
{
    errno_t errcode = strcpy_s(vg_ctrl->volume.defs[id].name, DSS_MAX_VOLUME_PATH_LEN, volume_name);
    DSS_SECUREC_SS_RETURN_IF_ERROR(errcode, CM_ERROR);
    vg_ctrl->volume.defs[id].flag = volume_flag;
    vg_ctrl->volume.defs[id].id = id;
    vg_ctrl->core.volume_attrs[id].id = id;
    vg_ctrl->core.volume_attrs[id].hwm = CM_CALC_ALIGN(DSS_VOLUME_HEAD_SIZE, dss_get_vg_au_size(vg_ctrl));
    vg_ctrl->core.volume_attrs[id].size = vol_size;
    if (vol_size <= vg_ctrl->core.volume_attrs[id].hwm) {
        DSS_THROW_ERROR(ERR_DSS_VOLUME_ADD, volume_name, "volume size is too small");
        return CM_ERROR;
    }
    vg_ctrl->core.volume_attrs[id].free = vol_size - vg_ctrl->core.volume_attrs[id].hwm;
    LOG_RUN_INF("Add volume refresh core, old core version:%llu, volume version:%llu, volume def version:%llu.",
        vg_ctrl->core.version, vg_ctrl->volume.version, vg_ctrl->volume.defs[id].version);
    vg_ctrl->volume.defs[id].version++;
    vg_ctrl->core.volume_count++;
    vg_ctrl->core.version++;
    vg_ctrl->volume.version++;
    return CM_SUCCESS;
}

static status_t dss_add_volume_impl_generate_redo(
    dss_session_t *session, dss_vg_info_item_t *vg_item, const char *volume_name, uint32 id)
{
    dss_redo_volhead_t redo;
    dss_volume_header_t *vol_head = (dss_volume_header_t *)redo.head;

    CM_RETURN_IFERR(dss_cmp_volume_head(vg_item, volume_name, id));
    CM_RETURN_IFERR(dss_gen_volume_head(vol_head, vg_item, volume_name, id));

    int32 ret = snprintf_s(redo.name, DSS_MAX_NAME_LEN, strlen(volume_name), "%s", volume_name);
    bool32 result = (bool32)(ret != -1);
    DSS_RETURN_IF_FALSE2(result, DSS_THROW_ERROR(ERR_SYSTEM_CALL, ret));
    dss_put_log(session, vg_item, DSS_RT_UPDATE_VOLHEAD, &redo, sizeof(redo));
    return CM_SUCCESS;
}

static status_t dss_add_volume_record_log(dss_session_t *session, dss_vg_info_item_t *vg_item, uint32 id)
{
    dss_ctrl_t *vg_ctrl = vg_item->dss_ctrl;
    dss_redo_volop_t volop_redo;
    volop_redo.volume_count = vg_ctrl->core.volume_count;
    volop_redo.core_version = vg_ctrl->core.version;
    volop_redo.volume_version = vg_ctrl->volume.version;
    volop_redo.is_add = DSS_TRUE;

    LOG_RUN_INF("Refresh core, old version:%llu, disk version:%llu.", vg_ctrl->core.version - 1, vg_ctrl->core.version);

    errno_t errcode =
        memcpy_sp(volop_redo.attr, DSS_DISK_UNIT_SIZE, &vg_ctrl->core.volume_attrs[id], sizeof(dss_volume_attr_t));
    DSS_SECUREC_RETURN_IF_ERROR(errcode, CM_ERROR);
    errcode = memcpy_sp(volop_redo.def, DSS_DISK_UNIT_SIZE, &vg_ctrl->volume.defs[id], sizeof(dss_volume_def_t));
    DSS_SECUREC_RETURN_IF_ERROR(errcode, CM_ERROR);
    dss_put_log(session, vg_item, DSS_RT_ADD_OR_REMOVE_VOLUME, &volop_redo, sizeof(volop_redo));
    return CM_SUCCESS;
}

static status_t dss_add_volume_impl(
    dss_session_t *session, dss_vg_info_item_t *vg_item, const char *volume_name, volume_slot_e volume_flag)
{
    uint32 id = dss_find_free_volume_id(vg_item);
    bool32 result = (bool32)(id < DSS_MAX_VOLUMES);
    DSS_RETURN_IF_FALSE2(
        result, LOG_DEBUG_ERR("[VOL][ADV] Failed to add volume, exceed max volumes %d.", DSS_MAX_VOLUMES));

    CM_RETURN_IFERR(dss_open_volume(volume_name, NULL, DSS_INSTANCE_OPEN_FLAG, &vg_item->volume_handle[id]));
    status_t status = dss_add_volume_impl_generate_redo(session, vg_item, volume_name, id);
    uint64 vol_size = dss_get_volume_size(&vg_item->volume_handle[id]);
    dss_close_volume(&vg_item->volume_handle[id]);
    if (status != CM_SUCCESS) {
        return status;
    }

    result = (bool32)(vol_size != DSS_INVALID_64);
    DSS_RETURN_IF_FALSE2(
        result, LOG_DEBUG_ERR("[VOL][ADV] Failed to get volume size when add volume:%s.", volume_name));
    status = dss_add_volume_vg_ctrl(vg_item->dss_ctrl, id, vol_size, volume_name, volume_flag);
    if (status != CM_SUCCESS) {
        return status;
    }
    return dss_add_volume_record_log(session, vg_item, id);
}

uint32_t dss_find_volume(dss_vg_info_item_t *vg_item, const char *volume_name)
{
    for (uint32_t i = 0; i < DSS_MAX_VOLUMES; i++) {
        if (vg_item->dss_ctrl->volume.defs[i].flag == VOLUME_FREE) {
            // not been used
            continue;
        }

        if (strcmp(vg_item->dss_ctrl->volume.defs[i].name, volume_name) == 0) {
            return i;
        }
    }

    return CM_INVALID_ID32;
}

status_t dss_add_volume_core(
    dss_session_t *session, dss_vg_info_item_t *vg_item, const char *volume_name, dss_config_t *inst_cfg)
{
    if (dss_refresh_vginfo(vg_item) != CM_SUCCESS) {
        LOG_DEBUG_ERR("[VOL][ADV] %s refresh vginfo failed.", "dss_add_volume");
        return CM_ERROR;
    }
    if (dss_find_volume(vg_item, volume_name) != CM_INVALID_ID32) {
        DSS_THROW_ERROR(ERR_DSS_VOLUME_EXISTED, volume_name, vg_item->vg_name);
        return CM_ERROR;
    }
    if (dss_add_volume_impl(session, vg_item, volume_name, VOLUME_PREPARE) != CM_SUCCESS) {
        return CM_ERROR;
    }

    if (dss_process_redo_log(session, vg_item) != CM_SUCCESS) {
        dss_unlock_vg_mem_and_shm(session, vg_item);
        dss_unlock_vg_storage(vg_item, vg_item->entry_path, inst_cfg);
        LOG_RUN_ERR("[DSS] ABORT INFO: redo log process failed, errcode:%d, OS errno:%d, OS errmsg:%s.",
            cm_get_error_code(), errno, strerror(errno));
        cm_fync_logfile();
        _exit(1);
    }
    return CM_SUCCESS;
}

static status_t dss_remove_volume_impl_core(
    dss_session_t *session, dss_vg_info_item_t *vg_item, uint32 id, const char *volume_name)
{
#ifndef WIN32
    char buf[DSS_ALIGN_SIZE] __attribute__((__aligned__(DSS_DISK_UNIT_SIZE)));
#else
    char buf[DSS_ALIGN_SIZE];
#endif
    errno_t errcode;
    dss_redo_volhead_t redo;
    dss_volume_header_t *vol_head = (dss_volume_header_t *)buf;
    status_t status = CM_ERROR;
    do {
        if (dss_read_volume(&vg_item->volume_handle[id], 0, vol_head, (int32)DSS_ALIGN_SIZE) != CM_SUCCESS) {
            break;
        }
        vol_head->valid_flag = 0;
        vol_head->software_version = 0;
        errcode = memcpy_sp(redo.head, DSS_ALIGN_SIZE, vol_head, DSS_ALIGN_SIZE);
        securec_check_ret(errcode);
        int32 ret = snprintf_s(redo.name, DSS_MAX_NAME_LEN, strlen(volume_name), "%s", volume_name);
        if (ret == -1) {
            DSS_THROW_ERROR(ERR_SYSTEM_CALL, ret);
            break;
        }

        dss_put_log(session, vg_item, DSS_RT_UPDATE_VOLHEAD, &redo, sizeof(redo));
        status = CM_SUCCESS;
    } while (0);
    return status;
}

void dss_remove_volume_vg_ctrl(dss_ctrl_t *vg_ctrl, uint32 id)
{
    vg_ctrl->volume.defs[id].flag = VOLUME_FREE;
    vg_ctrl->volume.defs[id].id = 0;
    vg_ctrl->core.volume_attrs[id].id = 0;
    vg_ctrl->core.volume_count--;
    LOG_RUN_INF("Remove volume refresh core, old core version:%llu, volume version:%llu, volume def version:%llu.",
        vg_ctrl->core.version, vg_ctrl->volume.version, vg_ctrl->volume.defs[id].version);
    vg_ctrl->volume.defs[id].version++;
    vg_ctrl->core.version++;
    vg_ctrl->volume.version++;
    LOG_RUN_INF("Refresh core, old version:%llu, disk version:%llu.", vg_ctrl->core.version - 1, vg_ctrl->core.version);
    return;
}

static status_t dss_remove_volume_impl(
    dss_session_t *session, dss_vg_info_item_t *vg_item, uint32 id, const char *volume_name)
{
    dss_ctrl_t *vg_ctrl = vg_item->dss_ctrl;

    if (vg_item->volume_handle[id].handle != DSS_INVALID_HANDLE) {
        dss_close_volume(&vg_item->volume_handle[id]);
    }

    if (dss_open_volume(volume_name, NULL, DSS_INSTANCE_OPEN_FLAG, &vg_item->volume_handle[id]) != CM_SUCCESS) {
        return CM_ERROR;
    }

    status_t status = dss_remove_volume_impl_core(session, vg_item, id, volume_name);

    dss_close_volume(&vg_item->volume_handle[id]);
    if (status != CM_SUCCESS) {
        return CM_ERROR;
    }

    dss_remove_volume_vg_ctrl(vg_ctrl, id);
    dss_redo_volop_t volop_redo;
    volop_redo.volume_count = vg_ctrl->core.volume_count;
    volop_redo.core_version = vg_ctrl->core.version;
    volop_redo.volume_version = vg_ctrl->volume.version;
    volop_redo.is_add = CM_FALSE;
    errno_t errcode =
        memcpy_sp(volop_redo.attr, DSS_DISK_UNIT_SIZE, &vg_ctrl->core.volume_attrs[id], sizeof(dss_volume_attr_t));
    DSS_SECUREC_RETURN_IF_ERROR(errcode, CM_ERROR);
    errcode = memcpy_sp(volop_redo.def, DSS_DISK_UNIT_SIZE, &vg_ctrl->volume.defs[id], sizeof(dss_volume_def_t));
    DSS_SECUREC_RETURN_IF_ERROR(errcode, CM_ERROR);
    dss_put_log(session, vg_item, DSS_RT_ADD_OR_REMOVE_VOLUME, &volop_redo, sizeof(volop_redo));
    return CM_SUCCESS;
}

status_t dss_check_remove_volume(dss_vg_info_item_t *vg_item, const char *volume_name, uint32 *volume_id)
{
    *volume_id = dss_find_volume(vg_item, volume_name);
    if (*volume_id == CM_INVALID_ID32) {
        DSS_THROW_ERROR(ERR_DSS_VOLUME_NOEXIST, volume_name, vg_item->vg_name);
        return CM_ERROR;
    }

    if (*volume_id == 0) {
        DSS_THROW_ERROR(ERR_DSS_VOLUME_REMOVE_SUPER_BLOCK, volume_name);
        LOG_DEBUG_ERR("[VOL][RMV] Not allow to delete super-block volume, %s.", volume_name);
        return CM_ERROR;
    }

    if (dss_check_volume_is_used(vg_item, *volume_id)) {
        DSS_THROW_ERROR(ERR_DSS_VOLUME_REMOVE_NONEMPTY, volume_name);
        LOG_DEBUG_ERR("[VOL][RMV] Not allow to delete a nonempty volume, %s.", volume_name);
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

status_t dss_remove_volume_core(
    dss_session_t *session, dss_vg_info_item_t *vg_item, const char *volume_name, dss_config_t *inst_cfg)
{
    uint32 volume_id;
    if (dss_refresh_vginfo(vg_item) != CM_SUCCESS) {
        LOG_DEBUG_ERR("%s refresh vginfo failed.", "dss_remove_volume");
        return CM_ERROR;
    }

    if (dss_check_remove_volume(vg_item, volume_name, &volume_id) != CM_SUCCESS) {
        return CM_ERROR;
    }

    if (dss_remove_volume_impl(session, vg_item, volume_id, volume_name) != CM_SUCCESS) {
        return CM_ERROR;
    }
    if (dss_process_redo_log(session, vg_item) != CM_SUCCESS) {
        dss_unlock_vg_mem_and_shm(session, vg_item);
        dss_unlock_vg_storage(vg_item, vg_item->entry_path, inst_cfg);
        LOG_RUN_ERR("[DSS] ABORT INFO: redo log process failed, errcode:%d, OS errno:%d, OS errmsg:%s.",
            cm_get_error_code(), errno, strerror(errno));
        cm_fync_logfile();
        _exit(1);
    }
    return CM_SUCCESS;
}

static status_t dss_modify_volume(dss_session_t *session, const char *vg_name, const char *volume_name, uint8 cmd)
{
    status_t status;
    dss_vg_info_item_t *vg_item = dss_find_vg_item(vg_name);
    if (vg_item == NULL) {
        DSS_THROW_ERROR(ERR_DSS_VG_NOT_EXIST, vg_name);
        return CM_ERROR;
    }
    if (cmd != (uint8)DSS_CMD_ADD_VOLUME && cmd != (uint8)DSS_CMD_REMOVE_VOLUME) {
        DSS_THROW_ERROR(ERR_DSS_VG_CHECK, vg_name, "invalid cmd when modify volume.");
        return CM_ERROR;
    }
    dss_config_t *inst_cfg = dss_get_inst_cfg();

    if (dss_lock_vg_storage_w(vg_item, vg_item->entry_path, inst_cfg) != CM_SUCCESS) {
        DSS_THROW_ERROR(ERR_DSS_VG_CHECK, vg_name, "refresh volume group info before modify volume failed.");
        return CM_ERROR;
    }

    dss_lock_vg_mem_and_shm_x(session, vg_item);
    if (cmd == (uint8)DSS_CMD_ADD_VOLUME) {
        status = dss_add_volume_core(session, vg_item, volume_name, inst_cfg);
    } else {
        status = dss_remove_volume_core(session, vg_item, volume_name, inst_cfg);
    }
    dss_unlock_vg_mem_and_shm(session, vg_item);
    dss_unlock_vg_storage(vg_item, vg_item->entry_path, inst_cfg);
    return status;
}

status_t dss_add_volume(dss_session_t *session, const char *vg_name, const char *volume_name)
{
    status_t status = dss_modify_volume(session, vg_name, volume_name, (uint8)DSS_CMD_ADD_VOLUME);
    if (status != CM_SUCCESS) {
        LOG_DEBUG_ERR("[VOL][ADV] Failed to add volume:%s in vg:%s.", volume_name, vg_name);
        return status;
    }
    LOG_RUN_INF("Succeed to add volume:%s in vg:%s.", volume_name, vg_name);
    return status;
}

status_t dss_remove_volume(dss_session_t *session, const char *vg_name, const char *volume_name)
{
    status_t status = dss_modify_volume(session, vg_name, volume_name, (uint8)DSS_CMD_REMOVE_VOLUME);
    if (status != CM_SUCCESS) {
        LOG_DEBUG_ERR("[VOL][RMV] Failed to delete volume:%s in vg:%s.", volume_name, vg_name);
        return status;
    }
    LOG_RUN_INF("Succeed to delete volume:%s in vg:%s.", volume_name, vg_name);
    return status;
}
static status_t dss_refresh_core_ctrl(dss_vg_info_item_t *vg_item)
{
    uint64 disk_core_version;
    status_t status = dss_get_core_version(vg_item, &disk_core_version);
    if (status != CM_SUCCESS) {
        LOG_RUN_ERR("Failed to get core version");
        return status;
    }
    LOG_RUN_INF("Try to load core ctrl, disk version:%llu, mem version:%llu for vg:%s.",
        disk_core_version, vg_item->dss_ctrl->core.version, vg_item->vg_name);
    if (dss_compare_version(disk_core_version, vg_item->dss_ctrl->core.version)) {
        status = dss_load_core_ctrl(vg_item, &vg_item->dss_ctrl->core);
        if (status != CM_SUCCESS) {
            LOG_RUN_ERR("Failed to load core ctrl data from disk.");
            return status;
        }
    }
    LOG_RUN_INF("End to load core ctrl, disk version:%llu, mem version:%llu for vg:%s.",
        disk_core_version, vg_item->dss_ctrl->core.version, vg_item->vg_name);
    return CM_SUCCESS;
}
static status_t dss_refresh_volume_ctrl(dss_vg_info_item_t *vg_item)
{
    uint64 disk_volume_version;
    status_t status = dss_get_volume_version(vg_item, &disk_volume_version);
    if (status != CM_SUCCESS) {
        LOG_RUN_ERR("Failed to get volume version");
        return status;
    }
    LOG_RUN_INF("Try to load volume ctrl, disk version:%llu, mem version:%llu for vg:%s.",
        disk_volume_version, vg_item->dss_ctrl->volume.version, vg_item->vg_name);
    if (dss_compare_version(disk_volume_version, vg_item->dss_ctrl->volume.version)) {
        status = dss_check_volume(vg_item, CM_INVALID_ID32);
        if (status != CM_SUCCESS) {
            LOG_RUN_ERR("Failed to load volume ctrl data from disk.");
            return status;
        }
    }
    LOG_RUN_INF("End to load volume ctrl, disk version:%llu, mem version:%llu for vg:%s.",
        disk_volume_version, vg_item->dss_ctrl->volume.version, vg_item->vg_name);
    return CM_SUCCESS;
}

status_t dss_load_ctrl_core(dss_vg_info_item_t *vg_item, uint32 index)
{
    status_t status = CM_ERROR;
    bool32 remote = CM_FALSE;
    switch (index) {
        case DSS_VG_INFO_CORE_CTRL:
            status = dss_refresh_core_ctrl(vg_item);
            break;
        case DSS_VG_INFO_VG_HEADER:
            status = dss_load_vg_ctrl_part(
                vg_item, (int64)DSS_CTRL_VG_DATA_OFFSET, vg_item->dss_ctrl->vg_data, (int32)DSS_VG_DATA_SIZE, &remote);
            if (status != CM_SUCCESS) {
                LOG_RUN_ERR("Failed to load vg data from disk.");
            }
            break;
        case DSS_VG_INFO_VOLUME_CTRL:
            status = dss_refresh_volume_ctrl(vg_item);
            break;
        case DSS_VG_INFO_ROOT_FT_BLOCK:
        case DSS_VG_INFO_GFT_NODE:
            status = dss_refresh_root_ft(vg_item, CM_TRUE, CM_TRUE);
            if (status != CM_SUCCESS) {
                LOG_RUN_ERR("Failed to load ft ctrl data from disk.");
            }
            break;
        case DSS_VG_INFO_REDO_CTRL:
            status = dss_load_vg_ctrl_part(
                vg_item, (int64)DSS_CTRL_REDO_OFFSET, vg_item->dss_ctrl->redo_ctrl_data, (int32)DSS_DISK_UNIT_SIZE, &remote);
            if (status != CM_SUCCESS) {
                LOG_RUN_ERR("Failed to load vg data from disk.");
            }
            break;
        default:
            LOG_RUN_ERR("the format of index %u is wrong.", index);
            break;
    }
    return status;
}

status_t dss_load_ctrl(dss_session_t *session, const char *vg_name, uint32 index)
{
    status_t status;
    dss_vg_info_item_t *vg_item = dss_find_vg_item(vg_name);
    if (vg_item == NULL) {
        DSS_THROW_ERROR(ERR_DSS_VG_NOT_EXIST, vg_name);
        return CM_ERROR;
    }
    dss_config_t *inst_cfg = dss_get_inst_cfg();
    if (vg_item->vg_name[0] == '\0' || vg_item->entry_path[0] == '\0') {
        LOG_DEBUG_ERR("Failed to load vg ctrl, input parameter is invalid.");
        return CM_ERROR;
    }

    status = dss_lock_vg_storage_r(vg_item, vg_item->entry_path, inst_cfg);
    if (status != CM_SUCCESS) {
        LOG_DEBUG_ERR("Failed to lock vg:%s.", vg_item->entry_path);
        return status;
    }

    dss_lock_vg_mem_and_shm_x(session, vg_item);
    status = dss_load_ctrl_core(vg_item, index);
    dss_unlock_vg_mem_and_shm(session, vg_item);
    dss_unlock_vg_storage(vg_item, vg_item->entry_path, inst_cfg);
    if (status == CM_SUCCESS) {
        LOG_RUN_INF("Succeed to load ctrl data from disk, vg_name:%s.", vg_name);
    }
    return status;
}

status_t dss_refresh_meta_info(dss_session_t *session)
{
    status_t status;
    for (uint32_t i = 0; i < g_vgs_info->group_num; i++) {
        for (uint32_t j = DSS_VG_INFO_CORE_CTRL; j < DSS_VG_INFO_TYPE_END; j++) {
            LOG_RUN_INF("refresh dss ctrl vg_name:%s, type %u.", g_vgs_info->volume_group[i].vg_name, j);
            status = dss_load_ctrl(session, g_vgs_info->volume_group[i].vg_name, j);
            if (status != CM_SUCCESS) {
                return status;
            }
        }

        LOG_DEBUG_INF("refresh meta info for vg_name:%s begin.", g_vgs_info->volume_group[i].vg_name);
        dss_lock_vg_mem_and_shm_x(session, &g_vgs_info->volume_group[i]);
        dss_init_vg_cache_node_info(&g_vgs_info->volume_group[i]);
        status = dss_refresh_buffer_cache(&g_vgs_info->volume_group[i], g_vgs_info->volume_group[i].buffer_cache);
        dss_unlock_vg_mem_and_shm(session, &g_vgs_info->volume_group[i]);
        if (status != CM_SUCCESS) {
            return status;
        }
        LOG_DEBUG_INF("refresh meta info for vg_name:%s end.", g_vgs_info->volume_group[i].vg_name);
    }
    return CM_SUCCESS;
}

uint64 dss_get_vg_latch_shm_offset(dss_vg_info_item_t *vg_item)
{
    cm_shm_key_t key = cm_shm_key_of(SHM_TYPE_FIXED, SHM_ID_APP_GA);
    sh_mem_p offset = cm_trans_shm_offset(key, vg_item->vg_latch);
    return offset;
}

// shoud lock in caller
status_t dss_load_volume_ctrl(dss_vg_info_item_t *vg_item, dss_volume_ctrl_t *volume_ctrl)
{
    bool32 remote = CM_TRUE;
    status_t status = dss_load_vg_ctrl_part(
        vg_item, (int64)DSS_CTRL_VOLUME_OFFSET, volume_ctrl, (int32)DSS_VOLUME_CTRL_SIZE, &remote);
    if (status != CM_SUCCESS) {
        LOG_DEBUG_ERR("Failed to load vg:%s volume ctrl.", vg_item->vg_name);
        return status;
    }
    if (remote == CM_FALSE) {
        uint32 checksum = dss_get_checksum(volume_ctrl, DSS_VOLUME_CTRL_SIZE);
        dss_check_checksum(checksum, volume_ctrl->checksum);
    }
    return CM_SUCCESS;
}

status_t dss_check_refresh_core(dss_vg_info_item_t *vg_item)
{
    if (!DSS_STANDBY_CLUSTER && dss_is_readwrite()) {
        DSS_ASSERT_LOG(dss_need_exec_local(), "only masterid %u can be readwrite.", dss_get_master_id());
        return CM_SUCCESS;
    }
#ifndef WIN32
    char buf[DSS_DISK_UNIT_SIZE] __attribute__((__aligned__(DSS_DISK_UNIT_SIZE)));
#else
    char buf[DSS_DISK_UNIT_SIZE];
#endif
    bool32 remote = CM_FALSE;
    uint64 core_version = vg_item->dss_ctrl->core.version;
    dss_fs_block_root_t *fs_root = (dss_fs_block_root_t *)vg_item->dss_ctrl->core.fs_block_root;
    uint64 fs_version = fs_root->version;
    dss_fs_aux_root_t *fs_aux_root = (dss_fs_aux_root_t *)vg_item->dss_ctrl->core.fs_aux_root;
    uint64 fs_aux_version = fs_aux_root->version;

    status_t status = dss_load_vg_ctrl_part(vg_item, (int64)DSS_CTRL_CORE_OFFSET, buf, DSS_DISK_UNIT_SIZE, &remote);
    if (status != CM_SUCCESS) {
        LOG_DEBUG_ERR("Failed to load vg core version %s.", vg_item->entry_path);
        return status;
    }

    dss_core_ctrl_t *new_core = (dss_core_ctrl_t *)buf;
    if (dss_compare_version(new_core->version, core_version)) {
        LOG_RUN_INF("Refresh core, old version:%llu, disk version:%llu.", core_version, new_core->version);
        status = dss_load_vg_ctrl_part(
            vg_item, (int64)DSS_CTRL_CORE_OFFSET, &vg_item->dss_ctrl->core, (int32)DSS_CORE_CTRL_SIZE, &remote);
        if (status != CM_SUCCESS) {
            LOG_DEBUG_ERR("Failed to load vg core %s.", vg_item->entry_path);
            return status;
        }
    } else {
        fs_root = (dss_fs_block_root_t *)new_core->fs_block_root;
        fs_aux_root = (dss_fs_aux_root_t *)new_core->fs_aux_root;
        if (dss_compare_version(fs_root->version, fs_version) ||
            dss_compare_version(fs_aux_root->version, fs_aux_version)) {
            LOG_RUN_INF("Refresh core head, old version:%llu, disk version:%llu.", fs_version, fs_root->version);
            errno_t errcode = memcpy_s(&vg_item->dss_ctrl->core, DSS_DISK_UNIT_SIZE, buf, DSS_DISK_UNIT_SIZE);
            securec_check_ret(errcode);
        }
    }
    return CM_SUCCESS;
}

static status_t dss_init_volume_core(dss_vg_info_item_t *vg_item, dss_volume_ctrl_t *volume, uint32 i)
{
    if (volume->defs[i].flag == vg_item->dss_ctrl->volume.defs[i].flag) {
        return CM_SUCCESS;
    }

    if (vg_item->volume_handle[i].handle != DSS_INVALID_HANDLE) {
        dss_close_volume(&vg_item->volume_handle[i]);
    }

    if (volume->defs[i].flag == VOLUME_OCCUPY) {
        status_t status = dss_open_volume(
            volume->defs[i].name, volume->defs[i].code, DSS_INSTANCE_OPEN_FLAG, &vg_item->volume_handle[i]);
        if (status != CM_SUCCESS) {
            LOG_DEBUG_ERR("Failed to open volume:%s.", volume->defs[i].name);
            return status;
        }
        vg_item->volume_handle[i].id = i;
    }

    vg_item->dss_ctrl->volume.defs[i] = volume->defs[i];
    LOG_RUN_INF("Refresh volume, add id:%u, name:%s.", i, vg_item->dss_ctrl->volume.defs[i].name);
    return CM_SUCCESS;
}

status_t dss_init_volume(dss_vg_info_item_t *vg_item, dss_volume_ctrl_t *volume)
{
    status_t status;

    for (uint32 i = 0; i < DSS_MAX_VOLUMES; i++) {
        status = dss_init_volume_core(vg_item, volume, i);
        if (status != CM_SUCCESS) {
            return status;
        }
    }
    return CM_SUCCESS;
}

static status_t dss_check_free_volume(dss_vg_info_item_t *vg_item, uint32 volumeid)
{
    if (vg_item->dss_ctrl->volume.defs[volumeid].flag == VOLUME_OCCUPY) {
        return CM_SUCCESS;
    }

    dss_volume_ctrl_t *volume = (dss_volume_ctrl_t *)cm_malloc_align(DSS_ALIGN_SIZE, DSS_VOLUME_CTRL_SIZE);
    bool32 result = (bool32)(volume != NULL);
    DSS_RETURN_IF_FALSE2(result, LOG_DEBUG_ERR("Can not allocate memory in stack."));

    status_t status = dss_load_volume_ctrl(vg_item, volume);
    if (status != CM_SUCCESS) {
        DSS_FREE_POINT(volume);
        LOG_DEBUG_ERR("Failed load vg ctrl.");
        return status;
    }
    if (volume->version <= vg_item->dss_ctrl->volume.version) {
        DSS_FREE_POINT(volume);
        return CM_ERROR;
    }

    if (volume->defs[volumeid].flag == VOLUME_FREE) {
        DSS_FREE_POINT(volume);
        return CM_ERROR;
    }

    status = dss_init_volume(vg_item, volume);
    if (status == CM_SUCCESS) {
        vg_item->dss_ctrl->volume.checksum = volume->checksum;
        vg_item->dss_ctrl->volume.version = volume->version;
    }
    DSS_FREE_POINT(volume);
    return status;
}

// NOTE:use in server.
status_t dss_check_volume(dss_vg_info_item_t *vg_item, uint32 volumeid)
{
    status_t status = CM_SUCCESS;
    dss_volume_ctrl_t *volume;

    if (volumeid == CM_INVALID_ID32) {
        volume = (dss_volume_ctrl_t *)cm_malloc_align(DSS_ALIGN_SIZE, DSS_VOLUME_CTRL_SIZE);
        bool32 result = (bool32)(volume != NULL);
        DSS_RETURN_IF_FALSE2(result, LOG_DEBUG_ERR("Can not allocate memory in stack."));

        status = dss_load_volume_ctrl(vg_item, volume);
        if (status != CM_SUCCESS) {
            DSS_FREE_POINT(volume);
            LOG_DEBUG_ERR("Failed load vg ctrl.");
            return status;
        }
        status = dss_init_volume(vg_item, volume);
        if (status == CM_SUCCESS) {
            vg_item->dss_ctrl->volume.checksum = volume->checksum;
            vg_item->dss_ctrl->volume.version = volume->version;
        }
        DSS_FREE_POINT(volume);
        return status;
    }

    return dss_check_free_volume(vg_item, volumeid);
}

// first check volume is valid.
status_t dss_check_write_volume(dss_vg_info_item_t *vg_item, uint32 volumeid, int64 offset, void *buf, uint32 size)
{
    dss_volume_t *volume;
    DSS_RETURN_IF_ERROR(dss_check_volume(vg_item, volumeid));
    volume = &vg_item->volume_handle[volumeid];
    return dss_write_volume_inst(vg_item, volume, offset, buf, size);
}

// first check volume is valid.
status_t dss_check_read_volume(
    dss_vg_info_item_t *vg_item, uint32 volumeid, int64 offset, void *buf, int32 size, bool32 *remote)
{
    dss_volume_t *volume;
    DSS_RETURN_IF_ERROR(dss_check_volume(vg_item, volumeid));
    volume = &vg_item->volume_handle[volumeid];
    LOG_DEBUG_INF("Begin to read volume %s when check, offset:%lld,size:%d.", vg_item->entry_path, offset, size);
    return dss_read_volume_inst(vg_item, volume, offset, buf, size, remote);
}

dss_remote_read_proc_t remote_read_proc = NULL;
void regist_remote_read_proc(dss_remote_read_proc_t proc)
{
    remote_read_proc = proc;
}

static inline bool32 dss_need_load_remote(int size)
{
    return ((remote_read_proc != NULL) && (!dss_need_exec_local()) && (size <= (int32)DSS_LOADDISK_BUFFER_SIZE));
}

bool32 dss_need_exec_local(void)
{
    dss_config_t *cfg = dss_get_inst_cfg();
    uint32 master_id = dss_get_master_id();
    uint32 curr_id = (uint32)(cfg->params.inst_id);
    return ((curr_id == master_id));
}

status_t dss_read_volume_inst(
    dss_vg_info_item_t *vg_item, dss_volume_t *volume, int64 offset, void *buf, int32 size, bool32 *remote_chksum)
{
    status_t status = CM_ERROR;
    CM_ASSERT(offset % DSS_DISK_UNIT_SIZE == 0);
    CM_ASSERT(size % DSS_DISK_UNIT_SIZE == 0);
    CM_ASSERT(((uint64)buf) % DSS_DISK_UNIT_SIZE == 0);
    while (get_instance_status_proc != NULL && get_instance_status_proc() != DSS_STATUS_RECOVERY && dss_need_load_remote(size) == CM_TRUE &&
        status != CM_SUCCESS) {
        if (size == (int32)sizeof(dss_ctrl_t)) {
            LOG_RUN_INF("Try to load dssctrl from remote.");
        }
        status = remote_read_proc(vg_item->vg_name, volume, offset, buf, size);
        if (status != CM_SUCCESS) {
            if (status == DSS_READ4STANDBY_ERR || get_instance_status_proc() == DSS_STATUS_PREPARE) {
                LOG_RUN_ERR("Failed to load disk(%s) data from the active node, result:%d", volume->name_p, status);
                return CM_ERROR;
            }
            LOG_RUN_WAR("Failed to load disk(%s) data from the active node, result:%d", volume->name_p, status);
            cm_sleep(DSS_READ_REMOTE_INTERVAL);
            continue;
        }

        if (*remote_chksum == CM_TRUE) {
            if (dss_read_remote_checksum(buf, size) != CM_TRUE) {
                LOG_RUN_WAR("Failed to load disk(%s) data from the active node, checksum error", volume->name_p);
                status = CM_ERROR;
                continue;
            }
        }
        return status;
    }

    if (dss_is_server()) {
        uint32 recover_thread_id = dss_get_recover_thread_id();
        uint32 curr_thread_id = dss_get_current_thread_id();
        uint32 recover_status = get_instance_status_proc();
        if (recover_status != DSS_STATUS_OPEN && recover_thread_id != curr_thread_id &&
            vg_item->status == DSS_VG_STATUS_OPEN) {
            DSS_THROW_ERROR(ERR_DSS_RECOVER_CAUSE_BREAK);
            LOG_RUN_INF("Read volume inst break by recovery");
            return CM_ERROR;
        }
    }

    *remote_chksum = CM_FALSE;
    status = dss_read_volume(volume, offset, buf, size);
    if (status != CM_SUCCESS) {
        LOG_RUN_ERR("Failed to load disk(%s) data, result:%d", volume->name_p, status);
        return status;
    }

    return CM_SUCCESS;
}

status_t dss_read_volume_4standby(const char *vg_name, uint32 volume_id, int64 offset, void *buf, uint32 size)
{
    dss_vg_info_item_t *vg_item = dss_find_vg_item(vg_name);
    if (vg_item == NULL) {
        LOG_RUN_ERR("Read volume for standby failed, find vg(%s) error.", vg_name);
        return CM_ERROR;
    }

    if (volume_id >= DSS_MAX_VOLUMES) {
        LOG_RUN_ERR("Read volume for standby failed, vg(%s) volume id[%u] error.", vg_name, volume_id);
        return CM_ERROR;
    }

    dss_volume_t *volume = &vg_item->volume_handle[volume_id];
    if (volume->handle == DSS_INVALID_HANDLE) {
        if (dss_open_volume(volume->name_p, NULL, DSS_INSTANCE_OPEN_FLAG, volume) != CM_SUCCESS) {
            LOG_RUN_ERR("Read volume for standby failed, failed to open volume(%s).", volume->name_p);
            return CM_ERROR;
        }
    }

    uint64 volumesize = vg_item->dss_ctrl->core.volume_attrs[volume_id].size;
    if (((uint64)offset > volumesize) || ((uint64)size > (volumesize - (uint64)offset))) {
        LOG_RUN_ERR(
            "Read volume for standby failed, params err, vg(%s) voiume id[%u] offset[%llu] size[%u] volume size[%llu].",
            vg_name, volume_id, offset, size, volumesize);
        return CM_ERROR;
    }

    if (dss_read_volume(volume, offset, buf, (int32)size) != CM_SUCCESS) {
        LOG_RUN_ERR("Read volume for standby failed, failed to load disk(%s) data.", volume->name_p);
        return CM_ERROR;
    }

    LOG_DEBUG_INF("load disk(%s) data for standby success.", volume->name_p);
    return CM_SUCCESS;
}

bool32 dss_meta_syn(dss_session_t *session, dss_bg_task_info_t *bg_task_info)
{
    bool32 finish = CM_TRUE;
    for (uint32_t i = bg_task_info->vg_id_beg; i < bg_task_info->vg_id_end; i++) {
        bool32 cur_finish = dss_syn_buffer_cache(&g_vgs_info->volume_group[i]);
        if (!cur_finish && !finish) {
            finish = CM_FALSE;
        }
    }
    return finish;
}

#ifdef __cplusplus
}
#endif
