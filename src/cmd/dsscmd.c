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
 * dsscmd.c
 *
 *
 * IDENTIFICATION
 *    src/cmd/dsscmd.c
 *
 * -------------------------------------------------------------------------
 */

#ifndef WIN32
#include <unistd.h>
#include <sys/types.h>
#endif

#include "cm_base.h"
#include "cm_config.h"
#include "cm_dlock.h"
#include "cm_list.h"
#include "cm_system.h"
#include "cm_cipher.h"
#include "cm_encrypt.h"
#include "cm_utils.h"
#include "cm_signal.h"
#include "cm_sec_file.h"

#include "dss_errno.h"
#include "dss_defs.h"
#include "dss_malloc.h"
#include "dss_file.h"
#include "dss_io_fence.h"
#include "dss_api.h"
#include "dss_api_impl.h"
#include "dsscmd_inq.h"
#include "dsscmd_cli_msg.h"
#include "dsscmd_volume.h"
#include "dsscmd_showdisk.h"
#include "dsscmd_du.h"
#include "dsscmd_find.h"
#include "dsscmd_encrypt.h"
#include "dsscmd_conn_opt.h"
#include "dsscmd_interactive.h"
#ifndef WIN32
#include "config.h"
#endif

#ifdef WIN32
#define DEF_DSS_VERSION "Windows does not support this feature because it is built using vs."
#endif

// cmd format : cmd subcmd [-f val]
#define CMD_COMMAND_INJECTION_COUNT 22
#define DSS_DEFAULT_MEASURE "B"
#define DSS_SUBSTR_UDS_PATH "UDS:"
#define DSS_DEFAULT_VG_TYPE 't' /* show vg information in table format by default */
static const char dss_ls_print_flag[] = {'d', '-', 'l'};

typedef struct st_dss_print_help_t {
    char fmt;
    uint32 bytes;
} dss_print_help_t;

// add uni-check function after here
// ------------------------
static status_t cmd_check_flag(const char *input_flag)
{
    uint64 flag;
    status_t ret = cm_str2uint64(input_flag, &flag);
    if (ret != CM_SUCCESS) {
        DSS_PRINT_ERROR("The value of flag is invalid.\n");
        return CM_ERROR;
    }
    if (flag != 0 && flag != DSS_FILE_FLAG_INNER_INITED) {
        DSS_PRINT_ERROR("The value of flag must be 0 or 2147483648(means 0x80000000).\n");
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static status_t cmd_check_length(const char *input_length)
{
    uint64 length;
    status_t ret = cm_str2uint64(input_length, &length);
    if (ret != CM_SUCCESS) {
        DSS_PRINT_ERROR("The value of length is invalid.\n");
        return CM_ERROR;
    }
    if ((int64)length < 0) {
        DSS_PRINT_ERROR("The value of length must not be a negative number.\n");
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static status_t cmd_check_zero_or_one(const char *zero_or_one_str)
{
    uint32 zero_or_one;
    status_t ret = cm_str2uint32(zero_or_one_str, &zero_or_one);
    if (ret != CM_SUCCESS) {
        DSS_PRINT_ERROR("The value of zero_or_one is invalid.\n");
        return CM_ERROR;
    }
    if (zero_or_one != 0 && zero_or_one != 1) {
        DSS_PRINT_ERROR("The value of zero_or_one should be 0 or 1.\n");
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static status_t cmd_check_uds(const char *uds)
{
    const char *uds_prefix = "UDS:";
    if (strlen(uds) < strlen(uds_prefix) || memcmp(uds, uds_prefix, strlen(uds_prefix)) != 0) {
        DSS_PRINT_ERROR("uds name should start with %s.\n", uds_prefix);
        return CM_ERROR;
    }
    return dss_check_path(uds + strlen(uds_prefix));
}

static status_t dss_fetch_uds_path(char *server_path, char *path, char **file)
{
    char *pos = strrchr(server_path, '/');
    if (pos == NULL) {
        *file = server_path;
        path[0] = '.';
        path[1] = '\0';
        return CM_SUCCESS;
    }

    if (pos[1] == 0x00) {
        DSS_PRINT_ERROR("the format of UDS is wrong.\n");
        return CM_ERROR;
    }

    if (pos == server_path) {
        *file = (char *)(server_path + 1);
        path[0] = '/';
        path[1] = '\0';
    } else {
        *file = pos;
        errno_t errcode = memcpy_sp(path, (size_t)DSS_MAX_PATH_BUFFER_SIZE, server_path, (size_t)(pos - server_path));
        if (SECUREC_UNLIKELY(errcode != EOK)) {
            CM_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
            return CM_ERROR;
        }
        path[(int)(pos - server_path)] = '\0';
    }
    return CM_SUCCESS;
}

static status_t cmd_check_convert_uds_home(const char *input_args, void **convert_result, int *convert_size)
{
    const char *server_path = (const char *)(input_args + strlen(DSS_SUBSTR_UDS_PATH));
    char path[DSS_MAX_PATH_BUFFER_SIZE];
    char *file = NULL;
    status_t status = dss_fetch_uds_path((char *)server_path, (char *)path, (char **)&file);
    if (status != CM_SUCCESS) {
        DSS_PRINT_ERROR("Fetch uds path failed.\n");
        return CM_ERROR;
    }

    status = cmd_realpath_home(path, (char **)convert_result, convert_size);
    if (status != CM_SUCCESS) {
        DSS_PRINT_ERROR("home realpath failed, home: %s.\n", input_args);
        return status;
    }

    errno_t errcode = strcat_sp((char *)*convert_result, CM_FILE_NAME_BUFFER_SIZE, file);
    if (SECUREC_UNLIKELY(errcode != EOK)) {
        CM_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
        free(*convert_result);
        *convert_result = NULL;
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static status_t cmd_check_struct_name(const char *struct_name)
{
    if ((strcmp(struct_name, "core_ctrl") != 0) && (strcmp(struct_name, "vg_header") != 0) &&
        (strcmp(struct_name, "volume_ctrl") != 0) && (strcmp(struct_name, "root_ft_block") != 0)) {
        DSS_PRINT_ERROR("Incorrect struct_name input.\n");
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static status_t cmd_check_measure_type(const char *measure)
{
    if (strlen(measure) != 1) {
        DSS_PRINT_ERROR("The measure type len should be 1.\n");
        return CM_ERROR;
    }
    if ((measure[0] != 'B' && measure[0] != 'K' && measure[0] != 'M' && measure[0] != 'G' && measure[0] != 'T')) {
        DSS_PRINT_ERROR("measure_type error.\n");
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

static status_t cmd_check_inst_id(const char *inst_str)
{
    uint32 inst_id;
    status_t ret = cm_str2uint32(inst_str, &inst_id);
    if (ret != CM_SUCCESS) {
        DSS_PRINT_ERROR("The value of inst_id is invalid.\n");
        return CM_ERROR;
    }
    if (inst_id < DSS_MIN_INST_ID || inst_id >= DSS_MAX_INST_ID) {
        DSS_PRINT_ERROR("The value of inst_id should be in [%u, %u).\n", DSS_MIN_INST_ID, DSS_MAX_INST_ID);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static status_t cmd_check_block_index_id(const char *index_str)
{
    uint32 index_id;
    status_t ret = cm_str2uint32(index_str, &index_id);
    if (ret != CM_SUCCESS) {
        DSS_PRINT_ERROR("The value of index_id  or node_id is invalid.\n");
        return CM_ERROR;
    }
    uint32 max_block_index_id = MAX(DSS_FILE_SPACE_BLOCK_BITMAP_COUNT, DSS_MAX_FT_BLOCK_INDEX_ID);
    if (index_id < DSS_MIN_BLOCK_INDEX_ID || index_id >= max_block_index_id) {
        DSS_PRINT_ERROR(
            "The value of index_id or node_id should be in [%u, %u).\n", DSS_MIN_BLOCK_INDEX_ID, max_block_index_id);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static status_t cmd_check_show_type(const char *show_type)
{
    if (strlen(show_type) != 1) {
        DSS_PRINT_ERROR("The show type len should be 1.\n");
        return CM_ERROR;
    }
    if (show_type[0] != 'd' && show_type[0] != 't') {
        DSS_PRINT_ERROR("The show type should be [d|t].\n");
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static status_t cmd_check_inq_type(const char *inq_type)
{
    if (strcmp(inq_type, "lun") != 0 && strcmp(inq_type, "reg") != 0) {
        DSS_PRINT_ERROR("The show type should be [lun|reg].\n");
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static status_t cmd_check_disk_id(const char *id_str)
{
    uint64 id = 0;
    status_t status = cm_str2uint64(id_str, &id);
    if (status == CM_ERROR) {
        DSS_PRINT_ERROR("id_str:%s is not a valid uint64\n", id_str);
        return CM_ERROR;
    }
    dss_block_id_t *block_id = (dss_block_id_t *)&id;
    if (block_id->volume >= DSS_MAX_VOLUMES) {
        DSS_PRINT_ERROR("block_id is invalid, id = %llu, volume:%u.\n", id, (uint32)block_id->volume);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static status_t cmd_check_fid(const char *id_str)
{
    uint64 id = 0;
    status_t status = cm_str2uint64(id_str, &id);
    if (status == CM_ERROR) {
        DSS_PRINT_ERROR("fid:%s is not a valid uint64\n", id_str);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static status_t cmd_check_offset(const char *offset_str)
{
    int64 offset;
    status_t ret = cm_str2bigint(offset_str, &offset);
    if (ret != CM_SUCCESS) {
        DSS_PRINT_ERROR("The value of offset is invalid.\n");
        return CM_ERROR;
    }
    if (offset < 0 || offset % DSS_DISK_UNIT_SIZE != 0) {
        DSS_PRINT_ERROR("offset must be >= 0 and be align %d.\n", DSS_DISK_UNIT_SIZE);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static status_t cmd_check_format(const char *format)
{
    uint32 len = strlen(format);
    if (len == 0) {
        DSS_PRINT_ERROR("The value of format is invalid.\n");
        return CM_ERROR;
    }
    if (format[0] != 'c' && format[0] != 'h' && format[0] != 'u' && format[0] != 'l' && format[0] != 's' &&
        format[0] != 'x') {
        DSS_PRINT_ERROR("The name's letter of format should be [c|h|u|l|s|x].\n");
        return CM_ERROR;
    }
    if (format[1] != 0x00) {
        DSS_PRINT_ERROR("The name's letter of format should be [c|h|u|l|s|x].\n");
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static status_t cmd_check_read_size(const char *read_size_str)
{
    int32 read_size;
    status_t ret = cm_str2int(read_size_str, &read_size);
    if (ret != CM_SUCCESS) {
        DSS_PRINT_ERROR("The value of read_size is invalid.\n");
        return CM_ERROR;
    }

    if (read_size < 0) {
        DSS_PRINT_ERROR("The read_size should >= 0.\n");
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static status_t cmd_check_du_format(const char *du_format)
{
    uint32 len = strlen(du_format);
    if (len == 0) {
        DSS_PRINT_ERROR("The value of format is invalid.\n");
        return CM_ERROR;
    }
    int part_one = 0;
    int part_two = 0;
    int part_three = 0;
    for (uint32 i = 0; i < strlen(du_format); i++) {
        if (du_format[i] == 'B' || du_format[i] == 'K' || du_format[i] == 'M' || du_format[i] == 'G' ||
            du_format[i] == 'T') {
            if (part_one == 1) {
                DSS_PRINT_ERROR("The name's letter of du_format should be [BKMGT|sa|S].\n");
                return CM_ERROR;
            }
            part_one = 1;
        } else if (du_format[i] == 's' || du_format[i] == 'a') {
            if (part_two == 1) {
                DSS_PRINT_ERROR("The name's letter of du_format should be [BKMGT|sa|S].\n");
                return CM_ERROR;
            }
            part_two = 1;
        } else if (du_format[i] == 'S') {
            if (part_three == 1) {
                DSS_PRINT_ERROR("The name's letter of du_format should be [BKMGT|sa|S].\n");
                return CM_ERROR;
            }
            part_three = 1;
        } else {
            DSS_PRINT_ERROR("The name's letter of du_format should be [BKMGT|sa|S].\n");
            return CM_ERROR;
        }
    }
    return CM_SUCCESS;
}

static status_t cmd_check_cfg_name(const char *name)
{
    uint32 len = strlen(name);
    for (uint32 i = 0; i < len; i++) {
        if (!isalpha((int)name[i]) && !isdigit((int)name[i]) && name[i] != '-' && name[i] != '_') {
            DSS_PRINT_ERROR("The name's letter should be [alpha|digit|-|_].\n");
            return CM_ERROR;
        }
    }
    return CM_SUCCESS;
}

static status_t cmd_check_cfg_value(const char *value)
{
    uint32 len = strlen(value);
    if (len < 0) {
        DSS_PRINT_ERROR("The value is invalid.\n");
        return CM_ERROR;
    }
    for (uint32 i = 0; i < len; i++) {
        if (!isprint((int)value[i])) {
            DSS_PRINT_ERROR("The value's letter should be print-able.\n");
            return CM_ERROR;
        }
    }
    return CM_SUCCESS;
}

static status_t cmd_check_cfg_scope(const char *scope)
{
    const char *scope_memory = "memory";
    const char *scope_pfile = "pfile";
    const char *scope_both = "both";
    if (strcmp(scope, scope_memory) != 0 && strcmp(scope, scope_pfile) != 0 && strcmp(scope, scope_both) != 0) {
        DSS_PRINT_ERROR("scope should be [%s | %s | %s].\n", scope_memory, scope_pfile, scope_both);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

// ------------------------
// add uni-check function before here
static inline void help_param_dsshome(void)
{
    (void)printf("-D/--DSS_HOME <DSS_HOME>, [optional], the run path of dssserver, default value is $DSS_HOME\n");
}

static inline void help_param_uds(void)
{
    (void)printf("-U/--UDS <UDS:socket_domain>, [optional], the unix socket path of dssserver, "
                 "default value is UDS:$DSS_HOME/.dss_unix_d_socket\n");
}

static dss_args_t cmd_cv_args[] = {
    {'g', "vg_name", CM_TRUE, CM_TRUE, dss_check_name, NULL, NULL, 0, NULL, NULL, 0},
    {'v', "vol_path", CM_TRUE, CM_TRUE, dss_check_volume_path, NULL, NULL, 0, NULL, NULL, 0},
    {'s', "au_size", CM_FALSE, CM_TRUE, cmd_check_au_size, NULL, NULL, 0, NULL, NULL, 0},
    {'D', "DSS_HOME", CM_FALSE, CM_TRUE, cmd_check_dss_home, cmd_check_convert_dss_home, cmd_clean_check_convert, 0,
        NULL, NULL, 0},
};
static dss_args_set_t cmd_cv_args_set = {
    cmd_cv_args,
    sizeof(cmd_cv_args) / sizeof(dss_args_t),
    NULL,
};

static void cv_help(const char *prog_name, int print_flag)
{
    (void)printf("\nUsage:%s cv <-g vg_name> <-v vol_path> [-s au_size] [-D DSS_HOME]\n", prog_name);
    (void)printf("[manage command] create volume group\n");
    if (print_flag == DSS_HELP_SIMPLE) {
        return;
    }
    (void)printf("-g/--vg_name <vg_name>, <required>, the volume group name\n");
    (void)printf("-v/--vol_path <vol_path>, <required>, the volume path\n");
    (void)printf("-s/--au_size [au_size], [optional], the size of single alloc unit of volume, unit is KB, "
                 "at least 2MB, default value is 2MB\n");
    help_param_dsshome();
}

static status_t cv_proc(void)
{
    status_t status;

    const char *vg_name;
    const char *volume_path;
    dss_config_t cv_cfg;
    vg_name = cmd_cv_args[DSS_ARG_IDX_0].input_args;
    volume_path = cmd_cv_args[DSS_ARG_IDX_1].input_args;
    // Documentation Constraints:au_size=0 equals default_au_size
    int64 au_size = 0;
    if (cmd_cv_args[DSS_ARG_IDX_2].input_args) {
        status = cm_str2bigint(cmd_cv_args[DSS_ARG_IDX_2].input_args, &au_size);
        DSS_RETURN_IFERR2(
            status, DSS_PRINT_ERROR("au_size:%s is not a valid int64.\n", cmd_cv_args[DSS_ARG_IDX_2].input_args));
    }
    char *home = cmd_cv_args[DSS_ARG_IDX_3].input_args;

    status = dss_set_cfg_dir(home, &cv_cfg);
    if (status != CM_SUCCESS) {
        DSS_PRINT_ERROR("Environment variant DSS_HOME not found!\n");
        return status;
    }
    status = dss_load_config(&cv_cfg);
    if (status != CM_SUCCESS) {
        DSS_PRINT_ERROR("Failed to load parameters!\n");
        return status;
    }
    status = dss_create_vg(vg_name, volume_path, &cv_cfg, (uint32)au_size);
    if (status != CM_SUCCESS) {
        DSS_PRINT_ERROR("Failed to create volume group, vg name is %s, volume path is %s.\n", vg_name, volume_path);
        return status;
    }
    DSS_PRINT_INF("Succeed to create volume group %s, entry volume is %s.\n", vg_name, volume_path);
    return CM_SUCCESS;
}

static dss_args_t cmd_lsvg_args[] = {
    {'m', "measure_type", CM_FALSE, CM_TRUE, cmd_check_measure_type, NULL, NULL, 0, NULL, NULL, 0},
    {'t', "show_type", CM_FALSE, CM_TRUE, cmd_check_show_type, NULL, NULL, 0, NULL, NULL, 0},
    {'U', "UDS", CM_FALSE, CM_TRUE, cmd_check_uds, cmd_check_convert_uds_home, cmd_clean_check_convert, 0, NULL, NULL,
        0},
};
static dss_args_set_t cmd_lsvg_args_set = {
    cmd_lsvg_args,
    sizeof(cmd_lsvg_args) / sizeof(dss_args_t),
    NULL,
};

static void lsvg_help(const char *prog_name, int print_flag)
{
    (void)printf("\nUsage:%s lsvg [-m measure_type] [-t show_type] [-U UDS:socket_domain]\n", prog_name);
    (void)printf("[client command]Show information of volume group and disk usage space\n");
    if (print_flag == DSS_HELP_SIMPLE) {
        return;
    }
    (void)printf("-m/--measure_type <measure_type>, [optional], B show size by Byte, K show size by kB ,"
                 "M show size by MB ,G show size by GB,  T show size by TB, default show size by Byte\n");
    (void)printf("-t/--show_type <show_type>, [optional], d show information in detail , t show information in table, "
                 "default value is 't'\n");
    help_param_uds();
}

static status_t dss_load_volumes(vg_vlm_space_info_t *volume_space, dss_volume_def_t *defs, const dss_ctrl_t *dss_ctrl)
{
    double dss_vg_free = 0;
    double dss_vg_size = 0;
    for (uint32 vol_id = 0; vol_id < DSS_MAX_VOLUMES; vol_id++) {
        if (defs[vol_id].flag == VOLUME_FREE) {
            continue;
        }

        if (strcpy_s(volume_space->volume_space_info[vol_id].volume_name, DSS_MAX_VOLUME_PATH_LEN, defs[vol_id].name) !=
            EOK) {
            return CM_ERROR;
        }

        double volume_free = (double)dss_ctrl->core.volume_attrs[vol_id].free;
        volume_space->volume_space_info[vol_id].volume_free = volume_free;

        dss_vg_free = dss_vg_free + volume_free;
        volume_space->vg_space_info.dss_vg_free = dss_vg_free;

        double volume_size = (double)dss_ctrl->core.volume_attrs[vol_id].size;
        volume_space->volume_space_info[vol_id].volume_size = volume_size;

        dss_vg_size = dss_vg_size + volume_size;
        volume_space->vg_space_info.dss_vg_size = dss_vg_size;

        double volume_used =
            (double)dss_ctrl->core.volume_attrs[vol_id].size - (double)dss_ctrl->core.volume_attrs[vol_id].free;
        volume_space->volume_space_info[vol_id].volume_used = volume_used;
    }
    return CM_SUCCESS;
}

static status_t dss_load_vginfo_sync_core(
    dss_conn_t *connection, dss_allvg_vlm_space_t *allvg_vlm_space_t, dss_vg_info_t *dss_vg_info)
{
    status_t status;
    for (uint32 vg_id = 0; vg_id < (uint32)dss_vg_info->group_num; vg_id++) {
        dss_vg_info_item_t *vg_item = &dss_vg_info->volume_group[vg_id];
        if (vg_item == NULL) {
            LOG_DEBUG_ERR("load vg item failed for vgid:%u.\n", vg_id);
            return CM_ERROR;
        }

        status = dss_load_ctrl_sync(connection, vg_item->vg_name, DSS_VG_INFO_CORE_CTRL);
        if (status != CM_SUCCESS) {
            LOG_DEBUG_ERR("load vginfo core ctrl failed, vg name %s.\n", vg_item->vg_name);
            return CM_ERROR;
        }

        status = dss_load_ctrl_sync(connection, vg_item->vg_name, DSS_VG_INFO_VOLUME_CTRL);
        if (status != CM_SUCCESS) {
            LOG_DEBUG_ERR("load vginfo volume ctrl failed, vg name %s.\n", vg_item->vg_name);
            return CM_ERROR;
        }

        dss_ctrl_t *dss_ctrl = vg_item->dss_ctrl;
        dss_core_ctrl_t *core_ctrl = &dss_ctrl->core;
        uint32 volume_count = core_ctrl->volume_count;

        dss_volume_ctrl_t *volume_ctrl = &dss_ctrl->volume;
        dss_volume_def_t *defs = volume_ctrl->defs;

        allvg_vlm_space_t->group_num++;
        if (strcpy_s(allvg_vlm_space_t->volume_group[vg_id].vg_name, DSS_MAX_NAME_LEN, vg_item->vg_name) != EOK) {
            return CM_ERROR;
        }
        allvg_vlm_space_t->volume_group[vg_id].volume_count = volume_count;
        vg_vlm_space_info_t *volume_space = &allvg_vlm_space_t->volume_group[vg_id];
        status = dss_load_volumes(volume_space, defs, dss_ctrl);
        if (status != CM_SUCCESS) {
            return status;
        }
    }
    return CM_SUCCESS;
}

static status_t dss_load_vginfo_sync(dss_conn_t *connection, dss_allvg_vlm_space_t *allvg_vlm_space_t)
{
    status_t status;
    dss_env_t *dss_env = dss_get_env();
    if (!dss_env->initialized) {
        DSS_THROW_ERROR(ERR_DSS_ENV_NOT_INITIALIZED);
        return CM_ERROR;
    }
    dss_latch_s(&dss_env->latch);
    status = dss_load_vginfo_sync_core(connection, allvg_vlm_space_t, g_vgs_info);
    dss_unlatch(&dss_env->latch);
    return status;
}

double dss_convert_size(double size, const char *measure)
{
    double result = size;
    switch (measure[0]) {
        case 'T':
            result /= SIZE_T(1);
            break;
        case 'G':
            result /= SIZE_G(1);
            break;
        case 'M':
            result /= SIZE_M(1);
            break;
        case 'K':
            result /= SIZE_K(1);
            break;
        default:
            break;
    }
    return result;
}

static void cmd_print_no_path_err()
{
    DSS_PRINT_ERROR("Need to input arg [-p|--path] or cd to a path.\n");
}

static void lsvg_printf_vlm_info(vg_vlm_space_info_t *vg_vlm_info, const char *measure, bool32 detail)
{
    if (detail) {
        (void)printf("vg_name:%s\n", vg_vlm_info->vg_name);
        (void)printf("   volume_count:%u\n", vg_vlm_info->volume_count);
        (void)printf("   volumes:\n");
        for (uint32 vol_id = 0; vol_id < DSS_MAX_VOLUMES; vol_id++) {
            if ((uint64)vg_vlm_info->volume_space_info[vol_id].volume_size == 0) {
                continue;
            }
            (void)printf("      volume_name:%s\n", vg_vlm_info->volume_space_info[vol_id].volume_name);
            double volume_free = vg_vlm_info->volume_space_info[vol_id].volume_free;
            volume_free = dss_convert_size(volume_free, measure);
            double volume_size = vg_vlm_info->volume_space_info[vol_id].volume_size;
            volume_size = dss_convert_size(volume_size, measure);
            double volume_used = vg_vlm_info->volume_space_info[vol_id].volume_used;
            volume_used = dss_convert_size(volume_used, measure);
            (void)printf("      volume_free:%.05f\n", volume_free);
            (void)printf("      volume_size:%.05f\n", volume_size);
            (void)printf("      volume_used:%.05f\n", volume_used);
        }
    }
}

static void lsvg_printf_vg_info(
    const vg_vlm_space_info_t *vg_vlm_info, double dss_vg_recycle_size_tmp, const char *measure, bool32 detail)
{
    double dss_vg_used_percent = 0;
    double dss_vg_size = vg_vlm_info->vg_space_info.dss_vg_size;
    double dss_vg_free = vg_vlm_info->vg_space_info.dss_vg_free + dss_vg_recycle_size_tmp;
    double dss_vg_used = dss_vg_size - dss_vg_free;
    double dss_vg_recycle_size = dss_convert_size(dss_vg_recycle_size_tmp, measure);
    dss_vg_size = dss_convert_size(dss_vg_size, measure);
    dss_vg_free = dss_convert_size(dss_vg_free, measure);
    dss_vg_used = dss_convert_size(dss_vg_used, measure);

    dss_vg_used_percent = (dss_vg_used / dss_vg_size) * 100;
    if (detail) {
        (void)printf("   .recycle:\n");
        (void)printf("      recycle_size:%.05f\n", dss_vg_recycle_size);
        (void)printf("   vg_size:%.05f\n", dss_vg_size);
        (void)printf("   vg_free:%.05f\n", dss_vg_free);
        (void)printf("   vg_used:%.05f\n", dss_vg_used);
        (void)printf("   vg_used_percent:%.2lf\n", dss_vg_used_percent);
    } else {
        (void)printf("%-14s%-20u%-20.05f %-20.05f %-20.05f %-20.2lf\n", vg_vlm_info->vg_name, vg_vlm_info->volume_count,
            dss_vg_size, dss_vg_free, dss_vg_used, dss_vg_used_percent);
    }
}

static status_t lsvg_operate_dir_impl(vg_vlm_space_info_t *vg_vlm_info, double *dss_vg_recycle_size,
    dss_conn_t *connection, const char *measure, bool32 detail)
{
    errno_t ret;
    char dirpath[DSS_FILE_PATH_MAX_LENGTH];
    gft_node_t *node;
    if (vg_vlm_info == NULL) {
        LOG_DEBUG_ERR("Failed to find vg.\n");
        return CM_ERROR;
    }
    lsvg_printf_vlm_info(vg_vlm_info, measure, detail);
    ret = snprintf_s(dirpath, sizeof(dirpath), sizeof(dirpath) - 1, "+%s/.recycle", vg_vlm_info->vg_name);
    if (ret == -1) {
        DSS_THROW_ERROR(ERR_SYSTEM_CALL, ret);
        return CM_ERROR;
    }

    dss_dir_t *dir = dss_open_dir_impl(connection, dirpath, CM_TRUE);
    if (dir == NULL) {
        LOG_DEBUG_ERR("Failed to open dir %s.\n", dirpath);
        return CM_ERROR;
    }

    while ((node = (gft_node_t *)dss_read_dir_impl(connection, dir, CM_FALSE)) != NULL) {
        *dss_vg_recycle_size = *dss_vg_recycle_size + (double)node->size;
    }
    (void)dss_close_dir_impl(connection, dir);
    return CM_SUCCESS;
}

static status_t lsvg_info(dss_conn_t *connection, const char *measure, bool32 detail)
{
    status_t status;
    dss_allvg_vlm_space_t *allvg_vlm_space_info = NULL;
    allvg_vlm_space_info = (dss_allvg_vlm_space_t *)cm_malloc(sizeof(dss_allvg_vlm_space_t));
    if (allvg_vlm_space_info == NULL) {
        LOG_DEBUG_ERR("Malloc failed.\n");
        return CM_ERROR;
    }
    (void)memset_s(allvg_vlm_space_info, sizeof(dss_allvg_vlm_space_t), 0, sizeof(dss_allvg_vlm_space_t));
    status = dss_load_vginfo_sync(connection, allvg_vlm_space_info);
    if (status != CM_SUCCESS) {
        LOG_DEBUG_ERR("Failed to load vg information.\n");
        DSS_FREE_POINT(allvg_vlm_space_info);
        return status;
    }

    if (!detail) {
        (void)printf(
            "%-14s%-20s%-20s %-20s %-20s %-20s\n", "vg_name", "volume_count", "size", "free", "used", "percent(%)");
    }

    for (uint32 vg_id = 0; vg_id < (uint32)allvg_vlm_space_info->group_num; vg_id++) {
        double dss_vg_recycle_size = 0;
        vg_vlm_space_info_t *vg_vlm_info = &allvg_vlm_space_info->volume_group[vg_id];
        status = lsvg_operate_dir_impl(vg_vlm_info, &dss_vg_recycle_size, connection, measure, detail);
        if (status != CM_SUCCESS) {
            DSS_FREE_POINT(allvg_vlm_space_info);
            return status;
        }
        lsvg_printf_vg_info(vg_vlm_info, dss_vg_recycle_size, measure, detail);
    }

    DSS_FREE_POINT(allvg_vlm_space_info);
    return CM_SUCCESS;
}

status_t get_default_server_locator(char *server_locator)
{
    char name[CM_MAX_PATH_LEN] = "LSNR_PATH";
    char *value = NULL;
    status_t status = dss_get_cfg_param(name, &value);
    if (status != CM_SUCCESS) {
        DSS_PRINT_ERROR("get cfg param failed, by %s.\n", name);
        return CM_ERROR;
    }
    const size_t PATH_SIZE = DSS_MAX_PATH_BUFFER_SIZE;
    int ret = snprintf_s(server_locator, PATH_SIZE, PATH_SIZE - 1, "UDS:%s/.dss_unix_d_socket", value);
    if (ret < 0) {
        DSS_PRINT_ERROR("Failed(%d) to snsprintf_s server_locator\n", ret);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

status_t get_specified_server_locator(const char *input_args, char *server_locator)
{
    errno_t errcode = strcpy_s(server_locator, DSS_MAX_PATH_BUFFER_SIZE, input_args);
    if (errcode != EOK) {
        DSS_PRINT_ERROR("Failed(%d) to strcpy_s of server_locator\n", errcode);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

status_t get_server_locator(const char *input_uds_home_args, char *server_locator)
{
    if (input_uds_home_args != NULL) {
        return get_specified_server_locator(input_uds_home_args, server_locator);
    }
    return get_default_server_locator(server_locator);
}

static status_t lsvg_get_parameter(const char **measure, bool32 *detail)
{
    if (cmd_lsvg_args[DSS_ARG_IDX_0].input_args != NULL) {
        *measure = cmd_lsvg_args[DSS_ARG_IDX_0].input_args;
    } else {
        *measure = DSS_DEFAULT_MEASURE;
    }

    char show_type = DSS_DEFAULT_VG_TYPE;
    if (cmd_lsvg_args[DSS_ARG_IDX_1].input_args != NULL) {
        show_type = cmd_lsvg_args[DSS_ARG_IDX_1].input_args[0];
    }
    if (show_type == 'd') {
        (*detail) = CM_TRUE;
    } else if (show_type == 't') {
        (*detail) = CM_FALSE;
    } else {
        DSS_PRINT_ERROR("show_type error.\n");
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static status_t lsvg_proc(void)
{
    bool32 detail;
    const char *measure;
    status_t status = lsvg_get_parameter(&measure, &detail);
    if (status != CM_SUCCESS) {
        return status;
    }

    const char *uds_path = cmd_lsvg_args[DSS_ARG_IDX_2].input_args;
    dss_conn_t *conn = dss_get_connection_opt(uds_path);
    if (conn == NULL) {
        DSS_PRINT_ERROR("Failed to get uds connection.\n");
        return CM_ERROR;
    }

    status = lsvg_info(conn, measure, detail);
    if (status != CM_SUCCESS) {
        DSS_PRINT_ERROR("Failed to display lsvg info.\n");
        return status;
    }
    DSS_PRINT_INF("Succeed to display lsvg info.\n");
    return CM_SUCCESS;
}

static dss_args_t cmd_adv_args[] = {
    {'g', "vg_name", CM_TRUE, CM_TRUE, dss_check_name, NULL, NULL, 0, NULL, NULL, 0},
    {'v', "vol_path", CM_TRUE, CM_TRUE, dss_check_volume_path, NULL, NULL, 0, NULL, NULL, 0},
    {'f', "force", CM_FALSE, CM_FALSE, NULL, NULL, NULL, 0, NULL, NULL, 0},
    {'D', "DSS_HOME", CM_FALSE, CM_TRUE, cmd_check_dss_home, cmd_check_convert_dss_home, cmd_clean_check_convert, 0,
        NULL, NULL, 0},
    {'U', "UDS", CM_FALSE, CM_TRUE, cmd_check_uds, cmd_check_convert_uds_home, cmd_clean_check_convert, 0, NULL, NULL,
        0},
};
static dss_args_set_t cmd_adv_args_set = {
    cmd_adv_args,
    sizeof(cmd_adv_args) / sizeof(dss_args_t),
    NULL,
};

static void adv_help(const char *prog_name, int print_flag)
{
    (void)printf("\nUsage:%s adv <-g vg_name> <-v vol_path> [-f] [-D DSS_HOME] [-U UDS:socket_domain]\n", prog_name);
    (void)printf("[client command]add volume in volume group\n");
    if (print_flag == DSS_HELP_SIMPLE) {
        return;
    }
    (void)printf("-g/--vg_name <vg_name>, <required>, the volume group name need to add volume\n");
    (void)printf("-v/--vol_path <vol_path>, <required>, the volume path need to be added to volume group\n");
    (void)printf("-f/--force, <required>, add volume offline forcibly\n");
    help_param_dsshome();
    help_param_uds();
}

static status_t adv_proc(void)
{
    const char *vg_name = cmd_adv_args[DSS_ARG_IDX_0].input_args;
    const char *vol_path = cmd_adv_args[DSS_ARG_IDX_1].input_args;
    bool32 force = cmd_adv_args[DSS_ARG_IDX_2].inputed ? CM_TRUE : CM_FALSE;
    const char *home = cmd_adv_args[DSS_ARG_IDX_3].input_args;
    status_t status;

    if (force) {
        status = dss_modify_volume_offline(home, vg_name, vol_path, NULL, VOLUME_MODIFY_ADD);
        if (status != CM_SUCCESS) {
            DSS_PRINT_ERROR("Failed to add volume offline, vg_name is %s, volume path is %s.\n", vg_name, vol_path);
        } else {
            DSS_PRINT_INF("Succeed to add volume offline, vg_name is %s, volume path is %s.\n", vg_name, vol_path);
        }
        return status;
    }
    const char *uds_path = cmd_adv_args[DSS_ARG_IDX_4].input_args;
    dss_conn_t *conn = dss_get_connection_opt(uds_path);
    if (conn == NULL) {
        DSS_PRINT_ERROR("Failed to get uds connection.\n");
        return CM_ERROR;
    }
    status = dsscmd_adv_impl(conn, vg_name, vol_path);
    if (status != CM_SUCCESS) {
        DSS_PRINT_ERROR("Failed to add volume online, vg_name is %s, volume path is %s.\n", vg_name, vol_path);
    } else {
        DSS_PRINT_INF("Succeed to add volume online, vg_name is %s, volume path is %s.\n", vg_name, vol_path);
    }
    return status;
}

static dss_args_t cmd_mkdir_args[] = {
    {'p', "path", CM_TRUE, CM_TRUE, dss_cmd_check_device_path, cmd_check_convert_path, cmd_clean_check_convert, 0, NULL,
        NULL, 0},
    {'d', "dir_name", CM_TRUE, CM_TRUE, dss_check_name, NULL, NULL, 0, NULL, NULL, 0},
    {'U', "UDS", CM_FALSE, CM_TRUE, cmd_check_uds, cmd_check_convert_uds_home, cmd_clean_check_convert, 0, NULL, NULL,
        0},
};
static dss_args_set_t cmd_mkdir_args_set = {
    cmd_mkdir_args,
    sizeof(cmd_mkdir_args) / sizeof(dss_args_t),
    NULL,
};

static void mkdir_help(const char *prog_name, int print_flag)
{
    if (g_run_interatively) {
        (void)printf("\nUsage:%s mkdir <-d dir_name> [-p path] [-U UDS:socket_domain]\n", prog_name);
    } else {
        (void)printf("\nUsage:%s mkdir <-p path> <-d dir_name> [-U UDS:socket_domain]\n", prog_name);
    }
    (void)printf("[client command]make dir\n");
    if (print_flag == DSS_HELP_SIMPLE) {
        return;
    }
    if (g_run_interatively) {
        (void)printf("-p/--path <path>, [optional], the name need to add dir\n");
    } else {
        (void)printf("-p/--path <path>, <required>, the name need to add dir\n");
    }
    (void)printf("-d/--dir_name <dir_name>, <required>, the dir name need to be added to path\n");
    help_param_uds();
}

static status_t mkdir_proc(void)
{
    const char *path = cmd_mkdir_args[DSS_ARG_IDX_0].input_args;
    if (cmd_mkdir_args[DSS_ARG_IDX_0].convert_result != NULL) {
        path = cmd_mkdir_args[DSS_ARG_IDX_0].convert_result;
    }
    if (path == NULL) {
        if (g_cur_path[0] == '\0') {
            cmd_print_no_path_err();
            return CM_ERROR;
        }
        path = g_cur_path;
    }

    const char *dir_name = cmd_mkdir_args[DSS_ARG_IDX_1].input_args;
    const char *uds_path = cmd_mkdir_args[DSS_ARG_IDX_2].input_args;
    dss_conn_t *conn = dss_get_connection_opt(uds_path);
    if (conn == NULL) {
        return CM_ERROR;
    }
    status_t status = dss_make_dir_impl(conn, path, dir_name);
    if (status != CM_SUCCESS) {
        DSS_PRINT_ERROR("Failed to make dir, path is %s, dir name is %s.\n", path, dir_name);
    } else {
        DSS_PRINT_INF("Succeed to make dir, path is %s, dir name is %s.\n", path, dir_name);
    }
    return status;
}

#define DSS_CMD_TOUCH_ARGS_PATH 0
#define DSS_CMD_TOUCH_ARGS_UDS 1
#define DSS_CMD_TOUCH_ARGS_FLAG 2
static dss_args_t cmd_touch_args[] = {
    {'p', "path", CM_TRUE, CM_TRUE, dss_cmd_check_device_path, cmd_check_convert_path, cmd_clean_check_convert, 0, NULL,
        NULL, 0},
    {'U', "UDS", CM_FALSE, CM_TRUE, cmd_check_uds, cmd_check_convert_uds_home, cmd_clean_check_convert, 0, NULL, NULL,
        0},
    {'f', "flag", CM_FALSE, CM_TRUE, cmd_check_flag, NULL, NULL, 0, NULL, NULL, 0},
};
static dss_args_set_t cmd_touch_args_set = {
    cmd_touch_args,
    sizeof(cmd_touch_args) / sizeof(dss_args_t),
    NULL,
};

static void touch_help(const char *prog_name, int print_flag)
{
    (void)printf("\nUsage:%s touch <-p path> [-U UDS:socket_domain]\n", prog_name);
    (void)printf("[client command]create file\n");
    if (print_flag == DSS_HELP_SIMPLE) {
        return;
    }
    if (g_run_interatively) {
        (void)printf("-p/--path <path>, <required>, file need to touch\n");
    } else {
        (void)printf("-p/--path <path>, <required>, file need to touch, path must begin with '+'\n");
    }
    (void)printf("-f/--flag <flag>, [optional], file flag need to set\n");
    help_param_uds();
}

static status_t touch_proc(void)
{
    const char *path = cmd_touch_args[DSS_CMD_TOUCH_ARGS_PATH].input_args;
    if (cmd_touch_args[DSS_CMD_TOUCH_ARGS_PATH].convert_result != NULL) {
        path = cmd_touch_args[DSS_CMD_TOUCH_ARGS_PATH].convert_result;
    }

    const char *input_args = cmd_touch_args[DSS_CMD_TOUCH_ARGS_UDS].input_args;
    dss_conn_t *conn = dss_get_connection_opt(input_args);
    if (conn == NULL) {
        return CM_ERROR;
    }

    int64 flag = 0;
    if (cmd_touch_args[DSS_CMD_TOUCH_ARGS_FLAG].inputed) {
        status_t status = cm_str2bigint(cmd_touch_args[DSS_CMD_TOUCH_ARGS_FLAG].input_args, &flag);
        if (status != CM_SUCCESS) {
            return status;
        }
    }

    status_t status = (status_t)dss_create_file_impl(conn, path, (int32)flag);
    if (status != CM_SUCCESS) {
        DSS_PRINT_ERROR("Failed to create file, name is %s.\n", path);
    } else {
        DSS_PRINT_INF("Succeed to create file, name is %s.\n", path);
    }
    return status;
}

static dss_args_t cmd_ts_args[] = {
    {'U', "UDS", CM_FALSE, CM_TRUE, cmd_check_uds, cmd_check_convert_uds_home, cmd_clean_check_convert, 0, NULL, NULL,
        0},
};

static dss_args_set_t cmd_ts_args_set = {
    cmd_ts_args,
    sizeof(cmd_ts_args) / sizeof(dss_args_t),
    NULL,
};

static void ts_help(const char *prog_name, int print_flag)
{
    (void)printf("\nUsage:%s ts [-U UDS:socket_domain]\n", prog_name);
    (void)printf("[client command]Show current API invoking time\n");
    if (print_flag == DSS_HELP_SIMPLE) {
        return;
    }
    help_param_uds();
}

static status_t ts_proc(void)
{
    status_t status = CM_SUCCESS;
    const char *input_args = cmd_ts_args[DSS_ARG_IDX_0].input_args;
    dss_conn_t *conn = dss_get_connection_opt(input_args);
    if (conn == NULL) {
        return CM_ERROR;
    }

    dss_stat_item_t time_stat[DSS_EVT_COUNT];
    status = dss_get_time_stat_on_server(conn, time_stat, DSS_EVT_COUNT);
    if (status != CM_SUCCESS) {
        DSS_PRINT_ERROR("Failed to get time stat.\n");
        return CM_ERROR;
    }
    (void)printf("|      event     |   count   | total_wait_time | avg_wait_time | max_single_time \n");
    (void)printf("+------------------------+-----------+-----------------+---------------+-----------------\n");
    for (int i = 0; i < DSS_EVT_COUNT; i++) {
        if (time_stat[i].wait_count == 0) {
            (void)printf("|%-24s|%-11d|%-17d|%-15d|%-17d\n", dss_get_stat_event(i), 0, 0, 0, 0);
            continue;
        }
        (void)printf("|%-24s|%-11lld|%-17lld|%-15lld|%-17lld\n", dss_get_stat_event(i), time_stat[i].wait_count,
            time_stat[i].total_wait_time, time_stat[i].total_wait_time / time_stat[i].wait_count,
            time_stat[i].max_single_time);
    }
    (void)printf("+------------------------+-----------+-----------------+---------------+-----------------\n");
    return CM_SUCCESS;
}

#define DSS_CMD_LS_PATH_IDX 0
#define DSS_CMD_LS_MEASURE_IDX 1
#define DSS_CMD_LS_UDS_IDX 2
#define DSS_CMD_LS_MIN_INITED_SIZE 3

static dss_args_t cmd_ls_args[] = {
    {'p', "path", CM_TRUE, CM_TRUE, dss_cmd_check_device_path, cmd_check_convert_path, cmd_clean_check_convert, 0, NULL,
        NULL, 0},
    {'m', "measure_type", CM_FALSE, CM_TRUE, cmd_check_measure_type, NULL, NULL, 0, NULL, NULL, 0},
    {'U', "UDS", CM_FALSE, CM_TRUE, cmd_check_uds, cmd_check_convert_uds_home, cmd_clean_check_convert, 0, NULL, NULL,
        0},
    {'w', "min_inited_size", CM_FALSE, CM_TRUE, cmd_check_zero_or_one, NULL, NULL, 0, NULL, NULL, 0},
};

static dss_args_set_t cmd_ls_args_set = {
    cmd_ls_args,
    sizeof(cmd_ls_args) / sizeof(dss_args_t),
    NULL,
};

static void ls_help(const char *prog_name, int print_flag)
{
    if (g_run_interatively) {
        (void)printf(
            "\nUsage:%s ls [-p path] [-m measure_type] [-w min_inited_size] [-U UDS:socket_domain]\n", prog_name);
    } else {
        (void)printf(
            "\nUsage:%s ls <-p path> [-m measure_type] [-w min_inited_size] [-U UDS:socket_domain]\n", prog_name);
    }
    (void)printf("[client command]Show information of volume group and disk usage space\n");
    if (print_flag == DSS_HELP_SIMPLE) {
        return;
    }
    if (g_run_interatively) {
        (void)printf("-p/--path <path>, [optional], show information for it\n");
    } else {
        (void)printf("-p/--path <path>, <required>, show information for it\n");
    }
    (void)printf("-m/--measure_type <measure_type>, [optional], B show size by Byte, K show size by kB ,"
                 "M show size by MB ,G show size by GB,  T show size by TB, default show size by Byte\n");
    (void)printf("-w/ --min_inited_size <min_inited_size>, [optional], "
                 "1 show min_inited_size, 0 not show min_inited_size\n");
    help_param_uds();
}

static status_t ls_get_parameter(const char **path, const char **measure, uint32 *show_min_inited_size)
{
    *path = cmd_ls_args[DSS_CMD_LS_PATH_IDX].input_args;
    if (cmd_ls_args[DSS_CMD_LS_PATH_IDX].convert_result != NULL) {
        *path = cmd_ls_args[DSS_CMD_LS_PATH_IDX].convert_result;
    }
    if (*path == NULL) {
        if (g_cur_path[0] == '\0') {
            cmd_print_no_path_err();
            return CM_ERROR;
        }
        *path = g_cur_path;
    }

    char *ls_measure_input_args = cmd_ls_args[DSS_CMD_LS_MEASURE_IDX].input_args;
    *measure = ls_measure_input_args != NULL ? ls_measure_input_args : DSS_DEFAULT_MEASURE;
    if (cmd_ls_args[DSS_CMD_LS_MIN_INITED_SIZE].input_args == NULL) {
        *show_min_inited_size = 0;
    } else {
        status_t status = cm_str2uint32(cmd_ls_args[DSS_CMD_LS_MIN_INITED_SIZE].input_args, show_min_inited_size);
        if (status != CM_SUCCESS) {
            DSS_PRINT_ERROR("The value of zero_or_one is invalid.\n");
            return CM_ERROR;
        }
    }
    return CM_SUCCESS;
}

static void dss_ls_show_base(uint32 show_min_inited_size)
{
    if (show_min_inited_size == 0) {
        (void)printf(
            "%-5s%-20s%-14s %-14s %-64s%-5s%-5s\n", "type", "time", "size", "written_size", "name", "fid", "node_id");
    } else {
        (void)printf("%-5s%-20s%-14s %-14s %-14s %-64s%-5s%-5s\n", "type", "time", "size", "written_size",
            "min_inited_size", "name", "fid", "node_id");
    }
}

static status_t dss_ls_print_node_info(gft_node_t *node, const char *measure, uint32 show_min_inited_size)
{
    char time[512] = {0};
    if (cm_time2str(node->create_time, "YYYY-MM-DD HH24:mi:ss", time, sizeof(time)) != CM_SUCCESS) {
        DSS_PRINT_ERROR("Failed to get create time of node %s.\n", node->name);
        return CM_ERROR;
    }
    double size = (double)node->size;
    if (node->size != 0) {
        size = dss_convert_size(size, measure);
    }
    if (node->type > GFT_LINK) {
        DSS_PRINT_ERROR("Invalid node type %u.\n", node->type);
        return CM_ERROR;
    }
    char type = dss_ls_print_flag[node->type];
    double written_size = (double)node->written_size;
    if (node->written_size != 0) {
        written_size = dss_convert_size(written_size, measure);
    }
    if (show_min_inited_size == 0) {
        (void)printf("%-5c%-20s%-14.05f %-14.05f %-64s%-5llu%-5llu\n", type, time, size, written_size, node->name,
            node->fid, DSS_ID_TO_U64(node->id));
    } else {
        double min_inited_size = node->min_inited_size;
        if (node->min_inited_size != 0) {
            min_inited_size = dss_convert_size((double)node->min_inited_size, measure);
        }
        (void)printf("%-5c%-20s%-14.05f %-14.05f %-14.05f %-64s%-5llu%-5llu\n", type, time, size, written_size,
            min_inited_size, node->name, node->fid, DSS_ID_TO_U64(node->id));
    }

    return CM_SUCCESS;
}

static status_t dss_ls_print_file(dss_conn_t *conn, const char *path, const char *measure, uint32 show_min_inited_size)
{
    gft_node_t *node = NULL;
    dss_check_dir_output_t output_info = {&node, NULL, NULL, CM_FALSE};
    DSS_RETURN_IF_ERROR(dss_check_dir(conn->session, path, GFT_FILE, &output_info, CM_FALSE));
    if (node == NULL) {
        LOG_DEBUG_INF("Failed to find path %s with the file type", path);
        return CM_ERROR;
    }
    dss_ls_show_base(show_min_inited_size);
    return dss_ls_print_node_info(node, measure, show_min_inited_size);
}

static status_t dss_ls_try_print_link(
    dss_conn_t *conn, const char *path, const char *measure, uint32 show_min_inited_size)
{
    if (dss_is_valid_link_path(path)) {
        gft_node_t *node = NULL;
        dss_check_dir_output_t output_info = {&node, NULL, NULL, CM_FALSE};
        DSS_RETURN_IF_ERROR(dss_check_dir(conn->session, path, GFT_LINK, &output_info, CM_FALSE));
        if (node != NULL) {  // ls print the link
            dss_ls_show_base(show_min_inited_size);
            return dss_ls_print_node_info(node, measure, show_min_inited_size);
        }
    }
    LOG_DEBUG_INF("Failed to try print path %s with the link type", path);
    return CM_ERROR;
}

static status_t ls_proc_core(dss_conn_t *conn, const char *path, const char *measure, uint32 show_min_inited_size)
{
    gft_node_t *node = NULL;
    dss_vg_info_item_t *vg_item = NULL;
    char name[DSS_MAX_NAME_LEN] = {0};
    status_t status = CM_ERROR;
    bool32 exist = false;
    gft_item_type_t type;
    DSS_RETURN_IFERR2(
        dss_find_vg_by_dir(path, name, &vg_item), DSS_PRINT_ERROR("Failed to find vg when ls the path %s.\n", path));
    DSS_RETURN_IFERR2(
        dss_exist_impl(conn, path, &exist, &type), DSS_PRINT_ERROR("Failed to check the path %s exists.\n", path));
    if (!exist) {
        DSS_PRINT_ERROR("The path %s is not exist.\n", path);
        return CM_ERROR;
    }
    if (type == GFT_FILE) {
        DSS_LOCK_VG_META_S_RETURN_ERROR(vg_item, conn->session);
        status = dss_ls_print_file(conn, path, measure, show_min_inited_size);
        DSS_UNLOCK_VG_META_S(vg_item, conn->session);
        if (status == CM_SUCCESS) {
            DSS_PRINT_INF("Succeed to ls file info %s.\n", path);
            return status;
        }
    } else if (type == GFT_LINK || type == GFT_LINK_TO_FILE || type == GFT_LINK_TO_PATH) {
        DSS_LOCK_VG_META_S_RETURN_ERROR(vg_item, conn->session);
        status = dss_ls_try_print_link(conn, path, measure, show_min_inited_size);
        DSS_UNLOCK_VG_META_S(vg_item, conn->session);
        if (status == CM_SUCCESS) {
            DSS_PRINT_INF("Succeed to ls link info %s.\n", path);
            return status;
        }
    }
    dss_dir_t *dir = dss_open_dir_impl(conn, path, CM_TRUE);
    if (dir == NULL) {
        DSS_PRINT_ERROR("Failed to open dir %s.\n", path);
        return CM_ERROR;
    }
    dss_ls_show_base(show_min_inited_size);
    while ((node = dss_read_dir_impl(conn, dir, CM_TRUE)) != NULL) {
        status = dss_ls_print_node_info(node, measure, show_min_inited_size);
        if (status != CM_SUCCESS) {
            (void)dss_close_dir_impl(conn, dir);
            return CM_ERROR;
        }
    }
    (void)dss_close_dir_impl(conn, dir);
    DSS_PRINT_INF("Succeed to ls dir info %s.\n", path);
    return CM_SUCCESS;
}

static status_t ls_proc(void)
{
    const char *path = NULL;
    const char *measure = NULL;
    uint32 show_min_inited_size = 0;
    status_t status = ls_get_parameter(&path, &measure, &show_min_inited_size);
    if (status != CM_SUCCESS) {
        return status;
    }
    const char *input_args = cmd_ls_args[DSS_CMD_LS_UDS_IDX].input_args;
    dss_conn_t *conn = dss_get_connection_opt(input_args);
    if (conn == NULL) {
        DSS_PRINT_ERROR("Failed to get uds connection.\n");
        return CM_ERROR;
    }
    status = ls_proc_core(conn, path, measure, show_min_inited_size);
    return status;
}

static dss_args_t cmd_cp_args[] = {
    {'s', "src_file", CM_TRUE, CM_TRUE, dss_check_path_both, NULL, NULL, 0, NULL, NULL, 0},
    {'d', "dest_file", CM_TRUE, CM_TRUE, dss_check_path_both, NULL, NULL, 0, NULL, NULL, 0},
    {'U', "UDS", CM_FALSE, CM_TRUE, cmd_check_uds, cmd_check_convert_uds_home, cmd_clean_check_convert, 0, NULL, NULL,
        0},
};
static dss_args_set_t cmd_cp_args_set = {
    cmd_cp_args,
    sizeof(cmd_cp_args) / sizeof(dss_args_t),
    NULL,
};

static void cp_help(const char *prog_name, int print_flag)
{
    (void)printf("\nUsage:%s cp <-s src_file> <-d dest_file> [-U UDS:socket_domain]\n", prog_name);
    (void)printf("[client command]copy source file to destination file\n");
    if (print_flag == DSS_HELP_SIMPLE) {
        return;
    }
    (void)printf("-s/--src_file <src_file>, <required>, source file\n");
    (void)printf("-d/--dest_file <dest_file>, <required>, destination file\n");
    help_param_uds();
}

static status_t cp_proc(void)
{
    char *srcpath = cmd_cp_args[DSS_ARG_IDX_0].input_args;
    char *despath = cmd_cp_args[DSS_ARG_IDX_1].input_args;

    status_t status = CM_SUCCESS;
    const char *input_args = cmd_cp_args[DSS_ARG_IDX_2].input_args;
    dss_conn_t *conn = dss_get_connection_opt(input_args);
    if (conn == NULL) {
        return CM_ERROR;
    }

    status = dss_copy_file_impl(conn, srcpath, despath);
    if (status != CM_SUCCESS) {
        DSS_PRINT_ERROR("Failed to copy file from srcpath %s to destpath %s.\n", srcpath, despath);
#ifdef OPENGAUSS
        DSS_PRINT_ERROR("Check whether the Linux file: %s is 512-aligned.\n", srcpath);
#endif
    } else {
        DSS_PRINT_INF("Succeed to copy file from srcpath %s to destpath %s.\n", srcpath, despath);
    }
    return status;
}

static dss_args_t cmd_rm_args[] = {
    {'p', "path", CM_TRUE, CM_TRUE, dss_cmd_check_device_path, cmd_check_convert_path, cmd_clean_check_convert, 0, NULL,
        NULL, 0},
    {'U', "UDS", CM_FALSE, CM_TRUE, cmd_check_uds, cmd_check_convert_uds_home, cmd_clean_check_convert, 0, NULL, NULL,
        0},
};
static dss_args_set_t cmd_rm_args_set = {
    cmd_rm_args,
    sizeof(cmd_rm_args) / sizeof(dss_args_t),
    NULL,
};

static void rm_help(const char *prog_name, int print_flag)
{
    (void)printf("\nUsage:%s rm <-p path> [-U UDS:socket_domain]\n", prog_name);
    (void)printf("[client command]remove device\n");
    if (print_flag == DSS_HELP_SIMPLE) {
        return;
    }
    if (g_run_interatively) {
        (void)printf("-p/--path <path>, <required>, device path\n");
    } else {
        (void)printf("-p/--path <path>, <required>, device path, must begin with '+'\n");
    }
    help_param_uds();
}

static status_t rm_proc(void)
{
    const char *path = cmd_rm_args[DSS_ARG_IDX_0].input_args;
    if (cmd_rm_args[DSS_ARG_IDX_0].convert_result != NULL) {
        path = cmd_rm_args[DSS_ARG_IDX_0].convert_result;
    }
    status_t status = CM_SUCCESS;
    const char *input_args = cmd_rm_args[DSS_ARG_IDX_1].input_args;
    dss_conn_t *conn = dss_get_connection_opt(input_args);
    if (conn == NULL) {
        return CM_ERROR;
    }

    status = dss_remove_file_impl(conn, path);
    if (status != CM_SUCCESS) {
        DSS_PRINT_ERROR("Failed to remove device %s.\n", path);
    } else {
        DSS_PRINT_INF("Succeed to remove device %s.\n", path);
    }
    return status;
}

static dss_args_t cmd_rmv_args[] = {
    {'g', "vg_name", CM_TRUE, CM_TRUE, dss_check_name, NULL, NULL, 0, NULL, NULL, 0},
    {'v', "vol_path", CM_TRUE, CM_TRUE, dss_check_volume_path, NULL, NULL, 0, NULL, NULL, 0},
    {'f', "force", CM_FALSE, CM_FALSE, NULL, NULL, NULL, 0, NULL, NULL, 0},
    {'D', "DSS_HOME", CM_FALSE, CM_TRUE, cmd_check_dss_home, cmd_check_convert_dss_home, cmd_clean_check_convert, 0,
        NULL, NULL, 0},
    {'U', "UDS", CM_FALSE, CM_TRUE, cmd_check_uds, cmd_check_convert_uds_home, cmd_clean_check_convert, 0, NULL, NULL,
        0},
};
static dss_args_set_t cmd_rmv_args_set = {
    cmd_rmv_args,
    sizeof(cmd_rmv_args) / sizeof(dss_args_t),
    NULL,
};

static void rmv_help(const char *prog_name, int print_flag)
{
    (void)printf("\nUsage:%s rmv <-g vg_name> <-v vol_path> [-f] [-D DSS_HOME] [-U UDS:socket_domain]\n", prog_name);
    (void)printf("[client command]remove volume of volume group\n");
    if (print_flag == DSS_HELP_SIMPLE) {
        return;
    }
    (void)printf("-g/--vg_name <vg_name>, <required>, the volume group name need to remove volume\n");
    (void)printf("-v/--vol_path <vol_path>, <required>, the volue path need to be removed from volume group\n");
    (void)printf("-f/--force, <required>, remove volume offline forcibly\n");
    help_param_dsshome();
    help_param_uds();
}

static status_t rmv_proc(void)
{
    const char *vg_name = cmd_rmv_args[DSS_ARG_IDX_0].input_args;
    const char *vol_path = cmd_rmv_args[DSS_ARG_IDX_1].input_args;
    bool32 force = cmd_rmv_args[DSS_ARG_IDX_2].inputed ? CM_TRUE : CM_FALSE;
    const char *home = cmd_rmv_args[DSS_ARG_IDX_3].input_args;
    status_t status = CM_SUCCESS;
    if (force) {
        status = dss_modify_volume_offline(home, vg_name, vol_path, NULL, VOLUME_MODIFY_REMOVE);
        if (status != CM_SUCCESS) {
            DSS_PRINT_ERROR("Failed to remove volume offline, vg name is %s, volume path is %s.\n", vg_name, vol_path);
        } else {
            DSS_PRINT_INF("Succeed to remove volume offline, vg name is %s, volume path is %s.\n", vg_name, vol_path);
        }
        return status;
    }

    const char *input_args = cmd_rmv_args[DSS_ARG_IDX_4].input_args;
    dss_conn_t *conn = dss_get_connection_opt(input_args);
    if (conn == NULL) {
        return CM_ERROR;
    }

    status = dsscmd_rmv_impl(conn, vg_name, vol_path);
    if (status != CM_SUCCESS) {
        DSS_PRINT_ERROR("Failed to remove volume online, vg name is %s, volume path is %s.\n", vg_name, vol_path);
    } else {
        DSS_PRINT_INF("Succeed to remove volume online, vg name is %s, volume path is %s.\n", vg_name, vol_path);
    }
    return status;
}

static dss_args_t cmd_rmdir_args[] = {
    {'p', "path", CM_TRUE, CM_TRUE, dss_cmd_check_device_path, cmd_check_convert_path, cmd_clean_check_convert, 0, NULL,
        NULL, 0},
    {'r', "recursive", CM_FALSE, CM_FALSE, NULL, NULL, NULL, 0, NULL, NULL, 0},
    {'U', "UDS", CM_FALSE, CM_TRUE, cmd_check_uds, cmd_check_convert_uds_home, cmd_clean_check_convert, 0, NULL, NULL,
        0},
};
static dss_args_set_t cmd_rmdir_args_set = {
    cmd_rmdir_args,
    sizeof(cmd_rmdir_args) / sizeof(dss_args_t),
    NULL,
};

static void rmdir_help(const char *prog_name, int print_flag)
{
    (void)printf("\nUsage:%s rmdir <-p path> [-r] [-U UDS:socket_domain path]\n", prog_name);
    (void)printf("[client command] remove dir or with it's contents recursively\n");
    if (print_flag == DSS_HELP_SIMPLE) {
        return;
    }
    (void)printf("-p/--path <path>, <required>, the name need to remove\n");
    (void)printf("-r/--recursive  [optional], remove dir and it's contents recursively\n");
    help_param_uds();
}

static status_t rmdir_proc(void)
{
    const char *path = cmd_rmdir_args[DSS_ARG_IDX_0].input_args;
    if (cmd_rmdir_args[DSS_ARG_IDX_0].convert_result != NULL) {
        path = cmd_rmdir_args[DSS_ARG_IDX_0].convert_result;
    }

    bool32 recursive = cmd_rmdir_args[DSS_ARG_IDX_1].inputed ? CM_TRUE : CM_FALSE;
    status_t status = CM_SUCCESS;
    const char *input_args = cmd_rmdir_args[DSS_ARG_IDX_2].input_args;
    dss_conn_t *conn = dss_get_connection_opt(input_args);
    if (conn == NULL) {
        return CM_ERROR;
    }

    status = dss_remove_dir_impl(conn, path, recursive);
    if (status != CM_SUCCESS) {
        DSS_PRINT_ERROR("Failed to rm dir, path is %s.\n", path);
    } else {
        DSS_PRINT_INF("Succeed to rm dir, path is %s.\n", path);
    }
    return status;
}

static dss_args_t cmd_inq_args[] = {
    {'t', "inq_type", CM_TRUE, CM_TRUE, cmd_check_inq_type, NULL, NULL, 0, NULL, NULL, 0},
    {'D', "DSS_HOME", CM_FALSE, CM_TRUE, cmd_check_dss_home, cmd_check_convert_dss_home, cmd_clean_check_convert, 0,
        NULL, NULL, 0},
};
static dss_args_set_t cmd_inq_args_set = {
    cmd_inq_args,
    sizeof(cmd_inq_args) / sizeof(dss_args_t),
    NULL,
};

static void inq_help(const char *prog_name, int print_flag)
{
    (void)printf("\nUsage:%s inq <-t inq_type> [-D DSS_HOME]\n", prog_name);
    (void)printf("[raid command] inquiry LUN information or reservations\n");
    if (print_flag == DSS_HELP_SIMPLE) {
        return;
    }
    (void)printf("-t/--type <inq_type>, <required>, the type need to inquiry, values [lun|reg]"
                 "lun :inquiry LUN information, reg:inquiry reservations\n");
    help_param_dsshome();
}

static status_t inq_proc(void)
{
    status_t status;
    char *home = cmd_inq_args[DSS_ARG_IDX_1].input_args;
    if (cm_strcmpi(cmd_inq_args[DSS_ARG_IDX_0].input_args, "lun") == 0) {
        status = dss_inq_lun(home);
        if (status != CM_SUCCESS) {
            DSS_PRINT_ERROR("Failed to inquire lun info, status is %d.\n", status);
            return status;
        }
    } else if (cm_strcmpi(cmd_inq_args[DSS_ARG_IDX_0].input_args, "reg") == 0) {
        status = dss_inq_reg(home);
        if (status != CM_SUCCESS) {
            DSS_PRINT_ERROR("Failed to inquire reg info, status is %d.\n", status);
            return status;
        }
    } else {
        DSS_PRINT_ERROR("error inq_type.\n");
        return CM_ERROR;
    }
    DSS_PRINT_INF("Succeed to inquiry LUN information, or inquiry reservations.\n");
    return CM_SUCCESS;
}

static dss_args_t cmd_inq_req_args[] = {
    {'i', "inst_id", CM_TRUE, CM_TRUE, cmd_check_inst_id, NULL, NULL, 0, NULL, NULL, 0},
    {'D', "DSS_HOME", CM_FALSE, CM_TRUE, cmd_check_dss_home, cmd_check_convert_dss_home, cmd_clean_check_convert, 0,
        NULL, NULL, 0},
};
static dss_args_set_t cmd_inq_req_args_set = {
    cmd_inq_req_args,
    sizeof(cmd_inq_req_args) / sizeof(dss_args_t),
    NULL,
};

static void inq_reg_help(const char *prog_name, int print_flag)
{
    (void)printf("\nUsage:%s inq_reg <-i inst_id> [-D DSS_HOME]\n", prog_name);
    (void)printf("[raid command]check whether the node is registered\n");
    if (print_flag == DSS_HELP_SIMPLE) {
        return;
    }
    (void)printf("-i/--inst_id <inst_id>, <required>, the id of the host need to reg\n");
    help_param_dsshome();
}

static status_t inq_reg_proc(void)
{
    DSS_PRINT_INF("Begin to inq reg.\n");
    int64 host_id;
    status_t status = cm_str2bigint(cmd_inq_req_args[DSS_ARG_IDX_0].input_args, &host_id);
    DSS_RETURN_IFERR2(
        status, DSS_PRINT_ERROR("host_id:%s is not a valid int64.\n", cmd_inq_req_args[DSS_ARG_IDX_0].input_args));
    char *home = cmd_inq_req_args[DSS_ARG_IDX_1].input_args;
    status = dss_inq_reg_core(home, host_id);
    if (status == CM_ERROR) {
        DSS_PRINT_ERROR("Failed to inq reg host %lld.\n", host_id);
    } else {
        DSS_PRINT_INF("Succeed to inq reg host %lld.\n", host_id);
    }
    return status;
}

static dss_args_set_t cmd_lscli_args_set = {
    NULL,
    0,
    NULL,
};

static void lscli_help(const char *prog_name, int print_flag)
{
    (void)printf("\nUsage:%s lscli\n", prog_name);
    (void)printf("[client command] Show information of client\n");
}

static status_t lscli_proc(void)
{
    errno_t errcode;
    dss_cli_info cli_info;

    cli_info.cli_pid = cm_sys_pid();
    status_t status = cm_sys_process_start_time(cli_info.cli_pid, &cli_info.start_time);
    if (status != CM_SUCCESS) {
        DSS_PRINT_ERROR("Failed to get process start time pid %llu.\n", cli_info.cli_pid);
        return CM_ERROR;
    }
    errcode = strncpy_s(
        cli_info.process_name, sizeof(cli_info.process_name), cm_sys_program_name(), strlen(cm_sys_program_name()));
    if (errcode != EOK) {
        DSS_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
        DSS_PRINT_ERROR("Failed to lscli.\n");
        return CM_ERROR;
    }

    (void)printf("%-20s%-20s%-256s\n", "cli_pid", "start_time", "process_name");
    (void)printf("%-20llu%-20lld%-256s\n", cli_info.cli_pid, cli_info.start_time, cli_info.process_name);
    return CM_SUCCESS;
}

static dss_args_t cmd_kickh_args[] = {
    {'i', "inst_id", CM_TRUE, CM_TRUE, cmd_check_inst_id, NULL, NULL, 0, NULL, NULL, 0},
    {'D', "DSS_HOME", CM_FALSE, CM_TRUE, cmd_check_dss_home, cmd_check_convert_dss_home, cmd_clean_check_convert, 0,
        NULL, NULL, 0},
};
static dss_args_set_t cmd_kickh_args_set = {
    cmd_kickh_args,
    sizeof(cmd_kickh_args) / sizeof(dss_args_t),
    NULL,
};

static void kickh_help(const char *prog_name, int print_flag)
{
    (void)printf("\nUsage:%s kickh <-i inst_id> [-D DSS_HOME]\n", prog_name);
    (void)printf("[client command] kick off the host from the array\n");
    if (print_flag == DSS_HELP_SIMPLE) {
        return;
    }
    (void)printf("-i/--inst_id <inst_id>, <required>, the id of the host need to kick off\n");
    help_param_dsshome();
}

static status_t kickh_proc(void)
{
    DSS_PRINT_INF("Begin to kick.\n");
    int64 kick_hostid;
    status_t status = cm_str2bigint(cmd_kickh_args[DSS_ARG_IDX_0].input_args, &kick_hostid);
    DSS_RETURN_IFERR2(
        status, DSS_PRINT_ERROR("kick_hostid:%s is not a valid int64.\n", cmd_kickh_args[DSS_ARG_IDX_0].input_args));
    char *home = cmd_kickh_args[DSS_ARG_IDX_1].input_args;

    status = dss_kickh_core(home, kick_hostid);
    if (status != CM_SUCCESS) {
        DSS_PRINT_ERROR("Failed to kick host, kickid %lld.\n", kick_hostid);
        return CM_ERROR;
    }
    DSS_PRINT_INF("Succeed to kick host, kickid %lld.\n", kick_hostid);
    return CM_SUCCESS;
}

static dss_args_t cmd_reghl_args[] = {
    {'D', "DSS_HOME", CM_FALSE, CM_TRUE, cmd_check_dss_home, cmd_check_convert_dss_home, cmd_clean_check_convert, 0,
        NULL, NULL, 0},
};
static dss_args_set_t cmd_reghl_args_set = {
    cmd_reghl_args,
    sizeof(cmd_reghl_args) / sizeof(dss_args_t),
    NULL,
};

static void reghl_help(const char *prog_name, int print_flag)
{
    (void)printf("\nUsage:%s reghl [-D DSS_HOME]\n", prog_name);
    (void)printf("[manage command] register host to array\n");
    if (print_flag == DSS_HELP_SIMPLE) {
        return;
    }
    help_param_dsshome();
}

static status_t reghl_proc(void)
{
    DSS_PRINT_INF("Begin to register.\n");
    char *home = cmd_reghl_args[DSS_ARG_IDX_0].input_args;
    status_t status = dss_reghl_core(home);
    if (status != CM_SUCCESS) {
        DSS_PRINT_ERROR("Failed to register.\n");
    } else {
        DSS_PRINT_INF("Succeed to register.\n");
    }
    return status;
}

static dss_args_t cmd_unreghl_args[] = {
    {'t', "type", CM_FALSE, CM_TRUE, NULL, NULL, NULL, 0, NULL, NULL, 0},
    {'D', "DSS_HOME", CM_FALSE, CM_TRUE, cmd_check_dss_home, cmd_check_convert_dss_home, cmd_clean_check_convert, 0,
        NULL, NULL, 0},
};
static dss_args_set_t cmd_unreghl_args_set = {
    cmd_unreghl_args,
    sizeof(cmd_unreghl_args) / sizeof(dss_args_t),
    NULL,
};

static void unreghl_help(const char *prog_name, int print_flag)
{
    (void)printf("\nUsage:%s unreghl [-t type] [-D DSS_HOME]\n", prog_name);
    (void)printf("[manage command] unregister host from array\n");
    if (print_flag == DSS_HELP_SIMPLE) {
        return;
    }
    (void)printf("-t/--type <type>, [optional], value is int, 0 without lock, otherwise with lock\n");
    help_param_dsshome();
}

static status_t unreghl_proc(void)
{
    int32 type = 1;
    status_t status;
    if (cmd_unreghl_args[DSS_ARG_IDX_0].input_args != NULL) {
        status = cm_str2int(cmd_unreghl_args[DSS_ARG_IDX_0].input_args, &type);
        if (status != CM_SUCCESS) {
            DSS_PRINT_ERROR("The value of type is invalid.\n");
            return CM_ERROR;
        }
    }

    DSS_PRINT_INF("Begin to unregister.\n");
    char *home = cmd_unreghl_args[DSS_ARG_IDX_1].input_args;
    status = dss_unreghl_core(home, (type == 0) ? CM_FALSE : CM_TRUE);
    if (status != CM_SUCCESS) {
        DSS_PRINT_ERROR("Failed to unregister.\n");
    } else {
        DSS_PRINT_INF("Succeed to unregister.\n");
    }
    return status;
}

static dss_args_t cmd_auid_args[] = {
    {'a', "auid", CM_TRUE, CM_TRUE, cmd_check_disk_id, NULL, NULL, 0, NULL, NULL, 0},
};
static dss_args_set_t cmd_auid_args_set = {
    cmd_auid_args,
    sizeof(cmd_auid_args) / sizeof(dss_args_t),
    NULL,
};

static void auid_help(const char *prog_name, int print_flag)
{
    (void)printf("\nUsage:%s auid <-a auid>\n", prog_name);
    (void)printf("[tool command] show auid\n");
    if (print_flag == DSS_HELP_SIMPLE) {
        return;
    }
    (void)printf("-a/--auid <auid>, <required>, the auid will to show");
}

static status_t auid_proc(void)
{
    uint64 id = 0;
    status_t status = cm_str2uint64(cmd_auid_args[DSS_ARG_IDX_0].input_args, &id);
    if (status == CM_ERROR) {
        DSS_PRINT_ERROR("auid:%s is not a valid uint64\n", cmd_auid_args[DSS_ARG_IDX_0].input_args);
        return CM_ERROR;
    }
    auid_t *auid = (auid_t *)&id;
    (void)printf("id:%llu:\n", id);
    (void)printf("  volumeid:%llu\n", (uint64)auid->volume);
    (void)printf("  auid:%llu\n", (uint64)auid->au);
    (void)printf("  blockid:%llu\n", (uint64)auid->block);
    (void)printf("  item:%llu\n", (uint64)auid->item);
    return CM_SUCCESS;
}

#define DSS_CMD_PRINT_BLOCK_SIZE SIZE_K(4)
#define DSS_PRINT_RETURN_BYTES 16
#define DSS_PRINT_FMT_NUM 6

static dss_args_t cmd_examine_args[] = {
    {'p', "path", CM_TRUE, CM_TRUE, dss_cmd_check_device_path, cmd_check_convert_path, cmd_clean_check_convert, 0, NULL,
        NULL, 0},
    {'o', "offset", CM_TRUE, CM_TRUE, cmd_check_offset, NULL, NULL, 0, NULL, NULL, 0},
    {'f', "format", CM_TRUE, CM_TRUE, cmd_check_format, NULL, NULL, 0, NULL, NULL, 0},
    {'s', "read_size", CM_FALSE, CM_TRUE, cmd_check_read_size, NULL, NULL, 0, NULL, NULL, 0},
    {'D', "DSS_HOME", CM_FALSE, CM_TRUE, cmd_check_dss_home, cmd_check_convert_dss_home, cmd_clean_check_convert, 0,
        NULL, NULL, 0},
    {'U', "UDS", CM_FALSE, CM_TRUE, cmd_check_uds, cmd_check_convert_uds_home, cmd_clean_check_convert, 0, NULL, NULL,
        0},
};
static dss_args_set_t cmd_examine_args_set = {
    cmd_examine_args,
    sizeof(cmd_examine_args) / sizeof(dss_args_t),
    NULL,
};

static void examine_help(const char *prog_name, int print_flag)
{
    (void)printf("\nUsage:%s examine <-p path> <-o offset> <-f format> [-s read_size] [-D DSS_HOME] "
                 "[-U UDS:socket_domain]\n",
        prog_name);
    (void)printf("[client command] display dss file content\n");
    if (print_flag == DSS_HELP_SIMPLE) {
        return;
    }
    if (g_run_interatively) {
        (void)printf("-p/--path <path>, <required>, device path\n");
    } else {
        (void)printf("-p/--path <path>, <required>, device path, must begin with '+'\n");
    }
    (void)printf("-o/--offset <offset>, <required>, the offset of the file need to examine\n");
    (void)printf("-f/--format <format>, <required>, value is[c|h|u|l|s|x]\n"
                 "c char, h unsigned short, u unsigned int, l unsigned long, s string, x hex.\n");
    (void)printf("-s/--read_size <DSS_HOME>, [optional], size to show, default value is 512byte\n");
    help_param_dsshome();
    help_param_uds();
}

static inline char escape_char(char c)
{
    if (c > 0x1f && c < 0x7f) {
        return c;
    } else {
        return '.';
    }
}

static status_t print_buf(const char *o_buf, uint32 buf_size, char format, int64 offset, uint32 read_size)
{
    uint32 pos = 0;
    int16 index = -1;
    dss_print_help_t print_help[] = {{'c', sizeof(char)}, {'h', sizeof(uint16)}, {'u', sizeof(uint32)},
        {'l', sizeof(uint64)}, {'s', sizeof(char)}, {'x', sizeof(uint8)}};

    for (int16 i = 0; i < DSS_PRINT_FMT_NUM; i++) {
        if (format == print_help[i].fmt) {
            index = i;
            break;
        }
    }
    if (index == -1) {
        LOG_DEBUG_ERR("Invalid format.\n");
        return CM_ERROR;
    }

    while ((pos + print_help[index].bytes) <= read_size) {
        if (pos % DSS_PRINT_RETURN_BYTES == 0) {
            (void)printf("%016llx ", (uint64)offset + pos);
        }

        if (format == 'x') {
            (void)printf("%02x", *(uint8 *)(o_buf + pos));
        } else if (format == 'c') {
            (void)printf("%c", escape_char(*(o_buf + pos)));
        } else if (format == 'h') {
            (void)printf("%5hu", *(uint16 *)(o_buf + pos));
        } else if (format == 'u') {
            (void)printf("%10u", *(uint32 *)(o_buf + pos));
        } else if (format == 'l') {
            (void)printf("%20llu", *(uint64 *)(o_buf + pos));
        } else if (format == 's') {
            (void)printf("%c", escape_char(*(o_buf + pos)));
        }

        pos += print_help[index].bytes;

        if (pos % DSS_PRINT_RETURN_BYTES == 0) {
            (void)printf("\n");
        } else {
            if (format != 's') {
                (void)printf(" ");
            }
        }
    }
    if ((read_size / print_help[index].bytes) % (DSS_PRINT_RETURN_BYTES / print_help[index].bytes) != 0) {
        (void)printf("\n");
    }

    return CM_SUCCESS;
}

static status_t get_examine_parameter(char **path, int64 *offset, char *fmt)
{
    *path = cmd_examine_args[DSS_ARG_IDX_0].input_args;
    if (cmd_examine_args[DSS_ARG_IDX_0].convert_result != NULL) {
        *path = cmd_examine_args[DSS_ARG_IDX_0].convert_result;
    }

    status_t status = cm_str2bigint(cmd_examine_args[DSS_ARG_IDX_1].input_args, offset);
    if (status != CM_SUCCESS) {
        LOG_DEBUG_ERR("Invalid offset.\n");
        return CM_ERROR;
    }
    *fmt = cmd_examine_args[DSS_ARG_IDX_2].input_args[0];
    return CM_SUCCESS;
}

static status_t get_examine_opt_parameter(int32 *read_size)
{
    *read_size = DSS_DISK_UNIT_SIZE;
    if (cmd_examine_args[DSS_ARG_IDX_3].input_args != NULL) {
        *read_size = (int32)strtol(cmd_examine_args[DSS_ARG_IDX_3].input_args, NULL, CM_DEFAULT_DIGIT_RADIX);
    }
    if (*read_size <= 0) {
        LOG_DEBUG_ERR("Invalid read_size.\n");
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static status_t print_file_proc(dss_conn_t *conn, int32 handle, int64 offset, int32 read_size, char fmt)
{
#ifndef WIN32
    char o_buf[DSS_CMD_PRINT_BLOCK_SIZE] __attribute__((__aligned__(DSS_DISK_UNIT_SIZE)));
#else
    char o_buf[DSS_CMD_PRINT_BLOCK_SIZE];
#endif
    int32 read_cnt = 0;
    int32 cur_read_size;
    int64 row_aligned_offset = (offset / DSS_PRINT_RETURN_BYTES) * DSS_PRINT_RETURN_BYTES;
    int64 print_offset = row_aligned_offset - (offset / DSS_DISK_UNIT_SIZE) * DSS_DISK_UNIT_SIZE;
    int64 offset_shift = offset - row_aligned_offset;

    while (read_cnt < read_size) {
        CM_RETURN_IFERR_EX(dss_read_file_impl(conn, handle, o_buf, sizeof(o_buf), &cur_read_size),
            LOG_DEBUG_ERR("Failed to read file.\n"));

        if (cur_read_size > read_size - read_cnt) {
            cur_read_size = read_size - read_cnt;
        }
        char *buf = o_buf + print_offset;
        uint32 buf_size = (uint32)(sizeof(o_buf) - print_offset);

        CM_RETURN_IFERR_EX(print_buf(buf, buf_size, fmt, offset - offset_shift, (uint32)(cur_read_size - print_offset)),
            LOG_DEBUG_ERR("Failed to print.\n"));

        read_cnt += cur_read_size;
        offset += (cur_read_size - print_offset) - offset_shift;
        print_offset = 0;
        offset_shift = 0;
    }
    return CM_SUCCESS;
}

static int64 adjust_readsize(int64 offset, int32 *read_size, int64 file_size)
{
    int64 unit_aligned_offset = (offset / DSS_DISK_UNIT_SIZE) * DSS_DISK_UNIT_SIZE;
    int64 new_read_size = *read_size;

    if (unit_aligned_offset != offset) {
        new_read_size += (offset - unit_aligned_offset);
    }

    if (new_read_size + unit_aligned_offset > file_size) {
        if (file_size < unit_aligned_offset) {
            new_read_size = 0;
        } else {
            new_read_size = file_size - unit_aligned_offset;
        }
    }

    if (new_read_size < 0) {
        new_read_size = 0;
    }

    if (new_read_size > INT32_MAX) {
        new_read_size = INT32_MAX;
    }

    *read_size = (int32)new_read_size;
    return unit_aligned_offset;
}

static status_t examine_proc(void)
{
    char *path;
    int64 offset;
    char format;
    int32 read_size = DSS_DISK_UNIT_SIZE;
    dss_config_t *inst_cfg = dss_get_g_inst_cfg();

    status_t status = get_examine_parameter(&path, &offset, &format);
    if (status != CM_SUCCESS) {
        return status;
    }

    status = get_examine_opt_parameter(&read_size);
    if (status != CM_SUCCESS) {
        return status;
    }

    char *input_args = cmd_examine_args[DSS_ARG_IDX_4].input_args;
    status = set_config_info(input_args, inst_cfg);
    if (status != CM_SUCCESS) {
        DSS_PRINT_ERROR("Failed to load config info!\n");
        return status;
    }

    dss_conn_t *conn = dss_get_connection_opt(input_args);
    if (conn == NULL) {
        DSS_PRINT_ERROR("Failed to get uds connection.\n");
        return CM_ERROR;
    }

    int32 handle;
    status = dss_open_file_impl(conn, path, O_RDONLY, &handle);
    if (status != CM_SUCCESS) {
        DSS_PRINT_ERROR("Failed to open dir, path is %s.\n", path);
        return CM_ERROR;
    }

    int64 file_size = dss_seek_file_impl(conn, handle, 0, SEEK_END);
    if (file_size == CM_INVALID_INT64) {
        DSS_PRINT_ERROR("Failed to seek file %s size.\n", path);
        (void)dss_close_file_impl(conn, handle);
        return CM_ERROR;
    }
    int64 unit_aligned_offset = adjust_readsize(offset, &read_size, file_size);

    unit_aligned_offset = dss_seek_file_impl(conn, handle, unit_aligned_offset, SEEK_SET);
    if (unit_aligned_offset == -1) {
        DSS_PRINT_ERROR("Failed to seek file %s.\n", path);
        (void)dss_close_file_impl(conn, handle);
        return CM_ERROR;
    }
    (void)printf("filename is %s, offset is %lld.\n", path, offset);
    status = print_file_proc(conn, handle, offset, read_size, format);
    if (status != CM_SUCCESS) {
        DSS_PRINT_ERROR("Failed to print file %s.\n", path);
    }
    (void)dss_close_file_impl(conn, handle);
    return status;
}

static dss_args_t cmd_dev_args[] = {
    {'v', "vol_path", CM_TRUE, CM_TRUE, dss_check_volume_path, NULL, NULL, 0, NULL, NULL, 0},
    {'o', "offset", CM_TRUE, CM_TRUE, cmd_check_offset, NULL, NULL, 0, NULL, NULL, 0},
    {'f', "format", CM_TRUE, CM_TRUE, cmd_check_format, NULL, NULL, 0, NULL, NULL, 0},
};
static dss_args_set_t cmd_dev_args_set = {
    cmd_dev_args,
    sizeof(cmd_dev_args) / sizeof(dss_args_t),
    NULL,
};

static void dev_help(const char *prog_name, int print_flag)
{
    (void)printf("\nUsage:%s dev <-v vol_path> <-o offset> <-f format> \n", prog_name);
    (void)printf("[client command] display dev file content\n");
    if (print_flag == DSS_HELP_SIMPLE) {
        return;
    }
    (void)printf("-v/--vol_path <vol_path>, <required>, the volume path of the host need to display\n");
    (void)printf("-o/--offset <offset>, <required>, the offset of the dev need to display\n");
    (void)printf("-f/--format <format>, <required>, value is[c|h|u|l|s|x]"
                 "c char, h unsigned short, u unsigned int, l unsigned long, s string, x hex.\n");
}

static status_t dev_proc(void)
{
    status_t status;
    const char *path = cmd_dev_args[DSS_ARG_IDX_0].input_args;
    dss_volume_t volume;
    status = dss_open_volume(path, NULL, DSS_INSTANCE_OPEN_FLAG, &volume);
    if (status != CM_SUCCESS) {
        DSS_PRINT_ERROR("Failed to open volume %s.\n", path);
        return status;
    }

#ifndef WIN32
    char o_buf[DSS_CMD_PRINT_BLOCK_SIZE] __attribute__((__aligned__(DSS_DISK_UNIT_SIZE)));
#else
    char o_buf[DSS_CMD_PRINT_BLOCK_SIZE];
#endif

    int64 offset = 0;
    status = cm_str2bigint(cmd_dev_args[DSS_ARG_IDX_1].input_args, &offset);
    if (status != CM_SUCCESS) {
        dss_close_volume(&volume);
        DSS_PRINT_ERROR("The value of offset is invalid.\n");
        return CM_ERROR;
    }

    (void)printf("volume path is %s, offset is %lld.\n", path, offset);
    status = dss_read_volume(&volume, offset, o_buf, (int32)DSS_CMD_PRINT_BLOCK_SIZE);
    if (status != CM_SUCCESS) {
        dss_close_volume(&volume);
        DSS_PRINT_ERROR("Failed to read volume %s.\n", path);
        return status;
    }
    dss_close_volume(&volume);
    char format = cmd_dev_args[DSS_ARG_IDX_2].input_args[0];
    status = print_buf(o_buf, DSS_CMD_PRINT_BLOCK_SIZE, format, offset, DSS_CMD_PRINT_BLOCK_SIZE);
    if (status != CM_SUCCESS) {
        DSS_PRINT_ERROR("Failed to print volume %s.\n", path);
        return status;
    }
    return CM_SUCCESS;
}

static dss_args_t cmd_showdisk_args[] = {
    {'g', "vg_name", CM_TRUE, CM_TRUE, dss_check_name, NULL, NULL, 0, NULL, NULL, 0},
    {'s', "struct_name", CM_TRUE, CM_TRUE, cmd_check_struct_name, NULL, NULL, 0, NULL, NULL, 0},
    {'b', "block_id", CM_TRUE, CM_TRUE, cmd_check_disk_id, NULL, NULL, 0, NULL, NULL, 0},
    {'n', "node_id", CM_TRUE, CM_TRUE, cmd_check_block_index_id, NULL, NULL, 0, NULL, NULL, 0},
    {'D', "DSS_HOME", CM_FALSE, CM_TRUE, cmd_check_dss_home, cmd_check_convert_dss_home, cmd_clean_check_convert, 0,
        NULL, NULL, 0},
};

static status_t showdisk_check_args(dss_args_t *cmd_args_set, int set_size)
{
    if (cmd_args_set == NULL || set_size <= 0) {
        DSS_PRINT_ERROR("args error.\n");
        return CM_ERROR;
    }
    if (!cmd_args_set[DSS_ARG_IDX_0].inputed) {
        DSS_PRINT_ERROR("should set the vg name to show.\n");
        return CM_ERROR;
    }
    if (!cmd_args_set[DSS_ARG_IDX_1].inputed && !cmd_args_set[DSS_ARG_IDX_2].inputed) {
        DSS_PRINT_ERROR("should at least set one way [struct_name | block_id] to show.\n");
        return CM_ERROR;
    }
    if (cmd_args_set[DSS_ARG_IDX_1].inputed && cmd_args_set[DSS_ARG_IDX_2].inputed) {
        DSS_PRINT_ERROR("should only set one way [struct_name | block_id] to show.\n");
        return CM_ERROR;
    }
    if (cmd_args_set[DSS_ARG_IDX_2].inputed && !cmd_args_set[DSS_ARG_IDX_3].inputed) {
        DSS_PRINT_ERROR("should set the block_id with node_id.\n");
        return CM_ERROR;
    }
    if (!cmd_args_set[DSS_ARG_IDX_2].inputed && cmd_args_set[DSS_ARG_IDX_3].inputed) {
        DSS_PRINT_ERROR("should not set the node_id without block_id.\n");
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static dss_args_set_t cmd_showdisk_args_set = {
    cmd_showdisk_args,
    sizeof(cmd_showdisk_args) / sizeof(dss_args_t),
    showdisk_check_args,
};

static void showdisk_help(const char *prog_name, int print_flag)
{
    (void)printf("\nUsage:%s showdisk <-g vg_name> <-s struct_name> [-D DSS_HOME]\n", prog_name);
    (void)printf("      %s showdisk <-g vg_name> <-b block_id> <-n node_id> [-D DSS_HOME]\n", prog_name);
    (void)printf("[client command] show disk information\n");
    if (print_flag == DSS_HELP_SIMPLE) {
        return;
    }
    (void)printf("-g/--vg_name <vg_name>, <required>, the volume group name\n");
    (void)printf("-s/--struct_name <struct_name>, <required>, the struct name of volume group, "
                 "the optional value(s):\n");
    (void)printf("    [core_ctrl | vg_header | volume_ctrl | root_ft_block]\n");
    (void)printf("-b/--block_id <block_id>, <required>, fs block id or ft block id\n");
    (void)printf("-n/--node_id <node_id>, <required>, node id in block\n");
    help_param_dsshome();
}

static status_t dss_print_struct_name(dss_vg_info_item_t *vg_item, const char *struct_name)
{
    dss_volume_t volume;
    status_t status = CM_SUCCESS;
    if (vg_item->from_type == FROM_DISK) {
        status = dss_open_volume(vg_item->entry_path, NULL, DSS_CLI_OPEN_FLAG, &volume);
        DSS_RETURN_IFERR2(
            status, DSS_PRINT_ERROR("Failed to open file %s.\nFailed to printf dss metadata.\n", vg_item->entry_path));
    }
    status = dss_print_struct_name_inner(vg_item, &volume, struct_name);
    if (vg_item->from_type == FROM_DISK) {
        dss_close_volume(&volume);
    }
    if (status != CM_SUCCESS) {
        DSS_PRINT_ERROR("Failed to printf dss metadata.\n");
        return CM_ERROR;
    }
    DSS_PRINT_INF("Succeed to printf dss metadata.\n");
    return status;
}

static status_t dss_print_block_id(dss_session_t *session, dss_vg_info_item_t *vg_item, uint64 block_id, uint64 node_id)
{
    status_t status = dss_printf_block_with_blockid(session, vg_item, block_id, node_id);
    if (status != CM_SUCCESS) {
        DSS_PRINT_ERROR("Failed to printf dss file block with block_id:%llu.\n", block_id);
        return CM_ERROR;
    }
    DSS_PRINT_INF("Succeed to printf dss file block with block_id:%llu.\n", block_id);
    return status;
}

static status_t showdisk_proc(void)
{
    const char *vg_name = cmd_showdisk_args[DSS_ARG_IDX_0].input_args;
    char *home = cmd_showdisk_args[DSS_ARG_IDX_4].input_args;
    status_t status;
    dss_config_t *inst_cfg = dss_get_g_inst_cfg();
    dss_vg_info_item_t *vg_item = NULL;
    status = set_config_info(home, inst_cfg);
    if (status != CM_SUCCESS) {
        DSS_PRINT_ERROR("Failed to load config info!\n");
        return status;
    }
    status = dss_load_vg_conf_info(&g_vgs_info, inst_cfg);
    if (status != CM_SUCCESS) {
        LOG_DEBUG_ERR("Failed to load vg info from config, errcode is %d.\n", status);
        return status;
    }
    status = dss_get_vg_item(&vg_item, vg_name);
    if (status != CM_SUCCESS) {
        DSS_PRINT_ERROR("Failed to get vg %s.\n", vg_name);
        return status;
    }
    vg_item->from_type = FROM_DISK;
    if (cmd_showdisk_args[DSS_ARG_IDX_2].inputed) {
        uint64 block_id = 0;
        status = cm_str2uint64(cmd_showdisk_args[DSS_ARG_IDX_2].input_args, &block_id);
        if (status == CM_ERROR) {
            DSS_PRINT_ERROR("block_id:%s is not a valid uint64\n", cmd_showdisk_args[DSS_ARG_IDX_2].input_args);
            return CM_ERROR;
        }
        uint64 node_id = 0;
        status = cm_str2uint64(cmd_showdisk_args[DSS_ARG_IDX_3].input_args, &node_id);
        if (status == CM_ERROR) {
            DSS_PRINT_ERROR("node_id:%s is not a valid uint64\n", cmd_showdisk_args[DSS_ARG_IDX_3].input_args);
            return CM_ERROR;
        }
        status = dss_print_block_id(NULL, vg_item, block_id, node_id);
    } else if (cmd_showdisk_args[DSS_ARG_IDX_1].inputed) {
        // for struct_name
        status = dss_print_struct_name(vg_item, cmd_showdisk_args[DSS_ARG_IDX_1].input_args);
    } else {
        DSS_PRINT_ERROR("none of struct_name and block_id.\n");
        return CM_ERROR;
    }

    return status;
}

static dss_args_t cmd_showmem_args[] = {
    {'g', "vg_name", CM_TRUE, CM_TRUE, dss_check_name, NULL, NULL, 0, NULL, NULL, 0},
    {'s', "struct_name", CM_TRUE, CM_TRUE, cmd_check_struct_name, NULL, NULL, 0, NULL, NULL, 0},
    {'b', "block_id", CM_TRUE, CM_TRUE, cmd_check_disk_id, NULL, NULL, 0, NULL, NULL, 0},
    {'i', "index_id", CM_TRUE, CM_TRUE, cmd_check_block_index_id, NULL, NULL, 0, NULL, NULL, 0},
    {'f', "fid", CM_TRUE, CM_TRUE, cmd_check_fid, NULL, NULL, 0, NULL, NULL, 0},
    {'n', "node_id", CM_TRUE, CM_TRUE, cmd_check_disk_id, NULL, NULL, 0, NULL, NULL, 0},
    {'p', "path", CM_TRUE, CM_TRUE, dss_cmd_check_device_path, cmd_check_convert_path, cmd_clean_check_convert, 0, NULL,
        NULL, 0},
    {'o', "offset", CM_TRUE, CM_TRUE, cmd_check_offset, NULL, NULL, 0, NULL, NULL, 0},
    {'z', "size", CM_TRUE, CM_TRUE, cmd_check_read_size, NULL, NULL, 0, NULL, NULL, 0},
    {'U', "UDS", CM_FALSE, CM_TRUE, cmd_check_uds, cmd_check_convert_uds_home, cmd_clean_check_convert, 0, NULL, NULL,
        0},
};

static status_t showmem_check_args_with_offset(dss_args_t *cmd_args_set, int set_size)
{
    if (cmd_args_set[DSS_ARG_IDX_7].inputed && !cmd_args_set[DSS_ARG_IDX_8].inputed) {
        DSS_PRINT_ERROR("should set the offset with size.\n");
        return CM_ERROR;
    }
    if (!cmd_args_set[DSS_ARG_IDX_7].inputed && cmd_args_set[DSS_ARG_IDX_8].inputed) {
        DSS_PRINT_ERROR("should not set the size without offset.\n");
        return CM_ERROR;
    }
    if (cmd_args_set[DSS_ARG_IDX_7].inputed) {
        if ((cmd_args_set[DSS_ARG_IDX_1].inputed || cmd_args_set[DSS_ARG_IDX_2].inputed)) {
            DSS_PRINT_ERROR("should not set one way [struct_name | block_id] with offset.\n");
            return CM_ERROR;
        }
        if (!(cmd_args_set[DSS_ARG_IDX_4].inputed || cmd_args_set[DSS_ARG_IDX_6].inputed)) {
            DSS_PRINT_ERROR("param offset should be set with one way [fid | path] to show.\n");
            return CM_ERROR;
        }
    }
    return CM_SUCCESS;
}

static status_t showmem_check_args_with_vg_name(dss_args_t *cmd_args_set, int set_size)
{
    if (!cmd_args_set[DSS_ARG_IDX_1].inputed && !cmd_args_set[DSS_ARG_IDX_2].inputed &&
        !cmd_args_set[DSS_ARG_IDX_4].inputed) {
        DSS_PRINT_ERROR("should at least set one way [struct_name | block_id | fid] to show with vg_name.\n");
        return CM_ERROR;
    }
    if ((cmd_args_set[DSS_ARG_IDX_1].inputed &&
            (cmd_args_set[DSS_ARG_IDX_2].inputed || cmd_args_set[DSS_ARG_IDX_4].inputed)) ||
        (cmd_args_set[DSS_ARG_IDX_2].inputed && cmd_args_set[DSS_ARG_IDX_4].inputed)) {
        DSS_PRINT_ERROR("should only set one way [struct_name | block_id | fid] to show with vg_name.\n");
        return CM_ERROR;
    }
    if (cmd_args_set[DSS_ARG_IDX_2].inputed && !cmd_args_set[DSS_ARG_IDX_3].inputed) {
        DSS_PRINT_ERROR("should set the block_id with index_id.\n");
        return CM_ERROR;
    }
    if (!cmd_args_set[DSS_ARG_IDX_2].inputed && cmd_args_set[DSS_ARG_IDX_3].inputed) {
        DSS_PRINT_ERROR("should not set the index_id without block_id.\n");
        return CM_ERROR;
    }
    if (cmd_args_set[DSS_ARG_IDX_4].inputed && !cmd_args_set[DSS_ARG_IDX_5].inputed) {
        DSS_PRINT_ERROR("should set the fid with node_id.\n");
        return CM_ERROR;
    }
    if (!cmd_args_set[DSS_ARG_IDX_4].inputed && cmd_args_set[DSS_ARG_IDX_5].inputed) {
        DSS_PRINT_ERROR("should not set the node_id without fid.\n");
        return CM_ERROR;
    }
    return showmem_check_args_with_offset(cmd_args_set, set_size);
}

static status_t showmem_check_args_with_path(dss_args_t *cmd_args_set, int set_size)
{
    if (cmd_args_set[DSS_ARG_IDX_1].inputed || cmd_args_set[DSS_ARG_IDX_2].inputed ||
        cmd_args_set[DSS_ARG_IDX_3].inputed || cmd_args_set[DSS_ARG_IDX_4].inputed ||
        cmd_args_set[DSS_ARG_IDX_5].inputed) {
        DSS_PRINT_ERROR("could not set other way if set the path.\n");
        return CM_ERROR;
    }
    return showmem_check_args_with_offset(cmd_args_set, set_size);
}

static status_t showmem_check_args(dss_args_t *cmd_args_set, int set_size)
{
    if (cmd_args_set == NULL || set_size <= 0) {
        DSS_PRINT_ERROR("args error.\n");
        return CM_ERROR;
    }
    if (cmd_args_set[DSS_ARG_IDX_0].inputed && cmd_args_set[DSS_ARG_IDX_6].inputed) {
        DSS_PRINT_ERROR("should not set the vg name and path at the same time.\n");
        return CM_ERROR;
    }
    if (!cmd_args_set[DSS_ARG_IDX_0].inputed && !cmd_args_set[DSS_ARG_IDX_6].inputed) {
        DSS_PRINT_ERROR("should set the vg name or path to show.\n");
        return CM_ERROR;
    }
    if (cmd_args_set[DSS_ARG_IDX_0].inputed) {
        return showmem_check_args_with_vg_name(cmd_args_set, set_size);
    }
    if (cmd_args_set[DSS_ARG_IDX_6].inputed) {
        return showmem_check_args_with_path(cmd_args_set, set_size);
    }
    return CM_SUCCESS;
}

static dss_args_set_t cmd_showmem_args_set = {
    cmd_showmem_args,
    sizeof(cmd_showmem_args) / sizeof(dss_args_t),
    showmem_check_args,
};

static void showmem_help(const char *prog_name, int print_flag)
{
    (void)printf("\nUsage:%s showmem <-g vg_name> <-s struct_name> [-U UDS:socket_domain]\n", prog_name);
    (void)printf("      %s showmem <-g vg_name> <-b block_id> <-i index_id> [-U UDS:socket_domain]\n", prog_name);
    (void)printf(
        "      %s showmem <-g vg_name> <-f fid> <-n node_id> [-o offset -z size] [-U UDS:socket_domain]\n", prog_name);
    (void)printf("      %s showmem <-p path> [-o offset -z size] [-U UDS:socket_domain]\n", prog_name);
    (void)printf("[client command] showmem information\n");
    if (print_flag == DSS_HELP_SIMPLE) {
        return;
    }
    (void)printf("-g/--vg_name <vg_name>, <required>, the volume group name\n");
    (void)printf("-s/--struct_name <struct_name>, <required>, the struct name of volume group, "
                 "the optional value(s):\n");
    (void)printf("    [core_ctrl | vg_header | volume_ctrl | root_ft_block]\n");
    (void)printf("-b/--block_id <block_id>, <required>, fs block id or ft block id\n");
    (void)printf("-i/--index_id <index_id>, <required>, index id in block\n");
    (void)printf("-f/--fid <fid>, <required>, file id\n");
    (void)printf("-n/--node_id <node_id>, <required>, node id\n");
    (void)printf("-p/--path <path>, <required>, dss file path\n");
    (void)printf("-o/--offset <offset>, [optional], offset\n");
    (void)printf("-z/--size <size>, [optional], size\n");
    help_param_uds();
}

static status_t showmem_proc_by_block_id_and_index_id(dss_session_t *session, dss_vg_info_item_t *vg_item)
{
    uint64 block_id = 0;
    status_t status = cm_str2uint64(cmd_showmem_args[DSS_ARG_IDX_2].input_args, &block_id);
    DSS_RETURN_IFERR2(
        status, DSS_PRINT_ERROR("block_id:%s is not a valid uint64\n", cmd_showmem_args[DSS_ARG_IDX_2].input_args));
    uint64 node_id = 0;
    status = cm_str2uint64(cmd_showmem_args[DSS_ARG_IDX_3].input_args, &node_id);
    DSS_RETURN_IFERR2(
        status, DSS_PRINT_ERROR("node_id:%s is not a valid uint64\n", cmd_showmem_args[DSS_ARG_IDX_3].input_args));
    DSS_RETURN_IFERR2(dss_lock_vg_s(vg_item, session), DSS_PRINT_ERROR("Failed to lock vg %s.\n", vg_item->vg_name));
    status = dss_print_block_id(session, vg_item, block_id, node_id);
    DSS_UNLOCK_VG_META_S(vg_item, session);
    return status;
}

static status_t showmem_proc_by_path(dss_session_t *session, dss_vg_info_item_t *vg_item, dss_show_param_t *show_param)
{
    status_t status;
    const char *path = cmd_showmem_args[DSS_ARG_IDX_6].input_args;
    if (cmd_showmem_args[DSS_ARG_IDX_6].convert_result != NULL) {
        path = cmd_showmem_args[DSS_ARG_IDX_6].convert_result;
    }

    errno_t errcode = strcpy_s(show_param->path, sizeof(show_param->path), path);
    if (errcode != EOK) {
        DSS_PRINT_ERROR("Failed to strcpy.\n");
        return CM_ERROR;
    }
    if (cmd_showmem_args[DSS_ARG_IDX_8].inputed) {
        status = cm_str2bigint(cmd_showmem_args[DSS_ARG_IDX_7].input_args, &show_param->offset);
        DSS_RETURN_IFERR2(
            status, DSS_PRINT_ERROR("offset:%s is not a valid int64\n", cmd_showmem_args[DSS_ARG_IDX_7].input_args));
        status = cm_str2int(cmd_showmem_args[DSS_ARG_IDX_8].input_args, &show_param->size);
        DSS_RETURN_IFERR2(
            status, DSS_PRINT_ERROR("size:%s is not a valid int32\n", cmd_showmem_args[DSS_ARG_IDX_8].input_args));
    }
    DSS_RETURN_IFERR2(dss_lock_vg_s(vg_item, session), DSS_PRINT_ERROR("Failed to lock vg %s.\n", vg_item->vg_name));
    status = dss_print_gft_node_by_path(session, vg_item, show_param);
    DSS_UNLOCK_VG_META_S(vg_item, session);
    return status;
}

static status_t showmem_proc_by_fid_and_node_id(
    dss_session_t *session, dss_vg_info_item_t *vg_item, dss_show_param_t *show_param)
{
    status_t status = cm_str2uint64(cmd_showmem_args[DSS_ARG_IDX_4].input_args, &show_param->fid);
    DSS_RETURN_IFERR2(
        status, DSS_PRINT_ERROR("fid:%s is not a valid uint64\n", cmd_showmem_args[DSS_ARG_IDX_4].input_args));
    status = cm_str2uint64(cmd_showmem_args[DSS_ARG_IDX_5].input_args, &show_param->ftid);
    DSS_RETURN_IFERR2(
        status, DSS_PRINT_ERROR("node_id:%s is not a valid uint64\n", cmd_showmem_args[DSS_ARG_IDX_5].input_args));
    if (cmd_showmem_args[DSS_ARG_IDX_8].inputed) {
        status = cm_str2bigint(cmd_showmem_args[DSS_ARG_IDX_7].input_args, &show_param->offset);
        DSS_RETURN_IFERR2(
            status, DSS_PRINT_ERROR("offset:%s is not a valid int64\n", cmd_showmem_args[DSS_ARG_IDX_7].input_args));
        status = cm_str2int(cmd_showmem_args[DSS_ARG_IDX_8].input_args, &show_param->size);
        DSS_RETURN_IFERR2(
            status, DSS_PRINT_ERROR("size:%s is not a valid int32\n", cmd_showmem_args[DSS_ARG_IDX_8].input_args));
    }
    DSS_RETURN_IFERR2(dss_lock_vg_s(vg_item, session), DSS_PRINT_ERROR("Failed to lock vg %s.\n", vg_item->vg_name));
    status = dss_print_gft_node_by_ftid_and_fid(session, vg_item, show_param);
    DSS_UNLOCK_VG_META_S(vg_item, session);
    return status;
}

static status_t showmem_proc(void)
{
    const char *vg_name = cmd_showmem_args[DSS_ARG_IDX_0].input_args;
    const char *path = cmd_showmem_args[DSS_ARG_IDX_6].input_args;
    if (cmd_showmem_args[DSS_ARG_IDX_6].convert_result != NULL) {
        path = cmd_showmem_args[DSS_ARG_IDX_6].convert_result;
    }

    dss_vg_info_item_t *vg_item = NULL;
    status_t status = CM_SUCCESS;
    const char *input_args = cmd_showmem_args[DSS_ARG_IDX_9].input_args;
    dss_conn_t *conn = dss_get_connection_opt(input_args);
    if (conn == NULL) {
        return CM_ERROR;
    }
    dss_show_param_t show_param;
    dss_init_show_param(&show_param);
    do {
        if (!cmd_showmem_args[DSS_ARG_IDX_0].inputed) {
            char name[DSS_MAX_NAME_LEN];
            DSS_BREAK_IFERR2(
                dss_find_vg_by_dir(path, name, &vg_item), DSS_PRINT_ERROR("Failed to get vg %s.\n", vg_name));
        } else {
            status = dss_get_vg_item(&vg_item, vg_name);
            DSS_BREAK_IFERR2(status, DSS_PRINT_ERROR("Failed to get vg %s.\n", vg_name));
        }
        vg_item->from_type = FROM_SHM;
        if (cmd_showmem_args[DSS_ARG_IDX_1].inputed) {
            DSS_BREAK_IFERR3(dss_lock_vg_s(vg_item, conn->session), status = CM_ERROR,
                DSS_PRINT_ERROR("Failed to lock vg %s.\n", vg_name));
            status = dss_print_struct_name(vg_item, cmd_showmem_args[DSS_ARG_IDX_1].input_args);
            DSS_UNLOCK_VG_META_S(vg_item, conn->session);
        } else if (cmd_showmem_args[DSS_ARG_IDX_2].inputed) {
            status = showmem_proc_by_block_id_and_index_id((dss_session_t *)conn->session, vg_item);
        } else if (cmd_showmem_args[DSS_ARG_IDX_4].inputed) {
            status = showmem_proc_by_fid_and_node_id((dss_session_t *)conn->session, vg_item, &show_param);
        } else if (cmd_showmem_args[DSS_ARG_IDX_6].inputed) {
            status = showmem_proc_by_path((dss_session_t *)conn->session, vg_item, &show_param);
        } else {
            status = CM_ERROR;
            DSS_PRINT_ERROR("none of struct_name and block_id and fid.\n");
        }
    } while (CM_FALSE);
    return status;
}

static dss_args_t cmd_fshowmem_args[] = {
    {'m', "memory_file_path", CM_TRUE, CM_TRUE, dss_check_path_both, NULL, NULL, 0, NULL, NULL, 0},
    {'g', "vg_name", CM_TRUE, CM_TRUE, dss_check_name, NULL, NULL, 0, NULL, NULL, 0},
    {'s', "struct_name", CM_TRUE, CM_TRUE, cmd_check_struct_name, NULL, NULL, 0, NULL, NULL, 0},
    {'b', "block_id", CM_TRUE, CM_TRUE, cmd_check_disk_id, NULL, NULL, 0, NULL, NULL, 0},
    {'i', "index_id", CM_TRUE, CM_TRUE, cmd_check_block_index_id, NULL, NULL, 0, NULL, NULL, 0},
    {'f', "fid", CM_TRUE, CM_TRUE, cmd_check_fid, NULL, NULL, 0, NULL, NULL, 0},
    {'n', "node_id", CM_TRUE, CM_TRUE, cmd_check_disk_id, NULL, NULL, 0, NULL, NULL, 0},
    {'p', "path", CM_TRUE, CM_TRUE, dss_cmd_check_device_path, cmd_check_convert_path, cmd_clean_check_convert, 0, NULL,
        NULL, 0},
    {'o', "offset", CM_TRUE, CM_TRUE, cmd_check_offset, NULL, NULL, 0, NULL, NULL, 0},
    {'z', "size", CM_TRUE, CM_TRUE, cmd_check_read_size, NULL, NULL, 0, NULL, NULL, 0},
    {'D', "DSS_HOME", CM_FALSE, CM_TRUE, cmd_check_dss_home, cmd_check_convert_dss_home, cmd_clean_check_convert, 0,
        NULL, NULL, 0},
};

static status_t fshowmem_check_args_with_offset(dss_args_t *cmd_args_set, int set_size)
{
    if (cmd_args_set[DSS_ARG_IDX_8].inputed && !cmd_args_set[DSS_ARG_IDX_9].inputed) {
        DSS_PRINT_ERROR("should set the offset with size.\n");
        return CM_ERROR;
    }
    if (!cmd_args_set[DSS_ARG_IDX_8].inputed && cmd_args_set[DSS_ARG_IDX_9].inputed) {
        DSS_PRINT_ERROR("should not set the size without offset.\n");
        return CM_ERROR;
    }
    if (cmd_args_set[DSS_ARG_IDX_8].inputed) {
        if ((cmd_args_set[DSS_ARG_IDX_2].inputed || cmd_args_set[DSS_ARG_IDX_3].inputed)) {
            DSS_PRINT_ERROR("should not set one way [struct_name | block_id] with offset.\n");
            return CM_ERROR;
        }
        if (!(cmd_args_set[DSS_ARG_IDX_5].inputed || cmd_args_set[DSS_ARG_IDX_7].inputed)) {
            DSS_PRINT_ERROR("param offset should be set with one way [fid | path] to show.\n");
            return CM_ERROR;
        }
    }
    return CM_SUCCESS;
}

static status_t fshowmem_check_args_with_vg_name(dss_args_t *cmd_args_set, int set_size)
{
    if (!cmd_args_set[DSS_ARG_IDX_2].inputed && !cmd_args_set[DSS_ARG_IDX_3].inputed &&
        !cmd_args_set[DSS_ARG_IDX_5].inputed) {
        DSS_PRINT_ERROR("should at least set one way [struct_name | block_id | fid] to show with vg_name.\n");
        return CM_ERROR;
    }
    if ((cmd_args_set[DSS_ARG_IDX_2].inputed &&
            (cmd_args_set[DSS_ARG_IDX_3].inputed || cmd_args_set[DSS_ARG_IDX_5].inputed)) ||
        (cmd_args_set[DSS_ARG_IDX_3].inputed && cmd_args_set[DSS_ARG_IDX_5].inputed)) {
        DSS_PRINT_ERROR("should only set one way [struct_name | block_id | fid] to show with vg_name.\n");
        return CM_ERROR;
    }
    if (cmd_args_set[DSS_ARG_IDX_3].inputed && !cmd_args_set[DSS_ARG_IDX_4].inputed) {
        DSS_PRINT_ERROR("should set the block_id with index_id.\n");
        return CM_ERROR;
    }
    if (!cmd_args_set[DSS_ARG_IDX_3].inputed && cmd_args_set[DSS_ARG_IDX_4].inputed) {
        DSS_PRINT_ERROR("should not set the index_id without block_id.\n");
        return CM_ERROR;
    }
    if (cmd_args_set[DSS_ARG_IDX_5].inputed && !cmd_args_set[DSS_ARG_IDX_6].inputed) {
        DSS_PRINT_ERROR("should set the fid with node_id.\n");
        return CM_ERROR;
    }
    if (!cmd_args_set[DSS_ARG_IDX_5].inputed && cmd_args_set[DSS_ARG_IDX_6].inputed) {
        DSS_PRINT_ERROR("should not set the node_id without fid.\n");
        return CM_ERROR;
    }
    return fshowmem_check_args_with_offset(cmd_args_set, set_size);
}

static status_t fshowmem_check_args_with_path(dss_args_t *cmd_args_set, int set_size)
{
    if (cmd_args_set[DSS_ARG_IDX_2].inputed || cmd_args_set[DSS_ARG_IDX_3].inputed ||
        cmd_args_set[DSS_ARG_IDX_4].inputed || cmd_args_set[DSS_ARG_IDX_5].inputed ||
        cmd_args_set[DSS_ARG_IDX_6].inputed) {
        DSS_PRINT_ERROR("could not set other way if set path.\n");
        return CM_ERROR;
    }
    return fshowmem_check_args_with_offset(cmd_args_set, set_size);
}

static status_t fshowmem_check_args(dss_args_t *cmd_args_set, int set_size)
{
    if (cmd_args_set == NULL || set_size <= 0) {
        DSS_PRINT_ERROR("args error.\n");
        return CM_ERROR;
    }
    if (!cmd_args_set[DSS_ARG_IDX_0].inputed) {
        DSS_PRINT_ERROR("should set the file path to load.\n");
        return CM_ERROR;
    }
    if (cmd_args_set[DSS_ARG_IDX_1].inputed && cmd_args_set[DSS_ARG_IDX_7].inputed) {
        DSS_PRINT_ERROR("should not set the vg name and path at the same time.\n");
        return CM_ERROR;
    }
    if (!cmd_args_set[DSS_ARG_IDX_1].inputed && !cmd_args_set[DSS_ARG_IDX_7].inputed) {
        DSS_PRINT_ERROR("should set the vg name or path to show.\n");
        return CM_ERROR;
    }
    if (cmd_args_set[DSS_ARG_IDX_1].inputed) {
        return fshowmem_check_args_with_vg_name(cmd_args_set, set_size);
    }
    if (cmd_args_set[DSS_ARG_IDX_7].inputed) {
        return fshowmem_check_args_with_path(cmd_args_set, set_size);
    }
    return CM_SUCCESS;
}

static dss_args_set_t cmd_fshowmem_args_set = {
    cmd_fshowmem_args,
    sizeof(cmd_fshowmem_args) / sizeof(dss_args_t),
    fshowmem_check_args,
};

static void fshowmem_help(const char *prog_name, int print_flag)
{
    (void)printf("\nUsage:%s fshowmem <-m memory_file_path> <-g vg_name> <-s struct_name> [-D DSS_HOME]\n", prog_name);
    (void)printf(
        "      %s fshowmem <-m memory_file_path> <-g vg_name> <-b block_id> <-i index_id> [-D DSS_HOME]\n", prog_name);
    (void)printf("      %s fshowmem <-m memory_file_path> <-g vg_name> <-f fid> <-n node_id> [-o offset -z size] [-D "
                 "DSS_HOME]\n",
        prog_name);
    (void)printf("      %s fshowmem <-m memory_file_path> <-g vg_name> <-p path> [-o offset -z size] [-D DSS_HOME]\n",
        prog_name);
    (void)printf("[client command] fshowmem information\n");
    if (print_flag == DSS_HELP_SIMPLE) {
        return;
    }
    (void)printf("-m/--memory_file_path <memory_file_path>, <required>, the file path to load\n");
    (void)printf("-g/--vg_name <vg_name>, <required>, the volume group name\n");
    (void)printf("-s/--struct_name <struct_name>, <required>, the struct name of volume group, "
                 "the optional value(s):\n");
    (void)printf("    [core_ctrl | volume_ctrl | vg_header | root_ft_block]\n");
    (void)printf("-b/--block_id <block_id>, <required>, fs block id or ft block id\n");
    (void)printf("-i/--index_id <index_id>, <required>, index id in block\n");
    (void)printf("-f/--fid <fid>, <required>, file id\n");
    (void)printf("-n/--node_id <node_id>, <required>, node id\n");
    (void)printf("-p/--path <path>, <required>, dss file path\n");
    (void)printf("-o/--offset <offset>, [optional], offset\n");
    (void)printf("-z/--size <size>, [optional], size\n");
    help_param_dsshome();
}

int32 dss_open_memory_file(const char *file_name)
{
    int32 file_fd;
    uint32 mode = O_RDONLY | O_BINARY;
    char realpath[CM_FILE_NAME_BUFFER_SIZE] = {0};
    if (realpath_file(file_name, realpath, CM_FILE_NAME_BUFFER_SIZE) != CM_SUCCESS) {
        LOG_DEBUG_ERR("Failed to find realpath file %s", file_name);
        return -1;
    }
    if (!cm_file_exist(realpath)) {
        DSS_THROW_ERROR_EX(ERR_DSS_FILE_NOT_EXIST, "%s not exist, please check", realpath);
        return -1;
    }
    if (cm_open_file(realpath, mode, &file_fd) != CM_SUCCESS) {
        LOG_DEBUG_ERR("Failed to open memory file %s", realpath);
        return -1;
    }
    return file_fd;
}

static void dss_free_buffer_pool_from_file()
{
    ga_pool_t *pool = &g_app_pools[GA_POOL_IDX(GA_8K_POOL)];
    if (pool != NULL && pool->ctrl != NULL) {
        CM_FREE_PTR(pool->ctrl);
    }
    pool = &g_app_pools[GA_POOL_IDX(GA_16K_POOL)];
    if (pool != NULL && pool->ctrl != NULL) {
        CM_FREE_PTR(pool->ctrl);
    }
}
static status_t dss_load_buffer_pool_from_file(int32 file_fd, ga_pool_id_e pool_id)
{
    uint64 total_size;
    int32 read_size;
    status_t status = cm_read_file(file_fd, &total_size, sizeof(uint64), &read_size);
    DSS_RETURN_IFERR2(status, LOG_DEBUG_ERR("Failed to read pool size."));
    char *pool_ft_block_buf = cm_malloc(total_size);
    if (pool_ft_block_buf == NULL) {
        LOG_DEBUG_ERR("Failed to malloc ft block pool.");
        return CM_ERROR;
    }
    ga_pool_t *pool = &g_app_pools[GA_POOL_IDX((uint32)pool_id)];
    if (pool == NULL) {
        CM_FREE_PTR(pool_ft_block_buf);
        LOG_DEBUG_ERR("Failed to get ga pool from file.");
        return CM_ERROR;
    }
    status = cm_read_file(file_fd, pool_ft_block_buf, (int32)total_size, &read_size);
    if (status != CM_SUCCESS) {
        CM_FREE_PTR(pool_ft_block_buf);
        LOG_DEBUG_ERR("Failed to read file.");
        return CM_ERROR;
    }
    pool->addr = pool_ft_block_buf;
    pool->ctrl = (ga_pool_ctrl_t *)pool->addr;
    pool->def = pool->ctrl->def;
    uint32 object_cost = pool->ctrl->def.object_size + (uint32)sizeof(ga_object_map_t);
    uint64 ex_pool_size = (uint64)object_cost * pool->ctrl->def.object_count;
    pool->capacity = CM_ALIGN_512((uint32)sizeof(ga_pool_ctrl_t)) + CM_ALIGN_512(ex_pool_size);
    if (pool->ctrl->ex_count > GA_MAX_EXTENDED_POOLS) {
        LOG_RUN_ERR("Invalid pool info[id=%u]: ex_count is %u, larger than maximum %u", pool_id, pool->ctrl->ex_count,
            GA_MAX_EXTENDED_POOLS);
        return CM_ERROR;
    }
    for (uint32 i = 0; i < pool->ctrl->ex_count; i++) {
        pool->ex_pool_addr[i] = pool_ft_block_buf + pool->capacity + i * ex_pool_size;
    }
    return CM_SUCCESS;
}

static void dss_free_vg_item_from_file(dss_vg_info_item_t *vg_item)
{
    if (vg_item->dss_ctrl != NULL) {
        CM_FREE_PTR(vg_item->dss_ctrl);
    }
    if (vg_item->buffer_cache != NULL) {
        CM_FREE_PTR(vg_item->buffer_cache);
    }
}

static status_t dss_load_dss_ctrl_from_file(int32 file_fd, dss_vg_info_item_t *vg_item)
{
    int32 read_size;
    vg_item->dss_ctrl = cm_malloc(sizeof(dss_ctrl_t));
    if (vg_item->dss_ctrl == NULL) {
        LOG_DEBUG_ERR("Malloc dss_ctrl failed.\n");
        return CM_ERROR;
    }
    status_t status = cm_read_file(file_fd, vg_item->dss_ctrl, sizeof(dss_ctrl_t), &read_size);
    DSS_RETURN_IFERR2(status, LOG_DEBUG_ERR("Failed to read file."));
    return CM_SUCCESS;
}

static status_t dss_load_buffer_cache_from_file(int32 file_fd, dss_vg_info_item_t *vg_item, int64 *offset)
{
    int32 read_size;
    char *buffer = NULL;
    uint64 dir_size = DSS_MAX_SEGMENT_NUM * (uint32)sizeof(uint32_t);
    buffer = cm_malloc(sizeof(shm_hashmap_t) + dir_size);
    if (buffer == NULL) {
        LOG_DEBUG_ERR("Malloc failed.\n");
        return CM_ERROR;
    }
    status_t status = cm_read_file(file_fd, buffer, sizeof(shm_hashmap_t), &read_size);
    DSS_RETURN_IFERR2(status, LOG_DEBUG_ERR("Failed to read file."));
    uint32 id = vg_item->id;
    uint32 shm_key = cm_shm_key_of(SHM_TYPE_HASH, id);
    vg_item->buffer_cache = (shm_hashmap_t *)buffer;
    vg_item->buffer_cache->hash_ctrl.dirs = cm_trans_shm_offset_from_malloc(shm_key, buffer + sizeof(shm_hashmap_t));
    vg_item->buffer_cache->shm_id = id;
    vg_item->buffer_cache->hash_ctrl.func = cm_oamap_uint64_compare;
    status = cm_read_file(file_fd, buffer + sizeof(shm_hashmap_t), (int32)dir_size, &read_size);
    DSS_RETURN_IFERR2(status, LOG_DEBUG_ERR("Failed to read file."));
    *offset = *offset + (int64)sizeof(shm_hashmap_t) + (int64)dir_size;
    return CM_SUCCESS;
}

static status_t dss_get_group_num(int32 file_fd, int64 *offset, uint32 *group_num)
{
    int32 read_size = 0;
    status_t status = cm_read_file(file_fd, group_num, sizeof(uint32), &read_size);
    DSS_RETURN_IFERR2(status, LOG_DEBUG_ERR("Failed to read group num."));
    *offset += (int64)sizeof(uint32);
    return CM_SUCCESS;
}

bool32 dss_check_software_version(int32 file_fd, int64 *offset)
{
    int32 read_size = 0;
    uint32 software_version;
    status_t status = cm_read_file(file_fd, &software_version, sizeof(uint32), &read_size);
    if (status != CM_SUCCESS) {
        LOG_DEBUG_ERR("Failed to read software_version");
        return CM_FALSE;
    }
    if (software_version > (uint32)DSS_SOFTWARE_VERSION) {
        LOG_DEBUG_ERR("The file software_version which is %u is bigger than the actural software_version which is %u.",
            software_version, (uint32)DSS_SOFTWARE_VERSION);
        return CM_FALSE;
    }
    *offset += (int64)sizeof(uint32);
    return CM_TRUE;
}

// length| vg_num| vg_name|size|buckets|map->num|
// vg_name|size|buckets|map->num|...|pool_size|pool->addr|pool->ex_pool_addr[0]|...|pool->ex_pool_addr[excount-1]|...
status_t dss_load_buffer_cache_group_from_file(
    int32 file_fd, int64 *length, const char *vg_name, dss_vg_info_item_t *vg_item)
{
    uint32 group_num = 0;
    int64 offset = *length;
    int32 read_size = 0;
    bool32 result;
    status_t status = cm_read_file(file_fd, length, sizeof(int64), &read_size);
    DSS_RETURN_IFERR2(status, LOG_DEBUG_ERR("Failed to read file."));
    offset += (int64)sizeof(int64);
    DSS_RETURN_IF_ERROR(dss_get_group_num(file_fd, &offset, &group_num));
    char read_vg_name[DSS_MAX_NAME_LEN];
    uint32 i;
    bool32 find = CM_FALSE;
    for (i = 0; i < group_num; i++) {
        status = cm_read_file(file_fd, read_vg_name, DSS_MAX_NAME_LEN, &read_size);
        DSS_RETURN_IFERR2(status, LOG_DEBUG_ERR("Failed to read file."));
        offset += DSS_MAX_NAME_LEN;
        if (strcmp(vg_name, read_vg_name) != 0) {
            uint64 bucket_size = DSS_MAX_SEGMENT_NUM * (uint32)sizeof(uint32_t);
            uint64 hashmap_size = sizeof(shm_hashmap_t) + bucket_size;
            offset = offset + (int64)hashmap_size;
            result = (bool32)(cm_seek_file(file_fd, offset, SEEK_SET) != -1);
            DSS_RETURN_IF_FALSE2(result, LOG_DEBUG_ERR("Failed to seek file %d", file_fd));
            continue;
        }
        DSS_RETURN_IF_ERROR(dss_load_buffer_cache_from_file(file_fd, vg_item, &offset));
        find = CM_TRUE;
    }
    if (!find) {
        LOG_DEBUG_ERR("Failed to find vg: %s.", vg_name);
        return CM_ERROR;
    }
    DSS_RETURN_IF_ERROR(dss_load_buffer_pool_from_file(file_fd, GA_8K_POOL));
    DSS_RETURN_IF_ERROR(dss_load_buffer_pool_from_file(file_fd, GA_16K_POOL));
    DSS_RETURN_IF_ERROR(dss_load_buffer_pool_from_file(file_fd, GA_FS_AUX_POOL));
    DSS_RETURN_IF_ERROR(dss_load_buffer_pool_from_file(file_fd, GA_SEGMENT_POOL));
    return CM_SUCCESS;
}

status_t dss_load_dss_ctrl_group_from_file(
    int32 file_fd, int64 *length, const char *vg_name, dss_vg_info_item_t *vg_item)
{
    uint32 group_num = 0;
    int64 offset = 0;
    int32 read_size = 0;
    status_t status = cm_read_file(file_fd, length, sizeof(int64), &read_size);
    DSS_RETURN_IFERR2(status, LOG_DEBUG_ERR("Failed to read file."));
    offset += (int64)sizeof(int64);
    DSS_RETURN_IF_ERROR(dss_get_group_num(file_fd, &offset, &group_num));
    char read_vg_name[DSS_MAX_NAME_LEN];
    uint32 i;
    bool32 find = CM_FALSE;
    bool32 result = CM_FALSE;
    for (i = 0; i < group_num; i++) {
        DSS_RETURN_IF_FALSE2(dss_check_software_version(file_fd, &offset),
            LOG_DEBUG_ERR("Failed to check software_version of vg %u", i));
        status = cm_read_file(file_fd, read_vg_name, DSS_MAX_NAME_LEN, &read_size);
        DSS_RETURN_IFERR2(status, LOG_DEBUG_ERR("Failed to read file."));
        offset += DSS_MAX_NAME_LEN;
        if (strcmp(vg_name, read_vg_name) != 0) {
            offset += (int64)sizeof(dss_ctrl_t);
            result = (bool32)(cm_seek_file(file_fd, offset, SEEK_SET) != -1);
            DSS_RETURN_IF_FALSE2(result, LOG_DEBUG_ERR("Failed to seek file %d", file_fd));
            continue;
        }
        DSS_RETURN_IF_ERROR(dss_load_dss_ctrl_from_file(file_fd, vg_item));
        offset += (int64)sizeof(dss_ctrl_t);
        find = CM_TRUE;
    }
    if (!find) {
        LOG_DEBUG_ERR("Failed to find vg: %s.", vg_name);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

status_t dss_load_vg_item_and_pool_from_file(const char *file_name, const char *vg_name, dss_vg_info_item_t *vg_item)
{
    int32 file_fd = dss_open_memory_file(file_name);
    if (file_fd == -1) {
        LOG_DEBUG_ERR("Failed to open memory file %s", file_name);
        return CM_ERROR;
    }
    int64 size = cm_file_size(file_fd);
    if (size == -1) {
        cm_close_file(file_fd);
        LOG_DEBUG_ERR("Failed to read file size %s", file_name);
        return CM_ERROR;
    }
    int64 length = -1;
    status_t status;
    bool32 result = (bool32)(cm_seek_file(file_fd, 0, SEEK_SET) != -1);
    DSS_RETURN_IF_FALSE2(result, LOG_DEBUG_ERR("Failed to seek file %s", file_name));
    do {
        status = dss_load_dss_ctrl_group_from_file(file_fd, &length, vg_name, vg_item);
        if (status != CM_SUCCESS) {
            if (length == -1) {
                break;
            }
            result = (bool32)(cm_seek_file(file_fd, length, SEEK_SET) != -1);
            DSS_RETURN_IF_FALSE2(result, LOG_DEBUG_ERR("Failed to seek file %s", file_name));
        }

        status = dss_load_buffer_cache_group_from_file(file_fd, &length, vg_name, vg_item);
        DSS_BREAK_IF_ERROR(status);
    } while (CM_FALSE);
    cm_close_file(file_fd);
    if (status != CM_SUCCESS) {
        LOG_DEBUG_ERR("Failed to load vg item %s", vg_name);
    }
    return status;
}

static status_t fshowmem_proc_by_block_id_and_index_id(dss_vg_info_item_t *vg_item)
{
    uint64 block_id = 0;
    status_t status = cm_str2uint64(cmd_fshowmem_args[DSS_ARG_IDX_3].input_args, &block_id);
    DSS_RETURN_IFERR2(
        status, DSS_PRINT_ERROR("block_id:%s is not a valid uint64\n", cmd_fshowmem_args[DSS_ARG_IDX_3].input_args));
    uint64 node_id = 0;
    status = cm_str2uint64(cmd_fshowmem_args[DSS_ARG_IDX_4].input_args, &node_id);
    DSS_RETURN_IFERR2(
        status, DSS_PRINT_ERROR("node_id:%s is not a valid uint64\n", cmd_fshowmem_args[DSS_ARG_IDX_4].input_args));
    status = dss_print_block_id(NULL, vg_item, block_id, node_id);
    return status;
}

static status_t fshowmem_proc_by_path(dss_vg_info_item_t *vg_item, dss_show_param_t *show_param)
{
    status_t status;
    const char *path = cmd_fshowmem_args[DSS_ARG_IDX_7].input_args;
    if (cmd_fshowmem_args[DSS_ARG_IDX_7].convert_result != NULL) {
        path = cmd_fshowmem_args[DSS_ARG_IDX_7].convert_result;
    }

    errno_t errcode = strcpy_s(show_param->path, sizeof(show_param->path), path);
    if (errcode != EOK) {
        DSS_PRINT_ERROR("Failed to strcpy.\n");
        return CM_ERROR;
    }
    if (cmd_fshowmem_args[DSS_ARG_IDX_8].inputed) {
        status = cm_str2bigint(cmd_fshowmem_args[DSS_ARG_IDX_8].input_args, &show_param->offset);
        DSS_RETURN_IFERR2(
            status, DSS_PRINT_ERROR("offset:%s is not a valid int64\n", cmd_fshowmem_args[DSS_ARG_IDX_8].input_args));
        status = cm_str2int(cmd_fshowmem_args[DSS_ARG_IDX_9].input_args, &show_param->size);
        DSS_RETURN_IFERR2(
            status, DSS_PRINT_ERROR("size:%s is not a valid int32\n", cmd_fshowmem_args[DSS_ARG_IDX_9].input_args));
    }
    status = dss_print_gft_node_by_path(NULL, vg_item, show_param);
    return status;
}

static status_t fshowmem_proc_by_fid_and_node_id(dss_vg_info_item_t *vg_item, dss_show_param_t *show_param)
{
    status_t status = cm_str2uint64(cmd_fshowmem_args[DSS_ARG_IDX_5].input_args, &show_param->fid);
    DSS_RETURN_IFERR2(
        status, DSS_PRINT_ERROR("fid:%s is not a valid uint64\n", cmd_fshowmem_args[DSS_ARG_IDX_5].input_args));
    status = cm_str2uint64(cmd_fshowmem_args[DSS_ARG_IDX_6].input_args, &show_param->ftid);
    DSS_RETURN_IFERR2(
        status, DSS_PRINT_ERROR("node_id:%s is not a valid uint64\n", cmd_fshowmem_args[DSS_ARG_IDX_6].input_args));
    if (cmd_fshowmem_args[DSS_ARG_IDX_8].inputed) {
        status = cm_str2bigint(cmd_fshowmem_args[DSS_ARG_IDX_8].input_args, &show_param->offset);
        DSS_RETURN_IFERR2(
            status, DSS_PRINT_ERROR("offset:%s is not a valid int64\n", cmd_fshowmem_args[DSS_ARG_IDX_8].input_args));
        status = cm_str2int(cmd_fshowmem_args[DSS_ARG_IDX_9].input_args, &show_param->size);
        DSS_RETURN_IFERR2(
            status, DSS_PRINT_ERROR("size:%s is not a valid int32\n", cmd_fshowmem_args[DSS_ARG_IDX_9].input_args));
    }
    status = dss_print_gft_node_by_ftid_and_fid(NULL, vg_item, show_param);
    return status;
}
static status_t fshowmem_proc(void)
{
    status_t status = CM_SUCCESS;
    if (cmd_fshowmem_args[DSS_ARG_IDX_10].inputed) {
        dss_config_t *inst_cfg = dss_get_g_inst_cfg();
        char *home = cmd_fshowmem_args[DSS_ARG_IDX_10].input_args;
        status = set_config_info(home, inst_cfg);
        if (status != CM_SUCCESS) {
            DSS_PRINT_ERROR("Failed to set config info.\n");
            return status;
        }
        status = dss_init_loggers(inst_cfg, dss_get_cmd_log_def(), dss_get_cmd_log_def_count(), "dsscmd");
        if (status != CM_SUCCESS) {
            DSS_PRINT_ERROR("DSS init loggers failed!\n");
            return status;
        }
    }
    const char *file_name = cmd_fshowmem_args[DSS_ARG_IDX_0].input_args;
    const char *path = cmd_fshowmem_args[DSS_ARG_IDX_7].input_args;
    if (cmd_fshowmem_args[DSS_ARG_IDX_7].convert_result != NULL) {
        path = cmd_fshowmem_args[DSS_ARG_IDX_7].convert_result;
    }

    dss_vg_info_item_t vg_item = {0};
    dss_show_param_t show_param;
    dss_init_show_param(&show_param);
    vg_item.from_type = FROM_BBOX;
    do {
        if (!cmd_fshowmem_args[DSS_ARG_IDX_1].inputed) {
            char name[DSS_MAX_NAME_LEN];
            uint32_t beg_pos = 0;
            status = dss_get_name_from_path(path, &beg_pos, name);
            if (status != CM_SUCCESS) {
                DSS_PRINT_ERROR("Failed to get vg name from path %s.\n", path);
                return status;
            }
            if (name[0] == 0) {
                DSS_PRINT_ERROR("Failed to get vg name from path %s.\n", path);
                return CM_ERROR;
            }
            status = dss_load_vg_item_and_pool_from_file(file_name, name, &vg_item);
            DSS_BREAK_IFERR2(status, DSS_PRINT_ERROR("Failed to get vg %s.\n", name));
        } else {
            const char *vg_name = cmd_fshowmem_args[DSS_ARG_IDX_1].input_args;
            status = dss_load_vg_item_and_pool_from_file(file_name, vg_name, &vg_item);
            DSS_BREAK_IFERR2(status, DSS_PRINT_ERROR("Failed to get vg %s.\n", vg_name));
        }
        if (cmd_fshowmem_args[DSS_ARG_IDX_2].inputed) {
            status = dss_print_struct_name(&vg_item, cmd_fshowmem_args[DSS_ARG_IDX_2].input_args);
        } else if (cmd_fshowmem_args[DSS_ARG_IDX_3].inputed) {
            status = fshowmem_proc_by_block_id_and_index_id(&vg_item);
        } else if (cmd_fshowmem_args[DSS_ARG_IDX_5].inputed) {
            status = fshowmem_proc_by_fid_and_node_id(&vg_item, &show_param);
        } else if (cmd_fshowmem_args[DSS_ARG_IDX_7].inputed) {
            status = fshowmem_proc_by_path(&vg_item, &show_param);
        } else {
            status = CM_ERROR;
            DSS_PRINT_ERROR("none of struct_name and block_id and fid and path.\n");
        }
    } while (CM_FALSE);
    dss_free_vg_item_from_file(&vg_item);
    dss_free_buffer_pool_from_file();
    return status;
}

static dss_args_t cmd_rename_args[] = {
    {'o', "old_name", CM_TRUE, CM_TRUE, dss_cmd_check_device_path, cmd_check_convert_path, cmd_clean_check_convert, 0,
        NULL, NULL, 0},
    {'n', "new_name", CM_TRUE, CM_TRUE, dss_cmd_check_device_path, cmd_check_convert_path, cmd_clean_check_convert, 0,
        NULL, NULL, 0},
    {'U', "UDS", CM_FALSE, CM_TRUE, cmd_check_uds, cmd_check_convert_uds_home, cmd_clean_check_convert, 0, NULL, NULL,
        0},
};
static dss_args_set_t cmd_rename_args_set = {
    cmd_rename_args,
    sizeof(cmd_rename_args) / sizeof(dss_args_t),
    NULL,
};

static void rename_help(const char *prog_name, int print_flag)
{
    (void)printf("\nUsage:%s rename <-o old_name> <-n new_name> [-U UDS:socket_domain]\n", prog_name);
    if (g_run_interatively) {
        (void)printf("[client command] rename file\n");
    } else {
        (void)printf("[client command] rename file, all file name must begin with '+'\n");
    }
    if (print_flag == DSS_HELP_SIMPLE) {
        return;
    }
    (void)printf("-o/--old_name <old_name>, <required>, the old file name\n");
    (void)printf("-n/--new_name <new_name>, <required>, the new file name\n");
    help_param_uds();
}

static status_t rename_proc(void)
{
    const char *old_name = cmd_rename_args[DSS_ARG_IDX_0].input_args;
    if (cmd_rename_args[DSS_ARG_IDX_0].convert_result != NULL) {
        old_name = cmd_rename_args[DSS_ARG_IDX_0].convert_result;
    }

    const char *new_name = cmd_rename_args[DSS_ARG_IDX_1].input_args;
    if (cmd_rename_args[DSS_ARG_IDX_1].convert_result != NULL) {
        new_name = cmd_rename_args[DSS_ARG_IDX_1].convert_result;
    }

    status_t status = CM_SUCCESS;
    const char *input_args = cmd_rename_args[DSS_ARG_IDX_2].input_args;
    dss_conn_t *conn = dss_get_connection_opt(input_args);
    if (conn == NULL) {
        return CM_ERROR;
    }

    status = dss_rename_file_impl(conn, old_name, new_name);
    if (status != CM_SUCCESS) {
        DSS_PRINT_ERROR("Failed to rename file, old name is %s, new name is %s.\n", old_name, new_name);
    } else {
        DSS_PRINT_INF("Succeed to rename file, old name is %s, new name is %s.\n", old_name, new_name);
    }
    return status;
}

static dss_args_t cmd_du_args[] = {
    {'p', "path", CM_TRUE, CM_TRUE, dss_cmd_check_device_path, cmd_check_convert_path, cmd_clean_check_convert, 0, NULL,
        NULL, 0},
    {'f', "format", CM_FALSE, CM_TRUE, cmd_check_du_format, NULL, NULL, 0, NULL, NULL, 0},
    {'U', "UDS", CM_FALSE, CM_TRUE, cmd_check_uds, cmd_check_convert_uds_home, cmd_clean_check_convert, 0, NULL, NULL,
        0},
};
static dss_args_set_t cmd_du_args_set = {
    cmd_du_args,
    sizeof(cmd_du_args) / sizeof(dss_args_t),
    NULL,
};

static void du_help(const char *prog_name, int print_flag)
{
    if (g_run_interatively) {
        (void)printf("\nUsage:%s du [-p path] [-f format] [-U UDS:socket_domain]\n", prog_name);
    } else {
        (void)printf("\nUsage:%s du <-p path> [-f format] [-U UDS:socket_domain]\n", prog_name);
    }
    (void)printf("[client command] show disk usage of the file/dir with optional params\n");
    if (print_flag == DSS_HELP_SIMPLE) {
        return;
    }
    if (g_run_interatively) {
        (void)printf("-p/--path <path>, [optional], the file/dir need to show disk usage\n");
    } else {
        (void)printf("-p/--path <path>, <required>, the file/dir need to show disk usage\n");
    }
    (void)printf("-f/--format [format], [optional], the format to show, default value is Bs\n");
    (void)printf("support 3 types of format, do not need any separators between params\n");
    (void)printf("        [BKMGT] B: Byte, K: kB ,M: MB , G: GB, T: TB\n");
    (void)printf("        [sa] s: summarize, a: count all files, not just directories\n");
    (void)printf("        [S] S: for directories do not include size of subdirectories\n");
    help_param_uds();
}

static status_t du_proc(void)
{
    const char *path = cmd_du_args[DSS_ARG_IDX_0].input_args;
    if (cmd_du_args[DSS_ARG_IDX_0].convert_result != NULL) {
        path = cmd_du_args[DSS_ARG_IDX_0].convert_result;
    }
    if (path == NULL) {
        if (g_cur_path[0] == '\0') {
            cmd_print_no_path_err();
            return CM_ERROR;
        }
        path = g_cur_path;
    }

    const char *input_param = cmd_du_args[DSS_ARG_IDX_1].input_args;
    char path_buf[DSS_FILE_PATH_MAX_LENGTH];
    errno_t errcode = strcpy_s(path_buf, sizeof(path_buf), path);
    if (errcode != EOK) {
        DSS_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
        DSS_PRINT_ERROR("Failed to strcpy.\n");
        return CM_ERROR;
    }

    char params[DSS_DU_PARAM_LEN] = {0};
    status_t status = du_get_params(input_param, params, sizeof(params));
    if (status != CM_SUCCESS) {
        return status;
    }

    const char *input_args = cmd_du_args[DSS_ARG_IDX_2].input_args;
    dss_conn_t *conn = dss_get_connection_opt(input_args);
    if (conn == NULL) {
        return CM_ERROR;
    }

    status = du_traverse_path(path_buf, sizeof(path_buf), conn, params, sizeof(params));
    if (status != CM_SUCCESS) {
        DSS_PRINT_ERROR("Failed to traverse path %s.\n", path_buf);
    }
    return status;
}

static dss_args_t cmd_find_args[] = {
    {'p', "path", CM_TRUE, CM_TRUE, dss_cmd_check_device_path, cmd_check_convert_path, cmd_clean_check_convert, 0, NULL,
        NULL, 0},
    {'n', "name", CM_TRUE, CM_TRUE, dss_check_name, NULL, NULL, 0, NULL, NULL, 0},
    {'U', "UDS", CM_FALSE, CM_TRUE, cmd_check_uds, cmd_check_convert_uds_home, cmd_clean_check_convert, 0, NULL, NULL,
        0},
};
static dss_args_set_t cmd_find_args_set = {
    cmd_find_args,
    sizeof(cmd_find_args) / sizeof(dss_args_t),
    NULL,
};

static void find_help(const char *prog_name, int print_flag)
{
    if (g_run_interatively) {
        (void)printf("\nUsage:%s find <-n name> [-p path] [-U UDS:socket_domain]\n", prog_name);
    } else {
        (void)printf("\nUsage:%s find <-p path> <-n name> [-U UDS:socket_domain]\n", prog_name);
    }
    (void)printf("[client command]find files by name from path recursively\n");
    if (print_flag == DSS_HELP_SIMPLE) {
        return;
    }
    if (g_run_interatively) {
        (void)printf("-p/--path <path>, [optional], the path to find from\n");
    } else {
        (void)printf("-p/--path <path>, <required>, the path to find from\n");
    }
    (void)printf("-n/--name <name>, <required>, the name to find, support unix style wildcards "
                 "(man 7 glob for detail)\n");
    help_param_uds();
}

static status_t find_proc(void)
{
    char *path = cmd_find_args[DSS_ARG_IDX_0].input_args;
    if (cmd_find_args[DSS_ARG_IDX_0].convert_result != NULL) {
        path = cmd_find_args[DSS_ARG_IDX_0].convert_result;
    }
    if (path == NULL) {
        if (g_cur_path[0] == '\0') {
            cmd_print_no_path_err();
            return CM_ERROR;
        }
        path = g_cur_path;
    }

    char *name = cmd_find_args[DSS_ARG_IDX_1].input_args;
    char path_buf[DSS_FILE_PATH_MAX_LENGTH];
    char name_buf[DSS_FILE_NAME_BUFFER_SIZE];

    errno_t errcode = strcpy_s(path_buf, sizeof(path_buf), path);
    if (errcode != EOK) {
        DSS_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
        DSS_PRINT_ERROR("Failed to strcpy.\n");
        return CM_ERROR;
    }

    errcode = strcpy_s(name_buf, sizeof(name_buf), name);
    if (errcode != EOK) {
        DSS_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
        DSS_PRINT_ERROR("Failed to strcpy.\n");
        return CM_ERROR;
    }

    const char *input_args = cmd_find_args[DSS_ARG_IDX_2].input_args;
    dss_conn_t *conn = dss_get_connection_opt(input_args);
    if (conn == NULL) {
        DSS_PRINT_ERROR("Failed to get uds connection.\n");
        return CM_ERROR;
    }
    status_t status = find_traverse_path(conn, path_buf, sizeof(path_buf), name_buf, sizeof(name_buf));
    if (status != CM_SUCCESS) {
        DSS_PRINT_ERROR("Failed to find traverse path %s.\n", path_buf);
    }
    return status;
}

static dss_args_t cmd_ln_args[] = {
    {'s', "src_path", CM_TRUE, CM_TRUE, dss_cmd_check_device_path, cmd_check_convert_path, cmd_clean_check_convert, 0,
        NULL, NULL, 0},
    {'t', "target_path", CM_TRUE, CM_TRUE, dss_cmd_check_device_path, cmd_check_convert_path, cmd_clean_check_convert,
        0, NULL, NULL, 0},
    {'U', "UDS", CM_FALSE, CM_TRUE, cmd_check_uds, cmd_check_convert_uds_home, cmd_clean_check_convert, 0, NULL, NULL,
        0},
};
static dss_args_set_t cmd_ln_args_set = {
    cmd_ln_args,
    sizeof(cmd_ln_args) / sizeof(dss_args_t),
    NULL,
};

static void ln_help(const char *prog_name, int print_flag)
{
    (void)printf("\nUsage:%s ln <-s src_path> <-t target_path> [-U UDS:socket_domain]\n", prog_name);
    (void)printf("[client command]make links between files\n");
    if (print_flag == DSS_HELP_SIMPLE) {
        return;
    }
    (void)printf("-s/--src_path <src_path>, <required>, the source path to link\n");
    (void)printf("-t/--target_path <target_path>, <required>, the target path to link\n");
    help_param_uds();
}

static status_t ln_proc(void)
{
    char *oldpath = cmd_ln_args[DSS_ARG_IDX_0].input_args;
    if (cmd_ln_args[DSS_ARG_IDX_0].convert_result != NULL) {
        oldpath = cmd_ln_args[DSS_ARG_IDX_0].convert_result;
    }
    char *newpath = cmd_ln_args[DSS_ARG_IDX_1].input_args;
    if (cmd_ln_args[DSS_ARG_IDX_1].convert_result != NULL) {
        newpath = cmd_ln_args[DSS_ARG_IDX_1].convert_result;
    }

    status_t status = CM_SUCCESS;
    const char *input_args = cmd_ln_args[DSS_ARG_IDX_2].input_args;
    dss_conn_t *conn = dss_get_connection_opt(input_args);
    if (conn == NULL) {
        return CM_ERROR;
    }

    status = dss_symlink_impl(conn, oldpath, newpath);
    if (status == CM_SUCCESS) {
        DSS_PRINT_INF("Success to link %s to %s.\n", newpath, oldpath);
    } else {
        DSS_PRINT_ERROR("Failed to link %s to %s.\n", newpath, oldpath);
    }
    return status;
}

static dss_args_t cmd_readlink_args[] = {
    {'p', "path", CM_TRUE, CM_TRUE, dss_cmd_check_device_path, cmd_check_convert_path, cmd_clean_check_convert, 0, NULL,
        NULL, 0},
    {'U', "UDS", CM_FALSE, CM_TRUE, cmd_check_uds, cmd_check_convert_uds_home, cmd_clean_check_convert, 0, NULL, NULL,
        0},
};
static dss_args_set_t cmd_readlink_args_set = {
    cmd_readlink_args,
    sizeof(cmd_readlink_args) / sizeof(dss_args_t),
    NULL,
};

static void readlink_help(const char *prog_name, int print_flag)
{
    (void)printf("\nUsage:%s readlink <-p path> [-U UDS:socket_domain]\n", prog_name);
    (void)printf("[client command]read link path\n");
    if (print_flag == DSS_HELP_SIMPLE) {
        return;
    }
    (void)printf("-p/--path <path>, <required>, the link path to read\n");
    help_param_uds();
}

static status_t readlink_proc(void)
{
    char *link_path = cmd_readlink_args[DSS_ARG_IDX_0].input_args;
    if (cmd_readlink_args[DSS_ARG_IDX_0].convert_result != NULL) {
        link_path = cmd_readlink_args[DSS_ARG_IDX_0].convert_result;
    }

    const char *input_args = cmd_readlink_args[DSS_ARG_IDX_1].input_args;
    dss_conn_t *conn = dss_get_connection_opt(input_args);
    if (conn == NULL) {
        return CM_ERROR;
    }

    bool32 is_link = false;
    status_t status = dss_islink_impl(conn, link_path, &is_link);
    if (status != CM_SUCCESS) {
        DSS_PRINT_ERROR("Failed to confirm that the path %s is a soft link.\n", link_path);
        return CM_ERROR;
    }
    if (status == CM_SUCCESS && !is_link) {
        DSS_PRINT_ERROR("The path %s does not exist or is not a soft link.\n", link_path);
        return CM_ERROR;
    }

    char path_convert[DSS_FILE_PATH_MAX_LENGTH] = {0};
    status = dss_readlink_impl(conn, link_path, (char *)path_convert, sizeof(path_convert));
    if (status == CM_SUCCESS) {
        DSS_PRINT_INF("link: %s link to: %s.\n", link_path, path_convert);
    } else {
        DSS_PRINT_ERROR("Failed to read link %s.\n", link_path);
    }
    return status;
}

static dss_args_t cmd_unlink_args[] = {
    {'p', "path", CM_TRUE, CM_TRUE, dss_cmd_check_device_path, cmd_check_convert_path, cmd_clean_check_convert, 0, NULL,
        NULL, 0},
    {'U', "UDS", CM_FALSE, CM_TRUE, cmd_check_uds, cmd_check_convert_uds_home, cmd_clean_check_convert, 0, NULL, NULL,
        0},
};
static dss_args_set_t cmd_unlink_args_set = {
    cmd_unlink_args,
    sizeof(cmd_unlink_args) / sizeof(dss_args_t),
    NULL,
};

static void unlink_help(const char *prog_name, int print_flag)
{
    (void)printf("\nUsage:%s unlink <-p path> [-U UDS:socket_domain]\n", prog_name);
    (void)printf("[client command] unlink path\n");
    if (print_flag == DSS_HELP_SIMPLE) {
        return;
    }
    (void)printf("-p/--path <path>, <required>, the link path to unlink\n");
    help_param_uds();
}

static status_t unlink_proc(void)
{
    char *link = cmd_unlink_args[DSS_ARG_IDX_0].input_args;
    if (cmd_unlink_args[DSS_ARG_IDX_0].convert_result != NULL) {
        link = cmd_unlink_args[DSS_ARG_IDX_0].convert_result;
    }

    const char *input_args = cmd_unlink_args[DSS_ARG_IDX_1].input_args;
    dss_conn_t *conn = dss_get_connection_opt(input_args);
    if (conn == NULL) {
        return CM_ERROR;
    }

    status_t status = dss_unlink_impl(conn, link);
    if (status != CM_SUCCESS) {
        DSS_PRINT_ERROR("Failed to unlink %s.\n", link);
    } else {
        DSS_PRINT_INF("Succeed to unlink %s.\n", link);
    }
    return status;
}

static dss_args_set_t cmd_encrypt_args_set = {
    NULL,
    0,
    NULL,
};

static void encrypt_help(const char *prog_name, int print_flag)
{
    (void)printf("\nUsage:%s encrypt\n", prog_name);
    (void)printf("[client command] password encrypt\n");
}

static status_t dss_save_random_file(const uchar *value, int32 value_len)
{
    char file_name[CM_FILE_NAME_BUFFER_SIZE];
    char dir_name[CM_FILE_NAME_BUFFER_SIZE];
    int32 handle;
    PRTS_RETURN_IFERR(snprintf_s(
        dir_name, CM_FILE_NAME_BUFFER_SIZE, CM_FILE_NAME_BUFFER_SIZE - 1, "%s/dss_protect", g_inst_cfg->home));
    PRTS_RETURN_IFERR(snprintf_s(file_name, CM_FILE_NAME_BUFFER_SIZE, CM_FILE_NAME_BUFFER_SIZE - 1, "%s/dss_protect/%s",
        g_inst_cfg->home, DSS_FKEY_FILENAME));
    if (!cm_dir_exist(dir_name)) {
        DSS_RETURN_IF_ERROR(cm_create_dir(dir_name));
    }
    if (access(file_name, R_OK | F_OK) == 0) {
        (void)chmod(file_name, S_IRUSR | S_IWUSR);
        DSS_RETURN_IF_ERROR(cm_overwrite_file(file_name));
        DSS_RETURN_IF_ERROR(cm_remove_file(file_name));
    }
    DSS_RETURN_IF_ERROR(
        cm_open_file_ex(file_name, O_SYNC | O_CREAT | O_RDWR | O_TRUNC | O_BINARY, S_IRUSR | S_IWUSR, &handle));
    status_t ret = cm_write_file(handle, value, value_len);
    cm_close_file(handle);
    return ret;
}

static status_t encrypt_proc(void)
{
    status_t status;
    char plain[CM_PASSWD_MAX_LEN + 1] = {0};
    status = dss_catch_input_text(plain, CM_PASSWD_MAX_LEN + 1);
    if (status != CM_SUCCESS) {
        (void)(memset_s(plain, CM_PASSWD_MAX_LEN + 1, 0, CM_PASSWD_MAX_LEN + 1));
        DSS_PRINT_ERROR("Failed to encrypt password when catch input.\n");
        return CM_ERROR;
    }
    cipher_t cipher;
    status = cm_encrypt_pwd((uchar *)plain, (uint32)strlen(plain), &cipher);
    if (status != CM_SUCCESS) {
        (void)(memset_s(plain, CM_PASSWD_MAX_LEN + 1, 0, CM_PASSWD_MAX_LEN + 1));
        DSS_PRINT_ERROR("Failed to encrypt password.\n");
        return CM_ERROR;
    }
    (void)(memset_s(plain, CM_PASSWD_MAX_LEN + 1, 0, CM_PASSWD_MAX_LEN + 1));
    status = dss_save_random_file(cipher.rand, RANDOM_LEN + 1);
    if (status != CM_SUCCESS) {
        DSS_PRINT_ERROR("Failed to save random component.\n");
        return CM_ERROR;
    }
    (void)(memset_s(cipher.rand, RANDOM_LEN + 1, 0, RANDOM_LEN + 1));
    char buf[CM_MAX_SSL_CIPHER_LEN] = {0};
    uint32_t buf_len = CM_MAX_SSL_CIPHER_LEN;
    status = cm_base64_encode((uchar *)&cipher, (uint32)sizeof(cipher_t), buf, &buf_len);
    if (status != CM_SUCCESS) {
        DSS_PRINT_ERROR("Failed to encrypt password when encode.\n");
        return CM_ERROR;
    }
    (void)printf("Cipher: \t\t%s\n", buf);
    return CM_SUCCESS;
}

static dss_args_t cmd_setcfg_args[] = {
    {'n', "name", CM_TRUE, CM_TRUE, cmd_check_cfg_name, NULL, NULL, 0, NULL, NULL, 0},
    {'v', "value", CM_TRUE, CM_TRUE, cmd_check_cfg_value, NULL, NULL, 0, NULL, NULL, 0},
    {'s', "scope", CM_FALSE, CM_TRUE, cmd_check_cfg_scope, NULL, NULL, 0, NULL, NULL, 0},
    {'U', "UDS", CM_FALSE, CM_TRUE, cmd_check_uds, cmd_check_convert_uds_home, cmd_clean_check_convert, 0, NULL, NULL,
        0},
};
static dss_args_set_t cmd_setcfg_args_set = {
    cmd_setcfg_args,
    sizeof(cmd_setcfg_args) / sizeof(dss_args_t),
    NULL,
};

static void setcfg_help(const char *prog_name, int print_flag)
{
    (void)printf("\nUsage:%s setcfg <-n name> <-v value> [-s scope] [-U UDS:socket_domain]\n", prog_name);
    (void)printf("[client command] set config value by name\n");
    if (print_flag == DSS_HELP_SIMPLE) {
        return;
    }
    (void)printf("-n/--name <name>, <required>, the config name to set\n");
    (void)printf("-v/--value <value>, <required>, the value of the config name to set\n");
    (void)printf("-s/--scope <scope>, [optional], the scope to save the config\n");
    (void)printf("scope optional values: [memory | pfile | both]. default value is both\n"
                 "Memory indicates that the modification is made in memory and takes effect immediately;\n"
                 "Pfile indicates that the modification is performed in the pfile. \n"
                 "The database must be restarted for the modification to take effect.\n");
    help_param_uds();
}

static status_t setcfg_proc(void)
{
    char *name = cmd_setcfg_args[DSS_ARG_IDX_0].input_args;
    char *value = cmd_setcfg_args[DSS_ARG_IDX_1].input_args;
    char *scope =
        cmd_setcfg_args[DSS_ARG_IDX_2].input_args != NULL ? cmd_setcfg_args[DSS_ARG_IDX_2].input_args : "both";

    const char *input_args = cmd_setcfg_args[DSS_ARG_IDX_3].input_args;
    dss_conn_t *conn = dss_get_connection_opt(input_args);
    if (conn == NULL) {
        return CM_ERROR;
    }

    status_t status = dss_setcfg_impl(conn, name, value, scope);
    if (status != CM_SUCCESS) {
        DSS_PRINT_ERROR("Failed to set cfg, name is %s, value is %s.\n", name, value);
    } else {
        DSS_PRINT_INF("Succeed to set cfg, name is %s, value is %s.\n", name, value);
    }
    return status;
}

static dss_args_t cmd_getcfg_args[] = {
    {'n', "name", CM_TRUE, CM_TRUE, cmd_check_cfg_name, NULL, NULL, 0, NULL, NULL, 0},
    {'U', "UDS", CM_FALSE, CM_TRUE, cmd_check_uds, cmd_check_convert_uds_home, cmd_clean_check_convert, 0, NULL, NULL,
        0},
};
static dss_args_set_t cmd_getcfg_args_set = {
    cmd_getcfg_args,
    sizeof(cmd_getcfg_args) / sizeof(dss_args_t),
    NULL,
};

static void getcfg_help(const char *prog_name, int print_flag)
{
    (void)printf("\nUsage:%s getcfg <-n name> [-U UDS:socket_domain]\n", prog_name);
    (void)printf("[client command] get config value by name\n");
    if (print_flag == DSS_HELP_SIMPLE) {
        return;
    }
    (void)printf("-n/--name <name>, <required>, the config name to set\n");
    help_param_uds();
}

static status_t getcfg_proc(void)
{
    char *name = cmd_getcfg_args[DSS_ARG_IDX_0].input_args;
    const char *input_args = cmd_touch_args[DSS_CMD_TOUCH_ARGS_UDS].input_args;
    dss_conn_t *conn = dss_get_connection_opt(input_args);
    if (conn == NULL) {
        return CM_ERROR;
    }
    char value[DSS_PARAM_BUFFER_SIZE] = {0};
    status_t status = dss_getcfg_impl(conn, name, value, DSS_PARAM_BUFFER_SIZE);
    if (status != CM_SUCCESS) {
        DSS_PRINT_ERROR("Failed to get cfg, name is %s, value is %s.\n", name, (strlen(value) == 0) ? NULL : value);
    } else {
        DSS_PRINT_INF("Succeed to get cfg, name is %s, value is %s.\n", name, (strlen(value) == 0) ? NULL : value);
    }
    return status;
}

static dss_args_t cmd_getstatus_args[] = {
    {'U', "UDS", CM_FALSE, CM_TRUE, cmd_check_uds, cmd_check_convert_uds_home, cmd_clean_check_convert, 0, NULL, NULL,
        0},
};

static dss_args_set_t cmd_getstatus_args_set = {
    cmd_getstatus_args,
    sizeof(cmd_getstatus_args) / sizeof(dss_args_t),
    NULL,
};

static void getstatus_help(const char *prog_name, int print_flag)
{
    (void)printf("\nUsage:%s getstatus [-U UDS:socket_domain]\n", prog_name);
    (void)printf("[client command] get dss server status\n");
    if (print_flag == DSS_HELP_SIMPLE) {
        return;
    }
    help_param_uds();
}

static status_t getstatus_proc(void)
{
    const char *input_args = cmd_getstatus_args[DSS_ARG_IDX_0].input_args;
    dss_conn_t *conn = dss_get_connection_opt(input_args);
    if (conn == NULL) {
        return CM_ERROR;
    }

    dss_server_status_t dss_status;
    status_t status = dss_get_inst_status_on_server(conn, &dss_status);
    if (status != CM_SUCCESS) {
        DSS_PRINT_ERROR("Failed to get server status.\n");
    } else {
        DSS_PRINT_INF("Server status of instance %u is %s and %s.\nMaster id is %u .\nDSS_MAINTAIN is %s.\n",
            dss_status.local_instance_id, dss_status.instance_status, dss_status.server_status, dss_status.master_id,
            (dss_status.is_maintain ? "TRUE" : "FALSE"));
    }
    return status;
}

static dss_args_t cmd_stopdss_args[] = {
    {'U', "UDS", CM_FALSE, CM_TRUE, cmd_check_uds, cmd_check_convert_uds_home, cmd_clean_check_convert, 0, NULL, NULL,
        0},
};
static dss_args_set_t cmd_stopdss_args_set = {
    cmd_stopdss_args,
    sizeof(cmd_stopdss_args) / sizeof(dss_args_t),
    NULL,
};

static void stopdss_help(const char *prog_name, int print_flag)
{
    (void)printf("\nUsage:%s stopdss [-U UDS:socket_domain]\n", prog_name);
    (void)printf("[client command] stop dss server\n");
    if (print_flag == DSS_HELP_SIMPLE) {
        return;
    }
    help_param_uds();
}

static status_t stopdss_proc(void)
{
    const char *input_args = cmd_stopdss_args[DSS_ARG_IDX_0].input_args;
    dss_conn_t *conn = dss_get_connection_opt(input_args);
    if (conn == NULL) {
        return CM_ERROR;
    }

    status_t status = dss_stop_server_impl(conn);
    if (status != CM_SUCCESS) {
        DSS_PRINT_ERROR("Failed to stop server.\n");
    } else {
        DSS_PRINT_INF("Succeed to stop server.\n");
    }
    dss_conn_opt_exit();
    return status;
}

static const char command_injection_check_list[] = {
    '|', ';', '&', '$', '<', '>', '`', '\\', '\'', '\"', '{', '}', '(', ')', '[', ']', '~', '*', '?', ' ', '!', '\n'};

static status_t dss_check_command_injection(const char *param)
{
    if (param == NULL) {
        DSS_THROW_ERROR(ERR_DSS_FILE_PATH_ILL, "[null]", "param cannot be a null string.");
        return CM_ERROR;
    }
    uint64 len = strlen(param);
    for (uint64 i = 0; i < len; i++) {
        for (uint32 j = 0; j < CMD_COMMAND_INJECTION_COUNT; j++) {
            if (param[i] == command_injection_check_list[j]) {
                DSS_PRINT_ERROR(
                    "Failed to check command injection, %s has %c.\n", param, command_injection_check_list[j]);
                return CM_ERROR;
            }
        }
    }
    return CM_SUCCESS;
}

static status_t cmd_check_user_or_group_name(const char *param)
{
    status_t status = dss_check_command_injection(param);
    if (status != CM_SUCCESS) {
        DSS_PRINT_ERROR("Failed to check name %s.\n", param);
        return CM_ERROR;
    }
    status = dss_check_name(param);
    if (status != CM_SUCCESS) {
        DSS_PRINT_ERROR("Failed to check name %s.\n", param);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static status_t cmd_check_scandisk_path(const char *param)
{
    status_t status = dss_check_command_injection(param);
    if (status != CM_SUCCESS) {
        DSS_PRINT_ERROR("Failed to check path %s.\n", param);
        return CM_ERROR;
    }
    status = dss_check_volume_path(param);
    if (status != CM_SUCCESS) {
        DSS_PRINT_ERROR("Failed to check name %s.\n", param);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static status_t cmd_check_file_type(const char *type)
{
    if (strcmp(type, "block") == 0) {
        return CM_SUCCESS;
    }
    DSS_PRINT_ERROR("Failed to check file type, only support block type.\n");
    return CM_ERROR;
}

static dss_args_t cmd_scandisk_args[] = {
    {'t', "type", CM_TRUE, CM_TRUE, cmd_check_file_type, NULL, NULL, 0, NULL, NULL, 0},
    {'p', "path", CM_TRUE, CM_TRUE, cmd_check_scandisk_path, NULL, NULL, 0, NULL, NULL, 0},
    {'u', "user_name", CM_TRUE, CM_TRUE, cmd_check_user_or_group_name, NULL, NULL, 0, NULL, NULL, 0},
    {'g', "group_name", CM_TRUE, CM_TRUE, cmd_check_user_or_group_name, NULL, NULL, 0, NULL, NULL, 0},
};

static dss_args_set_t cmd_scandisk_args_set = {
    cmd_scandisk_args,
    sizeof(cmd_scandisk_args) / sizeof(dss_args_t),
    NULL,
};

static void scandisk_help(const char *prog_name, int print_flag)
{
    (void)printf("\nUsage:%s scandisk <-t type> <-p path> <-u user_name> <-g group_name>\n", prog_name);
    (void)printf("[client command] Scan disk to rebuild soft link\n");
    if (print_flag == DSS_HELP_SIMPLE) {
        return;
    }
    (void)printf("-t/--type <type>, <required>, file type\n");
    (void)printf("-p/--path <path>, <required>, find disk path\n");
    (void)printf("-u/--user_name <user_name>, <required>, user name\n");
    (void)printf("-g/--group_name <group_name>, <required>, group name\n");
}

static status_t scandisk_proc(void)
{
#ifdef WIN32
    DSS_PRINT_ERROR("Windows does not support scan disk.\n");
    return CM_ERROR;
#else
    char *path = cmd_scandisk_args[DSS_ARG_IDX_1].input_args;
    char *user_name = cmd_scandisk_args[DSS_ARG_IDX_2].input_args;
    char *group_name = cmd_scandisk_args[DSS_ARG_IDX_3].input_args;

    char cmd[DSS_PARAM_BUFFER_SIZE] = {0};
    int ret = snprintf_s(cmd, DSS_PARAM_BUFFER_SIZE, DSS_PARAM_BUFFER_SIZE - 1,
        "ls -l %s* 2>/dev/null |grep ' %s \\+%s '|grep '^b'| awk -F\" %s\" '{print \"%s\" $2}' | awk '{print $1}'",
        path, user_name, group_name, path, path);
    if (ret < 0) {
        DSS_PRINT_ERROR("snprintf_s query cmd failed.\n");
        return CM_ERROR;
    }
    char result[DSS_PARAM_BUFFER_SIZE] = {0};
    FILE *ptr = popen(cmd, "r");
    if (ptr == NULL) {
        DSS_PRINT_ERROR("Failed to scan disk when popen.\n");
        return CM_ERROR;
    }
    int32 handle = -1;
    while (fgets(result, DSS_PARAM_BUFFER_SIZE, ptr) != NULL) {
        result[strlen(result) - 1] = '\0';
        handle = open(result, O_RDWR, 0);
        if (handle == -1) {
            (void)pclose(ptr);
            DSS_THROW_ERROR(ERR_DSS_VOLUME_OPEN, result, cm_get_os_error());
            DSS_PRINT_ERROR("Failed to scan disk when open handle.\n");
            return CM_ERROR;
        }
        ret = close(handle);
        if (ret != 0) {
            (void)pclose(ptr);
            DSS_PRINT_ERROR("Failed to scan disk when close handle.\n");
            return CM_ERROR;
        }
    }
    ret = pclose(ptr);
    if (ret != 0) {
        DSS_PRINT_ERROR("Failed to scan disk when pclose.\n");
        return CM_ERROR;
    }
    DSS_PRINT_INF("Succeed to scan disk.\n");
    return CM_SUCCESS;
#endif
}

static dss_args_t cmd_clean_vglock_args[] = {
    {'D', "DSS_HOME", CM_FALSE, CM_TRUE, cmd_check_dss_home, cmd_check_convert_dss_home, cmd_clean_check_convert, 0,
        NULL, NULL, 0},
};

static dss_args_set_t cmd_clean_vglock_args_set = {
    cmd_clean_vglock_args,
    sizeof(cmd_clean_vglock_args) / sizeof(dss_args_t),
    NULL,
};

static void clean_vglock_help(const char *prog_name, int print_flag)
{
    (void)printf("\nUsage:%s clean_vglock [-D DSS_HOME]\n", prog_name);
    (void)printf("[manage command] clean vg lock\n");
    if (print_flag == DSS_HELP_SIMPLE) {
        return;
    }
    help_param_dsshome();
}

static status_t clean_vglock_proc(void)
{
    char *home = cmd_clean_vglock_args[DSS_ARG_IDX_0].input_args;
    status_t status = dss_clean_vg_lock(home, DSS_MAX_INST_ID);
    if (status != CM_SUCCESS) {
        DSS_PRINT_ERROR("Failed to clean vg lock.\n");
    } else {
        DSS_PRINT_INF("Succeed to clean vg lock.\n");
    }
    return status;
}

static dss_args_t cmd_repl_args[] = {
    {'g', "vg_name", CM_TRUE, CM_TRUE, dss_check_name, NULL, NULL, 0, NULL, NULL, 0},
    {'o', "old_vol", CM_TRUE, CM_TRUE, dss_check_volume_path, NULL, NULL, 0, NULL, NULL, 0},
    {'n', "new_vol", CM_TRUE, CM_TRUE, dss_check_volume_path, NULL, NULL, 0, NULL, NULL, 0},
    {'f', "force", CM_FALSE, CM_FALSE, NULL, NULL, NULL, 0, NULL, NULL, 0},
    {'D', "DSS_HOME", CM_FALSE, CM_TRUE, cmd_check_dss_home, cmd_check_convert_dss_home, cmd_clean_check_convert, 0,
        NULL, NULL, 0},
};
static dss_args_set_t cmd_repl_args_set = {
    cmd_repl_args,
    sizeof(cmd_repl_args) / sizeof(dss_args_t),
    NULL,
};

static void repl_help(const char *prog_name, int print_flag)
{
    (void)printf("\nUsage:%s repl <-g vg_name> <-o old_vol> <-n new_vol> [-f] [-D DSS_HOME]\n", prog_name);
    (void)printf("[client command]replace old volume to new volume in volume group\n");
    if (print_flag == DSS_HELP_SIMPLE) {
        return;
    }
    (void)printf("-g/--vg_name <vg_name>, <required>, the volume group name need to replace volume\n");
    (void)printf("-o/--old_vol <old_vol>, <required>, old volume\n");
    (void)printf("-n/--new_vol <new_vol>, <required>, new volume\n");
    (void)printf("-f/--force, <required>, replace volume offline forcibly\n");
    help_param_dsshome();
}

static status_t repl_proc(void)
{
    const char *vg_name = cmd_repl_args[DSS_ARG_IDX_0].input_args;
    const char *old_vol = cmd_repl_args[DSS_ARG_IDX_1].input_args;
    const char *new_vol = cmd_repl_args[DSS_ARG_IDX_2].input_args;
    bool32 force = cmd_repl_args[DSS_ARG_IDX_3].inputed ? CM_TRUE : CM_FALSE;
    const char *home = cmd_repl_args[DSS_ARG_IDX_4].input_args;

    if (strcmp(old_vol, new_vol) == 0) {
        DSS_PRINT_ERROR("The old_vol %s is same as new_vol %s.\n", old_vol, new_vol);
        return CM_ERROR;
    }

    if (!force) {
        DSS_PRINT_ERROR("Not support to replace volume online, old_vol is %s, new_vol is %s.\n", old_vol, new_vol);
        return CM_ERROR;
    }
    status_t status = dss_modify_volume_offline(home, vg_name, old_vol, new_vol, VOLUME_MODIFY_REPLACE);
    if (status != CM_SUCCESS) {
        DSS_PRINT_ERROR("Failed to replace volume offline, old_vol is %s, new_vol is %s.\n", old_vol, new_vol);
    } else {
        DSS_PRINT_INF("Succeed to replace volume offline, old_vol is %s, new_vol is %s.\n", old_vol, new_vol);
    }
    return status;
}

static dss_args_t cmd_rollback_args[] = {
    {'g', "vg_name", CM_TRUE, CM_TRUE, dss_check_name, NULL, NULL, 0, NULL, NULL, 0},
    {'f', "force", CM_FALSE, CM_FALSE, NULL, NULL, NULL, 0, NULL, NULL, 0},
    {'D', "DSS_HOME", CM_FALSE, CM_TRUE, cmd_check_dss_home, cmd_check_convert_dss_home, cmd_clean_check_convert, 0,
        NULL, NULL, 0},
};
static dss_args_set_t cmd_rollback_args_set = {
    cmd_rollback_args,
    sizeof(cmd_rollback_args) / sizeof(dss_args_t),
    NULL,
};

static void rollback_help(const char *prog_name, int print_flag)
{
    (void)printf("\nUsage:%s rollback <-g vg_name> [-f] [-D DSS_HOME]\n", prog_name);
    (void)printf("[client command]rollback volume group\n");
    if (print_flag == DSS_HELP_SIMPLE) {
        return;
    }
    (void)printf("-g/--vg_name <vg_name>, <required>, the volume group name need to rollback\n");
    (void)printf("-f/--force, <required>, rollback volume group offline forcibly\n");
    help_param_dsshome();
}

static status_t rollback_proc(void)
{
    const char *vg_name = cmd_rollback_args[DSS_ARG_IDX_0].input_args;
    bool32 force = cmd_rollback_args[DSS_ARG_IDX_1].inputed ? CM_TRUE : CM_FALSE;
    const char *home = cmd_rollback_args[DSS_ARG_IDX_2].input_args;

    if (!force) {
        DSS_PRINT_ERROR("Not support to rollback volume group online, vg_name is %s.\n", vg_name);
        return CM_ERROR;
    }
    status_t status = dss_modify_volume_offline(home, vg_name, NULL, NULL, VOLUME_MODIFY_ROLLBACK);
    if (status != CM_SUCCESS) {
        DSS_PRINT_ERROR("Failed to rollback volume group offline, vg_name is %s.\n", vg_name);
    } else {
        DSS_PRINT_INF("Succeed to rollback volume group offline, vg_name is %s.\n", vg_name);
    }
    return status;
}

#define DSS_CMD_TRUNCATE_ARGS_PATH 0
#define DSS_CMD_TRUNCATE_ARGS_LENGTH 1
#define DSS_CMD_TRUNCATE_ARGS_UDS 2

static dss_args_t cmd_truncate_args[] = {
    {'p', "path", CM_TRUE, CM_TRUE, dss_cmd_check_device_path, NULL, NULL, 0, NULL, NULL, 0},
    {'l', "length", CM_TRUE, CM_TRUE, cmd_check_length, NULL, NULL, 0, NULL, NULL, 0},
    {'U', "UDS", CM_FALSE, CM_TRUE, cmd_check_uds, cmd_check_convert_uds_home, cmd_clean_check_convert, 0, NULL, NULL,
        0},
};

static dss_args_set_t cmd_truncate_args_set = {
    cmd_truncate_args,
    sizeof(cmd_truncate_args) / sizeof(dss_args_t),
    NULL,
};

static void truncate_help(const char *prog_name, int print_flag)
{
    (void)printf("\nUsage:%s truncate <-p path> <-l length> [-U UDS:socket_domain]\n", prog_name);
    (void)printf("[client command]truncate file to length\n");
    if (print_flag == DSS_HELP_SIMPLE) {
        return;
    }
    if (g_run_interatively) {
        (void)printf("-p/--path <path>, <required>, file need to truncate\n");
    } else {
        (void)printf("-p/--path <path>, <required>, file need to truncate, path must begin with '+'\n");
    }
    (void)printf("-l/--length <length>, <required>, length need to truncate\n");
    help_param_uds();
}

static status_t truncate_proc(void)
{
    const char *path = cmd_truncate_args[DSS_CMD_TRUNCATE_ARGS_PATH].input_args;
    if (cmd_truncate_args[DSS_CMD_TRUNCATE_ARGS_PATH].convert_result != NULL) {
        path = cmd_truncate_args[DSS_CMD_TRUNCATE_ARGS_PATH].convert_result;
    }

    int64 length;
    status_t status = cm_str2bigint(cmd_truncate_args[DSS_CMD_TRUNCATE_ARGS_LENGTH].input_args, &length);
    if (status != CM_SUCCESS) {
        DSS_PRINT_ERROR(
            "length:%s is not a valid int64.\n", cmd_truncate_args[DSS_CMD_TRUNCATE_ARGS_LENGTH].input_args);
        return status;
    }

    const char *input_args = cmd_truncate_args[DSS_CMD_TRUNCATE_ARGS_UDS].input_args;
    dss_conn_t *conn = dss_get_connection_opt(input_args);
    if (conn == NULL) {
        return CM_ERROR;
    }

    int handle;
    status = (status_t)dss_open_file_impl(conn, path, O_RDWR, &handle);
    if (status != CM_SUCCESS) {
        DSS_PRINT_ERROR("Failed to truncate file, name is %s.\n", path);
        return status;
    }

    status = (status_t)dss_truncate_impl(conn, handle, length);
    if (status != CM_SUCCESS) {
        DSS_PRINT_ERROR("Failed to truncate file, name is %s.\n", path);
        (void)dss_close_file_impl(conn, handle);
        return status;
    }
    DSS_PRINT_INF("Success to truncate file, name is %s.\n", path);

    (void)dss_close_file_impl(conn, handle);
    return status;
}

static dss_args_t cmd_disable_grab_lock_args[] = {
    {'U', "UDS", CM_FALSE, CM_TRUE, cmd_check_uds, cmd_check_convert_uds_home, cmd_clean_check_convert, 0, NULL, NULL,
        0},
};

static dss_args_set_t cmd_disable_grab_lock_args_set = {
    cmd_disable_grab_lock_args,
    sizeof(cmd_disable_grab_lock_args) / sizeof(dss_args_t),
    NULL,
};

static void disable_grab_lock_help(const char *prog_name, int print_flag)
{
    (void)printf("\nUsage:%s dis_grab_lock [-U UDS:socket_domain]\n", prog_name);
    (void)printf(
        "[client command] if the dssserver is primary, will release cm lock to be standby and not to grab lock\n");
    if (print_flag == DSS_HELP_SIMPLE) {
        return;
    }
    help_param_uds();
}

static status_t disable_grab_lock_proc(void)
{
    const char *input_args = cmd_disable_grab_lock_args[DSS_ARG_IDX_0].input_args;
    dss_conn_t *conn = dss_get_connection_opt(input_args);
    if (conn == NULL) {
        return CM_ERROR;
    }

    status_t status = dss_disable_grab_lock_on_server(conn);
    if (status != CM_SUCCESS) {
        DSS_PRINT_ERROR("Failed to disable grab lock.\n");
    } else {
        DSS_PRINT_INF("Succeed to disable grab lock.\n");
    }
    return status;
}

static dss_args_t cmd_enable_grab_lock_args[] = {
    {'U', "UDS", CM_FALSE, CM_TRUE, cmd_check_uds, cmd_check_convert_uds_home, cmd_clean_check_convert, 0, NULL, NULL,
        0},
};

static dss_args_set_t cmd_enable_grab_lock_args_set = {
    cmd_enable_grab_lock_args,
    sizeof(cmd_enable_grab_lock_args) / sizeof(dss_args_t),
    NULL,
};

static void enable_grab_lock_help(const char *prog_name, int print_flag)
{
    (void)printf("\nUsage:%s en_grab_lock [-U UDS:socket_domain]\n", prog_name);
    (void)printf("[client command] set dssserver to have the right to grab lock\n");
    if (print_flag == DSS_HELP_SIMPLE) {
        return;
    }
    help_param_uds();
}

static status_t enable_grab_lock_proc(void)
{
    const char *input_args = cmd_enable_grab_lock_args[DSS_ARG_IDX_0].input_args;
    dss_conn_t *conn = dss_get_connection_opt(input_args);
    if (conn == NULL) {
        return CM_ERROR;
    }
    status_t status = dss_enable_grab_lock_on_server(conn);
    if (status != CM_SUCCESS) {
        DSS_PRINT_ERROR("Failed to enable grab lock.\n");
    } else {
        DSS_PRINT_INF("Succeed to enable grab lock.\n");
    }
    return status;
}

#define DSS_CMD_HOTPATCH_ARGS_OPERATION 0
#define DSS_CMD_HOTPATCH_ARGS_PATCH_PATH 1
#define DSS_CMD_HOTPATCH_ARGS_UDS 2
static status_t cmd_check_hotpatch_operation(const char *operation)
{
    if (dss_hp_str_to_operation(operation) == DSS_HP_OP_INVALID) {
        DSS_PRINT_ERROR("Invalid operation: %s.\n", operation);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static status_t cmd_check_patch_path(const char *patch_path)
{
    CM_CHECK_NULL_PTR(patch_path);
    if (strlen(patch_path) > DSS_HP_FILE_PATH_MAX_LEN) {
        DSS_PRINT_ERROR("Length of parameter -p cannot be longger than %u.\n", DSS_HP_FILE_PATH_MAX_LEN);
        return CM_ERROR;
    }
    if (patch_path[0] != '/') {
        DSS_PRINT_ERROR("Path of patch file must be absolute.\n");
        return CM_ERROR;
    }
    return dss_check_path(patch_path);
}

static dss_args_t cmd_hotpatch_args[] = {
    {'o', "operation", CM_TRUE, CM_TRUE, cmd_check_hotpatch_operation, NULL, NULL, 0, NULL, NULL, 0},
    {'p', "patch", CM_FALSE, CM_TRUE, cmd_check_patch_path, NULL, NULL, 0, NULL, NULL, 0},
    {'U', "UDS", CM_FALSE, CM_TRUE, cmd_check_uds, cmd_check_convert_uds_home, cmd_clean_check_convert, 0, NULL, NULL,
        0},
};

static status_t cmd_check_hotpatch_args(dss_args_t *cmd_args_set, int set_size)
{
    if (!cmd_args_set[DSS_CMD_HOTPATCH_ARGS_OPERATION].inputed) {
        DSS_PRINT_ERROR("hotpatch operation must be specified with -o.\n");
        return CM_ERROR;
    }
    const char *operation = cmd_args_set[DSS_CMD_HOTPATCH_ARGS_OPERATION].input_args;
    dss_hp_operation_cmd_e hp_cmd = dss_hp_str_to_operation(operation);
    if (dss_hp_cmd_need_patch_file(hp_cmd)) {
        if (!cmd_args_set[DSS_CMD_HOTPATCH_ARGS_PATCH_PATH].inputed ||
            cmd_args_set[DSS_CMD_HOTPATCH_ARGS_PATCH_PATH].input_args == NULL) {
            DSS_PRINT_ERROR("For dsscmd hotpatch -o %s, path of patch file must be specified with -p.\n", operation);
            return CM_ERROR;
        }
        return CM_SUCCESS;
    }

    if (cmd_args_set[DSS_CMD_HOTPATCH_ARGS_PATCH_PATH].inputed) {
        DSS_PRINT_ERROR("For dsscmd hotpatch -o %s, -p option is redundant.\n", operation);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static dss_args_set_t cmd_hotpatch_args_set = {
    cmd_hotpatch_args,
    sizeof(cmd_hotpatch_args) / sizeof(dss_args_t),
    cmd_check_hotpatch_args,
};

static void hotpatch_help(const char *prog_name, int print_flag)
{
    (void)printf("\nUsage:%s hotpatch <-o operation> [-p path_of_patch] [-U UDS:socket_domain]\n", prog_name);
    (void)printf("[client command] load/unload/active/deactive/refresh hotpatch.\n");
    (void)printf("-o/--operation <operation>, <required>, the operation to do on hotpatch, valid values: "
                 "load/unload/active/deactive/refresh.\n");
    (void)printf("-p/--patch [patch_file_path], [optional], required for load/unload/active/deactive, not required for "
                 "refresh.\n");
    if (print_flag == DSS_HELP_SIMPLE) {
        return;
    }
    help_param_uds();
}

static status_t hotpatch_proc(void)
{
    dss_conn_t *connection = dss_get_connection_opt(cmd_hotpatch_args[DSS_CMD_HOTPATCH_ARGS_UDS].input_args);
    if (connection == NULL) {
        DSS_PRINT_ERROR("Failed to get uds connection.\n");
        return CM_ERROR;
    }
    const char *cmd_str = cmd_hotpatch_args[DSS_CMD_HOTPATCH_ARGS_OPERATION].input_args;
    const char *patch_path = cmd_hotpatch_args[DSS_CMD_HOTPATCH_ARGS_PATCH_PATH].inputed ?
                                 cmd_hotpatch_args[DSS_CMD_HOTPATCH_ARGS_PATCH_PATH].input_args :
                                 NULL;
    status_t status = dss_hotpatch_impl(connection, cmd_str, patch_path);
    if (status == CM_SUCCESS) {
        if (patch_path == NULL) {
            // for refresh
            DSS_PRINT_INF("Success to %s hotpatch in dssserver.\n", cmd_str);
        } else {
            // for load/unload/active/deactive
            DSS_PRINT_INF("Success to %s hotpatch %s in dssserver.\n", cmd_str, patch_path);
        }
    } else {
        if (patch_path == NULL) {
            // for refresh
            DSS_PRINT_ERROR("Fail to %s hotpatch in dssserver.\n", cmd_str);
        } else {
            // for load/unload/active/deactive
            DSS_PRINT_ERROR("Fail to %s hotpatch %s in dssserver.\n", cmd_str, patch_path);
        }
    }
    dss_disconnect_ex(connection);
    return status;
}

static void query_hotpatch_help(const char *prog_name, int print_flag)
{
    (void)printf("\nUsage:%s query_hotpatch [-U UDS:socket_domain]\n", prog_name);
    (void)printf("[client command] query status of all hotpatches.\n");
    if (print_flag == DSS_HELP_SIMPLE) {
        return;
    }
    help_param_uds();
}

static dss_args_t cmd_query_hotpatch_args[] = {
    {'U', "UDS", CM_FALSE, CM_TRUE, cmd_check_uds, cmd_check_convert_uds_home, cmd_clean_check_convert, 0, NULL, NULL,
        0},
};

static dss_args_set_t cmd_query_hotpatch_args_set = {
    cmd_query_hotpatch_args,
    sizeof(cmd_query_hotpatch_args) / sizeof(dss_args_t),
    NULL,
};

static void print_dss_hp_info_view(const dss_hp_info_view_t *hp_info_view)
{
    if (hp_info_view == NULL) {
        return;
    }
    (void)printf("There are %u patches in dssserver.\n", hp_info_view->count);
    if (hp_info_view->count == 0) {
        return;
    }
    // print headers
    (void)printf("%-4s%-96s %-14s%-10s%-12s%-11s%-20s\n", "ID", "NAME", "PATCH_NUMBER", "STATUS", "LIB_STATUS",
        "COMMIT_ID", "DSSSERVER_VERSION");
    // print contents
    for (uint32 i = 0; i < hp_info_view->count; ++i) {
        const dss_hp_info_view_row_t *row = &hp_info_view->info_list[i];
        (void)printf("%-4u%-96s %-14u%-10s%-12s%-11s%-20s\n", i, row->patch_name, row->patch_number,
            dss_hp_state_to_str(row->patch_state), row->patch_lib_state, row->patch_commit, row->patch_bin_version);
    }
}

static status_t query_hotpatch_proc(void)
{
    dss_conn_t *connection = dss_get_connection_opt(cmd_query_hotpatch_args[0].input_args);
    if (connection == NULL) {
        DSS_PRINT_ERROR("Failed to get uds connection.\n");
        return CM_ERROR;
    }
    dss_hp_info_view_t *hp_info_list = (dss_hp_info_view_t *)cm_malloc(sizeof(dss_hp_info_view_t));
    if (hp_info_list == NULL) {
        (void)printf("Failed to query hotpatch: memory allocation error.\n");
        return CM_ERROR;
    }
    status_t status = dss_query_hotpatch_impl(connection, hp_info_list);
    if (status == CM_SUCCESS) {
        print_dss_hp_info_view(hp_info_list);
    } else {
        DSS_PRINT_ERROR("Failed to query hotpatch.\n");
    }
    dss_disconnect_ex(connection);
    cm_free(hp_info_list);
    return status;
}

// clang-format off
dss_admin_cmd_t g_dss_admin_cmd[] = { {"cv", cv_help, cv_proc, &cmd_cv_args_set, true},
                                      {"lsvg", lsvg_help, lsvg_proc, &cmd_lsvg_args_set, false},
                                      {"adv", adv_help, adv_proc, &cmd_adv_args_set, true},
                                      {"mkdir", mkdir_help, mkdir_proc, &cmd_mkdir_args_set, true},
                                      {"touch", touch_help, touch_proc, &cmd_touch_args_set, true},
                                      {"ts", ts_help, ts_proc, &cmd_ts_args_set, false},
                                      {"ls", ls_help, ls_proc, &cmd_ls_args_set, false},
                                      {"cp", cp_help, cp_proc, &cmd_cp_args_set, true},
                                      {"rm", rm_help, rm_proc, &cmd_rm_args_set, true},
                                      {"rmv", rmv_help, rmv_proc, &cmd_rmv_args_set, true},
                                      {"rmdir", rmdir_help, rmdir_proc, &cmd_rmdir_args_set, true},
                                      {"inq", inq_help, inq_proc, &cmd_inq_args_set, false},
                                      {"inq_reg", inq_reg_help, inq_reg_proc, &cmd_inq_req_args_set, false},
                                      {"lscli", lscli_help, lscli_proc, &cmd_lscli_args_set, false},
                                      {"kickh", kickh_help, kickh_proc, &cmd_kickh_args_set, true},
                                      {"reghl", reghl_help, reghl_proc, &cmd_reghl_args_set, true},
                                      {"unreghl", unreghl_help, unreghl_proc, &cmd_unreghl_args_set, true},
                                      {"auid", auid_help, auid_proc, &cmd_auid_args_set, false},
                                      {"examine", examine_help, examine_proc, &cmd_examine_args_set, false},
                                      {"dev", dev_help, dev_proc, &cmd_dev_args_set, false},
                                      {"showdisk", showdisk_help, showdisk_proc, &cmd_showdisk_args_set, false},
                                      {"rename", rename_help, rename_proc, &cmd_rename_args_set, true},
                                      {"du", du_help, du_proc, &cmd_du_args_set, false},
                                      {"find", find_help, find_proc, &cmd_find_args_set, false},
                                      {"ln", ln_help, ln_proc, &cmd_ln_args_set, true},
                                      {"readlink", readlink_help, readlink_proc, &cmd_readlink_args_set, false},
                                      {"unlink", unlink_help, unlink_proc, &cmd_unlink_args_set, true},
                                      {"encrypt", encrypt_help, encrypt_proc, &cmd_encrypt_args_set, true},
                                      {"setcfg", setcfg_help, setcfg_proc, &cmd_setcfg_args_set, true},
                                      {"getcfg", getcfg_help, getcfg_proc, &cmd_getcfg_args_set, false},
                                      {"getstatus", getstatus_help, getstatus_proc, &cmd_getstatus_args_set, false},
                                      {"stopdss", stopdss_help, stopdss_proc, &cmd_stopdss_args_set, true},
                                      {"scandisk", scandisk_help, scandisk_proc, &cmd_scandisk_args_set, true},
                                      {"clean_vglock", clean_vglock_help, clean_vglock_proc,
                                          &cmd_clean_vglock_args_set, true},
                                      {"repl", repl_help, repl_proc, &cmd_repl_args_set, true},
                                      {"rollback", rollback_help, rollback_proc, &cmd_rollback_args_set, true},
                                      {"showmem", showmem_help, showmem_proc, &cmd_showmem_args_set, false},
                                      {"fshowmem", fshowmem_help, fshowmem_proc, &cmd_fshowmem_args_set, false},
                                      {"truncate", truncate_help, truncate_proc, &cmd_truncate_args_set, true},
                                      {"dis_grab_lock", disable_grab_lock_help, disable_grab_lock_proc,
                                        &cmd_disable_grab_lock_args_set, true},
                                      {"en_grab_lock", enable_grab_lock_help, enable_grab_lock_proc,
                                        &cmd_enable_grab_lock_args_set, true},
                                      {"hotpatch", hotpatch_help, hotpatch_proc, &cmd_hotpatch_args_set, true},
                                      {"query_hotpatch", query_hotpatch_help, query_hotpatch_proc,
                                          &cmd_query_hotpatch_args_set, false}};

void clean_cmd()
{
    dss_conn_opt_exit();
    dss_free_vg_info();
    ga_reset_app_pools();
}

// clang-format on
static void help(char *prog_name, dss_help_type help_type)
{
    (void)printf("Usage:%s [command] [OPTIONS]\n\n", prog_name);
    (void)printf("Usage:%s %s/%s show help information of dsscmd\n", prog_name, HELP_SHORT, HELP_LONG);
    (void)printf("Usage:%s %s/%s show all help information of dsscmd\n", prog_name, ALL_SHORT, ALL_LONG);
    (void)printf("Usage:%s %s/%s show version information of dsscmd\n", prog_name, VERSION_SHORT, VERSION_LONG);
    if (!g_run_interatively) {
        (void)printf("Usage:%s -i/--interactive run dsscmd interatively\n", prog_name);
    }
    (void)printf("commands:\n");
    for (uint32 i = 0; i < sizeof(g_dss_admin_cmd) / sizeof(g_dss_admin_cmd[0]); ++i) {
        g_dss_admin_cmd[i].help(prog_name, help_type);
    }
    cmd_print_interactive_help(prog_name, help_type);
    (void)printf("\n\n");
}

static status_t execute_one_cmd(int argc, char **argv, uint32 cmd_idx)
{
    cmd_parse_init(g_dss_admin_cmd[cmd_idx].args_set->cmd_args, g_dss_admin_cmd[cmd_idx].args_set->args_size);
    if (cmd_parse_args(argc, argv, g_dss_admin_cmd[cmd_idx].args_set) != CM_SUCCESS) {
        int32 code;
        const char *message;
        cm_get_error(&code, &message);
        if (code != 0) {
            DSS_PRINT_ERROR("\ncmd %s error:%d %s.\n", g_dss_admin_cmd[cmd_idx].cmd, code, message);
        }
        return CM_ERROR;
    }
    status_t ret = g_dss_admin_cmd[cmd_idx].proc();
    cmd_parse_clean(g_dss_admin_cmd[cmd_idx].args_set->cmd_args, g_dss_admin_cmd[cmd_idx].args_set->args_size);
    return ret;
}

static status_t dss_cmd_append_oper_log(char *log_buf, void *buf, uint32 *offset)
{
    uint32 len = (uint32)strlen(buf);
    errno_t errcode = memcpy_s(log_buf + *offset, CM_MAX_LOG_CONTENT_LENGTH - *offset, buf, len);
    if (errcode != EOK) {
        LOG_RUN_ERR("Copying buf to log_buf failed.\n");
        return CM_ERROR;
    }
    *offset += len;
    return CM_SUCCESS;
}

static void dss_cmd_oper_log(int argc, char **argv, status_t status)
{
    char log_buf[CM_MAX_LOG_CONTENT_LENGTH] = {0};
    uint32 offset = 0;

    if (!LOG_OPER_ON) {
        return;
    }

    DSS_RETURN_DRIECT_IFERR(dss_cmd_append_oper_log(log_buf, "dsscmd", &offset));

    for (int i = 1; i < argc; i++) {
        DSS_RETURN_DRIECT_IFERR(dss_cmd_append_oper_log(log_buf, " ", &offset));
        DSS_RETURN_DRIECT_IFERR(dss_cmd_append_oper_log(log_buf, argv[i], &offset));
    }

    char result[DSS_MAX_PATH_BUFFER_SIZE];
    int32 ret = snprintf_s(
        result, DSS_MAX_PATH_BUFFER_SIZE, DSS_MAX_PATH_BUFFER_SIZE - 1, ". execute result %d.", (int32)status);
    if (ret == -1) {
        return;
    }
    DSS_RETURN_DRIECT_IFERR(dss_cmd_append_oper_log(log_buf, result, &offset));

    if (offset + 1 > CM_MAX_LOG_CONTENT_LENGTH) {
        DSS_PRINT_ERROR("Oper log len %u exceeds max %u.\n", offset, CM_MAX_LOG_CONTENT_LENGTH);
        return;
    }
    log_buf[offset + 1] = '\0';
    cm_write_oper_log(log_buf, offset);
}

static bool32 get_cmd_idx(int argc, char **argv, uint32_t *idx)
{
    for (uint32 i = 0; i < sizeof(g_dss_admin_cmd) / sizeof(g_dss_admin_cmd[0]); ++i) {
        if (strcmp(g_dss_admin_cmd[i].cmd, argv[DSS_ARG_IDX_1]) == 0) {
            *idx = i;
            return CM_TRUE;
        }
    }
    return CM_FALSE;
}

bool8 cmd_check_run_interactive(int argc, char **argv)
{
    if (argc < CMD_ARGS_AT_LEAST) {
        return CM_FALSE;
    }
    if (cm_str_equal(argv[1], "-i") || cm_str_equal(argv[1], "--interactive")) {
        g_run_interatively = CM_TRUE;
        return CM_TRUE;
    }
    return CM_FALSE;
}

bool8 cmd_version_and_help(int argc, char **argv)
{
    if (cm_str_equal(argv[1], VERSION_SHORT) || cm_str_equal(argv[1], VERSION_LONG)) {
        (void)printf("dsscmd %s\n", (char *)DEF_DSS_VERSION);
        return CM_TRUE;
    }
    if (cm_str_equal(argv[1], ALL_SHORT) || cm_str_equal(argv[1], ALL_LONG)) {
        help(argv[0], DSS_HELP_DETAIL);
        return CM_TRUE;
    }
    if (cm_str_equal(argv[1], HELP_SHORT) || cm_str_equal(argv[1], HELP_LONG)) {
        help(argv[0], DSS_HELP_SIMPLE);
        return CM_TRUE;
    }
    return CM_FALSE;
}

int32 execute_help_cmd(int argc, char **argv, uint32_t *idx, bool8 *go_ahead)
{
    if (argc < CMD_ARGS_AT_LEAST) {
        if (!g_run_interatively) {
            (void)printf("dsscmd: no operation specified.\n");
            (void)printf("dsscmd: Try \"dsscmd -h/--help\" for help information.\n");
            (void)printf("dsscmd: Try \"dsscmd -a/--all\" for detailed help information.\n");
        }
        *go_ahead = CM_FALSE;
        return EXIT_FAILURE;
    }
    if (cmd_version_and_help(argc, argv)) {
        *go_ahead = CM_FALSE;
        return EXIT_SUCCESS;
    }
    if (!get_cmd_idx(argc, argv, idx)) {
        (void)printf("cmd:%s can not find.\n", argv[DSS_ARG_IDX_1]);
        help(argv[0], DSS_HELP_SIMPLE);
        *go_ahead = CM_FALSE;
        return EXIT_FAILURE;
    }
    if (argc > DSS_ARG_IDX_2 &&
        (strcmp(argv[DSS_ARG_IDX_2], "-h") == 0 || strcmp(argv[DSS_ARG_IDX_2], "--help") == 0)) {
        g_dss_admin_cmd[*idx].help(argv[0], DSS_HELP_DETAIL);
        *go_ahead = CM_FALSE;
        return EXIT_SUCCESS;
    }

    *go_ahead = CM_TRUE;
    return EXIT_SUCCESS;
}

status_t execute_cmd(int argc, char **argv, uint32 idx)
{
    status_t status = execute_one_cmd(argc, argv, idx);
    dss_cmd_oper_log(argc, argv, status);
    return status;
}

static bool32 is_log_necessary(int argc, char **argv)
{
    uint32_t cmd_idx;
    if (get_cmd_idx(argc, argv, &cmd_idx) && g_dss_admin_cmd[cmd_idx].log_necessary) {
        return true;
    }
    return false;
}

void dss_cmd_set_path_optional()
{
    // set cmd arg path optional
    cmd_mkdir_args[0].required = CM_FALSE;
    cmd_ls_args[0].required = CM_FALSE;
    cmd_du_args[0].required = CM_FALSE;
    cmd_find_args[0].required = CM_FALSE;
}

static status_t dss_check_user_permit()
{
#ifndef WIN32
    // check root
    if (geteuid() == 0 || getuid() != geteuid()) {
        (void)printf("The root user is not permitted to execute the dsscmd "
                     "and the real uids must be the same as the effective uids.\n");
        (void)fflush(stdout);
        return CM_ERROR;
    }
    if (cm_regist_signal(SIGPIPE, SIG_IGN) != CM_SUCCESS) {
        (void)printf("Can't assign function for SIGPIPE.\n");
        return CM_ERROR;
    }
#endif
    return CM_SUCCESS;
}

int main(int argc, char **argv)
{
    DSS_RETURN_IF_ERROR(dss_check_user_permit());
    uint32 idx = 0;
    bool8 go_ahead = CM_TRUE;
    bool8 is_interactive = cmd_check_run_interactive(argc, argv);
    if (!is_interactive) {
        int32 help_ret = execute_help_cmd(argc, argv, &idx, &go_ahead);
        if (!go_ahead) {
            exit(help_ret);
        }
    }
    dss_config_t *inst_cfg = dss_get_g_inst_cfg();
    status_t ret = dss_set_cfg_dir(NULL, inst_cfg);
    DSS_RETURN_IFERR2(ret, DSS_PRINT_ERROR("Environment variant DSS_HOME not found!\n"));
    ret = dss_load_local_server_config(inst_cfg);
    DSS_RETURN_IFERR2(ret, DSS_PRINT_ERROR("Failed to load local server config, status(%d).\n", ret));
    ret = cm_start_timer(g_timer());
    DSS_RETURN_IFERR2(ret, DSS_PRINT_ERROR("Aborted due to starting timer thread.\n"));
    ret = dss_init_loggers(inst_cfg, dss_get_cmd_log_def(), dss_get_cmd_log_def_count(), "dsscmd");
    if (ret != CM_SUCCESS && is_log_necessary(argc, argv)) {
        DSS_PRINT_ERROR("%s\nDSS init loggers failed!\n", cm_get_errormsg(cm_get_error_code()));
        return ret;
    }

    do {
        if (g_run_interatively) {
            dss_cmd_run_interactively();
            ret = CM_SUCCESS;
            break;
        }
        cm_reset_error();
        ret = execute_cmd(argc, argv, idx);
    } while (0);

    clean_cmd();
    return ret;
}
