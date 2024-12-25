/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
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
 * dsstbox_repair.h
 *
 *
 * IDENTIFICATION
 *    src/tbox/dsstbox_repair.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __DSSTBOX_REPAIR_H_
#define __DSSTBOX_REPAIR_H_

#include "dss_defs.h"
#include "dss_au.h"

#define DSS_REPAIR_ARG_VOL_PATH 0
#define DSS_REPAIR_ARG_TYPE 1
#define DSS_REPAIR_ARG_META_ID 2
#define DSS_REPAIR_ARG_AU_SIZE 3
#define DSS_REPAIR_ARG_KEY_VALUE 4

#define DSS_REPAIR_TYPE_FS_BLOCK "fs_block"
#define DSS_REPAIR_TYPE_FT_BLOCK "ft_block"
#define DSS_REPAIR_TYPE_CORE_CTRL "core_ctrl"
#define DSS_REPAIR_TYPE_ROOT_FT_BLOCK "root_ft_block"
#define DSS_REPAIR_TYPE_VOLUME_CTRL "volume_ctrl"
#define DSS_REPAIR_TYPE_VOLUME_HEADER "volume_header"
// software_version is modified by "-t software_version -k software_version=value",
//     rather than by "-t volume_header -k software_version=value".
#define DSS_REPAIR_TYPE_SOFTWARE_VERSION "software_version"
#define DSS_REPAIR_TYPE_FS_AUX_BLOCK "fs_aux_block"

typedef struct st_repair_input_def {
    char *vol_path;
    char *type;
    char *key_value;
    dss_block_id_t block_id;
    uint32_t au_size;
} repair_input_def_t;

status_t dss_repair_verify_disk_version(char *vol_path);
status_t dss_repair_fs_block(repair_input_def_t *input);
status_t dss_repair_ft_block(repair_input_def_t *input);
status_t dss_repair_core_ctrl(repair_input_def_t *input);
status_t dss_repair_volume_header(repair_input_def_t *input);
status_t dss_repair_software_version(repair_input_def_t *input);
status_t dss_repair_root_ft_block(repair_input_def_t *input);
status_t dss_repair_volume_ctrl(repair_input_def_t *input);
status_t dss_repair_fs_aux(repair_input_def_t *input);

#endif