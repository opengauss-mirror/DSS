/*
 * Copyright (c) 2024 Huawei Technologies Co.,Ltd.
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

typedef struct st_repair_input_def {
    char *vol_path;
    char *type;
    char *key_value;
    dss_block_id_t block_id;
    uint32_t au_size;
} repair_input_def_t;

status_t dss_repair_fs_block(repair_input_def_t *input);
status_t dss_repair_verify_disk_version(char *vol_path);

#endif