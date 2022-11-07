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
 * dsscmd_create_vg.h
 *
 *
 * IDENTIFICATION
 *    src/cmd/dsscmd_create_vg.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef DSSCMD_CREATE_VG_H_
#define DSSCMD_CREATE_VG_H_

#include "dss_param.h"

#define LENGTH_EIGHT_BYTE 8

status_t dss_create_vg(const char *vg_name, const char *volume_name, dss_config_t *inst_cfg, uint32 size);

#endif
