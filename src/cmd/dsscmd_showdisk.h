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
 * dsscmd_showdisk.h
 *
 *
 * IDENTIFICATION
 *    src/cmd/dsscmd_showdisk.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __DSSCMD_SHOWDISK_H__
#define __DSSCMD_SHOWDISK_H__

#include "dss_file_def.h"

status_t printf_dss_core_ctrl(dss_vg_info_item_t *vg_item, dss_volume_t *volume);
status_t printf_dss_block_with_blockid(dss_vg_info_item_t *vg_item, uint64 block_id, uint64 node_id);
status_t dss_read_meta_from_disk(dss_vg_info_item_t *vg_item, const char *struct_name);

#endif
