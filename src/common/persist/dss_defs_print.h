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
 * dss_defs_print.h
 *
 *
 * IDENTIFICATION
 *    src/common/persist/dss_defs_print.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __DSS_DEFS_PRINT_H__
#define __DSS_DEFS_PRINT_H__

#include "dss_diskgroup.h"
#include "dss_alloc_unit.h"
#include "dss_meta_buf.h"
#include "dss_file.h"
#include "dss_session.h"
#include "dss_fs_aux.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DSS_SECOND_PRINT_LEVEL 2
extern uint8 g_print_level;
void printf_auid(const auid_t *first);
void printf_dss_fs_block_list(dss_fs_block_list_t *free);
void printf_dss_fs_aux_root(dss_fs_aux_root_t *root);
void printf_dss_au_root(dss_au_root_t *au_root);
void printf_dss_fs_block_root(dss_fs_block_root_t *root);
void printf_dss_volume_attr(const dss_volume_attr_t *volume_attrs);
void dss_printf_core_ctrl_base(dss_core_ctrl_t *core_ctrl);
void printf_gft_root(gft_root_t *ft_root);
void printf_gft_node(gft_node_t *gft_node, const char *tab);
void printf_gft_list(gft_list_t *items);
#ifdef __cplusplus
}
#endif

#endif
