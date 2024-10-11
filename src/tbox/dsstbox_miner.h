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
 * dsstbox_miner.h
 *
 *
 * IDENTIFICATION
 *    src/tbox/dsstbox_miner.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __DSSTBOX_MINER_H_
#define __DSSTBOX_MINER_H_

#include "dss_defs.h"
#include "dss_redo_recovery.h"

#define DSS_ARG_MINER_VG 0
#define DSS_ARG_MINER_START_LSN 1
#define DSS_ARG_MINER_NUMBER 2
#define DSS_ARG_MINER_INDEX 3
#define DSS_ARG_MINER_OFFSET 4
#define DSS_ARG_MINER_HOME 5

typedef struct st_miner_input_def {
    char *vg_name;
    uint64 start_lsn;
    uint64 number;
    uint32 index;
    uint64 offset;
} miner_input_def_t;

typedef struct st_miner_run_ctx_def {
    miner_input_def_t input;
    dss_vg_info_item_t *vg_item;
    char *log_buf;       // total log buffer
    uint64 size;         // log buffer size
    uint64 curr_lsn;     // max lsn in valid redo log
    uint64 curr_offset;  // offset relative to total log
    uint32 count;        // valid redo buffer count
} miner_run_ctx_def_t;

status_t dss_check_index(const char *str);
status_t dss_init_miner_run_ctx(miner_run_ctx_def_t *ctx);
status_t dss_print_redo_info(miner_run_ctx_def_t *ctx);
status_t dss_print_redo_info_by_index(miner_run_ctx_def_t *ctx);
status_t dss_print_redo_info_by_lsn(miner_run_ctx_def_t *ctx);
void dss_print_redo_ctrl(dss_redo_ctrl_t *redo_ctrl);
#endif