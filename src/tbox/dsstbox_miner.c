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
 * dsstbox_miner.c
 *
 *
 * IDENTIFICATION
 *    src/tbox/dsstbox_miner.c
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

#include "dss_log.h"
#include "dss_errno.h"
#include "dss_malloc.h"
#include "dss_file.h"
#include "dss_args_parse.h"
#include "dss_defs_print.h"
#include "dsstbox_miner.h"
#ifndef WIN32
#include "config.h"
#endif

status_t dss_check_index(const char *str)
{
    uint32 index;
    status_t status = cm_str2uint32(str, &index);
    if (status == CM_ERROR) {
        DSS_PRINT_ERROR("[TBOX][MINER]%s is not a valid uint32\n", str);
        return CM_ERROR;
    }
    if (index >= DSS_MAX_EXTENDED_COUNT) {
        DSS_PRINT_ERROR("[TBOX][MINER]index %u should be in range [0, %d].\n", index, DSS_MAX_EXTENDED_COUNT - 1);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

/*
1. check vg valid
2. load redo_ctrl
*/
static status_t dss_init_and_load_vg(miner_run_ctx_def_t *ctx)
{
    dss_vg_info_item_t *vg_item = ctx->vg_item;
    bool32 remote = CM_FALSE;
    status_t status = dss_load_vg_ctrl_part(vg_item, 0, vg_item->dss_ctrl, (int32)sizeof(dss_ctrl_t), &remote);
    if (status != CM_SUCCESS) {
        DSS_PRINT_ERROR("[TBOX][MINER]Failed to load vg header from vol_path %s.\n", vg_item->entry_path);
        return CM_ERROR;
    }
    if (!DSS_VG_IS_VALID(vg_item->dss_ctrl)) {
        DSS_PRINT_ERROR("[TBOX][MINER]Failed to check valid of vg %s.\n", vg_item->vg_name);
        return CM_ERROR;
    }
    uint32 software_version = dss_get_software_version(&vg_item->dss_ctrl->vg_info);
    if (software_version > DSS_SOFTWARE_VERSION) {
        DSS_PRINT_ERROR("[TBOX][MINER] disk software_version:%u is not match dsstbox version:%u.\n", software_version,
            (uint32)DSS_SOFTWARE_VERSION);
        DSS_PRINT_ERROR("[TBOX][MINER] disk software_version:%u is not match dsstbox version:%u.\n", software_version,
            (uint32)DSS_SOFTWARE_VERSION);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static status_t dss_load_redo_buffer(char *log_buf, dss_vg_info_item_t *vg_item)
{
    dss_redo_ctrl_t *redo_ctrl = &vg_item->dss_ctrl->redo_ctrl;
    uint64 redo_buf_size = 0;
    status_t status;
    for (uint32 i = 0; i < redo_ctrl->count; i++) {
        auid_t redo_au = redo_ctrl->redo_start_au[i];
        uint32 redo_size = redo_ctrl->redo_size[i];
        uint64 log_start = dss_get_vg_au_size(vg_item->dss_ctrl) * redo_au.au;
        LOG_DEBUG_INF("[TBOX][MINER]Begin to load log_buf which index is %u from vg:%s, auid is %s, log_size is %u.", i,
            vg_item->vg_name, dss_display_metaid(redo_au), redo_size);
        status = dss_read_redolog_from_disk(
            vg_item, redo_au.volume, (int64)log_start, log_buf + redo_buf_size, (int32)redo_size);
        DSS_RETURN_IFERR2(status, DSS_PRINT_ERROR("[TBOX][MINER]Failed to load log_buf which index is %u from vg:%s.\n",
                                      i, vg_item->vg_name));
        redo_buf_size += redo_ctrl->redo_size[i];
    }
    return CM_SUCCESS;
}

status_t dss_init_miner_run_ctx(miner_run_ctx_def_t *ctx)
{
    dss_vg_info_item_t *vg_item = NULL;
    status_t status = dss_get_vg_item(&vg_item, ctx->input.vg_name);
    if (status != CM_SUCCESS) {
        DSS_PRINT_ERROR("[TBOX][MINER]Failed to get vg %s.\n", ctx->input.vg_name);
        return status;
    }
    vg_item->dss_ctrl = (dss_ctrl_t *)cm_malloc_align(DSS_ALIGN_SIZE, sizeof(dss_ctrl_t));
    if (vg_item->dss_ctrl == NULL) {
        DSS_PRINT_ERROR("[TBOX][MINER]Failed to alloc memory for dss ctrl.\n");
        return CM_ERROR;
    }
    ctx->vg_item = vg_item;
    status = dss_init_and_load_vg(ctx);
    if (status != CM_SUCCESS) {
        DSS_FREE_POINT(vg_item->dss_ctrl);
        DSS_PRINT_ERROR("[TBOX][MINER]Failed to init and load vg.\n");
        return CM_ERROR;
    }
    dss_redo_ctrl_t *redo_ctrl = &vg_item->dss_ctrl->redo_ctrl;
    ctx->curr_lsn = redo_ctrl->lsn;
    uint64 curr_offset = 0;
    for (uint32 i = 0; i < redo_ctrl->redo_index; i++) {
        curr_offset += redo_ctrl->redo_size[i];
    }
    curr_offset += redo_ctrl->offset;
    ctx->curr_offset = curr_offset;
    ctx->count = redo_ctrl->count;
    uint64 size = 0;
    for (uint32 i = 0; i < redo_ctrl->count; i++) {
        size += redo_ctrl->redo_size[i];
    }
    if (size == 0) {
        DSS_FREE_POINT(vg_item->dss_ctrl);
        DSS_PRINT_ERROR("[TBOX][MINER]redo buf size should not be 0.\n");
        return CM_ERROR;
    }
    char *log_buf = (char *)cm_malloc_align(DSS_ALIGN_SIZE, size);
    if (log_buf == NULL) {
        DSS_PRINT_ERROR("[TBOX][MINER]Failed to alloc memory for redo buf.\n");
        DSS_FREE_POINT(vg_item->dss_ctrl);
        return CM_ERROR;
    }
    status = dss_load_redo_buffer(log_buf, vg_item);
    if (status != CM_SUCCESS) {
        DSS_PRINT_ERROR("[TBOX][MINER]Failed to load redo buf.");
        DSS_FREE_POINT(vg_item->dss_ctrl);
        DSS_FREE_POINT(log_buf);
        return CM_ERROR;
    }
    ctx->log_buf = log_buf;
    ctx->size = size;
    return CM_SUCCESS;
}

static status_t dss_copy_wraparound_redo_buf(
    char *tmp_log_buf, char *log_buf, uint64 start_offset, uint64 end_offset, uint64 size)
{
    LOG_RUN_INF("[TBOX][MINER]Begin to copy wraparound redo buf, start_offset is %llu, end_offset is %llu.",
        start_offset, end_offset);
    errno_t errcode = memcpy_s(tmp_log_buf, DSS_VG_LOG_SPLIT_SIZE, log_buf + start_offset, size - start_offset);
    if (errcode != EOK) {
        DSS_PRINT_ERROR("[TBOX][MINER]Failed to copy wraparound redo buf.\n");
        return CM_ERROR;
    }
    errcode = memcpy_s(tmp_log_buf + (size - start_offset), DSS_VG_LOG_SPLIT_SIZE, log_buf, end_offset);
    if (errcode != EOK) {
        DSS_PRINT_ERROR("[TBOX][MINER]Failed to copy wraparound redo buf.\n");
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

bool32 dss_probe_valid_redo(miner_run_ctx_def_t *ctx, uint64 start_offset, uint64 *end_offset)
{
    char *log_buf = ctx->log_buf;
    uint64 curr_lsn = ctx->curr_lsn;
    uint64 size = ctx->size;
    dss_redo_batch_t *batch = (dss_redo_batch_t *)(log_buf + start_offset);
    if (batch->size == 0) {
        LOG_DEBUG_INF("[TBOX][MINER]batch size is invalid, ignored it.");
        return CM_FALSE;
    }
    if (batch->lsn > curr_lsn) {
        LOG_DEBUG_INF("[TBOX][MINER]batch lsn is invalid, ignored it.");
        return CM_FALSE;
    }
    uint64 load_size = (uint64)(CM_CALC_ALIGN(batch->size + sizeof(dss_redo_batch_t), DSS_DISK_UNIT_SIZE));
    if (load_size > DSS_VG_LOG_SPLIT_SIZE) {
        LOG_DEBUG_INF(
            "[TBOX][MINER]Redo log from offset %llu is invalid, ignored it. size is %llu, which is greater than %u",
            start_offset, load_size, DSS_VG_LOG_SPLIT_SIZE);
        return CM_FALSE;
    }
    dss_redo_batch_t *tail = NULL;
    uint64 tail_offset = load_size + start_offset - sizeof(dss_redo_batch_t);
    if (start_offset + load_size > size) {
        char *tmp_log_buf = (char *)cm_malloc(DSS_VG_LOG_SPLIT_SIZE);
        if (tmp_log_buf == NULL) {
            DSS_PRINT_ERROR("[TBOX][MINER]Failed to alloc wraparound redo buf.\n");
            return CM_FALSE;
        }
        uint64 wraparound_end_offset = (start_offset + load_size) % size;
        if (dss_copy_wraparound_redo_buf(tmp_log_buf, log_buf, start_offset, wraparound_end_offset, size) !=
            CM_SUCCESS) {
            DSS_FREE_POINT(tmp_log_buf);
            return CM_FALSE;
        }
        tail_offset = load_size - sizeof(dss_redo_batch_t);
        tail = (dss_redo_batch_t *)((char *)tmp_log_buf + tail_offset);
        if (!dss_check_redo_batch_complete(batch, tail, CM_FALSE)) {
            LOG_DEBUG_INF("[TBOX][MINER]No complete redo log.");
            DSS_FREE_POINT(tmp_log_buf);
            return CM_FALSE;
        }
        DSS_FREE_POINT(tmp_log_buf);
    } else {
        tail = (dss_redo_batch_t *)((char *)log_buf + tail_offset);
        if (!dss_check_redo_batch_complete(batch, tail, CM_TRUE)) {
            LOG_DEBUG_INF("[TBOX][MINER]No complete redo log.");
            return CM_FALSE;
        }
    }
    *end_offset = (load_size + start_offset) % size;
    return CM_TRUE;
}

void dss_print_redo_batch(char *log_buf, uint64 start_offset, uint64 end_offset)
{
    dss_redo_entry_t *entry = NULL;
    dss_redo_batch_t *batch = (dss_redo_batch_t *)log_buf;
    uint32 data_size = batch->size - DSS_REDO_BATCH_HEAD_SIZE;
    uint32 offset = 0;
    uint32 index = 0;
    (void)printf("redo_batch[%llu] = {\n", batch->lsn);
    (void)printf("  start_offset = %llu\n", start_offset);
    (void)printf("  end_offset = %llu\n", end_offset - 1);
    (void)printf("  size = %u\n", batch->size);
    (void)printf("  hash_code = %u\n", batch->hash_code);
    (void)printf("  time = %lld\n", batch->time);
    (void)printf("  lsn = %llu\n", batch->lsn);
    (void)printf("  count = %u\n", batch->count);
    while (offset < data_size) {
        (void)printf("  entry[%u] = {\n", index);
        entry = (dss_redo_entry_t *)(batch->data + offset);
        dss_print_redo_entry(entry);
        offset += entry->size;
        index++;
        (void)printf("  }\n");
    }
    (void)printf("}\n");
}

void dss_print_redo_ctrl(dss_redo_ctrl_t *redo_ctrl)
{
    (void)printf("redo_ctrl = {\n");
    (void)printf("  checksum = %u\n", redo_ctrl->checksum);
    (void)printf("  redo_index = %u\n", redo_ctrl->redo_index);
    (void)printf("  version = %llu\n", redo_ctrl->version);
    (void)printf("  offset = %llu\n", redo_ctrl->offset);
    (void)printf("  lsn = %llu\n", redo_ctrl->lsn);
    for (uint32 i = 0; i < redo_ctrl->count; i++) {
        (void)printf("  start_au[%u] = {\n", i);
        printf_auid(&redo_ctrl->redo_start_au[i]);
        (void)printf("  redo size = %u\n", redo_ctrl->redo_size[i]);
        (void)printf("   }\n");
    }
    (void)printf("  count = %u\n", redo_ctrl->count);
    (void)printf("}\n");
}

static status_t dss_print_redo_batch_base(char* log_buf, uint64 start_offset, uint64 end_offset, uint64 size)
{
    if (end_offset < start_offset) {
        char *tmp_log_buf = (char *)cm_malloc(DSS_VG_LOG_SPLIT_SIZE);
        if (tmp_log_buf == NULL) {
            DSS_PRINT_ERROR("[TBOX][MINER]Failed to alloc wraparound redo buf.\n");
            return CM_ERROR;
        }
        if (dss_copy_wraparound_redo_buf(tmp_log_buf, log_buf, start_offset, end_offset, size) != CM_SUCCESS) {
            DSS_FREE_POINT(tmp_log_buf);
            return CM_ERROR;
        }
        dss_print_redo_batch(tmp_log_buf, start_offset, end_offset);
        DSS_FREE_POINT(tmp_log_buf);
    } else {
        dss_print_redo_batch(log_buf + start_offset, start_offset, end_offset);
    }
    return CM_SUCCESS;
}
static status_t dss_print_redo_info_base(miner_run_ctx_def_t *ctx, uint64 start_offset)
{
    dss_redo_ctrl_t *redo_ctrl = &ctx->vg_item->dss_ctrl->redo_ctrl;
    dss_print_redo_ctrl(redo_ctrl);
    char *log_buf = ctx->log_buf;
    uint64 size = ctx->size;
    miner_input_def_t *input = &ctx->input;
    uint64 curr_lsn = ctx->curr_lsn;
    dss_redo_batch_t *batch = (dss_redo_batch_t *)(log_buf + start_offset);
    uint64 start_lsn = batch->lsn;
    uint64 end_offset = 0;
    uint64 index = 0;
    if (start_lsn == curr_lsn) {
        if (!dss_probe_valid_redo(ctx, start_offset, &end_offset)) {
            DSS_PRINT_ERROR("[TBOX][MINER]Failed to probe redo buf, just research.\n");
            return CM_ERROR;
        }
        if (dss_print_redo_batch_base(log_buf, start_offset, end_offset, size) != CM_SUCCESS) {
            return CM_ERROR;
        }
        index++;
    }
    while (start_lsn < curr_lsn) {
        batch = (dss_redo_batch_t *)(log_buf + start_offset);
        if (!dss_probe_valid_redo(ctx, start_offset, &end_offset)) {
            DSS_PRINT_ERROR("[TBOX][MINER]Failed to probe redo buf, just research.\n");
            return CM_ERROR;
        }
        if (input->number != 0 && index >= input->number) {
            break;
        }
        if (input->start_lsn != 0 && input->start_lsn > batch->lsn) {
            start_lsn = batch->lsn;
            start_offset = end_offset;
            continue;
        }
        if (dss_print_redo_batch_base(log_buf, start_offset, end_offset, size) != CM_SUCCESS) {
            return CM_ERROR;
        }
        start_lsn = batch->lsn;
        start_offset = end_offset;
        index++;
    }
    if (input->number != 0 && index != input->number) {
        DSS_PRINT_ERROR("[TBOX][MINER]number %llu must be less than or equal to %llu.\n", input->number, index);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

status_t dss_print_redo_info(miner_run_ctx_def_t *ctx)
{
    uint64 curr_offset = ctx->curr_offset;
    char *log_buf = ctx->log_buf;
    uint64 size = ctx->size;
    uint64 start_offset = 0;
    uint64 end_offset = 0;
    if (ctx->curr_offset == 0) {
        DSS_PRINT_INF("[TBOX][MINER]No redo log buffer can dispaly.\n");
        return CM_SUCCESS;
    }
    if (dss_probe_valid_redo(ctx, start_offset, &end_offset)) {
        dss_redo_batch_t *batch = (dss_redo_batch_t *)(log_buf + start_offset);
        if (batch->lsn == 1) {
            LOG_DEBUG_INF("[TBOX][MINER]No wraparound redo buf.");
            return dss_print_redo_info_base(ctx, start_offset);
        }
    }
    start_offset = curr_offset;
    while (start_offset < size) {
        if (!dss_probe_valid_redo(ctx, start_offset, &end_offset)) {
            start_offset += DSS_DISK_UNIT_SIZE;
            continue;
        }
        return dss_print_redo_info_base(ctx, start_offset);
    }
    DSS_PRINT_ERROR("[TBOX][MINER]No redo log buffer can dispaly.\n");
    return CM_ERROR;
}

status_t dss_print_redo_info_by_lsn(miner_run_ctx_def_t *ctx)
{
    char *log_buf = ctx->log_buf;
    miner_input_def_t *input = &ctx->input;
    uint64 curr_lsn = ctx->curr_lsn;
    if (input->start_lsn > curr_lsn) {
        DSS_PRINT_ERROR("[TBOX][MINER]start_lsn %llu is larger than curr_lsn %llu.\n", input->start_lsn, curr_lsn);
        return CM_ERROR;
    }
    uint64 curr_offset = ctx->curr_offset;
    uint64 size = ctx->size;
    uint64 start_offset = 0;
    uint64 end_offset = 0;
    // check first redo log from offset 0
    if (dss_probe_valid_redo(ctx, start_offset, &end_offset)) {
        dss_redo_batch_t *batch = (dss_redo_batch_t *)(log_buf + start_offset);
        if (batch->lsn == 1) {
            LOG_DEBUG_INF("[TBOX][MINER]No wraparound redo buf.");
            return dss_print_redo_info_base(ctx, start_offset);
        }
    }
    start_offset = curr_offset;
    while (start_offset < size) {
        if (!dss_probe_valid_redo(ctx, start_offset, &end_offset)) {
            start_offset += DSS_DISK_UNIT_SIZE;
            continue;
        }
        dss_redo_batch_t *batch = (dss_redo_batch_t *)(log_buf + start_offset);
        if (input->start_lsn != 0 && input->start_lsn < batch->lsn) {
            DSS_PRINT_ERROR("[TBOX][MINER]start_lsn %llu is smaller than the smallest effective lsn %llu.\n",
                input->start_lsn, batch->lsn);
            return CM_ERROR;
        }
        return dss_print_redo_info_base(ctx, start_offset);
    }
    DSS_PRINT_ERROR("[TBOX][MINER]No redo log buffer can dispaly.\n");
    return CM_ERROR;
}

status_t dss_print_redo_info_by_index(miner_run_ctx_def_t *ctx)
{
    miner_input_def_t *input = &ctx->input;
    dss_redo_ctrl_t *redo_ctrl = &ctx->vg_item->dss_ctrl->redo_ctrl;
    uint64 start_offset = 0;
    if (input->offset >= redo_ctrl->redo_size[input->index] - (uint32)sizeof(dss_redo_batch_t)) {
        DSS_PRINT_ERROR("[TBOX][MINER]offset: %llu should less than %u.\n", input->offset,
            redo_ctrl->redo_size[input->index] - (uint32)sizeof(dss_redo_batch_t));
        return CM_ERROR;
    }
    for (uint32 i = 0; i < input->index; i++) {
        start_offset += redo_ctrl->redo_size[i];
    }
    start_offset += input->offset;
    uint64 end_offset = 0;
    if (!dss_probe_valid_redo(ctx, start_offset, &end_offset)) {
        DSS_PRINT_ERROR("[TBOX][MINER]No valid redo from index: %u, offset: %llu.\n", input->index, input->offset);
        return CM_ERROR;
    }
    return dss_print_redo_info_base(ctx, start_offset);
}
