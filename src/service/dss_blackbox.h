/*
 * Copyright (c) 2023 Huawei Technologies Co.,Ltd.
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
 * dss_blackbox.h
 *
 *
 * IDENTIFICATION
 *    src/service/dss_blackbox.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __DSS_BLACKBOX_H__
#define __DSS_BLACKBOX_H__
#ifndef _WIN32
#include "cm_blackbox.h"
#include "cm_file.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DSS_LOG_BLACKBOX_OR_DYNAMIC_INF(log_id, format, ...) \
    do {                                                     \
        if (log_id == LOG_BLACKBOX) {                        \
            LOG_BLACKBOX_INF(format, ##__VA_ARGS__);         \
        } else {                                             \
            LOG_DYNAMIC_INF(format, ##__VA_ARGS__);          \
        }                                                    \
    } while (0)

static inline status_t dss_write_shm_memory_file_inner(int32 handle, int64 *length, const void* buffer, int32 size)
{
    status_t ret = cm_write_file(handle, buffer, size);
    if (ret == CM_SUCCESS) {
        *length += size;
    }
    return ret;
}

status_t dss_sigcap_handle_reg();
status_t dss_update_state_file(bool32 coredump);
void dss_exit_proc(int32 exit_code);
void dss_sig_collect_all_backtrace(uint32 log_id);
void dss_print_global_variable(uint32 log_id);
void dss_print_effect_param(uint32 log_id);
void dss_write_shm_memory(uint32 log_id);

#ifdef __cplusplus
}
#endif
#endif
#endif