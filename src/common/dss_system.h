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
 * dss_system.h
 *
 *
 * IDENTIFICATION
 *    src/common/dss_system.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __DSS_SYSTEM_H__
#define __DSS_SYSTEM_H__

#include <stdio.h>
#include <string.h>

#include "cm_defs.h"
#include "cm_error.h"
#include "cs_pipe.h"

#ifdef __cplusplus
extern "C" {
#endif

uint64 cm_sys_pid(void);
char *cm_sys_program_name(void);
char *cm_sys_user_name(void);
char *cm_sys_host_name(void);
char *cm_sys_platform_name(void);
int64 cm_sys_ticks(void);
int64 cm_sys_process_start_time(uint64 pid);
bool32 cm_sys_process_alived(uint64 pid, int64 start_time);
void cm_try_init_system(void);
void cm_save_remote_host(cs_pipe_t *pipe, char *os_host);

#ifdef __cplusplus
}
#endif

#endif
