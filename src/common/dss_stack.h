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
 * dss_stack.h
 *
 *
 * IDENTIFICATION
 *    src/common/dss_stack.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __DSS_STACK_H_
#define __DSS_STACK_H_

#include "cm_types.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DSS_MAX_STACK_DEPTH 32
typedef struct tagknl_stack {
    uint32 depth;
    uint32 buff_pos;
    uint32 indicator[DSS_MAX_STACK_DEPTH];
    uint32 size;
    uint32 reserve;
    char *buff;
} dss_stack;
char *dss_get_stack_pos(dss_stack *stack, uint32 depth);
void dss_pop_ex(dss_stack *stack, uint32 depth);

#ifdef __cplusplus
}
#endif

#endif
