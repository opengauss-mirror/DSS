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
 * dss_stack.c
 *
 *
 * IDENTIFICATION
 *    src/common/dss_stack.c
 *
 * -------------------------------------------------------------------------
 */
#include "dss_stack.h"
#include "cm_log.h"
#include "dss_defs.h"

char *dss_get_stack_pos(dss_stack *stack, uint32 depth)
{
    CM_ASSERT(stack != NULL);

    if (stack->depth < depth) {
        return NULL;
    }

    return (stack->buff + stack->indicator[depth]);
}

void dss_pop_ex(dss_stack *stack, uint32 depth)
{
    CM_ASSERT(stack != NULL);

    if (depth >= DSS_MAX_STACK_DEPTH) {
        LOG_DEBUG_ERR("pop vg_item stack depth is out of bound");
        return;
    }

    stack->depth = depth;
    stack->buff_pos = stack->indicator[depth];
}
