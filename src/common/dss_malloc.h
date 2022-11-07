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
 * dss_malloc.h
 *
 *
 * IDENTIFICATION
 *    src/common/dss_malloc.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __DSS_MALLOC_H__
#define __DSS_MALLOC_H__

#include <stdlib.h>
#include <stdio.h>
#include "cm_types.h"
#include "cm_debug.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define cm_malloc(size) (cm_malloc_ex(size, __LINE__, __FILE_NAME__))

static inline void *cm_malloc_ex(uint32 size, uint32 line, char *file)
{
    CM_ASSERT(size != 0);
    // To do some je_malloc
    uint8 *p = (uint8 *)malloc(size);
    return (void *)p;
}

#define cm_free free

static inline void *cm_malloc_align(uint32 alignment, uint32 size)
{
#ifndef WIN32
    int ret;
    void *memptr;
    ret = posix_memalign(&memptr, alignment, size);
    if (ret == 0) {
        return memptr;
    } else {
        return NULL;
    }
#else
    return cm_malloc(size);
#endif
}

#ifdef __cplusplus
}
#endif
#endif  // __DSS_MALLOC_H__
