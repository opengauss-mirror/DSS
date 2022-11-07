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
 * cm_ga.c
 *
 *
 * IDENTIFICATION
 *    src/common/cm_ga.c
 *
 * -------------------------------------------------------------------------
 */

#ifndef _DSS_SKIPLIST_MEM_H
#define _DSS_SKIPLIST_MEM_H

#include "cm_latch.h"
#include "cm_error.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MEM_PAGE_SIZE (1024 * 32)

typedef struct block_header {
    uint16 offset;
    uint16 size;
    void *next;
} block_header_t;

typedef struct page_header {
    struct mem_ctx *ctx;
    struct page_header *next;
    struct page_header *prev;
    struct page_header *next_free;
    struct page_header *prev_free;
    block_header_t *free_block;
    int32 free_offset;
    int32 free_size;
    uint32 magic;
} page_header_t;

typedef struct mem_ctx {
    page_header_t *head;
    page_header_t *free_page;
    uint64 total_memory;
    uint64 free_memory;
    spinlock_t lock;
} mem_ctx_t;

#define GET_BLOCK_HEADER(ptr) ((block_header_t *)((char *)(ptr) - sizeof(block_header_t)))

#define GET_PAGE_HEADER(block) ((page_header_t *)((char *)(block) - (block)->offset))

#define GET_PTR(block) ((void *)((char *)(block) + sizeof(block_header_t)))

uint32 sklist_mem_init(mem_ctx_t *ctx);

uint32 sklist_mem_alloc(mem_ctx_t *ctx, uint16 size, void **ptr);

uint16 sklist_mem_size(void *ptr);

void sklist_mem_free(void *ptr);

#ifdef __cplusplus
}
#endif

#endif
