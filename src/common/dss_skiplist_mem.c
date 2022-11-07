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
 * dss_skiplist_mem.h
 *
 *
 * IDENTIFICATION
 *    src/common/dss_skiplist_mem.h
 *
 * -------------------------------------------------------------------------
 */

#include "dss_skiplist_mem.h"
#include "dss_malloc.h"

uint32 sklist_mem_init(mem_ctx_t *ctx)
{
    CM_ASSERT(ctx != NULL);
    ctx->free_page = (page_header_t *)cm_malloc(MEM_PAGE_SIZE);
    if (ctx->free_page == NULL) {
        return ERR_ALLOC_MEMORY;
    }
    ctx->total_memory = (uint32)sizeof(mem_ctx_t) + MEM_PAGE_SIZE;
    ctx->free_memory = MEM_PAGE_SIZE - (uint32)sizeof(page_header_t);
    /* INIT the page header */
    ctx->free_page->magic = 0x12345678;
    ctx->free_page->ctx = ctx;
    ctx->free_page->next = NULL;
    ctx->free_page->prev = NULL;
    ctx->free_page->next_free = NULL;
    ctx->free_page->prev_free = NULL;
    ctx->free_page->free_block = NULL;
    ctx->free_page->free_offset = (int32)sizeof(page_header_t);
    ctx->free_page->free_size = MEM_PAGE_SIZE - (int32)sizeof(page_header_t);
    ctx->head = ctx->free_page;

    return CM_SUCCESS;
}

uint16 sklist_mem_size(void *ptr)
{
    CM_ASSERT(ptr != NULL);
    return (GET_BLOCK_HEADER(ptr)->size - (uint32)sizeof(block_header_t));
}

static bool32 sklist_find_free_page(mem_ctx_t *ctx, uint16 size, void **ptr)
{
    page_header_t *cur = ctx->free_page;
    block_header_t *block;
    while (cur) {
        if (cur->free_block) {
            block = cur->free_block;
            cur->free_block = block->next;
            cur->free_size -= block->size;
            ctx->free_memory -= block->size;
            *ptr = GET_PTR(block);

            /* magic number */
            block->next = (void *)0x12345678;
            return CM_TRUE;
        } else {
            if (cur->free_offset + size <= MEM_PAGE_SIZE) {
                block = (block_header_t *)((char *)cur + cur->free_offset);
                block->size = size;
                block->offset = (uint16)cur->free_offset;

                cur->free_offset += size;
                cur->free_size -= size;

                ctx->free_memory -= block->size;

                *ptr = GET_PTR(block);
                /* magic number */
                block->next = (void *)0x12345678;
                return CM_TRUE;
            }
        }
        /* remove the page from free list */
        if (cur->prev_free) {
            cur->prev_free->next_free = cur->next_free;
        } else {
            ctx->free_page = cur->next_free;
        }
        if (cur->next_free) {
            cur->next_free->prev_free = cur->prev_free;
        }
        cur->next_free = NULL;
        cur->prev_free = NULL;
        cur = ctx->free_page;
    }
    return CM_FALSE;
}

uint32 sklist_mem_alloc(mem_ctx_t *ctx, uint16 size, void **ptr)
{
    CM_ASSERT(ctx != NULL);
    CM_ASSERT(ptr != NULL);
    page_header_t *cur;
    block_header_t *block;
    size = size + (uint32)sizeof(block_header_t);
    if (sklist_find_free_page(ctx, size, ptr)) {
        return CM_SUCCESS;
    }

    /* add a new free page */
    cur = (page_header_t *)cm_malloc(MEM_PAGE_SIZE);
    if (cur == NULL) {
        return ERR_ALLOC_MEMORY;
    }
    ctx->total_memory += MEM_PAGE_SIZE;
    ctx->free_memory += (MEM_PAGE_SIZE - (uint32)sizeof(page_header_t));
    /* INIT the page header */
    cur->magic = 0x12345678;
    cur->ctx = ctx;
    cur->free_block = NULL;
    cur->free_offset = (int32)sizeof(page_header_t);
    cur->free_size = MEM_PAGE_SIZE - (int32)sizeof(page_header_t);

    cur->next = ctx->head;
    if (ctx->head) {
        ctx->head->prev = cur;
    }
    cur->prev = NULL;
    ctx->head = cur;

    cur->next_free = ctx->free_page;
    if (ctx->free_page) {
        ctx->free_page->prev_free = cur;
    }
    cur->prev_free = NULL;
    ctx->free_page = cur;

    block = (block_header_t *)((char *)cur + cur->free_offset);
    block->size = size;
    block->offset = (uint16)cur->free_offset;

    cur->free_offset += size;
    cur->free_size -= size;

    ctx->free_memory -= block->size;

    *ptr = GET_PTR(block);
    /* magic number */
    block->next = (void *)0x12345678;
    return CM_SUCCESS;
}

void sklist_mem_free(void *ptr)
{
    CM_ASSERT(ptr != NULL);

    page_header_t *page;
    mem_ctx_t *ctx;
    block_header_t *block;
    block = GET_BLOCK_HEADER(ptr);
    page = GET_PAGE_HEADER(block);
    ctx = page->ctx;
    block->next = page->free_block;
    page->free_block = block;
    page->free_size += block->size;

    ctx->free_memory += block->size;
    /* try to remove the page from ctx and release it to system */

    if (page->free_size == (int32)(MEM_PAGE_SIZE - sizeof(page_header_t))) {
        /* remove the page from page list */
        if (page->prev) {
            page->prev->next = page->next;
        } else {
            ctx->head = page->next;
        }
        if (page->next) {
            page->next->prev = page->prev;
        }
        // IF THE PAGE IN FREE LIST
        if (page->next_free != NULL || page->prev_free != NULL || ctx->free_page == page) {
            if (page->prev_free) {
                page->prev_free->next_free = page->next_free;
            } else {
                ctx->free_page = page->next_free;
            }
            if (page->next_free) {
                page->next_free->prev_free = page->prev_free;
            }
        }
        cm_free(page);
        ctx->total_memory -= MEM_PAGE_SIZE;
        ctx->free_memory -= (MEM_PAGE_SIZE - (uint32)sizeof(page_header_t));
        return;
    }

    // IF THE PAGE NOT IN FREE LIST
    if (page->next_free == NULL && page->prev_free == NULL && ctx->free_page != page) {
        /* ADD IT TO THE FREE LIST */
        page->next_free = ctx->free_page;
        if (page->next_free) {
            page->next_free->prev_free = page;
        }
        ctx->free_page = page;
    }
}
