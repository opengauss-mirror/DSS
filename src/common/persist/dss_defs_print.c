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
 * dss_defs_print.c
 *
 *
 * IDENTIFICATION
 *    src/common/persist/dss_defs_print.c
 *
 * -------------------------------------------------------------------------
 */

#include "cm_log.h"
#include "dss_malloc.h"
#include "dss_defs_print.h"

uint8 g_print_level = 0;

void printf_auid(const auid_t *first)
{
    char *tab = dss_get_print_tab(g_print_level);
    (void)printf("%s    auid = %llu\n", tab, *(uint64 *)first);
    (void)printf("%s      volume = %llu\n", tab, (uint64)first->volume);
    (void)printf("%s      au = %llu\n", tab, (long long unsigned int)(first->au));
    (void)printf("%s      block = %llu\n", tab, (uint64)first->block);
    (void)printf("%s      item = %llu\n", tab, (uint64)first->item);
}

void printf_dss_fs_block_list(dss_fs_block_list_t *free)
{
    (void)printf("      count = %llu\n", free->count);

    auid_t *first = &free->first;
    (void)printf("      first = {\n");
    printf_auid(first);
    (void)printf("      }\n");

    auid_t *last = &free->last;
    (void)printf("      last = {\n");
    printf_auid(last);
    (void)printf("      }\n");
}

void printf_dss_fs_aux_root(dss_fs_aux_root_t *root)
{
    (void)printf("    version = %llu\n", root->version);

    dss_fs_block_list_t *free = &root->free;
    (void)printf("    free = {\n");
    printf_dss_fs_block_list(free);
    (void)printf("    }\n");
}

void printf_dss_fs_block_root(dss_fs_block_root_t *root)
{
    (void)printf("    version = %llu\n", root->version);

    dss_fs_block_list_t *free = &root->free;
    (void)printf("    free = {\n");
    printf_dss_fs_block_list(free);
    (void)printf("    }\n");
}

void printf_dss_volume_attr(const dss_volume_attr_t *volume_attrs)
{
    (void)printf("    id = %llu\n", (uint64)volume_attrs->id);
    (void)printf("    size = %llu\n", volume_attrs->size);
    (void)printf("    hwm = %llu\n", volume_attrs->hwm);
    (void)printf("    free = %llu\n", volume_attrs->free);
}

static void printf_dss_au_list(dss_au_list_t *free_list)
{
    (void)printf("      count = %u\n", free_list->count);
    (void)printf("      frist = {\n");
    printf_auid(&free_list->first);
    (void)printf("      }\n");
    (void)printf("      last = {\n");
    printf_auid(&free_list->last);
    (void)printf("      }\n");
}

void printf_dss_au_root(dss_au_root_t *au_root)
{
    (void)printf("    version = %llu\n", au_root->version);
    (void)printf("    free_root = %llu\n", au_root->free_root);
    (void)printf("    count = %llu\n", au_root->count);
    (void)printf("    free_vol_id = %u\n", au_root->free_vol_id);
    (void)printf("    reserve = %u\n", au_root->reserve);

    dss_au_list_t *free_list = &au_root->free_list;
    (void)printf("    free_list = {\n");
    printf_dss_au_list(free_list);
    (void)printf("    }\n");
}

void dss_printf_core_ctrl_base(dss_core_ctrl_t *core_ctrl)
{
    (void)printf("core_ctrl = {\n");
    (void)printf("  checksum = %u\n", core_ctrl->checksum);
    (void)printf("  reserve = %u\n", core_ctrl->reserve);
    (void)printf("  version = %llu\n", core_ctrl->version);
    (void)printf("  au_size = %u\n", core_ctrl->au_size);
    (void)printf("  volume_count = %u\n", core_ctrl->volume_count);
    (void)printf("  fs_block_root = {\n");

    dss_fs_block_root_t *root = (dss_fs_block_root_t *)(core_ctrl->fs_block_root);
    printf_dss_fs_block_root(root);
    (void)printf("  }\n");
    (void)printf("  au_root = {\n");

    dss_au_root_t *au_root = (dss_au_root_t *)(core_ctrl->au_root);
    printf_dss_au_root(au_root);
    (void)printf("  }\n");

    dss_volume_attr_t *volume_attrs = core_ctrl->volume_attrs;
    for (uint32 i = 0; i < DSS_MAX_VOLUMES; ++i) {
        if (i == 0 || volume_attrs->id != 0) {
            (void)printf("  volume_attrs[%u] = {\n", i);
            printf_dss_volume_attr(volume_attrs);
            (void)printf("  }\n");
        }
        volume_attrs++;
        continue;
    }

    (void)printf("}\n");
}

void printf_gft_list(gft_list_t *items)
{
    (void)printf("      count = %u\n", items->count);
    (void)printf("      first = {\n");

    ftid_t *first = &items->first;
    printf_auid(first);
    (void)printf("      }\n");
    (void)printf("      last = {\n");

    ftid_t *last = &items->last;
    printf_auid(last);
    (void)printf("      }\n");
}

void printf_gft_root(gft_root_t *ft_root)
{
    (void)printf("    free_list = {\n");

    gft_list_t *free_list = &ft_root->free_list;
    printf_gft_list(free_list);
    (void)printf("    }\n");
    (void)printf("    items = {\n");

    gft_list_t *items = &ft_root->items;
    printf_gft_list(items);
    (void)printf("    }\n");
    (void)printf("    fid = %llu\n", ft_root->fid);
    (void)printf("    first = {\n");

    dss_block_id_t *block_id_first = &ft_root->first;
    printf_auid(block_id_first);
    (void)printf("    }\n");
    (void)printf("    last = {\n");

    dss_block_id_t *block_id_last = &ft_root->last;
    printf_auid(block_id_last);
    (void)printf("    }\n");
}

void printf_gft_node(gft_node_t *gft_node)
{
    if (gft_node->type == GFT_PATH) {
        (void)printf("  type = GFT_PATH\n");
        gft_list_t *items = &gft_node->items;
        (void)printf("  items = {\n");
        printf_gft_list(items);
        (void)printf("  }\n");
    } else if (gft_node->type == GFT_FILE) {
        (void)printf("  type = GFT_FILE\n");
        dss_block_id_t *entry = &gft_node->entry;
        (void)printf("  entry = {\n");
        printf_auid(entry);
        (void)printf("  }\n");
    } else if (gft_node->type == GFT_LINK) {
        (void)printf("  type = GFT_LINK\n");
        dss_block_id_t *entry = &gft_node->entry;
        (void)printf("  entry = {\n");
        printf_auid(entry);
        (void)printf("  }\n");
    }
    (void)printf("  software_version = %u\n", gft_node->software_version);
    (void)printf("  name = %s\n", gft_node->name);
    (void)printf("  fid = %llu\n", gft_node->fid);
    (void)printf("  flags = %u\n", gft_node->flags);
    (void)printf("  size = %lld\n", gft_node->size);
    (void)printf("  written_size = %llu\n", gft_node->written_size);
    (void)printf("  parent = {\n");
    printf_auid(&gft_node->parent);
    (void)printf("  }\n");
    (void)printf("  file_ver = %llu\n", gft_node->file_ver);
    (void)printf("  min_inited_size = %llu\n", gft_node->min_inited_size);
    char time[512];
    (void)cm_time2str(gft_node->create_time, "YYYY-MM-DD HH24:mi:ss", time, sizeof(time));
    (void)printf("  create_time = %s\n", time);
    (void)cm_time2str(gft_node->update_time, "YYYY-MM-DD HH24:mi:ss", time, sizeof(time));
    (void)printf("  update_time = %s\n", time);

    auid_t *id = &gft_node->id;
    (void)printf("  id = {\n");
    printf_auid(id);
    (void)printf("  }\n");

    auid_t *next = &gft_node->next;
    (void)printf("  next= {\n");
    printf_auid(next);
    (void)printf("  }\n");

    auid_t *prev = &gft_node->prev;
    (void)printf("  prev = {\n");
    printf_auid(prev);
    (void)printf("  }\n");
}
