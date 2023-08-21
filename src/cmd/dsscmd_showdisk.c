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
 * dsscmd_showdisk.c
 *
 *
 * IDENTIFICATION
 *    src/cmd/dsscmd_showdisk.c
 *
 * -------------------------------------------------------------------------
 */

#include "cm_log.h"
#include "dss_diskgroup.h"
#include "dss_alloc_unit.h"
#include "dss_malloc.h"

#define DSS_DEFAULT_NODE_ID 0

static void printf_dss_volume_type(const dss_volume_type_t *vol_type)
{
    printf("    type = %u\n", vol_type->type);
    printf("    id = %u\n", vol_type->id);
    printf("    entry_volume_name = %s\n", vol_type->entry_volume_name);
}

static status_t printf_dss_vg_header(const dss_vg_info_item_t *vg_item, dss_volume_t *volume)
{
    status_t status;
    int64 offset = (int64)OFFSET_OF(dss_ctrl_t, vg_info);
    if (offset % DSS_DISK_UNIT_SIZE != 0) {
        DSS_PRINT_ERROR("offset must be align %d.\n", DSS_DISK_UNIT_SIZE);
        return CM_ERROR;
    }

    dss_volume_header_t *vg_header = (dss_volume_header_t *)cm_malloc_align(DSS_ALIGN_SIZE, DSS_ALIGN_SIZE);
    if (vg_header == NULL) {
        DSS_THROW_ERROR(ERR_ALLOC_MEMORY, DSS_ALIGN_SIZE, "dss_core_ctrl_t");
        return CM_ERROR;
    }

    status = dss_read_volume(volume, offset, vg_header, (int32)DSS_ALIGN_SIZE);
    if (status != CM_SUCCESS) {
        DSS_PRINT_ERROR("Failed to read file %s.\n", vg_item->entry_path);
        DSS_FREE_POINT(vg_header);
        return status;
    }

    printf("vg_header = {\n");
    printf("  checksum = %u\n", vg_header->checksum);
    printf("  vol_type = {\n");

    dss_volume_type_t *vol_type = &vg_header->vol_type;
    printf_dss_volume_type(vol_type);
    printf("  }\n");
    printf("  vg_name = %s\n", vg_header->vg_name);
    printf("  valid_flag = %u\n", vg_header->valid_flag);
    printf("  software_version = %u\n", vg_header->software_version);

    date_t date = cm_timeval2date(vg_header->create_time);
    time_t time = cm_date2time(date);
    char create_time[512];
    status = cm_time2str(time, "YYYY-MM-DD HH24:mi:ss", create_time, sizeof(create_time));
    printf("  create_time = %s\n", create_time);
    printf("}\n");
    DSS_FREE_POINT(vg_header);
    return status;
}

static void printf_auid(const auid_t *first)
{
    printf("        volume = %llu\n", (uint64)first->volume);
    printf("        au = %llu\n", (long long unsigned int)(first->au));
    printf("        block = %llu\n", (uint64)first->block);
    printf("        item = %llu\n", (uint64)first->item);
}

static void printf_dss_fs_block_list(dss_fs_block_list_t *free)
{
    printf("      count = %llu\n", free->count);

    auid_t *first = &free->first;
    printf("      first = {\n");
    printf_auid(first);
    printf("      }\n");

    auid_t *last = &free->last;
    printf("      last = {\n");
    printf_auid(last);
    printf("      }\n");
}

static void printf_dss_fs_block_root(dss_fs_block_root_t *root)
{
    printf("    version = %llu\n", root->version);

    dss_fs_block_list_t *free = &root->free;
    printf("    free = {\n");
    printf_dss_fs_block_list(free);
    printf("    }\n");
}

static void printf_dss_au_list(dss_au_list_t *free_list)
{
    printf("      count = %u\n", free_list->count);
    printf("      frist = {\n");
    printf_auid(&free_list->first);
    printf("      }\n");
    printf("      last = {\n");
    printf_auid(&free_list->last);
    printf("      }\n");
}

static void printf_dss_au_root(dss_au_root_t *au_root)
{
    printf("    version = %llu\n", au_root->version);
    printf("    free_root = %llu\n", au_root->free_root);
    printf("    count = %llu\n", au_root->count);
    printf("    free_vol_id = %u\n", au_root->free_vol_id);
    printf("    count = %u\n", au_root->reserve);

    dss_au_list_t *free_list = &au_root->free_list;
    printf("    free_list = {\n");
    printf_dss_au_list(free_list);
    printf("    }\n");
}

static void printf_dss_volume_attr(const dss_volume_attr_t *volume_attrs)
{
    printf("    id = %llu\n", (uint64)volume_attrs->id);
    printf("    size = %llu\n", volume_attrs->size);
    printf("    hwm = %llu\n", volume_attrs->hwm);
    printf("    free = %llu\n", volume_attrs->free);
}

status_t printf_dss_core_ctrl(const dss_vg_info_item_t *vg_item, dss_volume_t *volume)
{
    status_t status;
    int64 offset = (int64)OFFSET_OF(dss_ctrl_t, core);
    if (offset % DSS_DISK_UNIT_SIZE != 0) {
        DSS_PRINT_ERROR("offset must be align %d.\n", DSS_DISK_UNIT_SIZE);
        return CM_ERROR;
    }

    dss_core_ctrl_t *core_ctrl = (dss_core_ctrl_t *)cm_malloc_align(DSS_ALIGN_SIZE, DSS_CORE_CTRL_SIZE);
    if (core_ctrl == NULL) {
        DSS_THROW_ERROR(ERR_ALLOC_MEMORY, DSS_CORE_CTRL_SIZE, "dss_core_ctrl_t");
        return CM_ERROR;
    }

    status = dss_read_volume(volume, offset, core_ctrl, (int32)DSS_CORE_CTRL_SIZE);
    if (status != CM_SUCCESS) {
        DSS_PRINT_ERROR("Failed to read file %s.\n", vg_item->entry_path);
        DSS_FREE_POINT(core_ctrl);
        return status;
    }

    printf("core_ctrl = {\n");
    printf("  checknum = %u\n", core_ctrl->checksum);
    printf("  reserve = %u\n", core_ctrl->reserve);
    printf("  version = %llu\n", core_ctrl->version);
    printf("  au_size = %u\n", core_ctrl->au_size);
    printf("  volume_count = %u\n", core_ctrl->volume_count);
    printf("  fs_block_root = {\n");

    dss_fs_block_root_t *root = (dss_fs_block_root_t *)(core_ctrl->fs_block_root);
    printf_dss_fs_block_root(root);
    printf("  }\n");
    printf("  au_root = {\n");

    dss_au_root_t *au_root = (dss_au_root_t *)(core_ctrl->au_root);
    printf_dss_au_root(au_root);
    printf("  }\n");

    dss_volume_attr_t *volume_attrs = core_ctrl->volume_attrs;
    for (uint32 i = 0; i < DSS_MAX_VOLUMES; ++i) {
        if (i == 0 || volume_attrs->id != 0) {
            printf("  volume_attrs[%u] = {\n", i);
            printf_dss_volume_attr(volume_attrs);
            printf("  }\n");
        }
        volume_attrs++;
        continue;
    }

    printf("}\n");
    DSS_FREE_POINT(core_ctrl);
    return CM_SUCCESS;
}

static void printf_dss_volume_def(const dss_volume_def_t *volume_defs)
{
    printf("    id = %llu\n", (uint64)volume_defs->id);
    printf("    flag = %llu\n", (uint64)volume_defs->flag);
    printf("    version = %llu\n", (uint64)volume_defs->version);
    printf("    name = %s\n", volume_defs->name);
    printf("    code = %s\n", volume_defs->code);
    printf("    resv = %s\n", volume_defs->resv);
}

static status_t printf_dss_volume_ctrl(const dss_vg_info_item_t *vg_item, dss_volume_t *volume)
{
    status_t status;
    int64 offset = (int64)OFFSET_OF(dss_ctrl_t, volume);
    if (offset % DSS_DISK_UNIT_SIZE != 0) {
        DSS_PRINT_ERROR("offset must be align %d.\n", DSS_DISK_UNIT_SIZE);
        return CM_ERROR;
    }

    dss_volume_ctrl_t *volume_ctrl = (dss_volume_ctrl_t *)cm_malloc_align(DSS_ALIGN_SIZE, DSS_VOLUME_CTRL_SIZE);
    if (volume_ctrl == NULL) {
        DSS_THROW_ERROR(ERR_ALLOC_MEMORY, DSS_VOLUME_CTRL_SIZE, "dss_volume_ctrl_t");
        return CM_ERROR;
    }

    status = dss_read_volume(volume, offset, volume_ctrl, (int32)DSS_VOLUME_CTRL_SIZE);
    if (status != CM_SUCCESS) {
        DSS_PRINT_ERROR("Failed to read file %s.\n", vg_item->entry_path);
        DSS_FREE_POINT(volume_ctrl);
        return status;
    }

    printf("volume_ctrl = {\n");
    printf("  checknum = %u\n", volume_ctrl->checksum);
    printf("  rsvd = %u\n", volume_ctrl->rsvd);
    printf("  version = %llu\n", volume_ctrl->version);
    dss_volume_def_t *volume_defs = volume_ctrl->defs;
    for (uint32 i = 0; i < DSS_MAX_VOLUMES; ++i) {
        if (volume_defs->flag != VOLUME_FREE) {
            printf("  volume_defs[%u] = {\n", i);
            printf_dss_volume_def(volume_defs);
            printf("  }\n");
        }
        volume_defs++;
        continue;
    }

    printf("}\n");
    DSS_FREE_POINT(volume_ctrl);
    return CM_SUCCESS;
}

static void printf_common_block_t(const dss_common_block_t *common)
{
    printf("      checksum = %u\n", common->checksum);
    printf("      type = %u\n", common->type);
    printf("      version = %llu\n", common->version);
    printf("      block_id = {\n");
    printf_auid(&common->id);
    printf("      }\n");
}

static void printf_ft_block(dss_ft_block_t *ft_block)
{
    printf("    block_common = {\n");

    dss_common_block_t *common = &ft_block->common;
    printf_common_block_t(common);
    printf("    }\n");

    printf("    ft_block_node_num = %u\n", ft_block->node_num);
    printf("    ft_block_next = {\n");

    dss_block_id_t *next = &ft_block->next;
    printf_auid(next);
    printf("    }\n");
}

static void printf_gft_list(gft_list_t *items)
{
    printf("      count = %u\n", items->count);
    printf("      first = {\n");

    ftid_t *first = &items->first;
    printf_auid(first);
    printf("      }\n");
    printf("      last = {\n");

    ftid_t *last = &items->last;
    printf_auid(last);
    printf("      }\n");
}

static void printf_gft_root(gft_root_t *ft_root)
{
    printf("    ft_root_free_list = {\n");

    gft_list_t *free_list = &ft_root->free_list;
    printf_gft_list(free_list);
    printf("    }\n");
    printf("    ft_root_items = {\n");

    gft_list_t *items = &ft_root->items;
    printf_gft_list(items);
    printf("    }\n");
    printf("    fid = %llu\n", ft_root->fid);
    printf("    block_id_first = {\n");

    dss_block_id_t *block_id_first = &ft_root->first;
    printf_auid(block_id_first);
    printf("    }\n");
    printf("    block_id_last = {\n");

    dss_block_id_t *block_id_last = &ft_root->last;
    printf_auid(block_id_last);
    printf("    }\n");
}

static void printf_root_ft_header(dss_root_ft_header_t *root_ft_header)
{
    printf("    block_common = {\n");

    dss_common_block_t *common = &root_ft_header->common;
    printf_common_block_t(common);
    printf("    }\n");
    printf("    ft_block_node_num = %u\n", root_ft_header->node_num);
    printf("    ft_block_next = {\n");

    dss_block_id_t *next = &root_ft_header->next;
    printf_auid(next);
    printf("    }\n");
}

static status_t printf_root_ft_block(const dss_vg_info_item_t *vg_item, dss_volume_t *volume)
{
    status_t status;
    int64 offset = (int64)OFFSET_OF(dss_ctrl_t, root);
    if (offset % DSS_DISK_UNIT_SIZE != 0) {
        DSS_PRINT_ERROR("offset must be align %d.\n", DSS_DISK_UNIT_SIZE);
        return CM_ERROR;
    }

    char *root = (char *)cm_malloc_align(DSS_ALIGN_SIZE, DSS_BLOCK_SIZE);
    if (root == NULL) {
        DSS_THROW_ERROR(ERR_ALLOC_MEMORY, DSS_BLOCK_SIZE, "root");
        return CM_ERROR;
    }

    status = dss_read_volume(volume, offset, root, (int32)DSS_BLOCK_SIZE);
    if (status != CM_SUCCESS) {
        DSS_PRINT_ERROR("Failed to read file %s.\n", vg_item->entry_path);
        DSS_FREE_POINT(root);
        return status;
    }

    dss_root_ft_block_t *root_ft_block = (dss_root_ft_block_t *)(root);
    printf("root_ft_block = {\n");

    dss_root_ft_header_t *ft_block = &root_ft_block->ft_block;
    printf("  ft_block = {\n");
    printf_root_ft_header(ft_block);
    printf("  }\n");

    gft_root_t *ft_root = &root_ft_block->ft_root;
    printf("  ft_root = {\n");
    printf_gft_root(ft_root);
    printf("  }\n");
    printf("}\n");
    DSS_FREE_POINT(root);
    return CM_SUCCESS;
}

status_t dss_read_meta_from_disk(dss_vg_info_item_t *vg_item, const char *struct_name)
{
    dss_volume_t volume;
    status_t status;
    status = dss_open_volume(vg_item->entry_path, NULL, DSS_CLI_OPEN_FLAG, &volume);
    DSS_RETURN_IFERR2(status, DSS_PRINT_ERROR("Failed to open file %s.\n", vg_item->entry_path));

    if (strcmp("vg_header", struct_name) == 0) {
        status = printf_dss_vg_header(vg_item, &volume);
        DSS_RETURN_IFERR3(status, DSS_PRINT_ERROR("Failed to printf metadata vg_header.\n"), dss_close_volume(&volume));
    } else if (strcmp("core_ctrl", struct_name) == 0) {
        status = printf_dss_core_ctrl(vg_item, &volume);
        DSS_RETURN_IFERR3(status, DSS_PRINT_ERROR("Failed to printf metadata core_ctrl.\n"), dss_close_volume(&volume));
    } else if (strcmp("volume_ctrl", struct_name) == 0) {
        status = printf_dss_volume_ctrl(vg_item, &volume);
        DSS_RETURN_IFERR3(
            status, DSS_PRINT_ERROR("Failed to printf metadata volume_ctrl.\n"), dss_close_volume(&volume));
    } else if (strcmp("root_ft_block", struct_name) == 0) {
        status = printf_root_ft_block(vg_item, &volume);
        DSS_RETURN_IFERR3(
            status, DSS_PRINT_ERROR("Failed to printf metadata root_ft_block.\n"), dss_close_volume(&volume));
    } else {
        dss_close_volume(&volume);
        DSS_PRINT_ERROR("Incorrect input, %s is not in core_ctrl vg_header volume_ctrl root_ft_block.\n", struct_name);
        return CM_ERROR;
    }

    dss_close_volume(&volume);
    return CM_SUCCESS;
}

static int64 dss_get_ftb_offset(const dss_core_ctrl_t *core_ctrl, const dss_block_id_t *id)
{
    if ((id->au) == 0) {
        return (int64)DSS_CTRL_ROOT_OFFSET;
    }
    return (int64)((uint64)id->au * core_ctrl->au_size + (uint64)DSS_BLOCK_SIZE * id->block);
}

static void printf_gft_node(gft_node_t *gft_node)
{
    if (gft_node->type == GFT_PATH) {
        printf("  type = GFT_PATH\n");
        gft_list_t *items = &gft_node->items;
        printf("  items = {\n");
        printf_gft_list(items);
        printf("  }\n");
    } else if (gft_node->type == GFT_FILE) {
        printf("  type = GFT_FILE\n");
        dss_block_id_t *entry = &gft_node->entry;
        printf("  entry = {\n");
        printf_auid(entry);
        printf("  }\n");
    } else if (gft_node->type == GFT_LINK) {
        printf("  type = GFT_LINK\n");
        dss_block_id_t *entry = &gft_node->entry;
        printf("  entry = {\n");
        printf_auid(entry);
        printf("  }\n");
    }

    printf("  name = %s\n", gft_node->name);
    printf("  fid = %llu\n", gft_node->fid);
    printf("  flags = %u\n", gft_node->flags);
    printf("  size = %llu\n", gft_node->size);

    char time[512];
    (void)cm_time2str(gft_node->create_time, "YYYY-MM-DD HH24:mi:ss", time, sizeof(time));
    printf("  create_time = %s\n", time);
    (void)cm_time2str(gft_node->update_time, "YYYY-MM-DD HH24:mi:ss", time, sizeof(time));
    printf("  update_time = %s\n", time);

    auid_t *id = &gft_node->id;
    printf("  id = {\n");
    printf_auid(id);
    printf("  }\n");

    auid_t *next = &gft_node->next;
    printf("  next= {\n");
    printf_auid(next);
    printf("  }\n");

    auid_t *prev = &gft_node->prev;
    printf("  prev = {\n");
    printf_auid(prev);
    printf("  }\n");
}

static status_t print_ftn_by_id(dss_volume_t volume, char *block, uint64 node_id)
{
    dss_ft_block_t *file_table_block = (dss_ft_block_t *)block;
    printf("file_table_block = {\n");
    printf_ft_block(file_table_block);
    printf("}\n\n");

    uint32 size = (DSS_BLOCK_SIZE - sizeof(dss_ft_block_t)) / sizeof(gft_node_t);
    gft_node_t *node = NULL;

    if (node_id == DSS_DEFAULT_NODE_ID) {
        for (uint32 i = 0; i < size; ++i) {
            node = (gft_node_t *)(block + sizeof(dss_ft_block_t) + i * sizeof(gft_node_t));
            printf("gft_node[%u] = {\n", i);
            printf_gft_node(node);
            printf("}\n");
        }
    } else {
        if (node_id > size - 1) {
            DSS_PRINT_ERROR("node_id should be in range 0-%u.\n", size - 1);
            dss_close_volume(&volume);
            DSS_FREE_POINT(block);
            return CM_ERROR;
        }
        node = (gft_node_t *)(block + sizeof(dss_ft_block_t) + node_id * sizeof(gft_node_t));
        printf("gft_node[%llu] = {\n", node_id);
        printf_gft_node(node);
        printf("}\n");
    }

    return CM_SUCCESS;
}

status_t printf_dss_file_table_block(
    dss_volume_ctrl_t *volume_ctrl, dss_core_ctrl_t *core_ctrl, dss_block_id_t *id, uint64 node_id)
{
    int64 offset;
    dss_volume_t volume;
    status_t status = dss_open_volume(volume_ctrl->defs[id->volume].name, NULL, DSS_CLI_OPEN_FLAG, &volume);
    if (status != CM_SUCCESS) {
        DSS_PRINT_ERROR("Failed to open file with volume handle:%d.\n", volume.handle);
        return status;
    }

    offset = dss_get_ftb_offset(core_ctrl, id);
    if (offset % DSS_DISK_UNIT_SIZE != 0) {
        DSS_PRINT_ERROR("offset must be align %d.\n", DSS_DISK_UNIT_SIZE);
        dss_close_volume(&volume);
        return CM_ERROR;
    }

    char *block = (char *)cm_malloc_align(DSS_ALIGN_SIZE, DSS_BLOCK_SIZE);
    if (block == NULL) {
        DSS_THROW_ERROR(ERR_ALLOC_MEMORY, DSS_BLOCK_SIZE, "block");
        dss_close_volume(&volume);
        return CM_ERROR;
    }

    status = dss_read_volume(&volume, offset, block, (int32)DSS_BLOCK_SIZE);
    if (status != CM_SUCCESS) {
        DSS_PRINT_ERROR("Failed to read file %d.n", volume.handle);
        dss_close_volume(&volume);
        DSS_FREE_POINT(block);
        return status;
    }

    DSS_RETURN_IF_ERROR(print_ftn_by_id(volume, block, node_id));
    dss_close_volume(&volume);
    DSS_FREE_POINT(block);
    return status;
}

static void printf_fs_block_header(dss_fs_block_header *fs_block_header)
{
    printf("    block_common = {\n");
    dss_common_block_t *common = &fs_block_header->common;
    printf_common_block_t(common);
    printf("    }\n");
    printf("    fs_block_next = {\n");

    dss_block_id_t *next = &fs_block_header->next;
    printf_auid(next);
    printf("    }\n");
    printf("    used_num = %hu\n", fs_block_header->used_num);
    printf("    total_num = %hu\n", fs_block_header->total_num);
    printf("    reserve = %u\n", fs_block_header->reserve);
}

static void printf_fs_block(dss_fs_block_t *fs_block)
{
    printf("  fs_block_header = {\n");
    dss_fs_block_header *fs_block_header = &fs_block->head;
    printf_fs_block_header(fs_block_header);
    printf("  }\n");
    printf("  bitmap[0] = {\n");

    dss_block_id_t *bitmap = &fs_block->bitmap[0];
    printf_auid(bitmap);
    printf("  }\n");
}

static int64 dss_get_fsb_offset(const dss_core_ctrl_t *core_ctrl, const dss_block_id_t *id)
{
    return (int64)id->au * core_ctrl->au_size + (int64)DSS_FILE_SPACE_BLOCK_SIZE * id->block;
}

static status_t print_fsb_by_id(dss_volume_t volume, char *block, uint64 node_id)
{
    dss_fs_block_t *file_space_block = (dss_fs_block_t *)block;
    printf("file_space_block = {\n");
    printf_fs_block(file_space_block);
    printf("}\n\n");

    uint32 size = (DSS_FILE_SPACE_BLOCK_SIZE - sizeof(dss_fs_block_t)) / sizeof(dss_block_id_t);
    dss_block_id_t *node = NULL;

    if (node_id == DSS_DEFAULT_NODE_ID) {
        for (uint32 i = 0; i < size; ++i) {
            node = (dss_block_id_t *)(block + sizeof(dss_fs_block_t) + i * sizeof(dss_block_id_t));
            printf("bitmap[%u] = {\n", i);
            printf_auid(node);
            printf("}\n");
        }
    } else {
        if (node_id > size - 1) {
            DSS_PRINT_ERROR("node_id should be in range 0-%u.\n", size - 1);
            return CM_ERROR;
        }
        node = (dss_block_id_t *)(block + sizeof(dss_fs_block_t) + node_id * sizeof(dss_block_id_t));
        printf("bitmap[%llu] = {\n", node_id);
        printf_auid(node);
        printf("}\n");
    }

    return CM_SUCCESS;
}

static status_t printf_dss_file_space_block(
    dss_volume_ctrl_t *volume_ctrl, dss_core_ctrl_t *core_ctrl, dss_block_id_t *id, uint64 node_id)
{
    status_t status;
    int64 offset;
    dss_volume_t volume;
    status = dss_open_volume(volume_ctrl->defs[id->volume].name, NULL, DSS_CLI_OPEN_FLAG, &volume);
    DSS_RETURN_IFERR2(status, DSS_PRINT_ERROR("Failed to open file with volume handle:%d.\n", volume.handle));

    offset = dss_get_fsb_offset(core_ctrl, id);
    bool32 result = (bool32)(offset % DSS_DISK_UNIT_SIZE == 0);
    DSS_RETURN_IF_FALSE3(
        result, DSS_PRINT_ERROR("offset must be align %d.\n", DSS_DISK_UNIT_SIZE), dss_close_volume(&volume));

    char *block = (char *)cm_malloc_align(DSS_ALIGN_SIZE, DSS_FILE_SPACE_BLOCK_SIZE);
    result = (bool32)(block != NULL);
    DSS_RETURN_IF_FALSE3(
        result, DSS_THROW_ERROR(ERR_ALLOC_MEMORY, DSS_FILE_SPACE_BLOCK_SIZE, "block"), dss_close_volume(&volume));

    status = dss_read_volume(&volume, offset, block, (int32)DSS_FILE_SPACE_BLOCK_SIZE);
    if (status != CM_SUCCESS) {
        DSS_PRINT_ERROR("Failed to read file %d.\n", volume.handle);
        dss_close_volume(&volume);
        DSS_FREE_POINT(block);
        return status;
    }
    status = print_fsb_by_id(volume, block, node_id);
    dss_close_volume(&volume);
    DSS_FREE_POINT(block);
    return status;
}

static int64 dss_get_type_offset(const dss_core_ctrl_t *core_ctrl, const dss_block_id_t *id)
{
    return (int64)((uint64)id->au * core_ctrl->au_size);
}

static status_t dss_get_block_type(
    dss_volume_ctrl_t *volume_ctrl, dss_core_ctrl_t *core_ctrl, dss_block_id_t *id, uint32_t *type)
{
    status_t status;
    int64 offset;
    dss_volume_t volume;
    status = dss_open_volume(volume_ctrl->defs[id->volume].name, NULL, DSS_CLI_OPEN_FLAG, &volume);
    DSS_RETURN_IFERR3(status, DSS_PRINT_ERROR("Failed to open file with volume handle:%d.\n", volume.handle),
        dss_close_volume(&volume));

    offset = dss_get_type_offset(core_ctrl, id);
    bool32 result = (bool32)(offset % DSS_DISK_UNIT_SIZE == 0);
    DSS_RETURN_IF_FALSE3(
        result, DSS_PRINT_ERROR("offset must be align %d.\n", DSS_DISK_UNIT_SIZE), dss_close_volume(&volume));

    dss_common_block_t *block_type = (dss_common_block_t *)cm_malloc_align(DSS_ALIGN_SIZE, core_ctrl->au_size);
    result = (bool32)(block_type != NULL);
    DSS_RETURN_IF_FALSE3(
        result, DSS_THROW_ERROR(ERR_ALLOC_MEMORY, core_ctrl->au_size, "block_type"), dss_close_volume(&volume));

    status = dss_read_volume(&volume, offset, block_type, (int32)core_ctrl->au_size);
    if (status != CM_SUCCESS) {
        DSS_PRINT_ERROR("Failed to read file %d.\n", volume.handle);
        dss_close_volume(&volume);
        DSS_FREE_POINT(block_type);
        return status;
    }

    *type = block_type->type;
    dss_close_volume(&volume);
    DSS_FREE_POINT(block_type);
    return CM_SUCCESS;
}

static status_t print_block_by_type(
    dss_volume_ctrl_t *volume_ctrl, dss_core_ctrl_t *core_ctrl, uint64 block_id, uint64 node_id)
{
    dss_block_id_t *id = (dss_block_id_t *)&block_id;
    printf("id = %llu : \n", block_id);

    if (volume_ctrl->defs[id->volume].flag == VOLUME_FREE) {
        DSS_PRINT_ERROR("volume doesn't exist,voleme_id:%llu.\n", (uint64)id->volume);
        return CM_ERROR;
    }
    uint32 block_type = 0;
    status_t status = dss_get_block_type(volume_ctrl, core_ctrl, id, &block_type);
    if (status != CM_SUCCESS) {
        return status;
    }

    if ((block_type != DSS_BLOCK_TYPE_FT) && (block_type != DSS_BLOCK_TYPE_FS)) {
        DSS_PRINT_ERROR("block_id is invalid, block type:%u.\n", block_type);
        return CM_ERROR;
    }

    if (block_type == DSS_BLOCK_TYPE_FT) {
        status = printf_dss_file_table_block(volume_ctrl, core_ctrl, id, node_id);
        if (status != CM_SUCCESS) {
            DSS_PRINT_ERROR("Failed to printf file table block with block_id:%llu.\n", block_id);
            return status;
        }
    } else {
        status = printf_dss_file_space_block(volume_ctrl, core_ctrl, id, node_id);
        if (status != CM_SUCCESS) {
            DSS_PRINT_ERROR("Failed to printf file space block with block_id:%llu.\n", block_id);
            return status;
        }
    }

    return CM_SUCCESS;
}

static status_t get_volume_core_ctrl(dss_vg_info_item_t *vg_item, dss_volume_t *volume, dss_core_ctrl_t *core_ctrl)
{
    status_t status = dss_open_volume(vg_item->entry_path, NULL, DSS_CLI_OPEN_FLAG, volume);
    DSS_RETURN_IFERR2(status, DSS_PRINT_ERROR("Failed to open file %s.\n", vg_item->entry_path));

    int64 offset = (int64)OFFSET_OF(dss_ctrl_t, core);
    bool32 result = (bool32)(offset % DSS_DISK_UNIT_SIZE == 0);
    DSS_RETURN_IF_FALSE3(
        result, DSS_PRINT_ERROR("offset must be align %d.\n", DSS_DISK_UNIT_SIZE), dss_close_volume(volume));

    status = dss_read_volume(volume, offset, core_ctrl, (int32)DSS_CORE_CTRL_SIZE);
    DSS_RETURN_IFERR3(
        status, DSS_PRINT_ERROR("Failed to read file %s.\n", vg_item->entry_path), dss_close_volume(volume));
    return CM_SUCCESS;
}

status_t printf_dss_block_with_blockid(dss_vg_info_item_t *vg_item, uint64 block_id, uint64 node_id)
{
    dss_volume_t volume;
    dss_core_ctrl_t *core_ctrl = (dss_core_ctrl_t *)cm_malloc_align(DSS_ALIGN_SIZE, DSS_CORE_CTRL_SIZE);
    bool32 result = (bool32)(core_ctrl != NULL);
    DSS_RETURN_IF_FALSE2(result, DSS_THROW_ERROR(ERR_ALLOC_MEMORY, DSS_CORE_CTRL_SIZE, "dss_core_ctrl_t"));

    status_t status = get_volume_core_ctrl(vg_item, &volume, core_ctrl);
    DSS_RETURN_IFERR3(
        status, DSS_PRINT_ERROR("Failed to get volume %s.\n", vg_item->entry_path), DSS_FREE_POINT(core_ctrl));

    int64 offset = (int64)OFFSET_OF(dss_ctrl_t, volume);
    if (offset % DSS_DISK_UNIT_SIZE != 0) {
        DSS_PRINT_ERROR("offset must be align %d.\n", DSS_DISK_UNIT_SIZE);
        DSS_FREE_POINT(core_ctrl);
        dss_close_volume(&volume);
        return CM_ERROR;
    }

    dss_volume_ctrl_t *volume_ctrl = (dss_volume_ctrl_t *)cm_malloc_align(DSS_ALIGN_SIZE, DSS_VOLUME_CTRL_SIZE);
    if (volume_ctrl == NULL) {
        DSS_THROW_ERROR(ERR_ALLOC_MEMORY, DSS_VOLUME_CTRL_SIZE, "dss_volume_ctrl_t");
        DSS_FREE_POINT(core_ctrl);
        dss_close_volume(&volume);
        return CM_ERROR;
    }

    status = dss_read_volume(&volume, offset, volume_ctrl, (int32)DSS_VOLUME_CTRL_SIZE);
    if (status != CM_SUCCESS) {
        DSS_PRINT_ERROR("Failed to read file %s.\n", vg_item->entry_path);
        DSS_FREE_POINT(core_ctrl);
        DSS_FREE_POINT(volume_ctrl);
        dss_close_volume(&volume);
        return status;
    }

    status = print_block_by_type(volume_ctrl, core_ctrl, block_id, node_id);
    dss_close_volume(&volume);
    DSS_FREE_POINT(core_ctrl);
    DSS_FREE_POINT(volume_ctrl);
    return status;
}
