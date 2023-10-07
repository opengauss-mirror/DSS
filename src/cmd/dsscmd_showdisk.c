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

#include "dsscmd_showdisk.h"
#include "cm_log.h"
#include "dss_diskgroup.h"
#include "dss_alloc_unit.h"
#include "dss_malloc.h"
#include "dss_meta_buf.h"
#include "dss_file.h"

#define DSS_DEFAULT_NODE_ID 0
#define DSS_SECOND_PRINT_LEVEL 2

static uint8 g_print_level = 0;

static void printf_dss_volume_type(const dss_volume_type_t *vol_type)
{
    (void)printf("    type = %u\n", vol_type->type);
    (void)printf("    id = %u\n", vol_type->id);
    (void)printf("    entry_volume_name = %s\n", vol_type->entry_volume_name);
}

static status_t dss_printf_vg_header(const dss_vg_info_item_t *vg_item, dss_volume_t *volume)
{
    status_t status;
    int64 offset = (int64)OFFSET_OF(dss_ctrl_t, vg_info);
    if (offset % DSS_DISK_UNIT_SIZE != 0) {
        DSS_PRINT_ERROR("offset must be align %d.\n", DSS_DISK_UNIT_SIZE);
        return CM_ERROR;
    }
    dss_volume_header_t *vg_header = NULL;
    if (vg_item->from_type == FROM_DISK) {
        vg_header = (dss_volume_header_t *)cm_malloc_align(DSS_ALIGN_SIZE, DSS_ALIGN_SIZE);
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
    } else {
        vg_header = &vg_item->dss_ctrl->vg_info;
    }
    (void)printf("vg_header = {\n");
    (void)printf("  checksum = %u\n", vg_header->checksum);
    (void)printf("  vol_type = {\n");

    dss_volume_type_t *vol_type = &vg_header->vol_type;
    printf_dss_volume_type(vol_type);
    (void)printf("  }\n");
    (void)printf("  vg_name = %s\n", vg_header->vg_name);
    (void)printf("  valid_flag = %u\n", vg_header->valid_flag);
    (void)printf("  software_version = %u\n", vg_header->software_version);

    date_t date = cm_timeval2date(vg_header->create_time);
    time_t time = cm_date2time(date);
    char create_time[512];
    status = cm_time2str(time, "YYYY-MM-DD HH24:mi:ss", create_time, sizeof(create_time));
    (void)printf("  create_time = %s\n", create_time);
    (void)printf("}\n");
    if (vg_item->from_type == FROM_DISK) {
        DSS_FREE_POINT(vg_header);
    }
    return status;
}

static void printf_auid(const auid_t *first)
{
    char *tab = dss_get_print_tab(g_print_level);
    (void)printf("%s    auid = %llu\n", tab, *(uint64 *)first);
    (void)printf("%s      volume = %llu\n", tab, (uint64)first->volume);
    (void)printf("%s      au = %llu\n", tab, (long long unsigned int)(first->au));
    (void)printf("%s      block = %llu\n", tab, (uint64)first->block);
    (void)printf("%s      item = %llu\n", tab, (uint64)first->item);
}

static void printf_dss_fs_block_list(dss_fs_block_list_t *free)
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

static void printf_dss_fs_block_root(dss_fs_block_root_t *root)
{
    (void)printf("    version = %llu\n", root->version);

    dss_fs_block_list_t *free = &root->free;
    (void)printf("    free = {\n");
    printf_dss_fs_block_list(free);
    (void)printf("    }\n");
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

static void printf_dss_au_root(dss_au_root_t *au_root)
{
    (void)printf("    version = %llu\n", au_root->version);
    (void)printf("    free_root = %llu\n", au_root->free_root);
    (void)printf("    count = %llu\n", au_root->count);
    (void)printf("    free_vol_id = %u\n", au_root->free_vol_id);
    (void)printf("    count = %u\n", au_root->reserve);

    dss_au_list_t *free_list = &au_root->free_list;
    (void)printf("    free_list = {\n");
    printf_dss_au_list(free_list);
    (void)printf("    }\n");
}

static void printf_dss_volume_attr(const dss_volume_attr_t *volume_attrs)
{
    (void)printf("    id = %llu\n", (uint64)volume_attrs->id);
    (void)printf("    size = %llu\n", volume_attrs->size);
    (void)printf("    hwm = %llu\n", volume_attrs->hwm);
    (void)printf("    free = %llu\n", volume_attrs->free);
}

status_t dss_printf_core_ctrl(dss_vg_info_item_t *vg_item, dss_volume_t *volume)
{
    status_t status;
    int64 offset = (int64)OFFSET_OF(dss_ctrl_t, core);
    if (offset % DSS_DISK_UNIT_SIZE != 0) {
        DSS_PRINT_ERROR("offset must be align %d.\n", DSS_DISK_UNIT_SIZE);
        return CM_ERROR;
    }
    dss_core_ctrl_t *core_ctrl = NULL;
    if (vg_item->from_type == FROM_DISK) {
        core_ctrl = (dss_core_ctrl_t *)cm_malloc_align(DSS_ALIGN_SIZE, DSS_CORE_CTRL_SIZE);
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
    } else {
        core_ctrl = &vg_item->dss_ctrl->core;
    }

    (void)printf("core_ctrl = {\n");
    (void)printf("  checknum = %u\n", core_ctrl->checksum);
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
    if (vg_item->from_type == FROM_DISK) {
        DSS_FREE_POINT(core_ctrl);
    }
    return CM_SUCCESS;
}

static void printf_dss_volume_def(const dss_volume_def_t *volume_defs)
{
    (void)printf("    id = %llu\n", (uint64)volume_defs->id);
    (void)printf("    flag = %llu\n", (uint64)volume_defs->flag);
    (void)printf("    version = %llu\n", (uint64)volume_defs->version);
    (void)printf("    name = %s\n", volume_defs->name);
    (void)printf("    code = %s\n", volume_defs->code);
    (void)printf("    resv = %s\n", volume_defs->resv);
}

static status_t dss_printf_volume_ctrl(const dss_vg_info_item_t *vg_item, dss_volume_t *volume)
{
    status_t status;
    int64 offset = (int64)OFFSET_OF(dss_ctrl_t, volume);
    if (offset % DSS_DISK_UNIT_SIZE != 0) {
        DSS_PRINT_ERROR("offset must be align %d.\n", DSS_DISK_UNIT_SIZE);
        return CM_ERROR;
    }
    dss_volume_ctrl_t *volume_ctrl = NULL;
    if (vg_item->from_type == FROM_DISK) {
        volume_ctrl = (dss_volume_ctrl_t *)cm_malloc_align(DSS_ALIGN_SIZE, DSS_VOLUME_CTRL_SIZE);
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
    } else {
        volume_ctrl = &vg_item->dss_ctrl->volume;
    }
    (void)printf("volume_ctrl = {\n");
    (void)printf("  checknum = %u\n", volume_ctrl->checksum);
    (void)printf("  rsvd = %u\n", volume_ctrl->rsvd);
    (void)printf("  version = %llu\n", volume_ctrl->version);
    dss_volume_def_t *volume_defs = volume_ctrl->defs;
    for (uint32 i = 0; i < DSS_MAX_VOLUMES; ++i) {
        if (volume_defs->flag != VOLUME_FREE) {
            (void)printf("  volume_defs[%u] = {\n", i);
            printf_dss_volume_def(volume_defs);
            (void)printf("  }\n");
        }
        volume_defs++;
        continue;
    }

    (void)printf("}\n");
    if (vg_item->from_type == FROM_DISK) {
        DSS_FREE_POINT(volume_ctrl);
    }
    return CM_SUCCESS;
}

static void printf_common_block_t(const dss_common_block_t *common)
{
    char *tab = dss_get_print_tab(g_print_level);
    (void)printf("%s      checksum = %u\n", tab, common->checksum);
    (void)printf("%s      type = %u\n", tab, common->type);
    (void)printf("%s      version = %llu\n", tab, common->version);
    (void)printf("%s      block_id = {\n", tab);
    printf_auid(&common->id);
    (void)printf("%s      }\n", tab);
}

static void printf_ft_block(dss_ft_block_t *ft_block)
{
    (void)printf("    block_common = {\n");

    dss_common_block_t *common = &ft_block->common;
    printf_common_block_t(common);
    (void)printf("    }\n");

    (void)printf("    ft_block_node_num = %u\n", ft_block->node_num);
    (void)printf("    ft_block_next = {\n");

    dss_block_id_t *next = &ft_block->next;
    printf_auid(next);
    (void)printf("    }\n");
}

static void printf_gft_list(gft_list_t *items)
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

static void printf_gft_root(gft_root_t *ft_root)
{
    (void)printf("    ft_root_free_list = {\n");

    gft_list_t *free_list = &ft_root->free_list;
    printf_gft_list(free_list);
    (void)printf("    }\n");
    (void)printf("    ft_root_items = {\n");

    gft_list_t *items = &ft_root->items;
    printf_gft_list(items);
    (void)printf("    }\n");
    (void)printf("    fid = %llu\n", ft_root->fid);
    (void)printf("    block_id_first = {\n");

    dss_block_id_t *block_id_first = &ft_root->first;
    printf_auid(block_id_first);
    (void)printf("    }\n");
    (void)printf("    block_id_last = {\n");

    dss_block_id_t *block_id_last = &ft_root->last;
    printf_auid(block_id_last);
    (void)printf("    }\n");
}

static void printf_root_ft_header(dss_root_ft_header_t *root_ft_header)
{
    (void)printf("    block_common = {\n");

    dss_common_block_t *common = &root_ft_header->common;
    printf_common_block_t(common);
    (void)printf("    }\n");
    (void)printf("    ft_block_node_num = %u\n", root_ft_header->node_num);
    (void)printf("    ft_block_next = {\n");

    dss_block_id_t *next = &root_ft_header->next;
    printf_auid(next);
    (void)printf("    }\n");
}

static status_t dss_printf_root_ft_block(const dss_vg_info_item_t *vg_item, dss_volume_t *volume)
{
    status_t status;
    int64 offset = (int64)OFFSET_OF(dss_ctrl_t, root);
    if (offset % DSS_DISK_UNIT_SIZE != 0) {
        DSS_PRINT_ERROR("offset must be align %d.\n", DSS_DISK_UNIT_SIZE);
        return CM_ERROR;
    }
    char *root = NULL;
    if (vg_item->from_type == FROM_DISK) {
        root = (char *)cm_malloc_align(DSS_ALIGN_SIZE, DSS_BLOCK_SIZE);
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
    } else {
        root = vg_item->dss_ctrl->root;
    }
    dss_root_ft_block_t *root_ft_block = (dss_root_ft_block_t *)(root);
    (void)printf("root_ft_block = {\n");

    dss_root_ft_header_t *ft_block = &root_ft_block->ft_block;
    (void)printf("  ft_block = {\n");
    printf_root_ft_header(ft_block);
    (void)printf("  }\n");

    gft_root_t *ft_root = &root_ft_block->ft_root;
    (void)printf("  ft_root = {\n");
    printf_gft_root(ft_root);
    (void)printf("  }\n");
    (void)printf("}\n");
    if (vg_item->from_type == FROM_DISK) {
        DSS_FREE_POINT(root);
    }
    return CM_SUCCESS;
}

status_t dss_print_struct_name_inner(
    dss_vg_info_item_t *vg_item, dss_volume_t *volume, const char *struct_name)
{
    status_t status;
    if (strcmp("vg_header", struct_name) == 0) {
        status = dss_printf_vg_header(vg_item, volume);
        DSS_RETURN_IFERR2(status, DSS_PRINT_ERROR("Failed to printf metadata vg_header.\n"));
    } else if (strcmp("core_ctrl", struct_name) == 0) {
        status = dss_printf_core_ctrl(vg_item, volume);
        DSS_RETURN_IFERR2(status, DSS_PRINT_ERROR("Failed to printf metadata core_ctrl.\n"));
    } else if (strcmp("volume_ctrl", struct_name) == 0) {
        status = dss_printf_volume_ctrl(vg_item, volume);
        DSS_RETURN_IFERR2(status, DSS_PRINT_ERROR("Failed to printf metadata volume_ctrl.\n"));
    } else if (strcmp("root_ft_block", struct_name) == 0) {
        status = dss_printf_root_ft_block(vg_item, volume);
        DSS_RETURN_IFERR2(status, DSS_PRINT_ERROR("Failed to printf metadata root_ft_block.\n"));
    } else {
        DSS_RETURN_IFERR2(CM_ERROR, DSS_PRINT_ERROR("Incorrect input, %s is not in core_ctrl vg_header volume_ctrl root_ft_block.\n", struct_name));
    }
    return CM_SUCCESS;
}

static int64 dss_get_ftb_offset(const dss_core_ctrl_t *core_ctrl, const dss_block_id_t *id)
{
    if ((id->au) == 0) {
        return (int64)DSS_CTRL_ROOT_OFFSET;
    }
    return (int64)((uint64)id->au * core_ctrl->au_size + (uint64)DSS_BLOCK_SIZE * id->block);
}

static void printf_fs_block_header(dss_fs_block_header *fs_block_header)
{
    char *tab = dss_get_print_tab(g_print_level);
    (void)printf("%s    block_common = {\n", tab);
    dss_common_block_t *common = &fs_block_header->common;
    printf_common_block_t(common);
    (void)printf("%s    }\n", tab);
    (void)printf("%s    fs_block_next = {\n", tab);

    dss_block_id_t *next = &fs_block_header->next;
    printf_auid(next);
    (void)printf("%s    }\n", tab);
    (void)printf("%s    used_num = %hu\n", tab, fs_block_header->used_num);
    (void)printf("%s    total_num = %hu\n", tab, fs_block_header->total_num);
    (void)printf("%s    reserve = %u\n", tab, fs_block_header->reserve);
}

static void printf_fs_block(dss_fs_block_t *fs_block)
{
    char *tab = dss_get_print_tab(g_print_level);
    (void)printf("%s  fs_block_header = {\n", tab);
    dss_fs_block_header *fs_block_header = &fs_block->head;
    printf_fs_block_header(fs_block_header);
    (void)printf("%s  }\n", tab);
    (void)printf("%s  bitmap[0] = {\n", tab);

    dss_block_id_t *bitmap = &fs_block->bitmap[0];
    printf_auid(bitmap);
    (void)printf("%s  }\n", tab);
}

static status_t dss_print_fsb_by_range(dss_block_id_t *node, dss_session_t *session, dss_vg_info_item_t *vg_item, dss_show_param_t *show_param)
{
    printf_auid(node);
    if (g_print_level == DSS_SECOND_PRINT_LEVEL) {
        return dss_print_fsb_by_id_detail(session, vg_item, *(uint64 *)node, show_param);
    }
    return CM_SUCCESS;
}

void dss_reset_first_fs_index(dss_show_param_t *show_param, uint32 start, uint32 end)
{
    if (g_print_level == DSS_SECOND_PRINT_LEVEL) {
        show_param->start_first_fs_index = start;
        show_param->end_first_fs_index = end;
        show_param->start_second_fs_index = CM_INVALID_ID32;
        show_param->end_second_fs_index = CM_INVALID_ID32;
    }
}

// print range by offset and size
status_t dss_print_fsb_by_id_detail_part(dss_session_t *session, dss_vg_info_item_t *vg_item, char *block, dss_show_param_t *show_param)
{
    dss_block_id_t *node = NULL;
    char *tab = dss_get_print_tab(g_print_level - 1); 
    uint32 size = (DSS_FILE_SPACE_BLOCK_SIZE - sizeof(dss_fs_block_t)) / sizeof(dss_block_id_t);
    uint32 start_first_fs_index = show_param->start_first_fs_index;
    uint32 end_first_fs_index = show_param->end_first_fs_index;
    uint32 start_second_fs_index = show_param->start_second_fs_index;
    uint32 end_second_fs_index = show_param->end_second_fs_index;
    if (start_first_fs_index > size - 1 
    || ((end_first_fs_index != CM_INVALID_ID32) && (end_first_fs_index > size - 1)) 
    || ((start_second_fs_index != CM_INVALID_ID32) && (start_second_fs_index > size - 1)) 
    || ((end_second_fs_index != CM_INVALID_ID32) && (end_second_fs_index > size - 1))) {
        DSS_PRINT_ERROR("node_id should be in range 0-%u.\n", size - 1);
        return CM_ERROR;
    }
    if (start_first_fs_index == end_first_fs_index) {
        (void)printf("%sbitmap[%u] = {\n", tab, start_first_fs_index);
        node = (dss_block_id_t *)(block + sizeof(dss_fs_block_t) + start_first_fs_index * sizeof(dss_block_id_t));
        dss_reset_first_fs_index(show_param, start_second_fs_index, end_second_fs_index);
        DSS_RETURN_IF_ERROR(dss_print_fsb_by_range(node, session, vg_item, show_param));
        (void)printf("%s}\n", tab); 
        return CM_SUCCESS;
    }
    for (uint32 i = start_first_fs_index; i <= end_first_fs_index; i++) {
        node = (dss_block_id_t *)(block + sizeof(dss_fs_block_t) + i * sizeof(dss_block_id_t));
        if (i == start_first_fs_index) {
            (void)printf("%sbitmap[%u] = {\n", tab, i);
            dss_reset_first_fs_index(show_param, start_second_fs_index, size - 1);
            DSS_RETURN_IF_ERROR(dss_print_fsb_by_range(node, session, vg_item, show_param));
            (void)printf("%s}\n", tab); 
        } else if (i == end_first_fs_index) {
            (void)printf("%sbitmap[%u] = {\n", tab, i);
            dss_reset_first_fs_index(show_param, 0, end_second_fs_index);
            DSS_RETURN_IF_ERROR(dss_print_fsb_by_range(node, session, vg_item, show_param));
            (void)printf("%s}\n", tab);
        } else {
            (void)printf("%sbitmap[%u] = {\n", tab, i);
            dss_reset_first_fs_index(show_param, CM_INVALID_ID32, CM_INVALID_ID32);
            DSS_RETURN_IF_ERROR(dss_print_fsb_by_range(node, session, vg_item, show_param));
            (void)printf("%s}\n", tab);
        }
    }
    return CM_SUCCESS;
}
status_t dss_print_fsb_by_id_detail(dss_session_t *session, dss_vg_info_item_t *vg_item, uint64 block_id, dss_show_param_t *show_param)
{
    dss_block_id_t *real_block_id = (dss_block_id_t *)&block_id;
    if (dss_cmp_auid(*(auid_t *)real_block_id, DSS_INVALID_64)) {
        return CM_SUCCESS;
    }
    char *block = dss_find_block_in_shm_no_refresh(session, vg_item, *real_block_id, NULL);
    if (block == NULL) {
        DSS_PRINT_ERROR("Failed to find block, block id is %llu.\n", block_id);
        return CM_ERROR;
    }
    dss_common_block_t *block_head = (dss_common_block_t *)block;
    if (block_head->type != DSS_BLOCK_TYPE_FS) {
        DSS_PRINT_ERROR("Failed to find fs block, block id is %llu.\n", block_id);
        return CM_ERROR;
    }
    dss_fs_block_t *file_space_block = (dss_fs_block_t *)block;
    char *tab = dss_get_print_tab(g_print_level);
    (void)printf("%sfile_space_block = {\n", tab);
    printf_fs_block(file_space_block);
    (void)printf("%s}\n\n", tab);
    uint32 size = (DSS_FILE_SPACE_BLOCK_SIZE - sizeof(dss_fs_block_t)) / sizeof(dss_block_id_t);
    dss_block_id_t *node = NULL;
    g_print_level++;
    if (show_param->start_first_fs_index == CM_INVALID_ID32) {
        for (uint32 i = 0; i < size; ++i) {
            node = (dss_block_id_t *)(block + sizeof(dss_fs_block_t) + i * sizeof(dss_block_id_t));
            if (dss_cmp_auid(*(auid_t *)node, DSS_INVALID_64)) {
                continue;
            }
            (void)printf("%sbitmap[%u] = {\n", tab, i);
            g_print_level--;
            printf_auid(node);
            g_print_level++;
            if (g_print_level == DSS_SECOND_PRINT_LEVEL) {
                (void)dss_print_fsb_by_id_detail(session, vg_item, *(uint64 *)node, show_param);
            }
            (void)printf("%s}\n", tab);
        }
    } else {

    }
    return CM_SUCCESS;
}

status_t dss_print_entry_fs_block_detail(dss_session_t *session, dss_vg_info_item_t *vg_item, dss_show_param_t *show_param)
{
    gft_node_t *gft_node = show_param->node;
    dss_block_id_t *entry = &gft_node->entry;
    g_print_level++;
    // print complete file
    if (show_param->offset == CM_INVALID_INT64 && show_param->size == CM_INVALID_INT32) {
        (void)printf("  entry detail = {\n");
        status_t status = dss_print_fsb_by_id_detail(session, vg_item, *(uint64 *)entry, show_param);
        if (status != CM_SUCCESS) {
            DSS_PRINT_ERROR("Failed to print fs block in detail.");
            return CM_ERROR;
        }
        (void)printf("  }\n");
    } else {
        if (show_param->offset + show_param->size > gft_node->size) {
            DSS_PRINT_ERROR("invalid offset %lld and size %u, it is larger than actural size.", show_param->offset, show_param->size);
            return CM_ERROR;
        }
        uint64 au_size = vg_item->dss_ctrl->core.au_size;
        status_t status = dss_get_fs_block_info_by_offset(show_param->offset, au_size, &show_param->start_first_fs_index, &show_param->start_second_fs_index, NULL);
        if (status != CM_SUCCESS) {
            DSS_PRINT_ERROR("Failed to get fs block info by offset.");
            return CM_ERROR;
        }
        status = dss_get_fs_block_info_by_offset(show_param->offset + show_param->size - 1, au_size, &show_param->end_first_fs_index, &show_param->end_second_fs_index, NULL);
        if (status != CM_SUCCESS) {
            DSS_PRINT_ERROR("Failed to get fs block info by offset.");
            return CM_ERROR;
        }
        (void)printf("  fs block range = {\n");
        status = dss_print_fsb_by_id_detail(session, vg_item, *(uint64 *)entry, show_param);
        if (status != CM_SUCCESS) {
            DSS_PRINT_ERROR("Failed to print fs block in detail.");
            return CM_ERROR;
        }
        (void)printf("  }\n");
    }
    return CM_SUCCESS;
}

static void printf_gft_node(gft_node_t *gft_node)
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

    (void)printf("  name = %s\n", gft_node->name);
    (void)printf("  fid = %llu\n", gft_node->fid);
    (void)printf("  flags = %u\n", gft_node->flags);
    (void)printf("  size = %lld\n", gft_node->size);

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

static status_t dss_print_ftn_by_id(char *block, uint64 node_id)
{
    dss_ft_block_t *file_table_block = (dss_ft_block_t *)block;
    (void)printf("file_table_block = {\n");
    printf_ft_block(file_table_block);
    (void)printf("}\n\n");

    uint32 size = (DSS_BLOCK_SIZE - sizeof(dss_ft_block_t)) / sizeof(gft_node_t);
    gft_node_t *node = NULL;

    if (node_id == DSS_DEFAULT_NODE_ID) {
        for (uint32 i = 0; i < size; ++i) {
            node = (gft_node_t *)(block + sizeof(dss_ft_block_t) + i * sizeof(gft_node_t));
            (void)printf("gft_node[%u] = {\n", i);
            printf_gft_node(node);
            (void)printf("}\n");
        }
    } else {
        if (node_id > size - 1) {
            DSS_PRINT_ERROR("node_id should be in range 0-%u.\n", size - 1);
            return CM_ERROR;
        }
        node = (gft_node_t *)(block + sizeof(dss_ft_block_t) + node_id * sizeof(gft_node_t));
        (void)printf("gft_node[%llu] = {\n", node_id);
        printf_gft_node(node);
        (void)printf("}\n");
    }
    return CM_SUCCESS;
}

status_t dss_printf_dss_file_table_block(
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
        DSS_PRINT_ERROR("Failed to read file %d.\n", volume.handle);
        dss_close_volume(&volume);
        DSS_FREE_POINT(block);
        return status;
    }

    status = dss_print_ftn_by_id(block, node_id);
    dss_close_volume(&volume);
    DSS_FREE_POINT(block);
    return status;
}

static int64 dss_get_fsb_offset(const dss_core_ctrl_t *core_ctrl, const dss_block_id_t *id)
{
    return (int64)id->au * core_ctrl->au_size + (int64)DSS_FILE_SPACE_BLOCK_SIZE * id->block;
}

static status_t dss_print_fsb_by_id(char *block, uint64 node_id)
{
    dss_fs_block_t *file_space_block = (dss_fs_block_t *)block;
    (void)printf("file_space_block = {\n");
    printf_fs_block(file_space_block);
    (void)printf("}\n\n");

    uint32 size = (DSS_FILE_SPACE_BLOCK_SIZE - sizeof(dss_fs_block_t)) / sizeof(dss_block_id_t);
    dss_block_id_t *node = NULL;

    if (node_id == DSS_DEFAULT_NODE_ID) {
        for (uint32 i = 0; i < size; ++i) {
            node = (dss_block_id_t *)(block + sizeof(dss_fs_block_t) + i * sizeof(dss_block_id_t));
            if (dss_cmp_auid(*(auid_t *)node, DSS_INVALID_64)) {
                continue;
            }
            (void)printf("bitmap[%u] = {\n", i);
            printf_auid(node);
            (void)printf("}\n");
        }
    } else {
        if (node_id > size - 1) {
            DSS_PRINT_ERROR("node_id should be in range 0-%u.\n", size - 1);
            return CM_ERROR;
        }
        node = (dss_block_id_t *)(block + sizeof(dss_fs_block_t) + node_id * sizeof(dss_block_id_t));
        (void)printf("bitmap[%llu] = {\n", node_id);
        printf_auid(node);
        (void)printf("}\n");
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
    status = dss_print_fsb_by_id(block, node_id);
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

static status_t dss_print_block_by_type(
    dss_volume_ctrl_t *volume_ctrl, dss_core_ctrl_t *core_ctrl, uint64 block_id, uint64 node_id)
{
    dss_block_id_t *id = (dss_block_id_t *)&block_id;
    (void)printf("id = %llu : \n", block_id);

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
        status = dss_printf_dss_file_table_block(volume_ctrl, core_ctrl, id, node_id);
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

status_t dss_printf_block_with_blockid_from_disk(dss_vg_info_item_t *vg_item, uint64 block_id, uint64 node_id, int64 offset)
{
    dss_volume_t volume;
    dss_core_ctrl_t *core_ctrl = (dss_core_ctrl_t *)cm_malloc_align(DSS_ALIGN_SIZE, DSS_CORE_CTRL_SIZE);
    bool32 result = (bool32)(core_ctrl != NULL);
    DSS_RETURN_IF_FALSE2(result, DSS_THROW_ERROR(ERR_ALLOC_MEMORY, DSS_CORE_CTRL_SIZE, "dss_core_ctrl_t"));
    status_t status = get_volume_core_ctrl(vg_item, &volume, core_ctrl);
    DSS_RETURN_IFERR3(
        status, DSS_PRINT_ERROR("Failed to get volume %s.\n", vg_item->entry_path), DSS_FREE_POINT(core_ctrl));
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
    status = dss_print_block_by_type(volume_ctrl, core_ctrl, block_id, node_id);
    dss_close_volume(&volume);
    DSS_FREE_POINT(core_ctrl);
    DSS_FREE_POINT(volume_ctrl);
    return status;  
}

status_t dss_printf_block_with_blockid_from_memory(dss_session_t *session, dss_vg_info_item_t *vg_item, uint64 block_id, uint64 node_id)
{
    dss_block_id_t *real_block_id = (dss_block_id_t *)&block_id;
    char *block = dss_find_block_in_shm_no_refresh(session, vg_item, *real_block_id, NULL);
    if (block == NULL) {
        DSS_PRINT_ERROR("Failed to find block, block id is %llu.\n", block_id);
        return CM_ERROR;
    }
    status_t status;
    dss_common_block_t *block_head = (dss_common_block_t *)block;
    if (block_head->type == DSS_BLOCK_TYPE_FT) {
        status = dss_print_ftn_by_id(block, node_id);
    } else if (block_head->type == DSS_BLOCK_TYPE_FS) {
        status = dss_print_fsb_by_id(block, node_id);
    } else {
        DSS_PRINT_ERROR("Invalid block type %u, block id is %llu.\n", block_head->type, block_id);
        return CM_ERROR;
    }
    return status;
}

status_t dss_printf_block_with_blockid(dss_session_t *session, dss_vg_info_item_t *vg_item, uint64 block_id, uint64 node_id)
{
    status_t status;
    int64 offset = (int64)OFFSET_OF(dss_ctrl_t, volume);
    if (offset % DSS_DISK_UNIT_SIZE != 0) {
        DSS_PRINT_ERROR("offset must be align %d.\n", DSS_DISK_UNIT_SIZE);
        return CM_ERROR;
    }
    if (vg_item->from_type == FROM_DISK) {
        status = dss_printf_block_with_blockid_from_disk(vg_item, block_id, node_id, offset);
    } else {
        status = dss_printf_block_with_blockid_from_memory(session, vg_item, block_id, node_id);
    }
    return status;
}

gft_node_t* dss_find_gft_node_by_fid_in_bucket_inner(dss_ft_block_t *block, uint64 fid)
{
    gft_node_t *node = NULL;
    for (uint32 j = 0; j < block->node_num; j++) {
        node = (gft_node_t *)((char *)block + sizeof(dss_ft_block_t) + sizeof(gft_node_t) * j);
        if (node->fid == fid) {
            return node;
        }
    }
    return NULL;
}

gft_node_t* dss_find_gft_node_by_fid_in_bucket(dss_session_t *session, dss_vg_info_item_t *vg_item, shm_hashmap_bucket_t *bucket, uint64 fid)
{
    char *addr = NULL;
    dss_block_ctrl_t *block_ctrl = NULL;
    gft_node_t *node = NULL;
    dss_common_block_t *block_head = NULL;
    dss_ft_block_t *block = NULL;
    if (vg_item->from_type == FROM_SHM) {
        (void)dss_lock_shm_meta_bucket_s(session, vg_item->id, &bucket->enque_lock);
    }
    ga_obj_id_t next_id = *(ga_obj_id_t *)&bucket->first;
    bool32 has_next = bucket->has_next;
    while (has_next) {
        addr = ga_object_addr(next_id.pool_id, next_id.obj_id);   
        block_head = DSS_GET_COMMON_BLOCK_HEAD(addr);
        if (block_head->type == DSS_BLOCK_TYPE_FT) {
            block = (dss_ft_block_t *)addr;
            block_ctrl = (dss_block_ctrl_t *)(addr + DSS_BLOCK_SIZE); 
            node = dss_find_gft_node_by_fid_in_bucket_inner(block, fid);      
            if (node != NULL) {
                break;
            }
        } else {
            block_ctrl = (dss_block_ctrl_t *)(addr + DSS_FILE_SPACE_BLOCK_SIZE);
        }
        has_next = block_ctrl->has_next;
        next_id = *(ga_obj_id_t *)&block_ctrl->hash_next;
    }
    if (vg_item->from_type == FROM_SHM) {
        dss_unlock_shm_meta_bucket(session, &bucket->enque_lock);
    }
    return node;
}

gft_node_t* dss_get_gft_node_by_fid(dss_session_t *session, dss_vg_info_item_t *vg_item, uint64 fid)
{
    shm_hashmap_t *map = vg_item->buffer_cache;
    shm_hashmap_bucket_t *buckets = (shm_hashmap_bucket_t *)OFFSET_TO_ADDR(map->buckets);
    shm_hashmap_bucket_t *bucket = NULL;
    gft_node_t *node = NULL;
    for (uint32 i = 0; i < map->num; i++) {
        bucket = &buckets[i];
        node = dss_find_gft_node_by_fid_in_bucket(session, vg_item, bucket, fid);
        if (node != NULL) {
            return node;
        }
    }
    return NULL;
}

status_t dss_print_gft_node_by_path(dss_session_t *session, dss_vg_info_item_t *vg_item, dss_show_param_t *show_param)
{
    dss_vg_info_item_t *dir_vg_item = NULL;
    show_param->node = dss_get_gft_node_by_path(session, vg_item, show_param->path, &dir_vg_item);
    if (show_param->node == NULL) {
        DSS_PRINT_ERROR("Failed to find ft node by path %s.\n", show_param->path);
        return CM_ERROR;
    }
    printf_gft_node(show_param->node);
    if (show_param->node->type == GFT_FILE) {
        if (show_param->offset == 0 && show_param->size == 0) {
            return CM_SUCCESS;
        }
        return dss_print_entry_fs_block_detail(session, dir_vg_item, show_param);
    }
    return CM_SUCCESS;
}

status_t dss_print_gft_node_by_ftid_and_fid(dss_session_t *session, dss_vg_info_item_t *vg_item, dss_show_param_t *show_param)
{
    if (show_param->ftid == 0) {
        show_param->node = dss_get_gft_node_by_fid(session, vg_item, show_param->fid);
        if (show_param->node == NULL) {
            DSS_PRINT_ERROR("Failed to find fid %llu in share memory.\n", show_param->fid);
            return CM_ERROR;
        }
    } else {
        dss_block_id_t *block_id = (dss_block_id_t *)&show_param->ftid;
        show_param->node = dss_get_ft_node_by_ftid(session, vg_item, *(ftid_t *)block_id, CM_FALSE, CM_FALSE);
        if (show_param->node == NULL) {
            DSS_PRINT_ERROR("Failed to find block, block id is %llu.\n", show_param->ftid);
            return CM_ERROR;
        }
        if (show_param->node->fid != show_param->fid) {
            DSS_PRINT_ERROR("Failed to find ft node by id, expect is %llu, actural is %llu.", show_param->fid, show_param->node->fid);
            return CM_ERROR;
        }
    }
    printf_gft_node(show_param->node);
    if (show_param->node->type == GFT_FILE) {
        if (show_param->offset == 0 && show_param->size == 0) {
            return CM_SUCCESS;
        }
        return dss_print_entry_fs_block_detail(session, vg_item, show_param);
    }
    return CM_SUCCESS;
}
