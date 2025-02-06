/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
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
 * dsstbox_repair.c
 *
 *
 * IDENTIFICATION
 *    src/tbox/dsstbox_repair.c
 *
 * -------------------------------------------------------------------------
 */

#include "dsstbox_repair.h"
#ifndef WIN32
#include <unistd.h>
#include <sys/types.h>
#endif
#include "cm_base.h"
#include "cm_signal.h"

#include "dss_log.h"
#include "dss_errno.h"
#include "dss_malloc.h"
#include "dss_fs_aux.h"
#include "dss_file.h"
#include "dss_diskgroup.h"
#include "dss_args_parse.h"
#ifndef WIN32
#include "config.h"
#endif

#ifdef WIN32
#define dss_strdup _strdup
#else
#define dss_strdup strdup
#endif

static status_t check_no_sub_meta_member(text_t *key)
{
    // When key->str is NULL, it is the condition that the meta is not followed by ".xxx".
    // e.g. fs_block bitmap[0]=some_value
    // e.g. fs_block head.common.type=1
    if (key->str == NULL) {
        return CM_SUCCESS;
    }
    // When key->str is not NULL, it is the condition that the meta is followed by ".xxx".
    // e.g. fs_block bitmap[0].=some_value
    // e.g. fs_block bitmap[0].abc=some_value
    // e.g. fs_block head.common.type.=1
    // e.g. fs_block head.common.type.ttt=1
    key->str[key->len] = '\0';
    DSS_PRINT_RUN_ERROR(
        "Invalid post-fix(.%s) in key-value string, it may be following a meta of base type.\n", key->str);
    return CM_ERROR;
}

typedef status_t (*repair_func_t)(char *item_ptr, text_t *key, text_t *value);
typedef struct st_repair_items {
    const char *name;
    uint32 item_size;
    uint32 item_offset;
    repair_func_t repair_func;
} repair_items_t;

static void dss_format_tbox_key_value(text_t *key_value)
{
    // format this input str.
    for (uint32_t i = 0; i < key_value->len; i++) {
        if (key_value->str[i] == ',') {
            key_value->str[i] = '\n';
        }
    }
}

#define GS_MAX_CONFIG_LINE_SIZE SIZE_K(4)
status_t repair_parse_kv(text_t *text, text_t *name, text_t *value, uint32 *line_no, bool32 *is_eof)
{
    text_t line;

    *is_eof = CM_TRUE;

    while (cm_fetch_text(text, '\n', '\0', &line)) {
        if (line.len == 0) {
            continue;
        }

        (*line_no)++;
        cm_trim_text(&line);
        if (line.len >= GS_MAX_CONFIG_LINE_SIZE) {
            LOG_RUN_ERR("[TBOX][REPAIR] invalid intput when parse key_value, len is %u longer than %u.\n", line.len,
                GS_MAX_CONFIG_LINE_SIZE);
            return CM_ERROR;
        }

        if (*line.str == '#' || line.len == 0) { /* commentted line */
            continue;
        }

        cm_split_text(&line, '=', '\0', name, value);
        cm_trim_text(name);
        cm_trim_text(value);

        *is_eof = CM_FALSE;

        break;
    }

    return CM_SUCCESS;
}

static status_t repair_func_dss_block_id_t(char *item_ptr, text_t *key, text_t *value)
{
    DSS_RETURN_IF_ERROR(check_no_sub_meta_member(key));
    dss_block_id_t block_id;
    status_t status = cm_text2uint64(value, (uint64 *)&block_id);
    DSS_RETURN_IFERR2(status, DSS_PRINT_RUN_ERROR("block_id:%s is not a valid uint64\n", value->str));
    dss_block_id_t *repair_ptr = (dss_block_id_t *)item_ptr;
    LOG_RUN_INF("[TBOX][REPAIR] modify block id from %s.", dss_display_metaid(*repair_ptr));
    LOG_RUN_INF("[TBOX][REPAIR] modify block id to %s.", dss_display_metaid(block_id));
    *repair_ptr = block_id;
    return CM_SUCCESS;
}

static status_t repair_func_ftid_t(char *item_ptr, text_t *key, text_t *value)
{
    DSS_RETURN_IF_ERROR(check_no_sub_meta_member(key));
    ftid_t ftid;
    status_t status = cm_text2uint64(value, (uint64 *)&ftid);
    DSS_RETURN_IFERR2(status, DSS_PRINT_RUN_ERROR("ftid:%s is not a valid uint64\n", value->str));
    ftid_t *repair_ptr = (ftid_t *)item_ptr;
    LOG_RUN_INF("[TBOX][REPAIR] modify ft id from %s.", dss_display_metaid(*repair_ptr));
    LOG_RUN_INF("[TBOX][REPAIR] modify ft id to %s.", dss_display_metaid(ftid));
    *repair_ptr = ftid;
    return CM_SUCCESS;
}

static status_t repair_func_auid_t(char *item_ptr, text_t *key, text_t *value)
{
    return repair_func_dss_block_id_t(item_ptr, key, value);
}

static status_t repair_func_uint64(char *item_ptr, text_t *key, text_t *value)
{
    DSS_RETURN_IF_ERROR(check_no_sub_meta_member(key));
    uint64 val;
    status_t status = cm_text2uint64(value, &val);
    DSS_RETURN_IFERR2(status, DSS_PRINT_RUN_ERROR("repair value:%s is not a valid uint64\n", value->str));
    LOG_RUN_INF("[TBOX][REPAIR] modify uint64 from %llu to %llu;", *(uint64 *)item_ptr, val);
    *(uint64 *)item_ptr = val;
    return CM_SUCCESS;
}

static status_t repair_func_uint32_t(char *item_ptr, text_t *key, text_t *value)
{
    DSS_RETURN_IF_ERROR(check_no_sub_meta_member(key));
    uint32 val;
    status_t status = cm_text2uint32(value, &val);
    DSS_RETURN_IFERR2(status, DSS_PRINT_RUN_ERROR("repair value:%s is not a valid uint32\n", value->str));
    LOG_RUN_INF("[TBOX][REPAIR] modify uint32 from %u to %u;", *(uint32 *)item_ptr, val);
    *(uint32 *)item_ptr = val;
    return CM_SUCCESS;
}

static status_t repair_func_uint16_t(char *item_ptr, text_t *key, text_t *value)
{
    DSS_RETURN_IF_ERROR(check_no_sub_meta_member(key));
    uint16 val;
    status_t status = cm_text2uint16(value, &val);
    DSS_RETURN_IFERR2(status, DSS_PRINT_RUN_ERROR("repair value:%s is not a valid uint16\n", value->str));
    LOG_RUN_INF("[TBOX][REPAIR] modify uint16 from %hu to %hu;", *(uint16 *)item_ptr, val);
    *(uint16 *)item_ptr = val;
    return CM_SUCCESS;
}

typedef struct st_repair_complex_meta {
    const char *meta_name;
    repair_items_t *repair_items;
    uint32 repair_items_cnt;
} repair_complex_meta_funcs_t;

static status_t repair_func_complex_meta(
    repair_complex_meta_funcs_t *repair_funcs, char *item_ptr, text_t *key, text_t *value)
{
    text_t part1, part2;
    cm_split_text(key, '.', '\0', &part1, &part2);
    cm_trim_text(&part1);
    cm_trim_text(&part2);
    for (uint32_t i = 0; i < repair_funcs->repair_items_cnt; i++) {
        repair_items_t *item = &repair_funcs->repair_items[i];
        if (cm_text_str_equal(&part1, item->name)) {
            LOG_RUN_INF("[TBOX][REPAIR] modify %s key name : %s, offset : %u;", repair_funcs->meta_name, item->name,
                item->item_offset);
            return item->repair_func((void *)(((char *)item_ptr) + item->item_offset), &part2, value);
        }
    }
    DSS_PRINT_RUN_ERROR("[TBOX][REPAIR] Get invalid key : %s, when parse %s;\n", part1.str, repair_funcs->meta_name);
    return CM_ERROR;
}

#define REPAIR_ITEM(name, obj, item, type)                                                \
    {                                                                                     \
        (name), (uint32)(sizeof(type)), (uint32)(OFFSET_OF(obj, item)), repair_func_##type \
    }

#define REPAIR_ITEM_WITH_FUNC(name, obj, item, type, func)                     \
    {                                                                          \
        (name), (uint32)(sizeof(type)), (uint32)(OFFSET_OF(obj, item)), (func) \
    }

#define REPAIR_ITEM_WITH_LEN_FUNC(name, obj, item, len, func)         \
    {                                                                 \
        (name), (uint32)(len), (uint32)(OFFSET_OF(obj, item)), (func) \
    }

#define REPAIR_ITEM_WITH_OFFSET_FUNC(name, offset, type, func)   \
    {                                                            \
        (name), (uint32)(sizeof(type)), (uint32)(offset), (func) \
    }

static status_t repair_func_common_block_type(char *item_ptr, text_t *key, text_t *value)
{
    DSS_RETURN_IF_ERROR(check_no_sub_meta_member(key));
    uint32 val;
    status_t status = cm_text2uint32(value, &val);
    DSS_RETURN_IFERR2(status, DSS_PRINT_RUN_ERROR("repair value:%s is not a valid uint32\n", value->str));
    if (val >= DSS_BLOCK_TYPE_MAX) {
        DSS_PRINT_RUN_ERROR(
            "[TBOX][REPAIR] block type must be smaller than %u, your input is %u.\n", (uint32)DSS_BLOCK_TYPE_MAX, val);
        return CM_ERROR;
    }
    LOG_RUN_INF("[TBOX][REPAIR] modify type of block from %u to %u;", *(uint32 *)item_ptr, val);
    *(uint32 *)item_ptr = val;
    return CM_SUCCESS;
}
static status_t repair_func_common_block_flags(char *item_ptr, text_t *key, text_t *value)
{
    DSS_RETURN_IF_ERROR(check_no_sub_meta_member(key));
    uint8 val;
    status_t status = cm_text2uint8(value, &val);
    DSS_RETURN_IFERR2(status, DSS_PRINT_RUN_ERROR("repair value:%s is not a valid uint8\n", value->str));
    if (val >= DSS_BLOCK_FLAG_MAX) {
        DSS_PRINT_RUN_ERROR("[TBOX][REPAIR] block flags must be smaller than %hhu, your input is %hhu.\n",
            (uint8)DSS_BLOCK_FLAG_MAX, val);
        return CM_ERROR;
    }
    LOG_RUN_INF("[TBOX][REPAIR] modify block flags from %hhu to %hhu;", *(uint8 *)item_ptr, val);
    *(uint8 *)item_ptr = val;
    return CM_SUCCESS;
}

#define REPAIR_COMMON_BLOCK_ITEM_COUNT (sizeof(g_repair_common_block_items_list) / sizeof(repair_items_t))
repair_items_t g_repair_common_block_items_list[] = {
    REPAIR_ITEM_WITH_FUNC("type", dss_common_block_t, type, uint32_t, repair_func_common_block_type),
    REPAIR_ITEM("version", dss_common_block_t, version, uint64),
    REPAIR_ITEM("id", dss_common_block_t, id, dss_block_id_t),
    REPAIR_ITEM_WITH_FUNC("flags", dss_common_block_t, flags, uint8_t, repair_func_common_block_flags),
};

repair_complex_meta_funcs_t repair_set_common_block_funcs = {
    "common block", g_repair_common_block_items_list, REPAIR_COMMON_BLOCK_ITEM_COUNT};
static status_t repair_set_common_block(char *item_ptr, text_t *key, text_t *value)
{
    return repair_func_complex_meta(&repair_set_common_block_funcs, item_ptr, key, value);
}

#define REPAIR_FS_BLOCK_HEAD_ITEM_COUNT (sizeof(g_repair_fs_block_head_items_list) / sizeof(repair_items_t))
repair_items_t g_repair_fs_block_head_items_list[] = {
    REPAIR_ITEM_WITH_FUNC("common", dss_fs_block_header, common, dss_common_block_t, repair_set_common_block),
    REPAIR_ITEM("next", dss_fs_block_header, next, dss_block_id_t),
    REPAIR_ITEM("ftid", dss_fs_block_header, ftid, dss_block_id_t),
    REPAIR_ITEM("used_num", dss_fs_block_header, used_num, uint16_t),
    REPAIR_ITEM("total_num", dss_fs_block_header, total_num, uint16_t),
    REPAIR_ITEM("index", dss_fs_block_header, index, uint16_t),
};

repair_complex_meta_funcs_t repair_set_fs_block_header_funcs = {
    "fs block header", g_repair_fs_block_head_items_list, REPAIR_FS_BLOCK_HEAD_ITEM_COUNT};
static status_t repair_set_fs_block_header(char *item_ptr, text_t *key, text_t *value)
{
    return repair_func_complex_meta(&repair_set_fs_block_header_funcs, item_ptr, key, value);
}

static status_t repair_set_fs_block_bitmap(char *item_ptr, text_t *key, text_t *value)
{
    DSS_RETURN_IF_ERROR(check_no_sub_meta_member(key));
    LOG_RUN_INF("[TBOX][REPAIR] modify fs bitmap:%s.", value->str);
    return repair_func_dss_block_id_t(item_ptr, key, value);
}

#define REPAIR_FS_BLOCK_ITEM_COUNT (sizeof(g_repair_fs_block_items_list) / sizeof(repair_items_t))
repair_items_t g_repair_fs_block_items_list[] = {
    REPAIR_ITEM_WITH_FUNC("head", dss_fs_block_t, head, dss_fs_block_header, repair_set_fs_block_header),
    REPAIR_ITEM_WITH_FUNC("bitmap", dss_fs_block_t, bitmap, dss_block_id_t, repair_set_fs_block_bitmap),
};

static bool32 repair_key_with_index(text_t *key, const char *str, uint32_t *index)
{
    for (uint32 i = 0; i < key->len; i++) {
        if (str[i] == '\0' && key->str[i] == '[') {
            break;
        } else if (key->str[i] != str[i]) {
            return CM_FALSE;
        }
    }
    text_t part1, part2, part3;
    cm_split_text(key, '[', '\0', &part1, &part2);
    *key = part1;

    cm_split_text(&part2, ']', '\0', &part1, &part3);
    if (part1.len == 0) {
        LOG_RUN_ERR("[TBOX][REPAIR] Get invalid key : %s, when parse index.", key->str);
        return CM_FALSE;
    } else {
        if (cm_text2uint32(&part1, index) != CM_SUCCESS) {
            LOG_RUN_ERR("[TBOX][REPAIR] Get invalid key : %s, when parse index.", key->str);
            return CM_FALSE;
        }
    }
    if (part3.len != 0) {
        LOG_RUN_ERR("[TBOX][REPAIR] Get invalid key : %s, when parse index.", key->str);
        return CM_FALSE;
    }
    return CM_TRUE;
}

typedef status_t (*dss_meta_repairer_t)(char *meta_buffer, text_t *name, text_t *value);
static status_t dss_fs_block_repairer(char *block, text_t *name, text_t *value)
{
    text_t part1, part2;
    uint32 index = 0;
    LOG_RUN_INF("[TBOX][REPAIR] modify fs block key value : %s;", name->str);
    cm_split_text(name, '.', '\0', &part1, &part2);
    cm_trim_text(&part1);
    cm_trim_text(&part2);
    for (uint32_t i = 0; i < REPAIR_FS_BLOCK_ITEM_COUNT; i++) {
        repair_items_t *item = &g_repair_fs_block_items_list[i];
        if (cm_text_str_equal(&part1, item->name)) {
            LOG_RUN_INF("[TBOX][REPAIR] modify fs block key name : %s, offset : %u;", item->name, item->item_offset);
            return item->repair_func((void *)(((char *)block) + item->item_offset), &part2, value);
        } else if (repair_key_with_index(&part1, item->name, &index)) {
            if (index >= DSS_FS_BLOCK_ITEM_NUM) {
                DSS_PRINT_RUN_ERROR("[TBOX][REPAIR] invalid fs block index : %u;\n", index);
                return CM_ERROR;
            }
            uint32 repair_offset = item->item_offset + index * item->item_size;
            LOG_RUN_INF("[TBOX][REPAIR] modify fs block key name : %s, index : %u, offset : %u;", item->name, index,
                repair_offset);
            return item->repair_func((void *)(((char *)block) + repair_offset), &part2, value);
        }
    }
    DSS_PRINT_RUN_ERROR("[TBOX][REPAIR] Get invalid key : %s, when parse fs block;", part1.str);
    return CM_ERROR;
}

repair_items_t g_repair_fs_block_list_items_list[] = {REPAIR_ITEM("count", dss_fs_block_list_t, count, uint64),
    REPAIR_ITEM_WITH_FUNC("first", dss_fs_block_list_t, first, dss_block_id_t, repair_func_dss_block_id_t),
    REPAIR_ITEM_WITH_FUNC("last", dss_fs_block_list_t, last, dss_block_id_t, repair_func_dss_block_id_t)};
repair_complex_meta_funcs_t g_repair_fs_block_list_funcs = {"fs block list", g_repair_fs_block_list_items_list,
    sizeof(g_repair_fs_block_list_items_list) / sizeof(repair_items_t)};
static status_t repair_set_fs_block_list(char *item_ptr, text_t *key, text_t *value)
{
    return repair_func_complex_meta(&g_repair_fs_block_list_funcs, item_ptr, key, value);
}

repair_items_t g_repair_fs_block_root_items_list[] = {REPAIR_ITEM("version", dss_fs_block_root_t, version, uint64),
    REPAIR_ITEM_WITH_FUNC("free", dss_fs_block_root_t, free, dss_fs_block_list_t, repair_set_fs_block_list)};
repair_complex_meta_funcs_t repair_set_fs_block_root_funcs = {"fs block root", g_repair_fs_block_root_items_list,
    sizeof(g_repair_fs_block_root_items_list) / sizeof(repair_items_t)};

static status_t repair_set_fs_block_root(char *item_ptr, text_t *key, text_t *value)
{
    return repair_func_complex_meta(&repair_set_fs_block_root_funcs, item_ptr, key, value);
}

repair_items_t g_repair_au_list_items_list[] = {REPAIR_ITEM("count", dss_au_list_t, count, uint64),
    REPAIR_ITEM("first", dss_au_list_t, first, auid_t), REPAIR_ITEM("last", dss_au_list_t, last, auid_t)};
repair_complex_meta_funcs_t g_repair_au_list_funcs = {
    "au_root", g_repair_au_list_items_list, sizeof(g_repair_au_list_items_list) / sizeof(repair_items_t)};
static status_t repair_set_au_list(char *item_ptr, text_t *key, text_t *value)
{
    return repair_func_complex_meta(&g_repair_au_list_funcs, item_ptr, key, value);
}

repair_items_t g_repair_au_root_items_list[] = {
    REPAIR_ITEM("version", dss_au_root_t, version, uint64),
    REPAIR_ITEM("free_root", dss_au_root_t, free_root, auid_t),
    REPAIR_ITEM("count", dss_au_root_t, count, uint64),
    REPAIR_ITEM("free_vol_id", dss_au_root_t, free_vol_id, uint32_t),
    REPAIR_ITEM_WITH_FUNC("free_list", dss_au_root_t, free_list, dss_au_list_t, repair_set_au_list),
};
repair_complex_meta_funcs_t repair_set_au_root_funcs = {
    "au root", g_repair_au_root_items_list, sizeof(g_repair_au_root_items_list) / sizeof(repair_items_t)};

static status_t repair_set_au_root(char *item_ptr, text_t *key, text_t *value)
{
    return repair_func_complex_meta(&repair_set_au_root_funcs, item_ptr, key, value);
}

repair_items_t g_repair_fs_aux_root_items_list[] = {
    REPAIR_ITEM("version", dss_fs_aux_root_t, version, uint64),
    REPAIR_ITEM_WITH_FUNC("free", dss_fs_aux_root_t, free, dss_fs_block_list_t, repair_set_fs_block_list),
};
repair_complex_meta_funcs_t repair_set_fs_aux_root_funcs = {
    "fs aux root", g_repair_fs_aux_root_items_list, sizeof(g_repair_fs_aux_root_items_list) / sizeof(repair_items_t)};
static status_t repair_set_fs_aux_root(char *item_ptr, text_t *key, text_t *value)
{
    return repair_func_complex_meta(&repair_set_fs_aux_root_funcs, item_ptr, key, value);
}

static status_t repair_set_volume_attr_id(char *item_ptr, text_t *key, text_t *value)
{
    DSS_RETURN_IF_ERROR(check_no_sub_meta_member(key));
    uint16 val;
    status_t status = cm_text2uint16(value, &val);
    DSS_RETURN_IFERR2(status, DSS_PRINT_RUN_ERROR("repair value:%s is not a valid uint16\n", value->str));
    if (val >= DSS_MAX_VOLUMES) {
        DSS_PRINT_RUN_ERROR("[TBOX][REPAIR] volume_attrs[i].id must be smaller than %hu, your input is %hu.\n",
            (uint16)DSS_MAX_VOLUMES, val);
        return CM_ERROR;
    }
    dss_volume_attr_t *volume_attr = (dss_volume_attr_t *)item_ptr;
    volume_attr->id = val;
    return CM_SUCCESS;
}

repair_items_t g_repair_volume_attr_items_list[] = {
    // id is a bit-field member, treat it as an uint64 with special process
    REPAIR_ITEM_WITH_OFFSET_FUNC("id", 0, uint64, repair_set_volume_attr_id),
    REPAIR_ITEM("size", dss_volume_attr_t, size, uint64), REPAIR_ITEM("hwm", dss_volume_attr_t, hwm, uint64),
    REPAIR_ITEM("free", dss_volume_attr_t, free, uint64)};
repair_complex_meta_funcs_t g_repair_set_volume_attr_funcs = {
    "volume attr", g_repair_volume_attr_items_list, sizeof(g_repair_volume_attr_items_list) / sizeof(repair_items_t)};
static status_t repair_set_volume_attr(char *item_ptr, text_t *key, text_t *value)
{
    return repair_func_complex_meta(&g_repair_set_volume_attr_funcs, item_ptr, key, value);
}

static status_t repair_set_au_size(char *item_ptr, text_t *key, text_t *value)
{
    DSS_RETURN_IF_ERROR(check_no_sub_meta_member(key));
    status_t status = cmd_check_au_size(value->str);
    DSS_RETURN_IF_ERROR(status);
    uint32 val;
    status = cm_text2uint32(value, &val);
    DSS_RETURN_IFERR2(status, DSS_PRINT_RUN_ERROR("repair value:%s is not a valid uint32\n", value->str));
    // unit of user-inputted au_size is KB, but that on disk is Byte, so a transformation is needed.
    uint32 bytes = val * SIZE_K(1);
    LOG_RUN_INF("[TBOX][REPAIR] user-inputted au_size is %uKB, it is %uB.", val, bytes);
    LOG_RUN_INF("[TBOX][REPAIR] modify uint32 from %u to %u;", *(uint32 *)item_ptr, bytes);
    *(uint32 *)item_ptr = val;
    return CM_SUCCESS;
}

#define REPAIR_CORE_CTRL_ITEM_COUNT (sizeof(g_repair_core_ctrl_items_list) / sizeof(repair_items_t))
repair_items_t g_repair_core_ctrl_items_list[] = {REPAIR_ITEM("version", dss_core_ctrl_t, version, uint64),
    REPAIR_ITEM_WITH_FUNC("au_size", dss_core_ctrl_t, au_size, uint32_t, repair_set_au_size),
    REPAIR_ITEM("volume_count", dss_core_ctrl_t, volume_count, uint32_t),
    REPAIR_ITEM_WITH_FUNC(
        "fs_block_root", dss_core_ctrl_t, fs_block_root, dss_fs_block_root_t, repair_set_fs_block_root),
    REPAIR_ITEM_WITH_FUNC("au_root", dss_core_ctrl_t, au_root, dss_au_root_t, repair_set_au_root),
    REPAIR_ITEM_WITH_FUNC("fs_aux_root", dss_core_ctrl_t, fs_aux_root, dss_fs_aux_root_t, repair_set_fs_aux_root),
    REPAIR_ITEM_WITH_FUNC("volume_attrs", dss_core_ctrl_t, volume_attrs, dss_volume_attr_t, repair_set_volume_attr)};

static status_t dss_core_ctrl_repairer(char *meta_buffer, text_t *name, text_t *value)
{
    LOG_RUN_INF("[TBOX][REPAIR] modify core_ctrl key value : %s;", name->str);
    text_t part1, part2;
    uint32 index = 0;
    cm_split_text(name, '.', '\0', &part1, &part2);
    cm_trim_text(&part1);
    cm_trim_text(&part2);
    for (uint32_t i = 0; i < REPAIR_CORE_CTRL_ITEM_COUNT; ++i) {
        repair_items_t *item = &g_repair_core_ctrl_items_list[i];
        if (cm_text_str_equal(&part1, item->name)) {
            LOG_RUN_INF("[TBOX][REPAIR] modify core_ctrl key name : %s, offset : %u;", item->name, item->item_offset);
            return item->repair_func((void *)((meta_buffer + item->item_offset)), &part2, value);
        } else if (repair_key_with_index(&part1, item->name, &index)) {
            if (index >= DSS_MAX_VOLUMES) {
                DSS_PRINT_RUN_ERROR("[TBOX][REPAIR] invalid volume attr index : %u;\n", index);
                return CM_ERROR;
            }
            uint32 repair_offset = item->item_offset + index * item->item_size;
            LOG_RUN_INF(
                "[TBOX][REPAIR] modify core_ctrl key : %s, index : %u, offset : %u;", item->name, index, repair_offset);
            return item->repair_func((void *)(((char *)meta_buffer) + repair_offset), &part2, value);
        }
    }
    DSS_PRINT_RUN_ERROR("[TBOX][REPAIR] Get invalid key : %s, when parse core_ctrl;", part1.str);
    return CM_ERROR;
}

static status_t repair_func_volume_name(char *item_ptr, text_t *key, text_t *value)
{
    DSS_RETURN_IF_ERROR(check_no_sub_meta_member(key));
    if (value->len > DSS_MAX_VOLUME_PATH_LEN - 1) {
        DSS_PRINT_RUN_ERROR("[TBOX][REPAIR] volume_name is too long, max len is %u, your input is %u.\n",
            (uint32)(DSS_MAX_VOLUME_PATH_LEN - 1), value->len);
        return CM_ERROR;
    }
    return cm_text2str(value, item_ptr, DSS_MAX_VOLUME_PATH_LEN);
}
static status_t repair_func_volume_type_val(char *item_ptr, text_t *key, text_t *value)
{
    DSS_RETURN_IF_ERROR(check_no_sub_meta_member(key));
    uint32 val;
    status_t status = cm_text2uint32(value, &val);
    DSS_RETURN_IFERR2(status, DSS_PRINT_RUN_ERROR("repair value:%s is not a valid uint32\n", value->str));
    if (val != DSS_VOLUME_TYPE_MANAGER && val != DSS_VOLUME_TYPE_NORMAL) {
        DSS_PRINT_RUN_ERROR("[TBOX][REPAIR] invalid volume_type value: %u, only support %u or %u.\n", val,
            (uint32)DSS_VOLUME_TYPE_MANAGER, (uint32)DSS_VOLUME_TYPE_NORMAL);
        return CM_ERROR;
    }
    LOG_RUN_INF("[TBOX][REPAIR] modify uint32 from %u to %u;", *(uint32 *)item_ptr, val);
    *(uint32 *)item_ptr = val;
    return CM_SUCCESS;
}
repair_items_t g_repair_volume_type_items_list[] = {
    REPAIR_ITEM_WITH_FUNC("type", dss_volume_type_t, type, uint32_t, repair_func_volume_type_val),
    REPAIR_ITEM("id", dss_volume_type_t, id, uint32_t),
    REPAIR_ITEM_WITH_FUNC("entry_volume_name", dss_volume_type_t, entry_volume_name,
        ((dss_volume_type_t *)0)->entry_volume_name, repair_func_volume_name)};
repair_complex_meta_funcs_t repair_set_volume_type_funcs = {
    "volume_header", g_repair_volume_type_items_list, sizeof(g_repair_volume_type_items_list) / sizeof(repair_items_t)};
static status_t repair_set_volume_type(char *item_ptr, text_t *key, text_t *value)
{
    return repair_func_complex_meta(&repair_set_volume_type_funcs, item_ptr, key, value);
}

static status_t repair_set_vg_name(char *item_ptr, text_t *key, text_t *value)
{
    DSS_RETURN_IF_ERROR(check_no_sub_meta_member(key));
    if (value->len > DSS_MAX_NAME_LEN - 1) {
        DSS_PRINT_RUN_ERROR("[TBOX][REPAIR] vg_name is too long, max len is %u, your input is %u.\n",
            (uint32)(DSS_MAX_NAME_LEN - 1), value->len);
        return CM_ERROR;
    }
    return cm_text2str(value, item_ptr, DSS_MAX_NAME_LEN);
}

repair_items_t g_repair_timeval_items_list[] = {
    REPAIR_ITEM("tv_sec", timeval_t, tv_sec, uint32_t), REPAIR_ITEM("tv_usec", timeval_t, tv_usec, uint32_t)};
repair_complex_meta_funcs_t repair_set_timeval_funcs = {
    "timeval", g_repair_timeval_items_list, sizeof(g_repair_timeval_items_list) / sizeof(repair_items_t)};
static status_t repair_set_timeval(char *item_ptr, text_t *key, text_t *value)
{
    return repair_func_complex_meta(&repair_set_timeval_funcs, item_ptr, key, value);
}

static status_t repair_func_bak_level_e(char *item_ptr, text_t *key, text_t *value)
{
    DSS_RETURN_IF_ERROR(check_no_sub_meta_member(key));
    uint32 val = 0;
    status_t status = cm_text2uint32(value, &val);
    DSS_RETURN_IFERR2(
        status, DSS_PRINT_RUN_ERROR("[TBOX][REPAIR] repair value:%s is not a valid uint32.\n", value->str));
    if (val > DSS_MAX_BAK_LEVEL) {
        DSS_PRINT_RUN_ERROR(
            "[TBOX][REPAIR] currently maximum of bak_level is %u, your input is %u.\n", (uint32)DSS_MAX_BAK_LEVEL, val);
        return CM_ERROR;
    }
    LOG_RUN_INF("[TBOX][REPAIR] modify bak_level_e from %u to %u;", *(uint32 *)item_ptr, val);
    *(uint32 *)item_ptr = val;
    return CM_SUCCESS;
}

// Note: software_version cannot be modified via "-t volume_header -k software_version=value".
//       It can only be modified by "-t software_version -k software_version=value".
static status_t repair_reject_set_software_version(char *item_ptr, text_t *key, text_t *value)
{
    DSS_PRINT_RUN_ERROR(
        "[TBOX][REPAIR] software_version is not allowed to be modified by "
        "\"dsstbox ssrepair -t volume_header -k software_version=NEW_VERSION\"."
        "If needed, use \"dsstbox ssrepair -t software_version -k software_version=NEW_VERSION\" instead.");
    return CM_ERROR;
}

#define REPAIR_VOLUME_HEADER_ITEM_COUNT (sizeof(g_repair_volume_header_items_list) / sizeof(repair_items_t))
repair_items_t g_repair_volume_header_items_list[] = {
    REPAIR_ITEM_WITH_FUNC("vol_type", dss_volume_header_t, vol_type, dss_volume_type_t, repair_set_volume_type),
    REPAIR_ITEM_WITH_FUNC(
        "vg_name", dss_volume_header_t, vg_name, ((dss_volume_header_t *)0)->vg_name, repair_set_vg_name),
    REPAIR_ITEM("valid_flag", dss_volume_header_t, valid_flag, uint32_t),
    REPAIR_ITEM_WITH_FUNC(
        "software_version", dss_volume_header_t, software_version, uint32_t, repair_reject_set_software_version),
    REPAIR_ITEM_WITH_FUNC("create_time", dss_volume_header_t, create_time, timeval_t, repair_set_timeval),
    REPAIR_ITEM_WITH_FUNC("bak_level", dss_volume_header_t, bak_level, dss_bak_level_e, repair_func_bak_level_e),
    REPAIR_ITEM("ft_node_ratio", dss_volume_header_t, ft_node_ratio, uint32_t),
    REPAIR_ITEM("bak_ft_offset", dss_volume_header_t, bak_ft_offset, uint64)};

static status_t dss_volume_header_repairer(char *meta_buffer, text_t *name, text_t *value)
{
    LOG_RUN_INF("[TBOX][REPAIR] modify volume_header key value : %s;", name->str);
    text_t part1, part2;
    cm_split_text(name, '.', '\0', &part1, &part2);
    cm_trim_text(&part1);
    cm_trim_text(&part2);
    for (uint32_t i = 0; i < REPAIR_VOLUME_HEADER_ITEM_COUNT; ++i) {
        repair_items_t *item = &g_repair_volume_header_items_list[i];
        if (cm_text_str_equal(&part1, item->name)) {
            LOG_RUN_INF(
                "[TBOX][REPAIR] modify volume_header key name : %s, offset : %u;", item->name, item->item_offset);
            return item->repair_func((void *)((meta_buffer + item->item_offset)), &part2, value);
        }
    }
    DSS_PRINT_RUN_ERROR("[TBOX][REPAIR] Get invalid key : %s, when parse volume_header;\n", part1.str);
    return CM_ERROR;
}

static status_t dss_repair_meta_by_input(
    repair_input_def_t *input, char *meta_buffer, dss_meta_repairer_t meta_repairer)
{
    text_t key_value, name, value;
    bool32 is_eof = CM_FALSE;
    uint32 line_no = 0;
    status_t ret = CM_ERROR;
    key_value.len = (uint32)strlen(input->key_value);
    char *parse_str = (char *)dss_strdup(input->key_value);
    key_value.str = parse_str;
    if (key_value.str == NULL) {
        DSS_PRINT_RUN_ERROR("[TBOX][REPAIR] Failed to strdup %u buf;\n", key_value.len);
        return ret;
    }

    dss_format_tbox_key_value(&key_value);
    for (;;) {
        // parse each key and value
        if (repair_parse_kv(&key_value, &name, &value, &line_no, &is_eof) != CM_SUCCESS) {
            DSS_PRINT_RUN_ERROR("[TBOX][REPAIR] invalid intput key_value :%s;\n", input->key_value);
            ret = CM_ERROR;
            break;
        }

        if (is_eof) {
            LOG_RUN_INF("[TBOX][REPAIR] Finish to modify %s.", input->type);
            ret = CM_SUCCESS;
            break;
        }
        cm_trim_text(&name);
        cm_trim_text(&value);
        cm_text_lower(&name);
        ret = meta_repairer(meta_buffer, &name, &value);
        DSS_BREAK_IFERR2(ret, DSS_PRINT_RUN_ERROR("[TBOX][REPAIR] Invalid intput key_value :%s;\n", input->key_value));
    }
    DSS_FREE_POINT(parse_str);
    return ret;
}

static status_t dss_repair_load_fs_block(repair_input_def_t *input, dss_fs_block_t **block, dss_volume_t *volume)
{
    *block = (dss_fs_block_t *)cm_malloc_align(DSS_ALIGN_SIZE, DSS_FILE_SPACE_BLOCK_SIZE);
    if (*block == NULL) {
        DSS_THROW_ERROR(ERR_ALLOC_MEMORY, DSS_VG_DATA_SIZE, "[TBOX][REPAIR] load fs block");
        return CM_ERROR;
    }
    int64 offset = dss_get_fsb_offset(SIZE_K(input->au_size), &input->block_id);
    LOG_RUN_INF("[TBOX][REPAIR] load fs block to read volume %s, offset:%lld, id:%s.\n", input->vol_path, offset,
        dss_display_metaid(input->block_id));
    status_t status = dss_read_volume(volume, offset, *block, (int32)DSS_FILE_SPACE_BLOCK_SIZE);
    if (status != CM_SUCCESS) {
        LOG_RUN_ERR("[TBOX][REPAIR] Failed to read volume %s, offset:%lld, id:%s, errno:%u.\n", input->vol_path, offset,
            dss_display_metaid(input->block_id), errno);
        DSS_FREE_POINT(*block);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static status_t dss_repair_write_fs_block(repair_input_def_t *input, dss_fs_block_t *block, dss_volume_t *volume)
{
    uint32_t checksum = dss_get_checksum(block, DSS_FILE_SPACE_BLOCK_SIZE);
    int64 offset = dss_get_fsb_offset(SIZE_K(input->au_size), &input->block_id);
    LOG_RUN_INF("[TBOX][REPAIR] Repair fs block %s, volume:%s, offset:%lld, checksum old:%u new:%u.",
        dss_display_metaid(input->block_id), input->vol_path, offset, block->head.common.checksum, checksum);
    (void)printf("[TBOX][REPAIR] Repair fs block %s, volume:%s, offset:%lld, checksum old:%u new:%u.\n",
        dss_display_metaid(input->block_id), input->vol_path, offset, block->head.common.checksum, checksum);
    block->head.common.checksum = checksum;

    status_t status = dss_write_volume(volume, offset, block, (int32)DSS_FILE_SPACE_BLOCK_SIZE);
    if (status != CM_SUCCESS) {
        DSS_PRINT_RUN_ERROR("[TBOX][REPAIR] Failed to write volume %s, offset:%lld, id:%s.\n", input->vol_path, offset,
            dss_display_metaid(input->block_id));
    }
    return status;
}

status_t dss_repair_fs_block(repair_input_def_t *input)
{
    dss_volume_t volume;
    dss_fs_block_t *block = NULL;
    status_t status = dss_open_volume(input->vol_path, NULL, DSS_CLI_OPEN_FLAG, &volume);
    DSS_RETURN_IFERR2(status, LOG_RUN_ERR("[TBOX][REPAIR] Open volume %s failed.\n", input->vol_path));
    // malloc and load fs_block mem
    status = dss_repair_load_fs_block(input, &block, &volume);
    if (status != CM_SUCCESS) {
        DSS_PRINT_RUN_ERROR("[TBOX][REPAIR] load fs block failed, volume %s.\n", input->vol_path);
        dss_close_volume(&volume);
        return CM_ERROR;
    }

    status = dss_repair_meta_by_input(input, (char *)block, dss_fs_block_repairer);
    if (status != CM_SUCCESS) {
        DSS_FREE_POINT(block);
        dss_close_volume(&volume);
        return CM_ERROR;
    }

    status = dss_repair_write_fs_block(input, block, &volume);
    DSS_FREE_POINT(block);
    dss_close_volume(&volume);
    return status;
}

static status_t dss_repair_load_ft_block(repair_input_def_t *input, dss_ft_block_t **block, dss_volume_t *volume)
{
    *block = (dss_ft_block_t *)cm_malloc_align(DSS_ALIGN_SIZE, DSS_BLOCK_SIZE);
    if (*block == NULL) {
        DSS_THROW_ERROR(ERR_ALLOC_MEMORY, DSS_VG_DATA_SIZE, "[TBOX][REPAIR] load ft block");
        return CM_ERROR;
    }
    int64 offset = dss_get_ftb_offset(SIZE_K(input->au_size), &input->block_id);
    LOG_RUN_INF("[TBOX][REPAIR] load ft block to read volume %s, offset:%lld, id:%s.\n", input->vol_path, offset,
        dss_display_metaid(input->block_id));
    status_t status = dss_read_volume(volume, offset, *block, (int32)DSS_BLOCK_SIZE);
    if (status != CM_SUCCESS) {
        LOG_RUN_ERR("[TBOX][REPAIR] Failed to read volume %s, offset:%lld, id:%s, errno:%u.\n", input->vol_path, offset,
            dss_display_metaid(input->block_id), errno);
        DSS_FREE_POINT(*block);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

repair_items_t g_repair_gft_list_items_list[] = {
    REPAIR_ITEM("count", gft_list_t, count, uint32_t),
    REPAIR_ITEM("first", gft_list_t, first, ftid_t),
    REPAIR_ITEM("last", gft_list_t, last, ftid_t),
};
#define REPAIR_FT_LIST_ITEM_COUNT (sizeof(g_repair_gft_list_items_list) / sizeof(repair_items_t))

repair_complex_meta_funcs_t repair_set_gft_list_funcs = {
    "gft list", g_repair_gft_list_items_list, REPAIR_FT_LIST_ITEM_COUNT};
static status_t repair_func_gft_list_t(char *item_ptr, text_t *key, text_t *value)
{
    return repair_func_complex_meta(&repair_set_gft_list_funcs, item_ptr, key, value);
}

static status_t repair_set_ft_name(char *item_ptr, text_t *key, text_t *value)
{
    DSS_RETURN_IF_ERROR(check_no_sub_meta_member(key));
    LOG_RUN_INF("[TBOX][REPAIR] modify ft name from %s to %s;", item_ptr, value->str);
    if (value->len > DSS_MAX_NAME_LEN - 1) {
        DSS_PRINT_RUN_ERROR("[TBOX][REPAIR] modify ft name is too long, max len is %u, your input %s, len is %u.\n",
            (uint32)(DSS_MAX_NAME_LEN - 1), value->str, value->len);
        return CM_ERROR;
    }
    return cm_text2str(value, item_ptr, DSS_MAX_NAME_LEN);
}

static status_t repair_set_ft_type(char *item_ptr, text_t *key, text_t *value)
{
    DSS_RETURN_IF_ERROR(check_no_sub_meta_member(key));
    uint32 ft_type;
    status_t status = cm_text2uint32(value, &ft_type);
    DSS_RETURN_IFERR2(status, DSS_PRINT_RUN_ERROR("repair value:%s is not a valid uint32\n", value->str));
    LOG_RUN_INF("[TBOX][REPAIR] modify uint32 from %u to %u;", *(uint32 *)item_ptr, ft_type);
    if (ft_type > GFT_LINK) {
        DSS_PRINT_RUN_ERROR("[TBOX][REPAIR] modify ft type failed, %u is not a valid type.\n", ft_type);
        return CM_ERROR;
    }
    *(uint32 *)item_ptr = ft_type;
    return CM_SUCCESS;
}

repair_items_t g_repair_ft_node_items_list[] = {
    REPAIR_ITEM_WITH_FUNC("type", gft_node_t, type, uint32_t, repair_set_ft_type),
    REPAIR_ITEM("flags", gft_node_t, flags, uint32_t),
    REPAIR_ITEM("size", gft_node_t, size, uint64),
    REPAIR_ITEM("entry", gft_node_t, entry, dss_block_id_t),
    REPAIR_ITEM("items", gft_node_t, items, gft_list_t),
    REPAIR_ITEM("id", gft_node_t, id, ftid_t),
    REPAIR_ITEM("next", gft_node_t, next, ftid_t),
    REPAIR_ITEM("prev", gft_node_t, prev, ftid_t),
    REPAIR_ITEM_WITH_LEN_FUNC("name", gft_node_t, name, DSS_MAX_NAME_LEN, repair_set_ft_name),
    REPAIR_ITEM("fid", gft_node_t, fid, uint64),
    REPAIR_ITEM("written_size", gft_node_t, written_size, uint64),
    REPAIR_ITEM("parent", gft_node_t, parent, ftid_t),
    REPAIR_ITEM("file_ver", gft_node_t, file_ver, uint64),
    REPAIR_ITEM("min_inited_size", gft_node_t, min_inited_size, uint64),
};
#define REPAIR_FT_NODE_ITEM_COUNT (sizeof(g_repair_ft_node_items_list) / sizeof(repair_items_t))

repair_complex_meta_funcs_t repair_set_ft_node_funcs = {
    "ft node", g_repair_ft_node_items_list, REPAIR_FT_NODE_ITEM_COUNT};
static status_t repair_set_ft_node(char *item_ptr, text_t *key, text_t *value)
{
    return repair_func_complex_meta(&repair_set_ft_node_funcs, item_ptr, key, value);
}

#define REPAIR_FT_BLOCK_ITEM_COUNT (sizeof(g_repair_ft_block_items_list) / sizeof(repair_items_t))
repair_items_t g_repair_ft_block_items_list[] = {
    REPAIR_ITEM_WITH_FUNC("common", dss_ft_block_t, common, dss_common_block_t, repair_set_common_block),
    REPAIR_ITEM("node_num", dss_ft_block_t, node_num, uint32_t),
    REPAIR_ITEM("next", dss_ft_block_t, next, dss_block_id_t),
    REPAIR_ITEM_WITH_OFFSET_FUNC("ft_node", sizeof(dss_ft_block_t), gft_node_t, repair_set_ft_node),
};

static status_t dss_ft_block_repairer(char *block, text_t *name, text_t *value)
{
    text_t part1, part2;
    LOG_RUN_INF("[TBOX][REPAIR] modify ft block key value : %s;", name->str);
    cm_split_text(name, '.', '\0', &part1, &part2);
    cm_trim_text(&part1);
    cm_trim_text(&part2);
    for (uint32_t i = 0; i < REPAIR_FT_BLOCK_ITEM_COUNT; i++) {
        repair_items_t *item = &g_repair_ft_block_items_list[i];
        if (cm_text_str_equal(&part1, item->name)) {
            LOG_RUN_INF("[TBOX][REPAIR] modify ft block key name : %s, offset : %u;", item->name, item->item_offset);
            return item->repair_func((void *)(((char *)block) + item->item_offset), &part2, value);
        }
    }
    DSS_PRINT_RUN_ERROR("[TBOX][REPAIR] Get invalid key : %s, when parse ft block;", part1.str);
    return CM_ERROR;
}

static status_t dss_repair_write_ft_block(repair_input_def_t *input, dss_ft_block_t *block, dss_volume_t *volume)
{
    uint32_t checksum = dss_get_checksum(block, DSS_BLOCK_SIZE);
    int64 offset = dss_get_ftb_offset(SIZE_K(input->au_size), &input->block_id);
    LOG_RUN_INF("[TBOX][REPAIR] Repair ft block %s, volume:%s, offset:%lld, checksum old:%u new:%u.",
        dss_display_metaid(input->block_id), input->vol_path, offset, block->common.checksum, checksum);
    (void)printf("[TBOX][REPAIR] Repair ft block %s, volume:%s, offset:%lld, checksum old:%u new:%u.\n",
        dss_display_metaid(input->block_id), input->vol_path, offset, block->common.checksum, checksum);
    block->common.checksum = checksum;

    status_t status = dss_write_volume(volume, offset, block, (int32)DSS_BLOCK_SIZE);
    if (status != CM_SUCCESS) {
        DSS_PRINT_RUN_ERROR("[TBOX][REPAIR] Failed to write ft block on volume %s, offset:%lld, id:%s.\n",
            input->vol_path, offset, dss_display_metaid(input->block_id));
    }
    return status;
}

status_t dss_repair_ft_block(repair_input_def_t *input)
{
    dss_volume_t volume;
    dss_ft_block_t *block = NULL;
    status_t status = dss_open_volume(input->vol_path, NULL, DSS_CLI_OPEN_FLAG, &volume);
    DSS_RETURN_IFERR2(status, LOG_RUN_ERR("[TBOX][REPAIR] Open volume %s failed.\n", input->vol_path));
    // malloc and load ft block mem
    status = dss_repair_load_ft_block(input, &block, &volume);
    if (status != CM_SUCCESS) {
        DSS_PRINT_RUN_ERROR("[TBOX][REPAIR] load ft block failed, volume %s.\n", input->vol_path);
        dss_close_volume(&volume);
        return CM_ERROR;
    }

    status = dss_repair_meta_by_input(input, (char *)block, dss_ft_block_repairer);
    if (status != CM_SUCCESS) {
        DSS_FREE_POINT(block);
        dss_close_volume(&volume);
        return CM_ERROR;
    }

    status = dss_repair_write_ft_block(input, block, &volume);
    DSS_FREE_POINT(block);
    dss_close_volume(&volume);
    return status;
}

static status_t dss_repair_load_volume_header(dss_volume_t *volume, dss_volume_header_t **header)
{
    *header = NULL;
    char *buf = (char *)cm_malloc_align(DSS_ALIGN_SIZE, DSS_VG_DATA_SIZE);
    if (buf == NULL) {
        DSS_THROW_ERROR(ERR_ALLOC_MEMORY, DSS_VG_DATA_SIZE, "dss_volume_header_t");
        return CM_ERROR;
    }
    status_t status = dss_read_volume(volume, 0, buf, DSS_VG_DATA_SIZE);
    if (status != CM_SUCCESS) {
        DSS_FREE_POINT(buf);
        return CM_ERROR;
    }
    *header = (dss_volume_header_t *)buf;
    return CM_SUCCESS;
}

status_t dss_repair_verify_disk_version(char *vol_path)
{
    dss_volume_t volume;
    status_t status = dss_open_volume(vol_path, NULL, DSS_CLI_OPEN_FLAG, &volume);
    DSS_RETURN_IFERR2(status, DSS_PRINT_RUN_ERROR("[TBOX][REPAIR] Open volume %s failed.\n", vol_path));

    dss_volume_header_t *header = NULL;
    status = dss_repair_load_volume_header(&volume, &header);
    if (status != CM_SUCCESS) {
        DSS_PRINT_RUN_ERROR("[TBOX][REPAIR] Failed to load volume head of %s when verifying disk version.\n", vol_path);
        dss_close_volume(&volume);
        return CM_ERROR;
    }

    if (header->software_version > (uint32)DSS_SOFTWARE_VERSION) {
        DSS_PRINT_RUN_ERROR("[TBOX][REPAIR] disk software_version:%u is not match dsstbox version:%u.",
            header->software_version, (uint32)DSS_SOFTWARE_VERSION);
        status = CM_ERROR;
    }
    DSS_FREE_POINT(header);
    dss_close_volume(&volume);
    return status;
}

static status_t dss_check_is_entry_volume(dss_volume_t *volume, const char *meta_type)
{
    dss_volume_header_t *header = NULL;
    status_t status = dss_repair_load_volume_header(volume, &header);
    if (status != CM_SUCCESS) {
        DSS_PRINT_RUN_ERROR(
            "[TBOX][REPAIR] Failed to load volume head of %s when checking is entry volume.\n", volume->name);
        return CM_ERROR;
    }

    if (header->vol_type.type != DSS_VOLUME_TYPE_MANAGER) {
        DSS_PRINT_RUN_ERROR(
            "[TBOX][REPAIR] Volume %s is not an entry volume, it has no %s to repair.\n", volume->name, meta_type);
        status = CM_ERROR;
    }
    DSS_FREE_POINT(header);
    return status;
}

static status_t dss_repair_load_core_ctrl(dss_volume_t *volume, dss_core_ctrl_t **core_ctrl)
{
    *core_ctrl = NULL;
    char *buf = (char *)cm_malloc_align(DSS_ALIGN_SIZE, DSS_CORE_CTRL_SIZE);
    if (buf == NULL) {
        DSS_THROW_ERROR(ERR_ALLOC_MEMORY, DSS_CORE_CTRL_SIZE, "dss_core_ctrl_t");
        return CM_ERROR;
    }
    status_t status = dss_read_volume(volume, (int64)DSS_CTRL_CORE_OFFSET, buf, (int32)DSS_CORE_CTRL_SIZE);
    if (status != CM_SUCCESS) {
        DSS_FREE_POINT(buf);
        return status;
    }
    *core_ctrl = (dss_core_ctrl_t *)buf;
    return CM_SUCCESS;
}

static status_t dss_repair_write_core_ctrl(dss_volume_t *volume, dss_core_ctrl_t *core_ctrl)
{
    uint32_t checksum = dss_get_checksum(core_ctrl, DSS_CORE_CTRL_SIZE);
    int64 offset = (int64)OFFSET_OF(dss_ctrl_t, core);
    LOG_RUN_INF("[TBOX][REPAIR] Repair core_ctrl on volume:%s, offset:%lld, checksum old:%u new:%u.", volume->name,
        offset, core_ctrl->checksum, checksum);
    (void)printf("[TBOX][REPAIR] Repair core_ctrl on volume:%s, offset:%lld, checksum old:%u new:%u.\n", volume->name,
        offset, core_ctrl->checksum, checksum);
    core_ctrl->checksum = checksum;

    status_t status = dss_write_volume(volume, offset, core_ctrl, (int32)DSS_CORE_CTRL_SIZE);
    if (status != CM_SUCCESS) {
        DSS_PRINT_RUN_ERROR(
            "[TBOX][REPAIR] Failed to write core_ctrl of volume %s, offset:%lld.\n", volume->name, offset);
    }
    return status;
}

status_t dss_repair_core_ctrl(repair_input_def_t *input)
{
    dss_volume_t volume;
    status_t status = dss_open_volume(input->vol_path, NULL, DSS_CLI_OPEN_FLAG, &volume);
    DSS_RETURN_IFERR2(status, LOG_RUN_ERR("[TBOX][REPAIR] Open volume %s failed.", input->vol_path));

    status = dss_check_is_entry_volume(&volume, input->type);
    if (status != CM_SUCCESS) {
        dss_close_volume(&volume);
        return status;
    }

    dss_core_ctrl_t *core_ctrl = NULL;
    status = dss_repair_load_core_ctrl(&volume, &core_ctrl);
    if (status != CM_SUCCESS) {
        dss_close_volume(&volume);
        return status;
    }

    status = dss_repair_meta_by_input(input, (char *)core_ctrl, dss_core_ctrl_repairer);
    if (status != CM_SUCCESS) {
        DSS_FREE_POINT(core_ctrl);
        dss_close_volume(&volume);
        return status;
    }

    status = dss_repair_write_core_ctrl(&volume, core_ctrl);
    DSS_FREE_POINT(core_ctrl);
    dss_close_volume(&volume);
    return status;
}

static status_t dss_repair_write_volume_header(dss_volume_t *volume, dss_volume_header_t *volume_header)
{
    uint32_t checksum = dss_get_checksum(volume_header, DSS_VG_DATA_SIZE);
    LOG_RUN_INF("[TBOX][REPAIR] Repair volume_header on volume:%s, offset:0, checksum old:%u new:%u.", volume->name,
        volume_header->checksum, checksum);
    DSS_PRINT_INF("[TBOX][REPAIR] Repair volume_header on volume:%s, offset:0, checksum old:%u new:%u.\n", volume->name,
        volume_header->checksum, checksum);
    volume_header->checksum = checksum;

    status_t status = dss_write_volume(volume, 0, volume_header, (int32)DSS_VG_DATA_SIZE);
    if (status != CM_SUCCESS) {
        DSS_PRINT_RUN_ERROR("[TBOX][REPAIR] Failed to write volume_header of volume %s, offset:0.\n", volume->name);
    }
    return status;
}

status_t dss_repair_volume_header(repair_input_def_t *input)
{
    dss_volume_t volume;
    status_t status = dss_open_volume(input->vol_path, NULL, DSS_CLI_OPEN_FLAG, &volume);
    DSS_RETURN_IFERR2(status, LOG_RUN_ERR("[TBOX][REPAIR] Open volume %s failed.", input->vol_path));

    dss_volume_header_t *volume_header = NULL;
    status = dss_repair_load_volume_header(&volume, &volume_header);
    if (status != CM_SUCCESS) {
        LOG_RUN_ERR("[TBOX][REPAIR] Failed to load volume header of %s.", input->vol_path);
        dss_close_volume(&volume);
        return status;
    }

    status = dss_repair_meta_by_input(input, (char *)volume_header, dss_volume_header_repairer);
    if (status != CM_SUCCESS) {
        DSS_FREE_POINT(volume_header);
        dss_close_volume(&volume);
        return status;
    }

    status = dss_repair_write_volume_header(&volume, volume_header);
    DSS_FREE_POINT(volume_header);
    dss_close_volume(&volume);
    return status;
}

static status_t dss_software_version_repairer(char *meta_buffer, text_t *name, text_t *value)
{
    if (!cm_text_str_equal(name, DSS_REPAIR_TYPE_SOFTWARE_VERSION)) {
        DSS_PRINT_RUN_ERROR("[TBOX][REPAIR] For -t software_version, only support \"-k software_version=xxx\".\n");
        return CM_ERROR;
    }
    uint32_t version = 0;
    if (cm_text2uint32(value, &version) != CM_SUCCESS) {
        DSS_PRINT_RUN_ERROR("[TBOX][REPAIR] Invalid software version %s.\n", value->str);
        return CM_ERROR;
    }

    if (version > DSS_SOFTWARE_VERSION) {
        DSS_PRINT_RUN_ERROR("[TBOX][REPAIR] Currently newest supported software_version is %u, "
                            "your input is %u.\n",
            (uint32)DSS_SOFTWARE_VERSION, version);
        return CM_ERROR;
    }

    dss_volume_header_t *volume_header = (dss_volume_header_t *)meta_buffer;
    volume_header->software_version = version;
    return CM_SUCCESS;
}

status_t dss_repair_software_version(repair_input_def_t *input)
{
    dss_volume_t volume;
    status_t status = dss_open_volume(input->vol_path, NULL, DSS_CLI_OPEN_FLAG, &volume);
    DSS_RETURN_IFERR2(status, LOG_RUN_ERR("[TBOX][REPAIR] Open volume %s failed.", input->vol_path));

    dss_volume_header_t *volume_header = NULL;
    status = dss_repair_load_volume_header(&volume, &volume_header);
    if (status != CM_SUCCESS) {
        LOG_RUN_ERR("[TBOX][REPAIR] Failed to load volume header of %s.", input->vol_path);
        dss_close_volume(&volume);
        return status;
    }

    status = dss_repair_meta_by_input(input, (char *)volume_header, dss_software_version_repairer);
    if (status != CM_SUCCESS) {
        DSS_FREE_POINT(volume_header);
        dss_close_volume(&volume);
        return status;
    }

    status = dss_repair_write_volume_header(&volume, volume_header);
    DSS_FREE_POINT(volume_header);
    dss_close_volume(&volume);
    return status;
}

repair_items_t g_repair_root_ft_header_items_list[] = {
    REPAIR_ITEM_WITH_FUNC("common", dss_root_ft_header_t, common, dss_common_block_t, repair_set_common_block),
    REPAIR_ITEM("node_num", dss_root_ft_header_t, node_num, uint32_t),
    REPAIR_ITEM("next", dss_root_ft_header_t, next, dss_block_id_t)};
repair_complex_meta_funcs_t g_repair_root_ft_header_funcs = {"root_ft_block_header", g_repair_root_ft_header_items_list,
    sizeof(g_repair_root_ft_header_items_list) / sizeof(repair_items_t)};
static status_t repair_set_root_ft_header(char *item_ptr, text_t *key, text_t *value)
{
    return repair_func_complex_meta(&g_repair_root_ft_header_funcs, item_ptr, key, value);
}

repair_items_t g_repair_gft_root_items_list[] = {REPAIR_ITEM("free_list", gft_root_t, free_list, gft_list_t),
    REPAIR_ITEM("items", gft_root_t, items, gft_list_t), REPAIR_ITEM("fid", gft_root_t, fid, uint64),
    REPAIR_ITEM("first", gft_root_t, first, dss_block_id_t), REPAIR_ITEM("last", gft_root_t, last, dss_block_id_t)};
repair_complex_meta_funcs_t g_repair_gft_root_funcs = {
    "gft_root", g_repair_gft_root_items_list, sizeof(g_repair_gft_root_items_list) / sizeof(repair_items_t)};
static status_t repair_set_gft_root(char *item_ptr, text_t *key, text_t *value)
{
    return repair_func_complex_meta(&g_repair_gft_root_funcs, item_ptr, key, value);
}
#define REPAIR_ROOT_FT_BLOCK_ITEM_COUNT (sizeof(g_repair_root_ft_block_items_list) / sizeof(repair_items_t))
repair_items_t g_repair_root_ft_block_items_list[] = {
    REPAIR_ITEM_WITH_FUNC("ft_block", dss_root_ft_block_t, ft_block, dss_root_ft_header_t, repair_set_root_ft_header),
    REPAIR_ITEM_WITH_FUNC("ft_root", dss_root_ft_block_t, ft_root, gft_root_t, repair_set_gft_root),
};
static status_t dss_root_ft_block_repairer(char *meta_buffer, text_t *name, text_t *value)
{
    text_t part1, part2;
    LOG_RUN_INF("[TBOX][REPAIR] modify root_ft_block key value : %s;", name->str);
    cm_split_text(name, '.', '\0', &part1, &part2);
    cm_trim_text(&part1);
    cm_trim_text(&part2);
    for (uint32_t i = 0; i < REPAIR_ROOT_FT_BLOCK_ITEM_COUNT; i++) {
        repair_items_t *item = &g_repair_root_ft_block_items_list[i];
        if (cm_text_str_equal(&part1, item->name)) {
            LOG_RUN_INF(
                "[TBOX][REPAIR] modify root_ft_block key name : %s, offset : %u;", item->name, item->item_offset);
            return item->repair_func((void *)(((char *)meta_buffer) + item->item_offset), &part2, value);
        }
    }
    DSS_PRINT_RUN_ERROR("[TBOX][REPAIR] Get invalid key : %s, when parse root_ft_block;", part1.str);
    return CM_ERROR;
}

static status_t dss_repair_load_root_ft_block(dss_volume_t *volume, dss_root_ft_block_t **root_ft_block)
{
    *root_ft_block = NULL;
    char *buf = (char *)cm_malloc_align(DSS_ALIGN_SIZE, DSS_BLOCK_SIZE);
    if (buf == NULL) {
        DSS_THROW_ERROR(ERR_ALLOC_MEMORY, DSS_BLOCK_SIZE, "dss_root_ft_block_t");
        return CM_ERROR;
    }
    status_t status = dss_read_volume(volume, (int64)DSS_CTRL_ROOT_OFFSET, buf, DSS_BLOCK_SIZE);
    if (status != CM_SUCCESS) {
        DSS_FREE_POINT(buf);
        return CM_ERROR;
    }
    *root_ft_block = (dss_root_ft_block_t *)buf;
    return CM_SUCCESS;
}

static status_t dss_repair_write_root_ft_block(dss_volume_t *volume, dss_root_ft_block_t *root_ft_block)
{
    uint32_t checksum = dss_get_checksum(root_ft_block, DSS_BLOCK_SIZE);
    int64 offset = (int64)OFFSET_OF(dss_ctrl_t, root);
    LOG_RUN_INF("[TBOX][REPAIR] Repair root_ft_block on volume:%s, offset:%lld, checksum old:%u new:%u.", volume->name,
        offset, root_ft_block->ft_block.common.checksum, checksum);
    (void)printf("[TBOX][REPAIR] Repair root_ft_block on volume:%s, offset:%lld, checksum old:%u new:%u.\n",
        volume->name, offset, root_ft_block->ft_block.common.checksum, checksum);
    root_ft_block->ft_block.common.checksum = checksum;

    status_t status = dss_write_volume(volume, offset, root_ft_block, (int32)DSS_BLOCK_SIZE);
    if (status != CM_SUCCESS) {
        DSS_PRINT_RUN_ERROR(
            "[TBOX][REPAIR] Failed to write root_ft_block of volume %s, offset:%lld.\n", volume->name, offset);
    }
    return status;
}

status_t dss_repair_root_ft_block(repair_input_def_t *input)
{
    dss_volume_t volume;
    status_t status = dss_open_volume(input->vol_path, NULL, DSS_CLI_OPEN_FLAG, &volume);
    DSS_RETURN_IFERR2(status, LOG_RUN_ERR("[TBOX][REPAIR] Open volume %s failed.", input->vol_path));

    status = dss_check_is_entry_volume(&volume, input->type);
    if (status != CM_SUCCESS) {
        dss_close_volume(&volume);
        return status;
    }

    dss_root_ft_block_t *root_ft_block = NULL;
    status = dss_repair_load_root_ft_block(&volume, &root_ft_block);
    if (status != CM_SUCCESS) {
        LOG_RUN_ERR("[TBOX][REPAIR] Failed to load root_ft_block of %s.", input->vol_path);
        dss_close_volume(&volume);
        return status;
    }

    status = dss_repair_meta_by_input(input, (char *)root_ft_block, dss_root_ft_block_repairer);
    if (status != CM_SUCCESS) {
        DSS_FREE_POINT(root_ft_block);
        dss_close_volume(&volume);
        return status;
    }

    status = dss_repair_write_root_ft_block(&volume, root_ft_block);
    DSS_FREE_POINT(root_ft_block);
    dss_close_volume(&volume);
    return status;
}

static status_t dss_repair_load_volume_ctrl(dss_volume_t *volume, dss_volume_ctrl_t **volume_ctrl)
{
    *volume_ctrl = NULL;
    char *buf = (char *)cm_malloc_align(DSS_ALIGN_SIZE, DSS_VOLUME_CTRL_SIZE);
    if (buf == NULL) {
        DSS_THROW_ERROR(ERR_ALLOC_MEMORY, DSS_VOLUME_CTRL_SIZE, "dss_volume_ctrl_t");
        return CM_ERROR;
    }
    status_t status = dss_read_volume(volume, (int64)DSS_CTRL_VOLUME_OFFSET, buf, (int32)DSS_VOLUME_CTRL_SIZE);
    if (status != CM_SUCCESS) {
        DSS_FREE_POINT(buf);
        return CM_ERROR;
    }
    *volume_ctrl = (dss_volume_ctrl_t *)buf;
    return CM_SUCCESS;
}

static status_t repair_set_volume_def_id(char *item_ptr, text_t *key, text_t *value)
{
    DSS_RETURN_IF_ERROR(check_no_sub_meta_member(key));
    // id is only 16-bit long.
    uint16 val;
    status_t status = cm_text2uint16(value, &val);
    DSS_RETURN_IFERR2(status, DSS_PRINT_RUN_ERROR("repair value:%s is not a valid uint16\n", value->str));
    if (val >= DSS_MAX_VOLUMES) {
        DSS_PRINT_RUN_ERROR(
            "[TBOX][REPAIR] defs[i].id must be smaller than %hu, your input is %hu.\n", (uint16)DSS_MAX_VOLUMES, val);
        return CM_ERROR;
    }
    dss_volume_def_t *volume_def = (dss_volume_def_t *)item_ptr;
    LOG_RUN_INF("[TBOX][REPAIR] modify defs[i].id from %hu to %hu;", volume_def->id, val);
    volume_def->id = val;
    return CM_SUCCESS;
}

static status_t repair_set_volume_def_flag(char *item_ptr, text_t *key, text_t *value)
{
    DSS_RETURN_IF_ERROR(check_no_sub_meta_member(key));
    // flags is only 3-bit long.
    uint8 val;
    status_t status = cm_text2uint8(value, &val);
    DSS_RETURN_IFERR2(status, DSS_PRINT_RUN_ERROR("repair value:%s is not a valid uint8\n", value->str));
    if (val >= VOLUME_FLAG_MAX) {
        DSS_PRINT_RUN_ERROR("[TBOX][REPAIR] defs[i].flag must be smaller than %hhu, your input is %hhu.\n",
            (uint8)VOLUME_FLAG_MAX, val);
        return CM_ERROR;
    }
    dss_volume_def_t *volume_def = (dss_volume_def_t *)item_ptr;
    LOG_RUN_INF("[TBOX][REPAIR] modify defs[i].flag from %hhu to %hhu;", volume_def->flag, val);
    volume_def->flag = val;
    return CM_SUCCESS;
}

static status_t repair_set_volume_def_name(char *item_ptr, text_t *key, text_t *value)
{
    DSS_RETURN_IF_ERROR(check_no_sub_meta_member(key));
    if (value->len > DSS_MAX_VOLUME_PATH_LEN - 1) {
        DSS_PRINT_RUN_ERROR("[TBOX][REPAIR] defs[i].name is too long, max len is %u, your input is %u.\n",
            (uint32)(DSS_MAX_VOLUME_PATH_LEN - 1), value->len);
        return CM_ERROR;
    }
    return cm_text2str(value, item_ptr, DSS_MAX_VOLUME_PATH_LEN);
}

static status_t repair_set_volume_def_code(char *item_ptr, text_t *key, text_t *value)
{
    DSS_RETURN_IF_ERROR(check_no_sub_meta_member(key));
    if (value->len > DSS_VOLUME_CODE_SIZE - 1) {
        DSS_PRINT_RUN_ERROR("[TBOX][REPAIR] defs[i].code is too long, max len is %u, your input is %u.\n",
            (uint32)(DSS_VOLUME_CODE_SIZE - 1), value->len);
        return CM_ERROR;
    }
    return cm_text2str(value, item_ptr, DSS_VOLUME_CODE_SIZE);
}

repair_items_t g_repair_volume_def_items_list[] = {
    // id and flag are both bit-field members, treat them as an uint64 with special process
    {"id", 64, 0, repair_set_volume_def_id}, {"flag", 64, 0, repair_set_volume_def_flag},
    REPAIR_ITEM("version", dss_volume_def_t, version, uint64),
    {"name", DSS_MAX_VOLUME_PATH_LEN, OFFSET_OF(dss_volume_def_t, name), repair_set_volume_def_name},
    {"code", DSS_VOLUME_CODE_SIZE, OFFSET_OF(dss_volume_def_t, code), repair_set_volume_def_code}};
repair_complex_meta_funcs_t g_repair_volume_def_funcs = {
    "volume_def", g_repair_volume_def_items_list, sizeof(g_repair_volume_def_items_list) / sizeof(repair_items_t)};
static status_t repair_set_volume_def(char *item_ptr, text_t *key, text_t *value)
{
    return repair_func_complex_meta(&g_repair_volume_def_funcs, item_ptr, key, value);
}

#define REPAIR_VOLUME_CTRL_ITEM_COUNT (sizeof(g_repair_volume_ctrl_items_list) / sizeof(repair_items_t))
repair_items_t g_repair_volume_ctrl_items_list[] = {REPAIR_ITEM("version", dss_volume_ctrl_t, version, uint32_t),
    REPAIR_ITEM_WITH_FUNC("defs", dss_volume_ctrl_t, defs, dss_volume_def_t, repair_set_volume_def)};

static status_t dss_volume_ctrl_repairer(char *meta_buffer, text_t *name, text_t *value)
{
    text_t part1, part2;
    uint32 index = 0;
    LOG_RUN_INF("[TBOX][REPAIR] modify volume_ctrl key value : %s;", name->str);
    cm_split_text(name, '.', '\0', &part1, &part2);
    cm_trim_text(&part1);
    cm_trim_text(&part2);
    for (uint32_t i = 0; i < REPAIR_VOLUME_CTRL_ITEM_COUNT; i++) {
        repair_items_t *item = &g_repair_volume_ctrl_items_list[i];
        if (cm_text_str_equal(&part1, item->name)) {
            LOG_RUN_INF("[TBOX][REPAIR] modify volume_ctrl key name : %s, offset : %u;", item->name, item->item_offset);
            return item->repair_func((void *)(((char *)meta_buffer) + item->item_offset), &part2, value);
        } else if (repair_key_with_index(&part1, item->name, &index)) {
            if (index >= DSS_MAX_VOLUMES) {
                DSS_PRINT_RUN_ERROR("[TBOX][REPAIR] invalid volume_def index : %u;\n", index);
                return CM_ERROR;
            }
            uint32 repair_offset = item->item_offset + index * item->item_size;
            LOG_RUN_INF("[TBOX][REPAIR] modify volume_ctrl key name : %s, index : %u, offset : %u;", item->name, index,
                repair_offset);
            return item->repair_func((void *)(((char *)meta_buffer) + repair_offset), &part2, value);
        }
    }
    DSS_PRINT_RUN_ERROR("[TBOX][REPAIR] Get invalid key : %s, when parse volume_ctrl;", part1.str);
    return CM_ERROR;
}

static status_t dss_repair_write_volume_ctrl(dss_volume_t *volume, dss_volume_ctrl_t *volume_ctrl)
{
    uint32_t checksum = dss_get_checksum(volume_ctrl, DSS_VOLUME_CTRL_SIZE);
    int64 offset = (int64)DSS_CTRL_VOLUME_OFFSET;
    LOG_RUN_INF("[TBOX][REPAIR] Repair root_ft_block on volume:%s, offset:%lld, checksum old:%u new:%u.", volume->name,
        offset, volume_ctrl->checksum, checksum);
    (void)printf("[TBOX][REPAIR] Repair root_ft_block on volume:%s, offset:%lld, checksum old:%u new:%u.\n",
        volume->name, offset, volume_ctrl->checksum, checksum);
    volume_ctrl->checksum = checksum;

    status_t status = dss_write_volume(volume, offset, volume_ctrl, (int32)DSS_VOLUME_CTRL_SIZE);
    if (status != CM_SUCCESS) {
        DSS_PRINT_RUN_ERROR(
            "[TBOX][REPAIR] Failed to write volume_ctrl of volume %s, offset:%lld.\n", volume->name, offset);
    }
    return status;
}

status_t dss_repair_volume_ctrl(repair_input_def_t *input)
{
    dss_volume_t volume;
    status_t status = dss_open_volume(input->vol_path, NULL, DSS_CLI_OPEN_FLAG, &volume);
    DSS_RETURN_IFERR2(status, LOG_RUN_ERR("[TBOX][REPAIR] Open volume %s failed.", input->vol_path));

    status = dss_check_is_entry_volume(&volume, input->type);
    if (status != CM_SUCCESS) {
        dss_close_volume(&volume);
        return status;
    }

    dss_volume_ctrl_t *volume_ctrl = NULL;
    status = dss_repair_load_volume_ctrl(&volume, &volume_ctrl);
    if (status != CM_SUCCESS) {
        LOG_RUN_ERR("[TBOX][REPAIR] Failed to load volume_ctrl of %s.", input->vol_path);
        dss_close_volume(&volume);
        return status;
    }

    status = dss_repair_meta_by_input(input, (char *)volume_ctrl, dss_volume_ctrl_repairer);
    if (status != CM_SUCCESS) {
        DSS_FREE_POINT(volume_ctrl);
        dss_close_volume(&volume);
        return status;
    }

    status = dss_repair_write_volume_ctrl(&volume, volume_ctrl);
    DSS_FREE_POINT(volume_ctrl);
    dss_close_volume(&volume);
    return status;
}

static status_t dss_repair_load_fs_aux_block(repair_input_def_t *input, dss_volume_t *volume, dss_fs_aux_t **block)
{
    *block = (dss_fs_aux_t *)cm_malloc_align(DSS_ALIGN_SIZE, DSS_FS_AUX_SIZE);
    if (*block == NULL) {
        DSS_THROW_ERROR(ERR_ALLOC_MEMORY, DSS_FS_AUX_SIZE, "[TBOX][REPAIR] load fs_aux_block");
        return CM_ERROR;
    }
    int64 offset = dss_get_fab_offset(SIZE_K(input->au_size), input->block_id);
    LOG_RUN_INF("[TBOX][REPAIR] load fs_aux_block to read volume %s, offset:%lld, id:%s.\n", input->vol_path, offset,
        dss_display_metaid(input->block_id));
    status_t status = dss_read_volume(volume, offset, *block, (int32)DSS_FS_AUX_SIZE);
    if (status != CM_SUCCESS) {
        LOG_RUN_ERR("[TBOX][REPAIR] Failed to read volume %s, offset:%lld, id:%s, errno:%u.\n", input->vol_path, offset,
            dss_display_metaid(input->block_id), errno);
        DSS_FREE_POINT(*block);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static status_t repair_set_fs_aux_bitmap_num(char *item_ptr, text_t *key, text_t *value)
{
    DSS_RETURN_IF_ERROR(check_no_sub_meta_member(key));
    uint32 val;
    status_t status = cm_text2uint32(value, &val);
    DSS_RETURN_IFERR2(status, DSS_PRINT_RUN_ERROR("repair value:%s is not a valid uint32\n", value->str));
    if (val > DSS_MAX_FS_AUX_BITMAP_SIZE || val < DSS_MIN_FS_AUX_BITMAP_SIZE) {
        DSS_PRINT_RUN_ERROR("[TBOX][REPAIR] bitmap_num of fs_aux_header must be in [%u, %u], your input is %u.\n",
            (uint32)DSS_MIN_FS_AUX_BITMAP_SIZE, (uint32)DSS_MAX_FS_AUX_BITMAP_SIZE, val);
        return CM_ERROR;
    }
    LOG_RUN_INF("[TBOX][REPAIR] modify bitmap_num of fs_aux_header from %u to %u;", *(uint32 *)item_ptr, val);
    *(uint32 *)item_ptr = val;
    return CM_SUCCESS;
}

#define REPAIR_FS_AUX_BLOCK_HEAD_ITEM_COUNT (sizeof(g_repair_fs_aux_block_head_items_list) / sizeof(repair_items_t))
repair_items_t g_repair_fs_aux_block_head_items_list[] = {
    REPAIR_ITEM_WITH_FUNC("common", dss_fs_aux_header_t, common, dss_common_block_t, repair_set_common_block),
    REPAIR_ITEM("next", dss_fs_aux_header_t, next, dss_block_id_t),
    REPAIR_ITEM("ftid", dss_fs_aux_header_t, ftid, dss_block_id_t),
    REPAIR_ITEM("data_id", dss_fs_aux_header_t, data_id, dss_block_id_t),
    REPAIR_ITEM_WITH_FUNC("bitmap_num", dss_fs_aux_header_t, bitmap_num, uint32_t, repair_set_fs_aux_bitmap_num),
    REPAIR_ITEM("index", dss_fs_aux_header_t, index, uint16_t),
};

repair_complex_meta_funcs_t repair_set_fs_aux_block_header_funcs = {
    "fs aux block header", g_repair_fs_aux_block_head_items_list, REPAIR_FS_AUX_BLOCK_HEAD_ITEM_COUNT};

static status_t repair_set_fs_aux_block_header(char *item_ptr, text_t *key, text_t *value)
{
    return repair_func_complex_meta(&repair_set_fs_aux_block_header_funcs, item_ptr, key, value);
}

static status_t repair_set_fs_aux_block_bitmap(char *item_ptr, text_t *key, text_t *value)
{
    DSS_RETURN_IF_ERROR(check_no_sub_meta_member(key));
    bool32 set_or_unset = (value->str[0] == '1');
    uint8 bit_offset = *(uint8 *)(&value->str[1]);
    uint8 bit_mask = ((uint8)0x1 << bit_offset);
    uint8 new_value = (*(uint8 *)item_ptr);
    if (set_or_unset) {
        new_value = new_value | bit_mask;
    } else {
        new_value = new_value & (~bit_mask);
    }
    LOG_RUN_INF("[TBOX][REPAIR] modify fs_aux_block bitmap from %hhu to %hhu", *(uint8 *)item_ptr, new_value);
    *(uint8 *)item_ptr = new_value;
    return CM_SUCCESS;
}

#define REPAIR_FS_AUX_BLOCK_ITEM_COUNT (sizeof(g_repair_fs_aux_block_items_list) / sizeof(repair_items_t))
repair_items_t g_repair_fs_aux_block_items_list[] = {
    REPAIR_ITEM_WITH_FUNC("head", dss_fs_aux_t, head, dss_fs_aux_header_t, repair_set_fs_aux_block_header),
    REPAIR_ITEM_WITH_FUNC("bitmap", dss_fs_aux_t, bitmap, uchar, repair_set_fs_aux_block_bitmap),
};

static status_t dss_fs_aux_block_repairer(char *block, text_t *name, text_t *value)
{
    text_t part1, part2;
    uint32 index = 0;
    LOG_RUN_INF("[TBOX][REPAIR] modify fs_aux_block key value : %s;", name->str);
    cm_split_text(name, '.', '\0', &part1, &part2);
    cm_trim_text(&part1);
    cm_trim_text(&part2);
    for (uint32_t i = 0; i < REPAIR_FS_AUX_BLOCK_ITEM_COUNT; i++) {
        repair_items_t *item = &g_repair_fs_aux_block_items_list[i];
        if (cm_text_str_equal(&part1, item->name)) {
            LOG_RUN_INF(
                "[TBOX][REPAIR] modify fs_aux_block key name : %s, offset : %u;", item->name, item->item_offset);
            return item->repair_func((void *)(((char *)block) + item->item_offset), &part2, value);
        } else if (repair_key_with_index(&part1, item->name, &index)) {
            // for bitmap of fs_aux_block, "index" does not describe offset of BYTE in bitmap, but describes offset of
            // BIT in bitmap.
            uint32 max_fs_aux_bitmap_idx = (uint32)(DSS_MAX_FS_AUX_BITMAP_SIZE * DSS_BYTE_BITS_SIZE);
            if (index >= max_fs_aux_bitmap_idx) {
                DSS_PRINT_RUN_ERROR(
                    "[TBOX][REPAIR] index of bitmap in fs_aux_block must be smaller than %u, your input is %u.\n",
                    max_fs_aux_bitmap_idx, index);
                return CM_ERROR;
            }
            uint32 byte_index = index / DSS_BYTE_BITS_SIZE;         // offset of BYTE in bitmap
            uint8 bit_index_in_byte = index % DSS_BYTE_BITS_SIZE;   // offset of BIT in BYTE
            uint32 repair_offset = item->item_offset + byte_index;  // we have to modify BYTE by BYTE, not BIT by BIT
            if (value->len != 1 || (value->str[0] != '0' && value->str[0] != '1')) {
                DSS_PRINT_RUN_ERROR(
                    "[TBOX][REPAIR] value of bitmap of fs_aux_block can only be 0 or 1, your input is %s.\n",
                    value->str);
                return CM_ERROR;
            }
            uint16 modify_bufffer = 0;
            text_t modifier = {(char *)&modify_bufffer, sizeof(modify_bufffer)};  // a two-byte buffer
            modifier.str[0] = value->str[0];  // the first byte specifies whether to set or unset the bit in bitmap
            *(uint8 *)(&modifier.str[1]) = bit_index_in_byte;  // the second specifies offset of the bit in its byte
            LOG_RUN_INF("[TBOX][REPAIR] modify fs_aux_block key name : %s, index : %u, offset : %u;", item->name, index,
                repair_offset);
            return item->repair_func((void *)(((char *)block) + repair_offset), &part2, &modifier);
        }
    }
    DSS_PRINT_RUN_ERROR("[TBOX][REPAIR] Get invalid key : %s, when parse fs_aux_block;", part1.str);
    return CM_ERROR;
}

static status_t dss_repair_write_fs_aux_block(repair_input_def_t *input, dss_volume_t *volume, dss_fs_aux_t *block)
{
    uint32_t checksum = dss_get_checksum(block, DSS_FS_AUX_SIZE);
    int64 offset = dss_get_fab_offset(SIZE_K(input->au_size), input->block_id);
    LOG_RUN_INF("[TBOX][REPAIR] Repair fs_aux_block %s, volume:%s, offset:%lld, checksum old:%u new:%u.",
        dss_display_metaid(input->block_id), input->vol_path, offset, block->head.common.checksum, checksum);
    (void)printf("[TBOX][REPAIR] Repair fs_aux_block %s, volume:%s, offset:%lld, checksum old:%u new:%u.\n",
        dss_display_metaid(input->block_id), input->vol_path, offset, block->head.common.checksum, checksum);
    block->head.common.checksum = checksum;

    status_t status = dss_write_volume(volume, offset, block, (int32)DSS_FS_AUX_SIZE);
    if (status != CM_SUCCESS) {
        DSS_PRINT_RUN_ERROR("[TBOX][REPAIR] Failed to write volume %s, offset:%lld, id:%s.\n", input->vol_path, offset,
            dss_display_metaid(input->block_id));
    }
    return status;
}

status_t dss_repair_fs_aux(repair_input_def_t *input)
{
    dss_volume_t volume;
    status_t status = dss_open_volume(input->vol_path, NULL, DSS_CLI_OPEN_FLAG, &volume);
    DSS_RETURN_IFERR2(status, LOG_RUN_ERR("[TBOX][REPAIR] Open volume %s failed.", input->vol_path));

    dss_fs_aux_t *fs_aux_block = NULL;
    status = dss_repair_load_fs_aux_block(input, &volume, &fs_aux_block);
    if (status != CM_SUCCESS) {
        LOG_RUN_ERR("[TBOX][REPAIR] Failed to load fs_aux_block of %s, block_id:%s.", input->vol_path,
            dss_display_metaid(input->block_id));
        dss_close_volume(&volume);
        return status;
    }

    status = dss_repair_meta_by_input(input, (char *)fs_aux_block, dss_fs_aux_block_repairer);
    if (status != CM_SUCCESS) {
        DSS_FREE_POINT(fs_aux_block);
        dss_close_volume(&volume);
        return status;
    }

    status = dss_repair_write_fs_aux_block(input, &volume, fs_aux_block);
    DSS_FREE_POINT(fs_aux_block);
    dss_close_volume(&volume);
    return status;
}