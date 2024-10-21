/*
 * Copyright (c) 2024 Huawei Technologies Co.,Ltd.
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
    dss_block_id_t block_id;
    status_t status = cm_text2uint64(value, (uint64 *)&block_id);
    DSS_RETURN_IFERR2(status, DSS_PRINT_ERROR("block_id:%s is not a valid uint64\n", value->str));
    dss_block_id_t *repair_ptr = (dss_block_id_t *)item_ptr;
    LOG_RUN_INF("[TBOX][REPAIR] modify block id from %s.", dss_display_metaid(*repair_ptr));
    LOG_RUN_INF("[TBOX][REPAIR] modify block id to %s.", dss_display_metaid(block_id));
    *repair_ptr = block_id;
    return CM_SUCCESS;
}

static status_t repair_func_uint64(char *item_ptr, text_t *key, text_t *value)
{
    uint64 val;
    status_t status = cm_text2uint64(value, &val);
    DSS_RETURN_IFERR2(status, DSS_PRINT_ERROR("repair value:%s is not a valid uint64\n", value->str));
    LOG_RUN_INF("[TBOX][REPAIR] modify uint64 from %llu to %llu;", *(uint64 *)item_ptr, val);
    *(uint64 *)item_ptr = val;
    return CM_SUCCESS;
}

static status_t repair_func_uint32_t(char *item_ptr, text_t *key, text_t *value)
{
    uint32 val;
    status_t status = cm_text2uint32(value, &val);
    DSS_RETURN_IFERR2(status, DSS_PRINT_ERROR("repair value:%s is not a valid uint32\n", value->str));
    LOG_RUN_INF("[TBOX][REPAIR] modify uint32 from %u to %u;", *(uint32 *)item_ptr, val);
    *(uint32 *)item_ptr = val;
    return CM_SUCCESS;
}

static status_t repair_func_uint16_t(char *item_ptr, text_t *key, text_t *value)
{
    uint16 val;
    status_t status = cm_text2uint16(value, &val);
    DSS_RETURN_IFERR2(status, DSS_PRINT_ERROR("repair value:%s is not a valid uint16\n", value->str));
    LOG_RUN_INF("[TBOX][REPAIR] modify uint16 from %hu to %hu;", *(uint16 *)item_ptr, val);
    *(uint16 *)item_ptr = val;
    return CM_SUCCESS;
}

static status_t repair_func_uint8_t(char *item_ptr, text_t *key, text_t *value)
{
    uint8 val;
    status_t status = cm_text2uint8(value, &val);
    DSS_RETURN_IFERR2(status, DSS_PRINT_ERROR("repair value:%s is not a valid uint8\n", value->str));
    LOG_RUN_INF("[TBOX][REPAIR] modify uint8 from %hhu to %hhu;", *(uint8 *)item_ptr, val);
    *(uint8 *)item_ptr = val;
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
    DSS_PRINT_ERROR("[TBOX][REPAIR] Get invalid key : %s, when parse %s;\n", part1.str, repair_funcs->meta_name);
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

#define ARCHIVE_LOGS_LEN (sizeof(arch_log_id_t) * GS_MAX_ARCH_DEST)

typedef status_t (*repair_func_t)(char *item_ptr, text_t *key, text_t *value);

#define REPAIR_COMMON_BLOCK_ITEM_COUNT (sizeof(g_repair_common_block_items_list) / sizeof(repair_items_t))
repair_items_t g_repair_common_block_items_list[] = {
    REPAIR_ITEM("type", dss_common_block_t, type, uint32_t),
    REPAIR_ITEM("version", dss_common_block_t, version, uint64),
    REPAIR_ITEM("id", dss_common_block_t, id, dss_block_id_t),
    REPAIR_ITEM("flags", dss_common_block_t, flags, uint8_t),
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

static status_t repair_modify_fs_block_kv(char *block, text_t *name, text_t *value)
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
                LOG_RUN_ERR("[TBOX][REPAIR] invalid fs block index : %u;", index);
                return CM_ERROR;
            }
            uint32 repair_offset = item->item_offset + index * item->item_size;
            LOG_RUN_INF("[TBOX][REPAIR] modify fs block key name : %s, index : %u, offset : %u;", item->name, index,
                repair_offset);
            return item->repair_func((void *)(((char *)block) + repair_offset), &part2, value);
        }
    }
    DSS_PRINT_ERROR("[TBOX][REPAIR] Get invalid key : %s, when parse fs block;", part1.str);
    return CM_ERROR;
}

static status_t dss_repair_fs_block_core(repair_input_def_t *input, char *block)
{
    text_t key_value, name, value;
    bool32 is_eof = CM_FALSE;
    uint32 line_no = 0;
    status_t ret = CM_ERROR;
    key_value.len = (uint32)strlen(input->key_value);
    char *parse_str = (char *)dss_strdup(input->key_value);
    key_value.str = parse_str;
    if (key_value.str == NULL) {
        DSS_PRINT_ERROR("[TBOX][REPAIR] Failed to strdup %u buf;\n", key_value.len);
        return ret;
    }

    dss_format_tbox_key_value(&key_value);
    for (;;) {
        // parse each key and value
        if (repair_parse_kv(&key_value, &name, &value, &line_no, &is_eof) != CM_SUCCESS) {
            DSS_PRINT_ERROR("[TBOX][REPAIR] invalid intput key_value :%s;\n", input->key_value);
            ret = CM_ERROR;
            break;
        }

        if (is_eof) {
            LOG_RUN_INF("[TBOX][REPAIR] Finish modify fs block:%s.", dss_display_metaid(input->block_id));
            ret = CM_SUCCESS;
            break;
        }
        cm_trim_text(&name);
        cm_trim_text(&value);
        cm_text_lower(&name);
        ret = repair_modify_fs_block_kv(block, &name, &value);
        DSS_BREAK_IFERR2(ret, DSS_PRINT_ERROR("[TBOX][REPAIR] Invalid intput key_value :%s;\n", input->key_value));
    }
    DSS_FREE_POINT(parse_str);
    return ret;
}

static status_t dss_repair_load_fs_block(repair_input_def_t *input, dss_fs_block_t **block, dss_volume_t *volume)
{
    status_t status = dss_open_volume(input->vol_path, NULL, DSS_CLI_OPEN_FLAG, volume);
    DSS_RETURN_IFERR2(status, LOG_RUN_ERR("[TBOX][REPAIR] Open volume %s failed.", input->vol_path));
    *block = (dss_fs_block_t *)cm_malloc_align(DSS_ALIGN_SIZE, DSS_FILE_SPACE_BLOCK_SIZE);
    if (*block == NULL) {
        dss_close_volume(volume);
        DSS_THROW_ERROR(ERR_ALLOC_MEMORY, DSS_VG_DATA_SIZE, "[TBOX][REPAIR] load fs block");
        return CM_ERROR;
    }
    int64 offset = dss_get_fsb_offset(SIZE_K(input->au_size), &input->block_id);
    LOG_RUN_INF("[TBOX][REPAIR] load fs block to read volume %s, offset:%lld, id:%s.\n", input->vol_path, offset,
        dss_display_metaid(input->block_id));
    status = dss_read_volume(volume, offset, *block, DSS_FILE_SPACE_BLOCK_SIZE);
    if (status != CM_SUCCESS) {
        LOG_RUN_ERR("[TBOX][REPAIR] Failed to read volume %s, offset:%lld, id:%s, errno:%u.\n", input->vol_path, offset,
            dss_display_metaid(input->block_id), errno);
        DSS_FREE_POINT(*block);
        dss_close_volume(volume);
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

    status_t status = dss_write_volume(volume, offset, block, DSS_FILE_SPACE_BLOCK_SIZE);
    if (status != CM_SUCCESS) {
        LOG_RUN_ERR("[TBOX][REPAIR] Failed to write volume %s, offset:%lld, id:%s.\n", input->vol_path, offset,
            dss_display_metaid(input->block_id));
        DSS_PRINT_ERROR("Failed to write volume %s, offset:%lld, id:%s.\n", input->vol_path, offset,
            dss_display_metaid(input->block_id));
    }
    return status;
}

status_t dss_repair_fs_block(repair_input_def_t *input)
{
    dss_volume_t volume;
    dss_fs_block_t *block = NULL;
    status_t status = dss_repair_load_fs_block(input, &block, &volume);
    DSS_RETURN_IFERR2(status, DSS_PRINT_ERROR("[TBOX][REPAIR] load fs block failed, volume %s.", input->vol_path));

    status = dss_repair_fs_block_core(input, (char *)block);
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

status_t dss_repair_verify_disk_version(char *vol_path)
{
    dss_volume_t volume;
    status_t status = dss_open_volume(vol_path, NULL, DSS_CLI_OPEN_FLAG, &volume);
    DSS_RETURN_IFERR2(status, DSS_PRINT_ERROR("[TBOX][REPAIR] Open volume %s failed.", vol_path));
    char *buf = (char *)cm_malloc_align(DSS_ALIGN_SIZE, DSS_VG_DATA_SIZE);
    if (buf == NULL) {
        dss_close_volume(&volume);
        DSS_THROW_ERROR(ERR_ALLOC_MEMORY, DSS_VG_DATA_SIZE, "[TBOX][REPAIR] verify disk version");
        return CM_ERROR;
    }
    status = dss_read_volume(&volume, 0, buf, DSS_VG_DATA_SIZE);
    if (status != CM_SUCCESS) {
        DSS_FREE_POINT(buf);
        dss_close_volume(&volume);
        return CM_ERROR;
    }
    dss_volume_header_t *header = (dss_volume_header_t *)buf;
    if (header->software_version > DSS_SOFTWARE_VERSION) {
        LOG_RUN_ERR("[TBOX][REPAIR] disk software_version:%u is not match dsstbox version:%u.",
            header->software_version, DSS_SOFTWARE_VERSION);
        DSS_PRINT_ERROR("[TBOX][REPAIR] disk software_version:%u is not match dsstbox version:%u.",
            header->software_version, DSS_SOFTWARE_VERSION);
        status = CM_ERROR;
    }
    DSS_FREE_POINT(buf);
    dss_close_volume(&volume);
    return status;
}
