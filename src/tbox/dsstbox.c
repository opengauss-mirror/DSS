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
 * dsstbox.c
 *
 *
 * IDENTIFICATION
 *    src/tbox/dsstbox.c
 *
 * -------------------------------------------------------------------------
 */

#ifndef WIN32
#include <unistd.h>
#include <sys/types.h>
#endif
#include "cm_base.h"
#include "cm_config.h"
#include "cm_dlock.h"
#include "cm_list.h"
#include "cm_system.h"
#include "cm_cipher.h"
#include "cm_encrypt.h"
#include "cm_utils.h"
#include "cm_signal.h"
#include "cm_sec_file.h"

#include "dss_log.h"
#include "dss_errno.h"
#include "dss_malloc.h"
#include "dss_file.h"
#include "dss_args_parse.h"
#include "dss_redo.h"
#include "dss_defs_print.h"
#include "dsstbox_miner.h"
#include "dsstbox.h"
#ifndef WIN32
#include "config.h"
#endif

#ifdef WIN32
#define DEF_DSS_VERSION "Windows does not support this feature because it is built using vs."
#endif

#ifdef WIN32
#define dss_strdup _strdup
#else
#define dss_strdup strdup
#endif

dss_log_def_t g_dss_dsstbox_log[] = {
    {LOG_DEBUG, "debug/dsstbox.dlog"},
    {LOG_OPER, "oper/dsstbox.olog"},
    {LOG_RUN, "run/dsstbox.rlog"},
    {LOG_ALARM, "alarm/dsstbox.alog"},
};

static status_t dss_check_tbox_type(const char *type)
{
    if ((strcmp(type, "fs_block") != 0) && (strcmp(type, "ft_block") != 0) && (strcmp(type, "core") != 0) &&
        (strcmp(type, "root") != 0) && (strcmp(type, "volume") != 0) && (strcmp(type, "header") != 0)) {
        DSS_PRINT_ERROR("Invalid tbox ssrepair type:%s.\n", type);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static status_t dss_check_meta_id(const char *intput)
{
    uint64 id = 0;
    status_t status = cm_str2uint64(intput, &id);
    if (status == CM_ERROR) {
        DSS_PRINT_ERROR("intput:%s is not a valid uint64 meta id\n", intput);
        return CM_ERROR;
    }
    dss_block_id_t *block_id = (dss_block_id_t *)&id;
    if (block_id->volume >= DSS_MAX_VOLUMES) {
        DSS_PRINT_ERROR("block_id is invalid, id = %s.\n", dss_display_metaid(*block_id));
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static dss_args_t tbox_repair_args[] = {
    {'v', "vol_path", CM_TRUE, CM_TRUE, dss_check_volume_path, NULL, NULL, 0, NULL, NULL, 0},
    {'t', "type", CM_TRUE, CM_TRUE, dss_check_tbox_type, NULL, NULL, 0, NULL, NULL, 0},
    {'i', "id", CM_TRUE, CM_TRUE, dss_check_meta_id, NULL, NULL, 0, NULL, NULL, 0},
    {'s', "au_size", CM_TRUE, CM_TRUE, cmd_check_au_size, NULL, NULL, 0, NULL, NULL, 0},
    {'k', "key_value", CM_TRUE, CM_TRUE, NULL, NULL, NULL, 0, NULL, NULL, 0},
};

static dss_args_set_t tbox_repair_args_set = {
    tbox_repair_args,
    sizeof(tbox_repair_args) / sizeof(dss_args_t),
    NULL,
};

static void repair_help(const char *prog_name, int print_flag)
{
    (void)printf("\nUsage:%s ssrepair <-v vol_path> <-t type> <-i block_id> <-s au_size> <-k key_value>\n", prog_name);
    (void)printf("[TOOl BOX] Repairing Metadata on Physical Disks.\n");
    if (print_flag == DSS_HELP_SIMPLE) {
        return;
    }
    (void)printf("-v/--vol_path <vol_path>, <required>, the volume path of the host need to repair\n");
    (void)printf("-t/--type <type>, <required>, repair type for meta info.\n");
    (void)printf("-i/--id <meta_id>, <optional>, the meta id you want to repair if you want to repair fs or ft.\n");
    (void)printf("-s/--au_size <au_size>, <optional>, the size of single alloc uint of volume, unit is KB, "
                 "at least 2MB, at max 64M\n");
    (void)printf("-k/--key_value <key_value>, <required>, the meta id you want to repair.\n");
}

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

typedef struct st_repair_fs_block_items {
    const char *name;
    uint32 item_size;
    uint32 item_offset;
    repair_func_t repair_func;
} repair_items_t;

#define REPAIR_COMMON_BLOCK_ITEM_COUNT (sizeof(g_repair_common_block_items_list) / sizeof(repair_items_t))
repair_items_t g_repair_common_block_items_list[] = {
    REPAIR_ITEM("type", dss_common_block_t, type, uint32_t),
    REPAIR_ITEM("version", dss_common_block_t, version, uint64),
    REPAIR_ITEM("id", dss_common_block_t, id, dss_block_id_t),
    REPAIR_ITEM("flags", dss_common_block_t, flags, uint8_t),
};

static status_t repair_set_common_block(char *item_ptr, text_t *key, text_t *value)
{
    text_t part1, part2;
    cm_split_text(key, '.', '\0', &part1, &part2);
    cm_trim_text(&part1);
    cm_trim_text(&part2);
    for (uint32_t i = 0; i < REPAIR_COMMON_BLOCK_ITEM_COUNT; i++) {
        repair_items_t *item = &g_repair_common_block_items_list[i];
        if (cm_text_str_equal(&part1, item->name)) {
            LOG_RUN_INF(
                "[TBOX][REPAIR] modify common block key name : %s, offset : %u;", item->name, item->item_offset);
            return item->repair_func((void *)(((char*)item_ptr) + item->item_offset), &part2, value);
        }
    }
    DSS_PRINT_ERROR("[TBOX][REPAIR] Get invalid key : %s, when parse common block;\n", part1.str);
    return CM_ERROR;
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

static status_t repair_set_fs_block_header(char *item_ptr, text_t *key, text_t *value)
{
    text_t part1, part2;
    cm_split_text(key, '.', '\0', &part1, &part2);
    cm_trim_text(&part1);
    cm_trim_text(&part2);
    for (uint32_t i = 0; i < REPAIR_FS_BLOCK_HEAD_ITEM_COUNT; i++) {
        repair_items_t *item = &g_repair_fs_block_head_items_list[i];
        if (cm_text_str_equal(&part1, item->name)) {
            LOG_RUN_INF(
                "[TBOX][REPAIR] modify fs block header key name : %s, offset : %u;", item->name, item->item_offset);
            return item->repair_func((void*)(((char*)item_ptr) + item->item_offset), &part2, value);
        }
    }
    DSS_PRINT_ERROR("[TBOX][REPAIR] Get invalid key : %s, when parse fs block header;\n", part1.str);
    return CM_ERROR;
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

static status_t dss_repair_fs_block(repair_input_def_t *input)
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

static status_t dss_repair_verify_disk_version(char *vol_path)
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

static status_t repair_proc(void)
{
    repair_input_def_t input = {0};
    input.vol_path = tbox_repair_args[DSS_ARG_IDX_0].input_args;
    input.type = tbox_repair_args[DSS_ARG_IDX_1].input_args;

    status_t status = cm_str2uint64(tbox_repair_args[DSS_ARG_IDX_2].input_args, (uint64 *)&input.block_id);
    DSS_RETURN_IFERR2(status, DSS_PRINT_ERROR("[TBOX][REPAIR] block_id:%s is not a valid uint64\n",
        tbox_repair_args[DSS_ARG_IDX_2].input_args));
    status = cm_str2uint32(tbox_repair_args[DSS_ARG_IDX_3].input_args, &input.au_size);
    DSS_RETURN_IFERR2(status, DSS_PRINT_ERROR("[TBOX][REPAIR] au_size:%s is not a valid uint32\n",
        tbox_repair_args[DSS_ARG_IDX_3].input_args));
    input.key_value = tbox_repair_args[DSS_ARG_IDX_4].input_args;
    LOG_RUN_INF("[TBOX][REPAIR] vol_path:%s type:%s, id:%s, au_size:%u, key_value:%s", input.vol_path, input.type,
        dss_display_metaid(input.block_id), input.au_size, input.key_value);

    DSS_RETURN_IFERR2(dss_repair_verify_disk_version(input.vol_path),
        DSS_PRINT_ERROR("[TBOX][REPAIR] verify disk version failed %s", input.vol_path));

    if (strcmp(input.type, "fs_block") == 0) {
        status = dss_repair_fs_block(&input);
    } else {
        DSS_PRINT_ERROR("[TBOX][REPAIR] Only support -t fs_block, and your type is %s.", input.type);
        status = CM_ERROR;
    }
    LOG_RUN_INF("[TBOX][REPAIR] vol_path:%s type:%s, id:%s, au_size:%u, key_value:%s result:%u", input.vol_path,
        input.type, dss_display_metaid(input.block_id), input.au_size, input.key_value, status);
    if (status != CM_SUCCESS) {
        (void)printf("[TBOX][REPAIR] Failed to execute repair meta info.\n");
    } else {
        (void)printf("[TBOX][REPAIR] Succeed to execute repair meta info.\n");
    }
    return status;
}

static dss_args_t tbox_miner_args[] = {
    {'g', "vg_name", CM_TRUE, CM_TRUE, dss_check_name, NULL, NULL, 0, NULL, NULL, 0},
    {'s', "start_lsn", CM_TRUE, CM_TRUE, cmd_check_uint64, NULL, NULL, 0, NULL, NULL, 0},
    {'n', "number", CM_TRUE, CM_TRUE, cmd_check_uint64, NULL, NULL, 0, NULL, NULL, 0},
    {'i', "index", CM_TRUE, CM_TRUE, dss_check_index, NULL, NULL, 0, NULL, NULL, 0},
    {'o', "offset", CM_TRUE, CM_TRUE, cmd_check_uint64, NULL, NULL, 0, NULL, NULL, 0},
    {'D', "DSS_HOME", CM_FALSE, CM_TRUE, cmd_check_dss_home, cmd_check_convert_dss_home, cmd_clean_check_convert, 0,
        NULL, NULL, 0},
};

static status_t miner_check_args(dss_args_t *cmd_args_set, int set_size)
{
    if (cmd_args_set == NULL || set_size <= 0) {
        DSS_PRINT_ERROR("[TBOX][MINER]args error.\n");
        return CM_ERROR;
    }
    if (!cmd_args_set[DSS_ARG_MINER_VG].inputed) {
        DSS_PRINT_ERROR("[TBOX][MINER]should set the vol path to load.\n");
        return CM_ERROR;
    }
    if (cmd_args_set[DSS_ARG_MINER_START_LSN].inputed && cmd_args_set[DSS_ARG_MINER_INDEX].inputed) {
        DSS_PRINT_ERROR("[TBOX][MINER]should not set the start_lsn and index at the same time.\n");
        return CM_ERROR;
    }
    if (cmd_args_set[DSS_ARG_MINER_NUMBER].inputed &&
        (!cmd_args_set[DSS_ARG_MINER_START_LSN].inputed || !cmd_args_set[DSS_ARG_MINER_INDEX].inputed)) {
        DSS_PRINT_ERROR("[TBOX][MINER]should set the number with start_lsn or index to show.\n");
        return CM_ERROR;
    }
    if (cmd_args_set[DSS_ARG_MINER_OFFSET].inputed && !cmd_args_set[DSS_ARG_MINER_INDEX].inputed) {
        DSS_PRINT_ERROR("[TBOX][MINER]should set the offset with index to show.\n");
        return CM_ERROR;
    }
    if (cmd_args_set[DSS_ARG_MINER_NUMBER].inputed && cmd_args_set[DSS_ARG_MINER_INDEX].inputed &&
        !cmd_args_set[DSS_ARG_MINER_OFFSET].inputed) {
        DSS_PRINT_ERROR("[TBOX][MINER]should set the offset and number with index to show.\n");
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static dss_args_set_t tbox_miner_args_set = {
    tbox_miner_args,
    sizeof(tbox_miner_args) / sizeof(dss_args_t),
    miner_check_args,
};
static inline void help_param_dsshome_for_box(void)
{
    (void)printf("-D/--DSS_HOME <DSS_HOME>, [optional], the run path of dsstbox, default value is $DSS_HOME.\n");
}

static void miner_help(const char *prog_name, int print_flag)
{
    (void)printf("\nUsage:");
    (void)printf("\n%s ssminer <-g vg_name> [-D DSS_HOME]\n", prog_name);
    (void)printf("%s ssminer <-g vg_name> <-s start_lsn> [-n number] [-D DSS_HOME]\n", prog_name);
    (void)printf("%s ssminer <-g vg_name> <-i index> [-o offset] [-n number] [-D DSS_HOME]\n", prog_name);
    (void)printf("[TOOl BOX] Parsing redo logs on physical disks.\n");
    if (print_flag == DSS_HELP_SIMPLE) {
        return;
    }
    (void)printf("-g/--vg_name <vg_name>, <required>, the volume group name.\n");
    (void)printf("-s/--start_lsn <start_lsn>, <required>, the start lsn to parse.\n");
    (void)printf(
        "-n/--number <number>, [optional], the number to parse. If this parameter is used with start_lsn, "
        "number records starting with lsn are displayed. If this parameter is used with index and offset, number"
        "records from the specified position are displayed.\n");
    (void)printf("-i/--index <index>, <required>, the index of redo buffer.\n");
    (void)printf("-o/--offset <offset>, [optional], the offset to parse. This parameter should be set with index.\n");
    help_param_dsshome_for_box();
}

static status_t miner_proc_inner(miner_run_ctx_def_t *ctx)
{
    status_t status;
    if (tbox_miner_args[DSS_ARG_MINER_NUMBER].inputed) {
        status = cm_str2uint64(tbox_miner_args[DSS_ARG_MINER_NUMBER].input_args, (uint64 *)&ctx->input.number);
        DSS_RETURN_IFERR2(status, DSS_PRINT_ERROR("[TBOX][MINER] number:%s is not a valid uint64.\n",
                                      tbox_miner_args[DSS_ARG_MINER_NUMBER].input_args));
        if (ctx->input.number == 0) {
            if (tbox_miner_args[DSS_ARG_MINER_START_LSN].inputed) {
                status =
                    cm_str2uint64(tbox_miner_args[DSS_ARG_MINER_START_LSN].input_args, (uint64 *)&ctx->input.start_lsn);
                DSS_RETURN_IFERR2(status, DSS_PRINT_ERROR("[TBOX][MINER] start_lsn:%s is not a valid uint64.\n",
                                              tbox_miner_args[DSS_ARG_MINER_START_LSN].input_args));
                if (ctx->input.start_lsn == 0) {
                    dss_print_redo_ctrl(&ctx->vg_item->dss_ctrl->redo_ctrl);
                    return CM_SUCCESS;
                }
            }
            DSS_PRINT_ERROR("[TBOX][MINER]number should not be 0.\n");
            return CM_ERROR;
        }
    }
    if (tbox_miner_args[DSS_ARG_MINER_START_LSN].inputed) {
        status = cm_str2uint64(tbox_miner_args[DSS_ARG_MINER_START_LSN].input_args, (uint64 *)&ctx->input.start_lsn);
        DSS_RETURN_IFERR2(status, DSS_PRINT_ERROR("[TBOX][MINER] start_lsn:%s is not a valid uint64.\n",
                                      tbox_miner_args[DSS_ARG_MINER_START_LSN].input_args));
        if (ctx->input.start_lsn == 0) {
            DSS_PRINT_ERROR("[TBOX][MINER]start_lsn should not be 0.\n");
            return CM_ERROR;
        }
        status = dss_print_redo_info_by_lsn(ctx);
    } else if (tbox_miner_args[DSS_ARG_MINER_INDEX].inputed) {
        status = cm_str2uint32(tbox_miner_args[DSS_ARG_MINER_INDEX].input_args, (uint32 *)&ctx->input.index);
        DSS_RETURN_IFERR2(status, DSS_PRINT_ERROR("[TBOX][MINER] index:%s is not a valid uint32.\n",
                                      tbox_miner_args[DSS_ARG_MINER_START_LSN].input_args));
        if (ctx->input.index >= ctx->count) {
            DSS_PRINT_ERROR(
                "[TBOX][MINER]No valid redo from index %u for count is %u.\n", ctx->input.index, ctx->count);
            return CM_ERROR;
        }                          
        if (tbox_miner_args[DSS_ARG_MINER_OFFSET].inputed) {
            status = cm_str2uint64(tbox_miner_args[DSS_ARG_MINER_OFFSET].input_args, (uint64 *)&ctx->input.offset);
            DSS_RETURN_IFERR2(status, DSS_PRINT_ERROR("[TBOX][MINER] offset:%s is not a valid uint64.\n",
                                          tbox_miner_args[DSS_ARG_MINER_OFFSET].input_args));
            status = dss_print_redo_info_by_index(ctx);
        } else {
            status = dss_print_redo_info(ctx);
        }
    } else {
        status = dss_print_redo_info(ctx);
    }
    return status;
}

static status_t miner_proc(void)
{
    status_t status;
    dss_config_t inst_cfg;
    char *home = tbox_miner_args[DSS_ARG_MINER_HOME].input_args;
    status = set_config_info(home, &inst_cfg);
    if (status != CM_SUCCESS) {
        DSS_PRINT_ERROR("[TBOX][MINER]Failed to set config info.\n");
        return status;
    }
    status =
        dss_init_loggers(&inst_cfg, g_dss_dsstbox_log, sizeof(g_dss_dsstbox_log) / sizeof(dss_log_def_t), "dsstbox");
    if (status != CM_SUCCESS) {
        DSS_PRINT_ERROR("[TBOX][MINER]DSS init loggers failed!\n");
        return status;
    }
    status = dss_load_vg_conf_info(&g_vgs_info, &inst_cfg);
    if (status != CM_SUCCESS) {
        DSS_PRINT_ERROR("[TBOX][MINER]Failed to load vg info from config, errcode is %d.\n", status);
        return status;
    }
    miner_run_ctx_def_t ctx = {0};
    ctx.input.vg_name = tbox_miner_args[DSS_ARG_MINER_VG].input_args;
    status = dss_init_miner_run_ctx(&ctx);
    if (status != CM_SUCCESS) {
        DSS_PRINT_ERROR("[TBOX][MINER]Failed to init miner run ctx.\n");
        return CM_ERROR;
    }
    status = miner_proc_inner(&ctx);
    if (status != CM_SUCCESS) {
        DSS_PRINT_ERROR("[TBOX][MINER]Failed to print expected redo info.\n");
    } else {
        DSS_PRINT_ERROR("[TBOX][MINER]Succeed to print expected redo info.\n");
    }
    DSS_FREE_POINT(ctx.vg_item->dss_ctrl);
    DSS_FREE_POINT(g_vgs_info);
    DSS_FREE_POINT(ctx.log_buf);
    return status;
}

// clang-format off
dss_admin_cmd_t g_dss_admin_tbox[] = {{"ssrepair", repair_help, repair_proc, &tbox_repair_args_set, CM_TRUE},
                                      {"ssminer", miner_help, miner_proc, &tbox_miner_args_set, CM_TRUE},
};

static bool32 get_tbox_idx(int argc, char **argv, uint32_t *idx)
{
    for (uint32 i = 0; i < sizeof(g_dss_admin_tbox) / sizeof(g_dss_admin_tbox[0]); ++i) {
        *idx = i;
        if (strcmp(g_dss_admin_tbox[i].cmd, argv[DSS_ARG_IDX_1]) == 0) {
            return CM_TRUE;
        }
    }
    return CM_FALSE;
}

// clang-format on
static void tbox_help(char *prog_name, dss_help_type help_type)
{
    (void)printf("Usage:dsstbox [command] [OPTIONS]\n\n");
    (void)printf("Usage:%s -h/--help show help information of dsstbox\n", prog_name);
    (void)printf("Usage:%s -a/--all show all help information of dsstbox\n", prog_name);
    (void)printf("Usage:%s -v/--version show version information of dsstbox\n", prog_name);
    (void)printf("commands:\n");
    for (uint32 i = 0; i < sizeof(g_dss_admin_tbox) / sizeof(g_dss_admin_tbox[0]); ++i) {
        g_dss_admin_tbox[i].help(prog_name, help_type);
    }
    (void)printf("\n\n");
}

void dss_help_tbox(int argc, char **argv, uint32_t *idx)
{
    if (argc < CMD_ARGS_AT_LEAST) {
        (void)printf("dsstbox: no operation specified.\n");
        (void)printf("dsstbox: Try \"dsstbox -h/--help\" for help information.\n");
        (void)printf("dsstbox: Try \"dsstbox -a/--all\" for detailed help information.\n");
        exit(EXIT_FAILURE);
    }
    if (cm_str_equal(argv[1], "-v") || cm_str_equal(argv[1], "--version")) {
        (void)printf("dsstbox %s\n", (char *)DEF_DSS_VERSION);
        exit(EXIT_SUCCESS);
    }
    if (cm_str_equal(argv[1], "-h") || cm_str_equal(argv[1], "--help")) {
        tbox_help(argv[0], DSS_HELP_SIMPLE);
        exit(EXIT_SUCCESS);
    }
    if (cm_str_equal(argv[1], "-a") || cm_str_equal(argv[1], "--all")) {
        tbox_help(argv[0], DSS_HELP_DETAIL);
        exit(EXIT_SUCCESS);
    }

    if (!get_tbox_idx(argc, argv, idx)) {
        (void)printf("tbox:%s can not find.\n", argv[DSS_ARG_IDX_1]);
        tbox_help(argv[0], DSS_HELP_SIMPLE);
        exit(EXIT_FAILURE);
    }
    if (argc > DSS_ARG_IDX_2 &&
        (strcmp(argv[DSS_ARG_IDX_2], "-h") == 0 || strcmp(argv[DSS_ARG_IDX_2], "--help") == 0)) {
        g_dss_admin_tbox[*idx].help(argv[0], DSS_HELP_DETAIL);
        exit(EXIT_SUCCESS);
    }
}

static status_t dss_exec_tbox_core(int argc, char **argv, uint32 tbox_idx)
{
    cmd_parse_init(g_dss_admin_tbox[tbox_idx].args_set->cmd_args, g_dss_admin_tbox[tbox_idx].args_set->args_size);
    if (cmd_parse_args(argc, argv, g_dss_admin_tbox[tbox_idx].args_set) != CM_SUCCESS) {
        int32 code;
        const char *message;
        cm_get_error(&code, &message);
        if (code != 0) {
            DSS_PRINT_ERROR("\ntbox %s error:%d %s.\n", g_dss_admin_tbox[tbox_idx].cmd, code, message);
        }
        return CM_ERROR;
    }
    status_t ret = g_dss_admin_tbox[tbox_idx].proc();
    cmd_parse_clean(g_dss_admin_tbox[tbox_idx].args_set->cmd_args, g_dss_admin_tbox[tbox_idx].args_set->args_size);
    return ret;
}

static status_t dss_exec_tbox(int argc, char **argv, uint32 idx)
{
    status_t status = dss_exec_tbox_core(argc, argv, idx);
    // write oper log
    return status;
}

int main(int argc, char **argv)
{
#ifndef WIN32
    // check root
    if (geteuid() == 0 || getuid() != geteuid()) {
        (void)printf("The root user is not permitted to execute the dsstbox "
                     "and the real uids must be the same as the effective uids.\n");
        (void)fflush(stdout);
        return CM_ERROR;
    }
    if (cm_regist_signal(SIGPIPE, SIG_IGN) != CM_SUCCESS) {
        (void)printf("Can't assign function for SIGPIPE.\n");
        return CM_ERROR;
    }
#endif
    uint32 idx;
    dss_help_tbox(argc, argv, &idx);
    dss_config_t inst_cfg;
    if (dss_set_cfg_dir(NULL, &inst_cfg) != CM_SUCCESS) {
        (void)printf("Environment variant DSS_HOME not found!\n");
        return CM_ERROR;
    }
    status_t ret = dss_load_local_server_config(&inst_cfg);
    if (ret != CM_SUCCESS) {
        (void)printf("load local server config failed during init loggers.\n");
        return CM_ERROR;
    }

    if (cm_start_timer(g_timer()) != CM_SUCCESS) {
        (void)printf("Aborted due to starting timer thread.\n");
        return CM_ERROR;
    }

    ret = dss_init_loggers(&inst_cfg, g_dss_dsstbox_log, sizeof(g_dss_dsstbox_log) / sizeof(dss_log_def_t), "dsstbox");
    if (ret != CM_SUCCESS) {
        (void)printf("%s\nDSS init loggers failed!\n", cm_get_errormsg(cm_get_error_code()));
        return ret;
    }
    LOG_RUN_INF("[TBOX] Begin to execute.");
    cm_reset_error();
    ret = dss_exec_tbox(argc, argv, idx);
    LOG_RUN_INF("[TBOX] execute finish result:%u.", ret);
    return ret;
}