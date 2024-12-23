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
 * dss_defs.c
 *
 *
 * IDENTIFICATION
 *    src/common/persist/dss_defs.c
 *
 * -------------------------------------------------------------------------
 */

#include "dss_defs.h"
#include "cm_num.h"
#include "dss_errno.h"
#include "cm_text.h"

auid_t dss_invalid_auid = {.volume = 0x3ff, .au = 0x3ffffffff, .block = 0x1ffff, .item = 0x7};
auid_t dss_set_inited_mask = {.volume = 0, .au = 0, .block = 0, .item = 0x1};
auid_t dss_unset_inited_mask = {.volume = 0x3ff, .au = 0x3ffffffff, .block = 0x1ffff, .item = 0};

static char *g_dss_cmd_desc[DSS_CMD_TYPE_OFFSET(DSS_CMD_END)] = {
    [DSS_CMD_TYPE_OFFSET(DSS_CMD_MKDIR)] = "mkdir",
    [DSS_CMD_TYPE_OFFSET(DSS_CMD_RMDIR)] = "rmdir",
    [DSS_CMD_TYPE_OFFSET(DSS_CMD_OPEN_DIR)] = "open dir",
    [DSS_CMD_TYPE_OFFSET(DSS_CMD_CLOSE_DIR)] = "close dir",
    [DSS_CMD_TYPE_OFFSET(DSS_CMD_OPEN_FILE)] = "open file",
    [DSS_CMD_TYPE_OFFSET(DSS_CMD_CLOSE_FILE)] = "close file",
    [DSS_CMD_TYPE_OFFSET(DSS_CMD_CREATE_FILE)] = "create file",
    [DSS_CMD_TYPE_OFFSET(DSS_CMD_DELETE_FILE)] = "delete file",
    [DSS_CMD_TYPE_OFFSET(DSS_CMD_EXTEND_FILE)] = "extend file",
    [DSS_CMD_TYPE_OFFSET(DSS_CMD_ATTACH_FILE)] = "attach file",
    [DSS_CMD_TYPE_OFFSET(DSS_CMD_DETACH_FILE)] = "detach file",
    [DSS_CMD_TYPE_OFFSET(DSS_CMD_RENAME_FILE)] = "rename file",
    [DSS_CMD_TYPE_OFFSET(DSS_CMD_REFRESH_FILE)] = "refresh file",
    [DSS_CMD_TYPE_OFFSET(DSS_CMD_TRUNCATE_FILE)] = "truncate file",
    [DSS_CMD_TYPE_OFFSET(DSS_CMD_REFRESH_FILE_TABLE)] = "refresh file table",
    [DSS_CMD_TYPE_OFFSET(DSS_CMD_FALLOCATE_FILE)] = "fallocate file",
    [DSS_CMD_TYPE_OFFSET(DSS_CMD_ADD_VOLUME)] = "add volume",
    [DSS_CMD_TYPE_OFFSET(DSS_CMD_REMOVE_VOLUME)] = "remove volume",
    [DSS_CMD_TYPE_OFFSET(DSS_CMD_REFRESH_VOLUME)] = "refresh volume",
    [DSS_CMD_TYPE_OFFSET(DSS_CMD_KICKH)] = "kick off host",
    [DSS_CMD_TYPE_OFFSET(DSS_CMD_LOAD_CTRL)] = "load ctrl",
    [DSS_CMD_TYPE_OFFSET(DSS_CMD_UPDATE_WRITTEN_SIZE)] = "update written size",
    [DSS_CMD_TYPE_OFFSET(DSS_CMD_STOP_SERVER)] = "stopserver",
    [DSS_CMD_TYPE_OFFSET(DSS_CMD_SETCFG)] = "setcfg",
    [DSS_CMD_TYPE_OFFSET(DSS_CMD_SYMLINK)] = "symlink",
    [DSS_CMD_TYPE_OFFSET(DSS_CMD_UNLINK)] = "unlink",
    [DSS_CMD_TYPE_OFFSET(DSS_CMD_SET_MAIN_INST)] = "set main inst",
    [DSS_CMD_TYPE_OFFSET(DSS_CMD_SWITCH_LOCK)] = "switch cm lock",
    [DSS_CMD_TYPE_OFFSET(DSS_CMD_DISABLE_GRAB_LOCK)] = "disable grab cm lock",
    [DSS_CMD_TYPE_OFFSET(DSS_CMD_ENABLE_GRAB_LOCK)] = "enable grab cm lock",
    [DSS_CMD_TYPE_OFFSET(DSS_CMD_HOTPATCH)] = "hotpatch operation",
    [DSS_CMD_TYPE_OFFSET(DSS_CMD_HANDSHAKE)] = "handshake with server",
    [DSS_CMD_TYPE_OFFSET(DSS_CMD_EXIST)] = "exist item",
    [DSS_CMD_TYPE_OFFSET(DSS_CMD_READLINK)] = "readlink",
    [DSS_CMD_TYPE_OFFSET(DSS_CMD_GET_FTID_BY_PATH)] = "get ftid by path",
    [DSS_CMD_TYPE_OFFSET(DSS_CMD_GETCFG)] = "getcfg",
    [DSS_CMD_TYPE_OFFSET(DSS_CMD_GET_INST_STATUS)] = "get inst status",
    [DSS_CMD_TYPE_OFFSET(DSS_CMD_GET_TIME_STAT)] = "get time stat",
    [DSS_CMD_TYPE_OFFSET(DSS_CMD_EXEC_REMOTE)] = "exec remote",
    [DSS_CMD_TYPE_OFFSET(DSS_CMD_QUERY_HOTPATCH)] = "query status of hotpatch",
};

char *dss_get_cmd_desc(dss_cmd_type_e cmd_type)
{
    if (cmd_type < DSS_CMD_BEGIN || cmd_type >= DSS_CMD_END) {
        return "unknown";
    }
    return g_dss_cmd_desc[DSS_CMD_TYPE_OFFSET(cmd_type)];
}

#define DSS_MAX_PRINT_LEVEL 4
static char *g_dss_printf_tab[DSS_MAX_PRINT_LEVEL] = {
    "",
    "\t",
    "\t\t",
    "\t\t\t",
};

char *dss_get_print_tab(uint8 level)
{
    return g_dss_printf_tab[level];
}

#define DSS_DISPLAY_SIZE 75

#ifdef WIN32
__declspec(thread) char g_display_buf[DSS_DISPLAY_SIZE];
#else
__thread char g_display_buf[DSS_DISPLAY_SIZE];
#endif

char *dss_display_metaid(auid_t id)
{
    int ret = sprintf_s(g_display_buf, DSS_DISPLAY_SIZE, "metaid:%llu (v:%u, au:%llu, block:%u, item:%u)",
        DSS_ID_TO_U64(id), (id).volume, (uint64)(id).au, (id).block, (id).item);
    if (ret < 0) {
        g_display_buf[0] = '\0';
    }
    return g_display_buf;
}