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
 * dss_au.c
 *
 *
 * IDENTIFICATION
 *    src/common/persist/dss_au.c
 *
 * -------------------------------------------------------------------------
 */

#include "dss_au.h"

auid_t dss_invalid_auid = {.volume = 0x3ff, .au = 0x3ffffffff, .block = 0x1ffff, .item = 0x7};
auid_t dss_set_inited_mask = {.volume = 0, .au = 0, .block = 0, .item = 0x1};
auid_t dss_unset_inited_mask = {.volume = 0x3ff, .au = 0x3ffffffff, .block = 0x1ffff, .item = 0};

#define DSS_DISPLAY_SIZE 75

#ifdef WIN32
__declspec(thread) char g_display_buf[DSS_DISPLAY_SIZE];
#else
__thread char g_display_buf[DSS_DISPLAY_SIZE];
#endif

char *dss_display_metaid(auid_t id)
{
    int ret = sprintf_s(g_display_buf, DSS_DISPLAY_SIZE, "metaid:%llu (v:%u, au:%llu, block:%u, item:%u)",
        DSS_ID_TO_U64(id), (uint32)(id).volume, (uint64)(id).au, (uint32)(id).block, (uint32)(id).item);
    if (ret < 0) {
        g_display_buf[0] = '\0';
    }
    return g_display_buf;
}
