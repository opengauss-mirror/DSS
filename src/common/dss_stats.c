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
 * dss_stats.c
 *
 *
 * IDENTIFICATION
 *    src/common/dss_stats.c
 *
 * -------------------------------------------------------------------------
 */

#include "dss_stats.h"

#ifdef __cplusplus
extern "C" {
#endif

const char *g_dss_stat_events[DSS_EVT_COUNT] = {
    [DSS_PREAD] = "DSS Pread",
    [DSS_PWRITE] = "DSS Pwrite",
    [DSS_FREAD] = "DSS Fread",
    [DSS_FWRITE] = "DSS Fwrite",
    [DSS_PREAD_SYN_META] = "DSS Pread Sync Metadata",
    [DSS_PWRITE_SYN_META] = "DSS Pwrite Sync Metadata",
    [DSS_PREAD_DISK] = "DSS Pread Disk",
    [DSS_PWRITE_DISK] = "DSS Pwrite Disk",
    [DSS_FOPEN] = "DSS File Open",
    [DSS_STAT] = "DSS Stat",
    [DSS_FIND_FT_ON_SERVER] = "Find File Node On Server",
    [DSS_LOCK_VG] = "DSS Lock Vg",
    [DSS_LATCH_CONTEXT] = "DSS Latch Context",
    [DSS_FTRUNCATE] = "DSS Ftruncate",
    [DSS_SET_MAIN_INST] = "DSS Set Main Inst",
    [DSS_CMD_BROADCAST] = "DSS Cmd Boradcast",
    [DSS_CMD_SYB2ACTIVE] = "DSS Cmd Syb2Active",
    [DSS_CMD_LOAD_DISK] = "DSS Cmd Load Disk",
    [DSS_CMD_JOIN_CLUSTER] = "DSS Cmd Join Cluster",
    [DSS_CMD_REFRESH_FT] = "DSS Cmd Refresh Ft",
    [DSS_CMD_GET_FT_BLOCK] = "DSS Cmd Get Ft Block",
};

const char *dss_get_stat_event(dss_wait_event_e event)
{
    return g_dss_stat_events[event];
}

#ifdef __cplusplus
}
#endif
