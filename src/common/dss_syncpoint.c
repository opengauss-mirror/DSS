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
 * dss_syncpoint.c
 *
 *
 * IDENTIFICATION
 *    src/common/dss_syncpoint.c
 *
 * -------------------------------------------------------------------------
 */

#include "cm_log.h"
#include "dss_syncpoint.h"

static void dss_syncpoint_abort(uint32 *action, uint32 count)
{
    LOG_DEBUG_ERR("syncpoint match exit!");
    CM_ASSERT(0);
}

#define INVALID_MATCH_COUNT 10000000
static void dss_syncpoint_return_null(uint32 *action, uint32 count)
{
    static uint32 matched_count = 0;
    matched_count++;
    if (action && matched_count == count) {
        *action = DSS_SP_ACTION_RETURN_NULL;
        LOG_DEBUG_WAR("syncpoint match, return null!");
        matched_count = INVALID_MATCH_COUNT;  // set not matched next time.
    } else {
        LOG_DEBUG_WAR("syncpoint not match, count:%u, matched_count:%u.", count, matched_count);
    }
}

static void dss_syncpoint_return_error(uint32 *action, uint32 count)
{
    if (action) {
        *action = DSS_SP_ACTION_RETURN_ERROR;
    }

    LOG_DEBUG_WAR("syncpoint match, return error!");
}

dss_syncpoint_def g_dss_syncpoint[] = {
    {DSS_SP_ID_FULL_REDO_BREAK, DSS_FALSE, DSS_TRUE, "full redo break", 0, dss_syncpoint_abort},
    {DSS_SP_ID_PARTIAL_REDO_BREAK, DSS_FALSE, DSS_TRUE, "partially redo break", 0, dss_syncpoint_abort},
    {DSS_SP_ID_FLUSH_REDO_BREAK, DSS_FALSE, DSS_TRUE, "flush redo break", 0, dss_syncpoint_abort},
    {DSS_SP_ID_TRIGGER_ROLLBACK, DSS_FALSE, DSS_TRUE, "trigger rollback", 0, dss_syncpoint_return_null},
    {DSS_SP_ID_TRIGGER_ROLLBACK2, DSS_FALSE, DSS_TRUE, "trigger rollback", 0, dss_syncpoint_return_error},
    {DSS_SP_ID_TRIGGER_NOT_UNLOCK, DSS_FALSE, DSS_FALSE, "trigger not unlock", 0, dss_syncpoint_return_error}};

#define DSS_SYNCPOINT_SIZE (sizeof(g_dss_syncpoint) / sizeof(g_dss_syncpoint[0]))

int dss_enable_syncpoint(uint32 id, uint32 count)
{
#ifdef DB_DEBUG_VERSION
    if (id >= DSS_SYNCPOINT_SIZE) {
        return CM_ERROR;
    }
    g_dss_syncpoint[id].count = count;
    g_dss_syncpoint[id].flag = DSS_TRUE;
    return CM_SUCCESS;
#else
    return CM_ERROR;
#endif
}

status_t dss_disable_syncpoint(uint32 id)
{
#ifdef DB_DEBUG_VERSION
    if (id >= DSS_SYNCPOINT_SIZE) {
        return CM_ERROR;
    }
    g_dss_syncpoint[id].count = 0;
    g_dss_syncpoint[id].flag = DSS_FALSE;
    return CM_SUCCESS;
#else
    return CM_ERROR;
#endif
}

void dss_execute_syncpoint(uint32 id, uint32 *action)
{
#ifdef DB_DEBUG_VERSION
    if (id >= DSS_SYNCPOINT_SIZE) {
        return;
    }

    if (!g_dss_syncpoint[id].flag) {
        return;
    }
    LOG_DEBUG_WAR("Execute syncpoint:%u.", id);
    g_dss_syncpoint[id].op(action, g_dss_syncpoint[id].count);
#endif
    return;
}

bool32 dss_is_client_syncpoint(uint32 id)
{
    return !g_dss_syncpoint[id].is_server;
}
