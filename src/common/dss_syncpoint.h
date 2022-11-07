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
 * dss_syncpoint.h
 *
 *
 * IDENTIFICATION
 *    src/common/dss_syncpoint.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __DSS_SYNCPOINT_H__
#define __DSS_SYNCPOINT_H__

#include "dss_defs.h"
#include "dss_latch.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DSS_SP_ID_FULL_REDO_BREAK 0
#define DSS_SP_ID_PARTIAL_REDO_BREAK 1
#define DSS_SP_ID_FLUSH_REDO_BREAK 2
#define DSS_SP_ID_TRIGGER_ROLLBACK 3
#define DSS_SP_ID_TRIGGER_ROLLBACK2 4
#define DSS_SP_ID_TRIGGER_NOT_UNLOCK 5

#define DSS_SP_ACTION_DO_NOTHING 0
#define DSS_SP_ACTION_RETURN_NULL 1
#define DSS_SP_ACTION_RETURN_ERROR 2

typedef void (*syncpoint_func)(uint32 *action, uint32 count);

typedef struct st_dss_syncpoint_def {
    uint32 id;
    bool32 flag;
    bool32 is_server;
    char name[DSS_MAX_NAME_LEN];
    uint32 count;  // match count
    syncpoint_func op;
} dss_syncpoint_def;

int dss_enable_syncpoint(uint32 id, uint32 count);
int dss_disable_syncpoint(uint32 id);
void dss_execute_syncpoint(uint32 id, uint32 *action);
bool32 dss_is_client_syncpoint(uint32 id);

#ifdef DB_DEBUG_VERSION
#define DSS_TEST_ROLLBACK2(err_no)                                   \
    do {                                                             \
        uint32 action = DSS_SP_ACTION_DO_NOTHING;                    \
        dss_execute_syncpoint(DSS_SP_ID_TRIGGER_ROLLBACK2, &action); \
        if (action == DSS_SP_ACTION_RETURN_ERROR) {                  \
            DSS_THROW_ERROR(err_no);                                 \
            return CM_ERROR;                                         \
        }                                                            \
    } while (0)

#define DSS_TEST_ROLLBACK                                           \
    do {                                                            \
        uint32 action = DSS_SP_ACTION_DO_NOTHING;                   \
        dss_execute_syncpoint(DSS_SP_ID_TRIGGER_ROLLBACK, &action); \
        if (action == DSS_SP_ACTION_RETURN_NULL) {                  \
            return NULL;                                            \
        }                                                           \
    } while (0)

#define DSS_TEST_NOT_UNLOCK(err_no, latch)                            \
    do {                                                              \
        uint32 action = DSS_SP_ACTION_DO_NOTHING;                     \
        dss_execute_syncpoint(DSS_SP_ID_TRIGGER_NOT_UNLOCK, &action); \
        if (action == DSS_SP_ACTION_RETURN_ERROR) {                   \
            dss_unlatch(latch);                                       \
            DSS_THROW_ERROR(err_no);                                  \
            return CM_ERROR;                                          \
        }                                                             \
    } while (0)
#else
#define DSS_TEST_ROLLBACK2(err_no)
#define DSS_TEST_ROLLBACK
#define DSS_TEST_NOT_UNLOCK(err_no, latch)
#endif

#ifdef __cplusplus
}
#endif

#endif
