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
 * dss_signal.c
 *
 *
 * IDENTIFICATION
 *    src/common/dss_signal.c
 *
 * -------------------------------------------------------------------------
 */
#ifndef WIN32
#include <sys/prctl.h>
#include "cm_log.h"
#include "dss_signal.h"

#define DSS_SIG_FLAG_ONESHOT (int)((uint32_t)SA_ONESHOT | (uint32_t)SA_RESETHAND)
typedef void (*dss_signal_handler)(int32_t);

#define MAX_STACK_LEN 256

void dss_output_current_bt(void)
{
    void *stackArray[MAX_STACK_LEN] = {0};
    int stackSize = backtrace(stackArray, MAX_STACK_LEN);
    char **stackInfo = backtrace_symbols(stackArray, stackSize);
    if (stackInfo == NULL) {
        return;
    }
    for (int index = 0; index < stackSize; index++) {
        if (stackInfo[index] != NULL) {
            LOG_RUN_ERR("[STACK-%d]:%s", index, stackInfo[index]);
        }
    }
    CM_FREE_PTR(stackInfo);
}

static status_t dss_signal(int32 signo, dss_signal_handler sigHandler, int flags)
{
    struct sigaction act;
    errno_t errcode = memset_s(&act, sizeof(struct sigaction), 0, sizeof(struct sigaction));
    if (errcode != EOK) {
        return CM_ERROR;
    }

    if (sigemptyset(&act.sa_mask) != 0) {
        return CM_ERROR;
    }

    act.sa_handler = sigHandler;
    act.sa_flags = flags;

    if (sigaction(signo, &act, NULL) < 0) {
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static status_t dss_register_signal(const int32 signo_Array[], int32 sigLen, dss_signal_handler sigHandler, int flags)
{
    status_t ret;
    for (int32 index = 0; index < sigLen; index++) {
        ret = dss_signal(signo_Array[index], sigHandler, flags);
        if (ret != CM_SUCCESS) {
            return ret;
        }
    }
    return CM_SUCCESS;
}

static void dss_croedump_signal_handler_proc(int32 signo)
{
    LOG_RUN_ERR("recv coredump signal: %d ", signo);
    dss_output_current_bt();
    (void)prctl(PR_SET_DUMPABLE, 1);
    (void)raise(signo);
}

status_t dss_signal_proc(void)
{
    int32 coredump_signal_array[] = {SIGILL, SIGTRAP, SIGABRT, SIGBUS, SIGFPE, SIGSEGV};
    status_t ret =
        dss_register_signal(coredump_signal_array, sizeof(coredump_signal_array) / sizeof(coredump_signal_array[0]),
            dss_croedump_signal_handler_proc, DSS_SIG_FLAG_ONESHOT);
    return ret;
}
#endif
