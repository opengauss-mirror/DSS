/*
 * Copyright (c) 2023 Huawei Technologies Co.,Ltd.
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
 * dss_blackbox.h
 *
 *
 * IDENTIFICATION
 *    src/service/dss_blackbox.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __DSS_BLACKBOX_H__
#define __DSS_BLACKBOX_H__

#include "cm_blackbox.h"
status_t dss_sigcap_handle_reg();
status_t dss_update_state_file(bool32 coredump);
#endif
