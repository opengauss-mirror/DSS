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
 * dsscmd_encrypt.h
 *
 *
 * IDENTIFICATION
 *    src/cmd/dsscmd_encrypt.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef DSSCMD_ENCRYPT_H_
#define DSSCMD_ENCRYPT_H_

#include "dss_param.h"

status_t dss_catch_input_text(char *plain, uint32 plain_size);
status_t dss_receive_info_from_terminal(char *buff, int32 buff_size, bool32 is_plain_text);
#endif
