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
 * dss_copyfile.h
 *
 *
 * IDENTIFICATION
 *    src/common_api/dss_copyfile.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef DSS_COPYFILE_H_
#define DSS_COPYFILE_H_

#include "dss_api_impl.h"

#ifdef __cplusplus
extern "C" {
#endif

status_t dss_copy_file(dss_conn_t conn, const char *srcpath, const char *destpath);

#ifdef __cplusplus
}
#endif
#endif
