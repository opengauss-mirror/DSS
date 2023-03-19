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
 * dss_copyfile.c
 *
 *
 * IDENTIFICATION
 *    src/common_api/dss_copyfile.c
 *
 * -------------------------------------------------------------------------
 */

#include "dss_copyfile.h"
#include "dss_diskgroup.h"
#include "dss_alloc_unit.h"
#include "dss_file.h"
#include "dss_malloc.h"
#include "dss_redo.h"

#define DSS_PRINT_BLOCK_SIZE SIZE_M(1)

static status_t dtod_cp_buf(
    dss_conn_t conn, int32 srchandle, int32 desthandle, const char *spath, const char *dpath, int64 count)
{
    status_t status;
    int read_size;
    int64 offset = 0;
    char *buf = cm_malloc_align(DSS_DISK_UNIT_SIZE, DSS_PRINT_BLOCK_SIZE);
    if (buf == NULL) {
        DSS_THROW_ERROR(ERR_ALLOC_MEMORY, DSS_PRINT_BLOCK_SIZE, "dtod buf");
        return CM_ERROR;
    }

    for (int64 i = 0; i < count; ++i) {
        offset = DSS_PRINT_BLOCK_SIZE * (i);
        offset = dss_seek_file_impl(&conn, srchandle, offset, SEEK_SET);
        bool32 result = (bool32)(offset != -1);
        DSS_RETURN_IF_FALSE3(result, LOG_DEBUG_ERR("Failed to seek file %s", spath), DSS_FREE_POINT(buf));

        status = dss_read_file_impl(&conn, srchandle, buf, (int)DSS_PRINT_BLOCK_SIZE, &read_size);
        DSS_RETURN_IFERR3(status, LOG_DEBUG_ERR("Failed to read file %s", spath), DSS_FREE_POINT(buf));

        if (read_size < (int)DSS_PRINT_BLOCK_SIZE) {
            errno_t errcode = memset_s(
                buf + read_size, DSS_PRINT_BLOCK_SIZE - (uint32)read_size, 0, DSS_PRINT_BLOCK_SIZE - (uint32)read_size);
            result = (bool32)(errcode == EOK);
            DSS_RETURN_IF_FALSE3(result, CM_THROW_ERROR(ERR_SYSTEM_CALL, errcode), DSS_FREE_POINT(buf));
        }
        offset = DSS_PRINT_BLOCK_SIZE * (i);
        offset = dss_seek_file_impl(&conn, desthandle, offset, SEEK_SET);
        result = (bool32)(offset != -1);
        DSS_RETURN_IF_FALSE3(result, LOG_DEBUG_ERR("Failed to seek file %s", dpath), DSS_FREE_POINT(buf));

        status = dss_write_file_impl(&conn, desthandle, buf, read_size);
        DSS_RETURN_IFERR3(status, LOG_DEBUG_ERR("Failed to write file %s", dpath), DSS_FREE_POINT(buf));
    }
    DSS_FREE_POINT(buf);
    return CM_SUCCESS;
}

static status_t dtol_cp_buf(
    dss_conn_t conn, int32 srchandle, int32 desthandle, const char *spath, const char *dpath, int64 count)
{
    status_t ret;
    int32 read_size;
    int64 offset = 0;
    char *buf = cm_malloc_align(DSS_DISK_UNIT_SIZE, DSS_PRINT_BLOCK_SIZE);
    if (buf == NULL) {
        DSS_THROW_ERROR(ERR_ALLOC_MEMORY, DSS_PRINT_BLOCK_SIZE, "dtol buf");
        return CM_ERROR;
    }

    for (int64 i = 0; i < count; ++i) {
        offset = DSS_PRINT_BLOCK_SIZE * (i);
        offset = dss_seek_file_impl(&conn, srchandle, offset, SEEK_SET);
        bool32 result = (bool32)(offset != -1);
        DSS_RETURN_IF_FALSE3(result, LOG_DEBUG_ERR("Failed to seek file %s", spath), DSS_FREE_POINT(buf));

        ret = dss_read_file_impl(&conn, srchandle, buf, (int)DSS_PRINT_BLOCK_SIZE, &read_size);
        DSS_RETURN_IFERR3(ret, LOG_DEBUG_ERR("Failed to read file %s", spath), DSS_FREE_POINT(buf));

        if ((uint32)read_size < DSS_PRINT_BLOCK_SIZE) {
            errno_t errcode = memset_s(
                buf + read_size, DSS_PRINT_BLOCK_SIZE - (uint32)read_size, 0, DSS_PRINT_BLOCK_SIZE - (uint32)read_size);
            result = (bool32)(errcode == EOK);
            DSS_RETURN_IF_FALSE3(result, CM_THROW_ERROR(ERR_SYSTEM_CALL, errcode), DSS_FREE_POINT(buf));
        }
        offset = DSS_PRINT_BLOCK_SIZE * (i);
        offset = cm_seek_file(desthandle, offset, SEEK_SET);
        result = (bool32)(offset != -1);
        DSS_RETURN_IF_FALSE3(result, LOG_DEBUG_ERR("Failed to seek file %s", dpath), DSS_FREE_POINT(buf));

        ret = cm_write_file(desthandle, buf, read_size);
        DSS_RETURN_IFERR3(ret, LOG_DEBUG_ERR("Failed to write file %s", dpath), DSS_FREE_POINT(buf));
    }
    DSS_FREE_POINT(buf);
    return CM_SUCCESS;
}

static status_t ltod_cp_buf(
    dss_conn_t conn, int32 srchandle, int32 desthandle, const char *spath, const char *dpath, int64 count)
{
    status_t status;
    int32 read_size;
    int64 offset = 0;
    char *buf = cm_malloc_align(DSS_DISK_UNIT_SIZE, DSS_PRINT_BLOCK_SIZE);
    if (buf == NULL) {
        DSS_THROW_ERROR(ERR_ALLOC_MEMORY, DSS_PRINT_BLOCK_SIZE, "ltod buf");
        return CM_ERROR;
    }

    for (int64 i = 0; i < count; ++i) {
        offset = DSS_PRINT_BLOCK_SIZE * (i);
        offset = cm_seek_file(srchandle, offset, SEEK_SET);
        bool32 result = (bool32)(offset != -1);
        DSS_RETURN_IF_FALSE3(result, LOG_DEBUG_ERR("Failed to seek file %s", spath), DSS_FREE_POINT(buf));

        status = cm_read_file(srchandle, buf, (int32)DSS_PRINT_BLOCK_SIZE, &read_size);
        DSS_RETURN_IFERR3(status, LOG_DEBUG_ERR("Failed to read file %s", spath), DSS_FREE_POINT(buf));

        if ((uint32)read_size < DSS_PRINT_BLOCK_SIZE) {
            errno_t err = memset_s(
                buf + read_size, DSS_PRINT_BLOCK_SIZE - (uint32)read_size, 0, DSS_PRINT_BLOCK_SIZE - (uint32)read_size);
            result = (bool32)(err == EOK);
            DSS_RETURN_IF_FALSE3(result, CM_THROW_ERROR(ERR_SYSTEM_CALL, err), DSS_FREE_POINT(buf));
        }
#ifndef OPENGAUSS
        read_size = CM_CALC_ALIGN(read_size, DSS_DISK_UNIT_SIZE);
#endif
        offset = DSS_PRINT_BLOCK_SIZE * (i);
        offset = dss_seek_file_impl(&conn, desthandle, offset, SEEK_SET);
        result = (bool32)(offset != -1);
        DSS_RETURN_IF_FALSE3(result, LOG_DEBUG_ERR("Failed to seek file %s", dpath), DSS_FREE_POINT(buf));
        status = dss_write_file_impl(&conn, desthandle, buf, read_size);
        DSS_RETURN_IFERR3(status, LOG_DEBUG_ERR("Failed to write file %s", dpath), DSS_FREE_POINT(buf));
    }
    DSS_FREE_POINT(buf);
    return CM_SUCCESS;
}

/* cp +vg01/file1 +vg01/file2 */
static status_t dss_cp_dtod(dss_conn_t conn, const char *srcpath, const char *destpath)
{
    int srchandle;
    int desthandle;
    status_t status;
    status = dss_open_file_impl(&conn, srcpath, 0, &srchandle);
    if (status != CM_SUCCESS) {
        LOG_DEBUG_ERR("The format of srcfile %s is false.\n", srcpath);
        return status;
    }
    status = dss_create_file_impl(&conn, destpath, 0);
    if (status != CM_SUCCESS) {
        LOG_DEBUG_ERR("Create file %s failed.\n", destpath);
        dss_close_file_impl(&conn, srchandle);
        return status;
    }
    status = dss_open_file_impl(&conn, destpath, 0, &desthandle);
    if (status != CM_SUCCESS) {
        LOG_DEBUG_ERR("The format of destfile %s is false.\n", destpath);
        dss_close_file_impl(&conn, srchandle);
        return status;
    }
#ifndef OPENGAUSS
    int64 size = dss_seek_file_impl(&conn, srchandle, 0, SEEK_END);
#else
    int64 size = dss_seek_file_impl(&conn, srchandle, 0, DSS_SEEK_MAXWR);
#endif
    LOG_DEBUG_INF("Seek file %s, size is %lld.", srcpath, size);
    bool32 result = (bool32)(size != -1);
    DSS_RETURN_IF_FALSE3(result, dss_close_file_impl(&conn, srchandle), dss_close_file_impl(&conn, desthandle));

    int64 count = size / (int64)DSS_PRINT_BLOCK_SIZE;
    count = (size % (int64)DSS_PRINT_BLOCK_SIZE == 0) ? count : count + 1;
    status = dtod_cp_buf(conn, srchandle, desthandle, srcpath, destpath, count);
    dss_close_file_impl(&conn, srchandle);
    dss_close_file_impl(&conn, desthandle);
    if (status != CM_SUCCESS) {
        LOG_DEBUG_ERR("Dss to dss copy buffer failed");
        if (dss_remove_file_impl(&conn, destpath) != CM_SUCCESS) {
            LOG_DEBUG_ERR("Delete dest file: %s failed", destpath);
        }
    }
    return status;
}

/* cp +vg01/file1 /file1 */
static status_t dss_cp_dtol(dss_conn_t conn, const char *srcpath, const char *destpath)
{
    int srchandle;
    int desthandle;
    status_t status;
    status = dss_open_file_impl(&conn, srcpath, 0, &srchandle);
    if (status != CM_SUCCESS) {
        LOG_DEBUG_ERR("The format of srcfile %s is false.\n", srcpath);
        return status;
    }
    status = cm_create_file(destpath, O_RDWR | O_TRUNC | O_BINARY | O_CREAT, &desthandle);
    if (status != CM_SUCCESS) {
        LOG_DEBUG_ERR("Failed to create file %s", destpath);
        dss_close_file_impl(&conn, srchandle);
        return status;
    }
#ifndef OPENGAUSS
    int64 size = dss_seek_file_impl(&conn, srchandle, 0, SEEK_END);
#else
    int64 size = dss_seek_file_impl(&conn, srchandle, 0, DSS_SEEK_MAXWR);
#endif
    LOG_DEBUG_INF("Seek the src file %s, size is %lld.", srcpath, size);
    bool32 result = (bool32)(size != -1);
    DSS_RETURN_IF_FALSE3(result, dss_close_file_impl(&conn, srchandle), cm_close_file(desthandle));

    int64 count = size / (int64)DSS_PRINT_BLOCK_SIZE;
    int64 rem_size = size % (int64)DSS_PRINT_BLOCK_SIZE;
    if (rem_size != 0) {
        count++;
    }
    status = dtol_cp_buf(conn, srchandle, desthandle, srcpath, destpath, count);
    dss_close_file_impl(&conn, srchandle);
    cm_close_file(desthandle);
    if (status != CM_SUCCESS) {
        if (cm_remove_file(destpath) != CM_SUCCESS) {
            LOG_DEBUG_ERR("Delete dest file: %s failed", destpath);
        }
    }
    return status;
}

/* cp /file1 +vg01/file1 */
static status_t dss_cp_ltod(dss_conn_t conn, const char *srcpath, const char *destpath)
{
    int srchandle;
    int desthandle;
    status_t status;
    status = cm_open_file(srcpath, O_RDONLY | O_BINARY, &srchandle);
    if (status != CM_SUCCESS) {
        LOG_DEBUG_ERR("The format of srcfile %s is false.\n", srcpath);
        return status;
    }
    status = dss_create_file_impl(&conn, destpath, 0);
    if (status != CM_SUCCESS) {
        LOG_DEBUG_ERR("Create file %s failed.\n", destpath);
        cm_close_file(srchandle);
        return status;
    }
    status = dss_open_file_impl(&conn, destpath, 0, &desthandle);
    if (status != CM_SUCCESS) {
        LOG_DEBUG_ERR("The format of destfile %s is false.\n", destpath);
        cm_close_file(srchandle);
        return status;
    }
    int64 size = cm_seek_file(srchandle, 0, SEEK_END);
    if (size == -1) {
        LOG_DEBUG_ERR("Failed to seek file %s", srcpath);
        cm_close_file(srchandle);
        dss_close_file_impl(&conn, desthandle);
        return CM_ERROR;
    }
#ifdef OPENGAUSS
    if (size % DSS_DISK_UNIT_SIZE != 0) {
        LOG_DEBUG_ERR("Linux file %s not aligned with 512", srcpath);
        cm_close_file(srchandle);
        dss_close_file_impl(&conn, desthandle);
        if (dss_remove_file_impl(&conn, destpath) != CM_SUCCESS) {
            LOG_DEBUG_ERR("Delete dest file: %s failed", destpath);
        }
        return CM_ERROR;
    }
#endif
    int64 count = size / (int64)DSS_PRINT_BLOCK_SIZE;
    int64 rem_size = size % (int64)DSS_PRINT_BLOCK_SIZE;
    if (rem_size != 0) {
        count++;
    }
    status = ltod_cp_buf(conn, srchandle, desthandle, srcpath, destpath, count);
    cm_close_file(srchandle);
    dss_close_file_impl(&conn, desthandle);
    if (status != CM_SUCCESS) {
        LOG_DEBUG_ERR("Dss to dss copy buffer failed");
        if (dss_remove_file_impl(&conn, destpath) != CM_SUCCESS) {
            LOG_DEBUG_ERR("Delete dest file: %s failed", destpath);
        }
    }
    return status;
}

status_t dss_copy_file(dss_conn_t conn, const char *srcpath, const char *destpath)
{
    status_t status;
    if (srcpath[0] == '+' && destpath[0] == '/') {
        status = dss_cp_dtol(conn, srcpath, destpath);
        if (status != CM_SUCCESS) {
            LOG_DEBUG_ERR("Fail to copy file from dss to Linux.\n");
            return status;
        }
    } else if (srcpath[0] == '+' && destpath[0] == '+') {
        status = dss_cp_dtod(conn, srcpath, destpath);
        if (status != CM_SUCCESS) {
            LOG_DEBUG_ERR("Fail to copy file from dss to dss.\n");
            return status;
        }
    } else if (srcpath[0] == '/' && destpath[0] == '+') {
        status = dss_cp_ltod(conn, srcpath, destpath);
        if (status != CM_SUCCESS) {
            LOG_DEBUG_ERR("Fail to copy file from Linux to dss.\n");
            return status;
        }
    } else if (srcpath[0] == '/' && destpath[0] == '/') {
        DSS_PRINT_ERROR("Not support copy file from Linux to Linux.\n");
        return CM_ERROR;
    } else {
        DSS_PRINT_ERROR("The format of srcpath or destpath is wrong.\n");
        return CM_ERROR;
    }
    return CM_SUCCESS;
}
