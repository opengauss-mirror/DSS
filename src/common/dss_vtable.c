/*
 * Copyright (c) 2022 Huawei Technologies Co., Ltd. All rights reserved.
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
 * dss_vtable.c
 *
 *
 * IDENTIFICATION
 *    src/common/dss_vtable.c
 *
 * -------------------------------------------------------------------------
 */

#include "dss_defs.h"
#include "cm_log.h"
#include "cm_utils.h"
#include "dlfcn.h"
#include "dss_vtable.h"

vtable_func_t g_vtable_func = {0};

#define VTABLE_LOAD_SYMBOL_FUNC(func) \
    cm_load_symbol((void**)&g_vtable_func.func, #func, g_vtable_func.vtableHandle)

#define VTABLE_LOAD_SYMBOL_FUNC_ADAPTER(func) \
    cm_load_symbol((void**)&g_vtable_func.func, #func, g_vtable_func.vtableAdapterHandle)

#define IP_FIELD_LENGTH 16
#define DEFAULT_PAGE_SIZE (8 * 1024)

status_t vtable_func_init()
{
    if (g_vtable_func.symbolnited) {
        return CM_SUCCESS;
    }

    DSS_RETURN_IF_ERROR(cm_open_dl(&g_vtable_func.vtableHandle, LIB_VTABLE_NAME));
    DSS_RETURN_IF_ERROR(VTABLE_LOAD_SYMBOL_FUNC(BdevExit));
    DSS_RETURN_IF_ERROR(VTABLE_LOAD_SYMBOL_FUNC(Initialize));
    DSS_RETURN_IF_ERROR(VTABLE_LOAD_SYMBOL_FUNC(CreateVolume));
    DSS_RETURN_IF_ERROR(VTABLE_LOAD_SYMBOL_FUNC(DestroyVolume));
    DSS_RETURN_IF_ERROR(VTABLE_LOAD_SYMBOL_FUNC(Fence));
    DSS_RETURN_IF_ERROR(VTABLE_LOAD_SYMBOL_FUNC(FenceQuery));
    DSS_RETURN_IF_ERROR(VTABLE_LOAD_SYMBOL_FUNC(Write));
    DSS_RETURN_IF_ERROR(VTABLE_LOAD_SYMBOL_FUNC(Read));
    DSS_RETURN_IF_ERROR(VTABLE_LOAD_SYMBOL_FUNC(List));
    DSS_RETURN_IF_ERROR(VTABLE_LOAD_SYMBOL_FUNC(PtInfoListDestroy));
    DSS_RETURN_IF_ERROR(VTABLE_LOAD_SYMBOL_FUNC(PtInfoListCreate));
    DSS_RETURN_IF_ERROR(VTABLE_LOAD_SYMBOL_FUNC(GetMasterNodeIPByOffset));

    DSS_RETURN_IF_ERROR(cm_open_dl(&g_vtable_func.vtableAdapterHandle, LIB_VTABLE_ADAPTER_NAME));
    DSS_RETURN_IF_ERROR(VTABLE_LOAD_SYMBOL_FUNC_ADAPTER(VtableAdapterAppend));
    DSS_RETURN_IF_ERROR(VTABLE_LOAD_SYMBOL_FUNC_ADAPTER(VtableAdapterInit));
    DSS_RETURN_IF_ERROR(VTABLE_LOAD_SYMBOL_FUNC_ADAPTER(VtableAdapterWrite));

    g_vtable_func.symbolnited = true;
    return CM_SUCCESS;
}

void VtableExit(void)
{
    g_vtable_func.BdevExit();
}

status_t VtableInitAdapter()
{
    return (status_t)g_vtable_func.VtableAdapterInit();
}

status_t VtableInitialize(WorkerMode mode, ClientOptionsConfig *optConf)
{
    return (status_t)g_vtable_func.Initialize(mode, optConf);
}

status_t VtableCreateVolume(uint16_t volumeType, uint64_t cap, uint32_t alignedSize, uint64_t* volumeId)
{
    return (status_t)g_vtable_func.CreateVolume(volumeType, cap, alignedSize, volumeId);
}

status_t VtableDestroyVolume(uint64_t volumeId)
{
    return (status_t)g_vtable_func.DestroyVolume(volumeId);
}

status_t VtableWrite(uint64_t volumeId, uint64_t offset, uint32_t length, char *value)
{
    return (status_t)g_vtable_func.Write(volumeId, offset, length, value);
}

status_t VtableRead(uint64_t volumeId, uint64_t offset, uint32_t length, char *value)
{
    return (status_t)g_vtable_func.Read(volumeId, offset, length, value);
}

status_t VtableList(uint64_t volumeId, bool* exist, uint64_t* cap, uint32_t* alignedSize, uint16_t* type)
{
    return (status_t)g_vtable_func.List(volumeId, exist, cap, alignedSize, type);
}

status_t VtableAppendAdapter(uint64_t volumeId, uint64_t offset, uint32_t length, char *value)
{
    return (status_t)g_vtable_func.VtableAdapterAppend(volumeId, offset, length, value);
}

status_t VtableWriteAdapte(uint64_t volumeId, uint64_t offset, uint32_t length, char *value)
{
    return (status_t)g_vtable_func.VtableAdapterWrite(volumeId, offset, length, value);
}

status_t VtableFence(const char *ip, uint64_t volumeId, uint16_t operateType, bool fullOperate)
{
    return (status_t)g_vtable_func.Fence(ip, volumeId, operateType, fullOperate);
}

status_t VtableFenceQuery(const char *ip, uint64_t volumeId, uint16_t *isFenced)
{
    return (status_t)g_vtable_func.FenceQuery(ip, volumeId, isFenced);
}

status_t VtableGetMasterNodeIPByOffset(uint64_t volumeId, uint64_t offset, char *ip)
{
    PtInfoList* list = g_vtable_func.PtInfoListCreate(8);
    g_vtable_func.GetMasterNodeIPByOffset(volumeId, offset, DEFAULT_PAGE_SIZE, list);
    errno_t errcode = memcpy_s(ip, IP_FIELD_LENGTH, list->ipList[0], IP_FIELD_LENGTH);
    securec_check_ret(errcode);
    g_vtable_func.PtInfoListDestroy(list);

    return CM_SUCCESS;
}

status_t dss_init_vtable(void)
{
    if (g_vtable_func.isInitialize) {
        return CM_SUCCESS;
    }
    int status = 0;
    WorkerMode mode = SEPARATES;
    ClientOptionsConfig config;
    config.enable = false;
    config.logType = FILE_TYPE;
    config.isDriverServer = false;
    LOG_RUN_INF("DSS VtableInitialize start.");
    errno_t err = strcpy_s(config.logFilePath, PATH_MAX, "/var/log/turboio");
    DSS_SECUREC_SS_RETURN_IF_ERROR(err, CM_ERROR);

    status = vtable_func_init();
    DSS_RETURN_IFERR2(status, DSS_PRINT_ERROR("DSS load vtable failed!\n"));

    status = VtableInitialize(mode, &config);
    DSS_RETURN_IFERR2(status, DSS_PRINT_ERROR("DSS VtableInitialize failed!\n"));
    LOG_RUN_INF("DSS VtableInitialize success.");

    status = VtableInitAdapter();
    DSS_RETURN_IFERR2(status, DSS_PRINT_ERROR("DSS VtableInitAgain failed!\n"));
    LOG_RUN_INF("DSS VtableInitAgain success.");

    g_vtable_func.isInitialize = true;
    return CM_SUCCESS;
}

uint64 vtable_name_to_ptid(const char* name)
{
    uint64 res = 0;
    if (sscanf_s(name, "%llu", &res) != 1) {
        cm_panic(0);
    }
    return res;
}

status_t dss_open_volume_vtable(const char *name, const char *code, int flags, dss_volume_t *volume)
{
    volume->handle = vtable_name_to_ptid(name);
    if (volume->handle <= 0) {
        DSS_THROW_ERROR(ERR_DSS_VOLUME_OPEN, name, cm_get_os_error());
        return CM_ERROR;
    }
    volume->unaligned_handle = vtable_name_to_ptid(name);
    if (volume->unaligned_handle <= 0) {
        DSS_THROW_ERROR(ERR_DSS_VOLUME_OPEN, name, cm_get_os_error());
        return CM_ERROR;
    }
    errno_t ret = snprintf_s(volume->name, DSS_MAX_VOLUME_PATH_LEN, DSS_MAX_VOLUME_PATH_LEN - 1, "%s", name);
    DSS_SECUREC_SS_RETURN_IF_ERROR(ret, CM_ERROR);
    volume->name_p = volume->name;
    return CM_SUCCESS;
}

status_t dss_open_simple_volume_vtable(const char *name, int flags, dss_simple_volume_t *volume)
{
    volume->handle = vtable_name_to_ptid(name);
    if (volume->handle <= 0) {
        DSS_THROW_ERROR(ERR_DSS_VOLUME_OPEN, name, cm_get_os_error());
        return CM_ERROR;
    }

    volume->unaligned_handle = vtable_name_to_ptid(name);
    if (volume->unaligned_handle <= 0) {
        DSS_THROW_ERROR(ERR_DSS_VOLUME_OPEN, name, cm_get_os_error());
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

void dss_close_volume_vtable(dss_volume_t *volume)
{
    if (memset_s(volume, sizeof(dss_volume_t), 0, sizeof(dss_volume_t)) != EOK) {
        cm_panic(0);
    }
    volume->handle = DSS_INVALID_HANDLE;
    volume->unaligned_handle = DSS_INVALID_HANDLE;
}

void dss_close_simple_volume_vtable(dss_simple_volume_t *simple_volume)
{
    simple_volume->handle = DSS_INVALID_HANDLE;
    simple_volume->unaligned_handle = DSS_INVALID_HANDLE;
}

uint64 dss_get_volume_size_vtable(dss_volume_t *volume)
{
    uint64_t size = 0;
    uint32_t alignedSize = 0;
    uint16_t type = 0;
    bool exist = false;
    status_t res = VtableList((uint64_t)volume->handle, &exist, &size, &alignedSize, &type);
    if (res != CM_SUCCESS) {
        DSS_LOG_WITH_OS_MSG("failed to get volume size vtable %s", volume->name_p);
        DSS_THROW_ERROR(ERR_DSS_VOLUME_SEEK, volume->name_p, volume->id, res);
        return DSS_INVALID_64;
    }
    return (uint64)size;
}

status_t dss_try_pread_volume_vtable(dss_volume_t *volume, int64 offset, char *buffer,
                                            int32 size, int32 *read_size)
{
    CResult res = VtableRead((uint64_t)volume->handle, (uint64_t)offset, size, buffer);
    if (res != RET_CACHE_OK) {
        DSS_THROW_ERROR(ERR_DSS_VOLUME_READ, volume->name_p, volume->id, cm_get_os_error());
        LOG_RUN_ERR("Failed to read volume %s, vtable ptid:%lld, volume id:%u,size:%d, offset:%lld, vtable_errno:%d.",
            volume->name_p, volume->handle, volume->id, size, offset, (int)res);
        return CM_ERROR;
    }
    *read_size = size;
    return CM_SUCCESS;
}

int32 dss_try_pwrite_volume_vtable(dss_volume_t *volume, int64 offset, char *buffer,
                                          int32 size, int32 *written_size)
{
    CResult res = VtableWriteAdapte((uint64_t)volume->handle, (uint64_t)offset, size, buffer);
    if (res != RET_CACHE_OK) {
        DSS_THROW_ERROR(ERR_DSS_VOLUME_WRITE, volume->name_p, volume->id, cm_get_os_error());
        LOG_RUN_ERR("Failed to write volume %s, vtable ptid:%lld, volume id:%u,size:%d, offset:%lld, vtable_errno:%d.",
            volume->name_p, volume->handle, volume->id, size, offset, (int)res);
        return CM_ERROR;
    }
    *written_size = size;
    return res;
}

int32 dss_try_append_volume_vtable(dss_volume_t *volume, int64 offset, char *buffer,
                                          int32 size, int32 *written_size)
{
    CResult res = VtableAppendAdapter((uint64_t)volume->handle, (uint64_t)offset, size, buffer);
    if (res != RET_CACHE_OK) {
        DSS_THROW_ERROR(ERR_DSS_VOLUME_WRITE, volume->name_p, volume->id, cm_get_os_error());
        LOG_RUN_ERR("Failed to append volume %s, vtable ptid:%lld, volume id:%u,size:%d, offset:%lld, vtable_errno:%d.",
            volume->name_p, volume->handle, volume->id, size, offset, (int)res);
        return CM_ERROR;
    }
    *written_size = size;
    return res;
}