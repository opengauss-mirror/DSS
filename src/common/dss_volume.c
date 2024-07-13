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
 * dss_volume.c
 *
 *
 * IDENTIFICATION
 *    src/common/dss_volume.c
 *
 * -------------------------------------------------------------------------
 */
#include "dss_volume.h"
#ifndef WIN32
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#endif  // !WIN32
#include "dss_file.h"

#ifdef __cplusplus
extern "C" {
#endif

uint64 g_log_offset = DSS_INVALID_ID64;
#ifdef WIN32
int32 device_os_error_array[] = {
    EOPNOTSUPP, ETIMEDOUT, ENOSPC, ENOLINK, ENODATA, EILSEQ, ENOMEM, EBUSY, EAGAIN, ENODEV, EOVERFLOW, EIO};
};
#else
int32 device_os_error_array[] = {EOPNOTSUPP, ETIMEDOUT, ENOSPC, ENOLINK, EBADE, ENODATA, EILSEQ, ENOMEM, EBUSY, EAGAIN,
    ENODEV, EREMCHG, ETOOMANYREFS, EOVERFLOW, EIO};
#endif

bool32 dss_is_device_os_error(int32 os_err)
{
    uint8 size = (uint8)sizeof(device_os_error_array) / sizeof(device_os_error_array[0]);
    for (uint8 i = 0; i < size; i++) {
        if (os_err == device_os_error_array[i]) {
            return CM_TRUE;
        }
    }
    return CM_FALSE;
}

#ifdef WIN32
status_t dss_open_volume(const char *name, const char *code, int flags, dss_volume_t *volume)
{
    volume->handle =
        CreateFile(name, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, 0, NULL);
    if (volume->handle == INVALID_HANDLE_VALUE) {
        if (dss_is_device_os_error(cm_get_os_error())) {
            DSS_THROW_ERROR(ERR_DSS_VOLUME_SYSTEM_IO, name);
            LOG_RUN_ERR("[DSS] ABORT OPEN VOLUME, because Linux OS error: errno:%d, errmsg:%s.", cm_get_os_error(),
                strerror(cm_get_os_error()));
            cm_fync_logfile();
            _exit(1);
        } else {
            DSS_THROW_ERROR(ERR_DSS_VOLUME_OPEN, name, cm_get_os_error());
        }
        return CM_ERROR;
    }

    errno_t ret;
    ret = snprintf_s(volume->name, DSS_MAX_VOLUME_PATH_LEN, DSS_MAX_VOLUME_PATH_LEN - 1, "%s", name);
    DSS_SECUREC_SS_RETURN_IF_ERROR(ret, CM_ERROR);
    volume->name_p = name;
    return CM_SUCCESS;
}

status_t dss_open_simple_volume(const char *name, int flags, dss_simple_volume_t *volume)
{
    volume->handle =
        CreateFile(name, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, 0, NULL);

    if (volume->handle == INVALID_HANDLE_VALUE) {
        if (dss_is_device_os_error(cm_get_os_error())) {
            DSS_THROW_ERROR(ERR_DSS_VOLUME_SYSTEM_IO, name);
            LOG_RUN_ERR("[DSS] ABORT OPEN SIMPLE VOLUME, because Linux OS error: errno:%d, errmsg:%s.", cm_get_os_error(),
                strerror(cm_get_os_error()));
            cm_fync_logfile();
            _exit(1);
        } else {
            DSS_THROW_ERROR(ERR_DSS_VOLUME_OPEN, name, cm_get_os_error());
        }
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

void dss_close_volume(dss_volume_t *volume)
{
    CloseHandle(volume->handle);

    errno_t errcode = memset_s(volume, sizeof(dss_volume_t), 0, sizeof(dss_volume_t));
    securec_check_ret(errcode);
    volume->handle = DSS_INVALID_HANDLE;
}

void dss_close_simple_volume(dss_simple_volume_t *simple_volume)
{
    CloseHandle(simple_volume->handle);
    simple_volume->handle = DSS_INVALID_HANDLE;
}

uint64 dss_get_volume_size(dss_volume_t *volume)
{
    DWORD low32, high32;
    uint64 size;

    low32 = GetFileSize(volume->handle, &high32);
    size = (uint64)high32;
    size <<= 32;
    size += low32;
    return size;
}

static status_t dss_seek_volume(dss_volume_t *volume, uint64 offset)
{
    LONG low32, high32;

    low32 = (LONG)(offset & 0xFFFFFFFF);
    high32 = (LONG)(offset >> 32);

    if (SetFilePointer(volume->handle, low32, &high32, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
        if (dss_is_device_os_error(cm_get_os_error())) {
            DSS_THROW_ERROR(ERR_DSS_VOLUME_SYSTEM_IO, volume->name_p);
            LOG_RUN_ERR("[DSS] ABORT SEEK VOLUME, because Linux OS error: errno:%d, errmsg:%s.", cm_get_os_error(),
                strerror(cm_get_os_error()));
            cm_fync_logfile();
            _exit(1);
        } else {
            DSS_THROW_ERROR(ERR_DSS_VOLUME_SEEK, volume->name_p, volume->id, cm_get_os_error());
        }
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

static status_t dss_try_read_volume(dss_volume_t *volume, char *buffer, int32 size, int32 *read_size)
{
    CM_ASSERT(volume != NULL);
    CM_ASSERT(buffer != NULL);
    CM_ASSERT(read_size != NULL);

    if (!ReadFile(volume->handle, buffer, (DWORD)size, (LPDWORD)read_size, NULL)) {
        if (dss_is_device_os_error(cm_get_os_error())) {
            DSS_THROW_ERROR(ERR_DSS_VOLUME_SYSTEM_IO, volume->name_p);
            LOG_RUN_ERR("[DSS] ABORT READ VOLUME, because Linux OS error: errno:%d, errmsg:%s.", cm_get_os_error(),
                strerror(cm_get_os_error()));
            cm_fync_logfile();
            _exit(1);
        } else {
            DSS_THROW_ERROR(ERR_DSS_VOLUME_READ, volume->name_p, volume->id, cm_get_os_error());
        }
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

static status_t dss_try_write_volume(dss_volume_t *volume, char *buffer, int32 size, int32 *written_size)
{
    if (!WriteFile(volume->handle, buffer, (DWORD)size, (LPDWORD)written_size, NULL)) {
        if (dss_is_device_os_error(cm_get_os_error())) {
            DSS_THROW_ERROR(ERR_DSS_VOLUME_SYSTEM_IO, volume->name_p);
            LOG_RUN_ERR("[DSS] ABORT WRITE VOLUME, because Linux OS error: errno:%d, errmsg:%s.", cm_get_os_error(),
                strerror(cm_get_os_error()));
            cm_fync_logfile();
            _exit(1);
        } else {
            DSS_THROW_ERROR(ERR_DSS_VOLUME_WRITE, volume->name_p, volume->id, cm_get_os_error());
        }
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

#else
static inline void dss_open_fail(const char *name)
{
    if (dss_is_device_os_error(cm_get_os_error())) {
        DSS_THROW_ERROR(ERR_DSS_VOLUME_SYSTEM_IO, name);
        LOG_RUN_ERR("[DSS] ABORT OPEN VOLUME RAW, because Linux OS error: errno:%d, errmsg:%s.", cm_get_os_error(),
            strerror(cm_get_os_error()));
        cm_fync_logfile();
        _exit(1);
    } else {
        DSS_THROW_ERROR(ERR_DSS_VOLUME_OPEN, name, cm_get_os_error());
    }
}

static status_t dss_open_filehandle_raw(const char *name, int flags, volume_handle_t *fd, volume_handle_t *unaligned_fd)
{
    // O_RDWR | O_SYNC | O_DIRECT
    *fd = open(name, flags, 0);
    if (*fd == -1) {
        dss_open_fail(name);
        return CM_ERROR;
    }

    // O_RDWR | O_SYNC
    *unaligned_fd = open(name, DSS_NOD_OPEN_FLAG, 0);
    if (*unaligned_fd == -1) {
        dss_open_fail(name);
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

status_t dss_open_volume_raw(const char *name, const char *code, int flags, dss_volume_t *volume)
{
    if (dss_open_filehandle_raw(name, flags, &volume->handle, &volume->unaligned_handle) != CM_SUCCESS) {
        return CM_ERROR;
    }
    errno_t ret = snprintf_s(volume->name, DSS_MAX_VOLUME_PATH_LEN, DSS_MAX_VOLUME_PATH_LEN - 1, "%s", name);
    DSS_SECUREC_SS_RETURN_IF_ERROR(ret, CM_ERROR);
    volume->name_p = volume->name;
    return CM_SUCCESS;
}

status_t dss_open_simple_volume_raw(const char *name, int flags, dss_simple_volume_t *volume)
{
    if (dss_open_filehandle_raw(name, flags, &volume->handle, &volume->unaligned_handle) != CM_SUCCESS) {
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

void dss_close_volume_raw(dss_volume_t *volume)
{
    int ret = close(volume->handle);
    if (ret != 0) {
        LOG_RUN_ERR("failed to close file with handle %d, error code %d", volume->handle, errno);
    }
    ret = close(volume->unaligned_handle);
    if (ret != 0) {
        LOG_RUN_ERR("failed to close file with unaligned_handle %d, error code %d", volume->unaligned_handle, errno);
    }

    if (memset_s(volume, sizeof(dss_volume_t), 0, sizeof(dss_volume_t)) != EOK) {
        cm_panic(0);
    }
    volume->handle = DSS_INVALID_HANDLE;
    volume->unaligned_handle = DSS_INVALID_HANDLE;
}

void dss_close_simple_volume_raw(dss_simple_volume_t *simple_volume)
{
    (void)close(simple_volume->handle);
    simple_volume->handle = DSS_INVALID_HANDLE;
    (void)close(simple_volume->unaligned_handle);
    simple_volume->unaligned_handle = DSS_INVALID_HANDLE;
}

uint64 dss_get_volume_size_raw(dss_volume_t *volume)
{
    int64 size = lseek64(volume->handle, 0, SEEK_END);
    if (size == -1) {
        DSS_LOG_WITH_OS_MSG("failed to seek file with handle %d", volume->handle);
        if (dss_is_device_os_error(cm_get_os_error())) {
            DSS_THROW_ERROR(ERR_DSS_VOLUME_SYSTEM_IO, volume->name_p);
            LOG_RUN_ERR("[DSS] ABORT GET VOLUME SIZE, because Linux OS error: errno:%d, errmsg:%s.", cm_get_os_error(),
                strerror(cm_get_os_error()));
            cm_fync_logfile();
            _exit(1);
        } else {
            DSS_THROW_ERROR(ERR_DSS_VOLUME_SEEK, volume->name_p, volume->id, cm_get_os_error());
        }
        return DSS_INVALID_64;
    }
    return (uint64)size;
}

static status_t dss_try_pread_volume_raw(dss_volume_t *volume, int64 offset, char *buffer, int32 size, int32 *read_size)
{
    *read_size = (int32)pread(volume->handle, buffer, size, (off_t)offset);
    if (*read_size == -1) {
        if (dss_is_device_os_error(cm_get_os_error())) {
            DSS_THROW_ERROR(ERR_DSS_VOLUME_SYSTEM_IO, volume->name_p);
            LOG_RUN_ERR("[DSS] ABORT PREAD VOLUME, because Linux OS error: errno:%d, errmsg:%s.", cm_get_os_error(),
                strerror(cm_get_os_error()));
            cm_fync_logfile();
            _exit(1);
        } else {
            DSS_THROW_ERROR(ERR_DSS_VOLUME_READ, volume->name_p, volume->id, cm_get_os_error());
        }
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

static int32 dss_try_pwrite_volume_raw(
    dss_volume_t *volume, int64 offset, char *buffer, int32 size, int32 *written_size)
{
    bool8 aligned_pwrite =
        offset % DSS_DISK_UNIT_SIZE == 0 && size % DSS_DISK_UNIT_SIZE == 0 && (uint64)buffer % DSS_DISK_UNIT_SIZE == 0;
    if (aligned_pwrite) {
        *written_size = (int32)pwrite(volume->handle, buffer, size, (off_t)offset);
        if (*written_size == -1) {
            if (dss_is_device_os_error(cm_get_os_error())) {
                DSS_THROW_ERROR(ERR_DSS_VOLUME_SYSTEM_IO, volume->name_p);
                LOG_RUN_ERR("[DSS] ABORT ALIGNED PWRITE VOLUME, because Linux OS error: errno:%d, errmsg:%s.", cm_get_os_error(),
                    strerror(cm_get_os_error()));
                cm_fync_logfile();
                _exit(1);
            } else {
                DSS_THROW_ERROR(ERR_DSS_VOLUME_WRITE, volume->name_p, volume->id, cm_get_os_error());
            }
            return CM_ERROR;
        }
    } else {
        *written_size = (int32)pwrite(volume->unaligned_handle, buffer, size, (off_t)offset);
        if (*written_size == -1) {
            if (dss_is_device_os_error(cm_get_os_error())) {
                DSS_THROW_ERROR(ERR_DSS_VOLUME_SYSTEM_IO, volume->name_p);
                LOG_RUN_ERR("[DSS] ABORT UNALIGNED PWRITE VOLUME, because Linux OS error: errno:%d, errmsg:%s.", cm_get_os_error(),
                    strerror(cm_get_os_error()));
                cm_fync_logfile();
                _exit(1);
            } else {
                DSS_THROW_ERROR(ERR_DSS_VOLUME_WRITE, volume->name_p, volume->id, cm_get_os_error());
            }
            return CM_ERROR;
        }
    }

    return CM_SUCCESS;
}

typedef struct dss_file_mgr {
    status_t (*open_volume)(const char *name, const char *code, int flags, dss_volume_t *volume);
    status_t (*open_simple_volume)(const char *name, int flags, dss_simple_volume_t *volume);
    void (*close_volume)(dss_volume_t *volume);
    void (*close_simple_volume)(dss_simple_volume_t *simple_volume);
    uint64 (*get_volume_size)(dss_volume_t *volume);
    status_t (*try_pread_volume)(dss_volume_t *volume, int64 offset, char *buffer, int32 size, int32 *read_size);
    int32 (*try_pwrite_volume)(dss_volume_t *volume, int64 offset, char *buffer, int32 size, int32 *written_size);
} file_mgr;

static const file_mgr file_mgr_funcs[] = {
    {dss_open_volume_raw, dss_open_simple_volume_raw, dss_close_volume_raw, dss_close_simple_volume_raw,
        dss_get_volume_size_raw, dss_try_pread_volume_raw, dss_try_pwrite_volume_raw}
};

dss_vg_device_Type_e parse_vg_open_type(const char *name)
{
    return DSS_VOLUME_TYPE_RAW;
}

status_t dss_open_volume(const char *name, const char *code, int flags, dss_volume_t *volume)
{
    volume->vg_type = parse_vg_open_type(name);
    return (*(file_mgr_funcs[volume->vg_type].open_volume))(name, code, flags, volume);
}

status_t dss_open_simple_volume(const char *name, int flags, dss_simple_volume_t *volume)
{
    volume->vg_type = parse_vg_open_type(name);
    return (*(file_mgr_funcs[volume->vg_type].open_simple_volume))(name, flags, volume);
}

void dss_close_volume(dss_volume_t *volume)
{
    (*(file_mgr_funcs[volume->vg_type].close_volume))(volume);
}

void dss_close_simple_volume(dss_simple_volume_t *simple_volume)
{
    (*(file_mgr_funcs[simple_volume->vg_type].close_simple_volume))(simple_volume);
}

uint64 dss_get_volume_size(dss_volume_t *volume)
{
    return (*(file_mgr_funcs[volume->vg_type].get_volume_size))(volume);
}

static status_t dss_try_pread_volume(dss_volume_t *volume, int64 offset, char *buffer, int32 size, int32 *read_size)
{
    return (*(file_mgr_funcs[volume->vg_type].try_pread_volume))(volume, offset, buffer, size, read_size);
}

static int32 dss_try_pwrite_volume(dss_volume_t *volume, int64 offset, char *buffer, int32 size, int32 *written_size)
{
    return (*(file_mgr_funcs[volume->vg_type].try_pwrite_volume))(volume, offset, buffer, size, written_size);
}

#endif

status_t dss_read_volume(dss_volume_t *volume, int64 offset, void *buf, int32 size)
{
    status_t ret;
    int32 curr_size, total_size;
#ifdef WIN32
    if (dss_seek_volume(volume, offset) != CM_SUCCESS) {
        return CM_ERROR;
    }
#endif
    total_size = 0;

    do {
        curr_size = 0;
#ifdef WIN32
        ret = dss_try_read_volume(volume, (char *)buf + total_size, size - total_size, &curr_size);
#else
        ret =
            dss_try_pread_volume(volume, offset + total_size, (char *)buf + total_size, size - total_size, &curr_size);
#endif
        if (ret != CM_SUCCESS) {
            LOG_RUN_ERR("Failed to read volume %s, begin:%d, volume id:%u, size:%d, offset:%lld.", volume->name_p,
                total_size, volume->id, size - total_size, offset);
            return CM_ERROR;
        }

        if ((curr_size == 0) && (total_size < size)) {
            LOG_RUN_ERR("Read volume %s size error, begin:%d, volume id:%u, size:%d, offset:%lld.", volume->name_p,
                total_size, volume->id, size - total_size, offset);
            return CM_ERROR;
        }

        total_size += curr_size;
    } while (total_size < size);

    return CM_SUCCESS;
}

status_t dss_write_volume(dss_volume_t *volume, int64 offset, const void *buf, int32 size)
{
    status_t ret;
    int32 curr_size, total_size;
#ifdef WIN32
    if (dss_seek_volume(volume, offset) != CM_SUCCESS) {
        LOG_RUN_ERR("failed to seek volume %s , volume id:%u", volume->name_p, volume->id);
        return CM_ERROR;
    }
#endif
    total_size = 0;

    do {
#ifdef WIN32
        ret = dss_try_write_volume(volume, (char *)buf + total_size, size - total_size, &curr_size);
#else
        ret =
            dss_try_pwrite_volume(volume, offset + total_size, (char *)buf + total_size, size - total_size, &curr_size);
#endif
        if (ret != CM_SUCCESS) {
            LOG_RUN_ERR("Failed to write volume %s, begin:%d, volume id:%u,size:%d, offset:%lld, errmsg:%s.",
                volume->name_p, total_size, volume->id, size - total_size, offset, strerror(errno));
            return CM_ERROR;
        }

        total_size += curr_size;
    } while (total_size < size);

    return CM_SUCCESS;
}

#ifdef __cplusplus
}
#endif
