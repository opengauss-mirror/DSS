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
 * cm_shm.c
 *
 *
 * IDENTIFICATION
 *    src/common/cm_shm.c
 *
 * -------------------------------------------------------------------------
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef WIN32
#include <sys/types.h>
#include <sys/shm.h>
#include <errno.h>
#include <sys/mman.h>
#endif
#include "cm_date.h"
#include "cm_memory.h"
#include "cm_thread.h"
#include "dss_defs.h"
#include "dss_errno.h"
#include "dss_malloc.h"
#include "dss_shm.h"

uint32 g_shm_key = 0;

/* shared memory mapping */
cm_shm_map_t g_shm_map;
static thread_lock_t g_shm_map_lock;
static bool32 g_shm_inited = CM_FALSE;

#define CM_INVALID_SHM_KEY (0)

static cm_shm_ctrl_t *cm_shm_ctrl(void)
{
    return (cm_shm_ctrl_t *)g_shm_map.entries[SHM_ID_MNG_CTRL].addr;
}

static uint32 cm_shm_idx_of(cm_shm_type_e type, uint32 id)
{
    uint32 result;

    if (type == SHM_TYPE_FIXED) {
        if (id >= CM_FIXED_SHM_ID_TAIL) {
            LOG_DEBUG_ERR("Fixed shared memory ID is out of  range : %u", id);
            return CM_INVALID_SHM_IDX;
        }
        result = id;
    } else if (type == SHM_TYPE_HASH) {
        if (id >= CM_HASH_SHM_MAX_ID) {
            LOG_DEBUG_ERR("GA shared memory ID is out of range : %u", id);
            return CM_INVALID_SHM_IDX;
        }
        result = CM_FIXED_SHM_ID_TAIL + id;
    } else if (type == SHM_TYPE_GA) {
        if (id >= CM_GA_SHM_MAX_ID) {
            LOG_DEBUG_ERR("GA shared memory ID is out of range : %u", id);
            return CM_INVALID_SHM_IDX;
        }
        result = CM_FIXED_SHM_ID_TAIL + CM_HASH_SHM_MAX_ID + id;
    } else {
        LOG_DEBUG_ERR("invalid type, type: %u", type);
        return CM_INVALID_SHM_IDX;
    }
    return result;
}

cm_shm_key_t cm_shm_key_of(cm_shm_type_e type, uint32 id)
{
    uint32 idx = cm_shm_idx_of(type, id);

    return idx != CM_INVALID_SHM_IDX ? CM_SHM_IDX_TO_KEY(idx) : CM_INVALID_SHM_KEY;
}

#define CM_SHM_MAP_ENTRY_OF(key) (&g_shm_map.entries[CM_SHM_KEY2IDX(key)])
#define SHM_ADDR_OF(key) (CM_SHM_MAP_ENTRY_OF(key)->addr)
#define SHM_ADDR_BAK_OF(key) (CM_SHM_MAP_ENTRY_OF(key)->addr_bak)

static void cm_lock_shm_map(void)
{
    cm_thread_lock(&g_shm_map_lock);
}

static void cm_unlock_shm_map(void)
{
    cm_thread_unlock(&g_shm_map_lock);
}

#ifdef WIN32
static void cm_fill_shm_name(char *name, cm_shm_key_t key)
{
    if (snprintf_s(name, CM_FILE_NAME_BUFFER_SIZE, CM_FILE_NAME_BUFFER_SIZE, "gmdb_0x%08x", key) == -1) {
        cm_panic(0);
    }
}
#endif

cm_shm_handle_t cm_native_create_shm(cm_shm_key_t key, uint64 size, uint32 permission)
{
#ifdef WIN32
    char name[CM_FILE_NAME_BUFFER_SIZE];
    uint32 high = (uint32)(size >> 32);
    uint32 low = (uint32)(size & 0xFFFFFFFF);
    (void)permission;

    cm_fill_shm_name(name, key);

    return CreateFileMapping(CM_INVALID_SHM_HANDLE, NULL, PAGE_READWRITE, high, low, name);
#else
    /* PL/MDE:qinchaoli 712:Loss of precision (Context) (Type to Type) */
    return shmget((key_t)key, size, (int32)(IPC_CREAT | IPC_EXCL | permission));
#endif
}

void cm_native_close_shm(cm_shm_handle_t handle)
{
#ifdef WIN32
    (void)CloseHandle(handle);
#else
    (void)handle;
#endif
}

void *cm_native_attach_shm(cm_shm_handle_t handle, uint32 flag)
{
#ifdef WIN32
    return MapViewOfFile(handle, flag, 0, 0, 0);
#else
    uint32 retry_num = SHM_MAX_RETRY_ATTACH_NUM;
    uint64 offset;
    void *result = NULL;
    for (uint32 i = 0; i < retry_num; i++) {
        result = shmat(handle, result, (int)flag);
        /* shmat will return -1 when error */
        if ((int64)result == -1) {
            return NULL;
        } else {
            offset = ((uint64)result) % DSS_ALIGN_SIZE;
            if (offset == 0) {
                return result;
            } else {
                shmdt(result);
                result = (char *)result + (DSS_ALIGN_SIZE - offset) + DSS_ALIGN_SIZE * retry_num;
            }
        }
    }
    return NULL;
#endif
}

static void *cm_create_shm(cm_shm_key_t key, uint64 size, uint32 flag, uint32 permission)
{
    cm_shm_map_entry_t *entry = &g_shm_map.entries[CM_SHM_KEY2IDX(key)];

    entry->handle = cm_native_create_shm(key, size, permission);
    if (entry->handle == CM_INVALID_SHM_HANDLE) {
        DSS_LOG_WITH_OS_MSG(
            "Failed to create shared memory, key=0x%08x, size=%llu. The system memory may be insufficient, please "
            "check it firstly. Or there may be existent shared memory which is created by other process or last "
            "existed gmdb instance, please delete it manually and retry again",
            key, size);
        return NULL;
    }

    entry->addr = cm_native_attach_shm(entry->handle, flag);
    if (entry->addr == NULL) {
        DSS_LOG_WITH_OS_MSG(
            "Failed to attach shared memory, handle=%d, key=0x%08x, size=%llu. The existent shared memory may be "
            "created by other process or last existed gmdb instance, please delete it manually and retry again",
            entry->handle, key, size);
        (void)cm_native_del_shm(entry->handle);
        entry->handle = CM_INVALID_SHM_HANDLE;
    } else {
#ifdef WIN32
        /* for Windows 32bit OS, the memory address can't bigger than 4G,
         * so convert uint64 to uint32.
         * IMPORTANT: NOT portable for Windows 64bit OS
         */
        errno_t errcode = memset_s(entry->addr, size, 0, (uint32)size);
        if (errcode != EOK) {
            cm_panic(0);
        }
#else
        errno_t errcode = memset_s(entry->addr, size, 0, size);
        if (errcode != EOK) {
            cm_panic(0);
        }
#endif
    }

    return entry->addr;
}

cm_shm_handle_t cm_native_open_shm(uint32 key)
{
#ifdef WIN32
    char name[CM_FILE_NAME_BUFFER_SIZE];
    cm_shm_handle_t result;

    cm_fill_shm_name(name, key);
    result = OpenFileMapping(FILE_MAP_ALL_ACCESS, CM_FALSE, name);

    return (NULL == result) ? CM_INVALID_SHM_HANDLE : result;
#else
    return shmget((int32)key, 0, 0);
#endif
}

uint64 cm_native_shm_size(cm_shm_key_t key)
{
#ifdef WIN32
    (void)key;
    return 0;
#else
    cm_shm_handle_t handle = cm_native_open_shm(key);
    if (handle == CM_INVALID_SHM_HANDLE) {
        return 0;
    } else {
        struct shmid_ds shm_stat;
        int32 ret;
        ret = shmctl(handle, IPC_STAT, &shm_stat);
        if (ret != -1) {
            return shm_stat.shm_segsz;
        } else {
            return 0;
        }
    }
#endif
}

bool32 cm_native_detach_shm(void *addr)
{
#ifdef WIN32
    return UnmapViewOfFile(addr);
#else
    int32 result = shmdt(addr);
    return result != -1;
#endif
}

#define SHM_CTRL_LOCK (cm_shm_ctrl()->lock_for_self)

static void *cm_attach_to_existing_shm(cm_shm_key_t key, cm_shm_handle_t handle, uint64 size, uint32 flag)
{
    void *result = cm_native_attach_shm(handle, flag);

    if (result == NULL) {
        DSS_LOG_WITH_OS_MSG(
            "Failed to attach shared memory, handle=%d, key=0x%08x, size=%llu. The existent shared memory may be "
            "created by other process or last existed gmdb instance, please delete it manually and retry again.",
            handle, key, size);
    }

#ifndef WIN32
    if ((result != NULL) && (size != 0)) {
        if (cm_native_shm_size(key) != size) {
            LOG_DEBUG_ERR("Failed to attach shared memory, key=0x%08x, reason=expected size %llu can not match actual "
                          "size %llu. The existent shared memory may be created by other process or last existed gmdb "
                          "instance, please delete it manually and retry again.",
                key, size, cm_native_shm_size(key));
            (void)cm_native_detach_shm(result);
            result = NULL;
        }
    }
#endif

    return result;
}

void *cm_do_attach_shm_without_register(cm_shm_key_t key, uint64 size, uint32 flag, bool32 logging_open_err)
{
    cm_shm_map_entry_t *entry = CM_SHM_MAP_ENTRY_OF(key);

    if (entry->addr != NULL) {
        return entry->addr;
    }

#ifndef WIN32
    entry->handle = cm_native_open_shm(key);
#else
    if (entry->handle == CM_INVALID_SHM_HANDLE) {
        entry->handle = cm_native_open_shm(key);
    }
#endif

    if (entry->handle == CM_INVALID_SHM_HANDLE) {
        if (logging_open_err) {
            DSS_LOG_WITH_OS_MSG("Failed to open shared memory, key=0x%08x, size=%llu", key, size);
        }
        return NULL;
    } else {
        entry->addr = cm_attach_to_existing_shm(key, entry->handle, size, flag);
        return entry->addr;
    }
}

static void *cm_do_attach_shm(cm_shm_key_t key, uint64 size, uint32 flag, bool32 logging_open_err)
{
    return cm_do_attach_shm_without_register(key, size, flag, logging_open_err);
}

#define CM_SHM_CTRL_KEY CM_SHM_IDX_TO_KEY((uint32)SHM_ID_MNG_CTRL)

static status_t cm_create_shm_ctrl(void)
{
    if (cm_create_shm(CM_SHM_CTRL_KEY, CM_SHM_SIZE_OF_CTRL, CM_SHM_ATTACH_RW, CM_SHM_PERMISSION) == NULL) {
        return ERR_DSS_SHM_CREATE;
    }

    GS_INIT_SPIN_LOCK(SHM_CTRL_LOCK);
    errno_t errcode =
        memcpy_s(cm_shm_ctrl()->magic, sizeof(cm_shm_ctrl()->magic), CM_SHM_MAGIC, sizeof(cm_shm_ctrl()->magic));
    securec_check_ret(errcode);
    cm_shm_ctrl()->self_version = CM_SHM_CTRL_CURRENT_VERSION;
    cm_shm_ctrl()->instance_id = CM_SHM_KEY2INSTANCE(CM_SHM_CTRL_KEY);

    return CM_SUCCESS;
}

static void *cm_create_shm_block(cm_shm_key_t key, uint64 size, uint32 flag, uint32 permission)
{
    return cm_create_shm(key, size, flag, permission);
}

static void init_entry(cm_shm_map_entry_t *entry)
{
    CM_ASSERT(entry != NULL);

    entry->handle = CM_INVALID_SHM_HANDLE;
    entry->addr = NULL;
}

static void cm_init_shm_map(void)
{
    for (uint32 i = 0; i < ELEMENT_COUNT(g_shm_map.entries); i++) {
        init_entry(&g_shm_map.entries[i]);
    }

    return;
}

static status_t cm_check_shm_ctrl(void)
{
#ifndef WIN32
    if (cm_native_shm_size(CM_SHM_CTRL_KEY) != CM_SHM_SIZE_OF_CTRL) {
        DSS_THROW_ERROR(ERR_DSS_SHM_CHECK, CM_SHM_CTRL_KEY, "mismatched size");
        return CM_ERROR;
    }
#endif

    if (memcmp(cm_shm_ctrl()->magic, CM_SHM_MAGIC, sizeof(cm_shm_ctrl()->magic)) != 0) {
        LOG_DEBUG_ERR("mismatched magic number");
        return ERR_DSS_SHM_CHECK;
    }

    if (cm_shm_ctrl()->self_version != CM_SHM_CTRL_CURRENT_VERSION) {
        LOG_DEBUG_ERR("Failed to check shared memory ctrl ,key=0x%08x, reason=expected version %u can not match actual "
                      "version %u.",
            CM_SHM_CTRL_KEY, CM_SHM_CTRL_CURRENT_VERSION, cm_shm_ctrl()->self_version);
        return ERR_DSS_SHM_CHECK;
    }

    return CM_SUCCESS;
}

static bool32 cm_do_detach_shm(cm_shm_key_t key, bool32 logging_err)
{
    void *addr = SHM_ADDR_OF(key);

    if (addr == NULL) {
        return CM_TRUE;
    }

    if (cm_native_detach_shm(addr)) {
        SHM_ADDR_BAK_OF(key) = addr;
        SHM_ADDR_OF(key) = NULL;
        return CM_TRUE;
    } else {
        if (logging_err) {
            DSS_LOG_WITH_OS_MSG("Failed to detach shared memory,key=0x%08x", key);
        }
        return CM_FALSE;
    }
}

static status_t cm_init_shm_ctrl()
{
    cm_shm_key_t key = CM_SHM_CTRL_KEY;
    if (cm_do_attach_shm_without_register(key, 0, CM_SHM_ATTACH_RW, CM_TRUE) == NULL) {
        return cm_create_shm_ctrl();
    } else {
        status_t result = cm_check_shm_ctrl();
        if (result != CM_SUCCESS) {
            (void)cm_do_detach_shm(CM_SHM_CTRL_KEY, CM_FALSE);
        }

        return result;
    }
}

status_t cm_do_init_shm(uint32 shm_key)
{
    int32 result;

    g_shm_key = shm_key;

    cm_init_shm_map();
    cm_init_thread_lock(&g_shm_map_lock);

    result = cm_init_shm_ctrl();
    if (result != CM_SUCCESS) {
        cm_destroy_thread_lock(&g_shm_map_lock);
    }

    return result;
}

status_t cm_init_shm(uint32 shm_key)
{
    if (g_shm_inited) {
        return CM_SUCCESS;
    } else {
        status_t result = cm_do_init_shm(shm_key);
        if (result == CM_SUCCESS) {
            g_shm_inited = CM_TRUE;
        }

        return result;
    }
}

static void *cm_do_get_shm(cm_shm_key_t key, uint64 size, uint32 flag, uint32 permission)
{
    void *result = cm_do_attach_shm(key, size, flag, CM_FALSE);

    return result != NULL ? result : cm_create_shm_block(key, size, flag, permission);
}

void *cm_get_shm(cm_shm_type_e type, uint32 id, uint64 size, uint32 flag, uint32 permission)
{
    cm_shm_key_t key = cm_shm_key_of(type, id);
    if (key == CM_INVALID_SHM_KEY) {
        return NULL;
    }
    cm_lock_shm_map();
    void *result = cm_do_get_shm(key, size, flag, permission);
    cm_unlock_shm_map();
    return result;
}

void *cm_attach_shm(cm_shm_type_e type, uint32 id, uint64 size, uint32 flag)
{
    cm_shm_key_t key = cm_shm_key_of(type, id);
    if (key == CM_INVALID_SHM_KEY) {
        return NULL;
    }
    cm_lock_shm_map();
    void *result = cm_do_attach_shm(key, size, flag, CM_TRUE);
    cm_unlock_shm_map();
    return result;
}

#define CM_SHM_HANDLE_OF(key) (g_shm_map.entries[CM_SHM_KEY2IDX(key)].handle)

bool32 cm_native_del_shm(cm_shm_handle_t handle)
{
#ifdef WIN32
    return CloseHandle(handle);
#else
    int32 ret = shmctl(handle, IPC_RMID, NULL);
    return ret != -1;
#endif
}

static bool32 do_del_shm_directly(cm_shm_key_t key)
{
    cm_shm_handle_t handle;
#ifdef WIN32
    handle = CM_SHM_HANDLE_OF(key);
#else
    handle = cm_native_open_shm(key);
#endif
    if (handle == CM_INVALID_SHM_HANDLE) {
        return CM_TRUE;
    }
    return cm_native_del_shm(handle);
}

static bool32 cm_del_shm_block(cm_shm_key_t key)
{
    if (!do_del_shm_directly(key)) {
        DSS_LOG_WITH_OS_MSG("Failed to delete shared memory,key=0x%08x", key);
        return CM_FALSE;
    }
    CM_SHM_HANDLE_OF(key) = CM_INVALID_SHM_HANDLE;
    return CM_TRUE;
}

static bool32 cm_do_del_shm(cm_shm_key_t key)
{
    return cm_do_detach_shm(key, CM_TRUE) ? cm_del_shm_block(key) : CM_FALSE;
}

static bool32 del_shm_by_key(cm_shm_key_t key)
{
    cm_lock_shm_map();
    bool32 result = cm_do_del_shm(key);
    cm_unlock_shm_map();
    return result;
}

bool32 cm_del_shm(cm_shm_type_e type, uint32 id)
{
    cm_shm_key_t key = cm_shm_key_of(type, id);
    if (key == CM_INVALID_SHM_KEY) {
        return CM_FALSE;
    }
    return del_shm_by_key(key);
}

bool32 cm_detach_shm(cm_shm_type_e type, uint32 id)
{
    cm_shm_key_t key = cm_shm_key_of(type, id);
    if (key == CM_INVALID_SHM_KEY) {
        return CM_FALSE;
    }
    cm_lock_shm_map();
    bool32 result = cm_do_detach_shm(key, CM_TRUE);
    cm_unlock_shm_map();
    return result;
}

static void cm_do_destroy_shm(void)
{
    cm_destroy_thread_lock(&g_shm_map_lock);

    memset_s(&g_shm_map_lock, sizeof(g_shm_map_lock), 0, sizeof(g_shm_map_lock));
}

void cm_destroy_shm(void)
{
    if (g_shm_inited) {
        cm_do_destroy_shm();
        g_shm_inited = CM_FALSE;
    }
}

void cm_set_shm_ctrl_flag(uint64 value)
{
    cm_shm_ctrl()->flag = value;
    CM_MFENCE
}

uint64 cm_get_shm_ctrl_flag(void)
{
    return cm_shm_ctrl()->flag;
}

sh_mem_p cm_trans_shm_offset(uint32_t key, void *ptr)
{
    sh_mem_p ptr_uint64 = 0;
    sh_mem_t *shm_ptr = (sh_mem_t *)(void *)&ptr_uint64;
    cm_shm_map_entry_t *entry = CM_SHM_MAP_ENTRY_OF(key);

    shm_ptr->offset = (uint32)((char *)ptr - (char *)entry->addr);
    shm_ptr->seg = CM_SHM_KEY2IDX(key);

    return ptr_uint64;
}
