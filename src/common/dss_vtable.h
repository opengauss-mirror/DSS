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
 * dss_vtable.h
 *
 *
 * IDENTIFICATION
 *    src/common/dss_vtable.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __DSS_VTABLE_H__
#define __DSS_VTABLE_H__

#include "dss_defs.h"
#include "dss_ctrl_def.h"
#include "cm_error.h"
#include "dss_errno.h"
#include "dss_vtable.h"
#include "stdint.h"
#include "stdbool.h"
#include <time.h>

#define LIB_VTABLE_NAME "libbio_bdev.so"
#define LIB_VTABLE_ADAPTER_NAME "libvTable.so"

#define VT_FULL_OPERATE 1
#define VT_PARTIAL_OPERATE 0
#define VT_INSERT_BL 0
#define VT_DELETE_BL 1

// BIO
typedef enum {
    RET_CACHE_OK = 0,            // successful
    RET_CACHE_PROTECTED = 1,     // cache write protected
    RET_CACHE_ERROR = 2,         // unknown error code
    RET_CACHE_EPERM = 3,         // input parameter is incorrect
    RET_CACHE_BUSY = 4,          // cache busy, need outer retry
    RET_CACHE_NEED_RETRY = 5,    // need retry
    RET_CACHE_NOT_READY = 6,     // retry is not required
    RET_CACHE_NOT_FOUND = 7,     // not found this key
    RET_CACHE_CONFLICT = 8,      // key conflict
    RET_CACHE_MISS = 9,          // cache miss
    RET_CACHE_NO_SPACE = 10,     // cache capacity not enough
    RET_CACHE_UNAVAILABLE = 11,  // cache service unavailable
    RET_CACHE_EXCEED_QUOTA = 12, // exceed cache quota limit
    RET_CACHE_PT_FAULT = 13,     // cache partition fault
    RET_CACHE_READ_EXCEED = 14,  // read limit is exceeded
    RET_CACHE_EXISTS = 15,       // cache already exists
    RET_CACHE_BUTT
} CResult;

typedef enum {
    LOCAL_AFFINITY = 1, // data local affinity
    GLOBAL_BALANCE = 2, // data global balance
    AFFINITY_BUTT
} AffinityStrategy;

typedef enum {
    WRITE_BACK = 1,
    WRITE_THROUGH = 2,
    STRATEGY_BUTT
} WriteStrategy;

typedef enum {
    CONVERGENCE,
    SEPARATES
} WorkerMode;

#define MAX_KEY_SIZE (256)
#define LOCATION_SIZE (2)
typedef void (*BioLoadCallback)(void *context, int32_t result);

typedef struct {
    char key[MAX_KEY_SIZE];
    uint32_t size;
    time_t time;
} ObjStat;

typedef struct {
    uint64_t location[LOCATION_SIZE];
} ObjLocation;

typedef struct {
    uint64_t tenantId;
    AffinityStrategy affinity;
    WriteStrategy strategy;
} CacheDescriptor;

#define CACHE_SPACE_ADDRESS_SIZE (2)
#define CACHE_SPACE_DEC_SIZE (64)

typedef struct {
    uint64_t address;
    uint32_t size;
} CacheAddress;

typedef struct {
    uint8_t allocLoc;
    uint16_t addressNum;
    uint16_t descriptorSize;
    ObjLocation loc;
    CacheAddress address[CACHE_SPACE_ADDRESS_SIZE];
    char descriptorInfo[CACHE_SPACE_DEC_SIZE];
} CacheSpaceInfo;

typedef enum {
    STDOUT_TYPE,
    FILE_TYPE,
    STDERR_TYPE
} LogType;

typedef struct {
    LogType logType;                   // STDOUT_TYPE/FILE_TYPE/STDERR_TYPE
    char logFilePath[PATH_MAX];        // log file path, if log type use FILE_TYPE, need to set this param
    uint8_t enable;                    // switch
    char certificationPath[PATH_MAX];  // certification path
    char caCerPath[PATH_MAX];          // caCer path
    char caCrlPath[PATH_MAX];          // caCer path
    char privateKeyPath[PATH_MAX];     // private key path
    char privateKeyPassword[PATH_MAX]; // private key password
    char hseKfsMasterPath[PATH_MAX];   // hseceasy kfs master path
    char hseKfsStandbyPath[PATH_MAX];  // hseceasy kfs standby path
    bool isDriverServer;
} ClientOptionsConfig;

typedef struct {
    char** ipList;       // IP address
    uint64_t* offsetList; // Dynamic array storing offsets
    uint64_t* lengthList; // Dynamic array storing lengths
    size_t size;          // Current number of stored elements
    size_t capacity;      // Current capacity
} PtInfoList;

// vtable
void Exit();
void BdevExit();
CResult Initialize(WorkerMode mode, ClientOptionsConfig *optConf);
CResult CreateVolume(uint16_t volumeType, uint64_t cap, uint32_t alignedSize, uint64_t* volumeId);
CResult DestroyVolume(uint64_t volumeId);
CResult Write(uint64_t volumeId, uint64_t offset, uint32_t length, char *value);
CResult List(uint64_t volumeId, bool* exist, uint64_t* cap, uint32_t* alignedSize, uint16_t* type);
CResult Read(uint64_t volumeId, uint64_t offset, uint32_t length, char *value);
CResult Append(uint64_t volumeId, uint64_t offset, uint32_t length, char *value);
CResult Fence(const char *ip, uint64_t volumeId, uint16_t operateType, bool fullOperate);  // 0 insert BL, 1 delete BL
CResult FenceQuery(const char *ip, uint64_t volumeId, uint16_t *isFenced);

// vtable Adapter
int VtableAdapterAppend(uint64_t lunId, uint64_t offset, uint64_t length, const char* value);
int VtableAdapterWrite(uint64_t lunId, uint64_t offset, uint64_t length, char* value);
int VtableAdapterInit();

// DSS
typedef struct st_vtable_func {
    bool symbolnited;
    bool isInitialize;
    void* vtableHandle;
    void* vtableAdapterHandle;
    void (*BdevExit)(void);
    CResult (*Initialize)(WorkerMode mode, ClientOptionsConfig *optConf);
    CResult (*CreateVolume)(uint16_t volumeType, uint64_t cap, uint32_t alignedSize, uint64_t* volumeId);
    CResult (*DestroyVolume)(uint64_t volumeId);
    CResult (*Write)(uint64_t volumeId, uint64_t offset, uint32_t length, char *value);
    CResult (*Read)(uint64_t volumeId, uint64_t offset, uint32_t length, char *value);
    CResult (*List)(uint64_t volumeId, bool* exist, uint64_t* cap, uint32_t* alignedSize, uint16_t* type);
    void (*PtInfoListDestroy)(PtInfoList *ptInfoList);
    PtInfoList* (*PtInfoListCreate)(size_t init_capacity);
    CResult (*GetMasterNodeIPByOffset)(uint64_t volumeId, uint64_t offset, uint64_t length, PtInfoList *ptInfoList);
    CResult (*VtableAdapterInit)();
    CResult (*VtableAdapterAppend)(uint64_t volumeId, uint64_t offset, uint32_t length, char *value);
    CResult (*VtableAdapterWrite)(uint64_t volumeId, uint64_t offset, uint64_t length, char *value);
    CResult (*Fence)(const char *ip, uint64_t volumeId, uint16_t operateType, bool fullOperate);
    CResult (*FenceQuery)(const char *ip, uint64_t volumeId, uint16_t *isFenced);
} vtable_func_t;

#ifdef __cplusplus
extern "C" {
#endif
extern vtable_func_t g_vtable_func;
status_t vtable_func_init();
void VtableExit(void);
status_t VtableInitAdapter();
status_t VtableInitialize(WorkerMode mode, ClientOptionsConfig *optConf);
status_t VtableCreateVolume(uint16_t volumeType, uint64_t cap, uint32_t alignedSize, uint64_t* volumeId);
status_t VtableDestroyVolume(uint64_t volumeId);
status_t VtableWrite(uint64_t volumeId, uint64_t offset, uint32_t length, char *value);
status_t VtableRead(uint64_t volumeId, uint64_t offset, uint32_t length, char *value);
status_t VtableList(uint64_t volumeId, bool* exist, uint64_t* cap, uint32_t* alignedSize, uint16_t* type);
status_t VtableGetMasterNodeIPByOffset(uint64_t volumeId, uint64_t offset, char *ip);
status_t VtableAppendAdapter(uint64_t volumeId, uint64_t offset, uint32_t length, char *value);
status_t VtableWriteAdapte(uint64_t volumeId, uint64_t offset, uint32_t length, char *value);
status_t VtableFence(const char *ip, uint64_t volumeId, uint16_t operateType, bool fullOperate);
status_t VtableFenceQuery(const char *ip, uint64_t volumeId, uint16_t *isFenced);
    
status_t dss_init_vtable(void);
uint64 vtable_name_to_ptid(const char* name);
status_t dss_open_volume_vtable(const char *name, const char *code, int flags, dss_volume_t *volume);
status_t dss_open_simple_volume_vtable(const char *name, int flags, dss_simple_volume_t *volume);
void dss_close_volume_vtable(dss_volume_t *volume);
void dss_close_simple_volume_vtable(dss_simple_volume_t *simple_volume);
uint64 dss_get_volume_size_vtable(dss_volume_t *volume);
status_t dss_try_pread_volume_vtable(dss_volume_t *volume, int64 offset, char *buffer,
                                            int32 size, int32 *read_size);
int32 dss_try_pwrite_volume_vtable(dss_volume_t *volume, int64 offset, char *buffer,
                                          int32 size, int32 *written_size);
int32 dss_try_append_volume_vtable(dss_volume_t *volume, int64 offset, char *buffer,
                                          int32 size, int32 *written_size);


#ifdef __cplusplus
}
#endif

#endif
