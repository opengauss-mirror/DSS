/*
 * Copyright (c) 2024 Huawei Technologies Co., Ltd. All rights reserved.
 * This file is part of the Cantian project.
 * Cantian is licensed under Mulan PSL v2.
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
 * dss_perf.c
 *
 *
 * IDENTIFICATION
 * src/tools/dss_perf/dss_perf.c
 *
 * -------------------------------------------------------------------------
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/time.h>
#include <errno.h>
#include <sys/stat.h>
#include "dss_defs.h"
#include "dss_api.h"
#include "dss_io_fence.h"
#include "dss_log.h"

#ifdef WIN32
#define DSSAPI "dssapi.dll"
#else
#define DSSAPISO "libdssapi.so"
#endif

#define CT_SUCCESS 0
#define CT_ERROR (-1)
#define CT_MAX_LOG_CONTENT_LENGTH 4096
#define CT_UNIX_PATH_MAX 1024
#define CT_TRUE 1

#define USECOND_PER_SECOND (1000000)
#define BYTES_PER_MB (1024 * 1024)
#define VALID_PARAM_COUNT (6)

typedef struct {
    dss_session_t session;
    dss_device_handle_t device_handle;
} dss_dev_handle_t;

/* DSS设备初始化 */
status_t perf_device_init(const char *path)
{
    dss_session_attr_t session_attr;
    status_t ret;
    
    memset(&session_attr, 0, sizeof(session_attr));
    session_attr.log_level = DSS_LOG_INFO;
    strncpy(session_attr.socket_path, path, DSS_MAX_PATH_LEN - 1);
    
    ret = dss_init_session(&session_attr);
    if (ret != CT_SUCCESS) {
        LOG_ERR_INF("Failed to initialize DSS session");
        return CT_ERROR;
    }
    
    LOG_RUN_INF("DSS session initialized successfully");
    return CT_SUCCESS;
}

/* 加载DSS路径配置 */
status_t perf_load_dss_path(char *inst_path)
{
    char *value = NULL;
    char config_path[CT_UNIX_PATH_MAX];
    FILE *config_file = NULL;
    char line[CT_UNIX_PATH_MAX];
    
    memset(inst_path, 0, CT_UNIX_PATH_MAX);
    
    value = getenv("DSS_HOME");
    if (value == NULL) {
        value = "/opt/openGauss/install/dss_home/.dss_unix_d_socket";
    } else {
        value += ".dss_unix_d_socket";
    }
    
    strncpy(config_path, value, CT_UNIX_PATH_MAX - 1);
    
    config_file = fopen(config_path, "r");
    if (config_file == NULL) {
        LOG_ERR_INF("Failed to open config file: %s", config_path);
        return CT_ERROR;
    }
    
    while (fgets(line, sizeof(line), config_file) != NULL) {
        char *key = strtok(line, "=");
        char *val = strtok(NULL, " \t\n");
        
        if (key != NULL && val != NULL) {
            if (strcmp(key, "DSS_INST_PATH") == 0 || 
                strcmp(key, "CTSTORE_INST_PATH") == 0) {
                strncpy(inst_path, val, CT_UNIX_PATH_MAX - 1);
                fclose(config_file);
                LOG_RUN_INF("Loaded DSS instance path from config: %s", inst_path);
                return CT_SUCCESS;
            }
        }
    }
    
    fclose(config_file);
    
    /* 如果配置文件中没有找到，使用默认值 */
    snprintf(inst_path, CT_UNIX_PATH_MAX, "UDS:/opt/dss/.dss_unix_d_socket");
    LOG_RUN_INF("Using default DSS instance path: %s", inst_path);
    return CT_SUCCESS;
}

/* 分配对齐的内存 */
void* dss_malloc_align(size_t alignment, size_t size)
{
    void *ptr = NULL;
    
    if (posix_memalign(&ptr, alignment, size) != 0) {
        LOG_ERR_INF("Failed to allocate aligned memory, alignment: %zu, size: %zu", alignment, size);
        return NULL;
    }
    
    return ptr;
}

/* 连续写入测试 */
int perf_write_continue(dss_device_handle_t handle, uint32 block_size, uint32 count)
{
    char *buf = NULL;
    uint32 written = 0;
    int64 offset = 0;
    struct timeval beg, end;
    status_t ret;
    
    buf = (char *)dss_malloc_align(512, block_size);
    if (buf == NULL) {
        LOG_ERR_INF("Failed to allocate aligned memory for write test");
        return -1;
    }
    
    memset(buf, 'A', block_size);
    
    LOG_RUN_INF("Starting write performance test: block_size=%u, count=%u", block_size, count);
    gettimeofday(&beg, NULL);
    
    while (written < count) {
        ret = dss_write(handle, buf, block_size, offset);
        if (ret != CT_SUCCESS) {
            LOG_ERR_INF("Failed to write to DSS device at offset %ld", offset);
            free(buf);
            return -1;
        }
        
        /* 确保数据落盘（如果需要同步写） */
        ret = dss_sync(handle);
        if (ret != CT_SUCCESS) {
            LOG_ERR_INF("Failed to sync DSS device");
            free(buf);
            return -1;
        }
        
        written++;
        offset += block_size;
    }
    
    gettimeofday(&end, NULL);
    
    /* 计算性能指标 */
    double time_cost = (end.tv_sec - beg.tv_sec) + 
                      (end.tv_usec - beg.tv_usec) / (double)USECOND_PER_SECOND;
    
    if (time_cost > 0) {
        double bandwidth = (written * block_size) / (double)BYTES_PER_MB / time_cost;
        double avg_delay = (time_cost / written) * USECOND_PER_SECOND;
        
        printf("Write %u blocks, cost time: %f s, bandwidth: %f MB/s, delay: %f us\n", 
               written, time_cost, bandwidth, avg_delay);
    } else {
        printf("Write %u blocks completed\n", written);
    }
    
    LOG_RUN_INF("Write test completed: %u blocks, total data: %.2f MB", 
               written, (written * block_size) / (double)BYTES_PER_MB);
    
    free(buf);
    return 0;
}

/* 连续读取测试 */
int perf_read_continue(dss_device_handle_t handle, uint32 block_size, uint32 count)
{
    char *buf = NULL;
    uint32 read_count = 0;
    int64 offset = 0;
    struct timeval beg, end;
    status_t ret;
    
    buf = (char *)dss_malloc_align(512, block_size);
    if (buf == NULL) {
        LOG_ERR_INF("Failed to allocate aligned memory for read test");
        return -1;
    }
    
    LOG_RUN_INF("Starting read performance test: block_size=%u, count=%u", block_size, count);
    gettimeofday(&beg, NULL);
    
    while (read_count < count) {
        ret = dss_read(handle, buf, block_size, offset);
        if (ret != CT_SUCCESS) {
            LOG_ERR_INF("Failed to read from DSS device at offset %ld", offset);
            free(buf);
            return -1;
        }
        
        read_count++;
        offset += block_size;
    }
    
    gettimeofday(&end, NULL);
    
    /* 计算性能指标 */
    double time_cost = (end.tv_sec - beg.tv_sec) + 
                      (end.tv_usec - beg.tv_usec) / (double)USECOND_PER_SECOND;
    
    if (time_cost > 0) {
        double bandwidth = (read_count * block_size) / (double)BYTES_PER_MB / time_cost;
        double avg_delay = (time_cost / read_count) * USECOND_PER_SECOND;
        
        printf("Read %u blocks, cost time: %f s, bandwidth: %f MB/s, delay: %f us\n", 
               read_count, time_cost, bandwidth, avg_delay);
    } else {
        printf("Read %u blocks completed\n", read_count);
    }
    
    LOG_RUN_INF("Read test completed: %u blocks, total data: %.2f MB", 
               read_count, (read_count * block_size) / (double)BYTES_PER_MB);
    
    free(buf);
    return 0;
}

int32 main(int32 argc, char *argv[])
{
    char inst_path[CT_UNIX_PATH_MAX];
    char *cmd = NULL;
    char *dss_path = NULL;
    uint32 block_size = 0;
    uint32 count = 0;
    status_t ret;
    dss_device_handle_t handle = DSS_INVALID_HANDLE;
    
    if (argc < VALID_PARAM_COUNT - 1) {
        printf("Usage: %s <cmd> <dss_path> <block_size> <count> [inst_path]\n", argv[0]);
        printf("Commands:\n");
        printf("  read     - Read performance test\n");
        printf("  writec   - Continuous write performance test\n");
        printf("Parameters:\n");
        printf("  dss_path   - DSS file path name\n");
        printf("  block_size - Size of each block in bytes\n");
        printf("  count      - Number of blocks to operate on\n");
        printf("  inst_path  - Optional DSS instance socket path\n");
        return -1;
    }
    
    /* 获取DSS实例路径 */
    if (argc == VALID_PARAM_COUNT) {
        strncpy(inst_path, argv[VALID_PARAM_COUNT - 1], CT_UNIX_PATH_MAX - 1);
        printf("Using command line DSS instance path: %s\n", inst_path);
    } else {
        /* 从配置文件加载或使用默认值 */
        ret = perf_load_dss_path(inst_path);
        if (ret != CT_SUCCESS) {
            printf("Warning: Using default DSS instance path\n");
            snprintf(inst_path, CT_UNIX_PATH_MAX, "UDS:/opt/dss/.dss_unix_d_socket");
        }
    }
    
    printf("DSS instance path: %s\n", inst_path);
    
    /* 初始化DSS设备 */
    ret = perf_device_init(inst_path);
    if (ret != CT_SUCCESS) {
        printf("Failed to initialize DSS device\n");
        return -1;
    }
    
    LOG_RUN_INF("DSS device initialized successfully");
    printf("DSS device initialized successfully\n");
    
    /* 解析命令行参数 */
    cmd = argv[1];
    dss_path = argv[2];
    block_size = (uint32)strtoul(argv[3], NULL, 10);
    count = (uint32)strtoul(argv[4], NULL, 10);
    
    if (strcmp(cmd, "read") == 0) {
        printf("Read DSS path: %s, block size: %u, count: %u\n", 
               dss_path, block_size, count);
        LOG_RUN_INF("Starting read test: path=%s, block_size=%u, count=%u", 
                   dss_path, block_size, count);
        
        /* 打开DSS设备用于读取 */
        ret = dss_fopen(dss_path, O_RDONLY, &handle);
        if (ret != CT_SUCCESS) {
            LOG_ERR_INF("Failed to open DSS device for reading: %s", dss_path);
            printf("Failed to open DSS device for reading: %s\n", dss_path);
            return -1;
        }
        
        LOG_RUN_INF("DSS device opened successfully for reading");
        
        /* 执行读取测试 */
        ret = perf_read_continue(handle, block_size, count);
        if (ret != CT_SUCCESS) {
            LOG_ERR_INF("Read performance test failed");
            dss_fclose(handle);
            return -1;
        }
        
        dss_fclose(handle);
        LOG_RUN_INF("Read test completed successfully");
        
    } else if (strcmp(cmd, "writec") == 0) {
        printf("Write DSS path: %s, block size: %u, count: %u\n", 
               dss_path, block_size, count);
        LOG_RUN_INF("Starting write test: path=%s, block_size=%u, count=%u", 
                   dss_path, block_size, count);
        
        /* 打开DSS设备用于写入（如果不存在则创建） */
        ret = dss_fopen(dss_path, DSS_READ_WRITE | DSS_CREATE, &handle);
        if (ret != CT_SUCCESS) {
            LOG_ERR_INF("Failed to open DSS device for writing: %s", dss_path);
            printf("Failed to open DSS device for writing: %s\n", dss_path);
            return -1;
        }
        
        LOG_RUN_INF("DSS device opened successfully for writing");
        
        /* 执行写入测试 */
        ret = perf_write_continue(handle, block_size, count);
        if (ret != CT_SUCCESS) {
            LOG_ERR_INF("Write performance test failed");
            dss_fclose(handle);
            return -1;
        }
        
        dss_fclose(handle);
        LOG_RUN_INF("Write test completed successfully");
        
    } else {
        printf("Unknown command: %s\n", cmd);
        printf("Usage: %s <cmd> <dss_path> <block_size> <count>\n", argv[0]);
        LOG_ERR_INF("Unknown command: %s", cmd);
        return -1;
    }
    
    dss_destroy_session();
    
    LOG_RUN_INF("Test completed successfully");
    printf("Test completed successfully\n");
    return 0;
}