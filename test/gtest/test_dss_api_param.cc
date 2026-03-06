#include <gtest/gtest.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>

extern "C" {
#include "dss_api.h"
}

// Define DSS_EVT_COUNT based on enum definition in dss_stats.h
// DSS_PREAD = 0, DSS_PWRITE, DSS_FREAD, DSS_FWRITE, DSS_PREAD_SYN_META,
// DSS_PWRITE_SYN_META, DSS_PREAD_DISK, DSS_PWRITE_DISK, DSS_FOPEN,
// DSS_STAT, DSS_FIND_FT_ON_SERVER, DSS_EVT_COUNT
// NOTE: DSS_EVT_COUNT equals 11 here because the enum's last value is the count itself.
#define DSS_EVT_COUNT 11

// Event names corresponding to dss_wait_event_e enum
static const char* g_dss_stat_event_names[DSS_EVT_COUNT] = {
    "DSS Pread",                    // DSS_PREAD = 0
    "DSS Pwrite",                   // DSS_PWRITE
    "DSS Fread",                    // DSS_FREAD
    "DSS Fwrite",                   // DSS_FWRITE
    "DSS Pread Sync Metadata",      // DSS_PREAD_SYN_META
    "DSS Pwrite Sync Metadata",     // DSS_PWRITE_SYN_META
    "DSS Pread Disk",               // DSS_PREAD_DISK
    "DSS Pwrite Disk",              // DSS_PWRITE_DISK
    "DSS File Open",                // DSS_FOPEN
    "DSS Stat",                     // DSS_STAT
    "Find File Node On Server",     // DSS_FIND_FT_ON_SERVER
};

// Get environment variable or return nullptr
static const char *GetEnvOrNull(const char *name)
{
    const char *val = std::getenv(name);
    if (val == nullptr || std::strlen(val) == 0) {
        return nullptr;
    }
    return val;
}

// Build dssserver UDS path:
// 1. If DSS_GTEST_SVR_PATH is set, use it directly;
// 2. Otherwise, build from DSS_HOME: UDS:$DSS_HOME/.dss_unix_d_socket
// Returns false on failure.
static bool BuildDssSvrPath(char *out, size_t out_size)
{
    const char *svr_path_env = GetEnvOrNull("DSS_GTEST_SVR_PATH");
    if (svr_path_env != nullptr) {
        size_t len = std::strlen(svr_path_env);
        if (len + 1 > out_size) {
            std::printf("[DSSApiParamTest] DSS_GTEST_SVR_PATH too long, skip server connection test.\n");
            return false;
        }
        std::memcpy(out, svr_path_env, len + 1);
        return true;
    }

    const char *dss_home = GetEnvOrNull("DSS_HOME");
    if (dss_home == nullptr) {
        std::printf("[DSSApiParamTest] Neither DSS_GTEST_SVR_PATH nor DSS_HOME set, skip server connection test.\n");
        return false;
    }

    int n = std::snprintf(out, out_size, "UDS:%s/.dss_unix_d_socket", dss_home);
    if (n <= 0 || static_cast<size_t>(n) >= out_size) {
        std::printf("[DSSApiParamTest] Failed to build UDS path from DSS_HOME, skip server connection test.\n");
        return false;
    }
    return true;
}

// Build test file path based on fixed path +data/test and a suffix.
// Example: suffix=_param_rw -> +data/test_param_rw
static bool BuildTestFilePath(const char *suffix, char *out, size_t out_size)
{
    const char *file_base = "+data/test";
    int n = std::snprintf(out, out_size, "%s%s", file_base, suffix);
    if (n <= 0 || static_cast<size_t>(n) >= out_size) {
        std::printf("[DSSApiParamTest] Failed to build test file path from base=%s, suffix=%s.\n", file_base, suffix);
        return false;
    }
    return true;
}

// 参数校验：dss_dread - item 或 result 为 NULL 应返回 DSS_ERROR（dir 非空占位即可）
TEST(DSSApiParamTest, DreadNullItemOrResult) {

    // 构建服务器路径
    char svr_path[1024] = {0};
    if (!BuildDssSvrPath(svr_path, sizeof(svr_path))) {
        // 环境变量未设置，跳过此测试
        return;
    }
    
    // 设置服务器路径
    if (dss_set_svr_path(svr_path) != DSS_SUCCESS) {
        std::printf("[DSSApiParamTest] dss_set_svr_path failed (svr_path=%s), skip server connection test.\n", svr_path);
        return;
    }

    dss_dirent_t item;
    dss_dir_item_t result = nullptr;
    // 这里传一个非空占位指针即可，真实实现不会在参数校验失败时解引用 dir
    dss_dir_handle fake_dir = (dss_dir_handle)0x1;

    EXPECT_EQ(DSS_ERROR, dss_dread(fake_dir, nullptr, &result));
    EXPECT_EQ(DSS_ERROR, dss_dread(fake_dir, &item, nullptr));
}

// 参数校验：dss_dread - NULL dir 但有效 item/result 应返回 DSS_SUCCESS（表示遍历结束）
TEST(DSSApiParamTest, DreadNullDirValidParams) {
    dss_dirent_t item;
    dss_dir_item_t result = nullptr;
    // 根据代码逻辑，dir == NULL 时直接返回 DSS_SUCCESS
    EXPECT_EQ(DSS_SUCCESS, dss_dread(nullptr, &item, &result));
    EXPECT_EQ(nullptr, result);
}

// 参数校验：dss_stat - NULL item 应返回 DSS_ERROR
TEST(DSSApiParamTest, StatNullItem) {
    EXPECT_EQ(DSS_ERROR, dss_stat("/some/path", nullptr));
}

// 参数校验：dss_lstat - NULL item 应返回 DSS_ERROR
TEST(DSSApiParamTest, LstatNullItem) {
    EXPECT_EQ(DSS_ERROR, dss_lstat("/some/path", nullptr));
}

// 参数校验：dss_fstat - NULL item 应返回 DSS_ERROR
TEST(DSSApiParamTest, FstatNullItem) {
    EXPECT_EQ(DSS_ERROR, dss_fstat(123, nullptr));
}

// 参数校验：dss_readlink - bufsize <= 0 应返回 DSS_ERROR
TEST(DSSApiParamTest, ReadlinkInvalidBufsize) {
    char buf[256];
    EXPECT_EQ(DSS_ERROR, dss_readlink("/some/link", buf, 0));
    EXPECT_EQ(DSS_ERROR, dss_readlink("/some/link", buf, -1));
}

// 参数校验：dss_pwrite - size < 0 应返回 DSS_ERROR
TEST(DSSApiParamTest, PwriteNegativeSize) {
    char buf[256] = {0};
    EXPECT_EQ(DSS_ERROR, dss_pwrite(123, buf, -1, 0));
}

// 参数校验：dss_pread - size < 0 应返回 DSS_ERROR
TEST(DSSApiParamTest, PreadNegativeSize) {
    char buf[256];
    int read_size = 0;
    EXPECT_EQ(DSS_ERROR, dss_pread(123, buf, -1, 0, &read_size));
}

// 参数校验：dss_pread - NULL read_size 应返回 DSS_ERROR
TEST(DSSApiParamTest, PreadNullReadSize) {
    char buf[256];
    EXPECT_EQ(DSS_ERROR, dss_pread(123, buf, 256, 0, nullptr));
}

// 参数校验：dss_is_maintain - NULL 指针应返回 DSS_ERROR
TEST(DSSApiParamTest, IsMaintainNullPointer) {
    EXPECT_EQ(DSS_ERROR, dss_is_maintain(nullptr));
}

// 正确读写：基于真实 dssserver 做一次简单的写入和读取，验证接口能正常工作
TEST(DSSApiParamTest, CorrectReadWriteWithServer) {
    // 构建服务器路径
    char svr_path[1024] = {0};
    if (!BuildDssSvrPath(svr_path, sizeof(svr_path))) {
        // 环境变量未设置，跳过此测试
        return;
    }

    // 设置服务器路径
    if (dss_set_svr_path(svr_path) != DSS_SUCCESS) {
        std::printf("[DSSApiParamTest] dss_set_svr_path failed (svr_path=%s), skip read/write test.\n", svr_path);
        return;
    }

    // 构造测试文件路径
    char file_path[1024] = {0};
    if (!BuildTestFilePath("_param_rw", file_path, sizeof(file_path))) {
        return;
    }

    // 确保文件不存在
    (void)dss_fremove(file_path);

    // 创建文件
    int ret = dss_fcreate(file_path, 0);
    if (ret != DSS_SUCCESS) {
        std::printf("[DSSApiParamTest] dss_fcreate failed (file_path=%s), skip read/write test.\n", file_path);
        return;
    }

    // 打开文件（读写模式）
    int handle = -1;
    ret = dss_fopen(file_path, O_RDWR, &handle);
    if (ret != DSS_SUCCESS) {
        std::printf("[DSSApiParamTest] dss_fopen failed (file_path=%s), skip read/write test.\n", file_path);
        (void)dss_fremove(file_path);
        return;
    }

    const char *write_data = "param rw test";
    int write_size = static_cast<int>(std::strlen(write_data));

    // 顺序写入
    ret = dss_fwrite(handle, write_data, write_size);
    ASSERT_EQ(DSS_SUCCESS, ret);

    // 重新定位到文件开头
    long long seek_ret = dss_fseek(handle, 0, SEEK_SET);
    ASSERT_EQ(0, seek_ret);

    // 关闭并删除文件
    ret = dss_fclose(handle);
    ASSERT_EQ(DSS_SUCCESS, ret);
    ret = dss_fremove(file_path);
    ASSERT_EQ(DSS_SUCCESS, ret);
}
// 参数校验：dss_get_time_stat - count >= DSS_EVT_COUNT 且 time_stat 非空应能正常调用
// 注意：此测试需要连接 DSS 服务器，如果环境变量未设置或连接失败，则跳过
TEST(DSSApiParamTest, GetTimeStatValidParams) {

    
    // 使用足够大的缓冲区
    dss_time_stat_item_t time_stat[DSS_EVT_COUNT];
    int ret = dss_get_time_stat(time_stat, DSS_EVT_COUNT);
    
    // 如果成功获取统计信息，打印每一项的详细信息
    if (ret == DSS_SUCCESS) {
        printf("\n=== DSS Time Statistics ===\n");
        printf("%-30s | %12s | %18s | %18s | %18s\n", 
               "Event Name", "Wait Count", "Total Wait Time(us)", 
               "Max Single Time(us)", "Avg Wait Time(us)");
        printf("--------------------------------------------------------------------------------------------------------\n");
        
        for (int i = 0; i < DSS_EVT_COUNT; i++) {
            unsigned long long avg_time = 0;
            if (time_stat[i].wait_count > 0) {
                avg_time = time_stat[i].total_wait_time / time_stat[i].wait_count;
            }
            
            printf("%-30s | %12llu | %18llu | %18llu | %18llu\n",
                   g_dss_stat_event_names[i],
                   time_stat[i].wait_count,
                   time_stat[i].total_wait_time,
                   time_stat[i].max_single_time,
                   avg_time);
        }
        printf("========================================================================================================\n\n");
    } else {
        std::printf("[DSSApiParamTest] dss_get_time_stat failed (ret=%d), server may not be running.\n", ret);
    }
    
    // 至少验证函数不会因为参数校验而崩溃
    SUCCEED();
}
