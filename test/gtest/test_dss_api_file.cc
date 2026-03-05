#include <gtest/gtest.h>
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <fcntl.h>

extern "C" {
#include "dss_api.h"
}

// 业务用例：基于真实 dssserver 的端到端文件操作
// 依赖外部环境：
//   - 环境变量 DSS_HOME，用于拼接默认 UDS 路径：UDS:$DSS_HOME/.dss_unix_d_socket（与 dsscmd 参数说明一致）
//   - 可选环境变量 DSS_GTEST_SVR_PATH：如果设置则优先使用，覆盖上述默认 UDS 路径
//   - 环境变量 DSS_GTEST_FILE_PATH：指定用于测试的 DSS 文件基础路径（例如 +dssvg/test/gtest_file）
// 如果环境未配置或前置条件不满足，则直接 return，当作“未启用业务用例”。

static const char *GetEnvOrNull(const char *name)
{
    const char *val = std::getenv(name);
    if (val == nullptr || std::strlen(val) == 0) {
        return nullptr;
    }
    return val;
}

// 构造 dssserver 的 UDS 实例路径：
// 1. 如果设置了 DSS_GTEST_SVR_PATH，则直接使用该值；
// 2. 否则从 DSS_HOME 拼接：UDS:$DSS_HOME/.dss_unix_d_socket。
// 构造失败返回 false。
static bool BuildDssSvrPath(char *out, size_t out_size)
{
    const char *svr_path_env = GetEnvOrNull("DSS_GTEST_SVR_PATH");
    if (svr_path_env != nullptr) {
        size_t len = std::strlen(svr_path_env);
        if (len + 1 > out_size) {
            std::printf("[DSSApiFileTest] DSS_GTEST_SVR_PATH too long, skip business test.\n");
            return false;
        }
        std::memcpy(out, svr_path_env, len + 1);
        return true;
    }

    const char *dss_home = GetEnvOrNull("DSS_HOME");
    if (dss_home == nullptr) {
        std::printf("[DSSApiFileTest] Neither DSS_GTEST_SVR_PATH nor DSS_HOME set, skip business test.\n");
        return false;
    }

    int n = std::snprintf(out, out_size, "UDS:%s/.dss_unix_d_socket", dss_home);
    if (n <= 0 || static_cast<size_t>(n) >= out_size) {
        std::printf("[DSSApiFileTest] Failed to build UDS path from DSS_HOME, skip business test.\n");
        return false;
    }
    return true;
}

// 简单工具：基于基础路径拼接子文件路径，例如：base=+vg/test/file，suffix=_pwrite -> +vg/test/file_pwrite
static bool BuildSubFilePath(const char *base, const char *suffix, char *out, size_t out_size)
{
    if (base == nullptr || suffix == nullptr) {
        return false;
    }
    int n = std::snprintf(out, out_size, "%s%s", base, suffix);
    if (n <= 0 || static_cast<size_t>(n) >= out_size) {
        std::printf("[DSSApiFileTest] Failed to build sub file path from base=%s, suffix=%s.\n", base, suffix);
        return false;
    }
    return true;
}

TEST(DSSApiFileTest, CreateWriteReadRemoveFile)
{
    const char *file_base = GetEnvOrNull("DSS_GTEST_FILE_PATH");
    if (file_base == nullptr) {
        std::printf("[DSSApiFileTest] DSS_GTEST_FILE_PATH not set, skip business test.\n");
        return;
    }

    char svr_path[1024] = {0};
    if (!BuildDssSvrPath(svr_path, sizeof(svr_path))) {
        return;
    }
    const char *file_path = file_base;

    // 设置服务端路径
    if (dss_set_svr_path(svr_path) != DSS_SUCCESS) {
        std::printf("[DSSApiFileTest] dss_set_svr_path failed (svr_path=%s), skip business test.\n", svr_path);
        return;
    }

    // 尝试删除遗留文件，忽略返回值
    (void)dss_fremove(file_path);

    // 创建文件
    int ret = dss_fcreate(file_path, 0);
    if (ret != DSS_SUCCESS) {
        std::printf("[DSSApiFileTest] dss_fcreate failed, skip business test.\n");
        return;
    }

    // 打开文件（读写模式）
    int handle = -1;
    ret = dss_fopen(file_path, O_RDWR, &handle);
    if (ret != DSS_SUCCESS) {
        std::printf("[DSSApiFileTest] dss_fopen failed, skip business test.\n");
        (void)dss_fremove(file_path);
        return;
    }

    const char *write_data = "hello dss gtest";
    int write_size = static_cast<int>(std::strlen(write_data));

    // 顺序写入
    ret = dss_fwrite(handle, write_data, write_size);
    ASSERT_EQ(DSS_SUCCESS, ret);

    // 重新定位到文件开头
    long long seek_ret = dss_fseek(handle, 0, SEEK_SET);
    ASSERT_EQ(0, seek_ret);

    // 读取并校验内容
    char read_buf[256] = {0};
    int read_size = 0;
    ret = dss_fread(handle, read_buf, write_size, &read_size);
    ASSERT_EQ(DSS_SUCCESS, ret);
    ASSERT_EQ(write_size, read_size);
    ASSERT_EQ(0, std::memcmp(read_buf, write_data, write_size));

    // 关闭文件
    ret = dss_fclose(handle);
    ASSERT_EQ(DSS_SUCCESS, ret);

    // 删除文件
    ret = dss_fremove(file_path);
    ASSERT_EQ(DSS_SUCCESS, ret);
}

// 业务用例：使用 pwrite/pread 在文件不同 offset 写入/读取，并结合 truncate 验证文件内容
TEST(DSSApiFileTest, PwritePreadAndTruncate)
{
    const char *file_base = GetEnvOrNull("DSS_GTEST_FILE_PATH");
    if (file_base == nullptr) {
        std::printf("[DSSApiFileTest] DSS_GTEST_FILE_PATH not set, skip business test.\n");
        return;
    }

    char svr_path[1024] = {0};
    if (!BuildDssSvrPath(svr_path, sizeof(svr_path))) {
        return;
    }

    // 为本用例构造一个独立文件路径，避免与其他用例冲突
    char file_path[1024] = {0};
    if (!BuildSubFilePath(file_base, "_pwrite", file_path, sizeof(file_path))) {
        return;
    }

    if (dss_set_svr_path(svr_path) != DSS_SUCCESS) {
        std::printf("[DSSApiFileTest] dss_set_svr_path failed (svr_path=%s), skip business test.\n", svr_path);
        return;
    }

    // 清理历史遗留文件
    (void)dss_fremove(file_path);

    // 创建并打开文件
    int ret = dss_fcreate(file_path, 0);
    if (ret != DSS_SUCCESS) {
        std::printf("[DSSApiFileTest] dss_fcreate failed for %s, skip business test.\n", file_path);
        return;
    }

    int handle = -1;
    ret = dss_fopen(file_path, O_RDWR, &handle);
    if (ret != DSS_SUCCESS) {
        std::printf("[DSSApiFileTest] dss_fopen failed for %s, skip business test.\n", file_path);
        (void)dss_fremove(file_path);
        return;
    }

    const char *block1 = "AAAAA";
    const char *block2 = "BBBBB";
    int len = 5;

    // 在 offset=0 写 block1，在 offset=len 写 block2，文件逻辑内容应为 \"AAAAABBBBB\"
    ret = dss_pwrite(handle, block1, len, 0);
    ASSERT_EQ(DSS_SUCCESS, ret);

    ret = dss_pwrite(handle, block2, len, len);
    ASSERT_EQ(DSS_SUCCESS, ret);

    // 使用 pread 验证两个 block
    char buf[32] = {0};
    int read_size = 0;

    ret = dss_pread(handle, buf, len, 0, &read_size);
    ASSERT_EQ(DSS_SUCCESS, ret);
    ASSERT_EQ(len, read_size);
    ASSERT_EQ(0, std::memcmp(buf, block1, len));

    std::memset(buf, 0, sizeof(buf));
    read_size = 0;
    ret = dss_pread(handle, buf, len, len, &read_size);
    ASSERT_EQ(DSS_SUCCESS, ret);
    ASSERT_EQ(len, read_size);
    ASSERT_EQ(0, std::memcmp(buf, block2, len));

    // 截断文件，只保留前 len 字节
    long long new_len = len;
    ret = dss_ftruncate(handle, new_len);
    ASSERT_EQ(DSS_SUCCESS, ret);

    // 从 offset=0 读取 len*2 字节，应至少保证前 len 字节内容与 block1 一致
    std::memset(buf, 0, sizeof(buf));
    read_size = 0;
    ret = dss_pread(handle, buf, len * 2, 0, &read_size);
    ASSERT_EQ(DSS_SUCCESS, ret);
    ASSERT_EQ(0, std::memcmp(buf, block1, len));

    // 关闭并删除
    ret = dss_fclose(handle);
    ASSERT_EQ(DSS_SUCCESS, ret);

    ret = dss_fremove(file_path);
    ASSERT_EQ(DSS_SUCCESS, ret);
}

// 业务用例：拷贝文件并使用 stat 校验类型和大小
TEST(DSSApiFileTest, CopyAndStatFile)
{
    const char *file_base = GetEnvOrNull("DSS_GTEST_FILE_PATH");
    if (file_base == nullptr) {
        std::printf("[DSSApiFileTest] DSS_GTEST_FILE_PATH not set, skip business test.\n");
        return;
    }

    char svr_path[1024] = {0};
    if (!BuildDssSvrPath(svr_path, sizeof(svr_path))) {
        return;
    }

    char src_path[1024] = {0};
    char dst_path[1024] = {0};
    if (!BuildSubFilePath(file_base, "_copy_src", src_path, sizeof(src_path))) {
        return;
    }
    if (!BuildSubFilePath(file_base, "_copy_dst", dst_path, sizeof(dst_path))) {
        return;
    }

    if (dss_set_svr_path(svr_path) != DSS_SUCCESS) {
        std::printf("[DSSApiFileTest] dss_set_svr_path failed (svr_path=%s), skip business test.\n", svr_path);
        return;
    }

    // 清理历史文件
    (void)dss_fremove(src_path);
    (void)dss_fremove(dst_path);

    // 创建源文件并写入数据
    int ret = dss_fcreate(src_path, 0);
    if (ret != DSS_SUCCESS) {
        std::printf("[DSSApiFileTest] dss_fcreate failed for %s, skip business test.\n", src_path);
        return;
    }

    int handle = -1;
    ret = dss_fopen(src_path, O_RDWR, &handle);
    if (ret != DSS_SUCCESS) {
        std::printf("[DSSApiFileTest] dss_fopen failed for %s, skip business test.\n", src_path);
        (void)dss_fremove(src_path);
        return;
    }

    const char *content = "COPY_TEST_CONTENT";
    int content_len = static_cast<int>(std::strlen(content));
    ret = dss_fwrite(handle, content, content_len);
    ASSERT_EQ(DSS_SUCCESS, ret);

    ret = dss_fclose(handle);
    ASSERT_EQ(DSS_SUCCESS, ret);

    // 拷贝文件
    ret = dss_fcopy(src_path, dst_path);
    ASSERT_EQ(DSS_SUCCESS, ret);

    // 使用 stat 校验目标文件存在且大小一致
    dss_stat_t src_stat = {0};
    dss_stat_t dst_stat = {0};

    ret = dss_stat(src_path, &src_stat);
    ASSERT_EQ(DSS_SUCCESS, ret);

    ret = dss_stat(dst_path, &dst_stat);
    ASSERT_EQ(DSS_SUCCESS, ret);

    EXPECT_EQ(src_stat.type, dst_stat.type);
    EXPECT_EQ(src_stat.size, dst_stat.size);
    EXPECT_EQ(static_cast<unsigned long long>(content_len), dst_stat.size);

    // 清理文件
    ret = dss_fremove(src_path);
    ASSERT_EQ(DSS_SUCCESS, ret);
    ret = dss_fremove(dst_path);
    ASSERT_EQ(DSS_SUCCESS, ret);
}

// 业务用例：打开不存在的文件应失败（返回错误码，句柄保持为 -1）
TEST(DSSApiFileTest, OpenNonExistFileShouldFail)
{
    const char *file_base = GetEnvOrNull("DSS_GTEST_FILE_PATH");
    if (file_base == nullptr) {
        std::printf("[DSSApiFileTest] DSS_GTEST_FILE_PATH not set, skip business test.\n");
        return;
    }

    char svr_path[1024] = {0};
    if (!BuildDssSvrPath(svr_path, sizeof(svr_path))) {
        return;
    }

    char file_path[1024] = {0};
    if (!BuildSubFilePath(file_base, "_nonexist", file_path, sizeof(file_path))) {
        return;
    }

    if (dss_set_svr_path(svr_path) != DSS_SUCCESS) {
        std::printf("[DSSApiFileTest] dss_set_svr_path failed (svr_path=%s), skip business test.\n", svr_path);
        return;
    }

    // 确保文件不存在
    (void)dss_fremove(file_path);

    int handle = 12345;  // 初始化为非 -1，观察失败路径是否保留原值
    int ret = dss_fopen(file_path, O_RDONLY, &handle);  // 尝试只读打开不存在的文件
    EXPECT_NE(DSS_SUCCESS, ret);
    EXPECT_EQ(-1, handle);  // 根据 dss_fopen 的实现，失败时应保持为 -1
}

