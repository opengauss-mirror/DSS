#include <gtest/gtest.h>

extern "C" {
#include "dss_api.h"
}

// 简单示例：测试 dss_get_lib_version 是否能被正常调用
TEST(DSSApiBasicTest, GetLibVersion) {
    int ver = dss_get_lib_version();
    // 版本号大于等于 0 即认为调用成功（具体语义由实现决定）
    EXPECT_GE(ver, 0);
}

// 基础：版本号应与头文件中的宏计算结果一致
TEST(DSSApiBasicTest, LibVersionMatchesMacros) {
    int ver = dss_get_lib_version();
    int expected = DSS_LOCAL_MAJOR_VERSION * DSS_LOCAL_MAJOR_VER_WEIGHT +
                   DSS_LOCAL_MINOR_VERSION * DSS_LOCAL_MINOR_VER_WEIGHT +
                   DSS_LOCAL_VERSION;
    EXPECT_EQ(ver, expected);
}

// 参数校验：dss_set_svr_path 传 NULL 应返回 DSS_ERROR
TEST(DSSApiBasicTest, SetSvrPathNull) {
    EXPECT_EQ(DSS_ERROR, dss_set_svr_path(nullptr));
}

// 参数校验：dss_set_svr_path 传空串应返回 DSS_ERROR
TEST(DSSApiBasicTest, SetSvrPathEmpty) {
    EXPECT_EQ(DSS_ERROR, dss_set_svr_path(""));
}

// 正常路径：dss_set_svr_path 传入一个简单的 Unix 域套接字路径，应返回 DSS_SUCCESS
TEST(DSSApiBasicTest, SetSvrPathNormal) {
    // 这里只是写入全局变量，不依赖真实 socket 是否存在
    EXPECT_EQ(DSS_SUCCESS, dss_set_svr_path("/tmp/dss.sock"));
}

// 日志相关 API：注册日志回调与设置日志级别不会崩溃
static void DummyLogCallback(dss_log_id_t log_type, dss_log_level_t log_level,
    const char *code_file_name, unsigned int code_line_num,
    const char *module_name, const char *format, ...) {
    (void)log_type;
    (void)log_level;
    (void)code_file_name;
    (void)code_line_num;
    (void)module_name;
    (void)format;
}

TEST(DSSApiBasicTest, RegisterLogCallbackAndSetLevel) {
    dss_register_log_callback(DummyLogCallback, DSS_LOG_LEVEL_INFO);
    dss_set_log_level(DSS_LOG_LEVEL_ERROR);
    SUCCEED();
}

// 连接超时：dss_set_default_conn_timeout - 正数应设置超时
TEST(DSSApiBasicTest, SetDefaultConnTimeoutPositive) {
    dss_set_default_conn_timeout(30);
    SUCCEED();
}

// 连接超时：dss_set_default_conn_timeout - 0 或负数应设置为永不超时
TEST(DSSApiBasicTest, SetDefaultConnTimeoutZeroOrNegative) {
    dss_set_default_conn_timeout(0);
    dss_set_default_conn_timeout(-1);
    SUCCEED();
}

// 错误获取：dss_get_error - 应能正常调用（不崩溃）
TEST(DSSApiBasicTest, GetError) {
    int errcode = 0;
    const char *errmsg = nullptr;
    dss_get_error(&errcode, &errmsg);
    SUCCEED();
}

