#include <gtest/gtest.h>

extern "C" {
#include "dss_api.h"
}

// 参数校验：dss_dread - item 或 result 为 NULL 应返回 DSS_ERROR（dir 非空占位即可）
TEST(DSSApiParamTest, DreadNullItemOrResult) {
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

