#include <gtest/gtest.h>

extern "C" {
#include "dss_api.h"
}

// 工具函数：dss_check_size - 对齐的 size 应返回 DSS_SUCCESS
TEST(DSSApiUtilityTest, CheckSizeAligned) {
    // DSS_DEFAULT_AU_SIZE 是 8MB，测试 8MB 的倍数
    EXPECT_EQ(DSS_SUCCESS, dss_check_size(8 * 1024 * 1024));
    EXPECT_EQ(DSS_SUCCESS, dss_check_size(16 * 1024 * 1024));
    EXPECT_EQ(DSS_SUCCESS, dss_check_size(0));
}

// 工具函数：dss_check_size - 不对齐的 size 应返回 DSS_ERROR
TEST(DSSApiUtilityTest, CheckSizeUnaligned) {
    EXPECT_EQ(DSS_ERROR, dss_check_size(1));
    EXPECT_EQ(DSS_ERROR, dss_check_size(1024));
    EXPECT_EQ(DSS_ERROR, dss_check_size(8 * 1024 * 1024 + 1));
}

// 工具函数：dss_align_size - 应向上对齐到 AU_SIZE 的倍数
TEST(DSSApiUtilityTest, AlignSize) {
    int au_size = 8 * 1024 * 1024;  // 8MB
    EXPECT_EQ(0, dss_align_size(0));
    EXPECT_EQ(au_size, dss_align_size(1));
    EXPECT_EQ(au_size, dss_align_size(au_size - 1));
    EXPECT_EQ(au_size, dss_align_size(au_size));
    EXPECT_EQ(2 * au_size, dss_align_size(au_size + 1));
}

