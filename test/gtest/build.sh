#!/bin/bash

set -e

RUN_TESTS=0

for arg in "$@"; do
    if [ "$arg" = "-t" ]; then
        RUN_TESTS=1
    fi
done

# 使用系统安装的 gtest（和 WR 一样通过 find_package(GTest)）
# 直接在 gtest 目录下生成编译产物，不创建 build 子目录

cmake .
make -j"$(nproc)"

if [ "$RUN_TESTS" -eq 1 ]; then
    # 使用 ctest 跑 CTest 中注册的用例
    ctest --output-on-failure
fi