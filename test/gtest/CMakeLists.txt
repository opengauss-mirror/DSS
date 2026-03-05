cmake_minimum_required(VERSION 3.10)

project(DSSApiTest)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)
set(CMAKE_BUILD_TYPE Debug)

# 为 gtest 可执行文件打开更完整的调试信息，便于在 IDE / gdb 里单步调试
add_compile_options(-O0 -g3 -ggdb)

find_package(GTest REQUIRED)

# 计算 DSS 工程根目录（test/gtest 的上上级目录）
get_filename_component(DSS_ROOT "${PROJECT_SOURCE_DIR}/../.." ABSOLUTE)

# 头文件路径
include_directories(${GTEST_INCLUDE_DIRS})
include_directories(${DSS_ROOT}/src/interface)

# 库路径（需要先在 DSS 根目录编译过一次，生成 output/lib/libdssapi.so）
link_directories(${DSS_ROOT}/output/lib)

# 仿照 WR：每个用例文件生成一个独立的测试可执行文件
add_executable(test_dss_api_basic test_dss_api_basic.cc)
add_executable(test_dss_api_param test_dss_api_param.cc)
add_executable(test_dss_api_util  test_dss_api_util.cc)
add_executable(test_dss_api_file  test_dss_api_file.cc)

# 一些发行版的 FindGTest 只设置 GTEST_LIBRARIES，有的还会设置 GTEST_MAIN_LIBRARIES
# 这里同时链接这两个变量，以确保把 gtest 自带的 main 链接进来，避免 “undefined reference to `main'”
target_link_libraries(test_dss_api_basic ${GTEST_LIBRARIES} ${GTEST_MAIN_LIBRARIES} pthread dssapi)
target_link_libraries(test_dss_api_param ${GTEST_LIBRARIES} ${GTEST_MAIN_LIBRARIES} pthread dssapi)
target_link_libraries(test_dss_api_util  ${GTEST_LIBRARIES} ${GTEST_MAIN_LIBRARIES} pthread dssapi)
target_link_libraries(test_dss_api_file  ${GTEST_LIBRARIES} ${GTEST_MAIN_LIBRARIES} pthread dssapi)

enable_testing()
add_test(NAME DSSApiBasicTest   COMMAND test_dss_api_basic)
add_test(NAME DSSApiParamTest   COMMAND test_dss_api_param)
add_test(NAME DSSApiUtilityTest COMMAND test_dss_api_util)
add_test(NAME DSSApiFileTest    COMMAND test_dss_api_file)

