CMAKE_MINIMUM_REQUIRED(VERSION 3.12.1)
PROJECT(dss)

message(${CMAKE_BUILD_TYPE})
if (${CMAKE_BUILD_TYPE} STREQUAL "Debug"
        OR ${CMAKE_BUILD_TYPE} STREQUAL "")
    message(STATUS "CMAKE_BUILD_TYPE is Debug")
    set(CMAKE_BUILD_TYPE Debug)
    add_compile_definitions(_DEBUG DB_DEBUG_VERSION)
elseif (${CMAKE_BUILD_TYPE} STREQUAL "Memcheck" OR ${CMAKE_BUILD_TYPE} STREQUAL "MemcheckDsstest")
    message(STATUS "CMAKE_BUILD_TYPE is Memcheck")
    set(CMAKE_BUILD_TYPE Memcheck)
    add_compile_definitions(_DEBUG DB_DEBUG_VERSION)
    add_compile_options(-fsanitize=address -fsanitize-recover=address -fsanitize=undefined -fsanitize-recover=undefined  -ggdb -fno-omit-frame-pointer -fno-optimize-sibling-calls)
    add_link_options(-fsanitize=address -fsanitize-recover=address -fsanitize=undefined -fsanitize-recover=undefined  -ggdb -fno-omit-frame-pointer -fno-optimize-sibling-calls)
    message(STATUS "Toolchain: Build with ASAN TEST Configure")
elseif (${CMAKE_BUILD_TYPE} STREQUAL "Release")
    message(STATUS "CMAKE_BUILD_TYPE is Release")
    set(CMAKE_BUILD_TYPE Release)
    set(CMAKE_CXX_FLAGS_RELEASE "-O2 -DNDEBUG")
else ()
    message(STATUS "unknown CMAKE_BUILD_TYPE = " ${CMAKE_BUILD_TYPE})
endif ()

set(COMPONENT "GaussDB Kernel")

option(OPENGAUSS_FLAG OFF)
if (OPENGAUSS_FLAG)
    add_definitions(-DOPENGAUSS)
    message(STATUS "openGauss on")
    set(COMPONENT "openGauss")
endif (OPENGAUSS_FLAG)

EXECUTE_PROCESS(
        COMMAND bash -c "git rev-parse HEAD | cut -b 1-8"
        OUTPUT_VARIABLE COMMIT_ID
        OUTPUT_STRIP_TRAILING_WHITESPACE
)
EXECUTE_PROCESS(
        COMMAND bash -c "date \"+%Y-%m-%d %H:%M:%S\""
        OUTPUT_VARIABLE COMPILE_TIME
        OUTPUT_STRIP_TRAILING_WHITESPACE
)

# DSS_VERSION_STR can be used for api/cmd/server
# DSS_VERSION_STR like: (openGauss build ab4a14da) compiled at 2000-01-01 00:00:00 debug)
SET(DSS_VERSION_STR
        "(${COMPONENT} build ${COMMIT_ID}) compiled at ${COMPILE_TIME} ${CMAKE_BUILD_TYPE}"
)

message(STATUS "Version info: ${DSS_VERSION_STR}")

set(CMAKE_C_FLAGS "-std=c99 ${CMAKE_C_FLAGS} -D__FILE_NAME__='\"$(notdir $(subst .o,,$(abspath $@)))\"'" )
add_compile_options(-fPIC -Wall -MMD -fno-strict-aliasing -fsigned-char -fms-extensions -lpthread)
add_compile_definitions(_GNU_SOURCE _LARGEFILE64_SOURCE KNL_PREFIX _REENTRANT __PERF_STAT__)
add_link_options(-pie)
add_link_options(-Wl,-z,noexecstack -Wl,-z,relro -Wl,-z,now)
add_compile_options(-fvisibility=default -fstack-protector-strong --param ssp-buffer-size=4)

# 安全编译选项
set(CMAKE_SKIP_RPATH TRUE)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -ldl -pthread -Wl,-z,noexecstack -Wl,-z,relro -Wl,-z,now")
add_compile_options(-fno-common)
add_compile_options(-Wtrampolines)
add_compile_options(-freg-struct-return)
add_compile_options(-pipe)
add_compile_options(-Wl,-Bsymbolic)
add_compile_options(-rdynamic)
add_compile_options(-Wall)
add_compile_options(-Werror)

add_compile_options(-Wvla)
add_compile_options(-Wcast-align)
add_compile_options(-Wshadow)
add_compile_options(-Wundef)
add_compile_options(-Wswitch-default)
add_compile_options(-Wfloat-equal)
add_compile_options(-Wdate-time)
add_compile_options(-Wunused)
add_compile_options(-fstrong-eval-order)
add_compile_options(-Werror=frame-larger-than=1048576)
add_compile_options(-Wextra)
add_compile_options(-Wstack-usage=1048576)
add_compile_options(-Wno-sign-compare)
add_compile_options(-Wno-type-limits)
add_compile_options(-Wno-implicit-fallthrough)
add_compile_options(-Wno-unused-parameter)
add_compile_options(-Wno-missing-field-initializers)
add_compile_options(-Wno-ignored-qualifiers)
add_compile_options(-Wno-cast-function-type)
add_compile_options(-Wno-enum-conversion)

OPTION(ENABLE_GCOV "Enable gcov (debug, Linux builds only)" OFF)
message(STATUS "ENABLE_GCOV = ${ENABLE_GCOV}")
IF (ENABLE_GCOV AND NOT WIN32 AND NOT APPLE)
    message(STATUS "Enable gcov (debug, Linux builds only).")
    SET(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -fprofile-arcs -ftest-coverage")
    SET(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -fprofile-arcs -ftest-coverage")
    SET(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG} -fprofile-arcs -ftest-coverage -lgcov")
    add_definitions(-DENABLE_GCOV)
ENDIF()

OPTION(USE_ASAN "Enable ASAN (debug, Linux builds only)" OFF)
message(STATUS "USE_ASAN = ${USE_ASAN}")
IF (USE_ASAN AND NOT WIN32 AND NOT APPLE)
    message(STATUS "Enable ASAN (debug, Linux builds only).")
    SET(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -fsanitize=address -fsanitize=leak -fsanitize-recover=address,all -O0 -Wall -g -fPIC -fno-omit-frame-pointer")
    SET(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -fsanitize=address -fsanitize=leak -fsanitize-recover=address,all -O0 -Wall -g -fPIC -fno-omit-frame-pointer")
    SET(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG} -fsanitize=address -fsanitize=leak -fsanitize-recover=address,all -O0 -Wall -g -fPIC -fno-omit-frame-pointer")
ENDIF()

OPTION(ENABLE_FUZZASAN "ENABLE FUZZASAN (debug, Linux builds only)" OFF)
message(STATUS "ENABLE_FUZZASAN = ${ENABLE_FUZZASAN}")
IF (ENABLE_FUZZASAN)
    SET(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -fprofile-arcs -ftest-coverage")
    SET(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -fprofile-arcs -ftest-coverage")
    SET(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG} -fprofile-arcs -ftest-coverage -lgcov")
    set(DSS_FUZZ_LIB_PATH ${PROJECT_SOURCE_DIR}/test/fuzz_test/lib)
    message(STATUS "DSS_FUZZ_LIB_PATH = ${DSS_FUZZ_LIB_PATH}")
ENDIF()

OPTION(ENABLE_EXPORT_API "Enable hidden internal api" OFF)
message(STATUS "ENABLE_EXPORT_API = ${ENABLE_EXPORT_API}")
IF (ENABLE_EXPORT_API)
    add_compile_options(-fvisibility=hidden)
ENDIF()

OPTION(ENABLE_DEFAULT_FILE_FLAG_INNER_INITED "Enable default file flag inited" OFF)
message(STATUS "ENABLE_DEFAULT_FILE_FLAG_INNER_INITED = ${ENABLE_DEFAULT_FILE_FLAG_INNER_INITED}")
IF (ENABLE_DEFAULT_FILE_FLAG_INNER_INITED)
    add_definitions(-DDSS_DEFAULT_FILE_FLAG_INNER_INITED)
ENDIF()

OPTION(ENABLE_DSSTEST "Enable dss test" OFF)
message(STATUS "ENABLE_DSSTEST = ${ENABLE_DSSTEST}")
IF (ENABLE_DSSTEST)
    add_definitions(-DENABLE_DSSTEST)
ENDIF()

execute_process(
    COMMAND uname -m
    OUTPUT_VARIABLE OS_ARCH
    OUTPUT_STRIP_TRAILING_WHITESPACE
)
set(CMAKE_SYSTEM_PROCESSOR ${OS_ARCH})
if (OS_ARCH STREQUAL "aarch64")
    option(USE_H1620 OFF)
    if (USE_H1620)
        add_compile_options(-march=armv8-a+crc+lse)
        message(STATUS "Toolchain: Build aarch64 USE_H1620")
    else ()
        add_compile_options(-march=armv8-a+crc)
    endif (USE_H1620)

    add_compile_options(-mtune=cortex-a72 -fsigned-char -g -ggdb3 -march=armv8-a+crc -funwind-tables)
else ()
    add_compile_options(-msse4.2 )
endif ()
Add_Definitions(-DWSEC_COMPILE_CAC_OPENSSL -DWSEC_AES_GCM_SUPPORT -DWSEC_USE_OPENSSL_110)

## dss include_directories
set(DSS_COMMON_PATH ${PROJECT_SOURCE_DIR}/src/common)
set(DSS_LOG_PATH ${PROJECT_SOURCE_DIR}/src/log)
set(DSS_PARAMS_PATH ${PROJECT_SOURCE_DIR}/src/params)
set(DSS_COMMON_API_PATH ${PROJECT_SOURCE_DIR}/src/common_api)
set(DSS_CMD_PATH ${PROJECT_SOURCE_DIR}/src/cmd)
set(DSS_SER_PATH ${PROJECT_SOURCE_DIR}/src/service)
set(DSS_INTERFACE_PATH ${PROJECT_SOURCE_DIR}/src/interface)
set(DSS_CEPH_PATH ${PROJECT_SOURCE_DIR}/src/ceph)

## other dependency include
set(DSS_SECUREC_INC_PATH        "${CMAKE_CURRENT_SOURCE_DIR}/library/huawei_security/include")
set(DSS_OPENSSL_PATH            "${CMAKE_CURRENT_SOURCE_DIR}/library/openssl/include")
set(DSS_CBB_PATH                "${CMAKE_CURRENT_SOURCE_DIR}/library/cbb/include")
set(LIBAIO_INC_PATH            "${CMAKE_CURRENT_SOURCE_DIR}/library/libaio/include")
set(ZLIB_INC_PATH               "${CMAKE_CURRENT_SOURCE_DIR}/library/zlib/include")
set(LZ4_INC_PATH               "${CMAKE_CURRENT_SOURCE_DIR}/library/lz4/include")
set(JAVA_HOME               "$ENV{JAVA_HOME}/include")
set(JAVA_HOME_INCLUDE               "$ENV{JAVA_HOME}/include/linux")

## lib
set(SECUREC_LIB_PATH            "${CMAKE_CURRENT_SOURCE_DIR}/library/huawei_security/lib")
set(OPENSSL_LIB_PATH            "${CMAKE_CURRENT_SOURCE_DIR}/library/openssl/lib")
set(CBB_LIB_PATH                "${CMAKE_CURRENT_SOURCE_DIR}/library/cbb/lib")
set(LIBZ_PATH                   "${CMAKE_CURRENT_SOURCE_DIR}/library/zlib/lib")
set(LZ4_PATH                   "${CMAKE_CURRENT_SOURCE_DIR}/library/lz4/lib")

## output path
set (LIBRARY_OUTPUT_PATH        ${CMAKE_CURRENT_SOURCE_DIR}/output/lib)
set (EXECUTABLE_OUTPUT_PATH     ${CMAKE_CURRENT_SOURCE_DIR}/output/bin)

CONFIGURE_FILE(config.h.in ${DSS_COMMON_API_PATH}/config.h)
CONFIGURE_FILE(config.h.in ${DSS_SER_PATH}/config.h)
## add source
link_directories(${LIBRARY_OUTPUT_PATH} ${SECUREC_LIB_PATH} ${LIBZ_PATH} ${LZ4_PATH} ${CBB_LIB_PATH})
IF (ENABLE_FUZZASAN)
    link_directories(${DSS_FUZZ_LIB_PATH})
    set(fuzz_lib "libSecodefuzz.a")
ENDIF()

set(vpp_libsecurec "libsecurec.a")
set(3rd_libccb "libcbb.a")
set(libz "libz.a")
set(lz4 "lz4")

set(vpp_libipsi_crypto "libcrypto.a")
set(3rd_libssl "libssl.a")
link_directories(${OPENSSL_LIB_PATH})

add_subdirectory(src)
