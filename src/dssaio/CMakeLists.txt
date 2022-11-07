## include
include_directories(${DSS_GLOBAL_CACHE_PATH})
include_directories(${DSS_COMMON_PATH})
include_directories(${DSS_COMMON_API_PATH})
include_directories(${DSS_INTERFACE_PATH})
include_directories(${DSS_DSSAIO_PATH})

option(ENABLE_FUZZASAN OFF)
if (ENABLE_FUZZASAN)
    add_compile_options(-fsanitize-coverage=trace-pc)
endif(ENABLE_FUZZASAN)

## other dependency include
include_directories(${DSS_SECUREC_INC_PATH})
include_directories(${DSS_OPENSSL_PATH})
include_directories(${DSS_CBB_PATH})
include_directories(${LIBAIO_INC_PATH})

## source
aux_source_directory(${DSS_COMMON_PATH} COMMON_SRC)
aux_source_directory(${DSS_COMMON_API_PATH} DSS_COMMON_API_SRC)
aux_source_directory(${DSS_INTERFACE_PATH} DSS_INTERFACE_SRC)
aux_source_directory(${DSS_DSSAIO_PATH} DSS_DSSAIO_SRC)
option(ENABLE_GLOBAL_CACHE OFF)
if (ENABLE_GLOBAL_CACHE)
    aux_source_directory(${DSS_GLOBAL_CACHE_PATH} GCACHE_SRC)
endif (ENABLE_GLOBAL_CACHE)

set(COMMON_ALL_SRC
        ${COMMON_SRC}
        ${DSS_DSSAIO_SRC}
        ${GCACHE_SRC}
        )

add_library(dssaio SHARED ${COMMON_ALL_SRC})

if (ENABLE_FUZZASAN)
    target_link_libraries(dssaio pthread dl rt -Wl,--whole-archive ${vpp_libsecurec} ${3rd_libssl} ${3rd_libccb} ${vpp_libipsi_crypto} ${fuzz_lib} -Wl,--no-whole-archive)
else()
target_link_libraries(dssaio pthread dl rt -Wl,--whole-archive ${vpp_libsecurec} ${3rd_libssl} ${3rd_libccb} ${vpp_libipsi_crypto} -Wl,--no-whole-archive)
endif(ENABLE_FUZZASAN)

