## include
include_directories(${DSS_GLOBAL_CACHE_PATH})
include_directories(${DSS_COMMON_PATH})
include_directories(${DSS_COMMON_API_PATH})
include_directories(${DSS_INTERFACE_PATH})

option(ENABLE_FUZZASAN OFF)
if (ENABLE_FUZZASAN)
    add_compile_options(-fsanitize-coverage=trace-pc)
endif(ENABLE_FUZZASAN)

## other dependency include
include_directories(${DSS_SECUREC_INC_PATH})
include_directories(${DSS_OPENSSL_PATH})
include_directories(${LIBAIO_INC_PATH})
include_directories(${DSS_CBB_PATH})

## source

aux_source_directory(${DSS_COMMON_PATH} DSS_COMMON_SRC)
aux_source_directory(${DSS_COMMON_API_PATH} DSS_COMMON_API_SRC)
aux_source_directory(${DSS_INTERFACE_PATH} DSS_INTERFACE_SRC)

option(ENABLE_GLOBAL_CACHE OFF)
if (ENABLE_GLOBAL_CACHE)
    aux_source_directory(${DSS_GLOBAL_CACHE_PATH} GCACHE_SRC)
endif (ENABLE_GLOBAL_CACHE)

aux_source_directory(${DSS_SER_PATH} DSS_SER_SRC)

set(COMMON_ALL_SRC
        ${DSS_COMMON_SRC}
        ${DSS_COMMON_API_SRC}
        ${DSS_INTERFACE_SRC}
        ${GCACHE_SRC}
        ${DSS_SER_SRC}
        )

add_library(dssapi SHARED ${COMMON_ALL_SRC})

if (ENABLE_FUZZASAN)
    target_link_libraries(dssapi pthread dl rt -Wl,--whole-archive ${vpp_libsecurec} ${3rd_libssl} ${fuzz_lib} -Wl,-Bstatic ${3rd_libccb} -Wl,-Bdynamic ${vpp_libipsi_crypto} -Wl,--no-whole-archive)
else()
    target_link_libraries(dssapi pthread dl rt -Wl,--whole-archive ${vpp_libsecurec} ${3rd_libssl} -Wl,-Bstatic ${3rd_libccb} -Wl,-Bdynamic ${vpp_libipsi_crypto} -Wl,--no-whole-archive)
endif(ENABLE_FUZZASAN)

