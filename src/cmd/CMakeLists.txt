## include
include_directories(${DSS_CEPH_PATH})
include_directories(${DSS_COMMON_PATH})
include_directories(${DSS_LOG_PATH})
include_directories(${DSS_PARAMS_PATH})
include_directories(${DSS_COMMON_API_PATH})
include_directories(${DSS_INTERFACE_PATH})

option(ENABLE_FUZZASAN OFF)
if (ENABLE_FUZZASAN)
    add_compile_options(-fsanitize-coverage=trace-pc)
endif (ENABLE_FUZZASAN)

## other dependency include 
include_directories(${DSS_SECUREC_INC_PATH})
include_directories(${DSS_OPENSSL_PATH})
include_directories(${DSS_CBB_PATH})

aux_source_directory(${DSS_COMMON_PATH} COMMON_SRC)
aux_source_directory(${DSS_LOG_PATH} LOG_SRC)
aux_source_directory(${DSS_PARAMS_PATH} PARAMS_SRC)
aux_source_directory(${DSS_COMMON_API_PATH} COMMON_API_SRC)
aux_source_directory(${DSS_CMD_PATH} CMD_SRC)
aux_source_directory(${DSS_CEPH_PATH} CEPH_SRC)

link_directories(${LIBRARY_OUTPUT_PATH} ${CBB_LIB_PATH})

set(COMMON_ALL_SRC
        ${COMMON_SRC}
        ${LOG_SRC}
        ${PARAMS_SRC}
        ${COMMON_API_SRC}
        ${CMD_SRC}
        ${CEPH_SRC}
        )

ADD_EXECUTABLE(dsscmd ${COMMON_ALL_SRC})

if (ENABLE_FUZZASAN)
    target_link_libraries(dsscmd dssapi pthread dl rt -Wl,--whole-archive ${vpp_libsecurec} ${libz} ${lz4} ${3rd_libssl} ${3rd_libccb} ${vpp_libipsi_crypto} ${fuzz_lib} -Wl,--no-whole-archive)
else()
    target_link_libraries(dsscmd dssapi pthread dl rt -Wl,--whole-archive ${vpp_libsecurec} ${libz} ${lz4} ${3rd_libssl} ${3rd_libccb} ${vpp_libipsi_crypto} -Wl,--no-whole-archive)
endif(ENABLE_FUZZASAN)

if (ENABLE_DSSTEST)
    add_library(dsscmd_test SHARED ${COMMON_ALL_SRC})
    if (ENABLE_FUZZASAN)
        target_link_libraries(dsscmd_test dssapi pthread dl rt -Wl,--whole-archive ${vpp_libsecurec} ${libz} ${lz4} ${3rd_libssl} ${3rd_libccb} ${vpp_libipsi_crypto} ${fuzz_lib} -Wl,--no-whole-archive)
    else()
        target_link_libraries(dsscmd_test dssapi pthread dl rt -Wl,--whole-archive ${vpp_libsecurec} ${libz} ${lz4} ${3rd_libssl} ${3rd_libccb} ${vpp_libipsi_crypto} -Wl,--no-whole-archive)
    endif(ENABLE_FUZZASAN)
endif(ENABLE_DSSTEST)

