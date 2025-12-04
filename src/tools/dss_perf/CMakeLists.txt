#### dss_perf ####
aux_source_directory(../dss_perf DSS_PERF_SRC)
ADD_EXECUTABLE(dss_perf ${DSS_PERF_SRC} ${_VERSION_SRC})
target_link_libraries(dss_perf PRIVATE zecommon m rt pthread dl z)