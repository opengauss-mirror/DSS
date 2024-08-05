set(DSS_HOTPATCH_PATH ${PROJECT_SOURCE_DIR}/src/hotpatch)
set(HOTPATCH_LDS "")
set(HOTPATCH_DEPENDENCY_LIB "")
set(HOT_PATCH_SRC
    ${DSS_HOTPATCH_PATH}/dss_hp_defs.c
    ${DSS_HOTPATCH_PATH}/dss_hp_interface_stub.c)

add_compile_options(-pipe)