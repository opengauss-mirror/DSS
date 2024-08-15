/*
 * Copyright (c) 2022 Huawei Technologies Co.,Ltd.
 *
 * DSS is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *
 *          http://license.coscl.org.cn/MulanPSL2
 *
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 * -------------------------------------------------------------------------
 *
 * dsscmd_find.c
 *
 *
 * IDENTIFICATION
 *    src/cmd/dsscmd_find.c
 *
 * -------------------------------------------------------------------------
 */

#ifndef WIN32
#include <fnmatch.h>
#endif

#include "dss_api_impl.h"
#include "dss_file.h"
#include "dss_malloc.h"

static inline bool is_match(const char *name, const char *pattern)
{
#ifndef WIN32
    return fnmatch(pattern, name, 0) == 0;
#else
    return strcmp(pattern, name) == 0;
#endif
}

static void find_traverse_node(
    dss_conn_t *conn, gft_node_t *node, dss_vg_info_item_t *vg_item, const char *name, const char *path_prefix)
{
    size_t origin_len = strlen(path_prefix);
    char *tmp = (char *)path_prefix;
    tmp[origin_len] = '/';
    tmp[origin_len + 1] = 0;
    text_t path_text, name_text;
    cm_str2text(tmp, &path_text);
    cm_str2text(node->name, &name_text);
    cm_concat_text(&path_text, DSS_MAX_PATH_BUFFER_SIZE, &name_text);

    if (node->type == GFT_PATH) {
        gft_node_t *sub_node = dss_get_ft_node_by_ftid(conn->session, vg_item, node->items.first, CM_TRUE, CM_FALSE);

        while (sub_node) {
            find_traverse_node(conn, sub_node, vg_item, name, path_prefix);
            sub_node = dss_get_ft_node_by_ftid(conn->session, vg_item, sub_node->next, CM_TRUE, CM_FALSE);
        }
    }

    if (is_match(node->name, name) && !(node->flags & DSS_FT_NODE_FLAG_DEL)) {
        (void)printf("%s\n", path_text.str);
    }
    if (memset_s(tmp + origin_len, DSS_MAX_PATH_BUFFER_SIZE - origin_len, 0, strlen(node->name) + 1) != EOK) {
        cm_panic(0);
    }
}

static status_t find_try_match_link(dss_conn_t *conn, char *path, const char *name)
{
    if (dss_is_valid_link_path(path)) {
        gft_node_t *node = NULL;
        dss_check_dir_output_t output_info = {&node, NULL, NULL, CM_FALSE};
        DSS_RETURN_IF_ERROR(dss_check_dir(conn->session, path, GFT_LINK, &output_info, CM_FALSE));
        if (node != NULL) {  // check the link name
            if (is_match(node->name, name)) {
                (void)printf("%s\n", path);
            }
            return CM_SUCCESS;
        }
    }
    LOG_DEBUG_INF("Failed to try match path %s with the link type", path);
    return CM_ERROR;
}

status_t find_traverse_path(dss_conn_t *conn, char *path, size_t path_size, char *name, size_t name_size)
{
    bool32 exist = false;
    gft_item_type_t type;
    gft_node_t *node = NULL;
    dss_vg_info_item_t *vg_item = NULL;
    dss_check_dir_output_t output_info = {&node, NULL, NULL, CM_FALSE};
    char vg_name[DSS_MAX_NAME_LEN] = {0};
    size_t len = strlen(path);
    status_t status = CM_ERROR;

    DSS_RETURN_IF_ERROR(dss_find_vg_by_dir(path, vg_name, &vg_item));
    DSS_RETURN_IF_ERROR(dss_exist_impl(conn, path, &exist, &type));
    if (!exist) {
        DSS_PRINT_ERROR("The path %s is not exist.\n", path);
        return CM_ERROR;
    }
    if (type == GFT_FILE) {
        DSS_LOCK_VG_META_S_RETURN_ERROR(vg_item, conn->session);
        status = dss_check_dir(conn->session, path, GFT_FILE, &output_info, CM_FALSE);
        if (status == CM_SUCCESS && node != NULL) {
            if (is_match(node->name, name)) {
                (void)printf("%s\n", path);
            }
            DSS_UNLOCK_VG_META_S(vg_item, conn->session);
            return CM_SUCCESS;
        }
        DSS_UNLOCK_VG_META_S(vg_item, conn->session);
    } else if (type == GFT_LINK || type == GFT_LINK_TO_FILE || type == GFT_LINK_TO_PATH) {
        DSS_LOCK_VG_META_S_RETURN_ERROR(vg_item, conn->session);
        status = find_try_match_link(conn, path, name);
        DSS_UNLOCK_VG_META_S(vg_item, conn->session);
        if (status == CM_SUCCESS) {
            return status;
        }
    }
    dss_dir_t *dir = dss_open_dir_impl(conn, path, CM_TRUE);
    if (dir == NULL) {
        LOG_DEBUG_ERR("Failed to open dir %s.\n", path);
        return CM_ERROR;
    }

    if (SECUREC_UNLIKELY(dss_lock_vg_s(dir->vg_item, conn->session) != CM_SUCCESS)) {
        (void)dss_close_dir_impl(conn, dir);
        return CM_ERROR;
    }
    node = dss_get_ft_node_by_ftid(conn->session, dir->vg_item, dir->pftid, CM_FALSE, CM_FALSE);
    if (node == NULL) {
        DSS_THROW_ERROR(ERR_DSS_INVALID_ID, "dir ftid", *(uint64 *)&dir->pftid);
        DSS_PRINT_ERROR("Failed to get ft node %s.\n", path);
        DSS_UNLOCK_VG_META_S(dir->vg_item, conn->session);
        (void)dss_close_dir_impl(conn, dir);
        return CM_ERROR;
    }

    len = strlen(path);
    while (len > 0 && path[len - 1] == '/') {
        path[len - 1] = 0;
        len--;
    }
    path[(strlen(path) - strlen(node->name)) - 1] = 0;
    find_traverse_node(conn, node, dir->vg_item, name, path);
    DSS_UNLOCK_VG_META_S(dir->vg_item, conn->session);
    (void)dss_close_dir_impl(conn, dir);
    return CM_SUCCESS;
}
