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

static void find_traverse_node(gft_node_t *node, dss_vg_info_item_t *vg_item, const char *name, const char *path_prefix)
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
        gft_node_t *sub_node = dss_get_ft_node_by_ftid(vg_item, node->items.first, CM_TRUE, CM_FALSE);

        while (sub_node) {
            find_traverse_node(sub_node, vg_item, name, path_prefix);
            sub_node = dss_get_ft_node_by_ftid(vg_item, sub_node->next, CM_TRUE, CM_FALSE);
        }
    }

    if (is_match(node->name, name)) {
        printf("%s\n", path_text.str);
    }
    if (memset_s(tmp + origin_len, DSS_MAX_PATH_BUFFER_SIZE - origin_len, 0, strlen(node->name) + 1) != EOK) {
        cm_panic(0);
    }
}

static status_t find_try_match_link(char *path, const char *name)
{
    size_t len = strlen(path);
    if (len > 0 && path[len - 1] != '/') {
        gft_node_t *node = NULL;

        dss_check_dir_output_t output_info = {&node, NULL, NULL};
        dss_check_dir(path, GFT_LINK, &output_info, CM_FALSE);
        if (node) {  // check the link name
            if (is_match(node->name, name)) {
                printf("%s\n", path);
            }
            return CM_SUCCESS;
        }
    }
    return CM_ERROR;
}

status_t find_traverse_path(dss_conn_t *conn, char *path, size_t path_size, char *name, size_t name_size)
{
    bool exist = false;
    gft_node_t *node = NULL;
    size_t len = strlen(path);

    DSS_RETURN_IF_SUCCESS(find_try_match_link(path, name));

    dss_exist_file_impl(conn, path, &exist);
    if (exist) {
        dss_check_dir_output_t output_info = {&node, NULL, NULL};
        dss_check_dir(path, GFT_FILE, &output_info, CM_TRUE);
        if (!node) {
            LOG_DEBUG_ERR("Failed to check file node\n");
            return CM_ERROR;
        }
        if (is_match(node->name, name)) {
            printf("%s\n", path);
        }
        return CM_SUCCESS;
    }

    dss_dir_t *dir = dss_open_dir_impl(conn, path, CM_TRUE);

    if (!dir) {
        LOG_DEBUG_ERR("Failed to open dir %s.\n", path);
        return CM_ERROR;
    }
    dss_check_dir_output_t output_info = {&node, NULL, NULL};
    dss_check_dir(path, GFT_PATH, &output_info, CM_TRUE);
    if (!node) {
        LOG_DEBUG_ERR("Failed to check dir node\n");
        (void)dss_close_dir_impl(conn, dir);
        return CM_ERROR;
    }

    len = strlen(path);
    while (len > 0 && path[len - 1] == '/') {
        path[len - 1] = 0;
        len--;
    }
    path[(strlen(path) - strlen(node->name)) - 1] = 0;
    find_traverse_node(node, dir->vg_item, name, path);
    (void)dss_close_dir_impl(conn, dir);
    return CM_SUCCESS;
}
