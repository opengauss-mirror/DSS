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
 * dsscmd_du.c
 *
 *
 * IDENTIFICATION
 *    src/cmd/dsscmd_du.c
 *
 * -------------------------------------------------------------------------
 */

#include "dss_api_impl.h"
#include "dss_file.h"
#include "dss_cli_conn.h"

#define DSS_ARG_IDX_0 0
#define DSS_ARG_IDX_1 1
#define DSS_ARG_IDX_2 2

#define DSS_DU_SIZE_BUF_LEN 20

double dss_convert_size(double size, const char *measure);

status_t du_get_params(const char *input, char *params, size_t params_size)
{
    if (input == NULL || input[0] == 0x00) {
        params[DSS_ARG_IDX_0] = 'B';
        params[DSS_ARG_IDX_1] = 's';
        return CM_SUCCESS;
    }
    for (uint32 i = 0; i < strlen(input); i++) {
        char c = input[i];
        if (c == 'B' || c == 'K' || c == 'M' || c == 'G' || c == 'T') {
            params[DSS_ARG_IDX_0] = c;
        } else if (c == 's' || c == 'a') {
            params[DSS_ARG_IDX_1] = c;
        } else if (c == 'S') {
            params[DSS_ARG_IDX_2] = (char)true;
        } else {
            DSS_PRINT_ERROR("wrong params %c.\n", c);
            return CM_ERROR;
        }
    }
    return CM_SUCCESS;
}

static void du_print(double size, const char *params, const char *path)
{
    char buf[DSS_DU_SIZE_BUF_LEN] = {0};
    size_t buf_size = sizeof(buf);
    char *fmt = "%0.0lf%c";
    if (params[DSS_ARG_IDX_0] == 'T' || params[DSS_ARG_IDX_0] == 'G') {
        fmt = "%0.5lf%c";
    }
    if (sprintf_s(buf, buf_size, fmt, dss_convert_size(size, params), params[DSS_ARG_IDX_0]) == -1) {
        cm_panic(0);
    }
    size_t buf_len = strlen(buf);
    if (memset_s(buf + buf_len, buf_size - buf_len, ' ', buf_size - buf_len) != EOK) {
        cm_panic(0);
    }
    buf[buf_size - 1] = 0;
    (void)printf("%s%s\n", buf, path);
}

static double du_traverse_node(
    dss_conn_t *conn, gft_node_t *node, dss_vg_info_item_t *vg_item, const char *params, char *path_prefix)
{
    char granularity = params[DSS_ARG_IDX_1];
    bool separate = (bool)params[DSS_ARG_IDX_2];
    double total_size = 0;

    size_t origin_len = strlen(path_prefix);
    path_prefix[origin_len] = '/';
    path_prefix[origin_len + 1] = 0;
    text_t path_text, name_text;
    cm_str2text(path_prefix, &path_text);
    cm_str2text(node->name, &name_text);
    cm_concat_text(&path_text, DSS_MAX_PATH_BUFFER_SIZE, &name_text);

    if (node->type == GFT_PATH) {
        gft_node_t *sub_node = dss_get_ft_node_by_ftid(conn->session, vg_item, node->items.first, CM_TRUE, CM_FALSE);

        while (sub_node) {
            if (sub_node->type != GFT_PATH || (sub_node->type == GFT_PATH && !separate)) {
                double size = du_traverse_node(conn, sub_node, vg_item, params, path_prefix);
                total_size += size;
            } else if (sub_node->type == GFT_PATH) {
                du_traverse_node(conn, sub_node, vg_item, params, path_prefix);
            }
            sub_node = dss_get_ft_node_by_ftid(conn->session, vg_item, sub_node->next, CM_TRUE, CM_FALSE);
        }
        if (granularity != 's') {
            du_print(total_size, params, path_prefix + 1);
        }
    } else {
        if (granularity == 'a') {
            du_print(node->size, params, path_prefix + 1);
        }
        total_size = node->size;
    }
    errno_t errcode =
        memset_s(path_prefix + origin_len, DSS_MAX_PATH_BUFFER_SIZE - origin_len, 0, strlen(node->name) + 1);
    securec_check_ret(errcode);
    return total_size;
}

static status_t du_try_print_link(dss_conn_t *conn, char *path, const char *params)
{
    if (dss_is_valid_link_path(path)) {
        gft_node_t *node = NULL;
        dss_check_dir_output_t output_info = {&node, NULL, NULL, CM_FALSE};
        DSS_RETURN_IF_ERROR(dss_check_dir(conn->session, path, GFT_LINK, &output_info, CM_FALSE));
        if (node != NULL) {  // print the link du
            du_print(node->size, params, path + 1);
            return CM_SUCCESS;
        }
    }
    LOG_DEBUG_INF("Failed to try print path %s with the link type", path);
    return CM_ERROR;
}

status_t du_traverse_path(char *path, size_t path_size, dss_conn_t *conn, const char *params, size_t params_size)
{
    bool32 exist = false;
    gft_item_type_t type;
    gft_node_t *node = NULL;
    dss_vg_info_item_t *vg_item = NULL;
    dss_check_dir_output_t output_info = {&node, NULL, NULL, CM_FALSE};
    char name[DSS_MAX_NAME_LEN] = {0};
    size_t len = strlen(path);
    status_t status = CM_ERROR;

    DSS_RETURN_IF_ERROR(dss_find_vg_by_dir(path, name, &vg_item));
    DSS_RETURN_IF_ERROR(dss_exist_impl(conn, path, &exist, &type));
    if (!exist) {
        DSS_PRINT_ERROR("The path %s is not exist.\n", path);
        return CM_ERROR;
    }
    if (type == GFT_FILE) {
        DSS_LOCK_VG_META_S_RETURN_ERROR(vg_item, conn->session);
        status = dss_check_dir(conn->session, path, GFT_FILE, &output_info, CM_FALSE);
        if (status == CM_SUCCESS && node != NULL) {
            du_print(node->size, params, path + 1);
            DSS_UNLOCK_VG_META_S(vg_item, conn->session);
            DSS_PRINT_INF("Succeed to du file info.\n");
            return CM_SUCCESS;
        }
        DSS_UNLOCK_VG_META_S(vg_item, conn->session);
    } else if (type == GFT_LINK || type == GFT_LINK_TO_FILE || type == GFT_LINK_TO_PATH) {
        DSS_LOCK_VG_META_S_RETURN_ERROR(vg_item, conn->session);
        status = du_try_print_link(conn, path, params);
        DSS_UNLOCK_VG_META_S(vg_item, conn->session);
        if (status == CM_SUCCESS) {
            return status;
        }
    }
    dss_dir_t *dir = dss_open_dir_impl(conn, path, CM_TRUE);
    if (dir == NULL) {
        DSS_PRINT_ERROR("Failed to open dir %s.\n", path);
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
    path[(len - strlen(node->name)) - 1] = 0;

    double total_size = du_traverse_node(conn, node, dir->vg_item, params, path);
    char granularity = params[DSS_ARG_IDX_1];

    path[strlen(path)] = '/';
    text_t path_text, name_text;
    cm_str2text(path, &path_text);
    cm_str2text(node->name, &name_text);
    cm_concat_text(&path_text, (uint32)path_size, &name_text);

    if (granularity == 's') {
        du_print(total_size, params, path);
    }
    DSS_UNLOCK_VG_META_S(dir->vg_item, conn->session);
    (void)dss_close_dir_impl(conn, dir);
    return CM_SUCCESS;
}
