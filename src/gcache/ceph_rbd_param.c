
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
 * ceph_rbd_param.c
 *
 *
 * IDENTIFICATION
 *    src/gcache/ceph_rbd_param.c
 *
 * -------------------------------------------------------------------------
 */

#include "dss_errno.h"
#include "dss_file.h"
#include "dss_param.h"
#include "ceph_rbd_param.h"

#ifdef __cplusplus
extern "C" {
#endif

static status_t dss_set_rbd_values(char *entry_path, rbd_config_params_t *rbd_config_s, int type, text_t value)
{
    int errcode;
    for (int i = 0; i < rbd_config_s->num; i++) {
        if (strcmp(rbd_config_s->rbd_config[i].entry_path, entry_path) == 0) {
            switch (type) {
                case RBD_CONFIG_TYPE_POOL:
                    errcode = sprintf_s(rbd_config_s->rbd_config[i].pool_name, DSS_MAX_NAME_LEN, "%s", value.str);
                    DSS_SECUREC_SS_RETURN_IF_ERROR(errcode, CM_ERROR);
                case RBD_CONFIG_TYPE_IMAGE:
                    errcode = sprintf_s(rbd_config_s->rbd_config[i].image_name, DSS_MAX_NAME_LEN, "%s", value.str);
                    DSS_SECUREC_SS_RETURN_IF_ERROR(errcode, CM_ERROR);
                default:
                    break;
            }
        }
    }
    return CM_SUCCESS;
}

static status_t dss_parse_rbd_config(char *buf, rbd_config_params_t *rbd_config_s, int type)
{
    text_t text, name, value;
    char sep[] = ":";
    char *token = NULL;
    char *saved = NULL;
    char key[DSS_MAX_NAME_LEN];
    int errcode;

    token = strtok_r(buf, sep, &saved);
    uint16_t i = 0;
    while (token != NULL) {
        text.len = (uint16_t)strlen(token);
        text.str = token;
        cm_trim_text(&text);
        cm_split_text(&text, '=', '\0', &name, &value);
        cm_trim_text(&name);
        errcode = strncpy_s(key, DSS_MAX_NAME_LEN, name.str, name.len);
        DSS_SECUREC_SS_RETURN_IF_ERROR(errcode, CM_ERROR);
        cm_trim_text(&value);

        if (type == RBD_CONFIG_TYPE_VG) {
            errcode = sprintf_s(rbd_config_s->rbd_config[i].entry_path, DSS_MAX_NAME_LEN, "%s", key);
            DSS_SECUREC_SS_RETURN_IF_ERROR(errcode, CM_ERROR);
            if (cm_str2uint16(value.str, &(rbd_config_s->rbd_config[i].vg_type)) != CM_SUCCESS) {
                DSS_THROW_ERROR(ERR_DSS_INVALID_PARAM, "VOLUME_TYPES");
                return CM_ERROR;
            }
            i += 1;
            rbd_config_s->num = i;
        } else {
            if (dss_set_rbd_values(key, rbd_config_s, type, value) == CM_ERROR) {
                return CM_ERROR;
            }
        }
        token = strtok_r(NULL, sep, &saved);
    }

    return CM_SUCCESS;
}

status_t dss_load_cephrbd_params(dss_config_t *inst_cfg)
{
    char *value_type = cm_get_config_value(&inst_cfg->config, "VOLUME_TYPES");
    char *value_pool = cm_get_config_value(&inst_cfg->config, "POOL_NAMES");
    char *value_image = cm_get_config_value(&inst_cfg->config, "IMAGE_NAMES");

    if (dss_parse_rbd_config(value_type, &inst_cfg->params.rbd_config_params, RBD_CONFIG_TYPE_VG) != CM_SUCCESS) {
        DSS_THROW_ERROR(ERR_DSS_INVALID_PARAM, "failed to load params, invalid ceph volume types.");
        return CM_ERROR;
    }
    if (dss_parse_rbd_config(value_pool, &inst_cfg->params.rbd_config_params, RBD_CONFIG_TYPE_POOL) != CM_SUCCESS) {
        DSS_THROW_ERROR(ERR_DSS_INVALID_PARAM, "failed to load params, invalid ceph pool names.");
        return CM_ERROR;
    }
    if (dss_parse_rbd_config(value_image, &inst_cfg->params.rbd_config_params, RBD_CONFIG_TYPE_IMAGE) != CM_SUCCESS) {
        DSS_THROW_ERROR(ERR_DSS_INVALID_PARAM, "failed to load params, invalid ceph image names.");
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

status_t dss_load_cephrbd_config_file(dss_config_t *inst_cfg)
{
    status_t ret;
    char *value = cm_get_config_value(&inst_cfg->config, "CEPH_CONFIG");
    ret = snprintf_s(inst_cfg->params.ceph_config, DSS_MAX_NAME_LEN, DSS_MAX_NAME_LEN - 1, "%s", value);
    if (ret == -1) {
        DSS_THROW_ERROR(ERR_DSS_INVALID_PARAM, "failed to load params, invalid ceph config file.");
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

rbd_config_param *ceph_parse_rbd_configs(const char *name)
{
    for (uint16_t i = 0; i < DSS_MAX_VOLUME_GROUP_NUM; i++) {
        if (strcmp(name, g_inst_cfg->params.rbd_config_params.rbd_config[i].entry_path) == 0) {
            return &g_inst_cfg->params.rbd_config_params.rbd_config[i];
        }
    }
    return NULL;
}

#ifdef __cplusplus
}
#endif
