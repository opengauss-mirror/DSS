#include "dss_api_impl.h"
#include "dss_interaction.h"
#include "dsscmd.h"
#include "dsscmd_conn_opt.h"
#include "dss_cli_conn.h"

#define DSS_SUBSTR_UDS_PATH "UDS:"

typedef struct {
    dss_conn_t conn;
    bool8 is_connected;
    char server_locator[DSS_MAX_PATH_BUFFER_SIZE];
} dss_uds_conn_t;

static dss_uds_conn_t g_dss_uds_conn = {};  /* global connection for dssCmd */

/**
 * [brief] disconnect uds connection
 * @param [IN] dss_conn
 */
void dss_disconnect_ex_conn()
{
    if (g_dss_uds_conn.is_connected) {
        dss_disconnect_ex(&g_dss_uds_conn.conn);
        g_dss_uds_conn.is_connected = false;
        (void)memset_s(&g_dss_uds_conn.conn, sizeof(dss_conn_t), 0, sizeof(dss_conn_t));
    }
}

/**
 * [brief] disconnect all uds connection
 * */
void dss_conn_opt_exit()
{
    dss_disconnect_ex_conn();
}

/**
 * [brief] setup a new connection
 * @param [IN] server_locator
 * @param [OUT] dss_conn
 * @return
 */
static status_t dss_uds_set_up_connection(const char *server_locator, dss_uds_conn_t *dss_conn)
{
    if (strlen(server_locator) <= strlen(DSS_SUBSTR_UDS_PATH)) {
        LOG_DEBUG_ERR("Error server locator format of UDS\n");
        return CM_ERROR;
    }
    const char *server_path = (const char *)(server_locator + strlen(DSS_SUBSTR_UDS_PATH));
    if (server_path[0] == '~') {
        const char *sys_home_path = getenv(SYS_HOME);
        char abs_server_path[DSS_MAX_PATH_BUFFER_SIZE];
        const size_t PATH_SIZE = DSS_MAX_PATH_BUFFER_SIZE;
        int32 ret = snprintf_s(abs_server_path, PATH_SIZE, PATH_SIZE - 1, "UDS:%s%s", sys_home_path, server_path + 1);
        if (ret < 0) {
            LOG_RUN_ERR("Failed(%d) to snprintf_s when convert relative path to absolute", ret);
            return CM_ERROR;
        }
        status_t status = dss_connect_ex((const char *)abs_server_path, NULL, &dss_conn->conn);
        if (status != CM_SUCCESS) {
            LOG_DEBUG_ERR("Failed to set up connect(url:%s)\n", abs_server_path);
            return status;
        }
    } else {
        status_t status = dss_connect_ex(server_locator, NULL, &dss_conn->conn);
        if (status != CM_SUCCESS) {
            LOG_DEBUG_ERR("Failed to set up connect(url:%s)\n", server_locator);
            return status;
        }
    }
    dss_conn->is_connected = true;
    return CM_SUCCESS;
}

/**
 * [brief] first setup a connection or use the exist connection
 * @param [IN] input_args
 * @return [OUT] uds connection
 */
dss_conn_t *dss_get_connection_opt(const char *input_args)
{
    if (g_dss_uds_conn.is_connected && input_args != NULL) {
        (void)printf("You are about to changing connection, the operation is not allowed!(%s)\n", input_args);
        return NULL;
    }
    /* use the connected conn if */
    if (g_dss_uds_conn.is_connected) {
        return &g_dss_uds_conn.conn;
    }
    status_t status = get_server_locator(input_args, g_dss_uds_conn.server_locator);
    if (status != CM_SUCCESS) {
        DSS_PRINT_ERROR("Failed(%d) to get server_locator(%s).\n", status, g_dss_uds_conn.server_locator);
        return NULL;
    }
    status = dss_uds_set_up_connection(g_dss_uds_conn.server_locator, &g_dss_uds_conn);
    if (status != CM_SUCCESS) {
        return NULL;
    }
    return &g_dss_uds_conn.conn;
}

bool8 dss_get_connection_opt_status()
{
    return g_dss_uds_conn.is_connected;
}