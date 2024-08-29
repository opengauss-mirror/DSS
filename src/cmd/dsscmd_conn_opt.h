#ifndef DSS_CMD_CONN_OPT
#define DSS_CMD_CONN_OPT

/* get opt connection */
dss_conn_t* dss_get_connection_opt(const char *input_args);

/* get opt connection status */
bool8 dss_get_connection_opt_status();

/* disconnection opt connection */
void dss_conn_opt_exit();

#endif
