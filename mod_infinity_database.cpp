// include main
#include "mod_infinity.h"
// mod_infinity namespace
namespace modinfinity
{
	// declare included namespaces
	using namespace std;
	// error string definitions
	const char *odb_error_strings[] = 
	{
		"System could not connect to the TCPDB Server.",
		"System could not allocate a handle to the TCPDB Server.",
		"System could not use winsock to connect to the TCPDB Server.",
		"System could not login to TCPDB database.",
		"System could not retrieve data on TCPDB database connection.",
		"System received an invalid response from the system firewall procedure.",
		"TCPDB SQL String is invalid."
	};
	// error severity levels
	int odb_severity_levels[] = 
	{ 
		APLOG_CRIT, APLOG_CRIT, APLOG_CRIT, 
		APLOG_WARNING, APLOG_CRIT, APLOG_CRIT, 
		APLOG_WARNING
	};
	// define tcpdb constructor
	tcpdb::tcpdb (request_rec *r, server_rec *s) : zErrMsg(0), dbglvl(APLOG_TRACE6), retcode(0),
		nrows(0), ncols(0), apache(0), server(0), config(0), request(0), local(0) { 
		// retrieve request or server records
		if (!(r == NULL) || !(s == NULL)) {
			// set config with r if not null
			if (!(r == NULL)) {
				// fill in as much as possible
				apache = r;
				// server
				server = r->server;
				// attempt to get the main configuration
				config = (infx_config *)ap_get_module_config(server->module_config, &infinity_security_module);
				// try to get the request tx
				request = (infx_tx_rec *)ap_get_module_config(r->request_config, &infinity_security_module);
				// check the request config
				if (request == NULL) { 
					local = r->pool; 
				} else {
					// fill with latest request record
					apache = request->r;
					// set local
					local  = request->mp;
				}
			} else if (!(s == NULL)) {
				// server
				server = s;
				// attempt to get the main configuration
				config = (infx_config *)ap_get_module_config(server->module_config, &infinity_security_module);
				// set local
				local = config->mp;
			}
		} else { 
			retcode = -1; 
		}
		// exit
		return;
	};
	// sysfirewall
	bool tcpdb::sysFWall(infx_tx_rec *&aReq) {
		// variables
		bool		retval = false;
		int			i = 0, cols = 0, dbl = -1;
		char		*sql;
		odbHANDLE	hCon = NULL, hQry = NULL;
		apr_table_t *client = apr_table_make(local, 0);
		// open logging connector
		logging logger(apache);
		// break point
		stdLog(logger, INFX_LOG_DATA, dbl);
		// build sql string
		sql = apr_psprintf
		(
			aReq->mp,
			"execute infinity.dbo._sys_firewall '%s','%s','%s','%s','%s','%s','%s','%d','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s'",
			aReq->i_request_uri, aReq->d_path_app, aReq->d_path_fun, aReq->d_path_var, aReq->i_query_string,
			aReq->i_request_host, aReq->i_request_ip, aReq->i_request_port, aReq->d_mode_class,
			aReq->o_infinity_unique, aReq->i_cookie_unique, aReq->i_cookie_session, aReq->i_cookie_authtoken,
			apache->connection->client_ip, aReq->i_remote_ip, aReq->i_remote_proxies, aReq->i_remote_useragent, 
			aReq->i_remote_referer, aReq->i_request_method, aReq->i_request_protocol
		);
		// break point
		stdLog(logger, INFX_LOG_DATA, APLOG_TRACE6, sql);
		// connect to database if none
		if (tcpdbLoadConn(hCon)) {
			// break point
			stdLog(logger, INFX_LOG_DATA, dbl);
			// attempt to allocate
			if ((hQry = odbAllocate(hCon))) {
				// break point
				stdLog(logger, INFX_LOG_DATA, dbl);
				// set timeouts read, send
				odbSetReadTimeout(hQry, 2);
				odbSetSendTimeout(hQry, 2);
				// set convert all to character data
				odbConvertAll(hCon, 1);
				// break point
				stdLog(logger, INFX_LOG_DATA, dbl); 
				// attempt to execute
				if (odbExecute(hQry, sql)) {
					// break point
					stdLog(logger, INFX_LOG_DATA, dbl);
					// get results
					if (!odbNoData(hQry) && odbFetchRow(hQry)) { 
						// break point
						stdLog(logger, INFX_LOG_DATA, dbl); 
						// push data into client cache
						for (i = 1, cols = odbGetTotalCols(hQry); i < (cols + 1); i++)
							apr_table_add(client, odbColName(hQry, i), strNotNull(odbColDataText(hQry, i)));
						// break point
						stdLog(logger, INFX_LOG_DATA, dbl);
						// assign data to return inside request object
						aReq->o_exit_http			= tabNotNull(client, "httpNUM");
						aReq->o_exit_code			= tabNotNull(client, "errNUM");
						aReq->o_infinity_session	= tabNotNull(client, "R_INF_skey");
						aReq->o_infinity_hash		= tabNotNull(client, "R_INF_hkey");
						// assign data directly to the sub process
						apr_table_set(apache->subprocess_env, "httpNUM", tabNotNull(client, "httpNUM")); 
						apr_table_set(apache->subprocess_env, "errNUM", tabNotNull(client, "errNUM")); 
						apr_table_set(apache->subprocess_env, "errMSG", tabNotNull(client, "errMSG"));
						apr_table_set(apache->subprocess_env, "errINT", tabNotNull(client, "errINT"));
						apr_table_set(apache->subprocess_env, "R_INF_skey", tabNotNull(client, "R_INF_skey"));
						apr_table_set(apache->subprocess_env, "R_INF_hkey", tabNotNull(client, "R_INF_hkey"));
						apr_table_set(apache->subprocess_env, "R_INF_loggedin", tabNotNull(client, "R_INF_loggedin"));
						apr_table_set(apache->subprocess_env, "R_INF_loginuser", tabNotNull(client, "R_INF_loginuser"));
						apr_table_set(apache->subprocess_env, "R_INF_pageauth", tabNotNull(client, "R_INF_pageauth"));
						apr_table_set(apache->subprocess_env, "R_INF_pagesrch", tabNotNull(client, "R_INF_pagesrch"));
						apr_table_set(apache->subprocess_env, "R_INF_srchenge", tabNotNull(client, "R_INF_srchenge"));
						// break point
						stdLog(logger, INFX_LOG_DATA, dbl);
						// clear client table
						apr_table_clear(client);
						// free query
						odbFree(hQry);
						// free connection
						tcpdbFreeConn(hCon);
						// return
						return true;
					} else { 
						return errLog(odb_fw_failed, logger, INFX_LOG_DATA, true, hCon, true); 
					}
				} else {
					return errLog(odb_conn_invalid, logger, INFX_LOG_DATA, true, hCon, true); 
				}
			} else { 
				return errLog(odb_setup, logger, INFX_LOG_DATA, true, hCon, true); 
			}
		} else { 
			return errLog(odb_open, logger, INFX_LOG_DATA, true, hCon, true); 
		}
		// break point
		stdLog(logger, INFX_LOG_DATA, dbl);
		// return
		return retval;
	};
	// free all procedure
	void tcpdb::tcpdbFreeAll()
	{
		// reset retcode, identity, affected
		retcode = 0; 
		nrows	= 0; 
		ncols	= 0;
		// zero errMsgs
		zErrMsg = "";
		// zero any results
		if (!vcol_head.empty() && vcol_head.size() > 0) { vcol_head.clear(); }
		if (!vcol_data.empty() && vcol_data.size() > 0) { vcol_data.clear(); }
		// return
		return;
	};
	// load odbtp connection
	bool tcpdb::tcpdbLoadConn(odbHANDLE &conn, const char *rlink, const char *ruser, const char *rpass, const char *rfile, const char *rserv, const char *rtype) {
		/*
			procedure can use interface or normal login, need to make this so that if it dies, it wont take down the server
		*/
		// variables
		bool		retval = false;
		const char	*c = "DRIVER={SQL SERVER};SERVER=%s;UID=%s;PWD=%s;DATABASE=%s;";
		const char	*link, *host, *file, *user, *pass;
		// open logging connector
		logging logger(apache);
		// break point
		stdLog(logger, INFX_LOG_DATA, -1);
		// set variables
		link = coalesce(nullif(rlink, ""), coalesce(config->dblink, "127.0.0.1")); //odb.brownstone-ind.info
		host = coalesce(nullif(rserv, ""), coalesce(config->dbserv, "127.0.0.1"));
		file = coalesce(nullif(rfile, ""), coalesce(config->dbfile, "infinity")); 
		user = coalesce(nullif(ruser, ""), coalesce(config->dbuser, "modinfinity"));
		pass = coalesce(nullif(rpass, ""), coalesce(config->dbpass, "v!shNu10451"));
		// set the connect string
		c = apr_psprintf(local, c, host, user, pass, file);
		// break point
		stdLog(logger, INFX_LOG_DATA, -1);
		// connect using startup
		if (odbWinsockStartup()) {
			// break point
			stdLog(logger, INFX_LOG_DATA, -1);
			// allocate
			if ((conn = odbAllocate(NULL))) {
				// break point
				stdLog(logger, INFX_LOG_DATA, -1);
				// set timeout
				odbSetConnectTimeout(conn, 2);
				// break point
				stdLog(logger, INFX_LOG_DATA, -1);	
				// attempt to login
				if (!odbLogin(conn, link, 2799, ODB_LOGIN_NORMAL, c)) 
					return errLog(odb_login_failed, logger, INFX_LOG_DATA, true, conn);
				// break point
				stdLog(logger, INFX_LOG_DATA, -1);
				// connected
				retval = true;
			} else { 
				return errLog(odb_setup, logger, INFX_LOG_DATA, true, conn); 
			}
		} else { 
			return errLog(odb_winsock, logger, INFX_LOG_DATA, true, conn); 
		}
		// break point
		stdLog(logger, INFX_LOG_DATA, -1);
		// return retval
		return retval;
	}
	// free odbtp connection
	bool tcpdb::tcpdbFreeConn(odbHANDLE conn) {
		// open logging connector
		logging logger(apache);
		// break point
		stdLog(logger, INFX_LOG_DATA, -1);
		// logout of connection
		if (!odbLogout(conn, true)) stdLog(logger, INFX_LOG_DATA, APLOG_WARNING, "Could not logout of connection.");
		// break point
		stdLog(logger, INFX_LOG_DATA, -1);
		// dismiss connections
		if (odbIsConnected(conn)) odbFree(conn);
		// break point
		stdLog(logger, INFX_LOG_DATA, -1);
		// close winsock
		odbWinsockCleanup();
		// return
		return true;
	};	
	// load firebird connection
	bool tcpdb::tcpfbLoadConn(IBPP::Database &fdb) {
		// variables
		bool   retcode = false;
		string username = "SYSDBA";
		string password = "sh!vA2025";
		string fbdbpath = string(ap_server_root) + string("/var/infinity/Infinity Logs/InfinityLogs.fdb");
		try {
			// create a link
			fdb = IBPP::DatabaseFactory("localhost", fbdbpath, username, password);
			// connect
			fdb->Connect();
			// set return
			if (fdb->Connected()) retcode = true;
		} catch(...){};
		// return connected state
		return retcode;
	};
	// free firebird connection
	bool tcpdb::tcpfbFreeConn(IBPP::Database fdb) {
		// disconnect
		fdb->Disconnect();
		// return
		return true;
	};
	// logger default for flagging
	void tcpdb::stdLog(logging &l, const char *f, const char *fx, int ln, int lvl, const char *msg) {
		// if lvl is negative 
		if (lvl == -1) lvl = dbglvl;
		// execute logger
		l.infEchoLog(f,fx,ln,"FLAG",lvl,false,strNotNull(msg));
		// return
		return;
	};
	// logger extended return quick
	bool tcpdb::errLog(odberror e, logging &l, const char *f, const char *fx, int ln, bool isExcept, odbHANDLE hCon, bool closedb) {
		// should change this to a map? 
		// variables
		odbHANDLE	hQry = NULL;
		const char	*errMsg = "";
		// set log level
		int  lvl  = odb_severity_levels[e];
		// check if number is in range
		bool sane = isNumInRange(lvl,0,100,1);
		// check if we are handling an exception
		if (isExcept) {
			if (hCon) {
				// get the query handle if there is one
				hQry = odbGetFirstQuery(hCon);
				// check if error is from the query
				if (hQry)	errMsg = apr_pstrdup(local, odbGetErrorText(hQry));
				else		errMsg = apr_pstrdup(local, odbGetErrorText(hCon));	
				// check if we are to free this connection
				if (closedb) tcpdbFreeConn(hCon);
			}
		}
		// set output
		if (sane) { 
			zErrMsg = apr_pstrdup(local, odb_error_strings[e]); 
		} else {
			// set default error message
			zErrMsg = apr_pstrdup(local, "Uncaught Error passed. Invalid TCPDB error code.");
			// set level to critical because this is a bug
			lvl = APLOG_CRIT;
		}		
		// concat messages
		if (strlen(errMsg)) { 
			zErrMsg = apr_pstrcat(local, zErrMsg, " DB Err(s): ", errMsg, NULL); 
		}
		// set retcode
		retcode = -1;
		// check inputs for file, function, line
		if (!ln) {
			f  = __FILE__;
			fx = __FUNCTION__;
			ln = __LINE__;
		}
		// execute logger
		l.infEchoLog(f,fx,ln,"WARNING/ERROR",lvl,false,zErrMsg);
		// return false
		return false;
	};
	// logger extended flagging with messages
	void tcpdb::extLog(logging &l, const char *f, const char *fx, int ln, int lvl, const char *msg, ...) {
		// variables
		const char	*o;
		va_list		args;
		// setup the input list
		va_start(args, msg);
		// get message data
		o = apr_pvsprintf(local, strNotNull(msg), args);
		// call va end
		va_end(args);
		// if lvl is negative 
		if (lvl == -1) lvl = dbglvl;
		// execute logger
		l.infEchoLog(f,fx,ln,"FLAG",lvl,false,o);
		// return
		return;
	};
	// logger echo log with unlimited inputs
	int tcpdb::echoLog(logging &l, int c, const char *f, const char *fx, int ln, const char *a, int lvl, bool irl, const char *msg, ...) {
		// variables
		const char	*o;
		va_list		args;
		// setup the input list
		va_start(args, msg);
		// get message data
		o = apr_pvsprintf(local, strNotNull(msg), args);
		// call va end
		va_end(args);
		// execute logger
		l.infEchoLog(f,fx,ln,a,lvl,irl,o);
		// return
		return c;
	};
	// get error text
	char *tcpdb::getErrTxt() { 
		// return error string		
		return apr_pstrdup(local, strNotNull(zErrMsg));
	};
	// get error code
	int tcpdb::getErrCode() {
		// return the error code
		return retcode;
	};
	// reset dbglvl
	void tcpdb::resetDBGLvl(int newlvl) {
		// reset the debug level
		dbglvl = newlvl;
		// exit 
		return;
	};
	// execute sql against source
	bool tcpdb::dbExecute(const char *sql, const char *ruser, const char *rpass, const char *rfile, const char *rserv, const char *rtype)
	{
		// variables
		int			dbl = -1;
		bool		retval = false;
		odbHANDLE	hCon = NULL, hQry = NULL;
		apr_size_t	datalen = 0, maxlen = 512000, bytesInChar = sizeof(char);
		// open logging connector
		logging logger(apache);
		// tools
		tools txc(apache);
		// break point
		stdLog(logger, INFX_LOG_DATA, -1);
		// sanity check
		if (strlen(sql) < 3) return errLog(odb_sql_invalid, logger, INFX_LOG_DATA);
		// break point
		stdLog(logger, INFX_LOG_DATA, -1);
		// replace double quotes
		//sql = txc.getStrReplace(sql, "''", "'");
		// break point
		stdLog(logger, INFX_LOG_DATA, -1);
		// escape quotes
		//sql = ap_escape_quotes(local, sql); // need better to escape with doubling quotes
		// break point
		stdLog(logger, INFX_LOG_DATA, dbl, sql);
		// free all
		tcpdbFreeAll();
		// break point
		stdLog(logger, INFX_LOG_DATA, -1);
		// connect to database if none
		if (tcpdbLoadConn(hCon, "", ruser, rpass, rfile, rserv, rtype))
		{
			// break point
			stdLog(logger, INFX_LOG_DATA, -1); 
			// attempt to allocate
			if ((hQry = odbAllocate(hCon)))
			{
				// break point
				stdLog(logger, INFX_LOG_DATA, -1); 
				// set timeouts read, send
				odbSetReadTimeout(hQry, 6);
				odbSetSendTimeout(hQry, 6);
				// set convert all to character data
				odbConvertAll(hCon, 1);
				// break point
				stdLog(logger, INFX_LOG_DATA, -1); 
				// attempt to execute
				if (odbExecute(hQry, sql))
				{
					// break point
					stdLog(logger, INFX_LOG_DATA, -1);
					// get results
					if (!odbNoData(hQry)) 
					{ 
						// break point
						stdLog(logger, INFX_LOG_DATA, -1);						
						// set columns
						ncols = odbGetTotalCols(hQry);
						// break point
						stdLog(logger, INFX_LOG_DATA, -1);
						// retrieve array of names
						for (int y = 1; y < (ncols + 1); y++) 
							vcol_head.push_back(strNotNull(odbColName(hQry, y)));
						// break point
						stdLog(logger, INFX_LOG_DATA, -1);
						// loop over rows
						while(odbFetchRow(hQry) && !odbNoData(hQry))
						{
							// break point
							stdLog(logger, INFX_LOG_DATA, -1);		
							// variables
							vector<string>	rowData;
							char			*value;	
							apr_size_t		rowLen = 0;
							bool			abort = false;
							// break point
							stdLog(logger, INFX_LOG_DATA, -1);
							// add not null column values to rowdata
							for (int z = 1; z < (ncols + 1); z++)
							{
								// set column value
								value = strNotNull(odbColDataText(hQry, z));
								// push onto stack
								rowData.push_back(value);
								// increment all rows len
								datalen += strlen(value);
								// increment row len
								rowLen += strlen(value);
								// check the rowLen to make sure it does not exceed memory and abort if
								if ((rowLen/bytesInChar) >= (maxlen/bytesInChar))
								{
									// break point
									stdLog(logger, INFX_LOG_DATA, APLOG_WARNING, "MAX_ROW_DATA_LEN_REACHED");
									// set abort
									abort = true;
									// exit out of this loop
									break;
								}
							}
							// check if we are aborting
							if (abort) break;
							// break point
							stdLog(logger, INFX_LOG_DATA, -1);
							// push columns onto rows
							vcol_data.push_back(rowData);
							// break point
							stdLog(logger, INFX_LOG_DATA, -1);
							// increment rows
							nrows++;
							//APLOG("ALL LEN: %d, ROW LEN: %d, sizeof char: %d, ar: %d, tr: %d, wnr: %d", datalen, rowLen, bytesInChar, (datalen/bytesInChar), (rowLen/bytesInChar), ((datalen + rowLen)/bytesInChar)); 
							// check if max has been reached or would be on next run
							if ((datalen/bytesInChar) >= (maxlen/bytesInChar) || ((datalen + rowLen)/bytesInChar) >= (maxlen/bytesInChar))
							{
								// break point
								stdLog(logger, INFX_LOG_DATA, APLOG_WARNING, "MAX_ROW_DATA_LEN_REACHED");
								// exit out of this loop
								break;
							}
						}
					}
					else { stdLog(logger, INFX_LOG_DATA, -1, "NO_DATA_FOUND"); }
					// break point
					stdLog(logger, INFX_LOG_DATA, -1);
					// free query
					odbFree(hQry);
					// free connection
					tcpdbFreeConn(hCon);
					// return
					return true;
				}
				else { return errLog(odb_conn_invalid, logger, INFX_LOG_DATA, true, hCon, true); }
			} 
			else { return errLog(odb_setup, logger, INFX_LOG_DATA, true, hCon, true); }
		}
		else { return errLog(odb_open, logger, INFX_LOG_DATA, true, hCon, true); }
		// break point
		stdLog(logger, INFX_LOG_DATA, -1);
		// return
		return retval;
	};
	// fetch sql into a linked list
	bool tcpdb::dbFetch(infx_sqlset *&sql, int &count, apr_pool_t *mp)
	{
		// variables
		int	dbl = -1;
		// open logging connector
		logging logger(apache);
		// break point
		stdLog(logger, INFX_LOG_DATA, dbl);
		// reset count
		count = 0;
		// reset sql
		sql = NULL;
		// break point
		stdLog(logger, INFX_LOG_DATA, dbl);
		// check if there is any data
		if (!ncols && !nrows) return true;
		// break point
		stdLog(logger, INFX_LOG_DATA, dbl);
		// check if there really is data
		if (vcol_head.empty() || vcol_data.empty()) return false;
		// break point
		stdLog(logger, INFX_LOG_DATA, dbl);
		// build row data
		for (int r = 0; r < nrows; r++)
		{
			// break point
			stdLog(logger, INFX_LOG_DATA, dbl);
			// assign row data
			vector<string> rowData = vcol_data.at(r);
			// break point
			stdLog(logger, INFX_LOG_DATA, dbl);
			// create new table space for these fields
			apr_table_t *fields = apr_table_make(local, 0);
			// break point
			stdLog(logger, INFX_LOG_DATA, dbl);
			// iterrate over columns
			for (int h = 0; h < ncols; h++)
				apr_table_add(fields, vcol_head.at(h).c_str(), rowData.at(h).c_str());
			// break point
			stdLog(logger, INFX_LOG_DATA, dbl);
			// add to list 
			if (!r)
			{
				// break point
				stdLog(logger, INFX_LOG_DATA, dbl);
				// setup the container
				sql = (infx_sqlset *)apr_palloc(mp, sizeof(infx_sqlset));
				// break point
				stdLog(logger, INFX_LOG_DATA, dbl);
				// check if memory was assigned successfully
				if (sql == NULL) return false;
				// break point
				stdLog(logger, INFX_LOG_DATA, dbl);
				// set nodes
				sql->pos    = 1;
				sql->fields = apr_table_copy(mp, fields);
				sql->rows   = nrows;
				sql->cols   = ncols;
				sql->next	= NULL;
			}
			else
			{
				// get link to start
				infx_sqlset *nset = sql;
				// breakpoint
				stdLog(logger, INFX_LOG_DATA, dbl);
				// check if next is null
				if (!(nset == NULL))
				{
					// breakpoint
					stdLog(logger, INFX_LOG_DATA, dbl);
					// find next
					while (!(nset->next == NULL)) { nset = nset->next; }
					// break point
					stdLog(logger, INFX_LOG_DATA, dbl);
					// create memory block for pointer
					nset->next = (infx_sqlset *)apr_palloc(mp, sizeof(infx_sqlset));
					// check if memory was assigned successfully
					if (nset->next == NULL) return false;
					// break point
					stdLog(logger, INFX_LOG_DATA, dbl);
					// point to it
					nset = nset->next;
					// break point
					stdLog(logger, INFX_LOG_DATA, dbl);
					// set nodes
					nset->pos    = sql->pos = sql->pos++;
					nset->fields = apr_table_copy(mp, fields);
					nset->rows   = nrows;
					nset->cols   = ncols;
					nset->next	= NULL;
				}
				else
				{
					// break point
					stdLog(logger, INFX_LOG_DATA, dbl);
					// return
					return false;
				}
			}
			// empty table
			apr_table_clear(fields);
		}
		// set output count
		count = nrows;
		// free all
		tcpdbFreeAll();
		// return
		return true;
	};
	// echo results of sql call into buffer or directly
	bool tcpdb::echoResult(apr_pool_t *mp, char *&response, bool directly)
	{
		// variables
		bool	retval = true;
		char	*heads = apr_pstrdup(mp, ""), *rows = apr_pstrdup(mp, ""), *datao = apr_pstrdup(mp, "");
		int		dbl = APLOG_DEBUG, h = 0, r = 0;	
		// open logging connector
		logging logger(apache);
		// break point
		stdLog(logger, INFX_LOG_DATA, -1);
		// check if there are headers
		if (vcol_head.empty()) return false;
		// build table out
		// break point
		stdLog(logger, INFX_LOG_DATA, -1);
		// build heads row
		for (h = 0; h < ncols; h++) { heads = apr_pstrcat(mp, heads, apr_psprintf(mp, "\r\n\t\t\t\t\t<td>%s</td>", vcol_head.at(h).c_str()), NULL); }
		// break point
		stdLog(logger, INFX_LOG_DATA, -1);
		// build row data
		for (r = 0; r < nrows; r++)
		{
			// capture this row
			char *thisrow = apr_pstrdup(mp, "");
			// assign row data
			vector<string> rowData = vcol_data.at(r);
			// iterrate over columns
			for (h = 0; h < ncols; h++)
				thisrow = apr_pstrcat(mp, thisrow, apr_psprintf(mp, "\r\n\t\t\t\t\t<td>%s</td>", rowData.at(h).c_str()), NULL);
			// assemble row out
			rows = apr_pstrcat(mp, rows, apr_psprintf(mp, "\r\n\t\t\t<tr>%s</tr>", thisrow), NULL);
		}
		// break point
		stdLog(logger, INFX_LOG_DATA, -1);
		// assemble full table
		datao = apr_psprintf(mp, "\t\t<table>\r\n\t\t\t<th>\r\n%s\r\n\t\t\t</th>\r\n%s\r\n\t\t</table>", heads, rows);
		// check if we are echo directly
		if (directly)
		{
			// break point
			stdLog(logger, INFX_LOG_DATA, -1);
			// if direct output, then apache needs to be available
			if (!apache)
			{
				// break point
				stdLog(logger, INFX_LOG_DATA, -1);
				// still attach output
				response = datao;
				// return false that could not echo
				return false;
			}
			// format a valid html body
			datao = apr_psprintf(mp, "<html>\r\n\t<head>\r\n\t\t<title>Results Echo</title>\r\n\t</head>\r\n\t<body>%s\t</body>\r\n</html>", datao);
			// output
			ap_rputs(datao, apache);
		}
		else { response = datao; }
		// return
		return retval;
	};
	/*
	// A more secure method is to use the website name as database, single access user as user, and pem for password
	// except for the system database
	// may need to preparse queries and save them as hashes with odbtp prepare
	// would like to be able to take data from enviornment and expand
	*/
}