// include mod_infinity
#include "mod_infinity.h"
// mod_infinity namespace
namespace modinfinity
{
	// declare included namespaces
	using namespace std;
	using namespace boost;
	// security constructor definition
	security::security(request_rec *r) : dbglvl(APLOG_TRACE4), retcode(0), apache(0), server(0), config(0), request(0), local(0) {
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
			local  = apache->pool; 
		} else {
			// fill with latest request record
			apache  = request->r;
			// fill with server record
			config	= request->server;
			// set local memory
			local   = request->mp;
		}
		// check enabled state (new advanced app will draw from firebird)
		if (!config->enabled) {
			// open logging connector
			logging logger(apache);
			// reset debug level to push out error messages
			if (ap_get_request_module_loglevel(r, APLOG_MODULE_INDEX) >= APLOG_TRACE1) 
				logger.resetDBGLvl(8);
			// log message
			echoLog(logger, 0, INFX_LOG_DATA, "Enabled Check", 8, false, "%s %s is not enabled.", MODULE_NAME, MODULE_VERSION);
			// set retcode
			retcode = -1;
		}
		// do not handle internal redirects
		if (!ap_is_initial_req(r) || (r->main != NULL)||(r->prev != NULL)) {
			// set retcode
			retcode = -1;
		}
		// exit
		return;
	};
	// handle new request
	void security::newRequest(int &httpRes) {
		// detect if not enabled
		if (retcode == -1) return;
		// retrieve new default request
		if (defRequest(request)) { 
			// fill in the blanks
			getRequest(request);
			// perform rule operations
			askRequest(request);
			// check if app
			if (request->d_request_is_app) {
				// open new db connection
				tcpdb tdb(apache);
				// perform database update
				if (!tdb.sysFWall(request)) {
					// set error code
					request->o_exit_code = apr_pstrdup(request->mp, "110");
					// set envelop call out
					apr_table_set(apache->subprocess_env, "errNUM", "110"); 
				}
				APLOG
				(
					"Entrance Data View request:%s, ip:%s, proxies:%s, ua:%s, refer:%s, method:%s, uri:%s, app:%s, fun:%s, var:%s, qs:%s, xtn:%s, ukey:%s, sid:%s, permatoken:%s, hnvp:%s, fnvp:%s",
					apache->the_request,
					request->i_remote_ip, 
					request->i_remote_proxies, 
					request->i_remote_useragent, 
					request->i_remote_referer, 
					request->i_request_method,
					request->i_request_uri, 
					request->d_path_app, 
					request->d_path_fun, 
					request->d_path_var, 
					request->i_query_string, 
					request->i_request_xtn, 
					request->i_cookie_unique, 
					request->i_cookie_session,
					request->i_cookie_authtoken, 
					request->d_path_half, 
					request->d_path_full
				);
			}
			// check if we are escaping immediately
			if (request->o_exit_kill) {
				// return http code
				httpRes = atoi(request->o_exit_http);
				// exit
				return;
			}
			// store the request handle
			ap_set_module_config(apache->request_config, &infinity_security_module, (void *)request);
		} else {
			// error out because we can't continue
			httpRes = HTTP_INTERNAL_SERVER_ERROR;
		}
	};
	// create default request structure and default enviornment only (no parsing)
	bool security::defRequest(infx_tx_rec *&aReq) {
		// variables
		apr_allocator_t	*allocator = NULL;
		apr_pool_t		*px = apache->pool;
		int				dbl = -1;
		const char		*cookie;
		// open logging connector
		logging logger(apache);
		// setup our structure
		aReq = (infx_tx_rec *)apr_pcalloc(apache->pool, sizeof(infx_tx_rec));
		// check if we got the memory
		if (aReq == NULL) return critLog(logger, "Memory Allocation Error");
		// setup an allocator
		apr_allocator_create(&allocator); 
		apr_allocator_max_free_set(allocator, 1024); 
		apr_pool_create_ex(&aReq->mp, apache->pool, NULL, allocator); 
		// again check the pool
		if (aReq->mp == NULL) return critLog(logger, "Memory Allocation Error");
		// set the owner of the allocator
		apr_allocator_owner_set(allocator, aReq->mp);
		// register clean up procedure ///----> cleanup request
		apr_pool_cleanup_register(aReq->mp, aReq, cleanup_request, apr_pool_cleanup_null);		
		// breakpoint
		stdLog(logger, INFX_LOG_DATA, dbl);
		// add common vars
		ap_add_common_vars(apache);
		// breakpoint
		stdLog(logger, INFX_LOG_DATA, dbl);
		// prime the entries with non null values
		aReq->server				= config; 
		aReq->r						= apache; 
		aReq->i_request_id			= apr_pstrdup(aReq->mp, tabNotNull(apache->subprocess_env, "UNIQUE_ID")); 
		aReq->i_request_time		= apache->request_time;
		aReq->i_request_host		= apr_pstrdup(aReq->mp, ap_get_server_name(apache));
		aReq->i_request_ip			= apr_pstrdup(aReq->mp, apache->connection->local_ip); 
		aReq->i_request_port		= apache->connection->local_addr->port;
		aReq->i_request_line		= apr_pstrdup(aReq->mp, apache->the_request); 
		aReq->i_request_uri			= apr_pstrdup(aReq->mp, "");
		aReq->i_request_xtn			= apr_pstrdup(aReq->mp, "");
		aReq->i_request_method		= apr_pstrdup(aReq->mp, apache->method);
		aReq->i_request_protocol	= apr_itoa(aReq->mp, apache->proto_num);
		aReq->i_remote_ip			= apr_pstrdup(aReq->mp, "");
		aReq->i_remote_user			= apr_pstrdup(aReq->mp, "");
		aReq->i_remote_host			= apr_pstrdup(aReq->mp, "");
		aReq->i_remote_domain		= apr_pstrdup(aReq->mp, "");
		aReq->i_remote_useragent	= tabNotNull(apache->headers_in, "User-Agent");
		aReq->i_remote_referer		= tabNotNull(apache->headers_in, "Referer");
		aReq->i_remote_proxies		= apr_pstrcat(aReq->mp,tabNotNull(apache->headers_in, "VIA"),tabNotNull(apache->headers_in, "X-Forwarded-For"),tabNotNull(apache->headers_in, "HTTP_CLIENT_IP"),tabNotNull(apache->headers_in, "HTTP_X_FORWARDED_FOR"),tabNotNull(apache->headers_in, "HTTP_REMOTE_ADDR"),NULL);
		aReq->i_query_string		= apr_pstrdup(aReq->mp, strNotNull(apache->args));
		aReq->i_query_array			= apr_table_make(aReq->mp, 0);
		aReq->i_cookie_unique		= apr_pstrdup(aReq->mp, "");
		aReq->i_cookie_session		= apr_pstrdup(aReq->mp, "");
		aReq->i_cookie_authtoken	= apr_pstrdup(aReq->mp, "");
		aReq->d_mode_class			= apr_pstrdup(aReq->mp, config->srv_class_level);
		aReq->d_path_app			= apr_pstrdup(aReq->mp, "");
		aReq->d_path_fun			= apr_pstrdup(aReq->mp, "");
		aReq->d_path_var			= apr_pstrdup(aReq->mp, "");
		aReq->d_path_domain			= apr_pstrdup(aReq->mp, "");
		aReq->d_path_root			= apr_pstrdup(aReq->mp, "");
		aReq->d_path_full			= apr_pstrdup(aReq->mp, "");
		aReq->d_path_half			= apr_pstrdup(aReq->mp, "");
		aReq->d_base_serving		= tabNotNull(config->infinity->paths, "apps_serving");
		aReq->d_base_shared			= tabNotNull(config->infinity->paths, "apps_shared");
		aReq->d_base_specific		= tabNotNull(config->infinity->paths, "apps_specific");
		aReq->d_shared_class		= tabNotNull(config->infinity->paths, "apps_shared_cls");
		aReq->d_shared_xsl			= tabNotNull(config->infinity->paths, "apps_shared_xsl");
		aReq->d_shared_xml			= tabNotNull(config->infinity->paths, "apps_shared_xml");
		aReq->d_target_r			= apr_pstrdup(aReq->mp, "");
		aReq->d_target_m			= apr_pstrdup(aReq->mp, "");
		aReq->d_target_c			= apr_pstrdup(aReq->mp, "");
		aReq->d_target_x			= apr_pstrdup(aReq->mp, "");
		aReq->d_target_s			= apr_psprintf(aReq->mp, "%s/system.infinity.php", aReq->d_shared_class);
		aReq->d_specific_root		= apr_pstrdup(aReq->mp, "");
		aReq->d_specific_class		= apr_pstrdup(aReq->mp, "");
		aReq->d_specific_xsl		= apr_pstrdup(aReq->mp, "");
		aReq->d_specific_xml		= apr_pstrdup(aReq->mp, "");
		aReq->d_request_is_auth		= 0;
		aReq->d_request_is_app		= 0;
		aReq->d_request_is_top		= 0;
		aReq->d_peer_is_local		= 0;
		aReq->d_peer_is_dev			= 0;
		aReq->d_peer_is_dnsv		= 0;
		aReq->d_mode_is_dev			= 0;
		aReq->o_exit_kill			= 0;
		aReq->o_exit_http			= apr_pstrdup(aReq->mp, "500");
		aReq->o_exit_uri			= apr_pstrdup(aReq->mp, "/index.php");
		aReq->o_exit_code			= apr_pstrdup(aReq->mp, "115");
		aReq->o_infinity_hash		= apr_pstrdup(aReq->mp, "");
		aReq->o_infinity_unique		= strKey(32, aReq->mp);
		aReq->o_infinity_session	= apr_pstrdup(aReq->mp, "");	
		aReq->d_debug_level			= 0;
		aReq->d_debug_classes		= apr_table_make(aReq->mp, 0);
		// get cookies
		ap_cookie_read(apache, "rid", &cookie, 1);
		aReq->i_cookie_unique		= apr_pstrdup(aReq->mp, strNotNull(cookie));
		ap_cookie_read(apache, "hid", &cookie, 1);
		aReq->i_cookie_session		= apr_pstrdup(aReq->mp, strNotNull(cookie));
		ap_cookie_read(apache, "permatoken", &cookie, 0);
		aReq->i_cookie_authtoken	= apr_pstrdup(aReq->mp, strNotNull(cookie));
		// set dummy envelop out
		apr_table_set(apache->subprocess_env, "httpNUM", "500"); 
		apr_table_set(apache->subprocess_env, "errNUM", "115"); 
		apr_table_set(apache->subprocess_env, "errMSG", "");
		apr_table_set(apache->subprocess_env, "errINT", "");
		apr_table_set(apache->subprocess_env, "R_infMODE", aReq->d_mode_class); 
		apr_table_set(apache->subprocess_env, "R_infAPP", "");
		apr_table_set(apache->subprocess_env, "R_infFUN", "");
		apr_table_set(apache->subprocess_env, "R_infVAR", "");
		apr_table_set(apache->subprocess_env, "R_path_shared_cls", aReq->d_shared_class);
		apr_table_set(apache->subprocess_env, "R_path_shared_xsl", aReq->d_shared_xsl);
		apr_table_set(apache->subprocess_env, "R_path_shared_xml", aReq->d_shared_xml);
		apr_table_set(apache->subprocess_env, "R_path_to_system", aReq->d_target_s);
		apr_table_set(apache->subprocess_env, "R_path_to_target", "");
		apr_table_set(apache->subprocess_env, "R_path_specific_root", aReq->d_specific_root);
		apr_table_set(apache->subprocess_env, "R_path_specific_xsl", "");
		apr_table_set(apache->subprocess_env, "R_path_specific_xml", "");
		apr_table_set(apache->subprocess_env, "R_path_specific_cls", "");
		apr_table_set(apache->subprocess_env, "R_path_to_fullnvp", "");
		apr_table_set(apache->subprocess_env, "R_path_to_halfnvp", "");
		apr_table_set(apache->subprocess_env, "R_INF_ukey", aReq->o_infinity_unique); 
		apr_table_set(apache->subprocess_env, "R_INF_skey", "0");
		apr_table_set(apache->subprocess_env, "R_INF_hkey", "");
		apr_table_set(apache->subprocess_env, "R_INF_loggedin", "0");
		apr_table_set(apache->subprocess_env, "R_INF_loginuser", "");
		apr_table_set(apache->subprocess_env, "R_INF_pageauth", "0");
		apr_table_set(apache->subprocess_env, "R_INF_pagesrch", "0");
		apr_table_set(apache->subprocess_env, "R_INF_srchenge", "0");
		apr_table_set(apache->subprocess_env, "R_INF_CLIENT_COUNTRY", "US");
		apr_table_set(apache->subprocess_env, "R_INF_CLIENT_POSTAL", "10001");
		// return
		return true;
	};
	// parse the request and fill in missing data
	void security::getRequest(infx_tx_rec *&aReq) {
		// vector container for split
		typedef vector<string> ixlist;
		// parse data
		// variables
		string server, ixroot = "", domain = "";
		string reqline = "", uri = "/", app = "", fun = "", var = "", qsa = "", xtn = "none";
		string half = "", full = "";
		ixlist reqpart, uripart, ippart;
		bool   even = true;
		tools  txc(apache);
		// copy server
		server  = ((apache->hostname) ?  apache->hostname : "www.example.com");
		// lower
		to_lower(server);
		// copy request line
		reqline = apache->the_request;
		// parse domain
		domain	= server.substr(server.find_first_of(".") + 1);
		// copy server into root
		ixroot	= ireplace_all_copy(server, ".", "_");
		// split the request and the uri into parts
		split(reqpart, reqline, is_any_of(" "));
		// capture result
		uri = reqpart.at(1);
		// capture query string
		qsa = aReq->i_query_string;
		// parse for contents if specified
		if (uri.length() > 1 && uri.find_first_of("/") == 0) {
			// clean query string
			uri = ireplace_all_copy(uri, "?" + qsa, "");
			// split uri
			split(uripart, uri.substr(1), is_any_of("/"));
			// capture parts
			app = uripart.at(0);
			fun = (uripart.size() > 1) ? uripart.at(1) : "base";
			var = (uripart.size() > 2) ? ireplace_all_copy(uri, ("/" + app + "/" + fun), "") : ""; 
			xtn = (uripart.back().find_first_of(".") == -1) ? "none" : uripart.back().substr(uripart.back().find_last_of(".") + 1);
			// merge new query string
			if (var.length()) {
				for (size_t i = 2; i < uripart.size(); i++) {
					// stack according to even or odd
					if (even) {
						qsa += "&" + uripart[i] + "=";
					} else {
						qsa += uripart[i];
					}
					// reset even
					even = !even;
				}
			}
		}
		// check if any proxies came through
		if (strlen(aReq->i_remote_proxies)) {
			// split ip addresses
			split(ippart, aReq->i_remote_proxies, is_any_of(","));
			// retreive first into var
			aReq->i_remote_ip = apr_pstrdup(aReq->mp,ippart.at(0).c_str());
		} else {
			aReq->i_remote_ip = apr_pstrdup(aReq->mp,apache->connection->client_ip);
		}
		// fix ip with v6 IP addresses being returned
		aReq->i_remote_ip = (apr_strnatcmp(aReq->i_remote_ip, "::1")) ? aReq->i_remote_ip : apr_pstrdup(aReq->mp, "127.0.0.1");
		// fix up half and full paths
		half = ireplace_all_copy(ireplace_all_copy(ireplace_all_copy(qsa,"/","%2F"),"&","/"),"=","/");
		full = ireplace_all_copy("/" + app + "/" + fun + "/" + half, "//", "/");
		// fill in the blanks in our structure
		aReq->d_path_root		= apr_pstrdup(aReq->mp, ixroot.c_str());
		aReq->d_path_domain		= apr_pstrdup(aReq->mp, domain.c_str());
		aReq->i_request_uri		= apr_pstrdup(aReq->mp, uri.c_str());
		aReq->d_path_app		= apr_pstrdup(aReq->mp, app.c_str());
		aReq->d_path_fun		= apr_pstrdup(aReq->mp, fun.c_str());
		aReq->d_path_var		= apr_pstrdup(aReq->mp, var.c_str());
		aReq->i_request_xtn		= apr_pstrdup(aReq->mp, xtn.c_str()); 
		aReq->i_query_string	= apr_pstrdup(aReq->mp, qsa.c_str());
		aReq->d_path_half		= apr_pstrdup(aReq->mp, half.c_str());
		aReq->d_path_full		= apr_pstrdup(aReq->mp, full.c_str());
		// fill in extended 
		aReq->d_specific_root	= apr_psprintf(aReq->mp, "%s/%s", aReq->d_base_specific, aReq->d_path_root);
		aReq->d_specific_class	= apr_psprintf(aReq->mp, "%s/classes", aReq->d_specific_root);
		aReq->d_specific_xsl	= apr_psprintf(aReq->mp, "%s/xsl", aReq->d_specific_root);
		aReq->d_specific_xml	= apr_psprintf(aReq->mp, "%s/xml", aReq->d_specific_root);
		aReq->d_target_r		= apr_psprintf(aReq->mp, "%s/%s", aReq->d_base_serving, aReq->i_request_uri);
		aReq->d_target_c		= apr_psprintf(aReq->mp, "%s/_application.php", aReq->d_specific_class);
		aReq->d_target_m		= apr_psprintf(aReq->mp, "%s/%s/%s", aReq->d_base_serving, aReq->d_path_root, aReq->i_request_uri);
		aReq->d_target_x		= apr_psprintf(aReq->mp, "%s/%s.php", aReq->d_specific_class, aReq->d_path_app);
		// answer request answers
		aReq->d_request_is_app	= (!apr_strnatcmp(aReq->i_request_xtn, "none")) ? 1 : 0;
		aReq->d_request_is_top	= (!apr_strnatcmp(aReq->i_request_uri, "/")) ? 1 : 0;
		aReq->d_peer_is_local	= (!apr_strnatcmp(aReq->i_remote_ip, "127.0.0.1")) ? 1 : 0;
		aReq->d_mode_is_dev		= (!apr_strnatcasecmp(aReq->d_mode_class, "development")) ? 1 : 0;
		// auth determination
		aReq->d_request_is_auth = (apr_strnatcasecmp(aReq->d_path_app, "account")) ? 0 : ((txc.isInList(aReq->d_path_fun,false,"auth","login","logout", NULL)) ? 1 : 0);
		// set query string
		apache->args = apr_pstrdup(apache->pool, qsa.c_str());
		// set env variables
		apr_table_set(apache->subprocess_env, "R_infAPP", aReq->d_path_app);
		apr_table_set(apache->subprocess_env, "R_infFUN", aReq->d_path_fun);
		apr_table_set(apache->subprocess_env, "R_infVAR", aReq->d_path_var);
		apr_table_set(apache->subprocess_env, "R_path_to_target", aReq->d_target_c);
		apr_table_set(apache->subprocess_env, "R_path_specific_root", aReq->d_specific_root);
		apr_table_set(apache->subprocess_env, "R_path_specific_cls", aReq->d_specific_class);
		apr_table_set(apache->subprocess_env, "R_path_specific_xsl", aReq->d_specific_xsl);
		apr_table_set(apache->subprocess_env, "R_path_specific_xml", aReq->d_specific_xml);	
		apr_table_set(apache->subprocess_env, "R_path_to_halfnvp", aReq->d_path_half);
		apr_table_set(apache->subprocess_env, "R_path_to_fullnvp", aReq->d_path_full);
		// release and cleanup
		reqpart.clear(); uripart.clear(); ippart.clear();
		ixroot.clear(); domain.clear(); uri.clear(); app.clear(); fun.clear(); 
		var.clear(); xtn.clear(); qsa.clear(); half.clear(); full.clear();
		// return
		return;
	};
	// interogate the request to be sure it is valid
	void security::askRequest(infx_tx_rec *&aReq) {
		// vector container for split
		typedef vector<string> ixlist;
		// variables
		ixlist	dnsparts;
		int		dbl = -1;
		char	*dnsresult, *indexroot;
		bool	appcheck = true;
		// new tools
		tools  txc(apache);
		// piece together index root
		indexroot = apr_pstrcat(aReq->mp, aReq->d_base_serving, "/index.php", NULL);
		// check for the existance of index root
		if (!fileExists(indexroot, aReq->mp)) {
			// set exit variables
			aReq->o_exit_code = apr_pstrdup(aReq->mp, "0");
			aReq->o_exit_http = apr_pstrdup(aReq->mp, "500");
			aReq->o_exit_kill = 1;
			// return
			return;
		}
		// check for shared dispatch files
		if (!fileExists(aReq->d_target_s, aReq->mp)) {
			// set exit variables
			aReq->o_exit_code = apr_pstrdup(aReq->mp, "0");
			aReq->o_exit_http = apr_pstrdup(aReq->mp, "500");
			aReq->o_exit_kill = 1;
			// return
			return;
		}
		// check for dev access rights
		if (aReq->d_mode_is_dev && !aReq->d_peer_is_local) {
			if (!devCheck(aReq)) {
				// set exit variables
				aReq->o_exit_code = apr_pstrdup(aReq->mp, "0");
				aReq->o_exit_http = apr_pstrdup(aReq->mp, "500");
				aReq->o_exit_kill = 1;
				// return
				return;
			}
		}
		// check if peer is is HTTP/0.9
		if (isStrNull(aReq->i_request_host) || apache->assbackwards) {
			// set exit variables
			aReq->o_exit_code = apr_pstrdup(aReq->mp, "0");
			aReq->o_exit_http = apr_pstrdup(aReq->mp, "500");
			aReq->o_exit_kill = 1;
			// return
			return;
		}
		// check if calling by IP
		if (isStrIP(aReq->i_request_host, aReq->mp)) {
			// set exit variables
			aReq->o_exit_code = apr_pstrdup(aReq->mp, "0");
			aReq->o_exit_http = apr_pstrdup(aReq->mp, "500");
			aReq->o_exit_kill = 1;
			// return
			return;
		}
		// check request method
		if (txc.isInList(aReq->d_path_fun,false,"get","post","head", NULL)) {
			// set exit variables
			aReq->o_exit_code = apr_pstrdup(aReq->mp, "0");
			aReq->o_exit_http = apr_pstrdup(aReq->mp, "500");
			aReq->o_exit_kill = 1;
			// return
			return;
		}
		// check resource usage
		if (!resCheck(aReq)) {
			// set exit variables
			aReq->o_exit_code = apr_pstrdup(aReq->mp, "0");
			aReq->o_exit_http = apr_pstrdup(aReq->mp, "500");
			aReq->o_exit_kill = 1;
			// return
			return;
		}
		// check GET url length
		if (strlen(aReq->i_request_uri) > 4000) {
			// set exit variables
			aReq->o_exit_code = apr_pstrdup(aReq->mp, "0");
			aReq->o_exit_http = apr_pstrdup(aReq->mp, "500");
			aReq->o_exit_kill = 1;
			// return
			return;
		}
		// check what type of request
		if (!aReq->d_request_is_app && !find_first(aReq->i_request_xtn, "none")) {
			if ((appcheck = appCheck(aReq))) {
				// check which resource is valid
				if (fileExists(aReq->d_target_r, aReq->mp))	{ 
					aReq->o_exit_uri = apr_psprintf(aReq->mp, "/%s", aReq->i_request_uri); 
				} else { 
					aReq->o_exit_uri = apr_psprintf(aReq->mp, "/%s/%s", aReq->d_path_root, aReq->i_request_uri); 
				}				
			} else {
				// set exit variables
				aReq->o_exit_code = apr_pstrdup(aReq->mp, "0");
				aReq->o_exit_http = apr_pstrdup(aReq->mp, "500");
				aReq->o_exit_kill = 1;
				// return
				return;
			}
		} else {
			// red flag zero length useragents
			if (!strlen(aReq->i_remote_useragent)) {
				// dismiss automatically if we don't have a list of peers that can send no UA 
				if (!strlen(config->srv_uawl_domains)) {
					// set exit variables
					aReq->o_exit_code = apr_pstrdup(aReq->mp, "107");
					aReq->o_exit_http = apr_pstrdup(aReq->mp, "0");
					aReq->o_exit_kill = 0;
					// return
					return;
				} else {
					// perform a reverse lookup and check results
					if ((apr_getnameinfo(&dnsresult, apache->connection->client_addr, 0)) == APR_SUCCESS && strlen(dnsresult)) {
						// set the details
						aReq->i_remote_host = dnsresult;
						// parse the results to get naked domain
						split(dnsparts, dnsresult, is_any_of("."));
						// piece together the domain name
						aReq->i_remote_domain = apr_pstrdup(aReq->mp, string(dnsparts.at(dnsparts.size() - 2) + "." + dnsparts.back()).c_str());
						// set the value to good
						aReq->d_peer_is_dnsv = 1;
						// check if domain is in the list
						if (!find_first(config->srv_uawl_domains, aReq->i_remote_domain)) {
							// set exit variables
							aReq->o_exit_code = apr_pstrdup(aReq->mp, "107");
							aReq->o_exit_http = apr_pstrdup(aReq->mp, "0");
							aReq->o_exit_kill = 0;
							// return
							return;
						}
					} else {
						// disqualify peers that we can not verify
						aReq->d_peer_is_dnsv = -1;
						// set exit variables
						aReq->o_exit_code = apr_pstrdup(aReq->mp, "107");
						aReq->o_exit_http = apr_pstrdup(aReq->mp, "0");
						aReq->o_exit_kill = 0;
						// return
						return;
					}
				}
			}
			// check dispatch files exists (loadable aliases here)
			if (!fileExists(aReq->d_target_c, aReq->mp)) {
				// set exit variables
				aReq->o_exit_code = apr_pstrdup(aReq->mp, "107");
				aReq->o_exit_http = apr_pstrdup(aReq->mp, "0");
				aReq->o_exit_kill = 0;
				// return
				return;
			} else if (!aReq->d_request_is_top) {
				// valid apps only
				if (!strlen(aReq->d_path_app) || !scanInput(aReq->d_path_app, apache->pool, INPUT_MUSTBE_CHAR)) {
					// set exit variables
					aReq->o_exit_code = apr_pstrdup(aReq->mp, "115");
					aReq->o_exit_http = apr_pstrdup(aReq->mp, "0");
					aReq->o_exit_kill = 0;
					// return
					return;
				} else if (!aprPathIsValid(aReq->d_path_full)) {
					// set exit variables
					aReq->o_exit_code = apr_pstrdup(aReq->mp, "115");
					aReq->o_exit_http = apr_pstrdup(aReq->mp, "0");
					aReq->o_exit_kill = 0;
					// return
					return;
				} else if (!aReq->d_request_is_auth && !fileExists(aReq->d_target_x, aReq->mp)) {
					// set exit variables
					aReq->o_exit_code = apr_pstrdup(aReq->mp, "107");
					aReq->o_exit_http = apr_pstrdup(aReq->mp, "0");
					aReq->o_exit_kill = 0;
					// return
					return;
				}
			}
		}
	};
	// resource usage check
	bool security::resCheck(infx_tx_rec *aReq) {
		// variables
		ap_sb_handle_t	*sbh = NULL;
		worker_score	*ws_record = NULL;
		char			*fids;
		int				i, j, k, ipl = 0;
		// new tools
		tools  txc(apache);
		// check ip for the number of active connections
		for (i = 0; i < server_limit; ++i) {
			for (j = 0; j < thread_limit; ++j) {
				// worker score record
				sbh = (ap_sb_handle_t *)apache->connection->sbh;
				// get record
				if (!(sbh == NULL))
					ws_record = ap_get_scoreboard_worker(sbh);
				// check data
				if (!(ws_record == NULL)) {
					// determine status
					switch (ws_record->status) {
						case SERVER_BUSY_READ:
						case SERVER_BUSY_WRITE:
						case SERVER_BUSY_KEEPALIVE:
						case SERVER_BUSY_LOG:
						case SERVER_BUSY_DNS:
						case SERVER_CLOSING:
						case SERVER_GRACEFUL:
							// determine if the user is attempting to overload a script
							fids = apr_pstrdup(aReq->mp, ws_record->request);
							fids = strTrim(txc.getStrReplace(fids, apache->method, ""), aReq->mp);
							fids = strLeft(fids, find(fids, " "), aReq->mp);
							// check data
							if (strlen(fids) && find(fids, ".") == -1) {
								if (!apr_strnatcmp(aReq->i_remote_ip, ws_record->client)) {
									ipl++;
								}
							}
							break;
						default: break;
					}
				}
			}
		}
		// set max limit
		k = config->max_per_client;
		// reset k if zero
		k = k || 4;
		// RETURN IP violates the max connections property
		return (ipl > k) ? false : true;
	};
	// dev mode/list usage check
	bool security::devCheck(infx_tx_rec *aReq) {
		// vector container for split
		typedef vector<string> ixlist;
		// container for split
		ixlist ippart;
		// strings
		string list = config->srv_bypass_ips;
		string p4, p3, p2, p1;
		// return 
		bool ret = false;
		// split the ip address
		split(ippart, aReq->i_remote_ip, is_any_of("."));
		// trim 
		trim(list);
		// push list over one to avoid false positives
		list = string(" ") + list + string(" ");
		// combine
		p4 = " " + string(aReq->i_remote_ip) + " ";
		p3 = " " + ippart[0] + "." + ippart[1] + "." + ippart[2] + " ";
		p2 = " " + ippart[0] + "." + ippart[1] + " ";
		p1 = " " + ippart[0] + " ";
		// check all
		if (find_first(list, p4) || find_first(list, p3) || find_first(list, p2) || find_first(list, p1)) 
			ret = true;
		// cleanup
		list.clear(); p4.clear(); p3.clear(); p2.clear(); p1.clear(); ippart.clear();
		// return
		return ret;
	};
	// app check (if resource)
	bool security::appCheck(infx_tx_rec *aReq) {
		// variables
		string	xtn, nol, www;
		bool	ret = true;
		// gather
		xtn = aReq->i_request_xtn;
		nol = config->ext_allow_nolimit;
		www = config->ext_allow_wwlimit;
		// check if an acceptable extension and exists
		if ((nol.find(xtn) == -1 && www.find(xtn) == -1) || (!fileExists(aReq->d_target_r, aReq->mp) && !fileExists(aReq->d_target_m, aReq->mp))) 
			ret = false;
		// clear all
		xtn.clear(); nol.clear(); www.clear();
		// return
		return ret;
	}
	// set the file returned to user
	void security::setURIFile(int &httpRes) {
		// detect if not enabled
		if (retcode == -1) return;
		// take in account the httpNum from earlier
		// set the request
		apache->uri = apr_pstrdup(apache->pool, request->o_exit_uri);
	}
	// echo cookies/complete request
	void security::doResponse(int &httpRes) {
		// detect if not enabled
		if (retcode == -1) return;
		// do nothing if exit code exists
		if (!apr_strnatcmp(request->o_exit_code, "0")) {
			// do nothing if not destined for an app
			if (request->d_request_is_app) {
				// complete only if there are values
				if (strlen(request->o_infinity_session) && strlen(request->o_infinity_unique)) {
					setCookie("hid", request->o_infinity_session, request->d_path_domain, 3600);
					setCookie("rid", request->o_infinity_unique, request->d_path_domain, 3600);
				}
			}
		}
	}
	// cookie builder
	int security::setCookie(char *name, char *value, char *domain, int expiration, int secure) {
		// variables
		char	*attributes = "";
		int		dbl = -1, rv = APR_SUCCESS;
		// create logger
		logging logger(apache);
		// set attributes
		attributes = apr_psprintf(local, "%s=%s; Max-Age=%d; path=/; domain=%s; HttpOnly;", name, value, expiration, strNotNull(domain));
		// breakpoint
		extLog(logger, INFX_LOG_DATA, dbl, "Set-Cookie: %s", attributes);
		// write cookie
		apr_table_addn(apache->err_headers_out, "Set-Cookie", attributes);
		// return cookie
		return rv;
	};
	// logger default for flagging
	void security::stdLog(logging &l, const char *f, const char *fx, int ln, int lvl, const char *msg) {
		// if lvl is negative 
		if (lvl == -1) lvl = dbglvl;
		// execute logger
		l.infEchoLog(f,fx,ln,"FLAG",lvl,false,strNotNull(msg));
		// return
		return;
	};
	// logger extended flagging with messages
	void security::extLog(logging &l, const char *f, const char *fx, int ln, int lvl, const char *msg, ...) {
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
	// logger critical
	bool security::critLog(logging &l, const char *error) {
		// echo to log ignoring the return code
		echoLog(l, 0, INFX_LOG_DATA, "INVALID", APLOG_CRIT, false, error, NULL);
		// return
		return false;
	}
	// logger echo log with unlimited inputs
	int security::echoLog(logging &l, int c, const char *f, const char *fx, int ln, const char *a, int lvl, bool irl, const char *msg, ...) {
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
	// reset the debug level
	void security::resetDBGLvl(int newlvl) {
		// reset
		dbglvl = newlvl;
		// exit
		return;
	};
}