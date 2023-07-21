// include mod_infinity
#include "mod_infinity.h"
// namespaces
using namespace modinfinity;
// type casting function
typedef const char *(*CMD_HAND_TYPE) ();
// echo to logging short
static int echoLog(logging &l, apr_pool_t *p, int c, const char *f, const char *fx, int ln, const char *a, int lvl, bool irl, const char *msg, ...) {
	// variables
	const char	*o;
	va_list		args;
	// setup the input list
	va_start(args, msg);
	// get message data
	o = apr_pvsprintf(p, msg, args);
	// call va end
	va_end(args);
	// execute logger
	l.infEchoLog(f,fx,ln,a,lvl,irl,o);
	// return
	return c;
}
// default return log
static int defLog(logging &l, apr_pool_t *p, int c, const char *f, const char *fx, int ln, int s, int r) {
	// variables
	const char	*o;
	// get message
	o = apr_psprintf(p, "Returning Status: %d, Return Code: %d", s, r);
	// execute logger
	l.infEchoLog(f,fx,ln,"DONE",APLOG_DEBUG,false,o);
	// return
	return c;
}
// standard info log
static void stdLog(logging &l, const char *f, const char *fx, int ln, int lvl, const char *msg = "") {
	// execute logger
	l.infEchoLog(f,fx,ln,"FLAG",lvl,false,msg);
	// return
	return;
}
// critcal logging
static int critLog(logging &l, apr_pool_t *p, const char *error) {
	// return echo log short
	return echoLog(l, p, 0, INFX_LOG_DATA, "INVALID", APLOG_CRIT, false, error, NULL);
}
/*******************************************************************************
	Infinity Engine Handlers
********************************************************************************/
// create an infinity engine
infx_engine *modinfinity_create(server_rec *s, apr_pool_t *mp, apr_pool_t *temp, int mode, int dbl = APLOG_TRACE8) {
	// create logger
	logging logger(NULL, s, mp);
	// tools
	tools txc(NULL, NULL, mp);
	// variables
	infx_engine *ixcore = NULL;
	// create structure
	ixcore = (infx_engine *)apr_pcalloc(mp, sizeof(infx_engine));
	// check result of ixcore create
	if (!(ixcore == NULL)) {
		// variables
		char		*rootDIR	= apr_psprintf(temp, "%s/var", ap_server_root);
		char		*rootDBX	= apr_psprintf(temp, "%s/database", rootDIR);
		char		*rootINF	= apr_psprintf(temp, "%s/infinity", rootDIR);
		char		*appDIR		= apr_psprintf(temp, "%s/application", rootINF);
		char		*appSHARE	= apr_psprintf(temp, "%s/shared", appDIR);
		char		*appINDV	= apr_psprintf(temp, "%s/specific", appDIR);
		char		*appSERVE	= apr_psprintf(temp, "%s/serving", appDIR);
		infx_config *icfg;
		server_rec	*sp;
		// break point
		stdLog(logger, INFX_LOG_DATA, dbl);
		// set defaults
		ixcore->mp			= mp;
		ixcore->mode		= mode;
		// allocate a table with 20 lines
		ixcore->paths		= apr_table_make(mp, 15);
		// break point
		stdLog(logger, INFX_LOG_DATA, dbl);
		// set paths ~using set because temp memory pool will be gone~
		// absolute server root
		apr_table_set(ixcore->paths, "sbase", ap_server_root);
		// absolute var directory root, restrict to this path
		apr_table_set(ixcore->paths, "ubase", rootDIR);
		// absolute database directory path
		apr_table_set(ixcore->paths, "database", rootDBX);
		// absolute infinity web app root
		apr_table_set(ixcore->paths, "infinity", rootINF);
		// absolute sub folders logs, apps, ...
		apr_table_set(ixcore->paths, "apps", appDIR);
		apr_table_set(ixcore->paths, "apps_shared", appSHARE);
		apr_table_set(ixcore->paths, "apps_serving", appSERVE);
		apr_table_set(ixcore->paths, "apps_specific", appINDV);
		apr_table_set(ixcore->paths, "apps_shared_xsl", apr_psprintf(mp, "%s/xsl", appSHARE));
		apr_table_set(ixcore->paths, "apps_shared_xml", apr_psprintf(mp, "%s/xml", appSHARE));
		apr_table_set(ixcore->paths, "apps_shared_cls", apr_psprintf(mp, "%s/classes", appSHARE));
		// break point
		stdLog(logger, INFX_LOG_DATA, dbl);
		// create server files for each server setup
		for (sp = s; sp; sp = sp->next) {
			// variables
			apr_allocator_t	*allocator = NULL;
			// breakpoint
			stdLog(logger, INFX_LOG_DATA, dbl);
			// retrieve config
			icfg = (infx_config *) ap_get_module_config(sp->module_config, &infinity_security_module);
			// create memory within each server
			// breakpoint
			stdLog(logger, INFX_LOG_DATA, dbl);
			// setup an allocator
			apr_allocator_create(&allocator); 
			// breakpoint
			stdLog(logger, INFX_LOG_DATA, dbl);
			// max before free is 4M
			apr_allocator_max_free_set(allocator, 4096);
			// breakpoint
			stdLog(logger, INFX_LOG_DATA, dbl);
			// create a pool using the main pool and an allocator
			apr_pool_create_ex(&icfg->mp, mp, NULL, allocator);
			// breakpoint
			stdLog(logger, INFX_LOG_DATA, dbl);
			// check the pool
			if (icfg->mp == NULL) { 
				// breakpoint
				stdLog(logger, INFX_LOG_DATA, APLOG_WARNING, "Server Memory could not be loaded. Using main pool memory.");
				// use a pointer to the main pool
				icfg->mp = mp; 
			} else {
				// breakpoint
				stdLog(logger, INFX_LOG_DATA, dbl);
				// set the owner of the allocator
				apr_allocator_owner_set(allocator, icfg->mp);
				// breakpoint
				stdLog(logger, INFX_LOG_DATA, dbl);
				// register clean up procedure
				apr_pool_cleanup_register(icfg->mp, icfg, apr_pool_cleanup_null, apr_pool_cleanup_null);
			}
			// breakpoint
			stdLog(logger, INFX_LOG_DATA, dbl);
			// set server core name
			icfg->srv_domain_corename = txc.getStrReplace(sp->server_hostname, ".", "_");
			// breakpoint
			stdLog(logger, INFX_LOG_DATA, dbl);
			// set admin email
			icfg->srv_domain_admin_email = strNotNull(sp->server_admin);
		}
	} else { 
		stdLog(logger, INFX_LOG_DATA, APLOG_CRIT, "FAILED TO LOAD ENGINE"); 
	}
	// return
	return ixcore;
}
// release resources being held by infinity
void modinfinity_shutdown(infx_engine *ixcore) {
    if (ixcore == NULL) return;
}
// cleanup at the end of server life
static apr_status_t module_cleanup(void *data) {
	// shutdown
    modinfinity_shutdown(infx_exec);
	// return success
    return APR_SUCCESS;
}

/*******************************************************************************
	Infinity Request Workflow
	start->cstart->begin->rename->check->redirect
********************************************************************************/
static int infinity_server_pload(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp) {
	// set extended status
	ap_extended_status = 1;
	// return
	return OK;
}
/*******************************************************************************
	Infinity Startup (runs right after the server has read the configuration file)
********************************************************************************/
static int infinity_server_start(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s) {
	// variables for base config start
	const char	*flag = "modinfinity-init-flag";
	char		*pidname;
    void		*init_flag = NULL;
    int			dbl = APLOG_TRACE4;
	pid_t		pidNKey;
	apr_file_t	*pidfile;
	// logger
	logging logger(NULL, s, p);
	// tools object
	tools txc(NULL, NULL, p);
	// breakpoint
	stdLog(logger, INFX_LOG_DATA, dbl);
	// determine if this is the first time we have loaded
	init_flag = ap_retained_data_get(flag);
	// check flag result
	if (init_flag == NULL) {
		// breakpoint
		stdLog(logger, INFX_LOG_DATA, dbl);
		// set first time flag local
		ap_retained_data_create(flag, 1);
	} else {
		// break point
		stdLog(logger, INFX_LOG_DATA, dbl);
		#if defined(WIN32)
		// create a pid if not exists
		if (ap_read_pid(p, "logs/httpd.pid", &pidNKey) == OK){
			// break point
			stdLog(logger, INFX_LOG_DATA, dbl);
			// create a pid especially for our setup
			pidname = apr_psprintf(ptemp, "logs/infx.%d.pid", pidNKey);
			// if pidfile does not exist then create it
			if (!fileExists(pidname, ptemp)) {
				// break point
				stdLog(logger, INFX_LOG_DATA, dbl);
				// create the pid
				apr_file_open(&pidfile, pidname, APR_WRITE|APR_APPEND|APR_CREATE, INFX_BASE_PERM, ptemp);
				// add nonsensical data to it
				apr_file_puts("1", pidfile);
				// cllose the file and wait for run 2
				apr_file_close(pidfile);
			} else {
				// break point
				stdLog(logger, INFX_LOG_DATA, dbl);
				// we no longer require the pid file
				apr_file_remove(pidname, ptemp);
		#endif
				// break point
				stdLog(logger, INFX_LOG_DATA, dbl);
				// execute engine create
				infx_exec = modinfinity_create(s, p, ptemp, MOD_INFINITY_ONLINE, dbl);
				// break point
				stdLog(logger, INFX_LOG_DATA, dbl);
				// check
				if (infx_exec == NULL) {
					// breakpoint
					stdLog(logger, INFX_LOG_DATA, APLOG_CRIT, "Engine Creation Failed. Can not continue.");
					// return an error
					return HTTP_INTERNAL_SERVER_ERROR;
				}
				// break point
				stdLog(logger, INFX_LOG_DATA, dbl);
				// update each server config with a link to the engine
				for (server_rec *sp = s; sp; sp = sp->next) {
					// break point
					stdLog(logger, INFX_LOG_DATA, dbl);
					// create a config
					infx_config *icfg = (infx_config *) ap_get_module_config(sp->module_config, &infinity_security_module);
					// break point
					stdLog(logger, INFX_LOG_DATA, dbl);
					// set aside memory on each for the engine
					icfg->infinity = (infx_engine *)apr_palloc(icfg->mp, sizeof(infx_engine));
					// check if memory has been allocated
					if (icfg->infinity == NULL) {
						// breakpoint
						stdLog(logger, INFX_LOG_DATA, APLOG_CRIT, "Engine Creation Failed. Memory allocation error.");
						// return an error
						return HTTP_INTERNAL_SERVER_ERROR;
					}
					// break point
					stdLog(logger, INFX_LOG_DATA, dbl);
					// push infx_exec onto config
					icfg->infinity = infx_exec;
				}
				// break point
				stdLog(logger, INFX_LOG_DATA, dbl);
		#if defined(WIN32)
			}
		} else {
			// breakpoint
			stdLog(logger, INFX_LOG_DATA, APLOG_CRIT, "HTTPD File not found? A Bug?");
			// set status
			return HTTP_INTERNAL_SERVER_ERROR;
		}
		#endif
	}
	// breakpoint
	stdLog(logger, INFX_LOG_DATA, dbl);
	// return
	return OK;
}
/*******************************************************************************
	POST REQUEST READ
********************************************************************************/
static int infinity_server_begin(request_rec *r) {
	// base status to be echoed or forwarded
	int	status = DECLINED;
	// call security
	security sec(r);
	// call new request
	sec.newRequest(status);
	// return status
	return status;
}
/*******************************************************************************
	hook to allow us to set the filename
********************************************************************************/
static int infinity_server_rename(request_rec* r) {
	// base status to be echoed or forwarded
	int	status = DECLINED;
	// call security
	security sec(r);
	// call setFile
	sec.setURIFile(status);
	// return status
	return status;
}
/*******************************************************************************
	Infinity Security Main Handler
********************************************************************************/
static int infinity_server_check(request_rec *r) {
	// base status to be echoed or forwarded
	int	status = DECLINED;
	// call security
	security sec(r);
	// call setFile
	sec.doResponse(status);
	// return status
	return status;
}
/*******************************************************************************
	Infinity Security Configuration (server config)
********************************************************************************/
static void *infsec_merge_sconfig(apr_pool_t *p, void *_parent, void *_child) {
	// create instances of the server sys config for both child and parent
	infx_config *merge	 = (infx_config *) apr_pcalloc(p, sizeof(infx_config));
	infx_config *parent  = (infx_config *) _parent;
	infx_config *child   = (infx_config *) _child;
	// merge the data
	merge->enabled					= child->enabled;
	merge->in_dev_mode				= child->in_dev_mode;
	merge->xauth_allowed			= child->xauth_allowed;
	merge->max_per_client			= parent->max_per_client;
	merge->use_logging				= child->use_logging;
	merge->logging_dir				= child->logging_dir;
	merge->logging_lvl				= child->logging_lvl;
	merge->logging_msk				= child->logging_msk;
	merge->dblink					= parent->dblink;
	merge->dbserv					= parent->dbserv;
	merge->dbuser					= parent->dbuser;
	merge->dbpass					= parent->dbpass;
	merge->dbfile					= parent->dbfile;
	merge->srv_domain_aliases		= (!strlen(child->srv_domain_aliases) ? parent->srv_domain_aliases : child->srv_domain_aliases);
	merge->srv_domain_admin_email	= (!strlen(child->srv_domain_admin_email) ? parent->srv_domain_admin_email : child->srv_domain_admin_email);
	merge->srv_domain_admin_sms		= (!strlen(child->srv_domain_admin_sms) ? parent->srv_domain_admin_sms : child->srv_domain_admin_sms);
	merge->srv_class_level			= (!strlen(child->srv_class_level) ? parent->srv_class_level : child->srv_class_level);
	merge->srv_bypass_ips			= (!strlen(child->srv_bypass_ips) ? parent->srv_bypass_ips : child->srv_bypass_ips);
	merge->srv_uawl_domains			= (!strlen(child->srv_uawl_domains) ? parent->srv_uawl_domains : child->srv_uawl_domains);
	merge->srv_seblock_paths		= (!strlen(child->srv_seblock_paths) ? parent->srv_seblock_paths : child->srv_seblock_paths);
	merge->ext_allow_nolimit		= (!strlen(child->ext_allow_nolimit) ? parent->ext_allow_nolimit : child->ext_allow_nolimit);
	merge->ext_allow_wwlimit		= (!strlen(child->ext_allow_wwlimit) ? parent->ext_allow_wwlimit : child->ext_allow_wwlimit);
	// return merged
	return merge;
}
static void *infsec_create_sconfig(apr_pool_t *p, server_rec *s) {
	// create an instance of the server system configuration
	infx_config  *cfg = (infx_config *) apr_pcalloc(p, sizeof(infx_config));
	// tools object
	tools txc(NULL, NULL, p);	
    // set a default configuration
	cfg->mp						= p;
	cfg->enabled				= true;
	cfg->in_dev_mode			= false;
	cfg->xauth_allowed			= false;
	cfg->max_per_client			= 5;
	cfg->use_logging			= true;
	cfg->logging_dir			= "";
	cfg->logging_lvl			= 4;
	cfg->logging_msk			= "*";
	cfg->dblink					= "";
	cfg->dbserv					= "";
	cfg->dbuser					= "";
	cfg->dbpass					= "";
	cfg->dbfile					= "";
	cfg->srv_domain_corename	= "";
	cfg->srv_domain_aliases		= "";
	cfg->srv_domain_admin_email = "";
	cfg->srv_domain_admin_sms	= "";
	cfg->srv_class_level		= "development";
	cfg->srv_bypass_ips			= "";
	cfg->srv_uawl_domains		= "";
	cfg->srv_seblock_paths		= "";
	cfg->ext_allow_nolimit		= "jpg|gif|png|ico|txt|oog";
	cfg->ext_allow_wwlimit		= "js|css|xml|xsl|pdf|flv|fla|wsdl|oog";
	// return the configuration
    return cfg;
}
/*******************************************************************************
	Infinity Security Command Parsers (server config)
********************************************************************************/
// single slot version
static const char *set_infinity_params(cmd_parms *cmd, void *dummy, const char *val) {
	// retrieve server record
    infx_config *cfg = (infx_config *) ap_get_module_config(cmd->server->module_config, &infinity_security_module);
	// variables
	char *arg = apr_pstrdup(cmd->pool, strNotNull(val));
	unsigned int mORvSvr = NOT_IN_DIRECTORY|NOT_IN_LOCATION|NOT_IN_FILES|NOT_IN_LIMIT;
	unsigned int mSvr = GLOBAL_ONLY;
	// check length
	if (!strlen(arg)) return NULL;
	// switch based on information input
    switch ((long) cmd->info) {
		// max connections allowed
		case maxconn:	
			// global only
			if (ap_check_cmd_context(cmd, mSvr) == NULL) {
				// can not be zero or less than 3 or greater than 7
				if (isNumInRange(atoi(arg), 3, 7))
					cfg->max_per_client = atoi(arg);
			}
			break; 
		// if enabled for root or vservers
		case enabled:   
			if (ap_check_cmd_context(cmd, mORvSvr) == NULL)
				cfg->enabled = isStrBool(arg);
			break;
		// logging
		case logenable:		
			if (ap_check_cmd_context(cmd, mORvSvr) == NULL)			
				cfg->use_logging = isStrBool(arg);
			break;			
		case logmask:		
			if (ap_check_cmd_context(cmd, mORvSvr) == NULL)				
				cfg->logging_msk = arg;
			break;
		case adminsms:
			if (ap_check_cmd_context(cmd, mORvSvr) == NULL)
				cfg->srv_domain_admin_sms = arg;
			break;
		// if in development mode
		case domain:		
			if (ap_check_cmd_context(cmd, mORvSvr) == NULL)				
				cfg->in_dev_mode = isStrBool(arg); 
			break;
		// if openid/oauth/etc security is allowed
		case xauth:		
			if (ap_check_cmd_context(cmd, mORvSvr) == NULL)				
				cfg->xauth_allowed = isStrBool(arg); 
			break;
		// db connection data
		case dblink:		
			if (ap_check_cmd_context(cmd, mORvSvr) == NULL)				
				cfg->dblink = arg; 
			break;
		case dbserv:		
			if (ap_check_cmd_context(cmd, mORvSvr) == NULL)				
				cfg->dbserv = arg; 
			break;
		case dbuser:		
			if (ap_check_cmd_context(cmd, mORvSvr) == NULL)				
				cfg->dbuser = arg; 
			break;
		case dbpass:		
			if (ap_check_cmd_context(cmd, mORvSvr) == NULL)				
				cfg->dbpass = arg; 
			break;
		case dbfile:		
			if (ap_check_cmd_context(cmd, mORvSvr) == NULL)				
				cfg->dbfile = arg; 
			break;
		// class associated with vserver (development, open, openwsec, secure)
		case sclass:		
			if (ap_check_cmd_context(cmd, mORvSvr) == NULL)				
				cfg->srv_class_level = strToLower(arg); 
			break;
		// bypass development block IPs
		case bypass:		
			if (ap_check_cmd_context(cmd, mORvSvr) == NULL)				
				cfg->srv_bypass_ips	= arg; 
			break;
		// whitelist domains if no ua provided
		case ualook:		
			if (ap_check_cmd_context(cmd, mORvSvr) == NULL)				
				cfg->srv_uawl_domains = arg; 
			break;
		// block paths from search engines
		case searchblock:	
			if (ap_check_cmd_context(cmd, mORvSvr) == NULL)				
				cfg->srv_seblock_paths = arg; 
			break;
		// file types with no limits
		case extnolimit:	
			if (ap_check_cmd_context(cmd, mORvSvr) == NULL)				
				cfg->ext_allow_nolimit = arg; 
			break;
		// file types with referer limits
		case extwwlimit:	
			if (ap_check_cmd_context(cmd, mORvSvr) == NULL)				
				cfg->ext_allow_wwlimit = arg; 
			break;
	}
	// return
	return NULL;
}
/*******************************************************************************
	Infinity Security Command Structure (server config)
********************************************************************************/
static const command_rec infsec_cmds[] = {
	AP_INIT_TAKE1("InfSecMaxConnIP", (CMD_HAND_TYPE) set_infinity_params, (void*)maxconn, RSRC_CONF, "maximum simultaneous connections per IP address"),
	AP_INIT_TAKE1("InfSecEnabled", (CMD_HAND_TYPE) set_infinity_params, (void*)enabled, RSRC_CONF, "whether or not the firewall is enabled"),
	AP_INIT_TAKE1("InfSecDomainOn", (CMD_HAND_TYPE) set_infinity_params, (void*)domain, RSRC_CONF, "allows for a domain to be put into development mode"),
	AP_INIT_TAKE1("InfSecAllowXAUTH", (CMD_HAND_TYPE) set_infinity_params, (void*)xauth, RSRC_CONF, "allows for a domain to use openid for authentication"),
	AP_INIT_TAKE1("InfSecEnableLogs", (CMD_HAND_TYPE) set_infinity_params, (void*)logenable, RSRC_CONF, "allows for enabling logging"),
	AP_INIT_TAKE1("InfSecLogMask", (CMD_HAND_TYPE) set_infinity_params, (void*)logmask, RSRC_CONF, "sets the mask of allowed logging items"),
	AP_INIT_TAKE1("InfSecDBLink", (CMD_HAND_TYPE) set_infinity_params, (void*)dblink, RSRC_CONF, "odbtp server link"),
	AP_INIT_TAKE1("InfSecDBServer", (CMD_HAND_TYPE) set_infinity_params, (void*)dbserv, RSRC_CONF, "database server"),
	AP_INIT_TAKE1("InfSecDBUser", (CMD_HAND_TYPE) set_infinity_params, (void*)dbuser, RSRC_CONF, "database user"),
	AP_INIT_TAKE1("InfSecDBPass", (CMD_HAND_TYPE) set_infinity_params, (void*)dbpass, RSRC_CONF, "database pass"),
	AP_INIT_TAKE1("InfSecDBFile", (CMD_HAND_TYPE) set_infinity_params, (void*)dbfile, RSRC_CONF, "database name"),
	AP_INIT_TAKE1("InfSecSiteClass", (CMD_HAND_TYPE) set_infinity_params, (void*)sclass, RSRC_CONF, "site class for security."),
	AP_INIT_TAKE1("InfSecAdminSMS", (CMD_HAND_TYPE) set_infinity_params, (void*)adminsms, RSRC_CONF, "the sms handle for the domain admin."),
    AP_INIT_RAW_ARGS("InfSecOverrideIPs", (CMD_HAND_TYPE) set_infinity_params, (void*)bypass, RSRC_CONF, "ip addresses which may bypass lock downs"),
	AP_INIT_RAW_ARGS("InfSecUAWLDomains", (CMD_HAND_TYPE) set_infinity_params, (void*)ualook, RSRC_CONF, "whitelist of domains that are allowed to present no ua"),
	AP_INIT_RAW_ARGS("InfSecEXTNOLIMIT", (CMD_HAND_TYPE) set_infinity_params, (void*)extnolimit, RSRC_CONF, "Files that can bypass if present"),
	AP_INIT_RAW_ARGS("InfSecEXTWWLIMIT", (CMD_HAND_TYPE) set_infinity_params, (void*)extwwlimit, RSRC_CONF, "Files that need referer check"),
    {NULL}
};
/*******************************************************************************
	Apache Hooks (server config)
********************************************************************************/
static void infsec_register_hooks(apr_pool_t* p) {
	// predecessors
	static const char * const aszPred[] = { "mod_env.c", "mod_request.c", NULL };
	static const char * const aszPost[] = { "mod_alias.c", NULL };
	// hooks to register
	ap_hook_pre_config			(infinity_server_pload, NULL, NULL, APR_HOOK_FIRST);
    ap_hook_post_config			(infinity_server_start, NULL, NULL, APR_HOOK_MIDDLE);
	ap_hook_translate_name		(infinity_server_rename, NULL, aszPost, APR_HOOK_MIDDLE);
	ap_hook_post_read_request	(infinity_server_begin, aszPred, NULL, APR_HOOK_MIDDLE);
	ap_hook_fixups				(infinity_server_check, aszPred, NULL, APR_HOOK_MIDDLE);
	// server limits
    ap_mpm_query(AP_MPMQ_HARD_LIMIT_THREADS, &thread_limit);
    ap_mpm_query(AP_MPMQ_HARD_LIMIT_DAEMONS, &server_limit);
};
/*******************************************************************************
	Infinity Security Module Definition
********************************************************************************/
module AP_MODULE_DECLARE_DATA infinity_security_module = {
	STANDARD20_MODULE_STUFF,
	NULL,
	NULL,
	infsec_create_sconfig,			/* create per-server config structures */
	infsec_merge_sconfig,			/* merge per-server config structures */
	infsec_cmds,					/* table of config file commands       */
	infsec_register_hooks			/* register hooks */
};
/*
Todo: 
	Use Log Mask
	Write to pipe for logrotate
	
*/
/*
Possible Useful Functions

http_vhost
ap_matches_request_vhost

http_protocol
ap_discard_request_body

http_core
ap_custom_response

http.h
ap_random_pick
ap_parse_form_data
ap_pstr2_alnum
ap_request_has_body
ap_escape_quotes
ap_content_type_tolower
apr_filepath_list_split
argstr_to_table

X:\Code Fragments\Apache_Loose_C_Projects\httpd-2.4.2\modules\aaa\mod_auth_form.c
X:\Code Fragments\Apache_Loose_C_Projects\modsecurity-apache_2.6.1\apache2\apache2_io.c
*/
/*
// FROM httd.h
// for more efficient mapping of the document root to the infinity directory roots
// get context_document_root
(const char *) ap_context_document_root(request_rec *r);
// get content prefix
(const char *) ap_context_prefix(request_rec *r);
// set the content root info
(void) ap_set_context_info(request_rec *r, const char *prefix, const char *document_root);
// set document root
(void) ap_set_document_root(request_rec *r, const char *document_root);
// random number within a range
(apr_uint32_t) ap_random_pick(apr_uint32_t min, apr_uint32_t max);


// not killing requests to no host domains
Instead of killing requests to domain name with no host,
make url canonical with host name and domain and 302 the user to this.
~may need to add a default host name parameter for each virtual host
~may need to add a function that takes IP direct access and forwards it to the tree-top
*/