// include main
#include "mod_infinity.h"
// mod_infinity namespace
namespace modinfinity
{
	// declare included namespaces
	using namespace std;
	// logging constructor definition
	logging::logging(request_rec *r, server_rec *s, apr_pool_t *p, int configdbglvl) : unique(0), dbglvl(0), 
		retcode(0), apache(0), config(0), server(0),request(0), local(0), fdb(0), trx(0), stm(0), fdbWriteError(false) {
		// determine how to fill memory variables
		if (!(r == NULL) || !(s == NULL) || !(p == NULL)) {
			// set config with r if not null
			if (!(r == NULL)) {
				// fill in as much as possible
				apache  = r;
				// try to get the request tx
				request = (infx_tx_rec *)ap_get_module_config(r->request_config, &infinity_security_module);
				// set server record
				server = r->server;
				// check the request config
				if (request == NULL) {
					// attempt to get the main configuration
					config = (infx_config *)ap_get_module_config(r->server->module_config, &infinity_security_module);
					// set local memory
					local  = r->pool;
				} else {
					// fill with latest request record
					apache  = request->r;
					// fill with server record
					config	= request->server;
					// set local memory
					local   = request->mp;
				}
				// set unique
				unique = strNotNull(apr_pstrdup(local, apr_table_get(r->subprocess_env, "UNIQUE_ID")));
			} else if (!(s == NULL)) {
				// attempt to get the main configuration
				config = (infx_config *)ap_get_module_config(s->module_config, &infinity_security_module);
				// set local memory
				local = config->mp;
				// set server record
				server = s;
			} else if (!(p == NULL)) {
				// set local memory
				local = p;
				// set server
				server = ap_server_conf;
			}
			// set the configdbglvl param for when config can't be accessed directly
			dbglvl = configdbglvl;
		} else { 
			// set defaults
			local  = ap_pglobal; 
			server = ap_server_conf;
		}
		// attempt to connect to firebird
		getFBDB();
		// check state
		if (fdbWriteError || fdb == NULL) 
			retcode = -1;
		// exit
		return;
	};
	// destructor
	logging::~logging() {
		if (!(fdb == NULL) && !(retcode == -1)) {
			fdb->Disconnect();
		}	
	};
	// overloaded infEchoLog
	// table base output
	void logging::infEchoLog(const char *file, const char *function, int line, const char *area, int level, bool inc_req_line, const char *msgStr, apr_table_t *table) {
		// check if we are able to log
		if (checkLvl(level) && !(retcode == -1)) {
			// version allows outputing table data to the logs
			// variables
			const apr_array_header_t	*envs = apr_table_elts(table);
			apr_table_entry_t			*env  = (apr_table_entry_t *)envs->elts;
			char						*newline = apr_pstrdup(local, "");
			// add line to newline
			newline = apr_psprintf(local, "Table Data Follows:%s%s %s", ptr(10, local), ptr(13, local),((strlen(msgStr)) ? msgStr : ""));
			// loop over all env vars
			for (int j = 0; j < envs->nelts; ++j)
				newline = apr_psprintf(local, "%s%s%s %s => %s", newline, ptr(10, local), ptr(13, local), env[j].key, env[j].val);
			// call main logger
			infEchoLog(file, function, line, area, level, inc_req_line, newline);
		}
		// exit
		return;
	};
	// base function
	void logging::infEchoLog(const char *file, const char *function, int line, const char *area, int level, bool inc_req_line, const char *msgStr) {
		// variables
		char *servername;
		// check if we are able to log
		if (checkLvl(level)) {
			// check connected state
			if (fdb->Connected() && !(retcode == -1)) {
				// determine the name of the host
				if (!(apache == NULL)) {
					servername = apr_pstrdup(local, apache->hostname);
				} else {
					servername = apr_pstrdup(local, server->server_hostname);
				}
				// wrap in a try block
				try {
					// start transaction
					trx->Start();
					// set the inputs
					stm->Set(1, strNotNull(unique));
					stm->Set(2, strNotNull(servername));
					stm->Set(3, level);
					stm->Set(4, strNotNull(file));
					stm->Set(5, strNotNull(function));
					stm->Set(6, strNotNull(area));
					stm->Set(7, line);
					stm->Set(8, strNotNull(msgStr));
					// execute the request
					stm->Execute();
					// commit
					trx->Commit();
				} catch (IBPP::SQLException &e) {
					// write directly to error logs
					APLOG("[FBERR: %s. Original:[%s:%s:%s(%d)][%s]]", e.what(), file, function, area, line, msgStr); 
				} catch (IBPP::LogicException &e) {
					// write directly to error logs
					APLOG("[FBERR: %s. Original:[%s:%s:%s(%d)][%s]]", e.what(), file, function, area, line, msgStr); 
				} catch (...) {
					// write directly to error logs
					APLOG("[FBERR Uncaught. Original:[%s:%s:%s(%d)][%s]]", file, function, area, line, msgStr); 
				};
			} else {
				// write directly to error logs
				APLOG("[FBERR UNLOADED. Original:[%s:%s:%s(%d)][%s]]", file, function, area, line, msgStr); 
			}
		}
		// exit
		return;
	};
	// check levels
	bool logging::checkLvl(int level) {
		// automatically write to logs for warning/error levels
		if (isNumInRange(level, 0, 4, 1)) 
			return true;
		// check if log level is higher than configure
		if (dbglvl && level <= dbglvl) 
			return true;
		// check enabled state
		if (!(config == NULL))
			if (!config->enabled || !config->use_logging)
				return false;
		// check if the logging setting is higher than what was passed
		if (!(apache == NULL))
			if (level <= ap_get_request_module_loglevel(apache, APLOG_MODULE_INDEX))
				return true;
		if (!(server == NULL))
			if (level <= ap_get_server_module_loglevel(server, APLOG_MODULE_INDEX))
				return true;
		// return default
		return false;
	};
	// load a firebird connection
	void logging::getFBDB() {
		// call database layer
		tcpdb dbx(apache);
		// get new connection
		if (!dbx.tcpfbLoadConn(fdb)) {
			// reset and log
			resetFDB(false);
			APLOG("Infinity::Logging: Failed Opening Connection To Firebird", NULL);
		} else {
			try {
				// transaction handle
				trx = IBPP::TransactionFactory(fdb);
				// start transaction
				trx->Start();
				// check if transaction has been started
				if (trx->Started()) {
					// statement handle
					stm = IBPP::StatementFactory(fdb, trx);
					// prepare
					stm->Prepare("insert into runtimeLog (logdate,uqlogid,dscope,dlevel,ldfile,ldfunc,ldarea,ldline,lddesc) values (CURRENT_TIMESTAMP,?,?,?,?,?,?,?,?)");
					// check prepare
					if (!(stm->Parameters() == 8)) {
						// reset and log
						resetFDB(true);
						APLOG("Infinity::Logging: Firebird did not find the correct parameter count.", NULL);
					} 
					
					/*else { APLOG("Infinity::Logging: %d", __LINE__);
						if (stm->ParameterType(13) != IBPP::sdString || stm->ParameterSubtype(5) != 1 || stm->ParameterSize(13) != 30) {
							// reset and log
							resetFDB(true);
							APLOG("Infinity::Logging: Firebird did not set the parameters correctly.", NULL);
						}
					}*/
				} else {
					// reset and log
					resetFDB(true);
					APLOG("Infinity::Logging: Firebird could not start the transaction.", NULL);
				}
			} catch(IBPP::SQLException &e) {
				// reset and log
				resetFDB(true);
				APLOG("Infinity::Logging: Firebird load threw an error: %s.", e.what());	
			} catch(IBPP::LogicException &e) {
				// reset and log
				resetFDB(true);
				APLOG("Infinity::Logging: Firebird load threw an error: %s.", e.what());			
			} catch (...) { 
				// reset and log
				resetFDB(true);
				APLOG("Infinity::Logging: Firebird load threw an uncaught error.", NULL);			
			};
		}
	};
	// reset firebird variables
	void logging::resetFDB(bool disconnect) {
		// disconnect
		if (disconnect) fdb->Disconnect();
		// reset all
		fdb = NULL;
		trx = NULL;
		stm = NULL;
		fdbWriteError = true;
		// exit
		return;
	}
	// reset dbglvl
	void logging::resetDBGLvl(int newlvl) {
		// reset the debug level
		this->dbglvl = newlvl;
		// exit 
		return;
	};
}