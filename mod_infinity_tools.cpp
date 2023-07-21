/*
	Class:			Tools 
	Segment:		Base Library 
	Create Date:	???
	Edit Date:		6/16/2012
	Description:	Contains class constructor def, logging interfaces, private access functions
*/
// include mod_infinity
#include "mod_infinity.h"
// mod_infinity namespace
namespace modinfinity
{
	// declare included namespaces
	using namespace std;
	// tools constructor definition
	tools::tools(request_rec *r, server_rec *s, apr_pool_t *p) : dbglvl(APLOG_TRACE8), retcode(0) , zErrMsg(0),
		apache(0), server(0), config(0), request(0), local(0), split(0)
	{
		// tools does not throw a not usuable return code like other classes
		// if one of these are provided then fill in, ELSE use global pool
		if (!(r == NULL) || !(s == NULL) || !(p == NULL))
		{
			// set config with r if not null
			if (!(r == NULL))
			{
				// fill in as much as possible
				apache = r;
				// server
				server = r->server;
				// attempt to get the main configuration
				config = (infx_config *)ap_get_module_config(server->module_config, &infinity_security_module);
				// try to get the request tx
				request = (infx_tx_rec *)ap_get_module_config(r->request_config, &infinity_security_module);
				// check the request config
				if (request == NULL) { local = r->pool; }
				else
				{
					// fill with latest request record
					apache = request->r;
					// set local
					local  = request->mp;
				}
			}
			// set config with s if not null
			else if (!(s == NULL))
			{
				// server
				server = s;
				// attempt to get the main configuration
				config = (infx_config *)ap_get_module_config(server->module_config, &infinity_security_module);
				// set local
				local = config->mp;
			}
			// set config with p if not null
			else if (!(p == NULL))
			{
				// set local memory
				local = p;
			}
		}
		else { local = ap_pglobal; }
		// reset error vars
		retcode = 0;
		zErrMsg = "";
		// exit
		return;
	};

	/*
		Direct String IO/Logging
	*/
	// outputs a formated string
	char *tools::getStrFormatted(const char *format, ...)
	{
		// variables
		char    *o = apr_pstrdup(local, "");
		va_list args;
		// setup the input list
		va_start(args, format);
		// call function
		o = getStrOutput(format, false, false, false, false, args);
		// call va end
		va_end(args);
		// return
		return o;
	};
	// base procedure
	char *tools::getStrOutput(const char *format, bool incname, bool tolog, bool toprint, bool tostring, va_list args, int loglevel)
	{
		// variables
		char *o = "";
		// set output
		o = apr_pvsprintf(local, format, args);
		// check if name should be included
		if (incname){ o = apr_pstrcat(local, (char *)MODULE_NAME, " ", (char *)MODULE_VERSION, " ", o, NULL); }
		// check how to output
		// print out to connection
		if (toprint && apache) { ap_rputs(o, apache); }
		// print out to the logs
		if (tolog)
		{
			// create logger
			logging logger(apache, server, local);
			// echo data to the logs ~ logger will use the best log destination ~
			logger.infEchoLog("DEBUG.cpp", "TOOLS::GETSTROUT", 0, "", loglevel, false, o);
		}
		// return o
		return o;
	};
	/*
		Internal logging
	*/
	// logger default for flagging
	void tools::stdLog(logging &l, const char *f, const char *fx, int ln, int lvl, const char *msg)
	{
		// if lvl is negative 
		if (lvl == -1) lvl = dbglvl;
		// execute logger
		l.infEchoLog(f,fx,ln,"FLAG",lvl,false,msg);
		// return
		return;
	};
	// logger extended flagging with messages
	void tools::extLog(logging &l, const char *f, const char *fx, int ln, int lvl, const char *msg, ...)
	{
		// variables
		const char	*o;
		va_list		args;
		// setup the input list
		va_start(args, msg);
		// get message data
		o = apr_pvsprintf(local, msg, args);
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
	int tools::echoLog(logging &l, int c, const char *f, const char *fx, int ln, const char *a, int lvl, bool irl, const char *msg, ...)
	{
		// variables
		const char	*o;
		va_list		args;
		// setup the input list
		va_start(args, msg);
		// get message data
		o = apr_pvsprintf(local, msg, args);
		// call va end
		va_end(args);
		// execute logger
		l.infEchoLog(f,fx,ln,a,lvl,irl,o);
		// return
		return c;
	};
	// reset the debug level
	void tools::resetDBGLvl(int newlvl)
	{
		// reset
		dbglvl = newlvl;
		// exit
		return;
	};
	// get error text
	char *tools::getErrTxt()
	{ 
		// return error string		
		return apr_pstrdup(local, strNotNull(zErrMsg));
	};
	// get error code
	int tools::getErrCode()
	{
		// return the error code
		return retcode;
	};
}