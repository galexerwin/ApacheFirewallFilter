// mod_infinity namespace
namespace modinfinity
{
	// declare included namespaces
	using namespace std;
	// logging
	class logging {
		// private
		private:
			char					*unique;
			int						dbglvl, retcode;
			request_rec				*apache;
			server_rec				*server;
			infx_config				*config;
			infx_tx_rec				*request;
			apr_pool_t				*local;
			IBPP::Database			fdb;
			IBPP::Statement			stm;
			IBPP::Transaction		trx;
			bool					fdbWriteError;
		// function list
		public:
			// constructor
			logging(request_rec *r = NULL, server_rec *s = NULL, apr_pool_t *p = NULL, int configdbglvl = 0);
			~logging();
			// reset debug level
			void resetDBGLvl(int newlvl);
			// overloaded echo functions
			void infxDynLog	(const char *file, const char *function, int line, const char *area, int level, bool inc_req_line, const char *msgStr, ...);
			void infEchoLog	(const char *file, const char *function, int line, const char *area, int level, bool inc_req_line, const char *msgStr, va_list ap);
			void infEchoLog	(const char *file, const char *function, int line, const char *area, int level, bool inc_req_line, const char *msgStr, apr_table_t *table);
			void infEchoLog (const char *file, const char *function, int line, const char *area, int level, bool inc_req_line, const char *msgStr);
		private:
			void getFBDB	(); // load a firebird connection
			bool checkLvl	(int level); // get the log level according to r or s
			bool alertADM	(); // alert admin on critical
			void resetFDB	(bool disconnect = true); // reset all fdb data links
	};
	// odbtp & firebird
	class tcpdb {
		// error string positions
		enum odberror {
			odb_open, odb_setup, odb_winsock,
			odb_login_failed, odb_conn_invalid, 
			odb_fw_failed, odb_sql_invalid 
		};
		// private
		private:
			const char				*zErrMsg;
			int						dbglvl, retcode, nrows, ncols;
			request_rec				*apache;
			server_rec				*server;
			infx_config				*config;
			infx_tx_rec				*request;
			apr_pool_t				*local;
		// public
		public:
			vector<string>			vcol_head;
			vector<vector<string> >	vcol_data;
		// function list
		public:
			// constructor
			tcpdb(request_rec *r = NULL, server_rec *s = NULL);
			// destructor
			~tcpdb(){};
			// basic functions
			void	resetDBGLvl		(int newlvl);
			char	*getErrTxt		();
			int		getErrCode		();
			bool	chkConnect		(const char *connstring, infx_tx_con *&connparams, apr_pool_t *mp);
			bool	sysFWall		(infx_tx_rec *&aReq);
			bool	dbExecute		(const char *sql, const char *ruser = "", const char *rpass = "", const char *rfile = "", const char *rserv = "", const char *rtype = "");
			bool	dbFetch			(infx_sqlset *&sql, int &count, apr_pool_t *mp);
			bool	echoResult		(apr_pool_t *mp, char *&response, bool directly = false);
			bool	tcpfbLoadConn	(IBPP::Database &fdb);
			bool	tcpfbFreeConn	(IBPP::Database fdb);
		private:
			void	tcpdbFreeAll	();
			bool	tcpdbLoadConn	(odbHANDLE &conn, const char *rlink = "", const char *ruser = "", const char *rpass = "", const char *rfile = "", const char *rserv = "", const char *rtype = "");
			bool	tcpdbFreeConn	(odbHANDLE conn);
			void	stdLog			(logging &l, const char *f, const char *fx, int ln, int lvl = -1, const char *msg = "");
			bool	errLog			(odberror e, logging &l, const char *f = "", const char *fx = "", int ln = 0, bool isExcep = false, odbHANDLE hCon = NULL, bool closedb = false);
			void	extLog			(logging &l, const char *f, const char *fx, int ln, int lvl, const char *msg, ...);
			int		echoLog			(logging &l, int c, const char *f, const char *fx, int ln, const char *a, int lvl, bool irl, const char *msg, ...);
	};
	// tools
	class tools {
		// private
		private:
			const char			*zErrMsg;
			int					dbglvl, retcode;
			request_rec			*apache;
			server_rec			*server;
			infx_config			*config;
			infx_tx_rec			*request;
			apr_pool_t			*local;
			apr_array_header_t	*split;
		// function list
		public:
			// functions in prefix (mod_infinity_tools(_abc.|.)cpp
			/*
				Additional
					X:\Code Fragments\Project\INC\infinity\mod_infinity_inc_tools.h
					X:\Code Fragments\Project\LIB\infinity\mod_infinity_tools.cpp
			*/
			/*
				These functions are in the root doc
			*/
			// constructor
			tools(request_rec *r = NULL, server_rec *s = NULL, apr_pool_t *p = NULL);
			// destructor
			~tools(){};
			// error handling access
			void			resetDBGLvl				(int newlvl); // reset debug level
			char			*getErrTxt				();
			int				getErrCode				();
			// string outputs
			char			*getStrFormatted		(const char *format, ...); // get formatted string, printf clone
			char			*getStrOutput			(const char *format, bool incname, bool tolog, bool toprint, bool tostring, va_list args, int loglevel = APLOG_INFO); // universally format and do something with a string
			/*
				These functions are in {prefix}_strings
			*/
			char			*b64HMACSHA1			(const char *input, const char *key);
			char			*getStrEscapeQuote		(const char *subject);
			char			*getStrUnQuoted			(const char *subject);
			char			*getStrReplace			(const char *subject, const char *token, const char *replacement);
			bool			getStrTransform			(const char *&subject, infx_reqvar *data, bool quoteval, apr_pool_t *mp, const char *begintok = "$");
			bool			setStrTransform			(const char *&subject, infx_reqvar *data, apr_pool_t *mp, const char *cmd = "URLENCODE");
			char			*getStrURLEncode		(const char *subject);
			char			*getStrURLDecode		(const char *subject);
			bool			isStrTokenMatch			(const char *subject, const char *token, int start); // if token passed matches to subject@start + length of token
			bool			doParseTokenString		(const char *&subject, apr_array_header_t *&sarray, int &count, apr_pool_t *mp, const char *begintok = "$");
			bool			doExtractTokenString	(const char *&varlist, infx_ws_var *&root, int &count, apr_pool_t *mp);
			bool			doExpandParsedString	(const char *&subject, infx_ws_var *varMAP, infx_reqvar *reqVAR, bool quoteval, apr_pool_t *mp, const char *begintok = "$");
			/*
				These functions are in {prefix}_array
			*/
			bool			isInList				(const char *subject, bool sensitive, ...); // checks if subject is in a list of variable const char * arguments
			bool			isInAssocArray			(apr_hash_t *ht, const char *key);
			bool			setAssocArrayRow		(apr_hash_t *&ht, const char *key, void *value, apr_pool_t *mp);
			bool			getAssocArrayRow		(apr_hash_t *ht, const char *key, void *&value, apr_pool_t *mp);
			bool			delAssocArrayRow		(apr_hash_t *&ht, const char *key, apr_pool_t *mp);
			void			*loopAssocArray			(apr_hash_t *ht, apr_hash_index_t *&in, apr_pool_t *mp);
			bool			nvpParseHash			(const char *subject, apr_hash_t *&container, infx_ws_cmd *&list, apr_pool_t *mp, int &count, char *listsep = "&", char *pairsep = "=");
			void			doExplode				(const char *subject, const char *delimiter);
			void			doExplode				(const char *subject, const char *delimiter, apr_array_header_t *&sarray);
			int				getIntSplitMax			();
			int				getIntSplitMax			(apr_array_header_t *sarray);
			char			*getStrImplodeByVal		(const char *delimiter, int s, int e);
			char			*getStrImplodeByVal		(const char *delimiter, int s, int e, apr_array_header_t *sarray);
			char			*getStrExplodeByNum		(int n);
			char			*getStrExplodeByNum		(int n, apr_array_header_t *sarray);

		private:
			/*
				These functions are in the root doc
			*/
			void			stdLog					(logging &l, const char *f, const char *fx, int ln, int lvl = -1, const char *msg = "");
			void			extLog					(logging &l, const char *f, const char *fx, int ln, int lvl, const char *msg, ...);
			int				echoLog					(logging &l, int c, const char *f, const char *fx, int ln, const char *a, int lvl, bool irl, const char *msg, ...);
			/*
				These functions are in {prefix}_string
			*/
			// input output of variable data into the host struct according to a map
			bool			doPushPullMapVars		(infx_ws_var *&tMAP, infx_reqvar *&tDATA, const char *&var, const char *&value_IO, int mode = 0);
	};
	// rules check
	class security {
		// private
		private:
			int						dbglvl, retcode;
			request_rec				*apache;
			server_rec				*server;
			infx_config				*config;
			infx_tx_rec				*request;
			apr_pool_t				*local;
		// function list
		public:
			// constructor
			security(request_rec *r);
			// destructor
			~security(){};
			// function list
			void	resetDBGLvl	(int newlvl); // reset debugging level
			void	newRequest	(int &httpRes); // handle new requests through handler functions
			void	setURIFile	(int &httpRes); // set the file to be sent back to user
			void	doResponse	(int &httpRes); // cookies or allow to complete
		private:
			bool	defRequest	(infx_tx_rec *&aReq); // create default request structure and fill default enviornment
			void	getRequest	(infx_tx_rec *&aReq); // parse the request and fill a default request with real data
			void	askRequest	(infx_tx_rec *&aReq); // interogate the request to make sure is valid
			bool	resCheck	(infx_tx_rec *aReq); // check the resource count being used
			bool	devCheck	(infx_tx_rec *aReq); // check the resource against dev mode/list
			bool	appCheck	(infx_tx_rec *aReq); // check if a resource file is being called
			int		setCookie	(char *name, char *value, char *domain, int expiration = 900, int secure = 0); // set cookies for exit
			void	stdLog		(logging &l, const char *f, const char *fx, int ln, int lvl = -1, const char *msg = "");
			void	extLog		(logging &l, const char *f, const char *fx, int ln, int lvl, const char *msg, ...);
			bool	critLog		(logging &l, const char *error);
			int		echoLog		(logging &l, int c, const char *f, const char *fx, int ln, const char *a, int lvl, bool irl, const char *msg, ...);
	};
}