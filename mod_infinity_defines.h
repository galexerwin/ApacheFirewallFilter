// define some basics for our app
#define INFX_BASE_PERM 0x0400|0x0200|0x0100|0x0040|0x0020|0x0010|0x0040|0x0010
// directorys
#if defined(WIN32)
#define INFX_ROOT_SQL ((char *)"127.0.0.1")
#else
#define INFX_ROOT_SQL ((char *)"odb.brownstone-ind.info")
#endif
// redefine to shorten these 
#define APLOG(msg,...) ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, NULL, msg, __VA_ARGS__);
// set module to use our name in the module logging
#ifdef APLOG_USE_MODULE
APLOG_USE_MODULE(infinity_security);
#endif
// first entry for all logs
#define INFX_LOG_DATA						__FILE__,__FUNCTION__,__LINE__
// status codes
#define MOD_INFINITY_OFFLINE				0
#define MOD_INFINITY_ONLINE					1
#define MOD_INFINITY_SINGLEUSER				2
#define RESBODY_STATUS_NOT_READ				0   /* we were not configured to read the body */
#define RESBODY_STATUS_ERROR				1   /* error occured while we were reading the body */
#define RESBODY_STATUS_PARTIAL				2   /* partial body content available in the brigade */
#define RESBODY_STATUS_READ_BRIGADE			3   /* body was read but not flattened */
#define RESBODY_STATUS_READ					4   /* body was read and flattened */
#define IF_STATUS_NONE						0
#define IF_STATUS_WANTS_TO_RUN				1
#define IF_STATUS_COMPLETE					2
#define OF_STATUS_NOT_STARTED				0
#define OF_STATUS_IN_PROGRESS				1
#define OF_STATUS_COMPLETE					2
#define INPUT_MUSTBE_NUMBER					0
#define INPUT_MUSTBE_CHAR					1
#define INPUT_MUSTBE_ALPHANUM				2
#define INPUT_MUSTBE_ALPHANUM_PERIOD		3
#define INPUT_MUSTBE_ALPHANUM_UNDERSCORE	4
// data handling
#define DEFAULT_POST_ENCTYPE "application/x-www-form-urlencoded"
#define XMLDATA_RAW1_ENCTYPE "application/xml"
#define XMLDATA_RAW2_ENCTYPE "text/xml"
// defaults
#define NOT_SET                    -1l
#define NOT_SET_P         ((void *)-1l)
// structure declarations
typedef struct infx_engine infx_engine; // core for global set once data
typedef struct infx_eregex infx_eregex; // saved regex strings
typedef struct infx_config infx_config; // server configuration
typedef struct infx_reqvar infx_reqvar; // collection of all request variables
typedef struct infx_tx_rec infx_tx_rec; // per request configuration
typedef struct infx_geoIPX infx_geoIPX; // geoIP database objects
typedef struct infx_ws_rec infx_ws_rec;	// structure of webservice records
typedef struct infx_tx_nvp infx_tx_nvp; // structure of name value pairs
typedef struct infx_tx_tcb infx_tx_tcb; // structure of label, options, and pool to pass to a table callback function
typedef struct infx_tx_con infx_tx_con; // structure of webservice db conn params
typedef struct infx_ws_cmd infx_ws_cmd; // structure of linear cmds
typedef struct infx_ws_var infx_ws_var; // structure of linear variable paths
typedef struct infx_xchild infx_xchild;	// linked list of xml nodes
typedef struct infx_sqlset infx_sqlset; // linked list of sql rows 
typedef struct infx_xmlset infx_xmlset;	// structure containing a hash table of xml children
// structure definitions
struct infx_engine {
    apr_pool_t			*mp;		// pool
	apr_table_t			*paths;		// infinity application paths
	int					mode;		// online or offline or single user
};
struct infx_config
{
	apr_pool_t			*mp;
	bool				enabled;
	infx_engine			*infinity;
	bool				in_dev_mode;
	bool				xauth_allowed;
	int					max_per_client;
	bool				use_logging;
	char				*logging_msk;
	char				*logging_dir;
	int					logging_lvl;
	char				*dblink;
	char				*dbserv;
	char				*dbuser;
	char				*dbpass;
	char				*dbfile;
	char				*srv_domain_corename; // used for path translation
	char				*srv_domain_aliases; // aliases by which this server goes by
	char				*srv_domain_admin_email;
	char				*srv_domain_admin_sms;
	char				*srv_class_level;
	char				*srv_bypass_ips;
	char				*srv_uawl_domains; // domains that are allowed on reverse lookup if ua is not specified 
	char				*srv_seblock_paths;
	char				*ext_allow_nolimit; // extensions that if found have no limit
	char				*ext_allow_wwlimit; // extensions that must be checked with referer
};
struct infx_tx_rec {
	// server structures
    apr_pool_t			*mp;
	infx_config			*server;
    request_rec			*r;	
	// inbound data
	// request
	char				*i_request_id;
	apr_time_t			i_request_time;
    char				*i_request_host;
    char				*i_request_ip;
    unsigned int		i_request_port;
	char				*i_request_line;
    char				*i_request_uri;
	char				*i_request_xtn;
	char				*i_request_method;
	char				*i_request_protocol;
	// remote
	char				*i_remote_ip;
    char				*i_remote_user;
	char				*i_remote_host;
	char				*i_remote_domain;
	char				*i_remote_useragent;
	char				*i_remote_referer;
	char				*i_remote_proxies;
	// arguments
	char				*i_query_string;
	apr_table_t			*i_query_array;
	// cookies
    char				*i_cookie_unique;
    char				*i_cookie_session;
	char				*i_cookie_authtoken;
	// decision support data
	// paths
	char				*d_mode_class;
	char				*d_path_app;
	char				*d_path_fun;
	char				*d_path_var;
	char				*d_path_domain;
	char				*d_path_root;
	char				*d_path_full;
	char				*d_path_half;
	char				*d_target_r;
	char				*d_target_m;
	char				*d_target_c;
	char				*d_target_x;
	char				*d_target_s;
	char				*d_base_serving;
	char				*d_base_shared;
	char				*d_base_specific;
	char				*d_shared_class;
	char				*d_shared_xsl;
	char				*d_shared_xml;
	char				*d_specific_root;
	char				*d_specific_class;
	char				*d_specific_xsl;
	char				*d_specific_xml;
	// bool
	unsigned int		d_request_is_auth;
	unsigned int		d_request_is_app;
	unsigned int		d_request_is_top;
	unsigned int		d_peer_is_local;
	unsigned int		d_peer_is_dev;
	unsigned int		d_peer_is_dnsv;
	unsigned int		d_mode_is_dev;
	// debug
	unsigned int		d_debug_level;
	apr_table_t			*d_debug_classes;
	// outbound data
	unsigned int		o_exit_kill; // kill the connection
	char				*o_exit_http; // to generate an http code
	char				*o_exit_uri; // to tell the rename engine where to find the resource
	char				*o_exit_code; // code for the application to handle the error
	char				*o_infinity_hash; // hash generated by sql server
	char				*o_infinity_unique; // unique generated by apache
	char				*o_infinity_session; // sessiond id generated by sql server		
};
struct infx_reqvar
{
	apr_xml_doc	*xmlparsed;	// parsed xml
	const char	*raw;		// raw data received from a post
	apr_table_t *req;		// selected items from the request structure, never empty
	apr_table_t	*get;		// nvp get data 
	apr_table_t	*post;		// nvp post data
	apr_table_t	*xml;		// nvp of parsed xml
	apr_table_t	*env;		// raw copy of enviornment
	apr_table_t *out;		// output variables
	infx_sqlset *sql;		// sql row storage
	int			postc;		// form count to not have to perfom table is empty function
	int			xmlc;		// xml count to not have to perfom table is empty function
	int			getc;		// get count to not have to perfom table is empty function
	int			sqlc;		// sql count
	bool		xmlInForm;  // was xml embedded 
	const char	*origXMLFName; // the original xml field name
};
struct infx_tx_tcb
{
	apr_pool_t	*mp; // pool
	request_rec	*r; // request record
	int			mode; // mode for table callback
	// additional options ????
};
struct infx_ws_rec
{
	int			paramcount; // count of params
	apr_hash_t	*paramdefs; // actual params
	infx_tx_con	*connparams; // database connection params
	infx_ws_cmd	*wscommands; // linear list of commands to issued
};
struct infx_tx_nvp
{
	const char	*name; // name portion
	apr_size_t	namelen; // length of name
	char		nameshort; // short letter for switch
	void		*value; // value as void
	apr_size_t	valuelen; // length maybe zero
	const char	*valtypelong; // long type
	char		valtypeshort; // short type for switch
	const char	*pairsep; // default is '='
	const char	*listsep; // default is '&'
	bool		isArray; // default is false
	infx_tx_nvp *arrMembers; // contains each member of the array
};
struct infx_tx_con
{
	char		*dbtype;
	char		*dbserv;
	char		*dbuser;
	char		*dbpass;
	char		*dbfile;
	int			dbvaryc;	// count of params preparsed
	char		*dbquery;  // the query that will be ran at execution time
	infx_ws_var	*dbvaries; // collections that need be filed in before prior to execution
};
struct infx_ws_cmd
{
	char		*cmd;  // the command to lookup   	
	infx_ws_cmd	*next; // next command structure
};
struct infx_ws_var
{
	char		*type;	// the collection the variable is in
	char		*name;  // the name of the variable 
	char		*var; // the actual variable
	infx_ws_var	*next; // next command structure
};
struct infx_xchild	
{
	char					*parent_n; // parent tagname
	char					*name; // tagname
	char					*value; // tagvalue
	bool					isempty; // is empty tag
	bool					isfirst; // is first child
	bool					isparent; // if this the parent because there are no children
	apr_table_t				*attributes; // attributes
	int						parent_family_size; // the number of direct children belonging to this parent
	const apr_xml_elem		*self; // this node
	const apr_xml_elem		*parent; // only one parent node allowed
	const apr_xml_elem		*children; // children pointer to first child
	infx_xchild				*prev; // pointer to previous sibling
	infx_xchild				*next; // pointer to next sibling
};
struct infx_xmlset
{
	char		*path; // original path value
	char		*name; // name of the top level node we started an array at
	char		*value; // value of this tag if this is a simple set with no children
	apr_table_t	*attributes; // attributes of this tag if this is a simple set with no children
	int			setcount; // count of the infx_xchild structs in the table
	apr_hash_t	*setdata; // actual hash table
};
struct infx_sqlset
{
	int			pos;  // position
	int			rows; // rowcount
	int			cols; // column count
	apr_table_t	*fields; // fields in table form
	infx_sqlset	*next; // next set of fields in the rowset
	// could add meta if needed
};
// static members
static int server_limit, thread_limit;
// global members
static infx_engine *infx_exec = NULL;
// function declarations
infx_engine	*modinfinity_create		(server_rec *s, apr_pool_t *mp, apr_pool_t *temp, int mode);
void		modinfinity_shutdown	(infx_engine *ixcore);
// cleanup a request
static apr_status_t cleanup_request(void *data) {
	// variables
    infx_tx_rec	*aReq = (infx_tx_rec *)data;
	// if already gone then just return    
    if (aReq == NULL) return APR_SUCCESS;    
	// todo
	// return
    return APR_SUCCESS;
}