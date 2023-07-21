/*
	Class:			Tools 
	Segment:		String Library 
	Create Date:	6/16/2012
	Edit Date:		6/16/2012
	Description:	Contains string manipulation functions
*/
// include mod_infinity
#include "mod_infinity.h"
// mod_infinity namespace
namespace modinfinity
{
	// declare included namespaces
	using namespace std;
	/*
		String Crypto
	*/
	char *tools::b64HMACSHA1(const char *input, const char *key)
	{
		// variables
		int				dbl = -1;
		CkCrypt2		crypt;
		// create logger
		logging logger(apache, server, local); dbl = APLOG_TRACE8;
		// breakpoint
		stdLog(logger, INFX_LOG_DATA, dbl);
		// unlock the params
		if (!(crypt.UnlockComponent(KCKCrypt)))
		{
			// log error
			stdLog(logger, INFX_LOG_DATA, APLOG_WARNING, crypt.lastErrorText());
			// return null string
			return apr_pstrdup(local, ""); 
		}
		// breakpoint
		stdLog(logger, INFX_LOG_DATA, dbl);
		//  set the EncodingMode to b64
		crypt.put_EncodingMode("base64");
		// char set tp utf-8
		crypt.put_Charset("utf-8");
		//  set the hash algorithm
		crypt.put_HashAlgorithm("sha-1");
		// breakpoint
		stdLog(logger, INFX_LOG_DATA, dbl);
		//  set the HMAC key
		crypt.SetHmacKeyString(key);
		// breakpoint
		stdLog(logger, INFX_LOG_DATA, dbl);
		// return
		return apr_pstrdup(local, crypt.hmacStringENC(input));
	};
	/*
		Mid-Level String Manipulation functions
	*/
	// remove quotes from string
	char *tools::getStrUnQuoted(const char *subject)
	{
		// variables
		char *s = (char *)subject;
		char q  = (char)39;
		int  l  = (int)strlen(subject), i = 0, j = 0;
		// create logger
		logging logger(apache, server, local);
		// loop forward until there is an actual character
		for (i = 0; i < l; i++)
			if (!isspace(s[i]))
				break;
		// strip the first quote
		if (s[i] == q)	s = strSub(s, i + 1, 0, local);
		// loop reverse until there is an actual character
		for (j = (int)strlen(s); j; --j)
			if (s[j] && !isspace(s[j]))
				break;
		// strip the last quote
		if (s[j] == q)	s = strSub(s, 0, j, local);
		// return
		return s;
	};
	// get sql escaped quoted string
	char *tools::getStrEscapeQuote(const char *subject)
	{
		// variables
		char *output, *chksql, *quotes;
		char q = (char)39;
		// set output
		chksql = apr_pstrdup(local, strToLower(subject));
		output = apr_pstrdup(local, "");
		quotes = ptr(q, local);
		/*// check if there are even quotes
		if (find(subject, quotes) == -1) 
			return (char *)subject;
		// explode string into parts based on a space
		doExplode(subject, " "); // what if this is in the middle? what if the space char is between the anchors?
		// iterate over each member
		for (int a = 1; a < (getIntSplitMax() + 1); a++)
		{
			// get string
			char	*s = getStrExplodeByNum(a);
			int		x, y, z;
			// prepopulate
			x = find(s, quotes); // find initial quote
			y = find(s, quotes, 1); // find quote after first char
			z = (int)strlen(s);
			// if no quotes or just anchor quotes
			if ( x == -1 || (!x && y == (z - 1)) )
			{
				// add string no changes
				output = apr_pstrcat(local, output, s, " ", NULL);
			}
			// check if x
			else if (!x && s[z - 1] == q)
			{
				// convert all embedded quotes into fully escaped quotes
				output = apr_psprintf(local, "%s'%s' ", output, getStrReplace(strSub(s, 0, z - 1, local), "'", "''''")); 
			}
			else
			{
				// convert all quotes
				output = apr_psprintf(local, "%s%s ", output, getStrReplace(strSub(s, 0, z - 1, local), "'", "''''")); 
			}
		}*/
		// trim the return
		return strTrim(output, local);



		// iterate over string
		/*
		stdLog(logger, INFX_LOG_DATA, APLOG_DEBUG, "TESTING THE ESCAPE QUOTE");
		stdLog(logger, INFX_LOG_DATA, APLOG_DEBUG, getStrEscapeQuote(subject));
		stdLog(logger, INFX_LOG_DATA, APLOG_DEBUG, getStrEscapeQuote("select 'tuscan's sun' as test2"));
		stdLog(logger, INFX_LOG_DATA, APLOG_DEBUG, getStrEscapeQuote("Wild flowers are a girl's best friend"));		
		
		while(!((p = find(subject, ptr(q, local), p)) == -1))
		{
			// get chars before and after and after
			char l = subject[p - 1];
			char n = subject[p + 1];
			char x = subject[p + 2];
			// copy the character prior to encounter
			o = apr_psprintf(local, "%s%s", o, strSub(subject, pp, p, local));
			// check the last and next to see if alnum
			if		(isalnum(l) && isalnum(n))
			{
				// insert an escaped quote
				o = apr_psprintf(local, "%s''", o);
				// move cursor past current find and set the substr marker to the next letter
				pp = p++;
			}
			// check if this a typical sql empty quoted space
			else if (isspace(l) && n == q && isspace(x))
			{
				// insert an escaped quote
				o = apr_psprintf(local, "%s''", o);
				// move cursor two spaces for both quotes
				pp = p = (p + 2);
			}
			// check if this a non-empty sql quote
			else if (n && isspace(l) && isalnum(n) && !(find(subject, ptr(q, local), p + 1) == -1))
			{


			}
		}*/

	};
	// replace string part
	char *tools::getStrReplace(const char *subject, const char *token, const char *replacement)
	{
		// variables
		string	base = subject;
		int		pos  = base.find(token, 0);
		// iterate until end of string
		while(!(pos == string::npos))
		{
			// perform replacement
			base.insert(pos, replacement);
			// perform erase
			base.erase(pos + (int)strlen(replacement), (int)strlen(token));
			// find string
			pos = base.find(token, pos);
		}
		// return
		return apr_pstrdup(local, base.c_str());
	};
	// transform subject string using tokens and input data
	bool tools::getStrTransform(const char *&subject, infx_reqvar *data, bool quoteval, apr_pool_t *mp, const char *begintok)
	{
		// variables
		int			dc = 0;
		infx_ws_var	*var = NULL;
		// extract token string
		if (!doExtractTokenString(subject, var, dc, mp))
			return false;
		// expand string
		if (!doExpandParsedString(subject, var, data, quoteval, mp, begintok))
			return false;
		// return
		return true;
	};
	// transform subject string using tokens and input data and then run additional commands on the data
	bool tools::setStrTransform(const char *&subject, infx_reqvar *data, apr_pool_t *mp, const char *cmd)
	{
		// variables
		int			dc = 0, ixl = 0, dbl = -1;
		const char	*var, *begintok = "$";
		infx_ws_var	*varMAP = NULL;
		bool		quoteval = false; // can be changed by requesting it in the cmd
		// create logger
		logging logger(apache, server, local);
		// reparse the command
		ixl = find(cmd, "_");
		cmd = (!(ixl == -1)) ? strSub(cmd, 0, ixl, mp) : cmd;
		// breakpoint
		stdLog(logger, INFX_LOG_DATA, dbl, cmd);
		// extract token string
		if (!doExtractTokenString(subject, varMAP, dc, mp))
			return false;
		// breakpoint
		stdLog(logger, INFX_LOG_DATA, dbl);
		// expand string as requested
		if (!doExpandParsedString(subject, varMAP, data, quoteval, mp, begintok))
			return false;
		// breakpoint
		stdLog(logger, INFX_LOG_DATA, dbl); 
		// eventually will have to implement a loop on the varMAP and submit new values for every var found
		// transform string
		if		(!comparecase(cmd, "URLENCODE")) 
		{
			// breakpoint
			stdLog(logger, INFX_LOG_DATA, dbl);
			// exec command on subject
			subject = getStrURLEncode(subject); 
		}
		else if (!comparecase(cmd, "URLDECODE")) 
		{
			// breakpoint
			stdLog(logger, INFX_LOG_DATA, dbl);
			// exec command on subject
			subject = getStrURLDecode(subject); 
		}
		else if (!comparecase(cmd, "STRIPCLRF"))  
		{
			// breakpoint
			stdLog(logger, INFX_LOG_DATA, dbl);
			// exec command on subject
			subject = strNoCLRF(subject, mp); 
		}
		// breakpoint
		stdLog(logger, INFX_LOG_DATA, dbl);
		// set the transform value back
		if (!doPushPullMapVars(varMAP, data, var, subject, 1))
			return false;
		// breakpoint
		stdLog(logger, INFX_LOG_DATA, dbl);
		// return
		return true;
	};
	// encode subject string
	char *tools::getStrURLEncode(const char *subject)
	{
		// variables
		string  unreserved = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.~";
		char	*result = apr_pstrdup(local, "");
		int		dbl = -1;
		// logger
		logging logger(apache, server, local);
		// break point
		stdLog(logger, INFX_LOG_DATA, dbl);
		// return result if subject is null
		if (isStrNull(subject) || !strlen(subject)) { return strNotNull(subject); }
		// break point
		stdLog(logger, INFX_LOG_DATA, dbl);
		// iterate over the input
		for (size_t i = 0; i < strlen(subject); i++)
		{
			// plug var
			char *s = ptr(subject[i], local);
			int	 x = int(subject[i]);
			// encode if reserved
			if		(x == 32)								{ result = apr_pstrcat(local, result, "%20", NULL); }
			else if (unreserved.find(s) == string::npos)	{ result = apr_psprintf(local, "%s%%%.2X", result, x); }
			else											{ result = apr_psprintf(local, "%s%c", result, subject[i]); }
		}
		// break point
		stdLog(logger, INFX_LOG_DATA, dbl);
		// return
		return result;
	};
	// decode subject string
	char *tools::getStrURLDecode(const char *subject)
	{
		// variables
		char *result = apr_pstrdup(local, "");
		int	 dbl = -1, ii;
		// logger
		logging logger(apache, server, local); //dbl = APLOG_TRACE8;
		// break point
		stdLog(logger, INFX_LOG_DATA, dbl);
		// return result if subject is null
		if (isStrNull(subject) || !strlen(subject)) { return strNotNull(subject); }
		// break point
		stdLog(logger, INFX_LOG_DATA, dbl);
		// iterate over the input
		for (size_t i = 0; i < strlen(subject); i++)
		{
			// if this is a percent sign
			if (int(subject[i]) == 37)
			{
				// get the integer/hex embedded in the string
				sscanf(strSub(subject, (i + 1), 2, local), "%x", &ii);
				// cast the integer to a char
				char ch = static_cast<char>(ii);
				// get result
				result = apr_psprintf(local, "%s%c", result, ch);
				// move the pointer 2 spaces beyond percent sign
				i = i + 2;
			}
			else { result = apr_psprintf(local, "%s%c", result, subject[i]); }
		}
		// break point
		stdLog(logger, INFX_LOG_DATA, dbl);
		// return
		return result;
	};
	// is token a match to subject @ start + length of token
	bool tools::isStrTokenMatch(const char *subject, const char *token, int start)
	{
		// first do sanity checks
		// no null strings
		if (isStrNull(subject) || isStrNull(token))		
			return false;
		// start must be within range
		if (start < 0 || start > (int)strlen(subject) || start + (int)strlen(token) > (int)strlen(subject))	
			return false;
		// use std string compare to substring subject@start, length of token, and token
		if (string(subject).compare(start, strlen(token), token) == OK) 
			return true;
		// return
		return false;
	};
	/*
		High-Level String Parsing functions
	*/
	// parse token string
	bool tools::doParseTokenString(const char *&subject, apr_array_header_t *&sarray, int &count, apr_pool_t *mp, const char *begintok)
	{
		// variables
		int		dbl = APLOG_TRACE8;
		char	*var;
		// create logger
		logging logger(apache, server, local);
		// breakpoint
		stdLog(logger, INFX_LOG_DATA, dbl);
		// make sure string has length
		if (!strlen(strNotNull(subject)))	{ return false; }
		// breakpoint
		stdLog(logger, INFX_LOG_DATA, dbl);
		// check if the string only includes delimiter and is the entire string
		if (find(subject, begintok) == -1)	{ return true; }
		// breakpoint
		stdLog(logger, INFX_LOG_DATA, dbl);
		// create the split chars database if not created
		if (sarray == NULL)	{ sarray  = apr_array_make(mp, 0, sizeof(char *)); }
		// breakpoint
		stdLog(logger, INFX_LOG_DATA, dbl);
		// always reset everything
		apr_array_clear(sarray);
		// breakpoint
		stdLog(logger, INFX_LOG_DATA, dbl);
		// set return count == 0
		count = 0;
		// breakpoint
		stdLog(logger, INFX_LOG_DATA, dbl);
		// iterate as long a token is found
		for (int z = 0, y = 0; z < (int)strlen(subject); z++)
		{
			// check if this item is the beginning of the token
			if (subject[z] == begintok[0])
			{
				// loop until we find end of variable
				for (y = (z + 1); y < (int)strlen(subject); y++)
					if (!isalnum(subject[y]) && !isInList(strSub(subject, y, 1, local), false, "$", ".", "-", "_", "#", "?", "=", NULL))
						break;
				// create variable
				var = strTrim(strSub(subject, z, y - z, local), local);
				// check if the variable was curly bracket enclosed
				if (z && subject[z - 1] == '{')
					var = apr_pstrcat(local, "{", var, "}", NULL);
				// place substring into que
				*(char **) apr_array_push(sarray) = apr_pstrdup(sarray->pool, var);
				// increment count
				count++;
				// move pointer to beyond the variable length
				z = y;
			}
		}
		// breakpoint
		stdLog(logger, INFX_LOG_DATA, dbl);
		// return
		return true;
	};
	// extract token string
	bool tools::doExtractTokenString(const char *&varlist, infx_ws_var *&root, int &count, apr_pool_t *mp)
	{
		// variables
		apr_array_header_t	*pvlist = NULL;
		apr_table_t			*assign = apr_table_make(local, 0);
		int					dbl = -1, pos = 0;
		char				*var, *col, *key;
		// logger
		logging logger(apache, server, local); dbl = APLOG_TRACE8;
		// break point
		stdLog(logger, INFX_LOG_DATA, dbl);
		// if no tokens exist then escape
		if (find(varlist, "$") == -1) return true;
		// parse string for variable collections
		if (doParseTokenString(varlist, pvlist, count, local))
		{
			// iterrate over returned and make sure collections match used collections
			// xml, form, get, env, json
			for (int j = 0, k = 0; j < pvlist->nelts; j++)
			{
				// break point
				stdLog(logger, INFX_LOG_DATA, dbl);
				// retrieve precheck var
				var = ((char**)pvlist->elts)[j];
				// break point
				stdLog(logger, INFX_LOG_DATA, dbl);
				// check if the variable is in this list already
				// avoid duplicate entries
				if (!(apr_table_get(assign, var) == (char *)0)) { continue; }
				else											{ apr_table_set(assign, var, "1"); }
				// break point
				stdLog(logger, INFX_LOG_DATA, dbl);
				// find collection/name delimiter
				pos = find(var, "."); // format of vars is collection.name
				col = strTrimIf(strTrimIf(strSub(var, 1, pos - 1, local), "$", local, 0, true), "{", local, 0, true); 
				key = strSub(var, pos + 1, 0, local);
				// break point
				stdLog(logger, INFX_LOG_DATA, dbl);
				// check if collection is valid
				if (pos == -1 || !isInList(col, false, "xml", "post", "get", "env", "json", "out", "sql", "req", NULL))
				{
					// return error
					zErrMsg = apr_pstrdup(mp, "Invalid collection.");
					// return
					return false;
				}
				// break point
				stdLog(logger, INFX_LOG_DATA, dbl);
				// make sure that only alphanum underscore dash is captured
				for (k = 0; k < (int)strlen(key); k++)
					if (!isalnum(key[k]) && !isInList(strSub(key, k, 1, local), false, ".", "_", "-", "#", "?", "=", NULL))
						break;
				// break point
				stdLog(logger, INFX_LOG_DATA, dbl);
				// set key
				key = strSub(key, 0, k, local);
				// break point
				stdLog(logger, INFX_LOG_DATA, dbl);
				// check if this is linked list zero
				if (!j)
				{
					// break point
					stdLog(logger, INFX_LOG_DATA, dbl);
					// assign root node
					root = (infx_ws_var *)apr_palloc(mp, sizeof(infx_ws_var));
					// check if memory was assigned successfully
					if (root == NULL)
					{
						// return error
						zErrMsg = apr_pstrdup(mp, "Memory allocation error.");
						// return
						return false;
					}
					// add root entry data
					root->name = apr_pstrdup(mp, key);
					root->type = apr_pstrdup(mp, col);
					root->var  = apr_pstrdup(mp, var);
					root->next = NULL;
				}
				else
				{
					// break point
					stdLog(logger, INFX_LOG_DATA, dbl);
					// set the pointer to equal the root node
					infx_ws_var	*varptr = root;
					// check if the pointer we receiver is NULL
					if (!(varptr == NULL))
					{
						// break point
						stdLog(logger, INFX_LOG_DATA, dbl);
						// find next
						while (!(varptr->next == NULL))
							varptr = varptr->next;
						// break point
						stdLog(logger, INFX_LOG_DATA, dbl);
						// create memory block for pointer
						varptr->next = (infx_ws_var *)apr_palloc(mp, sizeof(infx_ws_var));
						// check if memory was assigned successfully
						if (varptr->next == NULL)
						{
							// return error
							zErrMsg = apr_pstrdup(mp, "Memory allocation error.");
							// return
							return false;
						}
						// break point
						stdLog(logger, INFX_LOG_DATA, dbl);
						// point to it
						varptr = varptr->next;
						// break point
						stdLog(logger, INFX_LOG_DATA, dbl);
						// add data
						varptr->name = apr_pstrdup(mp, key);
						varptr->type = apr_pstrdup(mp, col);
						varptr->var  = apr_pstrdup(mp, var);
						varptr->next = NULL;
					}
					// root should not be null
					else
					{
						// return error
						zErrMsg = apr_pstrdup(mp, "Assignment error.");
						// return
						return false;
					}
				}
			}
		}
		// if we can not load there is a problem
		else
		{
			// return error
			zErrMsg = apr_pstrdup(mp, "Parser error.");
			// return
			return false;
		}
		// break point
		stdLog(logger, INFX_LOG_DATA, dbl);
		// return
		return true;
	};
	// parsed token string expansion
	bool tools::doExpandParsedString(const char *&subject, infx_ws_var *varMAP, infx_reqvar *reqVAR, bool quoteval, apr_pool_t *mp, const char *begintok)
	{
		// variables
		int			dbl = -1;
		const char	*raw, *var, *value;
		// create logger
		logging logger(apache, server, local); dbl = APLOG_TRACE8;
		// breakpoint
		stdLog(logger, INFX_LOG_DATA, dbl);
		// make sure string has length
		if (!strlen(strNotNull(subject)))	{ return false; }
		// breakpoint
		stdLog(logger, INFX_LOG_DATA, dbl);
		// make sure there are tokens before attempting to do anything to the string
		if (find(subject, begintok) == -1)	{ return true; }
		// breakpoint
		stdLog(logger, INFX_LOG_DATA, dbl);
		// make a copy of str
		raw = apr_pstrdup(local, subject);
		// empty original
		subject = apr_pstrdup(local, "");
		// breakpoint
		stdLog(logger, INFX_LOG_DATA, dbl);
		// iterate over the variable linked list
		while (!(varMAP == NULL))
		{
			// breakpoint
			stdLog(logger, INFX_LOG_DATA, dbl);
			// check for success
			if (!doPushPullMapVars(varMAP, reqVAR, var, value)) 
			{	
				// breakpoint
				stdLog(logger, INFX_LOG_DATA, dbl);
				// return
				return false;
			}
			// breakpoint
			stdLog(logger, INFX_LOG_DATA, dbl, apr_psprintf(local, "var %s, value %s", var, value));
			// set value
			raw = getStrReplace(raw, var, value);
		}
		// breakpoint
		stdLog(logger, INFX_LOG_DATA, dbl);
		// copy the rest of raw onto subject
		subject = apr_pstrcat(mp, subject, raw, NULL);
		// breakpoint
		stdLog(logger, INFX_LOG_DATA, APLOG_DEBUG, subject);
		// check string out for empty or unhandled markup
		if (!strlen(subject) || !(find(subject, begintok) == -1)) 
		{	
			// breakpoint
			stdLog(logger, INFX_LOG_DATA, dbl);
			// set error
			zErrMsg = apr_pstrdup(local, "Zero Length String Found! Aborting.");
			// return
			return false;
		}
		// breakpoint
		stdLog(logger, INFX_LOG_DATA, dbl);
		// return
		return true;
	};
	// input/output of variables in the request variable struct according to the varMAP
	bool tools::doPushPullMapVars(infx_ws_var *&tMAP, infx_reqvar *&tDATA, const char *&var, const char *&value_IO, int mode)
	{
		// variables
		int			dbl = -1;
		char		*type, *name;
		// create logger
		logging logger(apache, server, local); //dbl = APLOG_TRACE8;
		// breakpoint
		stdLog(logger, INFX_LOG_DATA, dbl);
		// check if the map is not null
		if (!(tMAP == NULL))
		{
			// breakpoint
			stdLog(logger, INFX_LOG_DATA, dbl);
			// setup the values
			type	= tMAP->type;
			name	= tMAP->name;
			var		= tMAP->var;
			tMAP	= tMAP->next;
			// breakpoint
			stdLog(logger, INFX_LOG_DATA, dbl, apr_psprintf(local, "type: %s, name %s, var %s", type, name, var)); 
			// find the data in the collections
			switch (type[0])
			{
				// get
				case 'g': 
					// get or set
					if (!mode)	{ value_IO = apr_table_get(tDATA->get, name); }
					else		{ apr_table_set(tDATA->get, name, value_IO); }
					// exit
					break;
				// env
				case 'e': 
					// get or set
					if (!mode)	{ value_IO = apr_table_get(tDATA->env, name); }
					else		{ apr_table_set(tDATA->env, name, value_IO); }
					// exit
					break;
				// post
				case 'p': 
					// get or set
					if (!mode)	{ value_IO = apr_table_get(tDATA->post, name); }
					else		{ apr_table_set(tDATA->post, name, value_IO); }
					// exit
					break;
				// xml
				case 'x': 
					// get or set
					if (!mode)	{ value_IO = apr_table_get(tDATA->xml, name); }
					else		{ apr_table_set(tDATA->xml, name, value_IO); }
					// exit
					break;
				// output
				case 'o': 
					// get or set
					if (!mode)	{ value_IO = apr_table_get(tDATA->out, name); }
					else		{ apr_table_set(tDATA->out, name, value_IO); }
					// exit
					break;	
				// output
				case 'r':
					// get or set
					if (!mode)	{ value_IO = apr_table_get(tDATA->req, name); }
					else		{ apr_table_set(tDATA->req, name, value_IO); }
					// exit
					break;	
				// sql only works in get mode
				case 's':
				if (!mode)
				{
					// parse the name for what we want
					// # == line number
					// ? == where left == right side
					// breakpoint
					stdLog(logger, INFX_LOG_DATA, dbl);
					// create a branch to main
					infx_sqlset *nset = tDATA->sql;
					// breakpoint
					stdLog(logger, INFX_LOG_DATA, dbl);		
					// variables
					char		*key, *test, *lval, *rval;
					int			row = 0;
					vector<int> tpos = findALL(name, ".");
					// breakpoint
					stdLog(logger, INFX_LOG_DATA, dbl);		
					// get line and key
					switch (name[0])
					{
						// line number seek
						case '#':
						// breakpoint
						stdLog(logger, INFX_LOG_DATA, dbl);
						// get row detail
						test = strSub(name, 1, tpos.at(0) - 1, local);
						row  = atoi(coalesce(strSub(test, 1, 0, local), "1"));
						key  = strSub(name, tpos.at(0) + 1, 0, local);
						stdLog(logger, INFX_LOG_DATA, dbl, test);
						stdLog(logger, INFX_LOG_DATA, dbl, key);
						stdLog(logger, INFX_LOG_DATA, dbl, apr_itoa(local, row));
						// iterate over until number is reached
						while (!(nset == NULL))
						{
							// check if this is the row
							if (row == nset->pos)
							{
								// set value
								value_IO = apr_table_get(nset->fields, key);
								// break
								break;
							}
							// move next
							nset = nset->next;
						}
						break;
						// named var seek
						case '?':
						// breakpoint
						stdLog(logger, INFX_LOG_DATA, dbl);
						// get row detail
						test = strSub(name, 1, tpos.at(0) - 1, local);
						key  = strSub(name, tpos.at(0) + 1, 0, local);
						lval = strSub(test, 0, find(test, "="), local);
						rval = strSub(test, find(test, "=") + 1, 0, local);
						// iterate over until number is reached
						while (!(nset == NULL))
						{
							// check if this is the row
							if (!comparecase(tabNotNull(nset->fields, lval), rval))
							{
								// set value
								value_IO = apr_table_get(nset->fields, key);
								// break
								break;
							}
							// move next
							nset = nset->next;
						}
						break;
					}
				}
				break;
			}
			// check if any data
			if (!mode && isStrNull(value_IO))
			{
				// set error
				zErrMsg = apr_psprintf(local, "Item->Type:%s->Name:%s Not Found. Aborting.", type, name);
				// return
				return false;
			}
		}
		// return
		return true;
	};
}