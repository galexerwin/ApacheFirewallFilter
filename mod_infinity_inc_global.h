// system wide global static features
// mod_infinity namespace
namespace modinfinity
{
	// declare included namespaces
	using namespace std;
	// apache cmd base enum
	typedef enum 
	{ 
		maxconn, enabled, domain, xauth, adminsms,
		logenable, logmask, 
		dblink, dbserv, dbuser, dbpass, dbfile,
		sclass, bypass, ualook, searchblock, 
		extnolimit, extwwlimit, webservice, authenticator
	} cmd_parts;
	// error enum
	typedef enum
	{ 
		auth_sql, 
		auth_response, 
		auth_provider, 
		auth_cookie, 
		auth_nosession,
		auth_canceled,
		auth_unauthorized,
		auth_nonce,
		auth_oidurl
	} error_log_t;
	// two digit iso codes for world countries
	const char xiso[254][3] = 
	{ 
		"--",
		"AP","EU","AD","AE","AF","AG","AI","AL","AM","CW",
		"AO","AQ","AR","AS","AT","AU","AW","AZ","BA","BB",
		"BD","BE","BF","BG","BH","BI","BJ","BM","BN","BO",
		"BR","BS","BT","BV","BW","BY","BZ","CA","CC","CD",
		"CF","CG","CH","CI","CK","CL","CM","CN","CO","CR",
		"CU","CV","CX","CY","CZ","DE","DJ","DK","DM","DO",
		"DZ","EC","EE","EG","EH","ER","ES","ET","FI","FJ",
		"FK","FM","FO","FR","SX","GA","GB","GD","GE","GF",
		"GH","GI","GL","GM","GN","GP","GQ","GR","GS","GT",
		"GU","GW","GY","HK","HM","HN","HR","HT","HU","ID",
		"IE","IL","IN","IO","IQ","IR","IS","IT","JM","JO",
		"JP","KE","KG","KH","KI","KM","KN","KP","KR","KW",
		"KY","KZ","LA","LB","LC","LI","LK","LR","LS","LT",
		"LU","LV","LY","MA","MC","MD","MG","MH","MK","ML",
		"MM","MN","MO","MP","MQ","MR","MS","MT","MU","MV",
		"MW","MX","MY","MZ","NA","NC","NE","NF","NG","NI",
		"NL","NO","NP","NR","NU","NZ","OM","PA","PE","PF",
		"PG","PH","PK","PL","PM","PN","PR","PS","PT","PW",
		"PY","QA","RE","RO","RU","RW","SA","SB","SC","SD",
		"SE","SG","SH","SI","SJ","SK","SL","SM","SN","SO",
		"SR","ST","SV","SY","SZ","TC","TD","TF","TG","TH",
		"TJ","TK","TM","TN","TO","TL","TR","TT","TV","TW",
		"TZ","UA","UG","UM","US","UY","UZ","VA","VC","VE",
		"VG","VI","VN","VU","WF","WS","YE","YT","RS","ZA",
		"ZM","ME","ZW","A1","A2","O1","AX","GG","IM","JE",
		"BL","MF", "BQ"
	};
	// compare 
	static int compare(const char *v1, const char *v2)
	{
		// return results
		return apr_strnatcmp(v1, v2);
	}
	// case insensitive
	static int comparecase(const char *v1, const char *v2)
	{
		// return results
		return apr_strnatcasecmp(v1, v2);
	}
	// coalesce
	static const char *coalesce(const char *v1, const char *v2)
	{
		// return
		return ((v1 && !(v1 == (const char *)0) && strlen(v1)) ? v1 : v2);
	}
	// null if
	static const char *nullif(const char *subject, const char *target, int insensitive = 0)
	{
		// test for case sensitive
		if (!insensitive)
			return (!apr_strnatcmp(subject, target)) ? NULL : subject;
		else
			return (!apr_strnatcasecmp(subject, target)) ? NULL : subject;
	}
	// datediff
	static double datediff(char *units, time_t start, time_t end)
	{
		// variables
		double  diff, res = 0;
		double	m = 60, h = (m * 60), d = (h * 24), w = (d * 7), M = (d * 30), y = (d * 365); 
		// sanity check
		if ( strlen(units) && start != (time_t)(-1) && end != (time_t)(-1) )
		{
			// cast time difference
			diff = difftime(end, start);
			// check if difference is not zero
			if (diff)
			{
				// switch the units
				switch (units[0])
				{
					case 'y': res = diff / y; break;
					case 'M': res = diff / M; break;
					case 'w': res = diff / w; break;
					case 'd': res = diff / d; break;
					case 'h': res = diff / h; break;
					case 'm': res = diff / m; break;
					case 's': res = diff; break;
				}
			}
		}
		// return results
		return res;
	}
	// elapsed time
	static double elapsed(clock_t start, clock_t end)
	{
		// return elapsed
		return ((double)(end - start) / (double)CLOCKS_PER_SEC);
	}
	// random number generator
	static int random()
	{
		#if APR_HAS_RANDOM
			unsigned char buf[2];
			if (apr_generate_random_bytes(buf, 2) == APR_SUCCESS)
			return (buf[0] << 8) | buf[1];
		#endif
		apr_uint64_t time_now = apr_time_now();
		srand((unsigned int)(((time_now >> 32) ^ time_now) & 0xffffffff));
		return rand() & 0x0FFFF;
	}
	// function to find data in a string
	static int find(const char *subject, const char *needle, int offset = 0)
	{
		// variables
		int l, p = 0;
		// offset the subject
		while (offset && p <= offset) subject++;
		// check required
		if (!needle || !subject || !strlen(subject) || !strlen(needle)) { return -1; }
		// if single char use ap_rind, else string
		if (strlen(needle) == 1)	{ l = ap_ind(subject, (char)needle[0]); }
		else						{ l = (int)string(subject).find(needle); l = (l == string::npos) ? -1 : l; }
		// return
		return l; 
	}
	// function to find in reverse
	static int rfind(const char *subject, const char *needle, int offset = 0)
	{
		// variables
		int l;
		// check required
		if (!needle || !subject || !strlen(subject) || !strlen(needle)) { return -1; }
		// if single char use ap_rind, else string
		if (strlen(needle) == 1)	{ l = ap_rind(subject, (char)needle[0]); }
		else						{ l = (int)string(subject).find_last_of(needle); }
		// return
		return (l == -1) ? l : (int)strlen(subject) - l; 
	}
	// function to chomp the rows
	static vector<int> findALL(const char *subject, const char *needle)
	{
		// variables
		vector<int> allpos;
		string		str = subject;
		int			pos = 0, found = 0;
		// loop over string
		while(!((pos = str.find(needle)) == string::npos))
		{
			// push onto stack
			allpos.push_back(pos + (found * (int)strlen(needle)));
			// erase for next run
			str.erase(pos, strlen(needle));
			// increment found to equal the found elements
			found++;
		}
		// return
		return allpos;
	}
	// is null check
	static bool isStrNull(const char *subject)
	{
		// variables
		bool rv = false;
		// check string
		if ((subject == (const char *)0)) 
			rv = true;
		// return
		return rv;
	}
	// clean not null string
	static char *strNotNull(const char *subject)
	{
		// variables
		char *output = "";
		// check string
		if (!(subject == (const char *)0) && strlen(subject) && apr_strnatcasecmp(subject, "NULL"))
			output = (char *)subject;
		// return
		return output; 
	}
	// clean not null table
	static char *tabNotNull(const apr_table_t *table, const char *subject)
	{
		// variables
		char *output = "";
		// check table
		if (!apr_is_empty_table(table) && !(apr_table_get(table, subject) == (const char *)0))
			output = (char *)apr_table_get(table, subject);
		// return
		return output;
	}
	// clean not null table or coalesce
	static char *tabALT(const apr_table_t *table, const char *subject, const char *alternate, apr_pool_t *mp)
	{
		// variables
		int			isEmpty = 0;
		const char	*valueAT = NULL;
		// set if table is empty
		isEmpty = apr_is_empty_table(table);
		// if not empty
		valueAT = (!isEmpty) ? apr_table_get(table, subject) : NULL;
		// return
		return apr_pstrdup(mp, coalesce(valueAT, strNotNull(alternate)));
	}
	// case functions
	static char *strToLower(const char *subject)
	{
		// variables
		char *output = strNotNull(subject);
		// lower string
		if (strlen(output)) ap_str_tolower(output);
		// return lowered string
		return output;
	}
	static char *strToUpper(const char *subject)
	{
		// variables
		char *output = strNotNull(subject);
		// lower string
		if (strlen(output)) ap_str_toupper(output);
		// return lowered string
		return output;
	}
	// partial string functions
	static char *strLeft(const char *subject, int count, apr_pool_t *mp)
	{
		// variables
		char *output = "", *negative = ""; 
		// make sure subject is not null
		if (mp == NULL)									return output;
		if (isStrNull(subject))							return output;
		if ((int)strlen(subject) < count && count > 0)	return (char *)subject;
		// create a copy
		if (count > 0) { output = apr_pstrmemdup(mp, subject, count); }
		else
		{
			// negative still can't be bigger than the original string
			if (abs(count) > (int)strlen(subject)) return (char *)subject;
			// set the prefix
			negative = apr_pstrmemdup(mp, subject, strlen(subject) + count);
			// return a prefixed copy
			output = apr_pstrdup(mp, ap_stripprefix(subject, negative));
		}
		// return output
		return output;
	}
	static char *strRight(const char *subject, int count, apr_pool_t *mp)
	{
		// variables
		char *output = "", *negative = ""; 
		// make sure subject is not null
		if (mp == NULL)									return output;
		if (isStrNull(subject))							return output;
		if ((int)strlen(subject) < count && count > 0)	return (char *)subject;
		if (count > 0)
		{
			// set the prefix
			negative = apr_pstrmemdup(mp, subject, strlen(subject) - count);
			// return a prefixed copy
			output = apr_pstrdup(mp, ap_stripprefix(subject, negative));
		}
		else
		{
			// negative still can't be bigger than the original string
			if (abs(count) > (int)strlen(subject)) return (char *)subject;
			// do a memdup of the string
			output = apr_pstrmemdup(mp, subject, abs(count));
		}
		// return
		return output;
	}
	static char *strSub(const char *subject, int start, int count, apr_pool_t *mp)
	{
		// variables
		char *output = "";
		// memory pool and positive len string required
		if (mp == NULL || isStrNull(subject))				
			return output;
		// sanity check string len
		if ((int)strlen(subject) < start || (int)strlen(subject) < (start + count))
			return (char *)subject;
		// if a negative number is passed then return right abs(x) characters
		if (count < 0)
			return strRight(subject, abs(count), mp);
		// if count is 0, we return whatever is left
		if (!count)
			return apr_pstrndup(mp, subject + start, strlen(subject));
		// finally return
		return apr_pstrndup(mp, subject + start, count);
	}
	// trim functions
	static char *strLTrim(const char *subject, apr_pool_t *mp)
	{
		// return if string is null
		if (!strlen(strNotNull(subject)) || mp == NULL) { return ""; }
		// iterate foward over subject
		while(isspace(*subject)) subject++;
		// return copy
		return apr_pstrdup(mp, subject);
	}
	static char *strRTrim(const char *subject, apr_pool_t *mp)
	{
		// return if string is null
		if (!strlen(strNotNull(subject)) || mp == NULL) { return ""; }
		// variables
		int pos = (int)strlen(subject);
		// iterate backward over subject
		while (pos > 0 && isspace(subject[pos - 1])) pos--;
		// return the string
		return apr_pstrndup(mp, subject, pos);
	}
	static char *strTrim(const char *subject, apr_pool_t *mp)
	{
		// return result if subject is null
		if (!strlen(strNotNull(subject)) || mp == NULL) { return ""; }
		// return data
		return strRTrim(strLTrim(subject, mp), mp);
	}
	static char *strTrimIf(const char *subject, const char *token, apr_pool_t *mp, int start = 0, bool exact = false)
	{
		// variables
		int	 pos = 0;
		// return result if subject, token, or memory is null
		if (!strlen(strNotNull(subject)) || !strlen(strNotNull(token)) || mp == NULL)
			return (char *)subject;
		// start can not be pass the strlen of subject
		if (start >= (int)strlen(subject)) 
			return (char *)subject;
		// start + strlen of toke may not go pass strlen of subject
		if ((start + (int)strlen(token)) >= (int)strlen(subject)) 
			return (char *)subject;
		// check if token even exists
		if ((pos = find(subject, token, start)) == -1) 
			return (char *)subject;
		// check if exact is requested
		if (exact && !(pos == start))
			return (char *)subject;
		// return string position
		return apr_pstrdup(mp, subject + (pos + (int)strlen(token)));
	}
	// transform functions
	static char *strNoCLRF(const char *subject, apr_pool_t *mp)
	{
		// variables
		char *output = apr_pstrdup(mp, "");
		// check string
		if (isStrNull(subject) || !strlen(subject)) return output;
		// iterate over the subject and strip line feeds and carriage returns
		for (size_t i = 0; i < strlen(subject); i++)
		{
			if (!isspace(subject[i]))
				output = apr_psprintf(mp, "%s%c", output, subject[i]);
			else if (i && !isspace(subject[i - 1]) && !isspace(subject[i + 1]))
				output = apr_psprintf(mp, "%s%c", output, subject[i]);
		}
		// return
		return output;
	}
	// char to char * convertor
	static char *ptr(char subject, apr_pool_t *mp)
	{
		// prepare stream and string
		stringstream	ss;
		string			s;
		// convert to string stream
		ss << subject;
		// convert to string
		ss >> s;
		// return
		return apr_pstrdup(mp, s.c_str());
	}
	// pad string
	static char *strPad(const char *subject, char *pad, size_t length, apr_pool_t *mp, int pad_type = 1)
	{
		/*
			length is equal to what the string must be after padding subject 
			with the pad string.

			0 for Left, 1 for Right
		*/
		// variables
		char	*result = NULL;
		size_t	str_len, pad_len, res_len, pad_num;
		int		i, left_pad = 0, right_pad = 0;
		// sanity checks
		// if subject is null or zero length
		if (!strlen(strNotNull(subject)))	return apr_pstrdup(mp, "");
		// if pad is null or zero length
		if (!strlen(strNotNull(pad)))		return (char *)subject;
		// get lengths
		str_len = strlen(subject);
		pad_len = strlen(pad);
		res_len = 0;
		// if length is less than or equal to strlen of subject, return the original string
		if (length <= 0 || (length - str_len) <= 0) return (char *)subject;
		// pad type must be in range 
		if (pad_type < 0 || pad_type > 2) return (char *)subject;
		// set the length of the padding
		pad_num = length - str_len;
		// sanity check
		if (pad_num >= INT_MAX) return (char *)subject;
		// allocate results
		result = (char *)apr_palloc(mp, str_len + pad_num + 1);
		// determine type (add both later)
		switch (pad_type)
		{
			case 0:
				left_pad  = 0;
				right_pad = pad_num;
				break;
			case 1:
				left_pad  = pad_num;
				right_pad = 0;
				break;
			case 2:
				left_pad  = pad_num / 2;
				right_pad = pad_num - left_pad;
				break;
		}
		// pad left first
		for (i = 0; i < left_pad; i++)
			result[res_len++] = pad[i % pad_len];
		// copy the input string into this
		memcpy(result + res_len, subject, str_len);
		// set the result length to be total of current res_len + str_len
		res_len += str_len;
		// pad right last
		for (i = 0; i < right_pad; i++)
			result[res_len++] = pad[i % pad_len];
		// set null character
		result[res_len] = '\0';
		// return
		return result;
	}
	// repeat string
	static char *strRepeat(const char *subject, int multi, apr_pool_t *mp)
	{
		// variables
		char	*result = NULL;
		size_t	res_len, str_len;
		// sanity checks
		// if subject is null or zero length
		if (!strlen(strNotNull(subject)))	return apr_pstrdup(mp, "");
		// if multiplier is less than or eq zero
		if (multi <= 0)						return (char *)subject;
		// get lengths
		str_len = strlen(subject);
		res_len = 0;
		// get the output length
		res_len = str_len * multi;
		// allocate results
		result = (char *)apr_palloc(mp, res_len + 1);	
		// repeat string
		if (str_len == 1) 
		{
			// just set the memory in result to the single char in subject * multi
			memset(result, *(subject), multi); 
		} 
		else 
		{
			// variables
			char *s, *e, *ee;
			int	 l = 0;
			// copy the subject into result
			memcpy(result, subject, str_len);
			// 
			s  = result;
			e  = result + str_len;
			ee = result + res_len;
			// loop while we are not at res_len
			while (e < ee) 
			{
				// if adding string to result is still less than the desired result
				// subtract 
				l = (e-s) < (ee-e) ? (e-s) : (ee-e);
				// move the memory 
				memmove(e, s, l);
				// add to pointer
				e += l;
			}
		}
		// set null character
		result[res_len] = '\0';
		// return
		return result;
	}
	// scan input to make sure it is of correct value using a regex
	static bool scanInput(const char *subject, apr_pool_t *mp, int mode = INPUT_MUSTBE_ALPHANUM)
	{
		// variables
		bool			rv = false;
		ap_regmatch_t	regmatch[AP_MAX_REG_MATCH];
		ap_regex_t		*regex = NULL;
		// check string to make sure it is not empty
		if (isStrNull(subject)) return rv;
		// switch mode
		switch (mode)
		{
			case INPUT_MUSTBE_NUMBER:				regex = ap_pregcomp(mp, "^[0-9]+$", NULL); break;
			case INPUT_MUSTBE_CHAR:					regex = ap_pregcomp(mp, "^[a-zA-Z]+$", NULL); break;
			case INPUT_MUSTBE_ALPHANUM:				regex = ap_pregcomp(mp, "^[0-9a-zA-Z]+$", NULL); break;
			case INPUT_MUSTBE_ALPHANUM_PERIOD:		regex = ap_pregcomp(mp, "^[0-9a-zA-Z.]+$", NULL); break;
			case INPUT_MUSTBE_ALPHANUM_UNDERSCORE:	regex = ap_pregcomp(mp, "^[0-9a-zA-Z_]+$", NULL); break;
		}
		// check regex
		if (regex)
			if (!ap_regexec(regex, subject, AP_MAX_REG_MATCH, regmatch, NULL))
				rv = true;
		// return
		return rv;
	}
	// key generator
	static char *strKey(int size, apr_pool_t *mp) 
	{
		// set string to nothing
		char *s = "";
		// array of characters
		const char *cs = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
		// iterate over and add to string
		for (int index = 0; index < size; index++) { s = apr_pstrcat(mp, s, string(cs).substr(random()%62,1).c_str(), NULL); }
		// return
		return s;
	}
	// string equality tests
	static bool isStrEqual(const char *against, const char *input, apr_pool_t *mp, int usearglen = 0, int usecase = 0, int begin = 0, int end = 0)
	{
		// variables
		const char	*comparevalue = input;
		int			capture = 0;
		// check input strings
		if (!strlen(strNotNull(input)) || !strlen(strNotNull(against)))		return false;
		// sanity check
		if (strlen(against) > strlen(input))								return false;
		// check if usearglen is on
		if ((usearglen || (begin + end)) && !(mp == NULL))
		{
			// reset string if use argument length
			if (usearglen) { begin = 0; end = (int)strlen(against); }
			// perform substring
			comparevalue = strSub(input, begin, end, mp);
		} 
		// check according to case preferences
		if (usecase) capture = apr_strnatcasecmp(comparevalue, against);
		else		 capture = apr_strnatcmp(comparevalue, against);
		// return
		return (capture) ? false : true;
	}
	// ipaddress test
	static bool isStrIP(const char *subject, apr_pool_t *mp)
	{
		// variables
		bool			rv = false;
		ap_regmatch_t	regmatch[AP_MAX_REG_MATCH];
		ap_regex_t		*regex = ap_pregcomp(mp, "^[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}$", NULL);
		// check string to make sure it is not empty
		if (isStrNull(subject)) return rv;
		// check regex
		if (!ap_regexec(regex, subject, AP_MAX_REG_MATCH, regmatch, NULL))
			rv = true;
		// return
		return rv;
	}
	// email test
	static bool isStrEmail(const char *subject, apr_pool_t *mp)
	{
		// variables
		bool			rv = false;
		ap_regmatch_t	regmatch[AP_MAX_REG_MATCH];
		ap_regex_t		*regex = ap_pregcomp(mp, "^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,4}$", NULL);
		// check string to make sure it is not empty
		if (isStrNull(subject)) return rv;
		// check regex
		if (!ap_regexec(regex, subject, AP_MAX_REG_MATCH, regmatch, NULL))
			rv = true;
		// return
		return rv;
	}
	// directory && simple xpath (no attribute defs) test
	static bool isStrDirectory(const char *subject, apr_pool_t *mp)
	{
		// variables
		bool			rv = false;
		ap_regmatch_t	regmatch[AP_MAX_REG_MATCH];
		ap_regex_t		*regex = ap_pregcomp(mp, "^[A-Za-z0-9/.-_]+$", NULL);
		// check string to make sure it is not empty
		if (isStrNull(subject)) return rv;
		// check regex
		if (!ap_regexec(regex, subject, AP_MAX_REG_MATCH, regmatch, NULL))
			rv = true;
		// return
		return rv;
	}
	// boolean test
	static bool isStrBool(const char *subject)
	{
		// bool values
		char *boolvals = "on true yes 1";
		// lower comparison string
		subject = strToLower(subject);
		// compare & return
		if (!(find(boolvals, subject) == -1)) { return true; }
		// return
		return false;
	}
	// number ranged test
	static bool isNumInRange (int subject, int begin, int end, int zeroAllowed = 0, int negativeAllowed = 0)
	{
		// zero tests
		if (!zeroAllowed && !subject) return false;
		// negative number tests
		if (!negativeAllowed && (subject < 0 || begin < 0 || end < 0)) return false;
		// perform test
		if (subject > begin && subject < end) return true;
		// return
		return false;
	}
	// file exists
	static bool fileExists(const char *filename, apr_pool_t *mp)
	{
		// variables
		apr_finfo_t finfo;
		// stat the file
		if ((apr_stat(&finfo, filename, APR_FINFO_NORM, mp)) == APR_SUCCESS)
			if (finfo.filetype == APR_REG)	
				return true;
		// return
		return false;
	}
	// get a numeric status as a loggable error code
	static char *aprErrOut(apr_status_t rc, apr_pool_t *mp)
	{
		// create a memory space for the error
		char *text = (char *)apr_pcalloc(mp, 201);
		// if is empty then return
		if (text == (char *)NULL) return NULL;
		// copy error string into the buffer
		apr_strerror(rc, text, 200);
		// return the error
		return text;
	}
	// replacement for count directories
	static bool aprPathIsValid(const char *path)
	{
		// variables
		int z = 0, c = 0;
		// return on null pointers
		if (isStrNull(path)) return false;
		// return if single directory
		if (!compare(path, "/")) return true;
		// iterrate over body path sep count
		for (z = 0, c = 0; z < (int)(strlen(path) - 1); z++)
			if (path[z] == '/')
				c++;
		// check count modulus
		if (c % 2 == 0)
			return true;
		// default
		return false;
	}
	// callback interface for apr_table
	static int aprTBasicCB(void *data, const char *key, const char *val)
	{
		// can make more efficient later -- 
		// variables
		infx_tx_tcb	*tcb = (infx_tx_tcb *)data; // the mode as a string
		int			mode = tcb->mode;
		apr_pool_t	*px  = tcb->mp;
		// switch based on mode
		switch (mode)
		{
			// 0 is not a valid mode
			case 0: return FALSE;
			// 1 is to create directories according to the value
			case 1:
				// if not equal to the server root
				if (!isStrEqual(ap_server_root, val, px))
				{
					// check if ap server root is in string and is either servroot/var or under
					if (!(find(val, ap_server_root) == -1) && !(find(val, "/var") == -1))
					{
						// make directory
						if (!(apr_dir_make_recursive(val, INFX_BASE_PERM, px) == OK)) // APR_FPROT_OS_DEFAULT
							return FALSE; // return false on errors
					}
				}
				// done
				break;
			// 2 is to dump table key value to logs
			case 2:
				// check how if request object available
				APLOG("INFX_KEY_DUMP Key: %s => Val: %s", key, val);
				// done
				break;
			// 3 is to merge into subprocessenv
			case 3:
				// merge data
				if (!tcb->r == NULL)	apr_table_set(tcb->r->subprocess_env, key, val);
				else					return FALSE;
				// done
				break;
			// default is not implemented
			default: return FALSE;
		}
		// return 
		return TRUE;
	}
}