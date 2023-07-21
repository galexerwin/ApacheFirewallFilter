/*
	Class:			Tools 
	Segment:		Array/List Library 
	Create Date:	6/16/2012
	Edit Date:		6/16/2012
	Description:	Contains Psuedo Array/List Functions
*/
// include mod_infinity
#include "mod_infinity.h"
// mod_infinity namespace
namespace modinfinity
{
	// declare included namespaces
	using namespace std;
	/*
		High level array/list functions
	*/
	// is in list
	bool tools::isInList (const char *subject, bool sensitive, ...) {
		// variables
		bool	rv = false;
		char	*str;
		va_list	args;
		// read the input list 2nd pass
		va_start(args, sensitive);
		// iterrate over collection
		while (!((str = va_arg(args, char *)) == NULL)) {
			if (sensitive && !comparecase(str, subject))	{ rv = true; break; }
			if (!sensitive && !comparecase(str, subject))	{ rv = true; break; }
		}
		// call va end
		va_end(args);
		// return
		return rv;
	};
	// is in assoc array
	bool tools::isInAssocArray(apr_hash_t *ht, const char *key)
	{
		// variables
		bool				retval = false;
		apr_hash_index_t	*hi;
		const void			*k;
		void				*v;
		// iterrate to find value
		for (hi = apr_hash_first(local, ht); hi; hi = apr_hash_next(hi)) 
		{
	        // get at the hash index by checking if key matches
			apr_hash_this(hi, &k, NULL, &v);
			// convert k to a const char
			const char *ckey = (const char *)k;
			// check if there is an exact match to key
			if (!compare(key, ckey))
			{
				// if found return
				if (!(v == NULL)) 
					return true;
			}
		}		
		// return 
		return retval;
	};
	// set assoc array row
	bool tools::setAssocArrayRow(apr_hash_t *&ht, const char *key, void *value, apr_pool_t *mp)
	{
		// variables
		bool retval = true;
		// check if hash is null
		if (ht == NULL)
			if ((ht = apr_hash_make(mp)) == NULL)
				return false;
		// set the value
		apr_hash_set(ht, (void *)key, APR_HASH_KEY_STRING, value);
		// return
		return retval;
	};
	// get assoc array row
	bool tools::getAssocArrayRow(apr_hash_t *ht, const char *key, void *&value, apr_pool_t *mp)
	{
		// variables
		bool retval = true;
		// check if hash is null
		if (ht == NULL && isStrNull(nullif(key, "")))
			return false;
		// set value
		if ((value = apr_hash_get(ht, key, APR_HASH_KEY_STRING)) == NULL)
			return false;
		// return
		return retval;
	};
	// del assoc array row
	bool tools::delAssocArrayRow(apr_hash_t *&ht, const char *key, apr_pool_t *mp)
	{
		// variables
		bool retval = true;
		// check if hash is null
		if (ht == NULL && isStrNull(nullif(key, "")))
			return false;
		// set the value
		apr_hash_set(ht, (void *)key, APR_HASH_KEY_STRING, NULL);
		// return
		return retval;
	};
	// loop over assoc array and return the value
	void *tools::loopAssocArray(apr_hash_t *ht, apr_hash_index_t *&in, apr_pool_t *mp)
	{
		// variables
		void *data = NULL;
		// check if hash index is for a hash
		if (in == NULL)	{ in = apr_hash_first(mp, ht); }
		else			{ in = apr_hash_next(in); }
		// get data
		if (!(in == NULL))
			apr_hash_this(in, NULL, NULL, &data);
		// return
		return data;
	};
	/*
		High-Level String to List to String Functions
	*/
	// nvp pair parser returns hash
	bool tools::nvpParseHash(const char *subject, apr_hash_t *&container, infx_ws_cmd *&list, apr_pool_t *mp, int &count, char *listsep, char *pairsep)
	{
		// variables
		int		dbl = -1, lnext = 0;
		bool	retval = false, basetype = false;
		// reset count
		count = 0;
		// create logger
		logging logger(apache, server, local);
		// breakpoint
		stdLog(logger, INFX_LOG_DATA, dbl, subject);
		// check subject string
		if (!isStrNull(nullif(subject, "")) && !(find(subject, pairsep) == -1))
		{
			// breakpoint
			stdLog(logger, INFX_LOG_DATA, dbl);
			// adjust subject for trailing commas
			if (isStrTokenMatch(subject, listsep, (strlen(subject) - 1)))		
				subject = strSub(subject, 0, strlen(subject) - 1, mp);
			// breakpoint
			stdLog(logger, INFX_LOG_DATA, dbl);
			// adjust subject for leading quote
			if (subject[0] == (char)39)					
				subject = strSub(subject, 1, 0, mp);
			// breakpoint
			stdLog(logger, INFX_LOG_DATA, dbl);
			// adjust subject for trailing quote
			if (subject[strlen(subject) - 1] == (char)39)	
				subject = strSub(subject, 0, strlen(subject) - 1, mp);
			// expand
			for (int z = 0, y = 0, x = 0, w = 0, v = 0, j = 0; z < (int)strlen(subject); z++)
			{
				// breakpoint
				stdLog(logger, INFX_LOG_DATA, dbl);
				// check if this is a pair token
				if (isStrTokenMatch(subject, pairsep, z)) // subject[z] == pairsep[0]
				{
					// breakpoint
					stdLog(logger, INFX_LOG_DATA, dbl);
					// set y = to pair token position minus one, chomp until hitting a list seperator or the beginning
					for (y = (z - 1); y >= x; y--)
						if (isStrTokenMatch(subject, listsep, y) || !y) //subject[y] == listsep[0]
							break;
					// breakpoint
					stdLog(logger, INFX_LOG_DATA, dbl);
					// set w for quoted value range
					for (v = 0, w = (z + 1); w < (int)strlen(subject); w++)
					{
						// variables
						char c = subject[w];
						char n = subject[w + 1];
						char l = listsep[0];
						char q = (char)39;
						// check for quotes
						if (w == (z + 1) && c == q)			 
							v = w + 1;
						// check if quotes were found
						if (v)
						{
							// examine the content if we encounter a quote and there is more length
							if ((c == q) && (w + 2) < (int)strlen(subject))
							{
								// if the very next item is a list seperator ~
								// and the item after is quote or a space and a quote
								if (n == l && (subject[w + 2] == q || (isspace(subject[w + 2]) && subject[w + 3] == q)))
									continue;
							}
							// this is not a quote
							else if (!(c == q)) { continue; }
						}
						// break if at the end
						if ((v && (n == l || !n)) || (c == l || !c))
							break;
					
					}
					// breakpoint
					stdLog(logger, INFX_LOG_DATA, dbl);
					// list seperator key found. note and move pass the pointer
					if (isStrTokenMatch(subject, listsep, y)) y++;// subject[y] == listsep[0]
					// breakpoint
					stdLog(logger, INFX_LOG_DATA, dbl);
					// x marker is now equal to the position of y
					x = y;
					// breakpoint
					stdLog(logger, INFX_LOG_DATA, dbl);
					// variables
					char		*key = strSub(subject, x, z - x, local);
					char		*val = strSub(subject, (z + 1), w - z, local);
					char		*sub = apr_pstrcat(local, key, pairsep, NULL);
					infx_tx_nvp	*nvp = (infx_tx_nvp *)apr_palloc(mp, sizeof(infx_tx_nvp));
					// breakpoint
					stdLog(logger, INFX_LOG_DATA, dbl);
					// replace name and token combo if inside the value
					if (!(find(val, sub) == -1))
						if (!(val[0] == (char)39))
							val = getStrReplace(val, sub, "");
					// breakpoint
					stdLog(logger, INFX_LOG_DATA, dbl);
					// adjust value for commas 
					if (isStrTokenMatch(val, listsep, (strlen(val) - 1)))		
						val = strSub(val, 0, strlen(val) - 1, mp);
					// breakpoint
					stdLog(logger, INFX_LOG_DATA, dbl);
					// adjust value for leading quote
					if (val[0] == (char)39)					
						val = strSub(val, 1, 0, mp);
					// breakpoint
					stdLog(logger, INFX_LOG_DATA, dbl);
					// adjust value for trailing quote
					if (val[strlen(val) - 1] == (char)39)	
						val = strSub(val, 0, strlen(val) - 1, mp);
					// breakpoint
					stdLog(logger, INFX_LOG_DATA, dbl);
					// z marker is now equal to the position of w
					if (v) { z = w; }
					// scan the key to make sure it is valid
					if (scanInput(key, local, INPUT_MUSTBE_ALPHANUM_UNDERSCORE))
					{
						// breakpoint
						stdLog(logger, INFX_LOG_DATA, dbl);
						// fill struct with initial data
						nvp->name		= strToLower(key);
						nvp->namelen	= strlen(key);
						nvp->nameshort	= key[0];
						nvp->listsep	= listsep;
						nvp->pairsep	= pairsep;
						// breakpoint
						stdLog(logger, INFX_LOG_DATA, dbl);
						// add name to return command/name linked list for parameter order
						if (!lnext)
						{
							// assign root
							list = (infx_ws_cmd *)apr_palloc(mp, sizeof(infx_ws_cmd));
							// check list node
							if (list == NULL) return false;
							// add data
							list->cmd  = apr_pstrdup(mp, strToLower(key));
							list->next = NULL;
						}
						else
						{
							// break point
							stdLog(logger, INFX_LOG_DATA, dbl);
							// set the pointer to equal the root node
							infx_ws_cmd *cmdptr = list;
							// check if the pointer we receiver is NULL
							if (!(cmdptr == NULL))
							{
								// break point
								stdLog(logger, INFX_LOG_DATA, dbl);
								// find next
								while (!(cmdptr->next == NULL))
									cmdptr = cmdptr->next;
								// break point
								stdLog(logger, INFX_LOG_DATA, dbl);
								// create memory block for pointer
								cmdptr->next = (infx_ws_cmd *)apr_palloc(mp, sizeof(infx_ws_cmd));
								// check if memory was assigned successfully
								if (cmdptr->next == NULL) return false;
								// break point
								stdLog(logger, INFX_LOG_DATA, -1);
								// point to it
								cmdptr = cmdptr->next;
								// break point
								stdLog(logger, INFX_LOG_DATA, -1);
								// add data
								cmdptr->cmd  = apr_pstrdup(mp, strToLower(key));
								cmdptr->next = NULL;
							}
							// root should not be null
							else { return false; }
						}
						// increment list past zero
						lnext++;
						// check if there is a value
						if (strlen(val))
						{
							// find array markers
							int arrMark = find(val, "{");
							// any curly bracket at the beginning means this is an array
							if (arrMark == -1 || arrMark) // so if not found or anywhere inside then not an array
							{
								// check type of data
								for (j = 0; j < 5; j++)
									if ((basetype = scanInput(val, mp, j)))
										break;
								// check if this a base type
								if (basetype && !j)
								{
									// I am a number
									nvp->value			= ((void *)atol(val));
									nvp->valuelen		= 0;
									nvp->valtypelong	= "long";
									nvp->valtypeshort	= 'l';								
								}
								else
								{
									// get value but set memory location back to mp
									char *eval = apr_pstrdup(mp, val);
									// set data
									nvp->value			= (void *)eval;
									nvp->valuelen		= strlen(val);
									nvp->valtypelong	= "char";
									nvp->valtypeshort	= 'c';
								}
							}
							else
							{
								// array could be hash (assoc) or array (simple)
							}
						}
						else
						{
							nvp->value			= (void *)"";
							nvp->valuelen		= 0;
							nvp->valtypelong	= "char";
							nvp->valtypeshort	= 'c';
						}
					}
					else 
					{ 
						// breakpoint
						stdLog(logger, INFX_LOG_DATA, dbl);
						// error
						return retval; 
					}
					// breakpoint
					stdLog(logger, INFX_LOG_DATA, dbl);
					// add data to the hash out
					if (!setAssocArrayRow(container, key, (void *)nvp, mp))
						return retval;
				}
			}
			// breakpoint
			stdLog(logger, INFX_LOG_DATA, dbl);
			// set count
			count = apr_hash_count(container);
			// breakpoint
			stdLog(logger, INFX_LOG_DATA, dbl);
			// check the hashcount and return true if not empty
			if (count) return true;
		}
		// breakpoint
		stdLog(logger, INFX_LOG_DATA, dbl);
		// return
		return retval;
	};
	// string to array
	// using local array header
	void tools::doExplode(const char *subject, const char *delimiter)
	{
		// variables
		int	 dbl = APLOG_TRACE8;
		// create logger
		logging logger(apache, server, local);
		// breakpoint
		stdLog(logger, INFX_LOG_DATA, dbl);
		// call doExplode with internal
		doExplode(subject, delimiter, this->split);
		// breakpoint
		stdLog(logger, INFX_LOG_DATA, dbl);
		// return
		return;
	};
	// using remote array header
	void tools::doExplode(const char *subject, const char *delimiter, apr_array_header_t *&sarray)
	{
		// variables
		int	 pos, dbl = APLOG_TRACE8;
		char *raw, *next, *last;
		// create logger
		logging logger(apache, server, local);
		// breakpoint
		stdLog(logger, INFX_LOG_DATA, dbl);
		// create the split chars database if not created
		if (sarray == NULL)	{ sarray  = apr_array_make(local, 0, sizeof(char *)); }
		// breakpoint
		stdLog(logger, INFX_LOG_DATA, dbl);
		// always reset everything
		apr_array_clear(sarray);
		// breakpoint
		stdLog(logger, INFX_LOG_DATA, dbl);
		// check if the string only includes delimiter and is the entire string
		if (!strcmp(subject, delimiter)) { return; }
		// breakpoint
		stdLog(logger, INFX_LOG_DATA, dbl);
		// load buffer with extra delimiter at the end
		raw = apr_pstrcat(local, subject, delimiter, NULL);
		// breakpoint
		stdLog(logger, INFX_LOG_DATA, dbl);
		// find the first token position
		if (!((pos = find(raw, delimiter)) == -1)) { pos += (int)strlen(delimiter); }
		// breakpoint
		stdLog(logger, INFX_LOG_DATA, dbl);
		// iterate as long a token is found
		while (pos > 0)
		{
			// get next string up to delimiter
			next = apr_pstrndup(local, raw, pos);
			// subtract the delimiter from results
			last = strTrim(apr_pstrndup(local, raw, strlen(next) - strlen(delimiter)), local);
			// if last != delimiter then add to table
			if (last)
				if (strlen(last))
					if (strcmp(last, delimiter))
						*(char **) apr_array_push(sarray) = apr_pstrdup(sarray->pool, last);
			// subtract portion from raw
			raw = apr_pstrdup(local, ap_stripprefix(raw, next));
			// look for another token and add length of delimiter if found
			if (!((pos = find(raw, delimiter)) == -1)) { pos += (int)strlen(delimiter); }
		}
		// breakpoint
		stdLog(logger, INFX_LOG_DATA, dbl);
		// return
		return;
	};
	// string to array count
	// using local array header
	int tools::getIntSplitMax()
	{
		// return overload
		return getIntSplitMax(this->split); 
	};
	// using remote array header
	int tools::getIntSplitMax(apr_array_header_t *sarray)
	{
		// return the count
		return (sarray == NULL) ? 0 : sarray->nelts; 
	};
	// array to string
	// using local array header
	char *tools::getStrImplodeByVal(const char *delimiter, int s, int e) 
	{ 
		// return overload
		return getStrImplodeByVal(delimiter, s, e, this->split); 
	};
	// using remote array header
	char *tools::getStrImplodeByVal(const char *delimiter, int s, int e, apr_array_header_t *sarray)
	{
		// variable
		char *out = "";
		// perform split by parameter
		if (sarray == NULL || s > sarray->nelts || !sarray->nelts) { return out; }
		// check start
		if (s == NULL) { s = 0; }
		// check end
		if (e == NULL || e > sarray->nelts) { e = sarray->nelts; }
		// iterate
		for (int list = s; list < e; list++)
		{
			// retrieve value
			char *v = ((char**)sarray->elts)[list];
			// concatenate the data with previous and delimiter
			out = apr_pstrcat(local, out, delimiter, v, NULL);
		}
		// return
		return out;
	};
	// array part to string
	// using local array header
	char *tools::getStrExplodeByNum(int n) 
	{ 
		// return overload
		return getStrExplodeByNum(n, this->split); 
	};
	// using remote array header
	char *tools::getStrExplodeByNum(int n, apr_array_header_t *sarray)
	{
		// perform split by parameter
		if (sarray == NULL)		{ return ""; }
		// return if no data
		if (!sarray->nelts)		{ return ""; }
		// decrement n if it is set in the positive
		if (n) { n = n - 1; }
		// return if n > slist->nelts
		if (n > sarray->nelts)	{ return ""; }
		// return entry
		return ((char**)sarray->elts)[n];
	};

}