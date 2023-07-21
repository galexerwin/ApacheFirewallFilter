/************************************************************************************
*																					*
*		Header for mod_infinity_all													*
*																					*
*		main apache plugin module													*
*************************************************************************************/
// declare constants
#define MODULE_NAME "mod_infinity"
#define MODULE_VERSION "2.0"
// declare includes
#include "mod_infinity_apache.h"
#include "mod_infinity_chilkat.h"
// fake this as c code for apache
extern "C" module AP_MODULE_DECLARE_DATA infinity_security_module;
// declare definitions
#include "mod_infinity_defines.h"
// remove this declaration so that c++ will work
#undef strtoul
// include our declarations
#include "mod_infinity_inc_global.h"
#include "mod_infinity_inc_classes.h"
