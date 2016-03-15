/**************************************************************************//**
 *
 * Utilities header file
 *
 * This file contains some utility macro and definitions
 *
 * @file: ss137/ss137_lib/include/utils.h
 * $Author: $
 * $Revision: $
 * $Date: $
 *
 * History:
 *
 * Version     Date      Author         Change Description
 *
 *- $Id: $
 *
 ******************************************************************************/

#ifndef KMC_UTILS_H_
#define KMC_UTILS_H_

/*****************************************************************************
* DEFINES
******************************************************************************/

/** Helper function for log print*/
#define log_print(...)													\
	do {																\
		fprintf(stdout, "LOG [%s: %d]\t", basename(__FILE__), __LINE__); \
		fprintf(stdout, ##__VA_ARGS__);									\
		fflush(NULL);													\
	} while (0)

/** Helper function for err print*/
#define err_print(...)													\
	do {																\
		fprintf(stderr, "ERR   [%s: %d]\t", basename(__FILE__), __LINE__); \
		fprintf(stderr, ##__VA_ARGS__);									\
		fflush(NULL);													\
	} while (0)

/** Helper function for warning print*/
#define warning_print(...)												\
	do {																\
		fprintf(stderr, "WARN  [%s: %d]\t", basename(__FILE__), __LINE__); \
		fprintf(stderr, ##__VA_ARGS__);									\
		fflush(NULL);													\
	} while (0)

/** Helper function for dump a messages*/
#ifdef __DEBUG__
#define dump_msg(type, buffer, size)									\
	do {																\
	uint32_t i = 0U;													\
	fprintf(stderr, "MSG %s (%d bytes)\t", (type), (size));				\
	for(i = 0U; i < (size); i++)										\
	{																	\
		fprintf(stderr, "0x%02X ", (buffer)[i]);						\
	}																	\
	fprintf(stderr, "\n");												\
	fflush(NULL);														\
	} while (0)
#else
#define dump_msg(type, buffer, size)
#endif

/** Assert macro for defensive programming */
#define ASSERT(_condition, code)							\
	do {													\
		if ( !(_condition) )								\
		{													\
			err_print("Assertion failed code: %d\n", code);	\
			exit(code);										\
		}													\
	} while (0U)

/*****************************************************************************
 * TYPEDEFS
 *****************************************************************************/

/** bool typedef */
typedef int32_t bool_t;

/** ssl137_lib return code */
typedef enum
{
	SUCCESS = 0,
	ERROR   = 1
}error_code_t;

/** assert error code */
typedef enum
{
	E_NULL_POINTER     = 1,
	E_BUFFER_TOO_SHORT = 2,
	E_INVALID_PARAM    = 3
} assert_error_code_t;

/** FALSE for bool_t type*/
#ifndef FALSE
#define FALSE 0
#endif

/** TRUE for bool_t type */
#ifndef TRUE
#define TRUE 1
#endif


#endif /* KMC_UTILS_H_ */
