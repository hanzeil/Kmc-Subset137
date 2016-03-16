/*
 *
 * Copyright (C) 2016 Neat S.r.l.
 *
 * This file is part of Kmc-Subset137.
 *
 * Kmc-Subset137 is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Kmc-Subset137 is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

/**************************************************************************//**
 *
 * Utilities header file as needed by Kmc-Subset137 project.
 *
 * This file contains some utility macro and definitions as needed 
 * by Kmc-Subset137 project.
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
