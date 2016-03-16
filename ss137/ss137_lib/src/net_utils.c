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
 * Net utility functions as needed by Kmc-Subset137 project.
 *
 * This file contains utility functions used to serialize and deserialize
 * buffers converting them from host to net format and from net to host
 * format respectively, as needed by Kmc-Subset137 project.
 *
 * @file: ss137/ss137_lib/src/net_utils.c
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

/*****************************************************************************
 * INCLUDES
 ******************************************************************************/

#include <stdio.h>     
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <libgen.h>

#include "utils.h"
#include "net_utils.h"

/*****************************************************************************
 * DEFINES
 ******************************************************************************/

/*****************************************************************************
 * TYPEDEFS
 *****************************************************************************/

/*****************************************************************************
 * VARIABLES
 *****************************************************************************/

/*****************************************************************************
 * LOCAL FUNCTION PROTOTYPES
 *****************************************************************************/

/*****************************************************************************
 * LOCAL FUNCTION DECLARATIONS
 *****************************************************************************/

/*****************************************************************************
 * PUBLIC FUNCTION DECLARATIONS
 *****************************************************************************/

/**
 * Initializes write_stream_t struct.
 *
 * This function takes pointer to write_stream_t struct, which contains parameters
 * of write stream, and initializes them to 0U.
 * The function calls the exit() function on any erorr on the addressing of the input parameters.
 */
error_code_t initWriteStream /** @return SUCCESS success, ERROR in case of error. */
(
	write_stream_t *const ostream /**< [out] The pointer to the struct to initialize. */
	)
{
	ASSERT(ostream != NULL, E_NULL_POINTER);

	ostream->curSize = 0U;

	return(SUCCESS);
}

/**
 * Initializes read_stream_t struct.
 *
 * This function takes pointer to t_UTILS_read_strem struct, which contains parameters
 * of read stream, and initializes them to 0U.
 * The function calls the exit() function on any erorr on the addressing of the input parameters.
 */
error_code_t initReadStream /** @return SUCCESS success, ERROR in case of error. */
(
	read_stream_t *const istream /**< [out] The pointer to the struct to initialize. */
	)
{
	ASSERT(istream != NULL, E_NULL_POINTER);

	istream->curPos = 0U;
	istream->validBytes = 0U;

	return(SUCCESS);
}

/**
 * Converts an uint32_t integer from host to net format and writes it in write_stream_t struct.
 *
 * The function converts the value var in net format and copies it to the ostream->buffer array starting from the current
 * position (buffer->curSize), the function performs the copy only if there is enough space in the destination buffer
 * (ostream->curSize + len) <= MAX_BUFFER_SIZE). Finally the value of ostream->curSize is increased of a value
 * sizeof(uint32_t).
 * The function calls the exit() function on any erorr on the addressing of the input parameters
 * or if (ostream->curSize + len) > MAX_BUFFER_SIZE).
 */
error_code_t hostToNet32 /** @return SUCCESS success, ERROR in case of error. */
(
	write_stream_t* const ostream, /**< [out] Where to put the converted value.*/ 
	const uint32_t var             /**< [in]  The value to convert.*/             
	)
{
    uint32_t len = 0U;
    uint32_t new_var = 0U;

	ASSERT(ostream != NULL, E_NULL_POINTER);

	len = (uint32_t)sizeof(uint32_t);

	ASSERT((ostream->curSize + len) <= (uint32_t)MSG_MAX_SIZE, E_BUFFER_TOO_SHORT);

	new_var = htonl(var);
	memmove((void*)&ostream->buffer[ostream->curSize], (void*)&new_var, (size_t)len);
	ostream->curSize += len;

	return(SUCCESS);
}

/**
 * Converts an uint16_t integer from host to net format and writes it in write_stream_t struct.
 *
 * The function converts the value var in net format and copies it to the ostream->buffer array starting from the current
 * position (buffer->curSize), the function performs the copy only if there is enough space in the destination buffer
 * (ostream->curSize + len) <= MAX_BUFFER_SIZE). Finally the value of ostream->curSize is increased of a value
 * sizeof(uint16_t).
 * The function calls the exit() function on any erorr on the addressing of the input parameters
 * or if (ostream->curSize + len) > MAX_BUFFER_SIZE).
 */
error_code_t hostToNet16 /** @return SUCCESS success, ERROR in case of error. */
(
	write_stream_t* const ostream, /**< [out] Where to put the converted value.*/ 
	const uint16_t var			   /**< [in]  The value to convert.*/             
	)
{
    uint32_t len = 0U;
    uint16_t new_var = 0U;

	ASSERT(ostream != NULL, E_NULL_POINTER);

	len = (uint32_t)sizeof(uint16_t);

	ASSERT((ostream->curSize + len) <= (uint32_t)MSG_MAX_SIZE, E_BUFFER_TOO_SHORT);

	new_var = htons(var);
	memmove((void*)&ostream->buffer[ostream->curSize], (void*)&new_var, (size_t)len);
	ostream->curSize += len;

	return(SUCCESS);
}

/**
 * Converts an array of uint8_t from host to net format and writes it in write_stream_t struct.
 *
 * The function converts the value var in net format and copies it to the ostream->buffer array starting from the current
 * position (buffer->curSize), the function performs the copy only if there is enough space in the destination buffer
 * (ostream->curSize + len) <= MAX_BUFFER_SIZE). Finally the value of ostream->curSize is increased of a value
 * len.
 * The function calls the exit() function on any erorr on the addressing of the input parameters
 * or if (ostream->curSize + len) > MAX_BUFFER_SIZE).
 */
error_code_t hostToNet8 /** @return SUCCESS success, ERROR in case of error. */
(
	write_stream_t* const ostream, /**< [out] Where to put the converted value.*/  
	const uint8_t* const var,      /**< [in]  The array to convert.*/  
	const uint32_t len             /**< [in]  Size of the array. */
	)
{
	ASSERT((ostream != NULL) && (var != NULL), E_NULL_POINTER);
	ASSERT((ostream->curSize + len) <= (uint32_t)MSG_MAX_SIZE, E_BUFFER_TOO_SHORT);

	memmove((void*)&ostream->buffer[ostream->curSize], (void*)var, (size_t)len);
	ostream->curSize += len;

	return(SUCCESS);
}

/**
 * Converts an uint32_t integer from net to host format reading from a read_stream_t struct.
 *
 * The function reads and coverts an uint32_t variable from net to host format from the current position of the istream buffer
 * and copies it to the value pointed by var, the function performs the copy only if there
 * is enough space/valid data for reading in the source buffer((ostream->curSize + len) <= MAX_BUFFER_SIZE and istream->validBytes ).
 * Finally the value of ostream->curPos is updated by increasing it of a value sizeof(uint32_t).
 * The function calls the exit() function on any erorr on the addressing of the input parameters.
 */
error_code_t netToHost32  /** @return SUCCESS if the value is correctly read, ERROR there is not enough bytes to read in the buffer. */
(
	uint32_t* const var,         /**< [out] Where to put the converted value.*/  
	read_stream_t* const istream /**< [in]  The struct holding the data to convert.*/  
	)
{
	uint32_t new_var = 0U;
	uint32_t len = 0U;

	ASSERT((istream != NULL) && (var != NULL), E_NULL_POINTER);

	len = (uint32_t)sizeof(uint32_t);

	ASSERT((istream->curPos + len) <= (uint32_t)MSG_MAX_SIZE, E_BUFFER_TOO_SHORT);

	if((istream->curPos + len) > istream->validBytes)
	{
	    return(ERROR);
	}

	memmove((void*)&new_var, (void*)&istream->buffer[istream->curPos], (size_t)len);
	*var = ntohl(new_var);
	istream->curPos += len;

	return(SUCCESS);
}

/**
 * Converts an uint16_t integer from net to host format reading from a read_stream_t struct.
 *
 * The function reads and coverts an uint16_t variable from net to host format from the current position of the istream buffer
 * and copies it to the value pointed by var, the function performs the copy only if there
 * is enough space/valid data for reading in the source buffer((ostream->curSize + len) <= MAX_BUFFER_SIZE and istream->validBytes ).
 * Finally the value of ostream->curPos is updated by increasing it of a value sizeof(uint16_t).
 * The function calls the exit() function on any erorr on the addressing of the input parameters.
 */
error_code_t netToHost16 /** @return SUCCESS if the value is correctly read, ERROR there is not enough bytes to read in the buffer. */
(
	uint16_t* const var,          /**< [out] Where to put the converted value.*/  
	read_stream_t* const istream  /**< [in]  The struct holding the data to convert.*/  
	)
{
	uint16_t new_var = 0U;
	uint32_t len = 0U;

	ASSERT((istream != NULL) && (var != NULL), E_NULL_POINTER);

	len = (uint32_t)sizeof(uint16_t);

	ASSERT((istream->curPos + len) <= (uint32_t)MSG_MAX_SIZE, E_BUFFER_TOO_SHORT);
		
	if((istream->curPos + len) > istream->validBytes)
	{
	    return(ERROR);
	}

	memmove((void*)&new_var, (void*)&istream->buffer[istream->curPos], (size_t)len);
	*var = ntohs(new_var);
	istream->curPos += len;

	return(SUCCESS);
}


/**
 * Converts an array of uint8_t integer from net to host format reading from a read_stream_t struct.
 *
 * The function reads and coverts an array of uint8_t from net to host format from the current position of the istream buffer
 * and copies it to the value pointed by var, the function performs the copy only if there
 * is enough space/valid data for reading in the source buffer((ostream->curSize + len) <= MAX_BUFFER_SIZE and istream->validBytes ).
 * Finally the value of ostream->curPos is updated by increasing it of a value len.
 * The function calls the exit() function on any erorr on the addressing of the input parameters.
 */
error_code_t netToHost8
(
	uint8_t* const var,           /**< [out] Where to put the converted value.*/  
	const uint32_t len,           /**< [in]  The number of bytes to read*/  
	read_stream_t* const istream  /**< [in]  The struct holding the data to convert.*/  
	)

{
	ASSERT((istream != NULL) && (var != NULL), E_NULL_POINTER);
	ASSERT((istream->curPos + len) <= (uint32_t)MSG_MAX_SIZE, E_BUFFER_TOO_SHORT);
		
	if((istream->curPos + len) > istream->validBytes)
	{
	    return(ERROR);
	}

	memmove((void*)var, (void*)&istream->buffer[istream->curPos], (size_t)len);
	istream->curPos += len;

	return(SUCCESS);
}
