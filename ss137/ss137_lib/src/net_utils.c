/**************************************************************************//**
 *
 * ...
 *
 * This file ...
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

/**
 * System headers
 */
#include <stdio.h>     /* for fopen, snprintf, etc... */
#include <string.h>    /* for memmove, memcmp, memset */
#include <arpa/inet.h> /* for htons, etc.. */
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#include "common.h"
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

int32_t initWriteStream(write_stream_t *const ostream)
{
	ASSERT(ostream != NULL, E_NULL_POINTER);

	ostream->curSize = 0U;

	return(0);
}


int32_t initReadStream(read_stream_t *const istream)
{
	ASSERT(istream != NULL, E_NULL_POINTER);

	istream->curPos = 0U;
	istream->validBytes = 0U;

	return(0);
}


int32_t hostToNet32(write_stream_t* const ostream,
					const uint32_t var)
{
    uint32_t len = 0U;
    uint32_t new_var = 0U;

	ASSERT(ostream != NULL, E_NULL_POINTER);

	len = (uint32_t)sizeof(uint32_t);

	ASSERT((ostream->curSize + len) <= (uint32_t)MSG_MAX_SIZE, E_BUFFER_TOO_SHORT);

	new_var = htonl(var);
	memmove((void*)&ostream->buffer[ostream->curSize], (void*)&new_var, (size_t)len);
	ostream->curSize += len;

	return(0);
}

int32_t hostToNet16(write_stream_t* const ostream,
					const uint16_t var)
{
    uint32_t len = 0U;
    uint16_t new_var = 0U;

	ASSERT(ostream != NULL, E_NULL_POINTER);

	len = (uint32_t)sizeof(uint16_t);

	ASSERT((ostream->curSize + len) <= (uint32_t)MSG_MAX_SIZE, E_BUFFER_TOO_SHORT);

	new_var = htons(var);
	memmove((void*)&ostream->buffer[ostream->curSize], (void*)&new_var, (size_t)len);
	ostream->curSize += len;

	return(0);
}

int32_t hostToNet8(write_stream_t* const ostream,
				   const uint8_t* const var,
				   const uint32_t len)
{
	ASSERT((ostream != NULL) && (var != NULL), E_NULL_POINTER);
	ASSERT((ostream->curSize + len) <= (uint32_t)MSG_MAX_SIZE, E_BUFFER_TOO_SHORT);

	memmove((void*)&ostream->buffer[ostream->curSize], (void*)var, (size_t)len);
	ostream->curSize += len;

	return(0);
}

int32_t netToHost32(uint32_t* const var,
					read_stream_t* const istream)
{
	uint32_t new_var = 0U;
	uint32_t len = 0U;

	ASSERT((istream != NULL) && (var != NULL), E_NULL_POINTER);

	len = (uint32_t)sizeof(uint32_t);

	ASSERT(((istream->curPos + len) <= (uint32_t)MSG_MAX_SIZE) &&
		   ((istream->curPos + len) <= istream->validBytes), E_BUFFER_TOO_SHORT);

	memmove((void*)&new_var, (void*)&istream->buffer[istream->curPos], (size_t)len);
	*var = ntohl(new_var);
	istream->curPos += len;

	return(0);
}

int32_t netToHost16(uint16_t* const var,
					read_stream_t* const istream)
{
	uint16_t new_var = 0U;
	uint32_t len = 0U;

	ASSERT((istream != NULL) && (var != NULL), E_NULL_POINTER);

	len = (uint32_t)sizeof(uint16_t);

	ASSERT(((istream->curPos + len) <= (uint32_t)MSG_MAX_SIZE) &&
		   ((istream->curPos + len) <= istream->validBytes), E_BUFFER_TOO_SHORT);

	memmove((void*)&new_var, (void*)&istream->buffer[istream->curPos], (size_t)len);
	*var = ntohs(new_var);
	istream->curPos += len;

	return(0);
}


int32_t netToHost8(uint8_t* const var,
				   const uint32_t len,
				   read_stream_t* const istream)

{
	ASSERT((istream != NULL) && (var != NULL), E_NULL_POINTER);
	ASSERT(((istream->curPos + len) <= (uint32_t)MSG_MAX_SIZE) &&
		   ((istream->curPos + len) <= istream->validBytes), E_BUFFER_TOO_SHORT);

	memmove((void*)var, (void*)&istream->buffer[istream->curPos], (size_t)len);
	istream->curPos += len;

	return(0);
}
