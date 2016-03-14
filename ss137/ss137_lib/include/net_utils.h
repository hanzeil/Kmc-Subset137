/**************************************************************************//**
 *
 * ...
 *
 * This file ...
 *
 * @file: ss137/ss137_lib/include/net_utils.h
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

#ifndef KMC_NET_UTILS_H_
#define KMC_NET_UTILS_H_

/*****************************************************************************
* DEFINES
******************************************************************************/

#define MSG_MAX_SIZE (5000U)

/*****************************************************************************
 * TYPEDEFS
 *****************************************************************************/

typedef struct
{
	uint32_t curPos;
	uint32_t validBytes;
	uint8_t  buffer[MSG_MAX_SIZE];
} read_stream_t;

typedef struct
{
	uint32_t  curSize;
	uint8_t   buffer[MSG_MAX_SIZE];
} write_stream_t;

/*****************************************************************************
 * PUBLIC FUNCTION PROTOTYPES
 *****************************************************************************/

error_code_t netToHost8(uint8_t* const var, const uint32_t len, read_stream_t* const istream);

error_code_t netToHost16(uint16_t* const var, read_stream_t* const istream);

error_code_t netToHost32(uint32_t* const var, read_stream_t* const istream);

error_code_t hostToNet8(write_stream_t* const ostream, const uint8_t* const var, const uint32_t len);

error_code_t hostToNet16(write_stream_t* const ostream, const uint16_t var);

error_code_t hostToNet32(write_stream_t* const ostream, const uint32_t var);

error_code_t initWriteStream(write_stream_t *const ostream);

error_code_t initReadStream(read_stream_t *const istream);


#endif /* KMC_NET_UTILS_H_ */
