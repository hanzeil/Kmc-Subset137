/**************************************************************************//**
 *
 * ...
 *
 * This file ...
 *
 * @file: ss137/ss137_lib/include/ss137_lib.h
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

#ifndef KMC_SS137_LIB_H_
#define KMC_SS137_LIB_H_

/*****************************************************************************
* DEFINES
******************************************************************************/

#define INTERFACE_VERSION (2U) /* current supported version */

#define NUM_VERSION       (1U) /* number of supported version */

/*****************************************************************************
 * TYPEDEFS
 *****************************************************************************/

typedef struct
{
	uint32_t tls_des;
	uint32_t myTransNum;
	uint32_t mySeqNum;
	uint32_t peerEtcsIDExp;
	uint32_t peerTransNum;
	uint32_t peerSeqNum;
}session_t;

/*****************************************************************************
 * PUBLIC FUNCTION PROTOTYPES
 *****************************************************************************/

int32_t startClientTLS(int32_t* const sock);

int32_t connectToTLSServer(uint32_t* const tls_des,
						   const int32_t sock,
						   const char* const r_ip,
						   const uint16_t r_port);
	
int32_t startServerTLS(int32_t* const listen_sock,
					   const uint16_t l_port);

int32_t waitForTLSClient(uint32_t* const tls_des,
						 int32_t* const client_sock,
						 const int32_t listen_sock);

int32_t closeTLSConnection(const uint32_t tls_des,
						   const int32_t sock);

int32_t initAppSession(const uint32_t peerETCSID,
					   session_t* const curr_session);

int32_t endAppSession(session_t* const curr_session);

int32_t receiveMsg(read_stream_t* const istream,
				   const uint32_t tls_des);

#endif /* KMC_SS137_LIB_H_ */
