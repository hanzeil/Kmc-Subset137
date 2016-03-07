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


/*****************************************************************************
 * TYPEDEFS
 *****************************************************************************/

typedef struct
{
	uint32_t tlsID;
	uint8_t  appTimeout;	
	uint32_t transNum;
	uint16_t peerSeqNum;
	uint32_t peerEtcsIDExp;
} session_t;

typedef enum
{
	OP_OK = 0,
	OP_NOK = 1
} OPERATION_STATUS;

/*****************************************************************************
 * PUBLIC FUNCTION PROTOTYPES
 *****************************************************************************/

/* tls function */
int32_t startClientTLS(uint32_t* const tls_id);

int32_t startServerTLS(uint32_t* const tls_id,
					   const uint16_t l_port);

int32_t connectToTLSServer(const uint32_t const tls_id,
						   const char* const r_ip,
						   const uint16_t r_port);

int32_t listenForTLSClient(const uint32_t tls_id);

int32_t closeTLSConnection(const uint32_t tls_id);

/* receive */
int32_t waitForResponse(response_t* const response,
						session_t* const curr_session,
						const MSG_TYPE exp_msg_type);

int32_t waitForRequestFromKMCToKMC(void* const payload,
								   uint32_t* const request_type,
								   session_t* const curr_session);

int32_t waitForRequestFromKMCToKMAC(request_t* const request,
									session_t* const curr_session);





int32_t initAppSession(session_t* const curr_session,
					   const uint8_t app_timeout,
					   const uint32_t peer_etcs_id_exp);

int32_t endAppSession(session_t* const curr_session);

int32_t performAddKeysOperation(session_t* const curr_session,
								response_t* const response,
								const request_t* const request);

int32_t performDelKeysOperation(session_t* const curr_session,
								response_t* const response,
								const request_t* const request);

int32_t performUpKeyValiditiesOperation(session_t* const curr_session,
										response_t* const response,
										const request_t* const request);
int32_t performUpKeyEntitiesOperation(session_t* const curr_session,
									  response_t* const response,
									  const request_t* const request);

int32_t performDeleteAllKeysOperation(session_t* const curr_session,
									  response_t* const response);

int32_t performReqDBChecksumOperation(session_t* const curr_session,
									  response_t* const response);

int32_t sendNotifResponse(const response_t* const response,
						  const session_t* const curr_session);

int32_t sendNotifKeyDBChecksum(const response_t* const response,
							   const session_t* const curr_session);



#endif /* KMC_SS137_LIB_H_ */
