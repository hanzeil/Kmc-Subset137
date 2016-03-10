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

#include <sys/time.h>

/*****************************************************************************
 * DEFINES
 ******************************************************************************/

#define DEFAULT_PORT (7912U)

/*****************************************************************************
 * TYPEDEFS
 *****************************************************************************/

typedef struct
{
	uint32_t       tlsID;
	uint8_t        appTimeout;	
	uint32_t       transNum;
	uint16_t       peerSeqNum;
	uint32_t       peerEtcsIDExp;
	struct timeval startTime;
} session_t;

/*****************************************************************************
 * PUBLIC FUNCTION PROTOTYPES
 *****************************************************************************/

/* tls function */
error_code_t startClientTLS(uint32_t* const tls_id);

error_code_t startServerTLS(void);

error_code_t connectToTLSServer(const uint32_t const tls_id,
										const char* const r_ip);

error_code_t listenForTLSClient(uint32_t* const tls_id, uint32_t* const client_ip);

error_code_t closeTLSConnection(const uint32_t tls_id);

/* receive */
error_code_t waitForRequestFromKMCToKMC(request_t* const request,
												session_t* const curr_session);

error_code_t waitForRequestFromKMCToKMAC(request_t* const request,
												 session_t* const curr_session);




error_code_t initAppSession(session_t* const curr_session,
									const uint8_t app_timeout,
									const uint32_t peer_etcs_id_exp);

error_code_t endAppSession(session_t* const curr_session);

error_code_t performAddKeysOperation(session_t* const curr_session,
											 response_t* const response,
											 const request_t* const request);

error_code_t performDelKeysOperation(session_t* const curr_session,
											 response_t* const response,
											 const request_t* const request);

error_code_t performUpKeyValiditiesOperation(session_t* const curr_session,
													 response_t* const response,
													 const request_t* const request);

error_code_t performUpKeyEntitiesOperation(session_t* const curr_session,
												   response_t* const response,
												   const request_t* const request);

error_code_t performDeleteAllKeysOperation(session_t* const curr_session,
												   response_t* const response);

error_code_t performReqDBChecksumOperation(session_t* const curr_session,
												   response_t* const response);


error_code_t sendNotifResponse(const response_t* const response,
									   const session_t* const curr_session);

error_code_t sendNotifKeyDBChecksum(const response_t* const response,
											const session_t* const curr_session);

error_code_t sendNotifKeyOpReqRcvd(const response_t* const response,
										   const session_t* const curr_session);

error_code_t sendNotifAckKeyUpStatus(const session_t* const curr_session);

#endif /* KMC_SS137_LIB_H_ */
