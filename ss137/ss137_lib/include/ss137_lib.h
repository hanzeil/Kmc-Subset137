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

#define SS137_TCP_PORT (7912U)

/*****************************************************************************
 * TYPEDEFS
 *****************************************************************************/
typedef enum
{
	SUCCESS = 0,
	ERROR   = 1
}error_code_t;

typedef uint32_t tls_des_t;

typedef struct
{
	tls_des_t      tlsID;
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
error_code_t startClientTLS(tls_des_t* const tls_id,
							const char* const ca_cert,
							const char *const key,
							const char* const cert);

error_code_t startServerTLS(const char* const ca_cert,
							const char *const key,
							const char* const cert);

error_code_t connectToTLSServer(const tls_des_t const tls_id,
								const char* const server_ip);

error_code_t listenForTLSClient(tls_des_t* const tls_id,
								char* const client_ip);

error_code_t closeTLSConnection(const tls_des_t tls_id);

/* receive */
error_code_t waitForRequestFromKMCToKMC(request_t* const request,
										session_t* const curr_session);

error_code_t waitForRequestFromKMCToKMAC(request_t* const request,
										 session_t* const curr_session);




error_code_t initAppSession(session_t* const curr_session,
							const uint8_t app_timeout,
							const uint32_t peer_etcs_id_exp);

error_code_t endAppSession(const session_t* const curr_session);

error_code_t performAddKeysOperation(response_t* const response,
									 session_t* const curr_session,
									 const request_t* const request);

error_code_t performDelKeysOperation(response_t* const response,
									 session_t* const curr_session,
									 const request_t* const request);

error_code_t performUpKeyValiditiesOperation(response_t* const response,
											 session_t* const curr_session,
											 const request_t* const request);

error_code_t performUpKeyEntitiesOperation(response_t* const response,
										   session_t* const curr_session,
										   const request_t* const request);

error_code_t performDeleteAllKeysOperation(response_t* const response,
										   session_t* const curr_session);

error_code_t performReqDBChecksumOperation(response_t* const response,
										   session_t* const curr_session);

error_code_t performNotifKeyUpStatusOperation(response_t* const response,
											  session_t* const curr_session,
											  const request_t* const request);

error_code_t performReqKeyOperation(response_t* const response,
									session_t* const curr_session,
									const request_t* const request);


error_code_t sendNotifResponse(const response_t* const response,
							   const session_t* const curr_session);

error_code_t sendNotifKeyDBChecksum(const response_t* const response,
									const session_t* const curr_session);

error_code_t sendNotifKeyOpReqRcvd(const response_t* const response,
								   const session_t* const curr_session);

error_code_t sendNotifAckKeyUpStatus(const session_t* const curr_session);

#endif /* KMC_SS137_LIB_H_ */
