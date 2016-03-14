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

#define SS137_TCP_PORT    (7912U)
#define MAX_IP_LENGTH     (16U)
#define MAX_KMS_ENTITIES  (100U)
#define MAX_PATH_LENGTH   (256U)

/*****************************************************************************
 * TYPEDEFS
 *****************************************************************************/

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

typedef struct
{
	uint32_t expEtcsId;
	char     ip[MAX_IP_LENGTH];
} kms_entity_id;

typedef struct
{
	char rsaCACertificateFile[MAX_PATH_LENGTH];
	char rsaKey[MAX_PATH_LENGTH];
	char rsaCertificate[MAX_PATH_LENGTH];
	kms_entity_id myEntityId;
	kms_entity_id kmsEntitiesId[MAX_KMS_ENTITIES];
} ss137_lib_configuration_t;

/*****************************************************************************
 * PUBLIC FUNCTION PROTOTYPES
 *****************************************************************************/

/* tls function */
error_code_t startClientTLS(tls_des_t* const tls_id);

error_code_t startServerTLS(void);

error_code_t connectToTLSServer(const tls_des_t const tls_id,
								const char* const server_ip);

error_code_t listenForTLSClient(tls_des_t* const tls_id,
								uint32_t* const exp_etcs_id);

void closeTLSConnection(const tls_des_t tls_id);

error_code_t waitForRequestFromKMCToKMC(request_t* const request,
										session_t* const curr_session);

error_code_t waitForRequestFromKMCToKMAC(request_t* const request,
										 session_t* const curr_session);

error_code_t initAppSession(session_t* const curr_session,
							const uint8_t app_timeout,
							const uint32_t peer_etcs_id_exp);

error_code_t endAppSession(const session_t* const curr_session);

error_code_t performAddKeysTransaction(response_t* const response,
									 session_t* const curr_session,
									 const request_t* const request);

error_code_t performDelKeysTransaction(response_t* const response,
									 session_t* const curr_session,
									 const request_t* const request);

error_code_t performUpKeyValiditiesTransaction(response_t* const response,
											 session_t* const curr_session,
											 const request_t* const request);

error_code_t performUpKeyEntitiesTransaction(response_t* const response,
										   session_t* const curr_session,
										   const request_t* const request);

error_code_t performDeleteAllKeysTransaction(response_t* const response,
										   session_t* const curr_session);

error_code_t performReqDBChecksumTransaction(response_t* const response,
										   session_t* const curr_session);

error_code_t performNotifKeyUpStatusTransaction(response_t* const response,
											  session_t* const curr_session,
											  const request_t* const request);

error_code_t performReqKeyOpTransaction(response_t* const response,
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
