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
 * ss137 library header files as needed by Kmc-Subset137 project.
 *
 * This file contains the prototype and definition of the ss137 library 
 * within Kmc-Subset137 project.
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

/** Default ss137 tcp port (see ref SUBSET137 7.3.1.2)*/
#define SS137_TCP_PORT    (7912U)

/** Max ip length in ASCII*/
#define MAX_IP_LENGTH     (16U)

/** Max kms entities configurable*/
#define MAX_KMS_ENTITIES  (100U)

/** Max length of certificate and key path*/
#define MAX_PATH_LENGTH   (256U)

/*****************************************************************************
 * TYPEDEFS
 *****************************************************************************/

/** TLS connection identifier */
typedef uint32_t tls_des_t;

/** Structure holding the current session status */
typedef struct
{
	tls_des_t      tlsID;         /**< TLS session identifier. */
	uint8_t        appTimeout;	  /**< Application timeout in seconds. */
	uint32_t       transNum;      /**< Current transaction number. */
	uint16_t       peerSeqNum;    /**< Peer entity sequence number. */
	uint32_t       peerEtcsIDExp; /**< Peer entity expanded ETCS-ID. */
	struct timeval startTime;     /**< Time of the last message received. */
} session_t;

/**< Struct holding the association between the expanded ETCS-ID and the IP of an entity. */
typedef struct
{
	uint32_t expEtcsId;         /**< The expanded ETCS-ID. */
	char     ip[MAX_IP_LENGTH]; /**< The IP in ascii. */
} kms_entity_id;

/**< Configuration struct for ssl137_lib. */
typedef struct
{
	char rsaCACertificateFile[MAX_PATH_LENGTH];    /**< The path of the CA certificate. */
	char rsaKey[MAX_PATH_LENGTH];                  /**< The path of the private key. */
	char rsaCertificate[MAX_PATH_LENGTH];          /**< The path of the certificate. */
	kms_entity_id myEntityId;                      /**< My entity id. */
	kms_entity_id kmsEntitiesId[MAX_KMS_ENTITIES]; /**< Other entity id. */
} ss137_lib_configuration_t;

/*****************************************************************************
 * PUBLIC FUNCTION PROTOTYPES
 *****************************************************************************/

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


error_code_t evaluateChecksum(notif_key_db_checksum_t* const checksum,
							  const k_struct_t k_struct_list[],
							  const uint32_t k_struct_num);

#endif /* KMC_SS137_LIB_H_ */
