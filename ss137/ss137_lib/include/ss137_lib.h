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


/* subset-137 libary functions */
int32_t sendNotifSessionInit(const session_t* const curr_session);

int32_t sendNotifEndUpdate(const session_t* const curr_session);


/* command */
int32_t sendCmdAddKeys(const cmd_add_keys_t* const payload,
					   const session_t* const curr_session);

int32_t sendCmdDeleteKeys(const cmd_del_keys_t* const payload,
						  const session_t* const curr_session);

int32_t sendCmdDeleteAllKeys(const session_t* const curr_session);

int32_t sendCmdReqKeyDBChecksum(const session_t* const curr_session);

int32_t sendCmdUpKeyValidities(const cmd_up_key_val_t* const payload,
							   const session_t* const curr_session);

int32_t sendCmdUpKeyEntities(const cmd_up_key_ent_t* const payload,
							 const session_t* const curr_session);

int32_t sendCmdReqKeyDBChecksum(const session_t* const curr_session);

int32_t sendCmdReqKeyOperation(const cmd_req_key_op_t* const payload,
							   const session_t* const curr_session);

int32_t sendNotifKeyUpdateStatus(const notif_key_up_status_t* const payload,
								 const session_t* const curr_session);

int32_t sendNotifAckKeyUpStatus(const session_t* const curr_session);

/* notification */
int32_t sendNotifResponse(const notif_response_t* const payload,
						  const session_t* const curr_session);

int32_t sendNotifKeyDBChecksum(const notif_key_db_checksum_t* const payload,
							   const session_t* const curr_session);

int32_t sendNotifKeyOpReqRcvd(const notif_key_op_req_rcvd_t* const payload,
							  const session_t* const curr_session);



int32_t waitForSessionInit(void* const payload,
						   session_t* const curr_session);

int32_t waitForResponse(void* const payload,
						session_t* const curr_session);


int32_t waitForRequestFromKMCToKMC(void* const payload,
								   uint32_t* const request_type,
								   session_t* const curr_session);

int32_t waitForRequestFromKMCToKMAC(void* const payload,
									uint32_t* const request_type,
									session_t* const curr_session);


#endif /* KMC_SS137_LIB_H_ */
