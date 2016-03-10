/**************************************************************************//**
 *
 * ...
 *
 * This file ...
 *
 * @file: ss137/ss137_lib/src/ss137_lib.c
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

#include <stdio.h>     /* for fopen, snprintf, etc... */
#include <string.h>    /* for memmove, memcmp, memset */
#include <arpa/inet.h> /* for htons, etc.. */
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/types.h>

#include "common.h"
#include "net_utils.h"
#include "tls_wrapper.h"
#include "msg_definitions.h"
#include "ss137_lib.h"

/*****************************************************************************
 * DEFINES
 ******************************************************************************/

#define INIT_CONNECTION_TIMEOUT (15U)

/*****************************************************************************
 * TYPEDEFS
 *****************************************************************************/

/*****************************************************************************
 * VARIABLES
 *****************************************************************************/

static uint16_t mySeqNum = 0U;

static const uint8_t supportedVersion[NUM_VERSION] = {2U};

/*****************************************************************************
 * LOCAL FUNCTION PROTOTYPES
 *****************************************************************************/

/*init and close app level connection */
static error_code_t sendNotifSessionInit(session_t* const curr_session);

static error_code_t sendNotifSessionEnd(session_t* const curr_session);

/* command */
static error_code_t sendCmdAddKeys(const request_t* const request,
										   const session_t* const curr_session);

static error_code_t sendCmdDeleteKeys(const request_t* const request,
											  const session_t* const curr_session);

static error_code_t sendCmdUpKeyValidities(const request_t* const request,
												   const session_t* const curr_session);

static error_code_t sendCmdUpKeyEntities(const request_t* const payload,
												 const session_t* const curr_session);

static error_code_t sendCmdReqKeyDBChecksum(const session_t* const curr_session);

static error_code_t sendCmdDeleteAllKeys(const session_t* const curr_session);

static error_code_t sendCmdReqKeyDBChecksum(const session_t* const curr_session);

static error_code_t sendCmdReqKeyOperation(const request_t* const request,
												   const session_t* const curr_session);

static error_code_t sendNotifKeyUpdateStatus(const request_t* const request,
													 const session_t* const curr_session);

static error_code_t buildMsgHeader(write_stream_t* const ostream,
										   const uint32_t msg_length,
										   const uint32_t msg_type,
										   const uint32_t peer_etcs_id_exp,
										   const uint32_t trans_num);

/*convert request*/
static error_code_t convertMsgHeaderToHost(msg_header_t* const header,
												   read_stream_t* const istream);

static error_code_t convertCmdAddKeysToHost(request_t* const request,
													read_stream_t* const istream);

static error_code_t convertCmdDeleteKeysToHost(request_t* const request,
													   read_stream_t* const istream);
	
static error_code_t convertCmdUpKeyValiditiesToHost(request_t* const request,
															read_stream_t* const istream);

static error_code_t convertCmdUpKeyEntitiesToHost(request_t* const request,
														  read_stream_t* const istream);

static error_code_t convertNotifKeyOpReqRcvdToHost(response_t* const response,
														   read_stream_t* const istream);

static error_code_t convertNotifKeyUpdateStatusToHost(request_t* const request,
															  read_stream_t* const istream);

static error_code_t convertCmdReqKeyOperationToHost(request_t* const request,
															read_stream_t* const istream);

/*convert response */
static error_code_t convertNotifSessionInitToHost(notif_session_init_t* const request,
														  read_stream_t* const istream);

static error_code_t convertNotifResponseToHost(response_t* const response,
													   read_stream_t* const istream);

static error_code_t convertNotifKeyDBChecksumToHost(response_t* const response,
															read_stream_t* const istream);
	
static error_code_t convertMsgHeaderToHost(msg_header_t* const header,
												   read_stream_t* const istream);

static error_code_t checkMsgHeader(session_t* const curr_session,
								   response_reason_t* const result,
								   const msg_header_t* const header,
								   const uint32_t exp_msg_length);

static error_code_t sendMsg(write_stream_t* const ostream,
									const uint32_t tls_id);

static error_code_t receiveMsg(read_stream_t* const istream,
									   const uint8_t timeout,
									   const uint32_t tls_id);

static void getMyEtcsIDExp(uint32_t* const my_etcs_id_exp);

/*****************************************************************************
 * LOCAL FUNCTION DECLARATIONS
 *****************************************************************************/

static void getMyEtcsIDExp(uint32_t* const my_etcs_id_exp)
{
	ASSERT(my_etcs_id_exp != NULL, E_NULL_POINTER);
	/* TBD decide how to get my id */
#ifdef KMC
	*my_etcs_id_exp = 0xAABBCCDD;	
#else
	*my_etcs_id_exp = 0x11223344;	
#endif
	return;
}

static error_code_t buildMsgHeader(write_stream_t* const ostream,
										   const uint32_t msg_length,
										   const uint32_t msg_type,
										   const uint32_t peer_etcs_id_exp,
										   const uint32_t trans_num)
{

	msg_header_t header;
	uint32_t my_etcs_id_exp = 0U;
	
	ASSERT(ostream != NULL, E_NULL_POINTER);

	getMyEtcsIDExp(&my_etcs_id_exp);
	
	memset(&header, 0U, sizeof(msg_header_t));
	
	header.msgLength = msg_length;
	header.version   = supportedVersion[0];
	header.recIDExp  = peer_etcs_id_exp;
	header.sendIDExp = my_etcs_id_exp;
	header.transNum  = trans_num;
	header.seqNum    = mySeqNum;
	header.msgType   = msg_type;

	hostToNet32(ostream, header.msgLength);
	hostToNet8(ostream, &header.version, sizeof(uint8_t));
	hostToNet32(ostream, header.recIDExp);
	hostToNet32(ostream, header.sendIDExp);
	hostToNet32(ostream, header.transNum);
	hostToNet16(ostream, header.seqNum);
	hostToNet8(ostream, &header.msgType, sizeof(uint8_t));
	
	return(SUCCESS);
}

static error_code_t convertMsgHeaderToHost(msg_header_t* const header,
										   read_stream_t* const istream)
{
	ASSERT((istream != NULL) && (header != NULL), E_NULL_POINTER);

	netToHost32(&header->msgLength, istream);
	netToHost8(&header->version, (uint32_t)sizeof(uint8_t), istream);
	netToHost32(&header->recIDExp, istream);
	netToHost32(&header->sendIDExp, istream);
	netToHost32(&header->transNum, istream);
	netToHost16(&header->seqNum, istream);
	netToHost8(&header->msgType, (uint32_t)sizeof(uint8_t), istream);

    return(SUCCESS);
}


static error_code_t convertCmdAddKeysToHost(request_t* const request,
													read_stream_t* const istream)
{
	uint32_t i = 0U;
	uint32_t j = 0U;
	
	ASSERT((istream != NULL) && (request != NULL), E_NULL_POINTER);

	netToHost16(&request->reqNum, istream);

	for(i = 0U; i < request->reqNum; i++)
	{
		netToHost8(&request->kStructList[i].length, sizeof(uint8_t), istream);
		netToHost32(&request->kStructList[i].kIdent.genID, istream);
		netToHost32(&request->kStructList[i].kIdent.serNum, istream);
		netToHost32(&request->kStructList[i].etcsID, istream);
		netToHost8(request->kStructList[i].kMAC, (uint32_t)KMAC_SIZE, istream);
		netToHost16(&request->kStructList[i].peerNum, istream);

		for (j = 0U; j < request->kStructList[i].peerNum; j++)
		{
			netToHost32(& request->kStructList[i].peerID[j], istream);
		}
		netToHost32(&request->kStructList[i].startValidity, istream);
		netToHost32(&request->kStructList[i].endValidity, istream);
	}

	return(SUCCESS);
}

static error_code_t convertCmdDeleteKeysToHost(request_t* const request,
													   read_stream_t* const istream)
{
	uint32_t i = 0U;

	ASSERT((istream != NULL) && (request != NULL), E_NULL_POINTER);

	netToHost16(&request->reqNum, istream);

	for(i = 0U; i < request->reqNum; i++)
	{
		netToHost32(&request->kIdentList[i].genID, istream);
		netToHost32(&request->kIdentList[i].genID, istream);
	}
	
	return(SUCCESS);
}

static error_code_t convertCmdUpKeyValiditiesToHost(request_t* const request,
															read_stream_t* const istream)
{
	uint32_t i = 0U;
	
	ASSERT((istream != NULL) && (request != NULL), E_NULL_POINTER);

	netToHost16(&request->reqNum, istream);

	for(i = 0U; i < request->reqNum; i++)
	{
		netToHost32(&request->kValidityList[i].kIdent.genID, istream);
		netToHost32(&request->kValidityList[i].kIdent.serNum, istream);
		netToHost32(&request->kValidityList[i].startValidity, istream);
		netToHost32(&request->kValidityList[i].endValidity, istream);
	}
		
	return(SUCCESS);
}


static error_code_t convertCmdUpKeyEntitiesToHost(request_t* const request,
														  read_stream_t* const istream)
{
	uint32_t i = 0U;
	uint32_t j = 0U;

	ASSERT((istream != NULL) && (request != NULL), E_NULL_POINTER);

	netToHost16(&request->reqNum, istream);

	for(i = 0U; i < request->reqNum; i++)
	{
		netToHost32(&request->kEntityList[i].kIdent.genID, istream);
		netToHost32(&request->kEntityList[i].kIdent.serNum, istream);
		netToHost16(&request->kEntityList[i].peerNum, istream);

		for (j = 0U; j < request->kEntityList[i].peerNum; j++)
		{
			netToHost32(&request->kEntityList[i].peerID[j], istream);
		}
	}
	
	return(SUCCESS);
}


static error_code_t convertCmdReqKeyOperationToHost(request_t* const request,
															read_stream_t* const istream)
{
	ASSERT((istream != NULL) && (request != NULL), E_NULL_POINTER);

	netToHost32(&request->reqKeyOpPayload.etcsID, istream);
	netToHost8(&request->reqKeyOpPayload.reason, sizeof(uint8_t), istream);

	if(request->reqKeyOpPayload.reason == RED_SCHED)
	{
		netToHost32(&request->reqKeyOpPayload.startValidity, istream);
		netToHost32(&request->reqKeyOpPayload.endValidity, istream);
	}
	
	netToHost16(&request->reqKeyOpPayload.textLength, istream);
	netToHost8((uint8_t*)request->reqKeyOpPayload.text,
			   request->reqKeyOpPayload.textLength, istream);
	
	return(SUCCESS);
}


static error_code_t convertNotifKeyUpdateStatusToHost(request_t* const request,
															  read_stream_t* const istream)
{
	ASSERT((istream != NULL) && (request != NULL), E_NULL_POINTER);

	netToHost32(&request->keyUpStatusPayload.kIdent.genID, istream);
	netToHost32(&request->keyUpStatusPayload.kIdent.serNum, istream);
	netToHost8(&request->keyUpStatusPayload.kStatus, sizeof(uint8_t), istream);
	
	return(SUCCESS);
}


static error_code_t convertNotifKeyOpReqRcvdToHost(response_t* const response,
														   read_stream_t* const istream)
{
	ASSERT((istream != NULL) && (response != NULL), E_NULL_POINTER);

	netToHost16(&response->keyOpRecvdPayload.maxTime, istream);

	return(SUCCESS);
}


static error_code_t convertNotifSessionInitToHost(notif_session_init_t* const response,
														  read_stream_t* const istream)
{
	ASSERT((istream != NULL) && (response != NULL), E_NULL_POINTER);

	netToHost8(&response->nVersion, sizeof(uint8_t), istream);
	netToHost8(response->version, sizeof(uint8_t)*NUM_VERSION, istream);
	netToHost8(&response->appTimeout, sizeof(uint8_t), istream);
	
	return(SUCCESS);
}

static error_code_t convertNotifResponseToHost(response_t* const response,
													   read_stream_t* const istream)
{
	ASSERT((istream != NULL) && (response != NULL), E_NULL_POINTER);

	netToHost8(&response->notifPayload.reason, sizeof(uint8_t), istream);
	netToHost16(&response->notifPayload.reqNum, istream);
	netToHost8(response->notifPayload.notificationList,
			   sizeof(uint8_t)*response->notifPayload.reqNum, istream);

	return(SUCCESS);
}

static error_code_t convertNotifKeyDBChecksumToHost(response_t* const response,
															read_stream_t* const istream)
{
	ASSERT((istream != NULL) && (response != NULL), E_NULL_POINTER);

	netToHost8(response->dbChecksumPayload.checksum, (uint32_t)CHECKSUM_SIZE, istream);
	
	return(SUCCESS);
}

static error_code_t checkMsgHeader(session_t* const curr_session,
								   response_reason_t* const result,
								   const msg_header_t* const header,
								   const uint32_t exp_msg_length)
{
	uint32_t my_etcs_id_exp = 0U;

	ASSERT(header != NULL, E_NULL_POINTER);
	ASSERT(curr_session != NULL, E_NULL_POINTER);
	ASSERT(result, E_NULL_POINTER);

	getMyEtcsIDExp(&my_etcs_id_exp);
	
	if( header->sendIDExp != curr_session->peerEtcsIDExp )
	{
		/* wrong sender id */
		*result = RESP_WRONG_SENDER_ID;
		warning_print("Invalid sender ID:  received 0x%08x exp 0x%08x\n",
					  header->sendIDExp, curr_session->peerEtcsIDExp);
	}
	else if( header->recIDExp != my_etcs_id_exp )
	{
		/* wrong receiver id */
		*result = RESP_WRONG_REC_ID;
		warning_print("Invalid rec ID:  received 0x%08x exp 0x%08x\n",
					  header->recIDExp, my_etcs_id_exp);
	}
	else if( header->msgLength !=  exp_msg_length )
	{
		/* wrong msg length */
		*result = RESP_WRONG_LENGTH;
		warning_print("Invalid msg length:  received 0x%08x exp 0x%08x\n",
					  header->msgLength, exp_msg_length);
	}
	else if( header->msgType > NOTIF_KEY_DB_CHECKSUM )
	{
		/* msg type not supported */
		*result = RESP_NOT_SUPPORTED;
		warning_print("Invalid msg type:  received 0x%02x\n",
					  header->msgType);
	}
	else if( header->version != supportedVersion[0] )
	{
		/* wrong version */
		*result = RESP_WRONG_VERSION;
		warning_print("Invalid interface version:  received 0x%02x exp 0x%02x\n",
					  header->version, supportedVersion[0]);
	}
	/* for the NOTIF_SESSION_INIT  message the sequence
	   number shall not be checked */
	else if( (header->seqNum != (curr_session->peerSeqNum + 1)) &&
			 (header->msgType != NOTIF_SESSION_INIT))
	{
		/* wrong sequence number */
		*result = RESP_WRONG_SEQ_NUM;
		warning_print("Invalid seq num:  received 0x%04x exp 0x%04x\n",
					  curr_session->transNum, header->transNum);
	}
	else if( ((header->transNum !=  curr_session->transNum) &&
			  (header->msgType != NOTIF_END_OF_UPDATE)) ||
			 ((header->transNum != 0U) &&
			  (header->msgType == NOTIF_END_OF_UPDATE)))
	{
		/* wrong transaction number */
		*result = RESP_WRONG_TRANS_NUM;
		warning_print("Invalid trans number:  received 0x%08x exp 0x%08x\n",
					  curr_session->transNum, header->transNum);
	}
	else
	{
		/* valid header */
		*result = RESP_OK;
	}

	/* set new peer sequence number */
	curr_session->peerSeqNum = header->seqNum;
	
	return(SUCCESS);
}

/* ostream shall be already initialized */
static error_code_t sendMsg(write_stream_t* const ostream,
									const uint32_t tls_id)
{
	
	uint32_t bytes_sent = 0U;
	
	ASSERT(ostream != NULL, E_NULL_POINTER);
	
	if(sendTLS(&bytes_sent, ostream->buffer, ostream->curSize, tls_id) != SUCCESS)
	{
		return(ERROR);
	}
	
	if( bytes_sent != ostream->curSize)
	{
		err_print("Cannot complete send operation of msg (bytes sent %d, expectd %d)\n", bytes_sent, ostream->curSize);
		return(ERROR);
	}
	
#ifdef __DEBUG__
	char dump_msg[2000];
	char tmp_str[5];
	uint32_t i = 0U;
	memset(dump_msg, 0, 2000);
	memset(tmp_str, 0, 5);
	sprintf(dump_msg, "Msg sent(%d bytes): ", ostream->curSize);
	for(i = 0U; i < ostream->curSize; i++)
	{
		sprintf(tmp_str, "0x%02X ", ostream->buffer[i]);
		strcat(dump_msg, tmp_str);
	}
	debug_print("%s\n", dump_msg);
#endif

	mySeqNum++;
	
	return(SUCCESS);
}

static error_code_t evaluateRemainingTime(uint8_t *const remaining_time,
												  const struct timeval start_time,
												  const uint8_t exp_timeout)
{
	struct timeval curr_time;
	uint64_t elapsed_time;
	uint64_t tmp_remaining_time;
	
	gettimeofday(&curr_time, NULL);

	if(curr_time.tv_sec < start_time.tv_sec)
	{
		return(ERROR);
	}
	else
	{
		elapsed_time = (curr_time.tv_sec - start_time.tv_sec) +
			((curr_time.tv_usec - start_time.tv_usec)/1000000U);

		tmp_remaining_time = exp_timeout - elapsed_time;
		if(tmp_remaining_time > 0xFFU)
		{
			return(ERROR);
		}
		else
		{
			*remaining_time = (uint8_t)tmp_remaining_time;
		}
	}
	
	return(SUCCESS);
}

/* istream shall be already initialized */
static error_code_t receiveMsg(read_stream_t* const istream,
									   const uint8_t timeout,
									   const uint32_t tls_id)
{

	ASSERT(istream != NULL, E_NULL_POINTER);

	debug_print("Waiting time = %d\n", timeout);
	
	if(receiveTLS(&istream->validBytes, istream->buffer,
				  (uint32_t)MSG_MAX_SIZE, timeout, tls_id) != SUCCESS)
	{
		return(ERROR);
	}

#ifdef __DEBUG__
	char dump_msg[2000];
	char tmp_str[5];
	uint32_t i = 0U;
	memset(dump_msg, 0, 2000);
	memset(tmp_str, 0, 5);
	sprintf(dump_msg, "Msg recv(%d bytes): ", istream->validBytes);
	for(i = 0U; i < istream->validBytes; i++)
	{
		sprintf(tmp_str, "0x%02X ", istream->buffer[i]);
		strcat(dump_msg, tmp_str);
	}
	debug_print("%s\n", dump_msg);
#endif

	return(SUCCESS);
}

static error_code_t sendNotifSessionInit(session_t* const curr_session)
{
	uint32_t msg_length = 0U;
	uint8_t tmp_num_version = NUM_VERSION;
	write_stream_t ostream;

	ASSERT(curr_session != NULL, E_NULL_POINTER);

	/* initialize output buffer */
	initWriteStream(&ostream);
	
	/* evaluate message length */
	msg_length = NOTIF_SESSION_INIT_SIZE;

	/* prepare msg header */
	buildMsgHeader(&ostream, msg_length, NOTIF_SESSION_INIT,
				   curr_session->peerEtcsIDExp, curr_session->transNum);

	/* serialize payload */
	hostToNet8(&ostream, &tmp_num_version, sizeof(uint8_t));
	hostToNet8(&ostream, supportedVersion, NUM_VERSION*sizeof(uint8_t));
	hostToNet8(&ostream, &curr_session->appTimeout, sizeof(uint8_t));

	if(sendMsg(&ostream, curr_session->tlsID) != SUCCESS)
	{
		return(ERROR);
	}
	
	return(SUCCESS);
}

static error_code_t sendNotifSessionEnd(session_t* const curr_session)
{
	uint32_t msg_length = 0U;
	write_stream_t ostream;
	
	ASSERT(curr_session != NULL, E_NULL_POINTER);

	/* the transaction number for end
	   session shall be set to 0 */
	curr_session->transNum = 0U;

	/* prepare output buffer */
	initWriteStream(&ostream);

	/* prepare message header */
	msg_length = NOTIF_END_UPDATE_SIZE;

	buildMsgHeader(&ostream, msg_length, NOTIF_END_OF_UPDATE,
				   curr_session->peerEtcsIDExp, curr_session->transNum);

	if(sendMsg(&ostream, curr_session->tlsID) != SUCCESS)
	{
		return(ERROR);
	}

	return(SUCCESS);
}

static error_code_t waitForSessionInit(notif_session_init_t* const payload,
									   response_reason_t* const result,
									   session_t* const curr_session)
{
	read_stream_t input_msg;
	msg_header_t header;
	uint8_t remaining_time = 0U;
	error_code_t error_code = ERROR;

	ASSERT(payload != NULL, E_NULL_POINTER);
	ASSERT(result != NULL, E_NULL_POINTER);
	ASSERT(curr_session != NULL, E_NULL_POINTER);
	
	initReadStream(&input_msg);

	/* evaluate difference between start  time and
	   current time in order to use the real app timeout value */
	if(evaluateRemainingTime(&remaining_time, curr_session->startTime, (uint8_t)INIT_CONNECTION_TIMEOUT) != SUCCESS)
	{
		return(ERROR);
	}

	if( receiveMsg(&input_msg, remaining_time, curr_session->tlsID) != SUCCESS )
	{
		return (error_code);
	}

	/* set the start time */
	gettimeofday(&(curr_session->startTime), NULL);

	convertMsgHeaderToHost(&header, &input_msg);

	checkMsgHeader(curr_session, result, &header, input_msg.validBytes);
	
	if( *result != RESP_OK)
	{
		warning_print("Error on checking header\n");
	}
	else
	{
		if( header.msgType != NOTIF_SESSION_INIT )
		{
			warning_print("Unexpected msg type received: rec %d\n", header.msgType);
			*result = RESP_NOT_SUPPORTED;
		}
		else
		{
			convertNotifSessionInitToHost((notif_session_init_t*)payload, &input_msg);
		}
		
		/* initialize peerSeqNumber */
		curr_session->peerSeqNum = header.seqNum;
		*result = RESP_OK;
	}
	
	return(SUCCESS);
}

static error_code_t sendCmdAddKeys(const request_t* const request,
								   const session_t* const curr_session)
{
	uint32_t i = 0U;
	uint32_t j = 0U;
	uint32_t k = 0U;
	uint32_t msg_length = 0U;
	write_stream_t ostream;
	
	ASSERT((curr_session != NULL) && (request != NULL), E_NULL_POINTER);
	ASSERT(request->reqNum < MAX_REQ_ADD_KEYS,  E_INVALID_PARAM);

	/* prepare output buffer */
	initWriteStream(&ostream);
	
	/* prepare message header */
	msg_length = CMD_ADD_KEYS_MIN_SIZE + (request->reqNum*K_STRUCT_MIN_SIZE);

	for(k = 0U; k < request->reqNum; k++)
	{
		msg_length += request->kStructList[k].peerNum*sizeof(uint32_t);
	}
	
	buildMsgHeader(&ostream, msg_length, CMD_ADD_KEYS,
				   curr_session->peerEtcsIDExp, curr_session->transNum);

	/* serialize request */
	hostToNet16(&ostream, request->reqNum);

	for(i = 0U; i < request->reqNum; i++)
	{
		hostToNet8(&ostream, &request->kStructList[i].length, sizeof(uint8_t));
		hostToNet32(&ostream, request->kStructList[i].kIdent.genID);
		hostToNet32(&ostream, request->kStructList[i].kIdent.serNum);
		hostToNet32(&ostream, request->kStructList[i].etcsID);
		hostToNet8(&ostream, request->kStructList[i].kMAC, (uint32_t)KMAC_SIZE);
		hostToNet16(&ostream, request->kStructList[i].peerNum);

		ASSERT(request->kStructList[i].peerNum < MAX_PEER_NUM,  E_INVALID_PARAM);

		for (j = 0U; j < request->kStructList[i].peerNum; j++)
		{
			hostToNet32(&ostream, request->kStructList[i].peerID[j]);
		}
		
		hostToNet32(&ostream, request->kStructList[i].startValidity);
		hostToNet32(&ostream, request->kStructList[i].endValidity);
	}

	if(sendMsg(&ostream, curr_session->tlsID) != SUCCESS)
	{
		return(ERROR);
	}
	
	return(SUCCESS);
}


static error_code_t sendCmdDeleteKeys(const request_t* const request,
											  const session_t* const curr_session)
{
	uint32_t msg_length = 0U;
	uint32_t i = 0U;
	write_stream_t ostream;
	
	ASSERT((curr_session != NULL) && (request != NULL), E_NULL_POINTER);
	ASSERT(request->reqNum < MAX_REQ_DEL_KEYS,  E_INVALID_PARAM);

	/* prepare output buffer */
	initWriteStream(&ostream);
	
	/* prepare message header */
	msg_length = CMD_DEL_KEYS_MIN_SIZE + (K_IDENT_SIZE * request->reqNum);
	
	buildMsgHeader(&ostream, msg_length, CMD_DELETE_KEYS,
				   curr_session->peerEtcsIDExp, curr_session->transNum);

	/* serialize request */
	hostToNet16(&ostream, request->reqNum);

	for(i = 0U; i < request->reqNum; i++)
	{
		hostToNet32(&ostream, request->kIdentList[i].genID);
		hostToNet32(&ostream, request->kIdentList[i].serNum);
	}

	if(sendMsg(&ostream, curr_session->tlsID) != SUCCESS)
	{
		return(ERROR);
	}

	return(SUCCESS);
}

static error_code_t sendCmdUpKeyValidities(const request_t* const request,
												   const session_t* const curr_session)
{
	uint32_t msg_length = 0U;
	uint32_t i = 0U;
	write_stream_t ostream;
 
	ASSERT((curr_session != NULL) && (request != NULL), E_NULL_POINTER);
	ASSERT(request->reqNum < MAX_REQ_UPDATE,  E_INVALID_PARAM);

	/* prepare output buffer */
	initWriteStream(&ostream);
	
	/* prepare message header */
	msg_length = CMD_UP_KEY_VAL_MIN_SIZE + (K_VALIDITY_SIZE*request->reqNum);
	
	buildMsgHeader(&ostream, msg_length, CMD_UPDATE_KEY_VALIDITIES,
				   curr_session->peerEtcsIDExp, curr_session->transNum);

	/* serialize request */
	hostToNet16(&ostream, request->reqNum);

	for(i = 0U; i < request->reqNum; i++)
	{
		hostToNet32(&ostream, request->kValidityList[i].kIdent.genID);
		hostToNet32(&ostream, request->kValidityList[i].kIdent.serNum);
		hostToNet32(&ostream, request->kValidityList[i].startValidity);
		hostToNet32(&ostream, request->kValidityList[i].endValidity);
	}

	if(sendMsg(&ostream, curr_session->tlsID) != SUCCESS)
	{
		return(ERROR);
	}

	return(SUCCESS);
}


static error_code_t sendCmdUpKeyEntities(const request_t* const request,
												 const session_t* const curr_session)
{
	uint32_t i = 0U;
	uint32_t j = 0U;
	uint32_t k = 0U;
	uint32_t msg_length = 0U;
	write_stream_t ostream;

	ASSERT((curr_session != NULL) && (request != NULL), E_NULL_POINTER);
	ASSERT(request->reqNum < MAX_REQ_UPDATE,  E_INVALID_PARAM);
	
	/* prepare output buffer */
	initWriteStream(&ostream);
	
	/* prepare message header */
	msg_length = CMD_UP_KEY_ENT_MIN_SIZE + (request->kEntityList[i].peerNum * K_ENTITY_MIN_SIZE);
	for(k = 0U; k < request->reqNum; k++)
	{
		msg_length += request->kEntityList[i].peerNum*sizeof(uint32_t);
	}
	
	buildMsgHeader(&ostream, msg_length, CMD_UPDATE_KEY_ENTITIES,
				   curr_session->peerEtcsIDExp, curr_session->transNum);

	/* serialize request */
	hostToNet16(&ostream, request->reqNum);

	for(i = 0U; i < request->reqNum; i++)
	{
		hostToNet32(&ostream, request->kEntityList[i].kIdent.genID);
		hostToNet32(&ostream, request->kEntityList[i].kIdent.serNum);
		hostToNet16(&ostream, request->kEntityList[i].peerNum);

		ASSERT(request->kEntityList[i].peerNum < MAX_PEER_NUM,  E_INVALID_PARAM);

		for (j = 0U; j < request->kEntityList[i].peerNum; j++)
		{
			hostToNet32(&ostream, request->kEntityList[i].peerID[j]);
		}
	}

	if(sendMsg(&ostream, curr_session->tlsID) != SUCCESS)
	{
		return(ERROR);
	}
	
	return(SUCCESS);
}


static error_code_t sendCmdDeleteAllKeys(const session_t* const curr_session)
{
	uint32_t msg_length = 0U;
	write_stream_t ostream;

	ASSERT(curr_session != NULL, E_NULL_POINTER);

	/* prepare output buffer */
	initWriteStream(&ostream);
	
	/* prepare message header */
	msg_length = CMD_DEL_ALL_KEYS_SIZE;
	
	buildMsgHeader(&ostream, msg_length, CMD_DELETE_ALL_KEYS,
				   curr_session->peerEtcsIDExp, curr_session->transNum);

	/* this command does not have request,
	   it consists only of the message header */
	if(sendMsg(&ostream, curr_session->tlsID) != SUCCESS)
	{
		return(ERROR);
	}
		
	return(SUCCESS);
}

static error_code_t sendCmdReqKeyDBChecksum(const session_t* const curr_session)
{
	uint32_t msg_length = 0U;
	write_stream_t ostream;
	
	ASSERT(curr_session != NULL, E_NULL_POINTER);

	/* prepare output buffer */
	initWriteStream(&ostream);
	
	/* prepare message header */
	msg_length = CMD_REQUEST_KEY_DB_CK_SIZE;
	
	buildMsgHeader(&ostream, msg_length, CMD_REQUEST_KEY_DB_CHECKSUM,
				   curr_session->peerEtcsIDExp, curr_session->transNum);

	if(sendMsg(&ostream, curr_session->tlsID) != SUCCESS)
	{
		return(ERROR);
	}

	return(SUCCESS);
}


static error_code_t sendCmdReqKeyOperation(const request_t* const request,
												   const session_t* const curr_session)
{
	uint32_t msg_length = 0U;
	write_stream_t ostream;
	
	ASSERT((curr_session != NULL) && (request != NULL), E_NULL_POINTER);
	ASSERT(strlen(request->reqKeyOpPayload.text) < MAX_TEXT_LENGTH, E_NULL_POINTER);

	/* prepare output buffer */
	initWriteStream(&ostream);
	
	/* prepare message header */
	msg_length = CMD_REQUEST_KEY_OP_MIN_SIZE+strlen(request->reqKeyOpPayload.text);
	
	buildMsgHeader(&ostream, msg_length, CMD_REQUEST_KEY_OPERATION,
				   curr_session->peerEtcsIDExp, curr_session->transNum);

	/* serialize payload */

	hostToNet32(&ostream,  request->reqKeyOpPayload.etcsID);
	hostToNet8(&ostream,  &request->reqKeyOpPayload.reason,  sizeof(uint8_t));

	/* the field start and end validity shall be used only in case of reason 2 */
	if( request->reqKeyOpPayload.reason == RED_SCHED)
	{
		hostToNet32(&ostream,  request->reqKeyOpPayload.startValidity);
		hostToNet32(&ostream,  request->reqKeyOpPayload.endValidity);
	}
	
	hostToNet32(&ostream,  request->reqKeyOpPayload.textLength);
	hostToNet8(&ostream, (uint8_t*)request->reqKeyOpPayload.text,
			   request->reqKeyOpPayload.textLength);

	if(sendMsg(&ostream, curr_session->tlsID) != SUCCESS)
	{
		return(ERROR);
	}
	
	return(SUCCESS);
}

static error_code_t sendNotifKeyUpdateStatus(const request_t* const request,
													 const session_t* const curr_session)
{
	uint32_t msg_length = 0U;
	write_stream_t ostream;

	ASSERT((curr_session != NULL) && (request != NULL), E_NULL_POINTER);

	/* prepare output buffer */
	initWriteStream(&ostream);
	
	/* prepare message header */
	msg_length = NOTIF_KEY_UP_STATUS_SIZE;
	
	buildMsgHeader(&ostream, msg_length, NOTIF_KEY_UPDATE_STATUS,
				   curr_session->peerEtcsIDExp, curr_session->transNum);
	
	/* serialize payload */
	hostToNet32(&ostream, request->keyUpStatusPayload.kIdent.genID);
	hostToNet32(&ostream, request->keyUpStatusPayload.kIdent.serNum);
	hostToNet8(&ostream, &request->keyUpStatusPayload.kStatus, sizeof(uint8_t));

	if(sendMsg(&ostream, curr_session->tlsID) != SUCCESS)
	{
		return(ERROR);
	}

	return(SUCCESS);
}



/*****************************************************************************
 * PUBLIC FUNCTION DECLARATIONS
 *****************************************************************************/

error_code_t sendNotifKeyDBChecksum(const response_t* const response,
											const session_t* const curr_session)
{
	uint32_t msg_length = 0U;
	write_stream_t ostream;
	
	ASSERT((curr_session != NULL) && (response != NULL), E_NULL_POINTER);

	/* prepare output buffer */
	initWriteStream(&ostream);
	
	/* prepare message header */
	msg_length = NOTIF_KEY_DB_CHECKSUM_SIZE;
	
	buildMsgHeader(&ostream, msg_length, NOTIF_KEY_DB_CHECKSUM,
				   curr_session->peerEtcsIDExp, curr_session->transNum);

	/* serialize payload */
	hostToNet8(&ostream, response->dbChecksumPayload.checksum, (uint32_t)CHECKSUM_SIZE);

	if(sendMsg(&ostream, curr_session->tlsID) != SUCCESS)
	{
		return(ERROR);
	}
	
	return(SUCCESS);
}

error_code_t sendNotifResponse(const response_t* const response,
									   const session_t* const curr_session)
{
	uint32_t msg_length = 0U;
	write_stream_t ostream;
	
	ASSERT((curr_session != NULL) && (response != NULL), E_NULL_POINTER);
	ASSERT(response->notifPayload.reqNum < MAX_REQ_NOTIF,  E_INVALID_PARAM);

	/* prepare output buffer */
	initWriteStream(&ostream);
	
	/* prepare message header */
	msg_length = NOTIF_RESPONSE_MIN_SIZE+sizeof(uint8_t)*response->notifPayload.reqNum;
	
	buildMsgHeader(&ostream, msg_length, NOTIF_RESPONSE,
				   curr_session->peerEtcsIDExp, curr_session->transNum);

	/* serialize payload */
	hostToNet8(&ostream, &response->notifPayload.reason, sizeof(uint8_t));
	hostToNet16(&ostream, response->notifPayload.reqNum);

	if(response->notifPayload.reqNum != 0U)
	{
		hostToNet8(&ostream, response->notifPayload.notificationList,
				   sizeof(uint8_t)*response->notifPayload.reqNum);
	}

	if(sendMsg(&ostream, curr_session->tlsID) != SUCCESS)
	{
		return(ERROR);
	}
	
	return(SUCCESS);
}

error_code_t sendNotifKeyOpReqRcvd(const response_t* const response,
										   const session_t* const curr_session)
{
	uint32_t msg_length = 0U;
	write_stream_t ostream;

	ASSERT((curr_session != NULL) && (response != NULL), E_NULL_POINTER);

	/* prepare output buffer */
	initWriteStream(&ostream);
	
	/* prepare message header */
	msg_length = NOTIF_KEY_OP_REQ_RCVD_SIZE;
	
	buildMsgHeader(&ostream, msg_length, NOTIF_KEY_OPERATION_REQ_RCVD,
				   curr_session->peerEtcsIDExp, curr_session->transNum);

	/* serialize payload */
	hostToNet16(&ostream, response->keyOpRecvdPayload.maxTime);

	if(sendMsg(&ostream, curr_session->tlsID) != SUCCESS)
	{
		return(ERROR);
	}
	
	return(SUCCESS);
}

error_code_t sendNotifAckKeyUpStatus(const session_t* const curr_session)
{
	uint32_t msg_length = 0U;
	write_stream_t ostream;
	
	ASSERT(curr_session != NULL, E_NULL_POINTER);

	/* prepare output buffer */
	initWriteStream(&ostream);
	
	/* prepare message header */
	msg_length = NOTIF_ACK_KEY_UP_STATUS_SIZE;
	
	buildMsgHeader(&ostream, msg_length, NOTIF_ACK_KEY_UPDATE_STATUS,
				   curr_session->peerEtcsIDExp, curr_session->transNum);

	if(sendMsg(&ostream, curr_session->tlsID) != SUCCESS)
	{
		return(ERROR);
	}
	
	return(SUCCESS);
}




error_code_t startClientTLS(uint32_t* const tls_id)
{
	ASSERT(tls_id != NULL, E_NULL_POINTER);

	if(initClientTLS(tls_id) != SUCCESS)
	{
		return(ERROR);
	}

	return(SUCCESS);
}

error_code_t connectToTLSServer(const uint32_t const tls_id,
										const char* const r_ip)
{
	ASSERT(r_ip != NULL, E_NULL_POINTER);

	if(connectTLS(tls_id, r_ip, DEFAULT_PORT) != SUCCESS)
	{
		return(ERROR);
	}

	return(SUCCESS);
}

error_code_t startServerTLS(void)
{
	if(initServerTLS(DEFAULT_PORT) != SUCCESS)
	{
		return(ERROR);
	}

	return(SUCCESS);
}

error_code_t listenForTLSClient(uint32_t* const tls_id, uint32_t* const client_ip)
{
	ASSERT(tls_id != NULL, E_NULL_POINTER);

	if(acceptTLS(tls_id, client_ip) != SUCCESS)
	{
		err_print("Error occurred in acceptTLS()\n");
		return(ERROR);
	}

	debug_print("Connection from client %d.%d.%d.%d\n",
				(*client_ip) & (0xFF),
				(*client_ip >> 8) & (0xFF),
				(*client_ip >> 16) & (0xFF),
				(*client_ip >> 24) & (0xFF));

	return(SUCCESS);
}

error_code_t closeTLSConnection(const uint32_t tls_id)
{

	closeTLS(tls_id);

	return(SUCCESS);
}


error_code_t waitForRequestFromKMCToKMAC(request_t* const request,
										 session_t* const curr_session)
{
	read_stream_t input_msg;
	msg_header_t header;
	response_reason_t result;
		
	ASSERT(request != NULL, E_NULL_POINTER);
	ASSERT(curr_session != NULL, E_NULL_POINTER);
	
	initReadStream(&input_msg);
	
	if(receiveMsg(&input_msg, curr_session->appTimeout, curr_session->tlsID) != SUCCESS)
	{
		return(ERROR);
	}
	
	convertMsgHeaderToHost(&header, &input_msg);
	
	checkMsgHeader(curr_session, &result, &header, input_msg.validBytes);

	if(result != RESP_OK)
	{
		/* tbd add send of notif init */
		warning_print("Error on checking header\n");
		return(ERROR);
	}

	switch(header.msgType)
	{
	case(CMD_ADD_KEYS):
		convertCmdAddKeysToHost(request, &input_msg);
		request->msgType = header.msgType;
		break;
	case(CMD_DELETE_KEYS):
		convertCmdDeleteKeysToHost(request, &input_msg);
		request->msgType = header.msgType;
		break;
	case(CMD_DELETE_ALL_KEYS):
		/* this message has no request */
		request->msgType = header.msgType;
		break;
	case(CMD_UPDATE_KEY_VALIDITIES):
		convertCmdUpKeyValiditiesToHost(request, &input_msg);
		request->msgType = header.msgType;
		break;
	case(CMD_UPDATE_KEY_ENTITIES):
		convertCmdUpKeyEntitiesToHost(request, &input_msg);
		request->msgType = header.msgType;
		break;
	case(CMD_REQUEST_KEY_DB_CHECKSUM):
		/* this message has no payload */
		request->msgType = header.msgType;
		break;
	case(NOTIF_END_OF_UPDATE):
		/* this message has no payload */
		request->msgType = header.msgType;
		break;
	default:
		/* tbd add send of notif init */
		err_print("Unexpected msg type received: rec %d\n", header.msgType);
		result = RESP_NOT_SUPPORTED;
		return(ERROR);
	}

	curr_session->transNum = header.transNum;

	return(SUCCESS);
}


error_code_t waitForRequestFromKMCToKMC(request_t* const request,
										session_t* const curr_session)
{
	read_stream_t input_msg;
	msg_header_t header;
	response_reason_t result;

	ASSERT(request != NULL, E_NULL_POINTER);
	ASSERT(curr_session != NULL, E_NULL_POINTER);
	
	initReadStream(&input_msg);
	
	if(receiveMsg(&input_msg, curr_session->appTimeout, curr_session->tlsID) != SUCCESS)
	{
		return(ERROR);
	}

	convertMsgHeaderToHost(&header, &input_msg);
	
	checkMsgHeader(curr_session, &result, &header, input_msg.validBytes);

	if(result != RESP_OK)
	{
		/* tbd add send of notif init */
		err_print("Error on checking header\n");
		return(ERROR);
	}

	switch(header.msgType)
	{
	case(CMD_ADD_KEYS):
		convertCmdAddKeysToHost(request, &input_msg);
		request->msgType = header.msgType;
		break;
	case(CMD_DELETE_KEYS):
		convertCmdDeleteKeysToHost(request, &input_msg);
		request->msgType = header.msgType;
		break;
	case(CMD_UPDATE_KEY_VALIDITIES):
		convertCmdUpKeyValiditiesToHost(request, &input_msg);
		request->msgType = header.msgType;
		break;
	case(CMD_UPDATE_KEY_ENTITIES):
		convertCmdUpKeyEntitiesToHost(request, &input_msg);
		request->msgType = header.msgType;
		break;
	case(CMD_REQUEST_KEY_OPERATION):
		convertCmdReqKeyOperationToHost(request, &input_msg);
		request->msgType = header.msgType;
		break;
	case(NOTIF_KEY_UPDATE_STATUS):
		convertNotifKeyUpdateStatusToHost(request, &input_msg);
		request->msgType = header.msgType;
		break;
	case(NOTIF_END_OF_UPDATE):
		/* this message has no payload */
		request->msgType = header.msgType;
		break;
	default:
		/* tbd add send of notif init */
		err_print("Unexpected msg type received: rec %d\n", header.msgType);
		result = RESP_NOT_SUPPORTED;
		return(ERROR);
	}
	
	return(SUCCESS);
}

static error_code_t waitForResponse(response_t* const response,
									session_t* const curr_session,
									response_reason_t* const result,
									const msg_type_t exp_msg_type)
{
	msg_header_t header;
	read_stream_t input_msg;
										   
	ASSERT(response!= NULL, E_NULL_POINTER);
	ASSERT(curr_session != NULL, E_NULL_POINTER);

	initReadStream(&input_msg);
		
	if(receiveMsg(&input_msg, curr_session->appTimeout, curr_session->tlsID) != SUCCESS)
	{
		return(ERROR);
	}

	convertMsgHeaderToHost(&header, &input_msg);

	checkMsgHeader(curr_session, result, &header, input_msg.validBytes);
	
	if(*result != RESP_OK)
	{
		err_print("Error on checking header\n");
		return(ERROR);
	}
	else
	{
		/* notif response could be received in case of error */
		if((exp_msg_type != header.msgType ) &&
		   exp_msg_type != NOTIF_RESPONSE)
		{
			err_print("Unexpected msg type received: rec %d\n", header.msgType);
		}
		else
		{
			switch(header.msgType)
			{
			case(NOTIF_RESPONSE):
				convertNotifResponseToHost(response, &input_msg);
				break;
			case(NOTIF_KEY_DB_CHECKSUM):
				convertNotifKeyDBChecksumToHost(response, &input_msg);
				break;
			case(NOTIF_KEY_OPERATION_REQ_RCVD):
				convertNotifKeyOpReqRcvdToHost(response, &input_msg);
				break;
			case(NOTIF_ACK_KEY_UPDATE_STATUS):
				/* this message has no payload */
				break;
			default:
				*result = RESP_NOT_SUPPORTED;
				return(ERROR);
			}
		}
	}
	
	return(SUCCESS);
}

error_code_t initAppSession(session_t* const curr_session,
									const uint8_t app_timeout,
									const uint32_t peer_etcs_id_exp)
{
	notif_session_init_t response;
	response_reason_t result = RESP_OK;

	/* init session struct */
	/* the transaction number for init
	   session shall be set to 0 */
	curr_session->transNum = 0U;
	curr_session->appTimeout = app_timeout;
	curr_session->peerEtcsIDExp = peer_etcs_id_exp;
	gettimeofday(&(curr_session->startTime), NULL);
	
	if(sendNotifSessionInit(curr_session) != SUCCESS)
	{
		return(ERROR);
	}

	if(waitForSessionInit(&response, &result, curr_session) != SUCCESS)
	{
		return(ERROR);
	}
		
	if(result != RESP_OK)
	{
		response_t response;
		response.notifPayload.reason = result;
		response.notifPayload.reqNum = 0U;
		sendNotifResponse(&response, curr_session);
		return(ERROR);
	}
	else
	{
		/* negotiate app_timeout and verify interface version compatibility */
		if(curr_session->appTimeout == APP_TIMEOUT_PEER_DEF)
		{
			curr_session->appTimeout = response.appTimeout;
		}
		
		if( response.version[0] != supportedVersion[0] )
		{
			response_t notif_response;
			notif_response.notifPayload.reason = RESP_WRONG_VERSION;
			notif_response.notifPayload.reqNum = 0U;
			sendNotifResponse(&notif_response,
							  curr_session);
			return(ERROR);
		}
		
		curr_session->transNum++;
	}

	return(SUCCESS);
}

/* this function send the notif session end message */
error_code_t endAppSession(session_t* const curr_session)
{

	if(sendNotifSessionEnd(curr_session) != SUCCESS)
	{
		return(ERROR);
	}

	return(SUCCESS);
}


error_code_t performAddKeysOperation(session_t* const curr_session,
									 response_t* const response,
									 const request_t* const request)
{
	msg_type_t exp_msg_type = NOTIF_RESPONSE;
	response_reason_t result;
		
	if(sendCmdAddKeys(request, curr_session) != SUCCESS)
	{
		return(ERROR);
	}

	if(waitForResponse(response, curr_session, &result, exp_msg_type) != SUCCESS)
	{
		return(ERROR);
	}

	if(result != RESP_OK)
	{
		response_t response;
		response.notifPayload.reason = result;
		response.notifPayload.reqNum = 0U;
		sendNotifResponse(&response, curr_session);
		return(ERROR);
	}
	else if ( request->reqNum != response->notifPayload.reqNum)
	{
		response_t response;
		response.notifPayload.reason = RESP_WRONG_FORMAT;
		response.notifPayload.reqNum = 0U;
		sendNotifResponse(&response, curr_session);
		return(ERROR);
	}
	else
	{
		curr_session->transNum++;
	}
	
	return(SUCCESS);
}

error_code_t performDelKeysOperation(session_t* const curr_session,
											 response_t* const response,
											 const request_t* const request)
{
	msg_type_t exp_msg_type = NOTIF_RESPONSE;
	response_reason_t result;
	
	if(sendCmdDeleteKeys(request, curr_session) != SUCCESS)
	{
		return(ERROR);
	}

	if(waitForResponse(response, curr_session, &result, exp_msg_type) != SUCCESS)
	{
		return(ERROR);
	}

	if(result != RESP_OK)
	{
		response_t response;
		response.notifPayload.reason = result;
		response.notifPayload.reqNum = 0U;
		sendNotifResponse(&response, curr_session);
		return(ERROR);
	}
	else if ( request->reqNum != response->notifPayload.reqNum)
	{
		response_t response;
		response.notifPayload.reason = RESP_WRONG_FORMAT;
		response.notifPayload.reqNum = 0U;
		sendNotifResponse(&response, curr_session);
		return(ERROR);
	}
	else
	{
		curr_session->transNum++;
	}
		
	return(SUCCESS);
}

error_code_t performUpKeyValiditiesOperation(session_t* const curr_session,
													 response_t* const response,
													 const request_t* const request)
{
	msg_type_t exp_msg_type = NOTIF_RESPONSE;
	response_reason_t result;
	
	if(sendCmdUpKeyValidities(request, curr_session) != SUCCESS)
	{
		return(ERROR);
	}

	if(waitForResponse(response, curr_session, &result, exp_msg_type) != SUCCESS)
	{
		return(ERROR);
	}

	if(result != RESP_OK)
	{
		response_t response;
		response.notifPayload.reason = result;
		response.notifPayload.reqNum = 0U;
		sendNotifResponse(&response,
						  curr_session);
		return(ERROR);
	}
	else if ( request->reqNum != response->notifPayload.reqNum)
	{
		response_t response;
		response.notifPayload.reason = RESP_WRONG_FORMAT;
		response.notifPayload.reqNum = 0U;
		sendNotifResponse(&response,
						  curr_session);
		return(ERROR);
	}
	else
	{
		curr_session->transNum++;
	}

	return(SUCCESS);
}

error_code_t performUpKeyEntitiesOperation(session_t* const curr_session,
										   response_t* const response,
										   const request_t* const request)
{
	msg_type_t exp_msg_type = NOTIF_RESPONSE;
	response_reason_t result;
	
	if(sendCmdUpKeyEntities(request, curr_session) != SUCCESS)
	{
		return(ERROR);
	}

	if(waitForResponse(response, curr_session, &result, exp_msg_type) != SUCCESS)
	{
		return(ERROR);
	}

	if(result != RESP_OK)
	{
		response_t response;
		response.notifPayload.reason = result;
		response.notifPayload.reqNum = 0U;
		sendNotifResponse(&response,
						  curr_session);
		return(ERROR);
	}
	else if ( request->reqNum != response->notifPayload.reqNum)
	{
		response_t response;
		response.notifPayload.reason = RESP_WRONG_FORMAT;
		response.notifPayload.reqNum = 0U;
		sendNotifResponse(&response,
						  curr_session);
		return(ERROR);
	}
	else
	{
		curr_session->transNum++;
	}
	
	return(SUCCESS);
}


error_code_t performDeleteAllKeysOperation(session_t* const curr_session,
												   response_t* const response)
{
	msg_type_t exp_msg_type = NOTIF_RESPONSE;
	response_reason_t result;
	
	if(sendCmdDeleteAllKeys(curr_session) != SUCCESS)
	{
		return(ERROR);
	}

	if(waitForResponse(response, curr_session, &result, exp_msg_type) != SUCCESS)
	{
		return(ERROR);
	}

	if(result != RESP_OK)
	{
		response_t response;
		response.notifPayload.reason = result;
		response.notifPayload.reqNum = 0U;
		sendNotifResponse(&response, curr_session);
		return(ERROR);
	}
	else
	{
		curr_session->transNum++;
	}

	return(SUCCESS);
}

error_code_t performReqDBChecksumOperation(session_t* const curr_session,
												   response_t* const response)
{
	msg_type_t exp_msg_type = NOTIF_KEY_DB_CHECKSUM;
	response_reason_t result;
	
	if(sendCmdReqKeyDBChecksum(curr_session) != SUCCESS)
	{
		return(ERROR);
	}

	if(waitForResponse(response, curr_session, &result, exp_msg_type) != SUCCESS)
	{
		return(ERROR);
	}

	if(result != RESP_OK)
	{
		response_t response;
		response.notifPayload.reason = result;
		response.notifPayload.reqNum = 0U;
		sendNotifResponse(&response,
						  curr_session);
		return(ERROR);
	}
	else
	{
		curr_session->transNum++;
	}
	
	return(SUCCESS);
}
