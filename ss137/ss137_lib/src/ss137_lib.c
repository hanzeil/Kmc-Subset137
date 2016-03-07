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

#include "common.h"
#include "net_utils.h"
#include "tls_wrapper.h"
#include "msg_definitions.h"
#include "ss137_lib.h"

/*****************************************************************************
 * DEFINES
 ******************************************************************************/

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
static int32_t sendNotifSessionInit(session_t* const curr_session,
							 	 	const uint8_t app_timeout,
							 	 	const uint32_t peer_etcs_id_exp);

static int32_t sendNotifSessionEnd(session_t* const curr_session);

/* command */
static int32_t sendCmdAddKeys(const request_t* const request,
					   	   	   const session_t* const curr_session);

static int32_t sendCmdDeleteKeys(const request_t* const request,
						  	  	  const session_t* const curr_session);

static int32_t sendCmdUpKeyValidities(const request_t* const request,
										const session_t* const curr_session);

static int32_t sendCmdUpKeyEntities(const request_t* const payload,
									const session_t* const curr_session);

static int32_t sendCmdReqKeyDBChecksum(const session_t* const curr_session);

static int32_t sendCmdDeleteAllKeys(const session_t* const curr_session);

static int32_t sendCmdReqKeyDBChecksum(const session_t* const curr_session);


/* notification */
static int32_t buildMsgHeader(write_stream_t* const ostream,
							  const uint32_t msg_length,
							  const uint32_t msg_type,
							  const uint32_t peer_etcs_id_exp,
							  const uint32_t trans_num);

static int32_t convertMsgHeaderToHost(msg_header_t* const header,
									  read_stream_t* const istream);

static int32_t convertCmdAddKeysToHost(request_t* const request,
									   read_stream_t* const istream);

static int32_t convertCmdDeleteKeysToHost(request_t* const request,
										  read_stream_t* const istream);
	
static int32_t convertCmdUpKeyValiditiesToHost(request_t* const request,
											   read_stream_t* const istream);

static int32_t convertCmdUpKeyEntitiesToHost(request_t* const request,
											 read_stream_t* const istream);

static int32_t convertNotifSessionInitToHost(notif_session_init_t* const request,
											 read_stream_t* const istream);

static int32_t convertNotifResponseToHost(response_t* const response,
										  read_stream_t* const istream);

static int32_t convertNotifKeyDBChecksumToHost(response_t* const response,
											   read_stream_t* const istream);
	
static int32_t convertMsgHeaderToHost(msg_header_t* const header,
									  read_stream_t* const istream);

static int32_t checkMsgHeader(session_t* const curr_session,
							  const msg_header_t* const header,
							  const uint32_t exp_msg_length);

static int32_t sendMsg(write_stream_t* const ostream,
					   const uint32_t tls_id);

static int32_t receiveMsg(read_stream_t* const istream,
						  const uint32_t tls_id);

static void getMyEtcsIDExp(uint32_t* const my_etcs_id_exp);

static void getMySeqNum(uint16_t* const my_seq_num);

static void increaseMySeqNum(void);



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

static void getMySeqNum(uint16_t* const my_seq_num)
{
	ASSERT(my_seq_num != NULL, E_NULL_POINTER);
	
	*my_seq_num = mySeqNum;
		
	return;
}

static void increaseMySeqNum(void)
{
	mySeqNum++;
	
	return;
}

static int32_t buildMsgHeader(write_stream_t* const ostream,
							  const uint32_t msg_length,
							  const uint32_t msg_type,
							  const uint32_t peer_etcs_id_exp,
							  const uint32_t trans_num)
{

	msg_header_t header;
	uint32_t my_etcs_id_exp = 0U;
	uint16_t my_seq_num = 0U;
	
	ASSERT(ostream != NULL, E_NULL_POINTER);

	getMyEtcsIDExp(&my_etcs_id_exp);
	getMySeqNum(&my_seq_num);
	
	memset(&header, 0U, sizeof(msg_header_t));
	
	header.msgLength = msg_length;
	header.version   = supportedVersion[0];
	header.recIDExp  = peer_etcs_id_exp;
	header.sendIDExp = my_etcs_id_exp;
	header.transNum  = trans_num;
	header.seqNum    = my_seq_num;
	header.msgType   = msg_type;

	hostToNet32(ostream, header.msgLength);
	hostToNet8(ostream, &header.version, sizeof(uint8_t));
	hostToNet32(ostream, header.recIDExp);
	hostToNet32(ostream, header.sendIDExp);
	hostToNet32(ostream, header.transNum);
	hostToNet16(ostream, header.seqNum);
	hostToNet8(ostream, &header.msgType, sizeof(uint8_t));
	
	return(RETURN_SUCCESS);
}

static int32_t convertMsgHeaderToHost(msg_header_t* const header,
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

    return(RETURN_SUCCESS);
}


static int32_t convertCmdAddKeysToHost(request_t* const request,
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

	return(RETURN_SUCCESS);
}

static int32_t convertCmdDeleteKeysToHost(request_t* const request,
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
	
	return(RETURN_SUCCESS);
}

static int32_t convertCmdUpKeyValiditiesToHost(request_t* const request,
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
		
	return(RETURN_SUCCESS);
}


static int32_t convertCmdUpKeyEntitiesToHost(request_t* const request,
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
	
	return(RETURN_SUCCESS);
}

/*
static int32_t convertCmdReqKeyOperationToHost(cmd_req_key_op_t* const request,
											   read_stream_t* const istream)
{
	ASSERT((istream != NULL) && (request != NULL), E_NULL_POINTER);

	netToHost32(&request->etcsID, istream);
	netToHost8(&request->reason, sizeof(uint8_t), istream);

	if(request->reason == RED_SCHED)
	{
		netToHost32(&request->startValidity, istream);
		netToHost32(&request->endValidity, istream);
	}
	
	netToHost16(&request->textLength, istream);
	netToHost8((uint8_t*)request->text, request->textLength, istream);
	
	return(RETURN_SUCCESS);
}
*/
/*
static int32_t convertNotifKeyUpdateStatusToHost(notif_key_up_status_t* const payload,
												 read_stream_t* const istream)
{
	ASSERT((istream != NULL) && (payload != NULL), E_NULL_POINTER);

	netToHost32(&payload->kIdent.genID, istream);
	netToHost32(&payload->kIdent.serNum, istream);
	netToHost8(&payload->kStatus, sizeof(uint8_t), istream);
	
	return(RETURN_SUCCESS);
}
*/
/*
static int32_t convertNotifKeyOpReqRcvdToHost(notif_key_op_req_rcvd_t* const payload,
											  read_stream_t* const istream)
{
	ASSERT((istream != NULL) && (payload != NULL), E_NULL_POINTER);

	netToHost16(&payload->maxTime, istream);

	return(RETURN_SUCCESS);
}
*/

static int32_t convertNotifSessionInitToHost(notif_session_init_t* const payload,
											 read_stream_t* const istream)
{
	ASSERT((istream != NULL) && (payload != NULL), E_NULL_POINTER);

	netToHost8(&payload->nVersion, sizeof(uint8_t), istream);
	netToHost8(payload->version, sizeof(uint8_t)*NUM_VERSION, istream);
	netToHost8(&payload->appTimeout, sizeof(uint8_t), istream);
	
	return(RETURN_SUCCESS);
}

static int32_t convertNotifResponseToHost(response_t* const response,
										  read_stream_t* const istream)
{
	ASSERT((istream != NULL) && (response != NULL), E_NULL_POINTER);

	netToHost8(&response->notif.reason, sizeof(uint8_t), istream);
	netToHost16(&response->notif.reqNum, istream);
	netToHost8(response->notif.notificationList, sizeof(uint8_t)*response->notif.reqNum, istream);

	return(RETURN_SUCCESS);
}

static int32_t convertNotifKeyDBChecksumToHost(response_t* const response,
											   read_stream_t* const istream)
{
	ASSERT((istream != NULL) && (response != NULL), E_NULL_POINTER);

	netToHost8(response->checksum, (uint32_t)CHECKSUM_SIZE, istream);
	
	return(RETURN_SUCCESS);
}

static int32_t checkMsgHeader(session_t* const curr_session,
							  const msg_header_t* const header,
							  const uint32_t exp_msg_length)
{
	int32_t ret_val = 0U;
	uint32_t my_etcs_id_exp = 0U;

	ASSERT(header != NULL, E_NULL_POINTER);
	ASSERT(curr_session != NULL, E_NULL_POINTER);

	getMyEtcsIDExp(&my_etcs_id_exp);
	
	if( header->sendIDExp != curr_session->peerEtcsIDExp )
	{
		/* wrong sender id */
		ret_val = RESP_WRONG_SENDER_ID;
		warning_print("Invalid sender ID:  received 0x%08x exp 0x%08x\n",
					  header->sendIDExp, curr_session->peerEtcsIDExp);
	}
	else if( header->recIDExp != my_etcs_id_exp )
	{
		/* wrong receiver id */
		ret_val = RESP_WRONG_REC_ID;
		warning_print("Invalid rec ID:  received 0x%08x exp 0x%08x\n",
					  header->recIDExp, my_etcs_id_exp);
	}
	else if( header->msgLength !=  exp_msg_length )
	{
		/* wrong msg length */
		ret_val = RESP_WRONG_LENGTH;
		warning_print("Invalid msg length:  received 0x%08x exp 0x%08x\n",
					  header->msgLength, exp_msg_length);
	}
	else if( header->msgType > NOTIF_KEY_DB_CHECKSUM )
	{
		/* msg type not supported */
		ret_val = RESP_NOT_SUPPORTED;
		warning_print("Invalid msg type:  received 0x%02x\n",
					  header->msgType);
	}
	else if( header->version != supportedVersion[0] )
	{
		/* wrong version */
		ret_val = RESP_WRONG_VERSION;
		warning_print("Invalid interface version:  received 0x%02x exp 0x%02x\n",
					  header->version, supportedVersion[0]);
	}
	/* for the NOTIF_SESSION_INIT  message the sequence number shall not be checked */
	else if( (header->seqNum != (curr_session->peerSeqNum + 1)) &&
			 (header->msgType != NOTIF_SESSION_INIT))
	{
		/* wrong sequence number */
		ret_val = RESP_WRONG_SEQ_NUM;
		warning_print("Invalid seq num:  received 0x%04x exp 0x%04x\n",
					  curr_session->transNum, header->transNum);
	}
	else if( ((header->transNum !=  curr_session->transNum) && (header->msgType != NOTIF_END_OF_UPDATE)) ||
			 ((header->transNum != 0U) &&  (header->msgType == NOTIF_END_OF_UPDATE)))
	{
		/* wrong transaction number */
		ret_val = RESP_WRONG_TRANS_NUM;
		warning_print("Invalid trans number:  received 0x%08x exp 0x%08x\n",
					  curr_session->transNum, header->transNum);
	}
	else
	{
		/* valid header */
		ret_val = RESP_OK;
	}

	/* set new sequence number */
	curr_session->peerSeqNum++;
	
	return(ret_val);
}

/* ostream shall be already initialized */
static int32_t sendMsg(write_stream_t* const ostream,
					   const uint32_t tls_id)
{
	
	uint32_t bytes_sent = 0U;
	
	ASSERT(ostream != NULL, E_NULL_POINTER);
	
	if(sendTLS(&bytes_sent, ostream->buffer, ostream->curSize, tls_id) != TLS_SUCCESS)
	{
		return(E_TLS_ERROR);
	}
	
	if( bytes_sent != ostream->curSize)
	{
		err_print("Cannot complete send operation of msg (bytes sent %d, expectd %d)\n", bytes_sent, ostream->curSize);
		return(E_WRITE);
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
	
	increaseMySeqNum();
	
	return(RETURN_SUCCESS);
}

/* istream shall be already initialized */
static int32_t receiveMsg(read_stream_t* const istream,
						  const uint32_t tls_id)
{

	if(receiveTLS(&istream->validBytes, istream->buffer, (uint32_t)MSG_MAX_SIZE, tls_id) != TLS_SUCCESS)
	{
		return(E_TLS_ERROR);
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

	return(RETURN_SUCCESS);
}



/*****************************************************************************
 * PUBLIC FUNCTION DECLARATIONS
 *****************************************************************************/

int32_t sendNotifSessionInit(session_t* const curr_session,
							 const uint8_t app_timeout,
							 const uint32_t peer_etcs_id_exp)
{
	uint32_t msg_length = 0U;
	uint32_t tmp_trans_num = 0U;
	uint8_t tmp_num_version = NUM_VERSION;
	write_stream_t ostream;

	ASSERT(curr_session != NULL, E_NULL_POINTER);

	/* the transaction number for init
	   session shall be set to 0 */
	tmp_trans_num = 0U;
	curr_session->transNum = 0U;
	curr_session->appTimeout = app_timeout;
	curr_session->peerEtcsIDExp = peer_etcs_id_exp;

	/* initialize output buffer */
	initWriteStream(&ostream);
	
	/* evaluate message length */
	msg_length = NOTIF_SESSION_INIT_SIZE;

	/* prepare msg header */
	buildMsgHeader(&ostream, msg_length, NOTIF_SESSION_INIT,
				   curr_session->peerEtcsIDExp, tmp_trans_num);

	/* serialize payload */
	hostToNet8(&ostream, &tmp_num_version, sizeof(uint8_t));
	hostToNet8(&ostream, supportedVersion, NUM_VERSION*sizeof(uint8_t));
	hostToNet8(&ostream, &curr_session->appTimeout, sizeof(uint8_t));

	sendMsg(&ostream, curr_session->tlsID);
	
	return(RETURN_SUCCESS);
}

int32_t sendNotifSessionEnd(session_t* const curr_session)
{
	uint32_t msg_length = 0U;
	uint32_t tmp_trans_num = 0U;
	write_stream_t ostream;

	ASSERT(curr_session != NULL, E_NULL_POINTER);

	/* the transaction number for end
	   session shall be set to 0 */
	tmp_trans_num = 0U;

	/* prepare output buffer */
	initWriteStream(&ostream);

	/* prepare message header */
	msg_length = NOTIF_END_UPDATE_SIZE;

	buildMsgHeader(&ostream, msg_length, NOTIF_END_OF_UPDATE,
				   curr_session->peerEtcsIDExp, tmp_trans_num);

	sendMsg(&ostream, curr_session->tlsID);

	return(RETURN_SUCCESS);
}

int32_t waitForSessionInit(notif_session_init_t* const payload,
						   session_t* const curr_session)
{
	read_stream_t input_msg;
	msg_header_t header;
	int32_t ret_val = -1;

	ASSERT(payload != NULL, E_NULL_POINTER);
	ASSERT(curr_session != NULL, E_NULL_POINTER);
	
	initReadStream(&input_msg);
		
	receiveMsg(&input_msg, curr_session->tlsID);

	convertMsgHeaderToHost(&header, &input_msg);

	ret_val = checkMsgHeader(curr_session,
							 &header,
							 input_msg.validBytes);
	
	if( ret_val != RESP_OK)
	{
		warning_print("Error on checking header\n");
		return(ret_val);
	}
	else
	{
		if( header.msgType != NOTIF_SESSION_INIT )
		{
			err_print("Unexpected msg type received: rec %d\n", header.msgType);
			ret_val = RESP_NOT_SUPPORTED;
			return(ret_val);
		}
		else
		{
			convertNotifSessionInitToHost((notif_session_init_t*)payload, &input_msg);
		}
		/* initialize peerSeqNumber */
		curr_session->peerSeqNum = header.seqNum;
		ret_val = RESP_OK;
	}
	return(ret_val);
}

int32_t sendCmdAddKeys(const request_t* const request,
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

	sendMsg(&ostream, curr_session->tlsID);
	
	return(RETURN_SUCCESS);
}


int32_t sendCmdDeleteKeys(const request_t* const request,
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

	sendMsg(&ostream, curr_session->tlsID);

	return(RETURN_SUCCESS);
}

int32_t sendCmdUpKeyValidities(const request_t* const request,
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

	sendMsg(&ostream, curr_session->tlsID);

	return(RETURN_SUCCESS);
}


int32_t sendCmdUpKeyEntities(const request_t* const request,
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

	sendMsg(&ostream, curr_session->tlsID);
	
	return(RETURN_SUCCESS);
}


int32_t sendCmdDeleteAllKeys(const session_t* const curr_session)
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
	sendMsg(&ostream, curr_session->tlsID);
		
	return(RETURN_SUCCESS);
}

int32_t sendCmdReqKeyDBChecksum(const session_t* const curr_session)
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

	sendMsg(&ostream, curr_session->tlsID);
	
	return(RETURN_SUCCESS);
}

int32_t sendNotifKeyDBChecksum(const response_t* const response,
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
	hostToNet8(&ostream, response->checksum, (uint32_t)CHECKSUM_SIZE);

	sendMsg(&ostream, curr_session->tlsID);
	
	return(RETURN_SUCCESS);
}

int32_t sendNotifResponse(const response_t* const response,
						  const session_t* const curr_session)
{
	uint32_t msg_length = 0U;
	write_stream_t ostream;
	
	ASSERT((curr_session != NULL) && (response != NULL), E_NULL_POINTER);
	ASSERT(response->notif.reqNum < MAX_REQ_NOTIF,  E_INVALID_PARAM);

	/* prepare output buffer */
	initWriteStream(&ostream);
	
	/* prepare message header */
	msg_length = NOTIF_RESPONSE_MIN_SIZE+sizeof(uint8_t)*response->notif.reqNum;
	
	buildMsgHeader(&ostream, msg_length, NOTIF_RESPONSE,
				   curr_session->peerEtcsIDExp, curr_session->transNum);

	/* serialize payload */
	hostToNet8(&ostream, &response->notif.reason, sizeof(uint8_t));
	hostToNet16(&ostream, response->notif.reqNum);

	if(response->notif.reqNum != 0U)
	{
		hostToNet8(&ostream, response->notif.notificationList, sizeof(uint8_t)*response->notif.reqNum);
	}
	sendMsg(&ostream, curr_session->tlsID);

	return(RETURN_SUCCESS);
}

int32_t waitForResponse(response_t* const response,
						session_t* const curr_session,
						const MSG_TYPE exp_msg_type)
{
	msg_header_t header;
	int32_t ret_val_header = -1;
	read_stream_t input_msg;

	ASSERT(response!= NULL, E_NULL_POINTER);
	ASSERT(curr_session != NULL, E_NULL_POINTER);

	initReadStream(&input_msg);
		
	receiveMsg(&input_msg, curr_session->tlsID);

	convertMsgHeaderToHost(&header, &input_msg);

	ret_val_header = checkMsgHeader(curr_session,
									&header,
									input_msg.validBytes);
	
	if(ret_val_header != RESP_OK)
	{
		err_print("Error on checking header\n");
		return(ret_val_header);
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
			default:
				ret_val_header = RESP_NOT_SUPPORTED;
				return(ret_val_header);
			}
		}
	}
	
	return(RETURN_SUCCESS);
}

int32_t startClientTLS(uint32_t* const tls_id)
{
	ASSERT(tls_id != NULL, E_NULL_POINTER);

	if(initClientTLS(tls_id) == TLS_ERROR)
	{
		err_print("Error occurred in initClientTLS()\n");
		return(E_TLS_ERROR);
	}

	return(RETURN_SUCCESS);
}

int32_t connectToTLSServer(const uint32_t const tls_id,
						   const char* const r_ip,
						   const uint16_t r_port)
{
	ASSERT(r_ip != NULL, E_NULL_POINTER);

	if(connectTLS(tls_id, r_ip, r_port) == TLS_ERROR)
	{
		err_print("Error occurred in connectTLS()\n");
		return(E_TLS_ERROR);
	}

	return(RETURN_SUCCESS);
}

int32_t startServerTLS(uint32_t* const tls_id,
					   const uint16_t l_port)
{
	ASSERT(tls_id != NULL, E_NULL_POINTER);
	
	if(initServerTLS(tls_id, l_port) == TLS_ERROR)
	{
		err_print("Error occurred in initServerTLS()\n");
		return(E_TLS_ERROR);
	}

	return(RETURN_SUCCESS);
}

int32_t listenForTLSClient(const uint32_t tls_id)
{
	if(acceptTLS(tls_id) == TLS_ERROR)
	{
		err_print("Error occurred in acceptTLS()\n");
		return(E_TLS_ERROR);
	}

	return(RETURN_SUCCESS);
}

int32_t closeTLSConnection(const uint32_t tls_id)
{

	closeTLS(tls_id);

	return(RETURN_SUCCESS);
}

int32_t waitForRequestFromKMCToKMAC(request_t* const request,
									session_t* const curr_session)
{
	read_stream_t input_msg;
	msg_header_t header;
	int32_t ret_val_header = -1;

	ASSERT(request != NULL, E_NULL_POINTER);
	ASSERT(curr_session != NULL, E_NULL_POINTER);
	
	initReadStream(&input_msg);
	
	receiveMsg(&input_msg, curr_session->tlsID);
	
	convertMsgHeaderToHost(&header, &input_msg);
	
	ret_val_header = checkMsgHeader(curr_session,
									&header,
									input_msg.validBytes);

	if(ret_val_header != RESP_OK)
	{
		warning_print("Error on checking header\n");
		return(ret_val_header);
	}
	else
	{
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
			err_print("Unexpected msg type received: rec %d\n", header.msgType);
			ret_val_header = RESP_NOT_SUPPORTED;
			return(ret_val_header);
		}
	}

	curr_session->transNum = header.transNum;

	return(RETURN_SUCCESS);
}


int32_t initAppSession(session_t* const curr_session,
					   const uint8_t app_timeout,
					   const uint32_t peer_etcs_id_exp)
{
	notif_session_init_t response;
	int32_t ret_val = -1;

	sendNotifSessionInit(curr_session, app_timeout, peer_etcs_id_exp);

	ret_val = waitForSessionInit(&response, curr_session);

	if(ret_val != RESP_OK)
	{
		response_t response;
		response.notif.reason = ret_val;
		response.notif.reqNum = 0U;
		sendNotifResponse(&response,
						  curr_session);
		return(OP_NOK);
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
			notif_response.notif.reason = RESP_WRONG_VERSION;
			notif_response.notif.reqNum = 0U;
			sendNotifResponse(&notif_response,
							  curr_session);
			return(OP_NOK);

		}

		curr_session->transNum++;
	}

	return(OP_OK);
}

/* this function send the notif session end message */
int32_t endAppSession(session_t* const curr_session)
{

	sendNotifSessionEnd(curr_session);

	return(OP_OK);
}


int32_t performAddKeysOperation(session_t* const curr_session,
								response_t* const response,
								const request_t* const request)
{
	MSG_TYPE exp_msg_type = NOTIF_RESPONSE;
	int32_t ret_val = -1;

	sendCmdAddKeys(request, curr_session);

	ret_val = waitForResponse(response, curr_session, exp_msg_type);

	if(ret_val != RESP_OK)
	{
		response_t response;
		response.notif.reason = ret_val;
		response.notif.reqNum = 0U;
		sendNotifResponse(&response,
						  curr_session);
		return(OP_NOK);
	}
	else if ( request->reqNum != response->notif.reqNum)
	{
		response_t response;
		response.notif.reason = RESP_WRONG_FORMAT;
		response.notif.reqNum = 0U;
		sendNotifResponse(&response,
						  curr_session);
		return(OP_NOK);
	}
	else
	{
		curr_session->transNum++;
	}

	return(RETURN_SUCCESS);
}

int32_t performDelKeysOperation(session_t* const curr_session,
								response_t* const response,
								const request_t* const request)
{
	MSG_TYPE exp_msg_type = NOTIF_RESPONSE;
	int32_t ret_val = -1;

	sendCmdDeleteKeys(request, curr_session);

	ret_val = waitForResponse(response, curr_session, exp_msg_type);
	if(ret_val != RESP_OK)
	{
		response_t response;
		response.notif.reason = ret_val;
		response.notif.reqNum = 0U;
		sendNotifResponse(&response,
						  curr_session);
		return(OP_NOK);
	}
	else if ( request->reqNum != response->notif.reqNum)
	{
		response_t response;
		response.notif.reason = RESP_WRONG_FORMAT;
		response.notif.reqNum = 0U;
		sendNotifResponse(&response,
						  curr_session);
		return(OP_NOK);
	}
	else
	{
		curr_session->transNum++;
	}

	return(OP_OK);
}

int32_t performUpKeyValiditiesOperation(session_t* const curr_session,
										response_t* const response,
										const request_t* const request)
{
	MSG_TYPE exp_msg_type = NOTIF_RESPONSE;
	int32_t ret_val = -1;

	sendCmdUpKeyValidities(request, curr_session);

	ret_val = waitForResponse(response, curr_session, exp_msg_type);
	if(ret_val != RESP_OK)
	{
		response_t response;
		response.notif.reason = ret_val;
		response.notif.reqNum = 0U;
		sendNotifResponse(&response,
						  curr_session);
		return(OP_NOK);
	}
	else if ( request->reqNum != response->notif.reqNum)
	{
		response_t response;
		response.notif.reason = RESP_WRONG_FORMAT;
		response.notif.reqNum = 0U;
		sendNotifResponse(&response,
						  curr_session);
		return(OP_NOK);
	}
	else
	{
		curr_session->transNum++;
	}

	return(OP_OK);
}

int32_t performUpKeyEntitiesOperation(session_t* const curr_session,
									  response_t* const response,
									  const request_t* const request)
{
	MSG_TYPE exp_msg_type = NOTIF_RESPONSE;
	int32_t ret_val = -1;

	sendCmdUpKeyEntities(request, curr_session);

	ret_val = waitForResponse(response, curr_session, exp_msg_type);
	if(ret_val != RESP_OK)
		{
			response_t response;
			response.notif.reason = ret_val;
			response.notif.reqNum = 0U;
			sendNotifResponse(&response,
							  curr_session);
			return(OP_NOK);
		}
		else if ( request->reqNum != response->notif.reqNum)
		{
			response_t response;
			response.notif.reason = RESP_WRONG_FORMAT;
			response.notif.reqNum = 0U;
			sendNotifResponse(&response,
							  curr_session);
			return(OP_NOK);
		}
		else
		{
			curr_session->transNum++;
		}

	return(OP_OK);
}


int32_t performDeleteAllKeysOperation(session_t* const curr_session,
									  response_t* const response)
{
	MSG_TYPE exp_msg_type = NOTIF_RESPONSE;
	int32_t ret_val = -1;

	sendCmdDeleteAllKeys(curr_session);

	ret_val = waitForResponse(response, curr_session, exp_msg_type);
	if(ret_val != RESP_OK)
	{
		response_t response;
		response.notif.reason = ret_val;
		response.notif.reqNum = 0U;
		sendNotifResponse(&response,
						  curr_session);
		return(OP_NOK);
	}
	else
	{
		curr_session->transNum++;
	}

	return(OP_OK);
}

int32_t performReqDBChecksumOperation(session_t* const curr_session,
									  response_t* const response)
{
	MSG_TYPE exp_msg_type = NOTIF_KEY_DB_CHECKSUM;
	int32_t ret_val = -1;

	sendCmdReqKeyDBChecksum(curr_session);

	ret_val = waitForResponse(response, curr_session, exp_msg_type);
	if(ret_val != RESP_OK)
	{
		response_t response;
		response.notif.reason = ret_val;
		response.notif.reqNum = 0U;
		sendNotifResponse(&response,
						  curr_session);
		return(OP_NOK);
	}
	else
	{
		curr_session->transNum++;
	}

	return(OP_OK);
}
