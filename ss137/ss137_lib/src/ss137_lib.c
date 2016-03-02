/* ------------------------------------------------------------------------------- */
/* I n c l u d e s                                                                 */
/* ------------------------------------------------------------------------------- */

/**
 * System headers
 */
#include <stdio.h>     /* for fopen, snprintf, etc... */
#include <string.h>    /* for memmove, memcmp, memset */
#include <arpa/inet.h> /* for htons, etc.. */
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#include "common.h"
#include "net_utils.h"
#include "tls_wrapper.h"
#include "ss137_lib.h"

/* ------------------------------------------------------------------------------- */
/* d e f i n e   c o n s t a n t s   a n d   m a c r o s                           */
/* ------------------------------------------------------------------------------- */


/* ------------------------------------------------------------------------------- */
/* Local Functions Prototypes                                                      */
/* ------------------------------------------------------------------------------- */

static uint32_t getMyEtcsIdExp(void);

static uint8_t getInterfaceVersion(void);

static int32_t buildMsgHeader(write_stream_t* const ostream,
							  const msg_header_t* const header);

static int32_t buildCmdAddKeys(write_stream_t* const ostream,
							   const cmd_add_keys_t* const payload);

static int32_t buildCmdDeleteKeys(write_stream_t* const ostream,
								  const cmd_del_keys_t* const payload);


static int32_t buildCmdUpKeyValidities(write_stream_t* const ostream,
									   const cmd_up_key_val_t* const payload);

static int32_t buildCmdUpKeyEntities(write_stream_t* const ostream,
									 const cmd_up_key_ent_t* const payload);


static int32_t buildCmdReqKeyOperation(write_stream_t* const ostream,
									   const cmd_req_key_op_t* const payload);


static int32_t buildNotifKeyUpdateStatus(write_stream_t* const ostream,
										 const notif_key_up_status_t* const payload);

static int32_t buildNotifSessionInit(write_stream_t* const ostream,
									 const notif_session_init_t* const payload);


static int32_t buildNotifResponse(write_stream_t* const ostream,
								  const notif_response_t* const payload);


static int32_t buildNotifKeyOpReqRcvd(write_stream_t* const ostream,
									  const notif_key_op_req_rcvd_t* const payload);

static int32_t buildNotifKeyDBChecksum(write_stream_t* const ostream,
									   const notif_key_db_checksum_t* const payload);




static int32_t convertMsgHeaderToHost(msg_header_t* const header,
									  read_stream_t* const istream);

static int32_t CheckMsgHeader(const msg_header_t* const header,
							  const uint32_t exp_msg_length,
							  const uint32_t exp_sender,
							  const uint32_t exp_seq_num,
							  const uint32_t exp_trans_num);

/* ------------------------------------------------------------------------------- */
/* Local Functions Bodies                                                          */
/* ------------------------------------------------------------------------------- */
	
static uint32_t getMyEtcsIdExp(void)
{
	/* TBD decide how to get my id */
	uint32_t myId = 0x11223344;
	return(myId);
}

static uint8_t getInterfaceVersion(void)
{
	/* TBD decide how to get interface version */
	return(INTERFACE_VERSION);
}


static int32_t buildMsgHeader(write_stream_t* const ostream,
							  const msg_header_t* const header)
{
	ASSERT((ostream != NULL) && (header != NULL), E_NULL_POINTER);

	hostToNet32(ostream, header->msgLength);
	hostToNet8(ostream, &header->version, sizeof(uint8_t));
	hostToNet32(ostream, header->recIDExp);
	hostToNet32(ostream, header->sendIDExp);
	hostToNet32(ostream, header->transNum);
	hostToNet16(ostream, header->seqNum);
	hostToNet8(ostream, &header->msgType, sizeof(uint8_t));
	
	return(RETURN_SUCCESS);
}

static int32_t buildCmdAddKeys(write_stream_t* const ostream,
							   const cmd_add_keys_t* const payload)
{
	uint32_t i = 0U;
	uint32_t j = 0U;

	ASSERT((ostream != NULL) && (payload != NULL), E_NULL_POINTER);
	ASSERT(payload->reqNum < MAX_REQ_ADD_KEYS,  E_INVALID_PARAM);

	hostToNet16(ostream, payload->reqNum);

	for(i = 0U; i < payload->reqNum; i++)
	{
		hostToNet8(ostream, &payload->kStructList[i].length, sizeof(uint8_t));
		hostToNet32(ostream, payload->kStructList[i].kIdent.genID);
		hostToNet32(ostream, payload->kStructList[i].kIdent.serNum);
		hostToNet32(ostream, payload->kStructList[i].etcsID);
		hostToNet8(ostream, payload->kStructList[i].kMAC, (uint32_t)KMAC_SIZE);
		hostToNet16(ostream, payload->kStructList[i].peerNum);

		ASSERT(payload->kStructList[i].peerNum < MAX_PEER_NUM,  E_INVALID_PARAM);

		for (j = 0U; j < payload->kStructList[i].peerNum; j++)
		{
			hostToNet32(ostream, payload->kStructList[i].peerID[j]);
		}
		
		hostToNet32(ostream, payload->kStructList[i].startValidity);
		hostToNet32(ostream, payload->kStructList[i].endValidity);
	}

	return(RETURN_SUCCESS);
}


static int32_t buildCmdDeleteKeys(write_stream_t* const ostream,
								  const cmd_del_keys_t* const payload)
{
	uint32_t i = 0U;
	
	ASSERT((ostream != NULL) && (payload != NULL), E_NULL_POINTER);
	ASSERT(payload->reqNum < MAX_REQ_DEL_KEYS,  E_INVALID_PARAM);

	hostToNet16(ostream, payload->reqNum);
	
	for(i = 0U; i < payload->reqNum; i++)
	{
		hostToNet32(ostream, payload->kIdentList[i].genID);
		hostToNet32(ostream, payload->kIdentList[i].serNum);
	}

	return(RETURN_SUCCESS);
}


static int32_t buildCmdUpKeyValidities(write_stream_t* const ostream,
									   const cmd_up_key_val_t* const payload)
{

	uint32_t i = 0U;

	ASSERT((ostream != NULL) && (payload != NULL), E_NULL_POINTER);
	ASSERT(payload->reqNum < MAX_REQ_UPDATE,  E_INVALID_PARAM);

	hostToNet16(ostream, payload->reqNum);

	for(i = 0U; i < payload->reqNum; i++)
	{
		hostToNet32(ostream, payload->kValidityList[i].kIdent.genID);
		hostToNet32(ostream, payload->kValidityList[i].kIdent.serNum);
		hostToNet32(ostream, payload->kValidityList[i].startValidity);
		hostToNet32(ostream, payload->kValidityList[i].endValidity);
	}

	return(RETURN_SUCCESS);
}

static int32_t buildCmdUpKeyEntities(write_stream_t* const ostream,
									 const cmd_up_key_ent_t* const payload)
{
	uint32_t i = 0U;
	uint32_t j = 0U;

	ASSERT((ostream != NULL) && (payload != NULL), E_NULL_POINTER);
	ASSERT(payload->reqNum < MAX_REQ_UPDATE,  E_INVALID_PARAM);
	
	hostToNet16(ostream, payload->reqNum);

	for(i = 0U; i < payload->reqNum; i++)
	{
		hostToNet32(ostream, payload->kEntityList[i].kIdent.genID);
		hostToNet32(ostream, payload->kEntityList[i].kIdent.serNum);
		hostToNet16(ostream, payload->kEntityList[i].peerNum);

		ASSERT(payload->kEntityList[i].peerNum < MAX_PEER_NUM,  E_INVALID_PARAM);

		for (j = 0U; j < payload->kEntityList[i].peerNum; j++)
		{
			hostToNet32(ostream, payload->kEntityList[i].peerID[j]);
		}
	}
	return(RETURN_SUCCESS);
}


static int32_t buildCmdReqKeyOperation(write_stream_t* const ostream,
									   const cmd_req_key_op_t* const payload)
{

	ASSERT((ostream != NULL) && (payload != NULL), E_NULL_POINTER);
	ASSERT(strlen(payload->text) < MAX_TEXT_LENGTH, E_NULL_POINTER);
	
	hostToNet32(ostream,  payload->etcsID);
	hostToNet8(ostream,  &payload->reason,  sizeof(uint8_t));
	hostToNet32(ostream,  payload->startValidity);
	hostToNet32(ostream,  payload->endValidity);
	hostToNet8(ostream, (uint8_t*)payload->text, strlen(payload->text));

	return(RETURN_SUCCESS);
}


static int32_t buildNotifKeyUpdateStatus(write_stream_t* const ostream,
										 const notif_key_up_status_t* const payload)
{

	ASSERT((ostream != NULL) && (payload != NULL), E_NULL_POINTER);
	
	hostToNet32(ostream, payload->kIdent.genID);
	hostToNet32(ostream, payload->kIdent.serNum);
	hostToNet8(ostream, &payload->kStatus, sizeof(uint8_t));

	return(RETURN_SUCCESS);
}

static int32_t buildNotifSessionInit(write_stream_t* const ostream,
									 const notif_session_init_t* const payload)
{

	ASSERT((ostream != NULL) && (payload != NULL), E_NULL_POINTER);

	hostToNet8(ostream, &payload->nVersion, sizeof(uint8_t));
	hostToNet8(ostream, &payload->version, sizeof(uint8_t));
	hostToNet8(ostream, &payload->appTimeout, sizeof(uint8_t));

	return(RETURN_SUCCESS);
}


static int32_t buildNotifResponse(write_stream_t* const ostream,
								  const notif_response_t* const payload)
{
	ASSERT((ostream != NULL) && (payload != NULL), E_NULL_POINTER);
	ASSERT(payload->reqNum < MAX_REQ_NOTIF,  E_INVALID_PARAM);

	hostToNet8(ostream, &payload->response, sizeof(uint8_t));
	hostToNet16(ostream, payload->reqNum);
	hostToNet8(ostream, payload->notificationList, sizeof(uint8_t)*payload->reqNum);

	return(RETURN_SUCCESS);
}


static int32_t buildNotifKeyOpReqRcvd(write_stream_t* const ostream,
									  const notif_key_op_req_rcvd_t* const payload)
{

	ASSERT((ostream != NULL) && (payload != NULL), E_NULL_POINTER);
	
	hostToNet16(ostream, payload->maxTime);

	return(RETURN_SUCCESS);
}

static int32_t buildNotifKeyDBChecksum(write_stream_t* const ostream,
									   const notif_key_db_checksum_t* const payload)
{

	ASSERT((ostream != NULL) && (payload != NULL), E_NULL_POINTER);
	
	hostToNet8(ostream, payload->checksum, (uint32_t)CHECKSUM_SIZE);

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


static int32_t CheckMsgHeader(const msg_header_t* const header,
							  const uint32_t exp_msg_length,
							  const uint32_t exp_sender,
							  const uint32_t exp_seq_num,
							  const uint32_t exp_trans_num)
{
	int32_t ret_val = 0U;

	ASSERT(header != NULL, E_NULL_POINTER);

	if( header->sendIDExp != exp_sender )
	{
		/* wrong sender id */
		ret_val = RESP_WRONG_SENDER_ID;
	}
	else if( header->recIDExp != getMyEtcsIdExp() )
	{
		/* wrong receiver id */
		ret_val = RESP_WRONG_REC_ID;
	}
	else if( header->msgLength !=  exp_msg_length )
	{
		/* wrong msg length */
		ret_val = RESP_WRONG_LENGTH;
	}
	else if( header->msgType > NOTIF_KEY_DB_CHECKSUM )
	{
		/* msg type not supported */
		ret_val = RESP_NOT_SUPPORTED;
	}
	else if( header->version !=  getInterfaceVersion() )
	{
		/* wrong version */
		ret_val = RESP_WRONG_VERSION;
	}
	else if( header->seqNum !=  exp_seq_num )
	{
		/* wrong sequence number */
		ret_val = RESP_WRONG_SEQ_NUM;
	}
	else if( header->transNum !=  exp_trans_num )
	{
		/* wrong transaction number */
		ret_val = RESP_WRONG_TRANS_NUM;
	}
	else
	{
		/* valid header */
		ret_val = RESP_OK;
	}
	
	return(ret_val);
}


/* ------------------------------------------------------------------------------- */
/* Public Functions Bodies                                                         */
/* ------------------------------------------------------------------------------- */

/* this function init the tls session and send the notif_init to the correspondin peer */
int32_t initSession(session_t* const curr_session,
					const uint32_t peer_etcs_id_exp)
{
	return(RETURN_SUCCESS);
}

/* this function send the notif_end to the corresponding peer */
int32_t endSession(uint32_t session_id)
{
	return(RETURN_SUCCESS);
}

/* ostream shall be already initialized */
int32_t sendMsg(write_stream_t* const ostream,
				const session_t * const curr_session)
{

	uint32_t bytes_sent = 0U;

	/* sendTLS(&bytes_sent, ostream->buffer, ostream->curSize, curr_session->ssl_des); */

	if( bytes_sent != ostream->curSize)
	{
		err_print("Cannot complete send operation of msg (bytes sent %d, expectd %d)\n", bytes_sent, ostream->curSize);
		return(-1);
	}

	return(RETURN_SUCCESS);
}

/* istream shall be already initialized */
int32_t receiveMsg(read_stream_t* const istream,
				   const session_t * const curr_session)
{

	/* receiveTLS(&istream->validBytes, istream->buffer, (uint32_t)MSG_MAX_SIZE, curr_session->ssl_des); */
	
	return(RETURN_SUCCESS);
}


