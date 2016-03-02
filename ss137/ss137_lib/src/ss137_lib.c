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

/* ------------------------------------------------------------------------------- */
/* Public Functions Bodies                                                         */
/* ------------------------------------------------------------------------------- */

int32_t buildMsgHeader(write_stream_t* const ostream,
					   const uint32_t msg_length,
					   const session_t* const curr_session,
					   const uint8_t msg_type)
{
	uint32_t my_etcs_id_exp = 0U;
	uint8_t curr_version = 0U;	

	ASSERT(ostream != NULL, E_NULL_POINTER);

	my_etcs_id_exp = getMyEtcsIdExp();
	curr_version = getInterfaceVersion();
	
	hostToNet32(ostream, msg_length);
	hostToNet8(ostream, &curr_version, sizeof(uint8_t));
	hostToNet32(ostream, curr_session->peerEtcsIDExp);
	hostToNet32(ostream, my_etcs_id_exp);
	hostToNet32(ostream, curr_session->myTransNum);
	hostToNet16(ostream, curr_session->mySeqNum);
	hostToNet8(ostream, &msg_type, sizeof(uint8_t));
	
	return(RETURN_SUCCESS);
}

/* this function init the tls session and send the notif_init to the correspondin peer */
int32_t initSession(session_t* const curr_session,
					const uint32_t peer_etcs_id_exp)
{
	uint8_t app_timeout = 250;
	write_stream_t notif_msg;
	
	ASSERT(curr_session != NULL, E_NULL_POINTER);

	memset(curr_session, 0U, sizeof(session_t));
	curr_session->peerEtcsIDExp = peer_etcs_id_exp;

	initWriteStream(&notif_msg);

	buildMsgHeader(&notif_msg, (MSG_HEADER_SIZE+3*sizeof(uint8_t)), curr_session, NOTIF_SESSION_INIT);
		
	buildNotifSessionInit(&notif_msg, app_timeout);

	uint32_t i = 0U;
	printf("Dump: ");
	for(i=0U; i < notif_msg.curSize; i++)
	{
		printf("0x%02x ", notif_msg.buffer[i]);
	}
	printf("\n");

	return(RETURN_SUCCESS);
}

/* this function send the notif_end to the corresponding peer */
int32_t endSession(uint32_t session_id)
{
	return(RETURN_SUCCESS);
}

int32_t buildCmdAddKeys(write_stream_t* const ostream,
						const uint16_t req_num,
						const k_struct_t* const k_struct_list)
{
	uint32_t i = 0U;
	uint32_t j = 0U;

	ASSERT((ostream != NULL) && (k_struct_list != NULL), E_NULL_POINTER);
	ASSERT(req_num < MAX_REQ_ADD_KEYS,  E_INVALID_PARAM);

	hostToNet16(ostream, req_num);

	for(i = 0U; i < req_num; i++)
	{
		hostToNet8(ostream, &k_struct_list[i].length, sizeof(uint8_t));
		hostToNet32(ostream, k_struct_list[i].kIdent.genID);
		hostToNet32(ostream, k_struct_list[i].kIdent.serNum);
		hostToNet32(ostream, k_struct_list[i].etcsID);
		hostToNet8(ostream, k_struct_list[i].kMAC, (uint32_t)KMAC_SIZE);
		hostToNet16(ostream, k_struct_list[i].peerNum);

		ASSERT(k_struct_list[i].peerNum < MAX_PEER_NUM,  E_INVALID_PARAM);

		for (j = 0U; j < k_struct_list[i].peerNum; j++)
		{
			hostToNet32(ostream, k_struct_list[i].peerID[j]);
		}
		
		hostToNet32(ostream, k_struct_list[i].startValidity);
		hostToNet32(ostream, k_struct_list[i].endValidity);
	}

	return(RETURN_SUCCESS);
}


int32_t buildCmdDeleteKeys(write_stream_t* const ostream,
						   const uint16_t req_num,
						   const k_ident_t* const k_ident)
{
	uint32_t i = 0U;
	
	ASSERT((ostream != NULL) && (k_ident != NULL), E_NULL_POINTER);
	ASSERT(req_num < MAX_REQ_DEL_KEYS,  E_INVALID_PARAM);

	hostToNet16(ostream, req_num);
	
	for(i = 0U; i < req_num; i++)
	{
		hostToNet32(ostream, k_ident[i].genID);
		hostToNet32(ostream, k_ident[i].serNum);
	}

	return(RETURN_SUCCESS);
}


int32_t buildCmdUpKeyValidities(write_stream_t* const ostream,
								const uint16_t req_num,
								const k_validity_t* const k_validity_list)
{

	uint32_t i = 0U;

	ASSERT((ostream != NULL) && (k_validity_list != NULL), E_NULL_POINTER);
	ASSERT(req_num < MAX_REQ_UPDATE,  E_INVALID_PARAM);

	hostToNet16(ostream, req_num);

	for(i = 0U; i < req_num; i++)
	{
		hostToNet32(ostream, k_validity_list[i].kIdent.genID);
		hostToNet32(ostream, k_validity_list[i].kIdent.serNum);
		hostToNet32(ostream, k_validity_list[i].startValidity);
		hostToNet32(ostream, k_validity_list[i].endValidity);
	}

	return(RETURN_SUCCESS);
}

int32_t buildCmdUpKeyEntities(write_stream_t* const ostream,
							  const uint16_t req_num,
							  const k_entity_t* const k_entity_list)
{
	uint32_t i = 0U;
	uint32_t j = 0U;

	ASSERT((ostream != NULL) && (k_entity_list != NULL), E_NULL_POINTER);
	ASSERT(req_num < MAX_REQ_UPDATE,  E_INVALID_PARAM);
	
	hostToNet16(ostream, req_num);

	for(i = 0U; i < req_num; i++)
	{
		hostToNet32(ostream, k_entity_list[i].kIdent.genID);
		hostToNet32(ostream, k_entity_list[i].kIdent.serNum);
		hostToNet16(ostream, k_entity_list[i].peerNum);

		ASSERT(k_entity_list[i].peerNum < MAX_PEER_NUM,  E_INVALID_PARAM);

		for (j = 0U; j < k_entity_list[i].peerNum; j++)
		{
			hostToNet32(ostream, k_entity_list[i].peerID[j]);
		}
	}
	return(RETURN_SUCCESS);
}


int32_t buildCmdReqKeyOperation(write_stream_t* const ostream,
								const uint32_t etcs_id_mod,
								const uint8_t reason,
								const uint32_t startValidity,
								const uint32_t endValidity,
								const char *const text)
{

	ASSERT((ostream != NULL) && (text != NULL), E_NULL_POINTER);
	ASSERT(strlen(text) < MAX_TEXT_LENGTH, E_NULL_POINTER);
	
	hostToNet32(ostream,  etcs_id_mod);
	hostToNet8(ostream, &reason,  sizeof(uint8_t));
	hostToNet32(ostream,  startValidity);
	hostToNet32(ostream,  endValidity);
	hostToNet8(ostream, (uint8_t*)&text, strlen(text));

	return(RETURN_SUCCESS);
}


int32_t buildNotifKeyUpdateStatus(write_stream_t* const ostream,
								  const k_ident_t* const k_ident,
								  const uint8_t k_status)
{

	ASSERT((ostream != NULL) && (k_ident != NULL), E_NULL_POINTER);
	
	hostToNet32(ostream, k_ident->genID);
	hostToNet32(ostream, k_ident->serNum);
	hostToNet8(ostream, &k_status, sizeof(uint8_t));

	return(RETURN_SUCCESS);
}

int32_t buildNotifSessionInit(write_stream_t* const ostream,
							  const uint8_t app_timeout)
{

	uint8_t n_version = 0U;
	uint8_t curr_version = 0U;

	ASSERT(ostream != NULL, E_NULL_POINTER);

	curr_version = getInterfaceVersion();
	n_version = NUM_VERSION;
	
	hostToNet8(ostream, &n_version, sizeof(uint8_t));
	hostToNet8(ostream, &curr_version, sizeof(uint8_t));
	hostToNet8(ostream, &app_timeout, sizeof(uint8_t));

	return(RETURN_SUCCESS);
}


int32_t buildNotifResponse(write_stream_t* const ostream,
						   const uint8_t response,
						   const uint16_t req_num,
						   const uint8_t* const notification_list)
{
	ASSERT(ostream != NULL, E_NULL_POINTER);
	ASSERT(req_num < MAX_REQ_NOTIF,  E_INVALID_PARAM);

	hostToNet8(ostream, &response, sizeof(uint8_t));
	hostToNet16(ostream, req_num);
	hostToNet8(ostream, notification_list, sizeof(uint8_t)*req_num);

	return(RETURN_SUCCESS);
}


int32_t buildNotifKeyOpReqRcvd(write_stream_t* const ostream,
							   const uint16_t max_time)
{

	ASSERT(ostream != NULL, E_NULL_POINTER);
	
	hostToNet16(ostream, max_time);

	return(RETURN_SUCCESS);
}

int32_t buildNotifKeyDBChecksum(write_stream_t* const ostream,
								const uint8_t* const checksum)
{

	ASSERT((ostream != NULL) && (checksum != NULL), E_NULL_POINTER);
	
	hostToNet8(ostream, checksum, (uint32_t)CHECKSUM_SIZE);

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


/* ----------------------------------------------------------------------------------- */
/* read                                                                                */
/* ----------------------------------------------------------------------------------- */


int32_t convertMsgHeaderToHost(msg_header_t* const header,
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


int32_t CheckMsgHeader(const msg_header_t* const header,
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
