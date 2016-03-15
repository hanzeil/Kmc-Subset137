/**************************************************************************//**
 *
 * SS137 library
 *
 * This files contains the implementation of the SUBSET137 as described
 * in the document SUBSET-137 On-line Key Management FFFIS ver 1.0.0. (17/12/2015)
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

#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/types.h>
#include <libgen.h>

#include "utils.h"
#include "net_utils.h"
#include "msg_definitions.h"
#include "tls_wrapper.h"
#include "ss137_lib.h"

/*****************************************************************************
 * DEFINES
 ******************************************************************************/

/**< Timeout application session initialization (ref. SUBSET-137 5.4.4.1) */
#define INIT_CONNECTION_TIMEOUT (15U)  

/*****************************************************************************
 * TYPEDEFS
 *****************************************************************************/

/*****************************************************************************
 * VARIABLES
 *****************************************************************************/

/**< Current sequence number */
static uint16_t mySeqNum = 0U; 

/**< List of current supported versions (ref. SUBSET-137 5.3.13) */
static const uint8_t supportedVersion[NUM_VERSION] = {2U};

/**< The ss137_lib configuration struct */
extern ss137_lib_configuration_t ss137_lib_config;

/*****************************************************************************
 * LOCAL FUNCTION PROTOTYPES
 *****************************************************************************/

static error_code_t sendNotifSessionInit(const session_t* const curr_session);

static error_code_t sendNotifSessionEnd(const session_t* const curr_session);

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

static error_code_t convertNotifSessionInitToHost(notif_session_init_t* const request,
												  read_stream_t* const istream);

static error_code_t convertNotifResponseToHost(response_t* const response,
											   read_stream_t* const istream);

static error_code_t convertNotifKeyDBChecksumToHost(response_t* const response,
													read_stream_t* const istream);

static error_code_t convertMsgHeaderToHost(msg_header_t* const header,
										   read_stream_t* const istream);

static error_code_t checkMsgHeader(response_reason_t* const result,
								   session_t* const curr_session,
								   const msg_header_t* const header,
								   const uint32_t exp_msg_length);

static error_code_t sendMsg(const write_stream_t* const ostream,
							const tls_des_t tls_id);

static error_code_t receiveMsg(read_stream_t* const istream,
							   const uint8_t timeout,
							   const tls_des_t tls_id);

static void getMyEtcsIDExp(uint32_t* const my_etcs_id_exp);

/*****************************************************************************
 * LOCAL FUNCTION DECLARATIONS
 *****************************************************************************/
/**
 * Gives my Expanded ETCS-ID.
 *
 * Gives my Expanded ETCS-ID taken from the configuration struct ss137_lib_config.
 */
static void getMyEtcsIDExp      /** @return void */
(
	uint32_t* const my_etcs_id_exp /**< [out] A pointer to be fill with my current Exp. ETCS-ID */
	)
{
	ASSERT(my_etcs_id_exp != NULL, E_NULL_POINTER);

	*my_etcs_id_exp = ss137_lib_config.myEntityId.expEtcsId;

	return;
}

/**
 * Builds message header. 
 *
 * It serializes in network format all the parameters given as input following the 
 * header message structure descibed in ref. SUBSET-137 5.3.3.
 */
static error_code_t buildMsgHeader       /** @return error code */
(
	write_stream_t* const ostream,   /**< [out] The pointer to the ostream structure used to store the serialized message in net format. */
	const uint32_t msg_length,       /**< [in]  The message length. */
	const uint32_t msg_type,         /**< [in]  The message type. */
	const uint32_t peer_etcs_id_exp, /**< [in]  The Expanded ETCS-ID of the corresponding peer. */
	const uint32_t trans_num         /**< [in]  The transaction number. */
	)
{
	msg_header_t header;
	uint32_t my_etcs_id_exp = 0U;
	
	ASSERT(ostream != NULL, E_NULL_POINTER);

	getMyEtcsIDExp(&my_etcs_id_exp);

	/* reset the header structure */
	memset(&header, 0U, sizeof(msg_header_t));

	/* fill the header structure using the input parameters */
	header.msgLength = msg_length;
	header.version   = supportedVersion[0];
	header.recIDExp  = peer_etcs_id_exp;
	header.sendIDExp = my_etcs_id_exp;
	header.transNum  = trans_num;
	header.seqNum    = mySeqNum;
	header.msgType   = msg_type;

	/* serialize the header  in net format*/
	hostToNet32(ostream, header.msgLength);
	hostToNet8(ostream, &header.version, sizeof(uint8_t));
	hostToNet32(ostream, header.recIDExp);
	hostToNet32(ostream, header.sendIDExp);
	hostToNet32(ostream, header.transNum);
	hostToNet16(ostream, header.seqNum);
	hostToNet8(ostream, &header.msgType, sizeof(uint8_t));
	
	return(SUCCESS);
}

/**
 * Converts Message header in host format.
 *
 * The function converts in host format the buffer istream->buffer and stores the data in the following fields
 * of the struct pointed by header:
 * - header->version;
 * - header->recIDExp;
 * - header->sendIDExp;
 * - header->transNum;
 * - header->msgType.
 * The function calls the exit() function on any erorr on the addressing of the input parameters.
 */
static error_code_t convertMsgHeaderToHost /** @return SUCCESS if the header is correctly converted, ERROR if the input buffer length is shorter than the expected. */
(
	msg_header_t* const header,  /**< [out] The pointer to the msg_header_t structure storing the header in host format. */
	read_stream_t* const istream /**< [in]  The pointer to the read_stream_t structure storing the header in net format. */ 
	)
{
	error_code_t tmp_error = SUCCESS;
  
	ASSERT((istream != NULL) && (header != NULL), E_NULL_POINTER);

	tmp_error |= netToHost32(&header->msgLength, istream);
	tmp_error |= netToHost8(&header->version, (uint32_t)sizeof(uint8_t), istream);
	tmp_error |= netToHost32(&header->recIDExp, istream);
	tmp_error |= netToHost32(&header->sendIDExp, istream);
	tmp_error |= netToHost32(&header->transNum, istream);
	tmp_error |= netToHost16(&header->seqNum, istream);
	tmp_error |= netToHost8(&header->msgType, (uint32_t)sizeof(uint8_t), istream);

	if(tmp_error != SUCCESS)
	{
	    return(ERROR);
	}

	return(SUCCESS);
}

/**
 * Converts the body of CMD_ADD_KEYS messages in host format.
 *
 * The function converts in host format the buffer istream->buffer and stores the data in the following fields
 * of the struct pointed by request:
 * - request->reqNum;
 * - request->kStructList[].
 * The function calls the exit() function on any erorr on the addressing of the input parameters.
 */
static error_code_t convertCmdAddKeysToHost /** @return SUCCESS if the header is correctly converted, ERROR if the input buffer length is shorter than the expected. */
(
	request_t* const request,     /**< [out] The pointer to the request_t structure storing the message body in host format. */
	read_stream_t* const istream  /**< [in]  The pointer to the read_stream_t structure storing the message body in net format. */
	)
{
	uint32_t i = 0U;
	uint32_t j = 0U;
	error_code_t tmp_error = SUCCESS;
	
	ASSERT((istream != NULL) && (request != NULL), E_NULL_POINTER);

	/* read the request number */
	tmp_error |= netToHost16(&request->reqNum, istream);

	/* read each K-STRUCT */
	for(i = 0U; i < request->reqNum; i++)
	{
		tmp_error |= netToHost8(&request->kStructList[i].length, sizeof(uint8_t), istream);
		tmp_error |= netToHost32(&request->kStructList[i].kIdent.genID, istream);
		tmp_error |= netToHost32(&request->kStructList[i].kIdent.serNum, istream);
		tmp_error |= netToHost32(&request->kStructList[i].etcsID, istream);
		tmp_error |= netToHost8(request->kStructList[i].kMAC, (uint32_t)KMAC_SIZE, istream);
		tmp_error |= netToHost16(&request->kStructList[i].peerNum, istream);

		for (j = 0U; j < request->kStructList[i].peerNum; j++)
		{
			tmp_error |= netToHost32(& request->kStructList[i].peerID[j], istream);
		}
		tmp_error |= netToHost32(&request->kStructList[i].startValidity, istream);
		tmp_error |= netToHost32(&request->kStructList[i].endValidity, istream);
	}

	if(tmp_error != SUCCESS)
	{
	    return(ERROR);
	}

	return(SUCCESS);
}

/**
 * Converts the body of CMD_DELETE_KEYS messages in host format.
 *
 * The function converts in host format the buffer istream->buffer and stores the data in the following fields
 * of the struct pointed by request:
 * - request->reqNum;
 * - request->kIdentList[].
 * The function calls the exit() function on any erorr on the addressing of the input parameters.
 */
static error_code_t convertCmdDeleteKeysToHost /** @return SUCCESS if the header is correctly converted, ERROR if the input buffer length is shorter than the expected. */
(
	request_t* const request,    /**< [out] The pointer to the request_t structure storing the message body in host format. */
	read_stream_t* const istream /**< [in]  The pointer to the read_stream_t structure storing the message body in net format. */
	)
{
	uint32_t i = 0U;
	error_code_t tmp_error = SUCCESS;

	ASSERT((istream != NULL) && (request != NULL), E_NULL_POINTER);

	/* read the request number */
	tmp_error |= netToHost16(&request->reqNum, istream);

	/* read each k-ident struct */
	for(i = 0U; i < request->reqNum; i++)
	{
		tmp_error |= netToHost32(&request->kIdentList[i].genID, istream);
		tmp_error |= netToHost32(&request->kIdentList[i].genID, istream);
	}

	if(tmp_error != SUCCESS)
	{
	    return(ERROR);
	}
	
	return(SUCCESS);
}

/**
 * Converts the body of CMD_UPDATE_KEY_VALIDITIES messages in host format.
 *
 * The function converts in host format the buffer istream->buffer and stores the data in the following fields
 * of the struct pointed by request:
 * - request->reqNum;
 * - request->kValidityList[].
 * The function calls the exit() function on any erorr on the addressing of the input parameters.
 */
static error_code_t convertCmdUpKeyValiditiesToHost /** @return SUCCESS if the header is correctly converted, ERROR if the input buffer length is shorter than the expected. */
(
	request_t* const request,    /**< [out] The pointer to the request_t structure storing the message body in host format. */
	read_stream_t* const istream /**< [in]  The pointer to the read_stream_t structure storing the message body in net format. */
	)
{
	uint32_t i = 0U;
	error_code_t tmp_error = SUCCESS;
	
	ASSERT((istream != NULL) && (request != NULL), E_NULL_POINTER);

	tmp_error |= netToHost16(&request->reqNum, istream);

	for(i = 0U; i < request->reqNum; i++)
	{
		tmp_error |= netToHost32(&request->kValidityList[i].kIdent.genID, istream);
		tmp_error |= netToHost32(&request->kValidityList[i].kIdent.serNum, istream);
		tmp_error |= netToHost32(&request->kValidityList[i].startValidity, istream);
		tmp_error |= netToHost32(&request->kValidityList[i].endValidity, istream);
	}

	if(tmp_error != SUCCESS)
	{
	    return(ERROR);
	}

	return(SUCCESS);
}

/**
 * Converts the body of CMD_UPDATE_KEY_ENTITIES messages in host format.
 *
 * The function converts in host format the buffer istream->buffer and stores the data in the following fields
 * of the struct pointed by request:
 * - request->reqNum;
 * - request->kValidityList[].
 * The function calls the exit() function on any erorr on the addressing of the input parameters.
 */
static error_code_t convertCmdUpKeyEntitiesToHost  /** @return SUCCESS if the header is correctly converted, ERROR if the input buffer length is shorter than the expected. */
(
	request_t* const request,    /**< [out] The pointer to the request_t structure storing the message body in host format. */
	read_stream_t* const istream /**< [in]  The pointer to the read_stream_t structure storing the message body in net format. */
	)
{
	uint32_t i = 0U;
	uint32_t j = 0U;
	error_code_t tmp_error = SUCCESS;

	ASSERT((istream != NULL) && (request != NULL), E_NULL_POINTER);

	/* read the request number */
	tmp_error |= netToHost16(&request->reqNum, istream);

	/* read each k-entity struct */
	for(i = 0U; i < request->reqNum; i++)
	{
		tmp_error |= netToHost32(&request->kEntityList[i].kIdent.genID, istream);
		tmp_error |= netToHost32(&request->kEntityList[i].kIdent.serNum, istream);
		tmp_error |= netToHost16(&request->kEntityList[i].peerNum, istream);

		for (j = 0U; j < request->kEntityList[i].peerNum; j++)
		{
			tmp_error |= netToHost32(&request->kEntityList[i].peerID[j], istream);
		}
	}

	if(tmp_error != SUCCESS)
	{
	    return(ERROR);
	}

	return(SUCCESS);
}

/**
 * Converts the body of CMD_REQUEST_KEY_OPERATION messages in host format.
 *
 * The function converts in host format the buffer istream->buffer and stores the data in the following fields
 * of the struct pointed by request:
 * - request->reqKeyOpPayload.etcsID;
 * - request->reqKeyOpPayload.reason;
 * - request->reqKeyOpPayload.startValidity only if the reason of message id RED_SCHED (see ref. SUBSET-137 5.3.9);
 * - request->reqKeyOpPayload.endValidity only if the reason of message id RED_SCHED (see ref. SUBSET-137 5.3.9);
 * - request->reqKeyOpPayload.textLength;
 * - request->reqKeyOpPayload.text.
 * The function calls the exit() function on any erorr on the addressing of the input parameters.
 */
static error_code_t convertCmdReqKeyOperationToHost /** @return SUCCESS if the header is correctly converted, ERROR if the input buffer length is shorter than the expected. */
(
	request_t* const request,    /**< [out] The pointer to the request_t structure storing the message body in host format.*/
	read_stream_t* const istream /**< [in]  The pointer to the read_stream_t structure storing the message body in net format.*/
	)
{
	error_code_t tmp_error = SUCCESS;
  
	ASSERT((istream != NULL) && (request != NULL), E_NULL_POINTER);
  
	tmp_error |= netToHost32(&request->reqKeyOpPayload.etcsID, istream);
	tmp_error |= netToHost8(&request->reqKeyOpPayload.reason, sizeof(uint8_t), istream);
  
	if(request->reqKeyOpPayload.reason == RED_SCHED)
    {
		tmp_error |= netToHost32(&request->reqKeyOpPayload.startValidity, istream);
		tmp_error |= netToHost32(&request->reqKeyOpPayload.endValidity, istream);
    }
  
	tmp_error |= netToHost16(&request->reqKeyOpPayload.textLength, istream);
	tmp_error |= netToHost8((uint8_t*)request->reqKeyOpPayload.text,
							request->reqKeyOpPayload.textLength, istream);
  
	if(tmp_error != SUCCESS)
    {
		return(ERROR);
    }
  
	return(SUCCESS);
}

/**
 * Converts the body of NOTIF_KEY_UPDATE_STATUS messages in host format.
 *
 * The function converts in host format the buffer istream->buffer and stores the data in the following fields
 * of the struct pointed by request:
 * - request->keyUpStatusPayload.kIdent;
 * - request->keyUpStatusPayload.kStatus.
 * The function calls the exit() function on any erorr on the addressing of the input parameters.
 */
static error_code_t convertNotifKeyUpdateStatusToHost /** @return SUCCESS if the header is correctly converted, ERROR if the input buffer length is shorter than the expected. */
(
	request_t* const request,    /**< [out] The pointer to the request_t structure storing the message body in host format.*/
	read_stream_t* const istream /**< [in]  The pointer to the read_stream_t structure storing the message body in net format.*/
	)
{
	error_code_t tmp_error = SUCCESS;
	ASSERT((istream != NULL) && (request != NULL), E_NULL_POINTER);

	tmp_error |= netToHost32(&request->keyUpStatusPayload.kIdent.genID, istream);
	tmp_error |= netToHost32(&request->keyUpStatusPayload.kIdent.serNum, istream);
	tmp_error |= netToHost8(&request->keyUpStatusPayload.kStatus, sizeof(uint8_t), istream);
  
	if(tmp_error != SUCCESS)
    {
		return(ERROR);
    }
	
	return(SUCCESS);
}

/**
 * Converts the body of NOTIF_KEY_OPERATION_REQ_RCVD messages in host format.
 *
 * The function converts in host format the buffer istream->buffer and stores the data in the following fields
 * of the struct pointed by request:
 * - response->keyOpRecvdPayload.maxTime.
 * The function calls the exit() function on any erorr on the addressing of the input parameters.
 */
static error_code_t convertNotifKeyOpReqRcvdToHost /** @return SUCCESS if the header is correctly converted, ERROR if the input buffer length is shorter than the expected. */
(
	response_t* const response,  /**< [out] The pointer to the request_t structure storing the message body in host format.*/
	read_stream_t* const istream /**< [in]  The pointer to the read_stream_t structure storing the message body in net format.*/
	)
{
  	error_code_t tmp_error = SUCCESS;
	
	ASSERT((istream != NULL) && (response != NULL), E_NULL_POINTER);

	tmp_error |= netToHost16(&response->keyOpRecvdPayload.maxTime, istream);

	return(SUCCESS);
}

/**
 * Converts the body of NOTIF_SESSION_INIT messages in host format.
 *
 * The function converts in host format the buffer istream->buffer and stores the data in the following fields
 * of the struct pointed by response:
 * - response->nVersion;
 * - response->version;
 * - response->appTimeout.
 * The function calls the exit() function on any erorr on the addressing of the input parameters.
 */
static error_code_t convertNotifSessionInitToHost /** @return SUCCESS if the header is correctly converted, ERROR if the input buffer length is shorter than the expected. */
(
	notif_session_init_t* const response, /**< [out] The pointer to the notif_session_t structure storing the message body in host format.*/
	read_stream_t* const istream          /**< [in]  The pointer to the read_stream_t structure storing the message body in net format.*/
	)
{
	error_code_t tmp_error = SUCCESS;
  
	ASSERT((istream != NULL) && (response != NULL), E_NULL_POINTER);
  
	tmp_error |= netToHost8(&response->nVersion, sizeof(uint8_t), istream);
	tmp_error |= netToHost8(response->version, sizeof(uint8_t)*NUM_VERSION, istream);
	tmp_error |= netToHost8(&response->appTimeout, sizeof(uint8_t), istream);
  
	if(tmp_error != SUCCESS)
    {
		return(ERROR);
    }
  
	return(SUCCESS);
}

/**
 * Converts the body of NOTIF_RESPONSE messages in host format.
 *
 * The function converts in host format the buffer istream->buffer and stores the data in the following fields
 * of the struct pointed by response:
 * - response->notifPayload.reason;
 * - response->notifPayload.reqNum;
 * - response->notifPayload.notificationList[].
 * The function calls the exit() function on any erorr on the addressing of the input parameters.
 */
static error_code_t convertNotifResponseToHost /** @return SUCCESS if the header is correctly converted, ERROR if the input buffer length is shorter than the expected. */
(
	response_t* const response,  /**< [out] The pointer to the response_t structure storing the message body in host format.*/
	read_stream_t* const istream /**< [in]  The pointer to the read_stream_t structure storing the message body in net format.*/
	)
{
	error_code_t tmp_error = SUCCESS;
  
	ASSERT((istream != NULL) && (response != NULL), E_NULL_POINTER);
  
	tmp_error |= netToHost8(&response->notifPayload.reason, sizeof(uint8_t), istream);
	tmp_error |= netToHost16(&response->notifPayload.reqNum, istream);
	tmp_error |= netToHost8(response->notifPayload.notificationList,
							sizeof(uint8_t)*response->notifPayload.reqNum, istream);
  
	if(tmp_error != SUCCESS)
    {
		return(ERROR);
    }
  
	return(SUCCESS);
}

/**
 * Converts the body of NOTIF_KEY_DB_CHECKSUM messages in host format.
 *
 * The function converts in host format the buffer istream->buffer and stores the data in the following fields
 * of the structure pointed by response:
 * - response->dbChecksumPayload.checksum.
 * The function calls the exit() function on any erorr on the addressing of the input parameters.
 */
static error_code_t convertNotifKeyDBChecksumToHost /** @return SUCCESS if the header is correctly converted, ERROR if the input buffer length is shorter than the expected. */
(
	response_t* const response,  /**< [out] The pointer to the response_t structure storing the message body in host format.*/
	read_stream_t* const istream /**< [in]  The pointer to the read_stream_t structure storing the message body in net format.*/
	)
{
	error_code_t tmp_error = SUCCESS;
  
	ASSERT((istream != NULL) && (response != NULL), E_NULL_POINTER);
  
	tmp_error |= netToHost8(response->dbChecksumPayload.checksum, (uint32_t)CHECKSUM_SIZE, istream);
  
	if(tmp_error != SUCCESS)
    {
		return(ERROR);
    }
  
	return(SUCCESS);
}

/**
 * Checks the message header
 *
 * The functions compares the values stored in the header struct with the values expected, in particular it compares:
 * - header->sendIDExp with curr_session->peerEtcsIDExp parameter, if not true result parameter is set to RESP_WRONG_SENDER_ID;
 * - header->recIDExp with my_etcs_id_exp, if not true result parameter is set to RESP_WRONG_REC_ID;
 * - header->msgLength with exp_msg_length parameter, if not true result parameter is set to RESP_WRONG_LENGTH;
 * - header->msgType has a value different from the ones expected, if not true result parameter is set to RESP_NOT_SUPPORTED;
 * - header->version with supportedVersion[0], if not true result parameter is set to  RESP_WRONG_VERSION;
 * - header->seqNum with curr_session->peerSeqNum + 1 it the message type is different from NOTIF_SESSION_INIT, if not true result parameter is set to RESP_WRONG_SEQ_NUM;
 * - header->transNum with curr_session->transNum t the message is different from NOTIF_END_OF_UPDATE, if not true result parameter is set to RESP_WRONG_TRANS_NUM;
 *
 * If the validation succeds the paramter result is set to RESP_OK and the current peer sequence number curr_session->peerSeqNum is set to the one stored in the header struct.
 * The function calls the exit() function on any erorr on the addressing of the input parameters.
 */
static error_code_t checkMsgHeader /** @return SUCCESS in any case. */
(
	response_reason_t* const result,  /**< [out]    The pointer to the result of the header validation.*/   
	session_t* const curr_session,    /**< [in/out] The pointer to the session_t struct that stores some of the values used for comparison.*/
	const msg_header_t* const header, /**< [in]     The pointer to the header struct to be validate.*/ 	  
	const uint32_t exp_msg_length     /**< [in]     The expected message length.*/     
	)
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
	/* For the NOTIF_SESSION_INIT  message the sequence
	   number shall not be checked, see ref. SUBSET-137 5.4.1.2*/
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

/**
 * Writes the data stored in the write_stream_t structure using the corresponding tls connection.
 *
 * The function send through TLS the message stored in the ostream->buffer array.
 * It sends the message of size ostream->curSize by calling the function sendTLS().
 * If the message is correctly sent the global variable mySeqNum is increased by one.
 * The function calls the exit() function on any erorr on the addressing of the input parameters.
 */
static error_code_t sendMsg           /** @return SUCCESS if the message is correctly sent, ERROR in case of error on sendTLS call or if the message is not sent entirely. */
(
	const write_stream_t* const ostream, /**< [in] Structure where the message to be sent is stored.*/   
	const tls_des_t tls_id		      /**< [in] Identifier of the TLS connection.*/
	)
{
	uint32_t bytes_sent = 0U;
	
	ASSERT(ostream != NULL, E_NULL_POINTER);
	
	if(sendTLS(&bytes_sent, ostream->buffer, ostream->curSize, tls_id) != TLS_SUCCESS)
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
	log_print("%s\n", dump_msg);
#endif
	
	mySeqNum++;
	
	return(SUCCESS);
}

/**
 * Evaluate the time to be used as application timeout.
 *
 * This function evaluates the remaining time to wait before considering the application session as in timeout.
 * In particular it evaluates the time difference between the time stored in the start_time(i.e. the time of the last message received
 * by the other peer) and the current time and applies the difference in seconds to the the exp_timeout value, 
 *the result is than stored in the are pointed by the reamaining time parameter.
 * The function calls the exit() function on any erorr on the addressing of the input parameters.
 */
static error_code_t evaluateRemainingTime /** @return SUCCESS if the difference is correctly evaluated, ERROR if start_time is larger than the current timeor if the remaining time is larger than 255 (see ref. SUBSET-137 5.3.13) */
(
	uint8_t *const remaining_time,        /**< [out] The pointer to the area storing the remaining time to wait.*/   
	const struct timeval start_time,      /**< [in]  The time of the last message received by the peer.*/   
	const uint8_t exp_timeout             /**< [in]  The current application timeout.*/   
	)
{
	struct timeval curr_time = {0U, 0U};
	uint64_t elapsed_time = 0U;
	uint64_t tmp_remaining_time = 0U;
  
	ASSERT(remaining_time != NULL, E_NULL_POINTER);
  
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

/**
 * Reads data from the TLS connection storing it to the read_stream_t struct.
 *
 * The function read a message from the TLS connection by means of the function receiveTLS(),
 * then it stores the message read in the buffer istream->buffer and sets istream->validBytes to
 * the number of bytes read.
 * The function calls the exit() function on any erorr on the addressing of the input parameters.
 */
static error_code_t receiveMsg  /** @return SUCCESS if the read operation succeds, ERROR if the receiveTLS() call fails or if the timeout expires without receiving new data. */
(
	read_stream_t* const istream,  /**< [out] Struct where the message read is stored.*/   
	const uint8_t timeout,         /**< [in]  The application timeout*/   
	const tls_des_t tls_id         /**< [in]  Identifier of the TLS connection */   
	)
{
	ASSERT(istream != NULL, E_NULL_POINTER);

	log_print("Waiting time = %d\n", timeout);
	
	if(receiveTLS(&istream->validBytes, istream->buffer, (uint32_t)MSG_MAX_SIZE, timeout, tls_id) != TLS_SUCCESS)
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
	log_print("%s\n", dump_msg);
#endif
	return(SUCCESS);
}

/**
 * Sends a message of type NOTIF_SESSION_INIT to the corresponding entity.
 *
 * This function prepares and serializes in net format a message of type NOTIF_SESSION_INIT to the peer entity
 * specified in the field curr_session->peerEtcsIDExp using the TLS connection identifier curr_session->tlsID.
 * The function calls the exit() function on any erorr on the addressing of the input parameters.
 */
static error_code_t sendNotifSessionInit /** @return SUCCESS if the message is correctly sent, ERROR if the call sendMsg() fails. */
(
	const session_t* const curr_session  /**< [in] The structure storing the information about the current application session.*/   
	)
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

/**
 * Sends a message of type NOTIF_END_OF_UPDATE to the corresponding peer entity.
 *
 * This function prepares, serializes in net format and sends a message of type NOTIF_END_OF_UPDATE to the peer
 * specified in the field curr_session->peerEtcsIDExp using the TLS connection identifier curr_session->tlsID.
 * The transaction number is set to 0(see ref. SUBSET-137 5.3.3).
 * The function calls the exit() function on any erorr on the addressing of the input parameters.
 */
static error_code_t sendNotifSessionEnd /** @return SUCCESS if the message is correctly sent, ERROR if the call sendMsg() fails. */
(
	const session_t* const curr_session /**< [in]  The structure holding the information about the current application session.*/   
	)
{
	uint32_t msg_length = 0U;
	write_stream_t ostream;
	uint32_t tmp_trans_num = 0U;
  
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
  
	if(sendMsg(&ostream, curr_session->tlsID) != SUCCESS)
    {
		return(ERROR);
    }
  
	return(SUCCESS);
}

/**
 * Waits for a message of type NOTIF_SESSION_INIT from the corresponding peer entity.
 *
 * This function waits for the reception of a NOTIF_SESSION_INIT message from the peer entity specified in curr_session->peerEtcsIDExp
 * using the TLS connection curr_session->peerEtcsIDExp for the time specified in curr_session->appTimeout.
 * If the message is correctly received and it's a message of type NOTIF_SESSION_INIT with a valid header, the message body 
 * is stored in the notif_session_t structure passed as parameter, the result variable is set to RESP_OK and the field
 * curr_session->peerSeqNum is set to the value stored in the header of the message.
 * In case of error the variable result it set to one of the value described in ref. SUBSET-137 5.3.15.
 * The function calls the exit() function on any erorr on the addressing of the input parameters.
 */
static error_code_t waitForSessionInit   /** @return SUCCESS if the message is correctly received and is a valid NOTIF_SESSION_INIT message, ERROR in case of errors in the reception of the message(i.e. connection timeout) or if the message has not a valid header.*/
(
	notif_session_init_t* const payload, /**< [out]    The structure holding the body of the NOTIF_SESSION_INIT message*/   
	response_reason_t* const result,     /**< [out]    The result of the validation of the message.*/   
	session_t* const curr_session        /**< [in/out] The structure holding the information about the current application session.*/   
	)
{
	read_stream_t input_msg;
	msg_header_t header;
	uint8_t remaining_time = 0U;
  
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
		return (ERROR);
    }
  
	/* reset the start time */
	gettimeofday(&(curr_session->startTime), NULL);
  
	if(convertMsgHeaderToHost(&header, &input_msg) != SUCCESS)
    {
		*result = RESP_WRONG_FORMAT;
		return(ERROR);
    }
   
	checkMsgHeader(result, curr_session, &header, input_msg.validBytes);
	if( *result != RESP_OK)
    {
		warning_print("Error on checking header\n");
		return(ERROR);
    }
	else
    {
		if( header.msgType != NOTIF_SESSION_INIT )
		{
			warning_print("Unexpected msg type received: rec %d\n", header.msgType);
			*result = RESP_NOT_SUPPORTED;
			return(ERROR);
		}
		else
		{
			if(convertNotifSessionInitToHost((notif_session_init_t*)payload, &input_msg) != SUCCESS)
			{
				*result = RESP_WRONG_FORMAT;
				return(ERROR);
			}
		}
      
		/* initialize peerSeqNumber */
		curr_session->peerSeqNum = header.seqNum;
		*result = RESP_OK;
    }
  
	return(SUCCESS);
}

/**
 * Sends a message of type CMD_ADD_KEYS to the corresponding peer entity.
 *
 * This function prepares,  serializes in net format and sends a message of type CMD_ADD_KEYS to the peer entity
 * specified in the field curr_session->peerEtcsIDExp using the TLS connection identifier curr_session->tlsID.
 * In particular it uses as message payload the request->reqNum field and the list of k-struct stored in the request->kStructList[] array.
 * The function calls the exit() function on any erorr on the addressing of the input parameters or if 
 * the request->reqNum field is larger than the maximum allowed MAX_REQ_ADD_KEYS( see ref. SUBSET-137 5.3.4).
 */
static error_code_t sendCmdAddKeys    /** @return SUCCESS if the message is correctly prepared and sent, ERROR if the sendMsg() call fails. */
(
	const request_t* const request,      /**< [in] The pointer to the structure holding the list of k-struct structures to be sent.*/     		  
	const session_t* const curr_session  /**< [in] The pointer the structure holding the information about the current application session.*/   
	)
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

/**
 * Sends a message of type CMD_DELETE_KEYS to the corresponding peer entity.
 *
 * This function prepares, serializes in net format and sends a message of type CMD_DELETE_KEYS to the peer entity
 * specified in the field curr_session->peerEtcsIDExp using the TLS connection identifier curr_session->tlsID.
 * In particular it uses as message payload request->reqNum field and the list of k-identifier stored in the request->kIdentList[] array.
 * The function calls the exit() function on any erorr on the addressing of the input parameters or if 
 * the request->reqNum field is larger than the maximum allowed MAX_REQ_DEL_KEYS( see ref. SUBSET-137 5.3.5).
 */
static error_code_t sendCmdDeleteKeys /** @return SUCCESS if the message is correctly prepared and sent, ERROR if the sendMsg() call fails. */ 
(				                                                                                                               
	const request_t* const request,      /**< [in] The pointer to the structure holding the list of k-identifier structures to be sent.*/		       
	const session_t* const curr_session  /**< [in] The pointer the structure holding the information about the current application session.*/     
	)
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

	/* send the message */
	if(sendMsg(&ostream, curr_session->tlsID) != SUCCESS)
    {
		return(ERROR);
    }
  
	return(SUCCESS);
}

/**
 * Sends a message of type CMD_UPDATE_KEY_VALIDITIES to the corresponding peer entity.
 *
 * This function prepares, serializes in net format and sends a message of type CMD_UPDATE_KEY_VALIDITIES to the peer entity
 * specified in the field curr_session->peerEtcsIDExp using the TLS connection identifier curr_session->tlsID.
 * In particular it uses as message payload the request->reqNum field and the list of k-validity stored in the request->kValidityList[] array.
 * The function calls the exit() function on any erorr on the addressing of the input parameters or if 
 * the request->reqNum field is larger than the maximum allowed MAX_REQ_UPDATE( see ref. SUBSET-137 5.3.7).
 */
static error_code_t sendCmdUpKeyValidities /** @return SUCCESS if the message is correctly prepared and sent, ERROR if the sendMsg() call fails. */  
(					                                                                                                             
	const request_t* const request,           /**< [in] The pointer to the structure holding the list of k-validity structures to be sent.*/
	const session_t* const curr_session	   /**< [in] The pointer the structure holding the information about the current application session.*/
	)
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

/**
 * Sends a message of type CMD_UPDATE_KEY_ENTITIES to the corresponding peer entity.
 *
 * This function prepares, serializes in net format and sends a message of type CMD_UPDATE_KEY_ENTITIES to the peer entity
 * specified in the field curr_session->peerEtcsIDExp using the TLS connection identifier curr_session->tlsID.
 * In particular it uses as message payload the request->reqNum field and the list of k-entities stored in the request->kEntityList[] array.
 * The function calls the exit() function on any erorr on the addressing of the input parameters or if 
 * the request->reqNum field is larger than the maximum allowed MAX_REQ_UPDATE( see ref. SUBSET-137 5.3.8).
 */
static error_code_t sendCmdUpKeyEntities /** @return SUCCESS if the message is correctly prepared and sent, ERROR if the sendMsg() call fails. */  
(					                                                                                                           
	const request_t* const request,  	 /**< [in] The pointer to the structure holding the list of k-entities structures to be sent.*/		     
	const session_t* const curr_session	 /**< [in] The pointer the structure holding the information about the current application session.*/      
	)
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

/**
 * Sends a message of type CMD_DELETE_ALL_KEYS to the corresponding peer entity.
 *
 * This function prepares, serializes in net format and sends a message of type CMD_DELETE_ALL to the peer entity
 * specified in the field curr_session->peerEtcsIDExp using the TLS connection identifier curr_session->tlsID.
 * The function calls the exit() function on any erorr on the addressing of the input parameters.
 */
static error_code_t sendCmdDeleteAllKeys /** @return SUCCESS if the message is correctly prepared and sent, ERROR if the sendMsg() call fails. */  
(
	const session_t* const curr_session     /**< [in] The pointer the structure holding the information about the current application session.*/      
	)
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

	/* this command does not have body,
	   it consists only of the message header */
	if(sendMsg(&ostream, curr_session->tlsID) != SUCCESS)
	{
		return(ERROR);
	}
		
	return(SUCCESS);
}

/**
 * Sends a message of type CMD_REQUEST_KEY_DB_CHECKSUM to the corresponding peer entity.
 *
 * This function prepares, serializes in net format and sends a message of type CMD_REQUEST_KEY_DB_CHECKSUM to the peer entity
 * specified in the field curr_session->peerEtcsIDExp using the TLS connection identifier curr_session->tlsID.
 * The function calls the exit() function on any erorr on the addressing of the input parameters.
 */
static error_code_t sendCmdReqKeyDBChecksum /** @return SUCCESS if the message is correctly prepared and sent, ERROR if the sendMsg() call fails. */  
(
	const session_t* const curr_session /**< [in] The pointer the structure holding the information about the current application session.*/      
	)
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

/**
 * Sends a message of type CMD_REQUEST_KEY_OPERATION to the corresponding peer entity.
 *
 * This function prepares, serializes in net format and sends a message of type CMD_REQUEST_KEY_OPERATION to the peer entity
 * specified in the field curr_session->peerEtcsIDExp using the TLS connection identifier curr_session->tlsID.
 * In particular it uses as message body the request->reqKeyOpPayload structure.
 * The function calls the exit() function on any erorr on the addressing of the input parameters.
 */
static error_code_t sendCmdReqKeyOperation /** @return SUCCESS if the message is correctly prepared and sent, ERROR if the sendMsg() call fails. */  
(
	const request_t* const request,     /**< [in] The pointer to the structure holding the body of message to be sent.*/
	const session_t* const curr_session /**< [in] The pointer the structure holding the information about the current application session.*/      
	)
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

/**
 * Sends a message of type NOTIF_KEY_UPDATE_STATUS to the corresponding peer entity.
 *
 * This function prepares, serializes in net format and sends a message of type NOTIF_KEY_UPDATE_STATUS to the peer entity
 * specified in the field curr_session->peerEtcsIDExp using the TLS connection identifier curr_session->tlsID.
 * In particular it uses as message body the request->keyUpStatusPayload structure.
 * The function calls the exit() function on any erorr on the addressing of the input parameters.
 */
static error_code_t sendNotifKeyUpdateStatus /** @return SUCCESS if the message is correctly prepared and sent, ERROR if the sendMsg() call fails. */  
(
	const request_t* const request,     /**< [in] The pointer to the structure holding the body of message to be sent.*/
	const session_t* const curr_session /**< [in] The pointer the structure holding the information about the current application session.*/
	)
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

	/* send the message */
	if(sendMsg(&ostream, curr_session->tlsID) != SUCCESS)
	{
		return(ERROR);
	}

	return(SUCCESS);
}



/*****************************************************************************
 * PUBLIC FUNCTION DECLARATIONS
 *****************************************************************************/

/**
 * Sends a message of type NOTIF_KEY_DB_CHECKSUM to the corresponding peer entity.
 *
 * This function prepares, serializes in net format and sends a message of type NOTIF_KEY_DB_CHECKSUM to the peer entity
 * specified in the field curr_session->peerEtcsIDExp using the TLS connection identifier curr_session->tlsID.
 * In particular it uses as message body the response->dbChecksumPayload structure holding the checksum evaluated on the key database.
 * The function calls the exit() function on any erorr on the addressing of the input parameters.
 */
error_code_t sendNotifKeyDBChecksum /** @return SUCCESS if the message is correctly prepared and sent, ERROR if the sendMsg() call fails. */  
(
	const response_t* const response,   /**< [in] The pointer to the structure holding the checksum of the database.*/
	const session_t* const curr_session /**< [in] The pointer the structure holding the information about the current application session.*/
	)
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

	/* send the message */
	if(sendMsg(&ostream, curr_session->tlsID) != SUCCESS)
	{
		return(ERROR);
	}
	
	return(SUCCESS);
}

/**
 * Sends a message of type NOTIF_RESPONSE to the corresponding peer entity.
 *
 * This function prepares, serializes in net format and sends a message of type NOTIF_RESPONSE to the peer entity
 * specified in the field curr_session->peerEtcsIDExp using the TLS connection identifier curr_session->tlsID.
 * In particular it uses as message body the response->notifPayload structure.
 * The function calls the exit() function on any erorr on the addressing of the input parameters.
 */
error_code_t sendNotifResponse /** @return SUCCESS if the message is correctly prepared and sent, ERROR if the sendMsg() call fails. */  
(
	const response_t* const response,   /**< [in] The pointer to the structure holding the message body.*/
	const session_t* const curr_session /**< [in] The pointer the structure holding the information about the current application session.*/
	)
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

/**
 * Sends a message of type NOTIF_KEY_OPERATION_REQ_RCVD to the corresponding peer entity.
 *
 * This function prepares, serializes in net format and sends a message of type NOTIF_KEY_OPERATION_REQ_RCVD to the peer entity
 * specified in the field curr_session->peerEtcsIDExp using the TLS connection identifier curr_session->tlsID.
 * In particular it uses as message body the response->keyOpRecvdPayload structure.
 * The function calls the exit() function on any erorr on the addressing of the input parameters.
 */
error_code_t sendNotifKeyOpReqRcvd /** @return SUCCESS if the message is correctly prepared and sent, ERROR if the sendMsg() call fails. */  
(
	const response_t* const response,   /**< [in] The pointer to the structure holding the message body.*/
	const session_t* const curr_session /**< [in] The pointer the structure holding the information about the current application session.*/
	)
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

	/* send the message */
	if(sendMsg(&ostream, curr_session->tlsID) != SUCCESS)
	{
		return(ERROR);
	}
	
	return(SUCCESS);
}

/**
 * Sends a message of type NOTIF_ACK_KEY_UPDATE_STATUS to the corresponding peer entity.
 *
 * This function prepares, serializes in net format and sends a message of type NOTIF_ACK_KEY_UPDATE_STATUS to the peer entity
 * specified in the field curr_session->peerEtcsIDExp using the TLS connection identifier curr_session->tlsID.
 * This message has no body.
 * The function calls the exit() function on any erorr on the addressing of the input parameters.
 */
error_code_t sendNotifAckKeyUpStatus /** @return SUCCESS if the message is correctly prepared and sent, ERROR if the sendMsg() call fails. */  
(
	const session_t* const curr_session /**< [in] The pointer the structure holding the information about the current application session.*/
	)
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
	/* send the message */
	if(sendMsg(&ostream, curr_session->tlsID) != SUCCESS)
	{
		return(ERROR);
	}
	
	return(SUCCESS);
}

/**
 * Initializes a TLS client.
 *
 * This function initialize a TLS client validating the Certificate Authority certificate and the private key
 * and certificate stored in the confiuration struct, if the initalization succeds the tls_id is updated with a valid TLS connection identifier.
 * The function calls the exit() function on any erorr on the addressing of the input parameters.
 */
error_code_t startClientTLS /** @return SUCCESS in case of initilization success, ERROR if the initClientTLS() call fails  */
(
	tls_des_t* const tls_id    /**< [out] The identifier of the TLS connection.*/     
	)
{
	ASSERT(tls_id != NULL, E_NULL_POINTER);
  
	if(initClientTLS(tls_id,
					 ss137_lib_config.rsaCACertificateFile,
					 ss137_lib_config.rsaKey,
					 ss137_lib_config.rsaCertificate) != TLS_SUCCESS)
    {
		return(ERROR);
    }
  
	return(SUCCESS);
}

/**
 * Connects to a TLS server.
 *
 * This function try to connect to the TLS server with the IP specified as argument.
 * The function calls the exit() function on any erorr on the addressing of the input parameters.
 */
error_code_t connectToTLSServer /** @return SUCCESS if the connection is enstablished, ERROR if the connectTLS() call fails  */
(
	const tls_des_t const tls_id,  /**< [in] The identifier of the TLS connection enstablished*/     
	const char* const server_ip    /**< [in] The server ip given in ASCII format(eg 10.0.1.200).*/     
	)
{
	ASSERT(server_ip != NULL, E_NULL_POINTER);
  
	if(connectTLS(tls_id, server_ip, SS137_TCP_PORT) != TLS_SUCCESS)
    {
		return(ERROR);
    }
  
	return(SUCCESS);
}

/**
 * Initializes a TLS server.
 *
 * This function initialize a TLS server validating the Certificate Authority certificate and the private key
 * and certificate stored in the configuration struct.
 * The function calls the exit() function on any erorr on the addressing of the input parameters.
 */
error_code_t startServerTLS /** @return SUCCESS in case of initilization success, ERROR if the initServerTLS() call fails  */
(
	void
	)
{

	if(initServerTLS(SS137_TCP_PORT,
					 ss137_lib_config.rsaCACertificateFile,
					 ss137_lib_config.rsaKey,
					 ss137_lib_config.rsaCertificate) != TLS_SUCCESS)
    {
		return(ERROR);
    }
  
	return(SUCCESS);
}

/**
 * Listens for incoming TLS connection.
 *
 * This function starts listening for incoming TLS connection. 
 * When a valid connection is enstablished the tls_id is updated with the identifier of the 
 * corresponding connection and exp_exts_id parameter with the Expanded ETCS Id of the connecting client.
 * The function calls the exit() function on any erorr on the addressing of the input parameters.
 */
error_code_t listenForTLSClient /** @return SUCCESS in case of initilization success, ERROR if the acceptTLS() call fails or there is no KMS Entity configured with the corresponding ip address  */
(
	tls_des_t* const tls_id,     /**< [out] The identifier of the TLS connection enstablished*/     
	uint32_t* const exp_etcs_id  /**< [out] The Expanded ETCS Id of the client connected.*/     
	)
{
	uint32_t i = 0U;
	bool_t found = FALSE;
	char client_ip[MAX_IP_LENGTH] = {0,};
	
	ASSERT(tls_id != NULL, E_NULL_POINTER);
	ASSERT(exp_etcs_id != NULL, E_NULL_POINTER);
  
	if(acceptTLS(tls_id, client_ip) != TLS_SUCCESS)
    {
		return(ERROR);
    }
  
	log_print("Connection from client %s\n", client_ip);
  
	/* look for the corresponding expanded etcs id */
	for(i = 0U; i < MAX_KMS_ENTITIES; i++)
	{
		if(strcmp(ss137_lib_config.kmsEntitiesId[i].ip, client_ip) == 0)
		{
			*exp_etcs_id = ss137_lib_config.kmsEntitiesId[i].expEtcsId;
			found = TRUE;
		}
	}

	if(found == FALSE)
	{
		return(ERROR);
	}
  
	return(SUCCESS);
}

/**
 * Closes a TLS connection.
 *
 * This function closes the TLS connection corresponding to the connection identifier passed as argument. 
 */
void closeTLSConnection /** @return void */
(
	const tls_des_t tls_id /**< [in] The identifier of the connection to close*/     
	)
{
	closeTLS(tls_id);

	return;
}

/**
 * Wait for a request from a KMC to a KMAC entity.
 *
 * This function is used by a KMAC entity when it is waiting for a request from a KMC. 
 * When a new KMC request is received, it is converted in host format and validated, in particular the header of the message is checked
 * and it is also checked if the message type is between the expected ones.
 * If the message is considered as valid the parameter request is set with the body of the message received.
 * If the header of the message is not valid, or the message has an invalid format a notify response message is sent
 * to the KMC with the corresponding error reason.
 * The function calls the exit() function on any erorr on the addressing of the input parameters.
 */
error_code_t waitForRequestFromKMCToKMAC /** @return SUCCESS if te request is considered valid, ERROR if the timeout expires without receiving new request or if the message is not valid */
(
	request_t* const request,      /**< [out]    The pointer to the structure holding the request from the KMC*/     			     
	session_t* const curr_session  /**< [in/out] The pointer the structure holding the information about the current application session.*/     
	)
{
	read_stream_t input_msg;
	msg_header_t header;
	response_reason_t result;
	response_t error_response;
	error_code_t tmp_error = SUCCESS;
  
	ASSERT(request != NULL, E_NULL_POINTER);
	ASSERT(curr_session != NULL, E_NULL_POINTER);
  
	memset(&error_response, 0U, sizeof(response_t));
  
	initReadStream(&input_msg);
  
	if(receiveMsg(&input_msg, curr_session->appTimeout, curr_session->tlsID) != SUCCESS)
    {
		return(ERROR);
    }
  
	/* reset the start time */
	gettimeofday(&(curr_session->startTime), NULL);
  
	if(convertMsgHeaderToHost(&header, &input_msg) != SUCCESS)
    {
		error_response.notifPayload.reason = RESP_WRONG_FORMAT;
		sendNotifResponse(&error_response, curr_session);
		return(ERROR);
    }
  
	checkMsgHeader(&result, curr_session, &header, input_msg.validBytes);
  
	if(result != RESP_OK)
    {
		error_response.notifPayload.reason = result;
		sendNotifResponse(&error_response, curr_session);
		return(ERROR);
    }
  
	switch(header.msgType)
    {
    case(CMD_ADD_KEYS):
		tmp_error = convertCmdAddKeysToHost(request, &input_msg);
		request->msgType = header.msgType;
		break;
    case(CMD_DELETE_KEYS):
		tmp_error = convertCmdDeleteKeysToHost(request, &input_msg);
		request->msgType = header.msgType;
		break;
    case(CMD_DELETE_ALL_KEYS):
		/* this message has no request */
		request->msgType = header.msgType;
		break;
    case(CMD_UPDATE_KEY_VALIDITIES):
		tmp_error = convertCmdUpKeyValiditiesToHost(request, &input_msg);
		request->msgType = header.msgType;
		break;
    case(CMD_UPDATE_KEY_ENTITIES):
		tmp_error = convertCmdUpKeyEntitiesToHost(request, &input_msg);
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
		error_response.notifPayload.reason = RESP_NOT_SUPPORTED;
		sendNotifResponse(&error_response, curr_session);
		return(ERROR);
    }
  
	if(tmp_error != SUCCESS)
    {
		error_response.notifPayload.reason = RESP_WRONG_FORMAT;
		sendNotifResponse(&error_response, curr_session);
		return(ERROR);
    }
  
	curr_session->transNum = header.transNum;
  
	return(SUCCESS);
}

/**
 * Wait for a request from a KMC to a KMC.
 *
 * This function is used by a KMC entity when it is waiting for a request from a KMC. 
 * When a new KMC request is received, it is converted in host format and validated, in particular the header of the message is checked
 * and it is also checked if the message type is between the expected ones.
 * If the message is considered as valid the parameter request is set with the body of the message received.
 * If the header of the message is not valid, or the message has an invalid format a notify response message is sent
 * to the KMC with the corresponding error reason.
 * The function calls the exit() function on any erorr on the addressing of the input parameters.
 */
error_code_t waitForRequestFromKMCToKMC  /** @return SUCCESS if the request is considered valid, ERROR if the timeout expires without receiving new request or if the message is not valid */
(
	request_t* const request,     /**< [out]    The pointer to the structure holding the request from the KMC*/
	session_t* const curr_session /**< [in/out] The pointer the structure holding the information about the current application session.*/
	)
{
	read_stream_t input_msg;
	msg_header_t header;
	response_reason_t result;
	response_t error_response;
	error_code_t tmp_error = SUCCESS;

	ASSERT(request != NULL, E_NULL_POINTER);
	ASSERT(curr_session != NULL, E_NULL_POINTER);	

	memset(&error_response, 0U, sizeof(response_t));
	
	initReadStream(&input_msg);
	
	if(receiveMsg(&input_msg, curr_session->appTimeout, curr_session->tlsID) != SUCCESS)
	{
		return(ERROR);
	}

	/* reset the start time */
	gettimeofday(&(curr_session->startTime), NULL);

	if(convertMsgHeaderToHost(&header, &input_msg) != SUCCESS)
	{
		error_response.notifPayload.reason = RESP_WRONG_FORMAT;
		sendNotifResponse(&error_response, curr_session);
		return(ERROR);
	}
	
	checkMsgHeader(&result, curr_session, &header, input_msg.validBytes);

	if(result != RESP_OK)
	{
		error_response.notifPayload.reason = result;
		sendNotifResponse(&error_response, curr_session);
		return(ERROR);
	}

	switch(header.msgType)
	{
	case(CMD_ADD_KEYS):
		tmp_error = convertCmdAddKeysToHost(request, &input_msg);
		request->msgType = header.msgType;
		break;
	case(CMD_DELETE_KEYS):
		tmp_error = convertCmdDeleteKeysToHost(request, &input_msg);
		request->msgType = header.msgType;
		break;
	case(CMD_UPDATE_KEY_VALIDITIES):
		tmp_error = convertCmdUpKeyValiditiesToHost(request, &input_msg);
		request->msgType = header.msgType;
		break;
	case(CMD_UPDATE_KEY_ENTITIES):
		tmp_error = convertCmdUpKeyEntitiesToHost(request, &input_msg);
		request->msgType = header.msgType;
		break;
	case(CMD_REQUEST_KEY_OPERATION):
		tmp_error = convertCmdReqKeyOperationToHost(request, &input_msg);
		request->msgType = header.msgType;
		break;
	case(NOTIF_KEY_UPDATE_STATUS):
		tmp_error = convertNotifKeyUpdateStatusToHost(request, &input_msg);
		request->msgType = header.msgType;
		break;
	case(NOTIF_END_OF_UPDATE):
		/* this message has no payload */
		request->msgType = header.msgType;
		break;
	default:
		err_print("Unexpected msg type received: rec %d\n", header.msgType);
		error_response.notifPayload.reason = RESP_NOT_SUPPORTED;
		sendNotifResponse(&error_response, curr_session);
		return(ERROR);
	}
	
	if(tmp_error != SUCCESS)
	{
	    error_response.notifPayload.reason = RESP_WRONG_FORMAT;
	    sendNotifResponse(&error_response, curr_session);
	    return(ERROR);
	}

	return(SUCCESS);
}

/**
 * Wait for a response from a KMC or a KMAC entity.
 *
 * This function is used by a KMC when it is waiting for a response to a request from a KMC or a KMAC. 
 * When a response is received, it is converted in host format and validated, in particular the header of the message is checked
 * and it is also checked if the message type is equal to the parameter exp_msg_type.
 * If the response message is considered as valid the parameter response is set with the body of the message received and the result 
 * parameter is set to RESP_OK.
 * If the header of the message is not valid, or the message has an invalid format a the parameter result 
 * is set to the corresponding error reason.
 * The function calls the exit() function on any erorr on the addressing of the input parameters.
 */
static error_code_t waitForResponse    /** @return SUCCESS if the response is considered valid, ERROR if the timeout expires without receiving the reponse or if the response message is not valid */
(
	response_t* const response,      /**< [out]    The pointer to the structure holding the body of the response message received.*/       
	response_reason_t* const result, /**< [out]    The result of the validation of the response message received.*/       
	session_t* const curr_session,   /**< [in/out] The pointer the structure holding the information about the current application session.*/       
	const msg_type_t exp_msg_type    /**< [in]     The expected message type.*/       
	)
{
	msg_header_t header;
	read_stream_t input_msg;
	error_code_t tmp_error = SUCCESS;
  
	ASSERT(response != NULL, E_NULL_POINTER);
	ASSERT(curr_session != NULL, E_NULL_POINTER);	
	ASSERT(result != NULL, E_NULL_POINTER);
  
	initReadStream(&input_msg);
  
	if(receiveMsg(&input_msg, curr_session->appTimeout, curr_session->tlsID) != SUCCESS)
    {
		return(ERROR);
    }
  
	/* reset the start time */
	gettimeofday(&(curr_session->startTime), NULL);
  
	if(convertMsgHeaderToHost(&header, &input_msg) != SUCCESS)
    {
		*result = RESP_WRONG_FORMAT;
		return(ERROR);
    }
  
	checkMsgHeader(result, curr_session, &header, input_msg.validBytes);
  
	if(*result != RESP_OK)
    {
		err_print("Error on checking header\n");
		return(ERROR);
    }
	else
    {
		/* notif response could be received in case of error */
		if((exp_msg_type != header.msgType ) &&
		   (exp_msg_type != NOTIF_RESPONSE))
		{
			err_print("Unexpected msg type received: rec %d\n", header.msgType);
			*result = RESP_NOT_SUPPORTED;
			return(ERROR);
		}
		else
		{
			switch(header.msgType)
			{
			case(NOTIF_RESPONSE):
				tmp_error = convertNotifResponseToHost(response, &input_msg);
				break;
			case(NOTIF_KEY_DB_CHECKSUM):
				tmp_error = convertNotifKeyDBChecksumToHost(response, &input_msg);
				break;
			case(NOTIF_KEY_OPERATION_REQ_RCVD):
				tmp_error = convertNotifKeyOpReqRcvdToHost(response, &input_msg);
				break;
			case(NOTIF_ACK_KEY_UPDATE_STATUS):
				/* this message has no payload */
				break;
			default:
				*result = RESP_NOT_SUPPORTED;
				return(ERROR);
			}
			if(tmp_error != SUCCESS)
			{
				*result = RESP_WRONG_FORMAT;
				return(ERROR);
			}
		}
    }
  
	return(SUCCESS);
}

/**
 * Initializes the application session.
 *
 * This function is used to initialize the application sesssion by sending the notify session init message and waiting
 * for the same message from the other peer.
 * The function performs the following steps:
 * - Initialize the curr_session parameter and set the field curr_session->appTimeout to the value app_timeout passed as parameter
 * - send a notif init session message to the other peer
 * - receive and validate the notif session init from the other peer
 * - Verify that the supported version field of the other peer is equal to the supportedVersion global variable
 * - If the curr_session->appTimeout is euqal to APP_TIMEOUT_PEER_DEF it is set to the application timeout defined by the other peer 
 * If the header of the message is not valid, the message has an invalid format or the version is not supported
 * a NOTIF_RESPONSE message is sent to the other peer reporting the error reason found.
 * The function calls the exit() function on any erorr on the addressing of the input parameters.
 */
error_code_t initAppSession  /** @return SUCCESS if the response is considered valid, ERROR if the timeout expires without receiving the notif_session_init message or if the message is not valid. */
(
	session_t* const curr_session,  /**< [in/out] The pointer the structure holding the information about the current application session.*/
	const uint8_t app_timeout,      /**< [in]     The application timeout.*/       
	const uint32_t peer_etcs_id_exp /**< [in]     The Expanded ETCS id of the other peer.*/       
	)
{
	notif_session_init_t response;
	response_reason_t result = RESP_OK;
	response_t error_response;

	ASSERT(curr_session != NULL, E_NULL_POINTER);
  
	memset(&error_response, 0U, sizeof(response_t));
		
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
		error_response.notifPayload.reason = result;
		sendNotifResponse(&error_response, curr_session);
		return(ERROR);
    }
	else
    {
		if( response.version[0] != supportedVersion[0] )
		{
			error_response.notifPayload.reason = RESP_WRONG_VERSION;
			sendNotifResponse(&error_response, curr_session);
			return(ERROR);
		}

		/* negotiate app_timeout and verify interface version compatibility */
		if(curr_session->appTimeout == APP_TIMEOUT_PEER_DEF)
		{
			curr_session->appTimeout = response.appTimeout;
		}

		curr_session->transNum++;
    }

	return(SUCCESS);
}

/**
 * End the application session.
 *
 * This function is used by a KMC to indicate that all requested updates have been transferred by sending 
 * a message of type NOTIF_END_OF_UPDATE.
 * The function calls the exit() function on any erorr on the addressing of the input parameters.
 */
error_code_t endAppSession  /** @return SUCCESS if the message is correctly sent, ERROR if the call sendNotifSessionEnd() fails. */
(
	const session_t* const curr_session /**< [in] The pointer the structure holding the information about the current application session.*/
	)
{
	ASSERT(curr_session != NULL, E_NULL_POINTER);
  
	if(sendNotifSessionEnd(curr_session) != SUCCESS)
    {
		return(ERROR);
    }
  
	return(SUCCESS);
}

/**
 * Performs a Add Keys transaction.
 *
 * This function is used by a KMC to install a set of keys to a given KMC or KMAC entity.
 * The function performs the following steps:
 * - it builds and sends the CMD_ADD_KEYS message using the request->kStructList array as body.
 * - it waits for the response from the other peer and verify if there is a notification for each 
 *  request sent. The single notification element needs to be checked externally.
 * - it increases the curr_session->transNum field of the structure passed as parameter.    
 * The function calls the exit() function on any erorr on the addressing of the input parameters.
 */
error_code_t performAddKeysTransaction /** @return SUCCESS if the command is successfully sent and a valid response is received, ERROR in case of error on sending or receiving the message or if the response is not valid. */  
(
	response_t* const response,      /**< [out]     The pointer to the structure holding the body of the NOTIF_RESPONSE message received.*/          
	session_t* const curr_session,   /**< [int/out] The pointer the structure holding the information about the current application session.*/          
	const request_t* const request   /**< [in]      The pointer to the structure holding the list of k-struct structures to be sent.*/     
	)
{
	msg_type_t exp_msg_type = NOTIF_RESPONSE;
	response_reason_t result;
	response_t error_response;
  
	ASSERT(curr_session != NULL, E_NULL_POINTER);
	ASSERT(response != NULL, E_NULL_POINTER);
	ASSERT(request != NULL, E_NULL_POINTER);
  
	memset(&error_response, 0U, sizeof(response_t));
  
	if(sendCmdAddKeys(request, curr_session) != SUCCESS)
    {
		return(ERROR);
    }
  
	if(waitForResponse(response,  &result, curr_session, exp_msg_type) != SUCCESS)
    {
		error_response.notifPayload.reason = result;
		sendNotifResponse(&error_response, curr_session);
		return(ERROR);
    }
  
	if ( request->reqNum != response->notifPayload.reqNum)
    {
		error_response.notifPayload.reason = RESP_WRONG_FORMAT;
		sendNotifResponse(&error_response, curr_session);
		return(ERROR);
    }
	else
    {
		curr_session->transNum++;
    }
  
	return(SUCCESS);
}

/**
 * Performs a Delete Keys transaction.
 *
 * This function is used by a KMC to delete a set of keys on a given KMC or KMAC entity.
 * The function performs the following steps:
 * - it builds and sends the CMD_DELETE_KEYS message using the request->kIdentList array as body.
 * - it waits for the response from the other peer and verify if there is a notification for each 
 *  request sent. The single notification element needs to be checked externally.
 * - it increases the curr_session->transNum field of the structure passed as parameter.    
 * The function calls the exit() function on any erorr on the addressing of the input parameters.
 */
error_code_t performDelKeysTransaction /** @return SUCCESS if the command is successfully sent and a valid response is received, ERROR in case of error on sending or receiving the message or if the response is not valid. */
(
	response_t* const response,    /**< [out]     The pointer to the structure holding the body of the NOTIF_RESPONSE message received.*/
	session_t* const curr_session, /**< [int/out] The pointer the structure holding the information about the current application session.*/
	const request_t* const request /**< [in]      The pointer to the structure holding the list of k-identifier structures to be sent.*/
	)
{
	msg_type_t exp_msg_type = NOTIF_RESPONSE;
	response_reason_t result;
	response_t error_response;
  
	ASSERT(curr_session != NULL, E_NULL_POINTER);
	ASSERT(response != NULL, E_NULL_POINTER);
	ASSERT(request != NULL, E_NULL_POINTER);
	
	memset(&error_response, 0U, sizeof(response_t));
  
	if(sendCmdDeleteKeys(request, curr_session) != SUCCESS)
    {
		return(ERROR);
    }
  
	if(waitForResponse(response, &result, curr_session, exp_msg_type) != SUCCESS)
    {
		error_response.notifPayload.reason = result;
		sendNotifResponse(&error_response, curr_session);
		return(ERROR);
    }
  
	if ( request->reqNum != response->notifPayload.reqNum)
    {
		error_response.notifPayload.reason = RESP_WRONG_FORMAT;
		sendNotifResponse(&error_response, curr_session);
		return(ERROR);
    }
	else
    {
		curr_session->transNum++;
    }
  
	return(SUCCESS);
}

/**
 * Performs a Update key Validities transaction.
 *
 * This function is used by a KMC to update the validity of a set of keys on a given KMC or KMAC entity.
 * The function performs the following steps:
 * - it builds and sends the CMD_UPDATE_KEY_VALIDITIES message using the request->kValidityList array as body.
 * - it waits for the response from the other peer and verify if there is a notification for each 
 *  request sent. The single notification element needs to be checked externally.
 * - it increases the curr_session->transNum field of the structure passed as parameter.    
 * The function calls the exit() function on any erorr on the addressing of the input parameters.
 */
error_code_t performUpKeyValiditiesTransaction /** @return SUCCESS if the command is successfully sent and a valid response is received, ERROR in case of error on sending or receiving the message or if the response is not valid. */
(
	response_t* const response,     /**< [out]     The pointer to the structure holding the body of the NOTIF_RESPONSE message received.*/
	session_t* const curr_session,  /**< [int/out] The pointer the structure holding the information about the current application session.*/
	const request_t* const request  /**< [in] The pointer to the structure holding the list of k-validity structures to be sent.*/
	)
{
	msg_type_t exp_msg_type = NOTIF_RESPONSE;
	response_reason_t result;
	response_t error_response;

	ASSERT(curr_session != NULL, E_NULL_POINTER);
	ASSERT(response != NULL, E_NULL_POINTER);
	ASSERT(request != NULL, E_NULL_POINTER);

	memset(&error_response, 0U, sizeof(response_t));

	if(sendCmdUpKeyValidities(request, curr_session) != SUCCESS)
	{
		return(ERROR);
	}

	if(waitForResponse(response, &result, curr_session, exp_msg_type) != SUCCESS)
	{
		error_response.notifPayload.reason = result;
		sendNotifResponse(&error_response, curr_session);
		return(ERROR);
	}

	if ( request->reqNum != response->notifPayload.reqNum)
	{
		error_response.notifPayload.reason = RESP_WRONG_FORMAT;
		sendNotifResponse(&error_response, curr_session);
		return(ERROR);
	}
	else
	{
		curr_session->transNum++;
	}

	return(SUCCESS);
}

/**
 * Performs a Update key Entities transaction.
 *
 * This function is used by a KMC to update the entities associated to a set of keys on a given KMC or KMAC entity.
 * The function performs the following steps:
 * - it builds and sends the CMD_UPDATE_KEY_ENTITIED message using the request->kEntityList array as body.
 * - it waits for the response from the other peer and verify if there is a notification for each 
 *  request sent. The single notification element needs to be checked externally.
 * - it increases the curr_session->transNum field of the structure passed as parameter.    
 * The function calls the exit() function on any erorr on the addressing of the input parameters.
 */
error_code_t performUpKeyEntitiesTransaction  /** @return SUCCESS if the command is successfully sent and a valid response is received, ERROR in case of error on sending or receiving the message or if the response is not valid. */
(
	response_t* const response,    /**< [out]     The pointer to the structure holding the body of the NOTIF_RESPONSE message received.*/
	session_t* const curr_session, /**< [int/out] The pointer the structure holding the information about the current application session.*/
	const request_t* const request /**< [in] The pointer to the structure holding the list of k-entity structures to be sent.*/
	)
{
	msg_type_t exp_msg_type = NOTIF_RESPONSE;
	response_reason_t result;
	response_t error_response;

	ASSERT(curr_session != NULL, E_NULL_POINTER);
	ASSERT(response != NULL, E_NULL_POINTER);
	ASSERT(request != NULL, E_NULL_POINTER);
	
	memset(&error_response, 0U, sizeof(response_t));

	if(sendCmdUpKeyEntities(request, curr_session) != SUCCESS)
	{
		return(ERROR);
	}

	if(waitForResponse(response, &result, curr_session, exp_msg_type) != SUCCESS)
	{
		error_response.notifPayload.reason = result;
		sendNotifResponse(&error_response, curr_session);
		return(ERROR);
	}

	if ( request->reqNum != response->notifPayload.reqNum)
	{
		error_response.notifPayload.reason = RESP_WRONG_FORMAT;
		sendNotifResponse(&error_response, curr_session);
		return(ERROR);
	}
	else
	{
		curr_session->transNum++;
	}
	
	return(SUCCESS);
}


/**
 * Performs a Delete All Keys transaction.
 *
 * This function is used by a KMC to request the deletion of all keys from the database of a given KMAC entities.
 * The function performs the following steps:
 * - it builds and sends the CMD_DELETE_ALL_KEYS message.
 * - it waits for the response from the other peer and validate the response.
 * - it increases the curr_session->transNum field of the structure passed as parameter.    
 * The function calls the exit() function on any erorr on the addressing of the input parameters.
 */
error_code_t performDeleteAllKeysTransaction /** @return SUCCESS if the command is successfully sent and a valid response is received, ERROR in case of error on sending or receiving the message or if the response is not valid. */
( 
	response_t* const response,   /**< [out]     The pointer to the structure holding the body of the NOTIF_RESPONSE message received.*/
	session_t* const curr_session /**< [int/out] The pointer the structure holding the information about the current application session.*/
	)
{
	msg_type_t exp_msg_type = NOTIF_RESPONSE;
	response_reason_t result;
	response_t error_response;
  
	ASSERT(curr_session != NULL, E_NULL_POINTER);
	ASSERT(response != NULL, E_NULL_POINTER);
  
	memset(&error_response, 0U, sizeof(response_t));
  
	if(sendCmdDeleteAllKeys(curr_session) != SUCCESS)
    {
		return(ERROR);
    }
  
	if(waitForResponse(response, &result, curr_session, exp_msg_type) != SUCCESS)
    {
		error_response.notifPayload.reason = result;
		sendNotifResponse(&error_response, curr_session);
		return(ERROR);
    }
	else
    {
		curr_session->transNum++;
    }
  
	return(SUCCESS);
}

/**
 * Performs a Request of Database checksum transaction.
 *
 * This function is used by a KMC to request the checksum of the Key Database from of a given KMAC entities.
 * The function performs the following steps:
 * - it builds and sends the CMD_REQUEST_KEY_DB_CHECKSUM.
 * - it waits for the response from the other peer and validate the response.
 * - it increases the curr_session->transNum field of the structure passed as parameter.    
 * The function calls the exit() function on any erorr on the addressing of the input parameters.
 */
error_code_t performReqDBChecksumTransaction /** @return SUCCESS if the command is successfully sent and a valid response is received, ERROR in case of error on sending or receiving the message or if the response is not valid. */
(
	response_t* const response,   /**< [out]     The pointer to the structure holding the body of the NOTIF_KEY_DB_CHECKSUM message received.*/
	session_t* const curr_session /**< [int/out] The pointer the structure holding the information about the current application session.*/
	)
{
	msg_type_t exp_msg_type = NOTIF_KEY_DB_CHECKSUM;
	response_reason_t result;
	response_t error_response;

	ASSERT(curr_session != NULL, E_NULL_POINTER);
	ASSERT(response != NULL, E_NULL_POINTER);

	memset(&error_response, 0U, sizeof(response_t));

	if(sendCmdReqKeyDBChecksum(curr_session) != SUCCESS)
	{
		return(ERROR);
	}

	if(waitForResponse(response, &result, curr_session, exp_msg_type) != SUCCESS)
	{
		error_response.notifPayload.reason = result;
		sendNotifResponse(&error_response, curr_session);
		return(ERROR);
	}
	else
	{
		curr_session->transNum++;
	}
	
	return(SUCCESS);
}

/**
 * Performs a Request of Key operation transaction.
 *
 * This function is used by a KMC to request to another KMC a key operation on a KMAC entities outside its domain.
 * The function performs the following steps:
 * - it builds and sends the CMD_REQUEST_KEY_OPERATION using the request->reqKeyOpPayload as message body.
 * - it waits for the response from the other peer and validate the response.
 * - it increases the curr_session->transNum field of the structure passed as parameter.    
 * The function calls the exit() function on any erorr on the addressing of the input parameters.
 */
error_code_t performReqKeyOpTransaction /** @return SUCCESS if the command is successfully sent and a valid response is received, ERROR in case of error on sending or receiving the message or if the response is not valid. */
(
	response_t* const response,     /**< [out]     The pointer to the structure holding the body of the NOTIF_KEY_OPERATION_REQ_RCVD message received.*/
	session_t* const curr_session,  /**< [int/out] The pointer the structure holding the information about the current application session.*/          
	const request_t* const request  /**< [in]      The pointer to the structure holding the body of the message to be sent.*/                      
	)
{
	msg_type_t exp_msg_type = NOTIF_KEY_OPERATION_REQ_RCVD;
	response_reason_t result;
	response_t error_response;
  
	ASSERT(curr_session != NULL, E_NULL_POINTER);
	ASSERT(response != NULL, E_NULL_POINTER);
  
	memset(&error_response, 0U, sizeof(response_t));
  
	if(sendCmdReqKeyOperation(request, curr_session) != SUCCESS)
    {
		return(ERROR);
    }
  
	if(waitForResponse(response, &result, curr_session, exp_msg_type) != SUCCESS)
    {
		error_response.notifPayload.reason = result;
		sendNotifResponse(&error_response, curr_session);
		return(ERROR);
    }
	else
    {
		curr_session->transNum++;
    }
  
	return(SUCCESS);
}

/**
 * Performs a Notif Key Update Status transaction.
 *
 * This function is used by a KMC to notify another KMC about the status of the key fow which an operation has been request.
 * The function performs the following steps:
 * - it builds and sends the NOTIF_KEY_UPDATE_STATUS using the request->keyUpStatusPayload as message body.
 * - it waits for the response from the other peer and validates the response.
 * - it increases the curr_session->transNum field of the structure passed as parameter.    
 * The function calls the exit() function on any erorr on the addressing of the input parameters.
 */
error_code_t performNotifKeyUpStatusTransaction /** @return SUCCESS if the command is successfully sent and a valid response is received, ERROR in case of error on sending or receiving the message or if the response is not valid. */
(
	response_t* const response,    /**< [out]     The pointer to the structure holding the body of the NOTIF_ACK_KEY_UPDATE_STATUS message received.*/
	session_t* const curr_session, /**< [int/out] The pointer the structure holding the information about the current application session.*/
	const request_t* const request /**< [in]      The pointer to the structure holding the body of the message to be sent.*/
	)
{
	msg_type_t exp_msg_type = NOTIF_ACK_KEY_UPDATE_STATUS;
	response_reason_t result;
	response_t error_response;
  
	ASSERT(curr_session != NULL, E_NULL_POINTER);
	ASSERT(response != NULL, E_NULL_POINTER);
	ASSERT(request != NULL, E_NULL_POINTER);
  
	memset(&error_response, 0U, sizeof(response_t));
  
	if(sendNotifKeyUpdateStatus(request, curr_session) != SUCCESS)
    {
		return(ERROR);
    }
  
	if(waitForResponse(response, &result, curr_session, exp_msg_type) != SUCCESS)
    {
		error_response.notifPayload.reason = result;
		sendNotifResponse(&error_response, curr_session);
		return(ERROR);
    }
	else
    {
		curr_session->transNum++;
    }
  
	return(SUCCESS);
}


/**
 * Evaluates the md4 checksum on a list of k-struct.
 *
 * TBD
 */
error_code_t evaluateChecksum /** @return SUCCESS if the checksum is correctly evaluated, ERROR in case of error. */
(
	notif_key_db_checksum_t* const checksum, /**< [out] The structure where the checksum will be stored.*/
	const k_struct_t k_struct_list[],        /**< [in]  The array of k-struct on which evaluate the checksum.*/
	const uint32_t k_struct_num              /**< [in]  The number ot k_struct_t.*/
	)
{
	ASSERT(checksum != NULL, E_NULL_POINTER);
	/* This function has not yet been implemented */

	return(SUCCESS);
}
