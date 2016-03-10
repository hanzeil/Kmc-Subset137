/**************************************************************************//**
 *
 * Definitions of messages for SUBSET-137
 *
 * This file ...
 *
 * @file: ss137/ss137_lib/include/msg_definitions.h
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

#ifndef KMC_MSG_DEFINITIONS_H_
#define KMC_MSG_DEFINITIONS_H_

/*****************************************************************************
* DEFINES
******************************************************************************/

#define NUM_VERSION       (1U) /* number of supported version */

#define KMAC_SIZE         (24U)

#define MIN_PEER_NUM      (1U)
#define MAX_PEER_NUM      (1000U)

#define MIN_REQ_ADD_KEYS  (1U)
#define MAX_REQ_ADD_KEYS  (100U)

#define MIN_REQ_DEL_KEYS  (1U)
#define MAX_REQ_DEL_KEYS  (500U)

#define MIN_REQ_UPDATE  (1U)
#define MAX_REQ_UPDATE  (250U)

#define MAX_REQ_NOTIF   (500U)

#define MAX_TEXT_LENGTH (1000U)

#define CHECKSUM_SIZE (20U) /* size of md4 checksum evaluated on DB */

#define K_LENGTH       (24U)

#define MSG_HEADER_SIZE      (4*sizeof(uint32_t) + sizeof(uint16_t) + 2*sizeof(uint8_t))  /* 20 bytes */
#define MSG_PAYLOAD_MAX_SIZE (MSG_MAX_SIZE - MSG_HEADER_SIZE) /* 4980 bytes */

#define K_IDENT_SIZE      (2*sizeof(uint32_t))  /* 8 bytes */
#define K_STRUCT_MIN_SIZE (K_IDENT_SIZE + 3*sizeof(uint32_t) + sizeof(uint16_t) + sizeof(uint8_t) + K_LENGTH*sizeof(uint8_t)) /* without etcsID field */
#define K_VALIDITY_SIZE   (K_IDENT_SIZE+2*sizeof(uint32_t))
#define K_ENTITY_MIN_SIZE (K_IDENT_SIZE+sizeof(uint16_t))

#define CMD_ADD_KEYS_MIN_SIZE        (MSG_HEADER_SIZE+sizeof(uint16_t))
#define CMD_DEL_KEYS_MIN_SIZE        (MSG_HEADER_SIZE+sizeof(uint16_t))
#define CMD_DEL_ALL_KEYS_SIZE        (MSG_HEADER_SIZE)
#define CMD_UP_KEY_VAL_MIN_SIZE      (MSG_HEADER_SIZE+sizeof(uint16_t))
#define CMD_UP_KEY_ENT_MIN_SIZE      (MSG_HEADER_SIZE+sizeof(uint16_t))
#define CMD_REQUEST_KEY_OP_MIN_SIZE  (MSG_HEADER_SIZE+3*sizeof(uint32_t)+sizeof(uint8_t)+sizeof(uint16_t))
#define CMD_REQUEST_KEY_DB_CK_SIZE   (MSG_HEADER_SIZE)
#define NOTIF_KEY_UP_STATUS_SIZE     (MSG_HEADER_SIZE+K_IDENT_SIZE+sizeof(uint8_t))
#define NOTIF_ACK_KEY_UP_STATUS_SIZE (MSG_HEADER_SIZE)
#define NOTIF_SESSION_INIT_SIZE      (MSG_HEADER_SIZE + sizeof(uint8_t) * 3)
#define NOTIF_END_UPDATE_SIZE        (MSG_HEADER_SIZE)
#define NOTIF_RESPONSE_MIN_SIZE      (MSG_HEADER_SIZE+sizeof(uint8_t)+sizeof(uint16_t))
#define NOTIF_KEY_OP_REQ_RCVD_SIZE   (MSG_HEADER_SIZE+sizeof(uint16_t))
#define NOTIF_KEY_DB_CHECKSUM_SIZE   (MSG_HEADER_SIZE+CHECKSUM_SIZE)

#define APP_TIMEOUT_PEER_DEF         (0xFFU)


/*****************************************************************************
 * TYPEDEFS
 *****************************************************************************/

typedef enum
{
	CMD_ADD_KEYS                 = 0,
	CMD_DELETE_KEYS              = 1,
	CMD_DELETE_ALL_KEYS          = 2,
	CMD_UPDATE_KEY_VALIDITIES    = 3,
	CMD_UPDATE_KEY_ENTITIES      = 4,
	CMD_REQUEST_KEY_OPERATION    = 5,
	CMD_REQUEST_KEY_DB_CHECKSUM  = 6,
	NOTIF_KEY_UPDATE_STATUS      = 7,
	NOTIF_ACK_KEY_UPDATE_STATUS  = 8,
	NOTIF_SESSION_INIT           = 9,
	NOTIF_END_OF_UPDATE          = 10,
	NOTIF_RESPONSE               = 11,
	NOTIF_KEY_OPERATION_REQ_RCVD = 12,
	NOTIF_KEY_DB_CHECKSUM        = 13
} msg_type_t;

typedef struct
{
	uint32_t  msgLength;
	uint8_t   version;
	uint32_t  recIDExp;
	uint32_t  sendIDExp;
	uint32_t  transNum;
	uint16_t  seqNum;
	uint8_t   msgType;
} msg_header_t;

/* request struct */
typedef struct
{
	uint32_t  genID;
	uint32_t  serNum;
} k_ident_t;

typedef struct
{
	uint8_t   length;
	k_ident_t kIdent;
	uint32_t  etcsID;
	uint8_t   kMAC[KMAC_SIZE];
	uint16_t  peerNum;
	uint32_t  peerID[MAX_PEER_NUM];
	uint32_t  startValidity;
	uint32_t  endValidity;
} k_struct_t;

typedef struct
{
	k_ident_t kIdent;
	uint32_t  startValidity;
	uint32_t  endValidity;
} k_validity_t;

typedef struct
{
	k_ident_t kIdent;
	uint16_t  peerNum;
	uint32_t  peerID[MAX_PEER_NUM];
} k_entity_t;

typedef struct
{
	uint32_t etcsID;
	uint8_t  reason;
	uint32_t startValidity;
	uint32_t endValidity;
	uint16_t textLength;
	char     text[MAX_TEXT_LENGTH];
} cmd_req_key_op_t;

typedef struct
{
	k_ident_t kIdent;
	uint8_t   kStatus;
} key_update_status_t;

typedef struct
{
	msg_type_t          msgType;
	uint16_t            reqNum;
	k_struct_t          kStructList[MAX_REQ_ADD_KEYS];
	k_ident_t           kIdentList[MAX_REQ_DEL_KEYS];
	k_validity_t        kValidityList[MAX_REQ_UPDATE];
	k_entity_t          kEntityList[MAX_REQ_UPDATE];
	cmd_req_key_op_t    reqKeyOpPayload;
	key_update_status_t keyUpStatusPayload;
} request_t;


/* notification struct */

typedef struct
{
	uint8_t nVersion;
	uint8_t version[NUM_VERSION];
	uint8_t appTimeout;
} notif_session_init_t;


typedef struct
{
	uint8_t  reason;
	uint16_t reqNum;
	uint8_t  notificationList[MAX_REQ_NOTIF];
} notif_response_t;

typedef struct
{
	uint16_t maxTime;
} notif_key_op_req_rcvd_t;

typedef struct
{
	uint8_t checksum[CHECKSUM_SIZE];
} notif_key_db_checksum_t;

typedef struct
{
	msg_type_t              msgType;
	notif_response_t        notifPayload;
	notif_key_db_checksum_t dbChecksumPayload;
	notif_key_op_req_rcvd_t keyOpRecvdPayload;
} response_t;

typedef enum
{
	NEW_TRAIN    = 0,
	MOD_AREA     = 1,
	RED_SCHED    = 2,
	APPR_END_VAL = 3
} req_key_op_t;

typedef enum
{
	KEY_INST  = 1,
	KEY_UP    = 2,
	KEY_DEL   = 3
} k_status_t;

typedef enum
{
	RESP_OK               = 0,  /*     Success */
	RESP_NOT_SUPPORTED    = 1,
	RESP_WRONG_LENGTH     = 1,
	RESP_WRONG_SENDER_ID  = 3,
	RESP_WRONG_REC_ID     = 4,
	RESP_WRONG_VERSION    = 5,
	RESP_KEY_BD_FAULT     = 6,
	RESP_MSG_PROC_FAULT   = 7,
	RESP_WRONG_CHKSUM     = 8,
	RESP_WRONG_SEQ_NUM    = 9,
	RESP_WRONG_TRANS_NUM  = 10,
	RESP_WRONG_FORMAT     = 11
} response_reason_t;

typedef enum
{
	REQ_SUCCESS   = 0,
	UNKNOWN_KEY   = 1,
	MAX_KEY       = 2,
	KEY_EXIST     = 3,
	KEY_CORRUPTED = 4,
	WRONG_ID      = 5
} notif_reason_t;

#endif /* KMC_MSG_DEFINITIONS_H_ */
