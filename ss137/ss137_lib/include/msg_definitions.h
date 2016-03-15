/**************************************************************************//**
 *
 * Definitions of messages for SUBSET-137
 *
 * This file contains all the definitions related to the messages
 * exchanged in SUBSET-137
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

/** Number of supported version in the current release (see ref. SUBSET-137 5.3.13) */
#define NUM_VERSION       (1U) 

/** Application timeout defined by the peer entity (see ref. SUBSET-137 5.3.13) */
#define APP_TIMEOUT_PEER_DEF (0xFFU)

/** The key length in bytes (see ref. SUBSET-137 5.3.4.1) */
#define KMAC_SIZE         (24U)

/** @name Number of peer entities associated with an authentication key (see ref. SUBSET-137 5.3.4.1)
 **@{*/
#define MIN_PEER_NUM      (1U)
#define MAX_PEER_NUM      (1000U)
/**@}*/

/** @name Number of k-struct in a CMD_ADD_KEYS message (see ref. SUBSET-137 5.3.4.1)
 **@{*/
#define MIN_REQ_ADD_KEYS  (1U)
#define MAX_REQ_ADD_KEYS  (100U)
/**@}*/

/** @name Number of k-identifier in a CMD_DEL_KEYS message (see ref. SUBSET-137 5.3.5)
 **@{*/
#define MIN_REQ_DEL_KEYS  (1U)
#define MAX_REQ_DEL_KEYS  (500U)
/**@}*/

/** @name Number of k-validity in a CMD_UPDATE_KEY_VALIDITIES (see ref. SUBSET-137 5.3.7)
	or k-entitites in a CMD_UPDATE_KEy_ENTITIES message (see ref. SUBSET-137 5.3.8)
	**@{*/
#define MIN_REQ_UPDATE  (1U)
#define MAX_REQ_UPDATE  (250U)
/**@}*/

/** Max number ot notification struct in a NOTIF_RESPONSE message (see ref. SUBSET-137 5.3.15) */
#define MAX_REQ_NOTIF   (500U)

/** Max text length in a CMD_REQUEST_KEY_OPERATION message (see ref. SUBSET-137 5.3.9) */
#define MAX_TEXT_LENGTH (1000U)

/** Size of the md4 checksum (see ref. SUBSET-137 5.3.9) */
#define CHECKSUM_SIZE (20U) 

/** Size of k-identifier struct (see ref. SUBSET-137 5.3.4.2) */
#define K_IDENT_SIZE      (2*sizeof(uint32_t))

/** Minimun size of a k-struct  (see ref. SUBSET-137 5.3.4.1) */
#define K_STRUCT_MIN_SIZE (K_IDENT_SIZE + 3*sizeof(uint32_t) + sizeof(uint16_t) + sizeof(uint8_t) + KMAC_SIZE*sizeof(uint8_t))

/** Size of k-validity struct (see ref. SUBSET-137 5.3.7.1) */
#define K_VALIDITY_SIZE   (K_IDENT_SIZE + 2*sizeof(uint32_t))

/** Minimum size of k-entity struct (see ref. SUBSET-137 5.3.8.1) */
#define K_ENTITY_MIN_SIZE (K_IDENT_SIZE + sizeof(uint16_t))

/** Message header size, 20 bytes (see ref. SUBSET-137 5.3.3) */
#define MSG_HEADER_SIZE      (4*sizeof(uint32_t) + sizeof(uint16_t) + 2*sizeof(uint8_t))

/** Message payload max size */
#define MSG_PAYLOAD_MAX_SIZE (MSG_MAX_SIZE - MSG_HEADER_SIZE) /* 4980 bytes */

/** Size of the number of request field */
#define REQ_NUM_SIZE      (sizeof(uint16_t))

/** @name Message tipical size
 **@{*/
#define CMD_ADD_KEYS_MIN_SIZE        (MSG_HEADER_SIZE+REQ_NUM_SIZE)
#define CMD_DEL_KEYS_MIN_SIZE        (MSG_HEADER_SIZE+REQ_NUM_SIZE)
#define CMD_DEL_ALL_KEYS_SIZE        (MSG_HEADER_SIZE)
#define CMD_UP_KEY_VAL_MIN_SIZE      (MSG_HEADER_SIZE+REQ_NUM_SIZE)
#define CMD_UP_KEY_ENT_MIN_SIZE      (MSG_HEADER_SIZE+REQ_NUM_SIZE)
#define CMD_REQUEST_KEY_OP_MIN_SIZE  (MSG_HEADER_SIZE+3*sizeof(uint32_t)+sizeof(uint8_t)+sizeof(uint16_t))
#define CMD_REQUEST_KEY_DB_CK_SIZE   (MSG_HEADER_SIZE)
#define NOTIF_KEY_UP_STATUS_SIZE     (MSG_HEADER_SIZE+K_IDENT_SIZE+sizeof(uint8_t))
#define NOTIF_ACK_KEY_UP_STATUS_SIZE (MSG_HEADER_SIZE)
#define NOTIF_SESSION_INIT_SIZE      (MSG_HEADER_SIZE + 3*sizeof(uint8_t))
#define NOTIF_END_UPDATE_SIZE        (MSG_HEADER_SIZE)
#define NOTIF_RESPONSE_MIN_SIZE      (MSG_HEADER_SIZE+sizeof(uint8_t)+REQ_NUM_SIZE)
#define NOTIF_KEY_OP_REQ_RCVD_SIZE   (MSG_HEADER_SIZE+sizeof(uint16_t))
#define NOTIF_KEY_DB_CHECKSUM_SIZE   (MSG_HEADER_SIZE+CHECKSUM_SIZE)
/**@}*/

/*****************************************************************************
 * TYPEDEFS
 *****************************************************************************/

/** Message type (see ref. SUBSET-137 5.3.3) */
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
	NOTIF_KEY_DB_CHECKSUM        = 13,
	END_MSG_TYPE                 = 14
} msg_type_t;

/** Message header struct typedef (see ref. SUBSET-137 5.3.3) */
typedef struct
{
	uint32_t  msgLength; /**< Message lenght */
	uint8_t   version;   /**< Interface Version */
	uint32_t  recIDExp;  /**< Receiver ID */
	uint32_t  sendIDExp; /**< Sender ID */
	uint32_t  transNum;  /**< Transaction Number  */
	uint16_t  seqNum;    /**< Sequence Number  */
	uint8_t   msgType;   /**< Message type  */
} msg_header_t;

/** k-ident struct typedef (see ref. SUBSET-137 5.3.4.2) */
typedef struct
{
	uint32_t  genID;  /**< The identity of the KMC that issued the key */
	uint32_t  serNum; /**< The serial number of the key */
} k_ident_t;

/** k-struct struct typedef (see ref. SUBSET-137 5.3.4.1) */
typedef struct
{
	uint8_t   length;               /**< The key length in bytes */
	k_ident_t kIdent;               /**< Structure that uniquely identifies a key */
	uint32_t  etcsID;               /**< The expanded ETCS-ID of the recipient KMAC entity */
	uint8_t   kMAC[KMAC_SIZE];      /**< The authentication key */
	uint16_t  peerNum;              /**< The number of peer entities following this field */
	uint32_t  peerID[MAX_PEER_NUM]; /**< List of KMAC entities linked to this key */
	uint32_t  startValidity;        /**< Start validity period */ 
	uint32_t  endValidity;          /**< End validity period */   
} k_struct_t;

/** k-validity struct typedef (see ref. SUBSET-137 5.3.7.1) */
typedef struct
{
	k_ident_t kIdent;        /**< Structure that uniquely identifies a key */
	uint32_t  startValidity; /**< Start validity period */ 
	uint32_t  endValidity;	 /**< End validity period */   
} k_validity_t;

/** k-entities struct typedef (see ref. SUBSET-137 5.3.8.1) */
typedef struct
{
	k_ident_t kIdent;                /**< Structure that uniquely identifies a key */
	uint16_t  peerNum;               /**< The number of peer entities following this field */
	uint32_t  peerID[MAX_PEER_NUM];  /**< List of KMAC entities linked to this key */
} k_entity_t;

/** CMD_REQUEST_KEY_OPERATION message struct typedef (see ref. SUBSET-137 5.3.9) */
typedef struct
{
	uint32_t etcsID;                /**< KMAC entity for which a key operation is requested.*/
	uint8_t  reason;                /**< Reason of the key operation.*/
	uint32_t startValidity;         /**< Start validity period */   
	uint32_t endValidity;           /**< End validity period */   
	uint16_t textLength;            /**< Lenght of the optional text. */   
	char     text[MAX_TEXT_LENGTH]; /**< Optional text to provide extra info for a key operation(UTF-8). */   
} cmd_req_key_op_t;

/** Request key operation reason (see ref. SUBSET-137 5.3.9) */
typedef enum
{
	NEW_TRAIN    = 0,
	MOD_AREA     = 1,
	RED_SCHED    = 2,
	APPR_END_VAL = 3
} req_key_op_t;

/** NOTIF_KEY_UPDATE_STATUS message struct typedef (see ref. SUBSET-137 5.3.11) */
typedef struct
{
	k_ident_t kIdent;  /**< Identifier of the key for which the status is reported.*/
	uint8_t   kStatus; /**< The status of the key operation.*/
} key_update_status_t;

/** Key status (see ref. SUBSET-137 5.3.11) */
typedef enum
{
	KEY_INST  = 1,
	KEY_UP    = 2,
	KEY_DEL   = 3
} k_status_t;

/** Struct holding all kind of command/request message payload */
typedef struct
{
	msg_type_t          msgType;                       /**< The type of the request.*/
	uint16_t            reqNum;                        /**< The number of kStructList, kIdentList, kValidityList or kEntityList that follows.*/
	k_struct_t          kStructList[MAX_REQ_ADD_KEYS]; /**< It stores the message body of a CMD_ADD_KEYS msg.*/
	k_ident_t           kIdentList[MAX_REQ_DEL_KEYS];  /**< It stores the message body of a CMD_DEL_KEYS msg.*/
	k_validity_t        kValidityList[MAX_REQ_UPDATE]; /**< It stores the message body of a CMD_UPDATE_KEY_VALIDITIES msg.*/
	k_entity_t          kEntityList[MAX_REQ_UPDATE];   /**< It stores the message body of a CMD_UPDATE_KEY_ENTITIED msg.*/
	cmd_req_key_op_t    reqKeyOpPayload;               /**< It stores the message body of a CMD_REQUEST_KEY_OPERATION msg.*/
	key_update_status_t keyUpStatusPayload;            /**< It stores the message body of a NOTIF_KEY_UPDATE_STATUS.*/
} request_t;

/** NOTIF_SESSION_INIT message struct typedef (see ref. SUBSET-137 5.3.13) */
typedef struct
{
	uint8_t nVersion;             /**< The number of version supported, currently 1.*/
	uint8_t version[NUM_VERSION]; /**< The list of supported version.*/
	uint8_t appTimeout;           /**< Application time-out in seconds.*/
} notif_session_init_t;

/** NOTIF_RESPONSE message struct typedef (see ref. SUBSET-137 5.3.13) */
typedef struct
{ 
	uint8_t  reason;                          /**< The response of the message.*/
	uint16_t reqNum;                          /**< The number of notification struct that follows.*/
	uint8_t  notificationList[MAX_REQ_NOTIF]; /**< The list of notification structures.*/
} notif_response_t;

/** Response reason of NOTIF_RESPONSE (see ref. SUBSET-137 5.3.13) */
typedef enum
{
	RESP_OK               = 0,
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

/** Notification status of NOTIF_RESPONSE (see ref. SUBSET-137 5.3.13) */
typedef enum
{
	REQ_SUCCESS   = 0,
	UNKNOWN_KEY   = 1,
	MAX_KEY       = 2,
	KEY_EXIST     = 3,
	KEY_CORRUPTED = 4,
	WRONG_ID      = 5
} notif_reason_t;

/** NOTIF_KEY_OPERAION_REQ_RCVD message struct typedef (see ref. SUBSET-137 5.3.16) */
typedef struct
{
	uint16_t maxTime; /**< Maximum time in hours required to respond to the key operation request.*/
} notif_key_op_req_rcvd_t;

/** NOTIF_KEY_DB_CHECKSUM message struct typedef (see ref. SUBSET-137 5.3.17) */
typedef struct
{
	uint8_t checksum[CHECKSUM_SIZE]; /**< The checksum of the KMAC entity's key database.*/
} notif_key_db_checksum_t;

/** Struct holding all of response */
typedef struct
{
	msg_type_t              msgType;           /**< The type of the response.*/
	notif_response_t        notifPayload;      /**< The NOTIF_RESPONSE body.*/
	notif_key_db_checksum_t dbChecksumPayload; /**< The NOTIF_KEY_DB_CHECKSUM body.*/
	notif_key_op_req_rcvd_t keyOpRecvdPayload; /**< The NOTIF_KEY_OPERAION_REQ_RCVD body.*/
} response_t;

#endif /* KMC_MSG_DEFINITIONS_H_ */
