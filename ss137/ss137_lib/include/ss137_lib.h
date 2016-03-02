#ifndef KMC_SS137_LIB_H_
#define KMC_SS137_LIB_H_

/* ------------------------------------------------------------------------------- */
/* d e f i n e   c o n s t a n t s   a n d   m a c r o s                           */
/* ------------------------------------------------------------------------------- */

#define MSG_HEADER_SIZE      (4*sizeof(uint32_t) + sizeof(uint16_t) + 2*sizeof(uint8_t))  /* 20 bytes */
#define MSG_PAYLOAD_MAX_SIZE (MSG_MAX_SIZE - MSG_HEADER_SIZE) /* 4980 bytes */

#define K_IDENT_SIZE      (2*sizeof(uint32_t))  /* 8 bytes */
#define K_STRUCT_MIN_SIZE (K_IDENT_SIZE + 3*sizeof(uint32_t) + sizeof(uint16_t) + sizeof(uint8_t) + K_LENGTH*sizeof(uint8_t) ) /* without peer num field */
#define K_STRUCT_MAX_SIZE (K_IDENT_SIZE + 3*sizeof(uint32_t) + sizeof(uint16_t) + sizeof(uint8_t) + K_LENGTH*sizeof(uint8_t) + MAX_PEER_NUM*sizeof(uint32_t))

#define INTERFACE_VERSION (2U) /* current supported version */
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

/* ------------------------------------------------------------------------------- */
/* t y p e s                                                                       */
/* ------------------------------------------------------------------------------- */

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
} MSG_TYPE;

typedef enum
{
	NEW_TRAIN    = 0,
	MOD_AREA     = 1,
	RED_SCHED    = 2,
	APPR_END_VAL = 3
} REQ_KEY_OP;

typedef enum
{
	KEY_INST  = 1,
	KEY_UP    = 2,
	KEY_DEL   = 3
} K_STATUS;

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
} RESPONSE_REASON;

typedef enum
{
	REQ_SUCCESS   = 0,
	UNKNOWN_KEY   = 1,
	MAX_KEY       = 2,
	KEY_EXIST     = 3,
	KEY_CORRUPTED = 4,
	WRONG_ID      = 5
} NOTIFY_REASON;


typedef struct
{
	bool_t   used;
	uint32_t myTransNum;
	uint32_t mySeqNum;
	uint32_t peerEtcsIDExp;
	uint32_t peerTransNum;
	uint32_t peerSeqNum;
	uint32_t ssl_des;
}session_t;


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


/* ------------------------------------------------------------------------------- */
/* Public Functions Prototypes                                                     */
/* ------------------------------------------------------------------------------- */

int32_t initSession(session_t* const curr_session,
					const uint32_t peer_etcs_id_exp);

int32_t buildNotifSessionInit(write_stream_t* const ostream,
							  const uint8_t app_timeout);

int32_t sendMsg(write_stream_t* const ostream, const session_t * const curr_session);

/* istream shall be already initialized */
int32_t receiveMsg(read_stream_t* const istream, const session_t * const curr_session);


int32_t buildCmdAddKeys(write_stream_t* const ostream,
						const uint16_t req_num,
						const k_struct_t* const k_struct_list);

int32_t buildCmdDeleteKeys(write_stream_t* const ostream,
						   const uint16_t req_num,
						   const k_ident_t* const k_ident);
								 
int32_t buildCmdUpKeyValidities(write_stream_t* const ostream,
								const uint16_t req_num,
								const k_validity_t* const k_validity_list);

int32_t buildCmdUpKeyEntities(write_stream_t* const ostream,
							  const uint16_t req_num,
							  const k_entity_t* const k_entity_list);

int32_t buildCmdReqKeyOperation(write_stream_t* const ostream,
								const uint32_t etcs_id_mod,
								const uint8_t reason,
								const uint32_t startValidity,
								const uint32_t endValidity,
								const char *const text);


int32_t buildNotifKeyUpdateStatus(write_stream_t* const ostream,
								  const k_ident_t* const k_ident,
								  const uint8_t k_status);

int32_t buildNotifSessionInit(write_stream_t* const ostream,
							  const uint8_t app_timeout);

int32_t buildNotifResponse(write_stream_t* const ostream,
						   const uint8_t response,
						   const uint16_t req_num,
						   const uint8_t* const notification_list);


int32_t buildNotifKeyOpReqRcvd(write_stream_t* const ostream,
							   const uint16_t max_time);

int32_t buildNotifKeyDBChecksum(write_stream_t* const ostream,
								const uint8_t* const checksum);


#endif /* KMC_SS137_LIB_H_ */
