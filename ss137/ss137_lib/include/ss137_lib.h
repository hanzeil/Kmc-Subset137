#ifndef KMC_SS137_LIB_H_
#define KMC_SS137_LIB_H_

/* ------------------------------------------------------------------------------- */
/* d e f i n e   c o n s t a n t s   a n d   m a c r o s                           */
/* ------------------------------------------------------------------------------- */

#define INTERFACE_VERSION (2U) /* current supported version */

#define NUM_VERSION       (1U) /* number of supported version */

/* ------------------------------------------------------------------------------- */
/* t y p e s                                                                       */
/* ------------------------------------------------------------------------------- */


typedef struct
{
	uint32_t tls_des;
	uint32_t myTransNum;
	uint32_t mySeqNum;
	uint32_t peerEtcsIDExp;
	uint32_t peerTransNum;
	uint32_t peerSeqNum;
}session_t;


/* ------------------------------------------------------------------------------- */
/* Public Functions Prototypes                                                     */
/* ------------------------------------------------------------------------------- */

int32_t initClientConnection(uint32_t* const tls_des,
							 int32_t* const sock,
							 const char* const r_ip,
							 const uint16_t r_port);

int32_t initServerConnection(uint32_t* const tls_des,
							 int32_t* const client_sock,
							 const uint16_t l_port);

int32_t initAppSession(const uint32_t peerETCSID,
					   session_t* const curr_session);

int32_t endAppSession(session_t* const curr_session);

int32_t sendMsg(write_stream_t* const ostream,
				const uint32_t tls_des);

int32_t receiveMsg(read_stream_t* const istream,
				   const uint32_t tls_des);

#endif /* KMC_SS137_LIB_H_ */
