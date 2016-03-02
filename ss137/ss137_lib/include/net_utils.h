#ifndef KMC_NET_UTILS_H_
#define KMC_NET_UTILS_H_

/* ------------------------------------------------------------------------------- */
/* d e f i n e   c o n s t a n t s   a n d   m a c r o s                           */
/* ------------------------------------------------------------------------------- */

#define MSG_MAX_SIZE (5000U)

/* ------------------------------------------------------------------------------- */
/* t y p e s                                                                       */
/* ------------------------------------------------------------------------------- */

typedef struct
{
	uint32_t curPos;
	uint32_t validBytes;
	uint8_t  buffer[MSG_MAX_SIZE];
} read_stream_t;

typedef struct
{
	uint32_t  curSize;
	uint8_t   buffer[MSG_MAX_SIZE];
} write_stream_t;


/* ------------------------------------------------------------------------------- */
/* Public Functions Prototypes                                                     */
/* ------------------------------------------------------------------------------- */

int32_t netToHost8(uint8_t* const var, const uint32_t len, read_stream_t* istream);

int32_t netToHost16(uint16_t* const var, read_stream_t* istream);

int32_t netToHost32(uint32_t* const var, read_stream_t* istream);

int32_t hostToNet8(write_stream_t* const ostream, const uint8_t* const var, const uint32_t len);

int32_t hostToNet16(write_stream_t* const ostream, const uint16_t var);

int32_t hostToNet32(write_stream_t* const ostream, const uint32_t var);

int32_t initWriteStream(write_stream_t *const ostream);

int32_t initReadStream(read_stream_t *const istream);


#endif /* KMC_NET_UTILS_H_ */
