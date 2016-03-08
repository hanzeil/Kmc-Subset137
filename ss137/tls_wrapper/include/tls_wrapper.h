/**************************************************************************//**
 *
 * ...
 *
 * This file ...
 *
 * @file: ss137/tls_wrapper/include/tls_wrapper.h
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

#ifndef KMC_TLS_WRAPPER_H_
#define KMC_TLS_WRAPPER_H_

/*****************************************************************************
* DEFINES
******************************************************************************/

#define TIME_TO_MSEC(x) (x*1000U)

/*****************************************************************************
 * TYPEDEFS
 *****************************************************************************/

typedef uint32_t tls_des_t;

typedef enum
{
	TLS_SUCCESS = 0,
	TLS_ERROR   = 1,
	TLS_TIMEOUT = 2
}tls_error_code_t;

/*****************************************************************************
 * PUBLIC FUNCTION PROTOTYPES
 *****************************************************************************/

/* client */
tls_error_code_t initClientTLS(tls_des_t* const tls_id);

tls_error_code_t connectTLS(const tls_des_t tls_id,
				   const char* const r_ip,
				   const uint16_t r_port);
	
/* server */
tls_error_code_t initServerTLS(const uint16_t l_port);

tls_error_code_t acceptTLS(tls_des_t* const tls_id);

/* common */
tls_error_code_t closeTLS(const tls_des_t tls_id);

tls_error_code_t sendTLS(uint32_t* const bytes_sent,
				const uint8_t* const buf,
				const uint32_t buf_len,
				const tls_des_t tls_id);

tls_error_code_t receiveTLS(uint32_t* const bytes_received,
							uint8_t* const buf,
							const uint32_t buf_len,
							const uint8_t timeout,
							const tls_des_t tls_id);

tls_error_code_t exitTLS(void);

#endif /* KMC_TLS_WRAPPER_H_ */
