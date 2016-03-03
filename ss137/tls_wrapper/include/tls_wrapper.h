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

/*****************************************************************************
 * TYPEDEFS
 *****************************************************************************/

/*****************************************************************************
 * PUBLIC FUNCTION PROTOTYPES
 *****************************************************************************/

/* client */
int32_t createClientTLS(int32_t* const sock);

int32_t connectTLS(uint32_t* const tls_des,
				   const int32_t sock,
				   const char* const r_ip,
				   const uint16_t r_port);

/* server */
int32_t createServerTLS(int32_t* const sock,
						const uint16_t l_port);

int32_t acceptTLS(uint32_t* const tls_des,
				  int32_t* const client_sock,
				  const int32_t listen_sock);

/* common */
int32_t closeTLS(const uint32_t tls_des,
				 const int32_t sock);

int32_t sendTLS(uint32_t* const bytes_sent,
				const uint8_t* const buf,
				const uint32_t buf_len,
				const uint32_t tls_des);

int32_t receiveTLS(uint32_t* const bytes_received,
				   uint8_t* const buf,
				   const uint32_t buf_len,
				   const uint32_t tls_des);

int32_t exitTLS(void);

#endif /* KMC_TLS_WRAPPER_H_ */
