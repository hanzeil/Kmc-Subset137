/*
 *
 * Copyright (C) 2016 Neat S.r.l.
 *
 * This file is part of Kmc-Subset137.
 *
 * Kmc-Subset137 is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Kmc-Subset137 is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

/**************************************************************************//**
 *
 * TLS Wrapper header files as needed by Kmc-Subset137 project.
 *
 * This file contains the function prototype of TLS Wrapper as needed by 
 * Kmc-Subset137 project.
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

/** tls_wrapper return code */
typedef enum
{
	TLS_SUCCESS = 0,
	TLS_ERROR   = 1
} tls_error_code_t;

/*****************************************************************************
 * PUBLIC FUNCTION PROTOTYPES
 *****************************************************************************/

/* client */
tls_error_code_t initClientTLS(uint32_t* const tls_id,
						   const char* const ca_cert,
						   const char *const key,
						   const char* const cert);

tls_error_code_t connectTLS(const uint32_t tls_id,
						const char* const server_ip,
						const uint16_t remote_port);
	
/* server */
tls_error_code_t initServerTLS(const uint16_t l_port,
						   const char* const ca_cert,
						   const char *const key,
						   const char* const cert);

tls_error_code_t acceptTLS(uint32_t* const tls_id,
					   char* const client_ip);

/* common */
tls_error_code_t closeTLS(const uint32_t tls_id);

tls_error_code_t sendTLS(uint32_t* const bytes_sent,
					 const uint8_t* const buf,
					 const uint32_t buf_len,
					 const uint32_t tls_id);

tls_error_code_t receiveTLS(uint32_t* const bytes_received,
						uint8_t* const buf,
						const uint32_t buf_len,
						const uint8_t timeout,
						const uint32_t tls_id);

tls_error_code_t exitTLS(void);

#endif /* KMC_TLS_WRAPPER_H_ */
