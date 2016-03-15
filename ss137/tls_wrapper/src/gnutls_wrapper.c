/**************************************************************************//**
 *
 * TLS wrapper for GnuTLS
 *
 * This file wraps the SS137-TLS-needs in an uniform API. This implementation
 * uses GnuTLS as low-level library
 *
 * @file: ss137/tls_wrapper/src/gnutls_wrapper.c
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

#include <stdint.h>
#include <unistd.h>
#include <poll.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <gnutls/gnutls.h>
#include <gnutls/x509.h>

#include "utils.h" 
#include "tls_wrapper.h"

/*****************************************************************************
 * DEFINES
 ******************************************************************************/

/** @name SSL tuning
 **@{*/
#define MAX_TLS_DES          (100U)
#define VERIFY_DEPTH         (1U)
/**@}*/

#define SEC_TO_MSEC(x) ((x)*1000U)

/*****************************************************************************
 * TYPEDEFS
 *****************************************************************************/

typedef struct
{
	bool_t  in_use;
	int32_t socket;
	gnutls_session_t session;
} tls_descriptor_t;

/*****************************************************************************
 * VARIABLES
 *****************************************************************************/

const char priority_string[] = "NONE:+VERS-TLS1.2:+MAC-ALL:+ECDHE-RSA:+AES-256-GCM:+SIGN-RSA-SHA384:+COMP-NULL:+CTYPE-ALL:+CURVE-ALL";

static tls_descriptor_t tls_descriptors[MAX_TLS_DES];

static int32_t listen_sock = -1;

static gnutls_certificate_credentials_t x509_cred;

/*****************************************************************************
 * FUNCTION PROTOTYPES
 *****************************************************************************/

static tls_error_code_t findTLSDes(uint32_t * const tls_id);

static tls_error_code_t initTLS(const char* const ca_cert, const char *const key, const char* const cert);

/*****************************************************************************
 * LOCAL FUNCTION DECLARATIONS
 *****************************************************************************/

/**
 * Some useful Doxygen comment findTLSDes
 */
static tls_error_code_t findTLSDes
(
	uint32_t * const tls_id /**< [in] TLS context */
	)
{
	uint32_t i = 0U;
	bool_t found = FALSE;

	ASSERT(tls_id != NULL, E_NULL_POINTER);

	for(i = 0U; i < MAX_TLS_DES; i++)
	{
		if(tls_descriptors[i].in_use == FALSE)
		{
			tls_descriptors[i].in_use = TRUE;
			*tls_id = i;
			found = TRUE;
			break;
		}
	}

	if(found == FALSE)
	{
		err_print("No valid tls descriptor.\n");
		return(TLS_ERROR);
	}

	return(TLS_SUCCESS);
}

static tls_error_code_t initTLS(const char* const ca_cert,
								const char *const key,
								const char* const cert)
{
	ASSERT(ca_cert != NULL, E_NULL_POINTER);
	ASSERT(key != NULL, E_NULL_POINTER);
	ASSERT(cert != NULL, E_NULL_POINTER);

	log_print("CA cert:  %s\n", ca_cert);
	log_print("RSA Key:  %s\n", key);
	log_print("RSA Cert: %s\n", cert);
	
	/* for backwards compatibility with gnutls < 3.3.0 */
	gnutls_global_init();

	 /* X509 stuff */
	gnutls_certificate_allocate_credentials(&x509_cred);

	/* sets the trusted CA file*/
	gnutls_certificate_set_x509_trust_file(x509_cred, ca_cert, GNUTLS_X509_FMT_PEM);

	/* Set local certificate and key*/
	gnutls_certificate_set_x509_key_file (x509_cred, cert, key, GNUTLS_X509_FMT_PEM);

	return(TLS_SUCCESS);

}


static tls_error_code_t verifyPeer(gnutls_session_t session)
{
	unsigned int status;

	if (gnutls_certificate_verify_peers2 (session, &status) < 0)
    {
		err_print ("Error on peer certificate\n");
		return(TLS_ERROR);
    }

	if (status & GNUTLS_CERT_SIGNER_NOT_FOUND)
	{
		err_print ("The certificate hasn't got a known issuer.\n");
		return(TLS_ERROR);
	}
	
	if (status & GNUTLS_CERT_REVOKED)
	{
		err_print ("The certificate has been revoked.\n");
		return(TLS_ERROR);
	}
	
	if (status & GNUTLS_CERT_EXPIRED)
	{
		err_print ("The certificate has expired\n");
		return(TLS_ERROR);
	}
	
	if (status & GNUTLS_CERT_NOT_ACTIVATED)
	{
		err_print ("The certificate is not yet activated\n");
		return(TLS_ERROR);
	}
	
	if (status & GNUTLS_CERT_INVALID)
    {
		err_print ("The certificate is not trusted.\n");
		return GNUTLS_E_CERTIFICATE_ERROR;
    }

	log_print("The peer's certificate is valid\n");
	return(TLS_SUCCESS);
}

/*****************************************************************************
 * PUBLIC FUNCTION DECLARATIONS
 *****************************************************************************/

/* client */
tls_error_code_t initClientTLS(uint32_t* const tls_id,
							   const char* const ca_cert,
							   const char *const key,
							   const char* const cert)
{
	int32_t tmp_sock = -1;
	gnutls_priority_t priority_cache;

	ASSERT(ca_cert != NULL, E_NULL_POINTER);
	ASSERT(key != NULL, E_NULL_POINTER);
	ASSERT(cert != NULL, E_NULL_POINTER);
	ASSERT(tls_id != NULL, E_NULL_POINTER);

	if(initTLS(ca_cert, key, cert) != TLS_SUCCESS)
	{
		return(TLS_ERROR);
	}

	if(gnutls_init(&tls_descriptors[*tls_id].session, GNUTLS_CLIENT) != GNUTLS_E_SUCCESS)
	{
		return(TLS_ERROR);
	}
	
	if(findTLSDes(tls_id) != TLS_SUCCESS)
	{
		return(TLS_ERROR);
	}

	if(gnutls_priority_init(&priority_cache, priority_string, NULL) != GNUTLS_E_SUCCESS)
	{
		return(TLS_ERROR);
	}
	
	if(gnutls_priority_set(tls_descriptors[*tls_id].session, priority_cache) != GNUTLS_E_SUCCESS)
	{
		return(TLS_ERROR);
	}
	
	if(gnutls_credentials_set(tls_descriptors[*tls_id].session, GNUTLS_CRD_CERTIFICATE, x509_cred) != GNUTLS_E_SUCCESS)
	{
		return(TLS_ERROR);
	}
	
	gnutls_session_set_verify_cert(tls_descriptors[*tls_id].session, NULL, 0);
	
	tmp_sock = socket (PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if(tmp_sock == -1)
	{
		err_print("Error opening socket\n");
		return(TLS_ERROR);
	}

	tls_descriptors[*tls_id].socket = tmp_sock;

	return(TLS_SUCCESS);
}

tls_error_code_t connectTLS(const uint32_t tls_id,
							const char* const server_ip,
							const uint16_t server_port)
{
	struct sockaddr_in server_addr;
	int32_t ret;
	uint8_t status = 1;
	int32_t type;
	gnutls_datum_t out;
		
	ASSERT(tls_id < MAX_TLS_DES, E_INVALID_PARAM);
	ASSERT(server_ip != NULL, E_NULL_POINTER);

	memset (&server_addr, '\0', sizeof(server_addr));
	server_addr.sin_family      = AF_INET;
 	server_addr.sin_port        = htons(server_port);     /* Server Port number */
	server_addr.sin_addr.s_addr = inet_addr(server_ip);   /* Server IP */

	/* Establish a TCP/IP connection to the TLS client */
	if(connect(tls_descriptors[tls_id].socket, (struct sockaddr*) &server_addr, sizeof(server_addr)) == -1)
	{
		err_print("Error on connect to server (%s:%d)\n", server_ip, server_port);
		return(TLS_ERROR);
	}

	gnutls_transport_set_int(tls_descriptors[tls_id].session, tls_descriptors[tls_id].socket);

	gnutls_handshake_set_timeout(tls_descriptors[tls_id].session, GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);

	/* Perform the TLS handshake     */
	do
	{
		ret = gnutls_handshake(tls_descriptors[tls_id].session);
	}
	while (ret < 0 && gnutls_error_is_fatal(ret) == 0);
	if (ret < 0)
	{
		err_print("*** TLS Handshake failed\n");
		gnutls_perror(ret);
		return(TLS_ERROR);
	}
	else
	{
		char *desc = NULL;
		desc = gnutls_session_get_desc(tls_descriptors[tls_id].session);
		log_print("Session info: %s\n", desc);
		gnutls_free(desc);
	}
	
	verifyPeer(tls_descriptors[tls_id].session);
	
	type = gnutls_certificate_type_get(tls_descriptors[tls_id].session);

	status = gnutls_session_get_verify_cert_status(tls_descriptors[tls_id].session);

	ret = gnutls_certificate_verification_status_print(status, type, &out, 0);
	if (ret < 0)
	{
		err_print("Peer certificate verification failed\n");
		return(TLS_ERROR);
	}

	log_print("%s\n", out.data);
	gnutls_free(out.data);
	
	return(TLS_SUCCESS);
}

/* server */
tls_error_code_t initServerTLS(const uint16_t l_port,
							   const char* const ca_cert,
							   const char *const key,
							   const char* const cert)
{
	struct sockaddr_in sa_serv;
	
	ASSERT(ca_cert != NULL, E_NULL_POINTER);
	ASSERT(key != NULL, E_NULL_POINTER);
	ASSERT(cert != NULL, E_NULL_POINTER);

	if(initTLS(ca_cert, key, cert) != TLS_SUCCESS)
	{
		err_print("Error during initTLS()\n");
		return(TLS_ERROR);
	}
	
	listen_sock = socket (PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if(listen_sock == -1)
	{
		err_print("Error opening listen socket\n");
		return(TLS_ERROR);
	}

	memset (&sa_serv, '\0', sizeof(sa_serv));
	sa_serv.sin_family      = AF_INET;
	sa_serv.sin_addr.s_addr = INADDR_ANY;
	sa_serv.sin_port        = htons (l_port);   /* Server Port number */

	if(bind(listen_sock, (struct sockaddr*)&sa_serv, sizeof(sa_serv)) == -1)
	{
		err_print("Error on binding() port %d\n", l_port);
		return(TLS_ERROR);
	}

	if(listen(listen_sock, 5) == -1)
	{
		err_print("Error on listen() call\n");
		return(TLS_ERROR);
	}

	return(TLS_SUCCESS);
}

tls_error_code_t acceptTLS(uint32_t* const tls_id,
						   char* const client_ip)
{
	struct sockaddr_in sa_cli;
	int32_t  client_len = 0;
	int32_t client_sock = -1;
	int32_t ret = -1;
	gnutls_priority_t priority_cache;
		
	ASSERT(tls_id != NULL, E_NULL_POINTER);
	ASSERT(client_ip != NULL, E_NULL_POINTER);

	if(findTLSDes(tls_id) != TLS_SUCCESS)
	{
		return(TLS_ERROR);
	}

	gnutls_init(&tls_descriptors[*tls_id].session, GNUTLS_SERVER);
	
	gnutls_priority_init(&priority_cache, priority_string, NULL);
	
	gnutls_priority_set(tls_descriptors[*tls_id].session, priority_cache);
	
	gnutls_credentials_set(tls_descriptors[*tls_id].session, GNUTLS_CRD_CERTIFICATE,  x509_cred);
	
	/* require the client certificate, the server will return an error if the peer does not provide a certificate */
	gnutls_certificate_server_set_request(tls_descriptors[*tls_id].session, GNUTLS_CERT_REQUIRE);
	
	client_len = sizeof(sa_cli);

	/* Wait for an incoming TCP connection. */
	client_sock = accept(listen_sock, (struct sockaddr*)&sa_cli, (socklen_t *)&client_len);
	if(client_sock == -1)
	{
		err_print("Cannot accept connection\n");
		return(TLS_ERROR);
	}
	
	sprintf(client_ip,"%d.%d.%d.%d", (sa_cli.sin_addr.s_addr & 0xFF),
			(sa_cli.sin_addr.s_addr >> 8 & 0xFF),
			(sa_cli.sin_addr.s_addr >> 16 & 0xFF),
			(sa_cli.sin_addr.s_addr >> 24 & 0xFF));
	
	tls_descriptors[*tls_id].socket = client_sock;

	gnutls_transport_set_int(tls_descriptors[*tls_id].session, tls_descriptors[*tls_id].socket);
	
	do {
		ret = gnutls_handshake(tls_descriptors[*tls_id].session);
	}
	while (ret < 0 && gnutls_error_is_fatal(ret) == 0);
	
	if (ret < 0)
	{
		err_print("TLS Handshake failed (%s)\n\n", gnutls_strerror(ret));
		return(TLS_ERROR);
	}

	verifyPeer(tls_descriptors[*tls_id].session);
	
	log_print("TLS Handshake completed\n");
	
	return(TLS_SUCCESS);
}

tls_error_code_t closeTLS(const uint32_t tls_id)
{
	ASSERT(tls_id < MAX_TLS_DES, E_INVALID_PARAM);

	gnutls_bye(tls_descriptors[tls_id].session, GNUTLS_SHUT_RDWR);

	gnutls_deinit(tls_descriptors[tls_id].session);

	close(tls_descriptors[tls_id].socket);

	tls_descriptors[tls_id].socket = -1;
	tls_descriptors[tls_id].in_use = FALSE;

	return(TLS_SUCCESS);
}

tls_error_code_t sendTLS(uint32_t* const bytes_sent,
						 const uint8_t* const buf,
						 const uint32_t buf_len,
						 const uint32_t tls_id)
{
	ASSERT(tls_id < MAX_TLS_DES, E_INVALID_PARAM);
	ASSERT(bytes_sent != NULL, E_NULL_POINTER);
	ASSERT(buf != NULL, E_NULL_POINTER);
	
	*bytes_sent = gnutls_record_send(tls_descriptors[tls_id].session, buf, buf_len);

	if(*bytes_sent <= 0)
	{
		return(TLS_ERROR);
	}

	return(TLS_SUCCESS);
}

tls_error_code_t receiveTLS(uint32_t* const bytes_received,
							uint8_t* const buf,
							const uint32_t buf_len,
							const uint8_t timeout,
							const uint32_t tls_id)
{
	struct pollfd handles[1];
    const nfds_t n_handles = 1;
	int32_t n_active = -1;

	ASSERT(tls_id < MAX_TLS_DES, E_INVALID_PARAM);
	ASSERT(bytes_received != NULL, E_NULL_POINTER);
	ASSERT(buf != NULL, E_NULL_POINTER);

    handles[0].fd = tls_descriptors[tls_id].socket;
    handles[0].events = POLLIN;

	n_active = poll(handles, n_handles, SEC_TO_MSEC(timeout));

	if(n_active < 0)
	{
		err_print("poll() error\n");
		return(TLS_ERROR);
	}
	else if( n_active == 0)
	{
		warning_print("Timeout expired\n");
		return(TLS_ERROR);
	}
	else
	{
		if ( ( handles[0].revents & POLLERR & POLLHUP & POLLNVAL ) != 0 )
		{
			err_print("poll() error\n");
			return(TLS_ERROR);
		}
		else if (handles[0].revents & POLLIN)
		{
			*bytes_received = gnutls_record_recv(tls_descriptors[tls_id].session, buf, buf_len);

			if (*bytes_received == 0)
			{
				log_print("Peer has closed the TLS connection\n");
				return(TLS_ERROR);
			}
			else if (*bytes_received < 0 && gnutls_error_is_fatal(*bytes_received) == 0)
			{
				log_print("%s\n", gnutls_strerror(*bytes_received));
			}
			else if (*bytes_received < 0)
			{
				err_print("%s\n", gnutls_strerror(*bytes_received));
				return(TLS_ERROR);
			}
		}
	}
	
	return(TLS_SUCCESS);
}

tls_error_code_t exitTLS(void)
{

	gnutls_certificate_free_credentials(x509_cred);
	
	gnutls_global_deinit();

	/* only the server side has a
	   listen_sock to close */
	if(listen_sock != -1)
	{
		close(listen_sock);
	}
	
	return(TLS_SUCCESS);
}

