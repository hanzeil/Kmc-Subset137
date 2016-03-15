/**************************************************************************//**
 *
 * TLS wrapper for GnuTLS
 *
 * This file wraps the SS137-TLS-needs in an uniform API. This implementation
 * uses GnuTLS as low-level library. Wrapper tested on:
 * - gnutls 3.4.9
 * - nettle 3.1
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
#include <libgen.h>

#include <gnutls/gnutls.h>
#include <gnutls/x509.h>

#include "utils.h" 
#include "tls_wrapper.h"

/*****************************************************************************
 * DEFINES
 ******************************************************************************/

/** @name TLS tuning parameters
 **@{*/
#define MAX_TLS_DES          (100U)
#define VERIFY_DEPTH         (1U)
/**@}*/

/** Converts seconds in milliseconds */
#define SEC_TO_MSEC(x) ((x)*1000U)

/*****************************************************************************
 * TYPEDEFS
 *****************************************************************************/

/** Struct holding the parameter used in a TLS session */
typedef struct
{
	bool_t  in_use;            /**< If the current descriptor is in use.*/
	int32_t socket;            /**< TCP socket of the current TLS connection.*/
	gnutls_session_t session;  /**< GnuTLS session.*/
} tls_descriptor_t;

/*****************************************************************************
 * VARIABLES
 *****************************************************************************/

/** Priority string for TLS_ECDHE_RSA_WITH_AES_254_GCM_SHA384 */
const char priority_string[] = "NONE:+VERS-TLS1.2:+MAC-ALL:+ECDHE-RSA:+AES-256-GCM:+SIGN-RSA-SHA384:+COMP-NULL:+CTYPE-ALL:+CURVE-ALL";

/** The list of TLS descriptor available */
static tls_descriptor_t tls_descriptors[MAX_TLS_DES];

/** The listen socket of the server side */
static int32_t listen_sock = -1;

/** Structure holding the certificates and keys */
static gnutls_certificate_credentials_t x509_cred;

/** Bool used to identify id the shutdown message has been received by the peer */
static bool_t shutdown_received = 0U;

/*****************************************************************************
 * FUNCTION PROTOTYPES
 *****************************************************************************/

static tls_error_code_t findTLSDes(uint32_t * const tls_id);

static int verifyPeerCallback(gnutls_session_t session);

static tls_error_code_t initTLS(const char* const ca_cert, const char *const key, const char* const cert);

/*****************************************************************************
 * LOCAL FUNCTION DECLARATIONS
 *****************************************************************************/

/**
 * Find a valid TLS descriptor.
 *
 * This fucntion look for a not in use TLS descriptot inside the tls_descriptors array.
 * The function calls the exit() function on any erorr on the addressing of the input parameters.
 */
static tls_error_code_t findTLSDes /** @return TLS_SUCCESS if the descpriptor is found, TLS_ERROR if there is no TLS descriptor available. */
(
	uint32_t * const tls_id /**< [in] TLS desciptor identifier. */
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

/**
 * Initialize the GnuTLS library.
 *
 * This function calls all the function needed to initiliaze the GnuTLS library
 * including the initialization of x509_cred struct used for certificate.
 * The function calls the exit() function on any erorr on the addressing of the input parameters.
 */
static tls_error_code_t initTLS /** @return TLS_SUCCESS if the initialization succeeds, TLS_ERROR in case of error. */
(
	const char* const ca_cert, /**< [in] CA certificate file. */
	const char *const key,     /**< [in] Private key file. */	
	const char* const cert     /**< [in] Certificate file. */    
	)
{
	ASSERT(ca_cert != NULL, E_NULL_POINTER);
	ASSERT(key != NULL, E_NULL_POINTER);
	ASSERT(cert != NULL, E_NULL_POINTER);

	log_print("CA cert:  %s\n", ca_cert);
	log_print("RSA Key:  %s\n", key);
	log_print("RSA Cert: %s\n", cert);
	
	gnutls_global_init();

	 /* Allocate X509 struct */
	gnutls_certificate_allocate_credentials(&x509_cred);

	/* Set the trusted CA file*/
	gnutls_certificate_set_x509_trust_file(x509_cred, ca_cert, GNUTLS_X509_FMT_PEM);

	/* set the callback function used during certificate validation */
	gnutls_certificate_set_verify_function (x509_cred, verifyPeerCallback);

	/* Set local certificate and key*/
	gnutls_certificate_set_x509_key_file (x509_cred, cert, key, GNUTLS_X509_FMT_PEM);

	return(TLS_SUCCESS);

}

/**
 * Verify peer certificate callback.
 *
 * This function is called during the TLS handshake peer certificate verification.
 */
static int verifyPeerCallback /** @return 0 if the peer certificate is valid, GNUTLS_E_CERTIFICATE_ERROR if the peer certificate is not valid. */
(
	gnutls_session_t session /**< [in] GnuTLS session.*/
	)
{
	unsigned int status;

	if (gnutls_certificate_verify_peers2 (session, &status) < 0)
    {
		err_print ("Error on peer certificate\n");
		return(GNUTLS_E_CERTIFICATE_ERROR);
    }

	if (status & GNUTLS_CERT_SIGNER_NOT_FOUND)
	{
		err_print ("The peer certificate hasn't got a known issuer.\n");
		return(GNUTLS_E_CERTIFICATE_ERROR);
	}
	
	if (status & GNUTLS_CERT_REVOKED)
	{
		err_print ("The peer certificate has been revoked.\n");
		return(GNUTLS_E_CERTIFICATE_ERROR);
	}
	
	if (status & GNUTLS_CERT_EXPIRED)
	{
		err_print ("The peer certificate has expired\n");
		return(GNUTLS_E_CERTIFICATE_ERROR);
	}
	
	if (status & GNUTLS_CERT_NOT_ACTIVATED)
	{
		err_print ("The peer certificate is not yet activated\n");
		return(GNUTLS_E_CERTIFICATE_ERROR);
	}
	
	if (status & GNUTLS_CERT_INVALID)
    {
		err_print ("The peer certificate is not trusted.\n");
		return(GNUTLS_E_CERTIFICATE_ERROR);
    }

	log_print("The peer certificate  is valid\n");
	
	return(0);
}

/*****************************************************************************
 * PUBLIC FUNCTION DECLARATIONS
 *****************************************************************************/

/**
 * TLS client init.
 *
 * This function initializes the TLS client side. In particular it opens the TCP socket
 * used to communicate with the server. If the initialization succeeds it returns a valid
 * TLS session identifier.
 * The function calls the exit() function on any erorr on the addressing of the input parameters.
 */
tls_error_code_t initClientTLS /** @return TLS_SUCCESS if the initialization succeeds, TLS_ERROR in case of error. */	
(							                                                                                            
	uint32_t* const tls_id,    /**< [out] The TLS session identifier. */												
	const char* const ca_cert, /**< [in] CA certificate file. */														
	const char *const key,	   /**< [in] Private key file. */															
	const char* const cert	   /**< [in] Certificate file. */                                                           
	)
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

	/* using this function the client will verify the server certificate sending also its own certificate */
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

/**
 * TLS client connect.
 *
 * This function tries to connect to the specified server at the given port and perform
 * the initial TLS handshake, including the certificate verification.
 * The function calls the exit() function on any erorr on the addressing of the input parameters.
 */
tls_error_code_t connectTLS      /** @return TLS_SUCCESS if the connect and handshake succeed, TLS_ERROR in case of error. */ 
(								                                                                                              
	const uint32_t tls_id,       /**< [in] The TLS session identifier. */													  
	const char* const server_ip, /**< [in] The server ip in ASCII format. */												  
	const uint16_t server_port   /**< [in] The server port. */                                                                   
	)
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

	/* Perform the TLS handshake  */
	do
	{
		ret = gnutls_handshake(tls_descriptors[tls_id].session);
	}
	while (ret < 0 && gnutls_error_is_fatal(ret) == 0);
	if (ret < 0)
	{
		err_print("Client TLS Handshake failed\n");
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
	
	type = gnutls_certificate_type_get(tls_descriptors[tls_id].session);

	status = gnutls_session_get_verify_cert_status(tls_descriptors[tls_id].session);

	ret = gnutls_certificate_verification_status_print(status, type, &out, 0);
	if (ret < 0)
	{
		err_print("Peer certificate verification failed.\n");
		return(TLS_ERROR);
	}

	log_print("%s\n", out.data);

	log_print("Client TLS Handshake completed successfully.\n");
	
	gnutls_free(out.data);
	
	return(TLS_SUCCESS);
}

/**
 * TLS server init.
 *
 * This function initializes the TLS server side. In particular it opens the TCP socket
 * used to listen for incoming connections and performs a bind on the local port specified as argument.
 * The function calls the exit() function on any erorr on the addressing of the input parameters.
 */
tls_error_code_t initServerTLS /** @return TLS_SUCCESS if the initialization succeeds, TLS_ERROR in case of error. */	
(							                                                                                            
	const uint16_t l_port,     /**< [in] The local listening port. */													
	const char* const ca_cert, /**< [in] CA certificate file. */														
	const char *const key,	   /**< [in] Private key file. */															
	const char* const cert	   /**< [in] Certificate file. */                                                           
	)
{
	struct sockaddr_in sa_serv;
	
	ASSERT(ca_cert != NULL, E_NULL_POINTER);
	ASSERT(key != NULL, E_NULL_POINTER);
	ASSERT(cert != NULL, E_NULL_POINTER);

	if(initTLS(ca_cert, key, cert) != TLS_SUCCESS)
	{
		err_print("Error during initTLS().\n");
		return(TLS_ERROR);
	}
	
	listen_sock = socket (PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if(listen_sock == -1)
	{
		err_print("Error opening listen socket.\n");
		return(TLS_ERROR);
	}

	memset (&sa_serv, '\0', sizeof(sa_serv));
	sa_serv.sin_family      = AF_INET;
	sa_serv.sin_addr.s_addr = INADDR_ANY;
	sa_serv.sin_port        = htons (l_port);   /* Server Port number */

	if(bind(listen_sock, (struct sockaddr*)&sa_serv, sizeof(sa_serv)) == -1)
	{
		err_print("Error on binding port %d.\n", l_port);
		return(TLS_ERROR);
	}

	if(listen(listen_sock, 5) == -1)
	{
		err_print("Error on listen() call.\n");
		return(TLS_ERROR);
	}

	return(TLS_SUCCESS);
}

/**
 * TLS server accept.
 *
 * This function waits for incoming tls connection and returns when a valid TLS handshake
 * has been performed with a client, including the certificate verification.
 * The function calls the exit() function on any erorr on the addressing of the input parameters.
 */
tls_error_code_t acceptTLS  /** @return TLS_SUCCESS if the accept succeeds, TLS_ERROR in case of error. */ 
(							                                                                               
	uint32_t* const tls_id, /**< [out] The TLS session identifier. */									   
	char* const client_ip   /**< [out] The IP of the connected client in ASCII format. */                  
	)
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
	
	/* require the client certificate, the server will send an certificate request message
	   during TLS handshake. The handshake will return an error if the peer does not provide
	   a certificate.*/
	gnutls_certificate_server_set_request(tls_descriptors[*tls_id].session, GNUTLS_CERT_REQUIRE);
	
	client_len = sizeof(sa_cli);

	/* Wait for an incoming TCP connection. */
	client_sock = accept(listen_sock, (struct sockaddr*)&sa_cli, (socklen_t *)&client_len);
	if(client_sock == -1)
	{
		err_print("Cannot accept connection.\n");
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
		err_print("Server TLS Handshake failed (%s).\n", gnutls_strerror(ret));
		return(TLS_ERROR);
	}

	log_print("Server TLS Handshake completed successfully.\n");
	
	return(TLS_SUCCESS);
}

/**
 * Closes a TLS connection.
 *
 * This function the TLS connection corresponding to the connection identifier passed as argument,
 * releasing the correspondig entry in the tls_descriptors struct.
 */
tls_error_code_t closeTLS  /** @return error code */									 
(						                                                                 
	const uint32_t tls_id  /**< [in] The TLS identifier of the connection to close*/     
	)
{
	ASSERT(tls_id < MAX_TLS_DES, E_INVALID_PARAM);

	log_print("Closing session...\n");

	if(shutdown_received == FALSE)
	{
		gnutls_bye(tls_descriptors[tls_id].session, GNUTLS_SHUT_WR);
	}
	else
	{
		shutdown_received = FALSE;
	}

	gnutls_deinit(tls_descriptors[tls_id].session);
	
	close(tls_descriptors[tls_id].socket);

	tls_descriptors[tls_id].socket = -1;
	tls_descriptors[tls_id].in_use = FALSE;

	log_print("closed\n");
	
	return(TLS_SUCCESS);
}

/**
 * Send a mesasage on a TLS connection already enstablished.
 *
 * The function sends through TLS the message stored in the buf array.
 * It sends the message of size buf_len using the TLS connection identifier
 * specified as argument.
 * 
 * The function calls the exit() function on any erorr on the addressing of the input parameters.
 */
tls_error_code_t sendTLS        /** @return TLS_SUCCESS if the message is correctly sent, TLS_ERROR in case of error. */   
(								                                                                                           
	uint32_t* const bytes_sent, /**< [out] The number of bytes sent.*/     												   
	const uint8_t* const buf,   /**< [in] The pointer to the buffer to be sent.*/     									   
	const uint32_t buf_len,     /**< [in] The buffer length.*/     														   
	const uint32_t tls_id       /**< [in] The TLS session identifier. */                                                   
	)
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

/**
 * Receive a mesasage from a TLS connection already enstablished.
 *
 * The function reads through TLS a message storing it in the area pointed
 * by the buf parameter. The function waits for the time specified as argument
 * and then return if no message has been received.
 * The function calls the exit() function on any erorr on the addressing of the input parameters.
 */
tls_error_code_t receiveTLS          /** @return TLS_SUCCESS if the message is correctly received,			 
									 	 TLS_ERROR in case of error or if the connection goes in timeout. */ 
(									                                                                         
	uint32_t* const bytes_received,  /**< [out] The number of bytes read.*/             					 
	uint8_t* const buf,              /**< [out] The buffer where the data read is stored.*/             	 
	const uint32_t buf_len,          /**< [in] Max bufer length.*/             								 
	const uint8_t timeout,           /**< [in] Receive timeout in seconds.*/             					 
	const uint32_t tls_id            /**< [in] The TLS session identifier. */                                
	)
{
	struct pollfd handles[1];
    const nfds_t n_handles = 1;
	int32_t n_active = -1;
	int32_t tmp_bytes_received = -1;

	ASSERT(tls_id < MAX_TLS_DES, E_INVALID_PARAM);
	ASSERT(bytes_received != NULL, E_NULL_POINTER);
	ASSERT(buf != NULL, E_NULL_POINTER);

	*bytes_received = 0U;
	
    handles[0].fd = tls_descriptors[tls_id].socket;
    handles[0].events = POLLIN;

	n_active = poll(handles, n_handles, SEC_TO_MSEC(timeout));

	if(n_active < 0)
	{
		err_print("poll() error.\n");
		return(TLS_ERROR);
	}
	else if( n_active == 0)
	{
		warning_print("Timeout expired.\n");
		return(TLS_ERROR);
	}
	else
	{
		if ( ( handles[0].revents & POLLERR & POLLHUP & POLLNVAL ) != 0 )
		{
			err_print("poll() error.\n");
			return(TLS_ERROR);
		}
		else if (handles[0].revents & POLLIN)
		{
			tmp_bytes_received = gnutls_record_recv(tls_descriptors[tls_id].session, buf, buf_len);

			if (tmp_bytes_received == 0)
			{
				log_print("Peer has closed the TLS connection.\n");
				shutdown_received = TRUE;
				return(TLS_ERROR);
			}
			else if (tmp_bytes_received < 0 && gnutls_error_is_fatal(*bytes_received) == 0)
			{
				log_print("%s.\n", gnutls_strerror(*bytes_received));
				shutdown_received = TRUE;
				return(TLS_ERROR);
			}
			else if (tmp_bytes_received < 0)
			{
				err_print("%s.\n", gnutls_strerror(*bytes_received));
				return(TLS_ERROR);
			}
		}
	}

	*bytes_received = (uint32_t) tmp_bytes_received;
	
	return(TLS_SUCCESS); 
}

/**
 * Exit GnuTLS library.
 *
 * This function frees all the structure related to GnuTLS library and close the server listen socket
 * if it's called by the TLS server.
 */
tls_error_code_t exitTLS /** @return TLS_SUCCESS if the close operation succeeds, TLS_ERROR in case of error. */
(
	void
	)
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

