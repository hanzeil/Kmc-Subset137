/**************************************************************************//**
																			 *
																			 * TLS wrapper for OpenSSL
																			 *
																			 * This file wraps the SS137-TLS-needs in an uniform API. This implementation
																			 * uses OpenSSL as low-level library
																			 *
																			 * @file: ss137/tls_wrapper/src/tls_wrapper.c
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

#include <arpa/inet.h>
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "common.h" 
#include "tls_wrapper.h"


/*****************************************************************************
 * DEFINES
 ******************************************************************************/

/** @name RSA-related pathnames
 **@{*/
#define RSA_CLIENT_CERT       "newcert.pem"                      /**< RSA Client Certificate pathname */
#define RSA_CLIENT_KEY        "newkey.pem"                       /**< RSA Client Key pathname */
#define RSA_CLIENT_CA_PATH    "./demoCA"                         /**< RSA Client root CA Certificate path */
#define RSA_CLIENT_CA_CERT    RSA_CLIENT_CA_PATH "/cacert.pem"   /**< RSA Client root CA Certificate full pathname */
/**@}*/


/** @name SSL tuning
 **@{*/
#define MAX_TLS_DES          (100U)
#define VERIFY_DEPTH         (1U)
/**@}*/


/*****************************************************************************
 * TYPEDEFS
 *****************************************************************************/

typedef struct
{
	bool_t  in_use;
	int32_t socket;
	SSL    *ssl_ptr;
} tls_descriptor_t;

/*****************************************************************************
 * VARIABLES
 *****************************************************************************/

/** List of ciphers. String is colon-separated i.e. "CIPHERA:CIPHERB:CIPHERC" */
const char allowed_ciphers[] = "AES256-GCM-SHA384"; 

static SSL_CTX *ctx = NULL;

static tls_descriptor_t tls_descriptors[MAX_TLS_DES];

static int32_t listen_sock = -1;

/*****************************************************************************
 * FUNCTION PROTOTYPES
 *****************************************************************************/

/**
 * Some useful Doxygen comment for getPeerCertificate
 */
static int32_t getPeerCertificate(SSL* ssl);

/**
 * Some useful Doxygen comment for initTLS
 */
static int32_t initTLS(void);

/**
 * Some useful Doxygen comment findTLSDes
 */
static int32_t findTLSDes(uint32_t * const tls_id);

/*****************************************************************************
 * LOCAL FUNCTION DECLARATIONS
 *****************************************************************************/

/**
 * Some useful Doxygen comment findTLSDes
 */
static int32_t findTLSDes
(
	uint32_t * const tls_id /**< [in] SSL context */
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
		return(E_TLS_ERROR);
	}

	return(RETURN_SUCCESS);
}

/**
 * Some useful Doxygen comment getPeerCertificate
 */
static int32_t getPeerCertificate
(
	SSL* ssl /**< [in] SSL context */
	)
{
	char *str;
	X509 *peer_cert;

	ASSERT(ssl != NULL, E_NULL_POINTER);
	
	peer_cert = SSL_get_peer_certificate (ssl);    
	
	if (peer_cert != NULL)
	{
		debug_print("Peer certificate\n");
		
		str = X509_NAME_oneline(X509_get_subject_name(peer_cert),0,0);
		debug_print("\t subject: %s\n", str);
		free (str);
		
		str = X509_NAME_oneline(X509_get_issuer_name(peer_cert),0,0);
		debug_print("\t issuer: %s\n", str);
		free(str);
		
		X509_free (peer_cert);
	}
	else
	{
		err_print("The SSL peer does not have certificate.\n");
	}
	
	return(0);
}

static int32_t initTLS(void)
{
	const SSL_METHOD * meth = NULL;

	/* Load encryption & hashing algorithms for the SSL program */
	SSL_library_init();
 
    /* Load the error strings */
	SSL_load_error_strings();
 
	/* Create an SSL_METHOD structure for TLSv1.2 */
	meth = TLSv1_2_method();
	if( meth == NULL )
	{
		ERR_print_errors_fp(stderr);
		return(E_TLS_ERROR);
	}
	
	/* Create an SSL_CTX structure */
	ctx = SSL_CTX_new(meth);
	if( meth == NULL )
	{
		ERR_print_errors_fp(stderr);
		return(E_TLS_ERROR);
	}
 
	/* Load the client certificate into the SSL_CTX structure */
	if(!SSL_CTX_use_certificate_file(ctx, RSA_CLIENT_CERT, SSL_FILETYPE_PEM))
	{
		ERR_print_errors_fp(stderr);
		return(E_TLS_ERROR);
	}
	
	/* Load the private-key corresponding to the client certificate */
	if(!SSL_CTX_use_PrivateKey_file(ctx, RSA_CLIENT_KEY, SSL_FILETYPE_PEM))
	{
		ERR_print_errors_fp(stderr);
		return(E_TLS_ERROR);
	}
	
	/* Check if the client certificate and private-key matches */
	if (!SSL_CTX_check_private_key(ctx))
	{
		ERR_print_errors_fp(stderr);
		return(E_TLS_ERROR);
	}
 
	/* Load the RSA CA certificate into the SSL_CTX structure */
	/* This will allow  to verify the peer's     */
	/* certificate.                                           */
	if(!SSL_CTX_load_verify_locations(ctx, RSA_CLIENT_CA_CERT, NULL))
	{
		ERR_print_errors_fp(stderr);
		return(E_TLS_ERROR);
	}
 
	/* Set flag in context to require peer certificate */
	/* verification */
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

	/* set the verify depth*/
	SSL_CTX_set_verify_depth(ctx,VERIFY_DEPTH);

	return(RETURN_SUCCESS);

}

/*****************************************************************************
 * PUBLIC FUNCTION DECLARATIONS
 *****************************************************************************/

/* client */
int32_t initClientTLS(uint32_t* const tls_id)
{
	int32_t tmp_sock = -1;

	ASSERT(tls_id != NULL, E_NULL_POINTER);

	if(initTLS() != RETURN_SUCCESS)
	{
		err_print("Error during initTLS()\n");
		return(E_TLS_ERROR);
	}

	/* TBD add error check */
	findTLSDes(tls_id);
	
	tmp_sock = socket (PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if(tmp_sock == -1)
	{
		err_print("Error opening socket\n");
		return(E_TLS_ERROR);
	}

	tls_descriptors[*tls_id].socket = tmp_sock;

	return(RETURN_SUCCESS);
}

int32_t connectTLS(const uint32_t tls_id, const char* const r_ip, const uint16_t r_port)
{
	struct sockaddr_in server_addr;
	SSL* ssl = NULL;

	ASSERT(tls_id < MAX_TLS_DES, E_INVALID_PARAM);
	ASSERT(r_ip != NULL, E_NULL_POINTER);
	
	memset (&server_addr, '\0', sizeof(server_addr));
	server_addr.sin_family      = AF_INET;
 	server_addr.sin_port        = htons(r_port);       /* Server Port number */
	server_addr.sin_addr.s_addr = inet_addr(r_ip); /* Server IP */

	/* Establish a TCP/IP connection to the SSL client */
	if(connect(tls_descriptors[tls_id].socket, (struct sockaddr*) &server_addr, sizeof(server_addr)) == -1)
	{
		err_print("Error on connect to server (%s:%d)\n", r_ip, r_port);
		return(E_TLS_ERROR);
	}

	ssl = SSL_new (ctx);
	if(ssl == NULL)
	{
		ERR_print_errors_fp(stderr);
		return(E_TLS_ERROR);
	}

	if(!SSL_set_cipher_list(ssl, allowed_ciphers))
	{
		ERR_print_errors_fp(stderr);
		return(E_TLS_ERROR);
	}
 
	/* Assign the socket into the SSL structure (SSL and socket without BIO) */
	if(!SSL_set_fd(ssl, tls_descriptors[tls_id].socket))
	{
		ERR_print_errors_fp(stderr);
		return(E_TLS_ERROR);
	}

	/* Perform SSL Handshake on the SSL client */
	if(!SSL_connect(ssl))
	{
		ERR_print_errors_fp(stderr);
		return(E_TLS_ERROR);
	}

	/* TBD add check on cipher ???*/
	debug_print("SSL connection using %s\n", SSL_get_cipher (ssl));

	tls_descriptors[tls_id].ssl_ptr = ssl;

	getPeerCertificate(ssl);
		
	return(RETURN_SUCCESS);
}

/* server */
int32_t initServerTLS(uint32_t* const tls_id, const uint16_t l_port)
{
	struct sockaddr_in sa_serv;

	ASSERT(tls_id != NULL, E_NULL_POINTER);
		
	if(initTLS() != RETURN_SUCCESS)
	{
		err_print("Error during initTLS()\n");
		return(E_TLS_ERROR);
	}
	
	listen_sock = socket (PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if(listen_sock == -1)
	{
		err_print("Error opening socket\n");
		return(E_TLS_ERROR);
	}

	memset (&sa_serv, '\0', sizeof(sa_serv));
	sa_serv.sin_family      = AF_INET;
	sa_serv.sin_addr.s_addr = INADDR_ANY;
	sa_serv.sin_port        = htons (l_port);   /* Server Port number */

	if(bind(listen_sock, (struct sockaddr*)&sa_serv, sizeof(sa_serv)) == -1)
	{
		err_print("Error on binding port %d\n", l_port);
		return(E_TLS_ERROR);
	}

	if(listen(listen_sock, 5) == -1)
	{
		err_print("Error on listen call\n");
		return(E_TLS_ERROR);
	}

	findTLSDes(tls_id);

	return(RETURN_SUCCESS);
}

int32_t acceptTLS(const uint32_t tls_id)
{
	struct sockaddr_in sa_cli;
	int32_t  client_len = 0;
	int32_t client_sock = -1;
		
	SSL *ssl = NULL;

	ASSERT(tls_id < MAX_TLS_DES, E_INVALID_PARAM);

	client_len = sizeof(sa_cli);

	/* Wait for an incoming TCP connection. */
	/* Socket for a TCP/IP connection is created */
	client_sock = accept(listen_sock, (struct sockaddr*)&sa_cli, (socklen_t *)&client_len);
	if(client_sock == -1)
	{
		err_print("Cannot accept connection\n");
		return(E_TLS_ERROR);
	}

	debug_print("Connection from %d.%d.%d.%d, port %d\n",
				(sa_cli.sin_addr.s_addr) & (0xFF),
				(sa_cli.sin_addr.s_addr >> 8) & (0xFF),
				(sa_cli.sin_addr.s_addr >> 16) & (0xFF),
				(sa_cli.sin_addr.s_addr >> 24) & (0xFF),
				sa_cli.sin_port);

	ssl = SSL_new(ctx);
	if(ssl == NULL)
	{
		ERR_print_errors_fp(stderr);
		return(E_TLS_ERROR);
	}

 	if(!SSL_set_cipher_list(ssl, allowed_ciphers))
	{
		ERR_print_errors_fp(stderr);
		return(E_TLS_ERROR);
	}
 
	/* Assign the socket into the SSL structure (SSL and socket without BIO) */
	if(!SSL_set_fd(ssl, client_sock))
	{
		ERR_print_errors_fp(stderr);
		return(E_TLS_ERROR);
	}

	/* Perform SSL Handshake on the SSL server */
	if(!SSL_accept(ssl))
 	{
		ERR_print_errors_fp(stderr);
		return(E_TLS_ERROR);
	}

	getPeerCertificate(ssl);

	tls_descriptors[tls_id].ssl_ptr = ssl;
	tls_descriptors[tls_id].socket = client_sock;

	return(RETURN_SUCCESS);
}

int32_t closeTLS(const uint32_t tls_id)
{
	ASSERT(tls_id < MAX_TLS_DES, E_INVALID_PARAM);
	
	if(!SSL_shutdown(tls_descriptors[tls_id].ssl_ptr))
 	{
		ERR_print_errors_fp(stderr);
		return(E_TLS_ERROR);
	}

	/* Free the SSL structure
	   and close the socket*/
	SSL_free(tls_descriptors[tls_id].ssl_ptr);
	close(tls_descriptors[tls_id].socket);

	tls_descriptors[tls_id].socket = -1;
	tls_descriptors[tls_id].ssl_ptr = NULL;
	tls_descriptors[tls_id].in_use = FALSE;

	return(RETURN_SUCCESS);
}

int32_t sendTLS(uint32_t* const bytes_sent,
				const uint8_t* const buf,
				const uint32_t buf_len,
				const uint32_t tls_id)
{
	ASSERT(tls_id < MAX_TLS_DES, E_INVALID_PARAM);
	ASSERT(bytes_sent != NULL, E_NULL_POINTER);
	ASSERT(buf != NULL, E_NULL_POINTER);
	
	*bytes_sent = SSL_write(tls_descriptors[tls_id].ssl_ptr, buf, buf_len);

	return(RETURN_SUCCESS);
}

int32_t receiveTLS(uint32_t* const bytes_received,
				   uint8_t* const buf,
				   const uint32_t buf_len,
				   const uint32_t tls_id)
{
	ASSERT(tls_id < MAX_TLS_DES, E_INVALID_PARAM);
	ASSERT(bytes_received != NULL, E_NULL_POINTER);
	ASSERT(buf != NULL, E_NULL_POINTER);

	*bytes_received = SSL_read(tls_descriptors[tls_id].ssl_ptr, buf, buf_len);

	/* if(*bytes_received == 0) */
	/* { */
	/* 	if(SSL_get_error(tls_descriptors[tls_id].ssl_ptr, *bytes_received) == SSL_ERROR_ZERO_RETURN) */
	/* 	{ */
	/* 		return(E_TLS_READ); */
	/* 	} */
	/* 	else */
	/* 	{ */
	/* 		return(E_TLS_ERROR); */
	/* 	} */
	/* } */

	return(RETURN_SUCCESS);
}

int32_t exitTLS(void)
{
	/* Free the SSL_CTX structure */
	SSL_CTX_free(ctx);

	/* only the server side has a
	   listen_sock to close */
	if(listen_sock != -1)
	{
		close(listen_sock);
	}
	
	return(RETURN_SUCCESS);
}

