/**************************************************************************//**
 *
 * TLS wrapper for OpenSSL
 *
 * This file wraps the SS137-TLS-needs in an uniform API. This implementation
 * uses OpenSSL as low-level library. Wrapper tested on:
 * - OpenSSL 1.0.1f 
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
#include <poll.h>
#include <arpa/inet.h>
#include <libgen.h>

#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#include "utils.h" 
#include "tls_wrapper.h"


/*****************************************************************************
 * DEFINES
 ******************************************************************************/

/** @name SSL tuning parameters
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
	bool_t  in_use;  /**< If the current descriptor is in use.*/
	int32_t socket;  /**< TCP socket of the current TLS connection.*/
	SSL    *ssl_ptr; /**< OpenSSL session.*/
} tls_descriptor_t;

/*****************************************************************************
 * VARIABLES
 *****************************************************************************/
/** List of ciphers. String is colon-separated i.e. "CIPHERA:CIPHERB:CIPHERC" */
const char allowed_ciphers[] = "ECDHE-RSA-AES256-GCM-SHA384";

/** Current OpenSSL context." */
static SSL_CTX *ctx = NULL;

/** The list of TLS descriptor available */
static tls_descriptor_t tls_descriptors[MAX_TLS_DES];

/** The listen socket of the server side */
static int32_t listen_sock = -1;

/*****************************************************************************
 * FUNCTION PROTOTYPES
 *****************************************************************************/

static tls_error_code_t getPeerCertificate(SSL* ssl);

static tls_error_code_t initTLS(const char* const ca_cert, const char *const key, const char* const cert);

static tls_error_code_t findTLSDes(uint32_t * const tls_id);

static tls_error_code_t verifyLocalCertificate(const char* const ca_cert, const char* const cert);

/*****************************************************************************
 * LOCAL FUNCTION DECLARATIONS
 *****************************************************************************/

/**
 * Find a valid TLS descriptor.
 *
 * This fucntion look for a not in use TLS descriptot inside the tls_descriptors array.
 * The function calls the exit() function on any erorr on the addressing of the input parameters.
 */
static tls_error_code_t findTLSDes
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
 * Verify local certificate.
 *
 * This function verifies the local certificate againt the CA certificate.
 * The function calls the exit() function on any erorr on the addressing of the input parameters.
 */
static tls_error_code_t verifyLocalCertificate /** @return TLS_SUCCESS if the certificate is valid, TLS_ERROR in case of error. */
(
	const char* const ca_cert, /**< [in] CA certificate file. */
	const char* const cert     /**< [in] Certificate file. */   
	)
{
	
  X509  *cert_str = NULL;
  X509_STORE  *store = NULL;
  X509_STORE_CTX *vrfy_ctx = NULL;
  BIO   *certbio = NULL;
  int ret;

  ASSERT(ca_cert != NULL, E_NULL_POINTER);
  ASSERT(cert != NULL, E_NULL_POINTER);

  certbio = BIO_new(BIO_s_file());
  OpenSSL_add_all_algorithms();
  ERR_load_BIO_strings();
  
  if ((store = X509_STORE_new()) == 0)
  {
	  log_print("Error creating X509 store object\n");
	  return(TLS_ERROR);
  }

  vrfy_ctx = X509_STORE_CTX_new();

  /* load the certificate and ca certificate in memory */
  ret = BIO_read_filename(certbio, cert);
  if ((cert_str = PEM_read_bio_X509(certbio, NULL, 0, NULL)) == 0)
  {
    log_print("Error loading cert into memory\n");
    return(TLS_ERROR);
  }

  if (X509_STORE_load_locations(store, ca_cert, NULL) != 1)
  {
    log_print("Error loading CA cert or chain file\n");
	return(TLS_ERROR);
  }

   /* Initialize the ctx structure for a verification operation*/
  X509_STORE_CTX_init(vrfy_ctx, store, cert_str, NULL);

/* Check the complete cert chain. */
  ret = X509_verify_cert(vrfy_ctx);
  if(ret == 0)
  {
	  err_print("Local certificate verification failed\n");
	  err_print("Result: %s\n", X509_verify_cert_error_string(vrfy_ctx->error));
	  return(TLS_ERROR);
  }
  else
  {
	  log_print("Local certificate is valid\n");
  }

  /* free used structure */
  X509_STORE_CTX_free(vrfy_ctx);
  X509_STORE_free(store);
  X509_free(cert_str);

  return(TLS_SUCCESS);
}

/**
 * Verify peer certificate.
 *
 * This function is called during the TLS handshake peer certificate verification.
 * The function calls the exit() function on any erorr on the addressing of the input parameters.
 */
static tls_error_code_t getPeerCertificate /** @return TLS_SUCCESS if the peer certificate is valid, TLS_ERROR if the peer certificate is not valid. */
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
		log_print("Peer certificate\n");
		
		str = X509_NAME_oneline(X509_get_subject_name(peer_cert),0,0);
		log_print("\t subject: %s\n", str);
		free (str);
		
		str = X509_NAME_oneline(X509_get_issuer_name(peer_cert),0,0);
		log_print("\t issuer: %s\n", str);
		free(str);
		
		X509_free (peer_cert);
	}
	else
	{
		err_print("The SSL peer does not have certificate.\n");
		return(TLS_ERROR);
	}
	
	return(TLS_SUCCESS);
}

/**
 * Initialize the GnuTLS library.
 *
 * This function calls all the function needed to initiliaze the OpenSSL library
 * including the initialization of ctx struct.
 * The function calls the exit() function on any erorr on the addressing of the input parameters.
 */
static tls_error_code_t initTLS  /** @return TLS_SUCCESS if the initialization succeeds, TLS_ERROR in case of error. */
(
	const char* const ca_cert, /**< [in] CA certificate file. */
	const char *const key,	   /**< [in] Private key file. */	
	const char* const cert	   /**< [in] Certificate file. */   
	)
{
	const SSL_METHOD * meth = NULL;

	ASSERT(ca_cert != NULL, E_NULL_POINTER);
	ASSERT(key != NULL, E_NULL_POINTER);
	ASSERT(cert != NULL, E_NULL_POINTER);

	log_print("CA cert:  %s\n", ca_cert);
	log_print("RSA Key:  %s\n", key);
	log_print("RSA Cert: %s\n", cert);
	
	/* Load encryption & hashing algorithms for the SSL program */
	SSL_library_init();
 
    /* Load the error strings */
	SSL_load_error_strings();
 
	/* Create an SSL_METHOD structure for TLSv1.2 */
	meth = TLSv1_2_method();
	if( meth == NULL )
	{
		ERR_print_errors_fp(stderr);
		return(TLS_ERROR);
	}
	
	/* Create an SSL_CTX structure */
	ctx = SSL_CTX_new(meth);
	if( meth == NULL )
	{
		ERR_print_errors_fp(stderr);
		return(TLS_ERROR);
	}
 
	/* Load the certificate into the SSL_CTX structure */
	if(!SSL_CTX_use_certificate_file(ctx, cert, SSL_FILETYPE_PEM))
	{
		ERR_print_errors_fp(stderr);
		return(TLS_ERROR);
	}
	
	/* Load the private-key corresponding to the certificate */
	if(!SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM))
	{
		ERR_print_errors_fp(stderr);
		return(TLS_ERROR);
	}
	
	/* Check if the certificate and private-key matches */
	if (!SSL_CTX_check_private_key(ctx))
	{
		ERR_print_errors_fp(stderr);
		return(TLS_ERROR);
	}
 
	/* Load the RSA CA certificate into the SSL_CTX structure */
	/* This will allow  to verify the peer's  */
	if(!SSL_CTX_load_verify_locations(ctx, ca_cert, NULL))
	{
		ERR_print_errors_fp(stderr);
		return(TLS_ERROR);
	}
 
	/* Set flag in context to require peer certificate */
	/* verification */
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

	/* set the verify depth*/
	SSL_CTX_set_verify_depth(ctx,VERIFY_DEPTH);

	/* verify local certificate */
	if(verifyLocalCertificate(ca_cert, cert) != TLS_SUCCESS)
	{
		return(TLS_ERROR);
		
	}
	return(TLS_SUCCESS);

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

	ASSERT(ca_cert != NULL, E_NULL_POINTER);
	ASSERT(key != NULL, E_NULL_POINTER);
	ASSERT(cert != NULL, E_NULL_POINTER);

	ASSERT(tls_id != NULL, E_NULL_POINTER);

	if(initTLS(ca_cert, key, cert) != TLS_SUCCESS)
	{
		return(TLS_ERROR);
	}

	if(findTLSDes(tls_id) != TLS_SUCCESS)
	{
		return(TLS_ERROR);
	}
	
	tmp_sock = socket (PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if(tmp_sock == -1)
	{
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
	const uint32_t tls_id,		 /**< [in] The TLS session identifier. */													  
	const char* const server_ip, /**< [in] The server ip in ASCII format. */												  
	const uint16_t server_port	 /**< [in] The server port. */                                                                
	)
{
	struct sockaddr_in server_addr;
	SSL* ssl = NULL;
	
	ASSERT(tls_id < MAX_TLS_DES, E_INVALID_PARAM);
	ASSERT(server_ip != NULL, E_NULL_POINTER);

	memset (&server_addr, '\0', sizeof(server_addr));
	server_addr.sin_family      = AF_INET;
 	server_addr.sin_port        = htons(server_port);     /* Server Port number */
	server_addr.sin_addr.s_addr = inet_addr(server_ip);        /* Server IP */

	/* Establish a TCP/IP connection to the SSL client */
	if(connect(tls_descriptors[tls_id].socket, (struct sockaddr*) &server_addr, sizeof(server_addr)) == -1)
	{
		err_print("Error on connect to server (%s:%d)\n", server_ip, server_port);
		return(TLS_ERROR);
	}

	ssl = SSL_new (ctx);
	if(ssl == NULL)
	{
		ERR_print_errors_fp(stderr);
		return(TLS_ERROR);
	}

	if(!SSL_set_cipher_list(ssl, allowed_ciphers))
	{
		ERR_print_errors_fp(stderr);
		return(TLS_ERROR);
	}

	/* Assign the socket into the SSL structure (SSL and socket without BIO) */
	if(!SSL_set_fd(ssl, tls_descriptors[tls_id].socket))
	{
		ERR_print_errors_fp(stderr);
		return(TLS_ERROR);
	}

	/* Perform SSL Handshake on the SSL client */
	if(!SSL_connect(ssl))
	{
		ERR_print_errors_fp(stderr);
		return(TLS_ERROR);
	}

	log_print("SSL connection using %s\n", SSL_get_cipher_list(ssl, 0));

	tls_descriptors[tls_id].ssl_ptr = ssl;

	if(getPeerCertificate(ssl) != TLS_SUCCESS)
	{
		return(TLS_ERROR);
	}

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
	const uint16_t l_port,	   /**< [in] The local listening port. */													
	const char* const ca_cert, /**< [in] CA certificate file. */														
	const char *const key,	   /**< [in] Private key file. */															
	const char* const cert	   /**< [in] Certificate file. */                                                           
	)
{
	struct sockaddr_in sa_serv;
	EC_KEY  *ecdh;

	ASSERT(ca_cert != NULL, E_NULL_POINTER);
	ASSERT(key != NULL, E_NULL_POINTER);
	ASSERT(cert != NULL, E_NULL_POINTER);

	if(initTLS(ca_cert, key, cert) != TLS_SUCCESS)
	{
		return(TLS_ERROR);
	}
	
	listen_sock = socket (PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if(listen_sock == -1)
	{
		err_print("Error opening socket\n");
		return(TLS_ERROR);
	}

	memset (&sa_serv, '\0', sizeof(sa_serv));
	sa_serv.sin_family      = AF_INET;
	sa_serv.sin_addr.s_addr = INADDR_ANY;
	sa_serv.sin_port        = htons (l_port);   /* Server Port number */

	if(bind(listen_sock, (struct sockaddr*)&sa_serv, sizeof(sa_serv)) == -1)
	{
		err_print("Error on binding port %d\n", l_port);
		return(TLS_ERROR);
	}

	if(listen(listen_sock, 5) == -1)
	{
		err_print("Error on listen call\n");
		return(TLS_ERROR);
	}


	/* set the elliptic curve to be used during key exchange */
	ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
	if (ecdh == NULL)
	  {
	    err_print("Failed to get EC curve");
	    return(TLS_ERROR);
	  }
	else
	  {

	    SSL_CTX_set_tmp_ecdh(ctx, ecdh);
	    EC_KEY_free(ecdh);
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
	uint32_t* const tls_id,	/**< [out] The TLS session identifier. */									   
	char* const client_ip	/**< [out] The IP of the connected client in ASCII format. */                  
	)
{
	struct sockaddr_in sa_cli;
	int32_t  client_len = 0;
	int32_t client_sock = -1;
	SSL *ssl = NULL;

	ASSERT(tls_id != NULL, E_NULL_POINTER);
	ASSERT(client_ip != NULL, E_NULL_POINTER);

	if(findTLSDes(tls_id) != TLS_SUCCESS)
	{
		return(TLS_ERROR);
	}

	client_len = sizeof(sa_cli);

	/* Wait for an incoming TCP connection. */
	/* Socket for a TCP/IP connection is created */
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
	
	ssl = SSL_new(ctx);
	if(ssl == NULL)
	{
		ERR_print_errors_fp(stderr);
		return(TLS_ERROR);
	}

	if(!SSL_set_cipher_list(ssl, allowed_ciphers))
	{
		ERR_print_errors_fp(stderr);
		return(TLS_ERROR);
	}
		
	/* Assign the socket into the SSL structure (SSL and socket without BIO) */
	if(!SSL_set_fd(ssl, client_sock))
	{
		ERR_print_errors_fp(stderr);
		return(TLS_ERROR);
	}

	/* Perform SSL Handshake on the SSL server */
	if(!SSL_accept(ssl))
 	{
		ERR_print_errors_fp(stderr);
		return(TLS_ERROR);
	}

	if(getPeerCertificate(ssl) != TLS_SUCCESS)
	{
		return(TLS_ERROR);
	}

	tls_descriptors[*tls_id].ssl_ptr = ssl;
	tls_descriptors[*tls_id].socket = client_sock;

	return(TLS_SUCCESS);
}

/**
 * Closes a TLS connection.
 *
 * This function the TLS connection corresponding to the connection identifier passed as argument,
 * releasing the correspondig entry in the tls_descriptors struct.
 */
tls_error_code_t closeTLS /** @return error code */									 
(						                                                                
	const uint32_t tls_id /**< [in] The TLS identifier of the connection to close*/     
	)
{
	ASSERT(tls_id < MAX_TLS_DES, E_INVALID_PARAM);
	
	if(!SSL_shutdown(tls_descriptors[tls_id].ssl_ptr))
 	{
		ERR_print_errors_fp(stderr);
		return(TLS_ERROR);
	}

	/* Free the SSL structure
	   and close the socket*/
	SSL_free(tls_descriptors[tls_id].ssl_ptr);
	close(tls_descriptors[tls_id].socket);

	tls_descriptors[tls_id].socket = -1;
	tls_descriptors[tls_id].ssl_ptr = NULL;
	tls_descriptors[tls_id].in_use = FALSE;

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
	uint32_t* const bytes_sent,	/**< [out] The number of bytes sent.*/     												   
	const uint8_t* const buf,	/**< [in] The pointer to the buffer to be sent.*/     									   
	const uint32_t buf_len,		/**< [in] The buffer length.*/     														   
	const uint32_t tls_id		/**< [in] The TLS session identifier. */                                                   
	)
{
	ASSERT(tls_id < MAX_TLS_DES, E_INVALID_PARAM);
	ASSERT(bytes_sent != NULL, E_NULL_POINTER);
	ASSERT(buf != NULL, E_NULL_POINTER);
	
	*bytes_sent = SSL_write(tls_descriptors[tls_id].ssl_ptr, buf, buf_len);

	if(*bytes_sent <= 0)
	{
		ERR_print_errors_fp(stderr);
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
tls_error_code_t receiveTLS         /** @return TLS_SUCCESS if the message is correctly received,			 
										 TLS_ERROR in case of error or if the connection goes in timeout. */ 
(									                                                                        
	uint32_t* const bytes_received,	/**< [out] The number of bytes read.*/             					 
	uint8_t* const buf,				/**< [out] The buffer where the data read is stored.*/             	 
	const uint32_t buf_len,			/**< [in] Max bufer length.*/             								 
	const uint8_t timeout,			/**< [in] Receive timeout in seconds.*/             					 
	const uint32_t tls_id			/**< [in] The TLS session identifier. */                                
	)
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
			*bytes_received = SSL_read(tls_descriptors[tls_id].ssl_ptr, buf, buf_len);
			
			if(*bytes_received <= 0)
			{
				if(SSL_get_shutdown(tls_descriptors[tls_id].ssl_ptr) == SSL_RECEIVED_SHUTDOWN)
				{
					warning_print("TLS shutdown received from the other peer\n");
					return(TLS_ERROR);
				}
			}
		}
	}
	
	return(TLS_SUCCESS);
}

/**
 * Exit OpenSSL library.
 *
 * This function frees all the structure related to OpenSSL library and close the server listen socket
 * if it's called by the TLS server.
 */
tls_error_code_t exitTLS /** @return TLS_SUCCESS if the close operation succeeds, TLS_ERROR in case of error. */
(
	void
	)
{
	/* Free the SSL_CTX structure */
	SSL_CTX_free(ctx);

	/* only the server side has a
	   listen_sock to close */
	if(listen_sock != -1)
	{
		close(listen_sock);
	}
	
	return(TLS_SUCCESS);
}

