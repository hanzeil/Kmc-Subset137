/* ------------------------------------------------------------------------------- */
/* I n c l u d e s                                                                 */
/* ------------------------------------------------------------------------------- */

/**
 * System headers
 */
#include <stdint.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "common.h"
#include "tls_wrapper.h"


/* ------------------------------------------------------------------------------- */
/* d e f i n e   c o n s t a n t s   a n d   m a c r o s                           */
/* ------------------------------------------------------------------------------- */

#define RSA_CLIENT_CERT       "newcert.pem"
#define RSA_CLIENT_KEY        "newkey.pem"
#define RSA_CLIENT_CA_CERT    "./demoCA/cacert.pem"
#define RSA_CLIENT_CA_PATH    "./demoCA/"
#define MAX_SSL_DES            (100U)

const char allowed_ciphers[] = "AES256-GCM-SHA384";

static SSL_CTX *ctx = NULL;

static SSL *ssl_fds[MAX_SSL_DES];

/* ------------------------------------------------------------------------------- */
/* Local Functions Prototypes                                                      */
/* ------------------------------------------------------------------------------- */

static int32_t getPeerCertificate(SSL* ssl);

static int32_t initTLS(void);

static int32_t findSSLDes(uint32_t * const ssl_des);

/* ------------------------------------------------------------------------------- */
/* Local Functions Bodies                                                          */
/* ------------------------------------------------------------------------------- */

static int32_t findSSLDes(uint32_t * const ssl_des)
{
	uint32_t i = 0U;
	bool_t found = FALSE;

	ASSERT(ssl_des != NULL, E_NULL_POINTER);

	for(i = 0U; i<MAX_SSL_DES; i++)
	{
		if(ssl_fds[i] == NULL)
		{
			*ssl_des = i;
			found = TRUE;
			break;
		}
	}

	if(found == FALSE)
	{
		err_print("No valid ssl fd.\n");
		return(E_TLS_ERROR);
	}

	return(RETURN_SUCCESS);
}

static int32_t getPeerCertificate(SSL* ssl)
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
	SSL_METHOD *meth = NULL;

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
	SSL_CTX_set_verify_depth(ctx,1);

	return(RETURN_SUCCESS);

}

/* ------------------------------------------------------------------------------- */
/* Public Functions Bodies                                                         */
/* ------------------------------------------------------------------------------- */

/* client */
int32_t createClientTLS(int32_t* const sock)
{
	ASSERT(sock != NULL, E_NULL_POINTER);

	if(initTLS() != RETURN_SUCCESS)
	{
		err_print("Error during initTLS()\n");
		return(E_TLS_ERROR);
	}
	
	*sock = socket (PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if(*sock == -1)
	{
		err_print("Error opening socket\n");
		return(E_TLS_ERROR);
	}
	
	return(RETURN_SUCCESS);
}

int32_t connectTLS(uint32_t* const ssl_des, const int32_t sock, const char* const r_ip, const uint16_t r_port)
{
	struct sockaddr_in server_addr;
	SSL* ssl = NULL;

	ASSERT(r_ip != NULL, E_NULL_POINTER);
	
	memset (&server_addr, '\0', sizeof(server_addr));
	server_addr.sin_family      = AF_INET;
 	server_addr.sin_port        = htons(r_port);       /* Server Port number */
	server_addr.sin_addr.s_addr = inet_addr(r_ip); /* Server IP */

	/* Establish a TCP/IP connection to the SSL client */
	if(connect(sock, (struct sockaddr*) &server_addr, sizeof(server_addr)) == -1)
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
	if(!SSL_set_fd(ssl, sock))
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

	findSSLDes(ssl_des);

	ssl_fds[*ssl_des] = ssl;

	getPeerCertificate(ssl);
		
	return(RETURN_SUCCESS);
}

/* server */
int32_t createServerTLS(int32_t* const sock, const uint16_t l_port)
{
	struct sockaddr_in sa_serv;
	
	ASSERT(sock != NULL, E_NULL_POINTER);

	if(initTLS() != RETURN_SUCCESS)
	{
		err_print("Error during initTLS()\n");
		return(E_TLS_ERROR);
	}
	
	*sock = socket (PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if(*sock == -1)
	{
		err_print("Error opening socket\n");
		return(E_TLS_ERROR);
	}

	memset (&sa_serv, '\0', sizeof(sa_serv));
	sa_serv.sin_family      = AF_INET;
	sa_serv.sin_addr.s_addr = INADDR_ANY;
	sa_serv.sin_port        = htons (l_port);   /* Server Port number */

	if(bind(*sock, (struct sockaddr*)&sa_serv, sizeof(sa_serv)) == -1)
	{
		err_print("Error on binding port %d\n", l_port);
		return(E_TLS_ERROR);
	}

	if(listen(*sock, 5) == -1)
	{
		err_print("Error on listen call\n");
		return(E_TLS_ERROR);
	}

	return(RETURN_SUCCESS);
}

int32_t acceptTLS(uint32_t* const ssl_des, int32_t* const client_sock, const int32_t listen_sock)
{
	struct sockaddr_in sa_cli;
	int32_t  client_len = 0;
	SSL *ssl = NULL;

	ASSERT(client_sock != NULL, E_NULL_POINTER);
	ASSERT(listen_sock != -1, E_INVALID_PARAM);

	client_len = sizeof(sa_cli);

	/* Wait for an incoming TCP connection. */
	/* Socket for a TCP/IP connection is created */
	*client_sock = accept(listen_sock, (struct sockaddr*)&sa_cli, (socklen_t *)&client_len);
	if(*client_sock == -1)
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
	if(!SSL_set_fd(ssl, *client_sock))
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

	findSSLDes(ssl_des);

	ssl_fds[*ssl_des] = ssl;

	return(RETURN_SUCCESS);
}

int32_t closeTLS(const uint32_t ssl_des, const int32_t sock)
{
	if(!SSL_shutdown(ssl_fds[ssl_des]))
 	{
		ERR_print_errors_fp(stderr);
		return(E_TLS_ERROR);
	}

	/* Free the SSL structure */
	SSL_free(ssl_fds[ssl_des]);

	ssl_fds[ssl_des] = NULL;

	close(sock);
	
	return(RETURN_SUCCESS);
}

int32_t sendTLS(uint32_t* const bytes_sent,
				const uint8_t* const buf,
				const uint32_t buf_len,
				const uint32_t ssl_des)
{
	
	*bytes_sent = SSL_write(ssl_fds[ssl_des], buf, buf_len);

	return(RETURN_SUCCESS);
}

int32_t receiveTLS(uint32_t* const bytes_received,
				   uint8_t* const buf,
				   const uint32_t buf_len,
				   const uint32_t ssl_des)
{
	*bytes_received = SSL_read(ssl_fds[ssl_des], buf, buf_len);

	return(RETURN_SUCCESS);
}

int32_t exitTLS(void)
{
	/* Free the SSL_CTX structure */
	SSL_CTX_free(ctx);

	return(RETURN_SUCCESS);
}

