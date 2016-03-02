#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "tls_wrapper.h"

int main(int32_t argc, char * argv[])
{
	int32_t     sock;
	char    buf [4096];
	char    hello[80];

	uint32_t ssl_des;
	uint32_t bytes_received = 0U;
	uint32_t bytes_sent = 0U;

	memset(hello, 0U, 80);
	
	/* ------------------------------------------------------------- */
	/* Set up a TCP socket */
	createClientTLS(&sock);

	connectTLS(&ssl_des, sock, argv[1], atoi(argv[2]));

	while( hello[0] != 'q')
	{
		printf ("Message to be sent to the TLS server: ");
		fgets (hello, 80, stdin);
		
		/*-------- DATA EXCHANGE - send message and receive reply. -------*/
		/* Send data to the TLS server */
		sendTLS(&bytes_sent, (uint8_t*)hello, strlen(hello), ssl_des);
		
		/* Receive data from the TLS server */
		receiveTLS(&bytes_received, (uint8_t*)buf, 4096, ssl_des);
		
		buf[bytes_received] = '\0';
		printf ("Received %d chars:'%s'\n", bytes_received, buf);
	}

	closeTLS(ssl_des, sock);

	/* cleanup all structure */
	exitTLS();

	return(0);
}
