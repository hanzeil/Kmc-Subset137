#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "tls_wrapper.h"

int main(int32_t argc, char * argv[])
{
	char    buf [4096];
	char    hello[80];

	uint32_t tls_id;
	uint32_t bytes_received = 0U;
	uint32_t bytes_sent = 0U;

	memset(hello, 0U, 80);
	
	/* ------------------------------------------------------------- */
	/* Set up a TCP socket */
	initClientTLS(&tls_id);

	connectTLS(tls_id, argv[1], atoi(argv[2]));

	while( hello[0] != 'q')
	{
		printf ("Message to be sent to the TLS server: ");
		fgets (hello, 80, stdin);
		
		/*-------- DATA EXCHANGE - send message and receive reply. -------*/
		/* Send data to the TLS server */
		sendTLS(&bytes_sent, (uint8_t*)hello, strlen(hello), tls_id);
		
		/* Receive data from the TLS server */
		receiveTLS(&bytes_received, (uint8_t*)buf, 4096, tls_id);
		
		buf[bytes_received] = '\0';
		printf ("Received %d chars:'%s'\n", bytes_received, buf);
	}

	closeTLS(tls_id);

	/* cleanup all structure */
	exitTLS();

	return(0);
}
