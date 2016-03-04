#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "tls_wrapper.h"

int main(int argc, char* argv[])
{
	char     buf[4096];
 
	uint32_t bytes_received;
	uint32_t bytes_send;
	uint32_t tls_id;

	short int       s_port = atoi(argv[1]);

	initServerTLS(&tls_id, s_port);

	printf("Start listening on incoming connection\n");
	acceptTLS(tls_id);

	/* ----------------------------------------------- */
	/* Wait for incoming connection. */
	while(1)
	{
		/*------- DATA EXCHANGE - Receive message and send reply.-----*/
		/* Receive data from the TLS client */
		receiveTLS(&bytes_received, (uint8_t*)buf, 4096, tls_id);
		
		buf[bytes_received] = '\0';
		
		printf ("Received %d chars:'%s'\n", bytes_received, buf);
		
		/* Send data to the TLS client */
		sendTLS(&bytes_send, (uint8_t*)"This message is from the TLS server", strlen("This message is from the TLS server"), tls_id);
		
	}

	closeTLS(tls_id);

	/*--------------- TLS closure ---------------*/
	/* Shutdown this side (server) of the connection. */
	exitTLS();
		
}
