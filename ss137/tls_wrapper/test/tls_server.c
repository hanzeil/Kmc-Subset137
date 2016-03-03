#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "tls_wrapper.h"

int main(int argc, char* argv[])
{
 	int     listen_sock = -1;
	int     client_sock = -1;
	char     buf[4096];
 
	uint32_t bytes_received;
	uint32_t bytes_send;
	uint32_t tls_des;

	short int       s_port = atoi(argv[1]);

	initServerTLS(&listen_sock, s_port);

	printf("Start listening on incoming connection\n");
	
	acceptTLS(&tls_des, &client_sock, listen_sock);

	/* ----------------------------------------------- */
	/* Wait for incoming connection. */
	while(1)
	{
		/*------- DATA EXCHANGE - Receive message and send reply.-----*/
		/* Receive data from the TLS client */
		receiveTLS(&bytes_received, (uint8_t*)buf, 4096, tls_des);
		
		buf[bytes_received] = '\0';
		
		printf ("Received %d chars:'%s'\n", bytes_received, buf);
		
		/* Send data to the TLS client */
		sendTLS(&bytes_send, (uint8_t*)"This message is from the TLS server", strlen("This message is from the TLS server"), tls_des);
		
	}

	closeTLS(tls_des, client_sock);

	/*--------------- TLS closure ---------------*/
	/* Shutdown this side (server) of the connection. */
	exitTLS();
		
}
