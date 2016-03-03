#include <stdio.h>     /* for fopen, snprintf, etc... */
#include <string.h>    /* for memmove, memcmp, memset */
#include <arpa/inet.h> /* for htons, etc.. */
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#include "common.h"
#include "net_utils.h"
#include "ss137_lib.h"

int main(int argc, char *argv[])
{
	int32_t client_sock = 0;
	int32_t listen_sock = 0;
	session_t session;

	memset(&session, 0, sizeof(session_t));

	startServerTLS(&listen_sock, atoi(argv[1]));

	while(1)
	{
		waitForTLSClient(&session.tls_des, &client_sock, listen_sock);
		
		initAppSession(0x11223344, &session);

		/* waitForCommand(session.tls_des); */

		closeTLSConnection(session.tls_des, client_sock);
	}
	
	return(0);
}


