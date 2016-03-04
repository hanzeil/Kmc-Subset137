#include <stdio.h>     /* for fopen, snprintf, etc... */
#include <string.h>    /* for memmove, memcmp, memset */
#include <arpa/inet.h> /* for htons, etc.. */
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#include "common.h"
#include "net_utils.h"
#include "msg_definitions.h"
#include "ss137_lib.h"

int main(int argc, char *argv[])
{
	session_t session;
	uint8_t payload[5000];
	notif_response_t notification_list;
	uint32_t i = 0U;

	memset(&session, 0, sizeof(session_t));

	startClientTLS(&session.tlsID);

	connectToTLSServer(session.tlsID, argv[1], atoi(argv[2]));

	session.appTimeout = 0xFF;

	initAppSession(0x11223344, &session);

	/* first transaction */
	for(i = 0U; i < atoi(argv[3]); i++)
	{
		sendCmdDeleteAllKeys(&session);
		
		waitForResponse(payload, &session);
		session.transNum++;

		sendCmdReqKeyDBChecksum(&session);
			
		waitForResponse(payload, &session);
		session.transNum++;
	}

	endAppSession(&session);

	closeTLSConnection(session.tlsID);

	return(0);
}

	

