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
	uint32_t request_type = 0U;

	memset(&session, 0, sizeof(session_t));

	startServerTLS(&session.tls_id, atoi(argv[1]));

	while(1)
	{
		listenForTLSClient(session.tls_id);

		initAppSession(0xAABBCCDD, &session);

		while(1)
		{
			waitForRequest(&request_type, &session);

			if(request_type == NOTIF_END_OF_UPDATE)
			{
				break;
			}
			
			debug_print("Request received : %d\n", request_type);
			
			/* some processing */
			notif_response_t payload;
			
			payload.response = RESP_OK;
			payload.reqNum = 0;
			
			sendNotifResponse(&payload, &session);
			session.transNum++;
		}

		closeTLSConnection(session.tls_id);
	}
	
	return(0);
}


