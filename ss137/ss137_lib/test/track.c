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
	uint32_t payload[5000];

	memset(&session, 0, sizeof(session_t));

	startServerTLS(&session.tlsID, atoi(argv[1]));

	while(1)
	{
		listenForTLSClient(session.tlsID);

		session.appTimeout = 0xFF;
		session.peerEtcsIDExp = 0xAABBCCDD;

		sendNotifSessionInit(&session);
		
		waitForSessionInit(payload, &session);
		session.transNum++;
		while(1)
		{
			waitForRequestFromKMCToKMAC(payload, &request_type, &session);

			debug_print("Request received : %d\n", request_type);

			if(request_type == NOTIF_END_OF_UPDATE)
			{
				break;
			}
			else if(request_type == CMD_REQUEST_KEY_DB_CHECKSUM)
			{
				/* evaluate crc */
				notif_key_db_checksum_t payload;
				uint32_t i = 0U;
				for(i=0U; i<sizeof(notif_key_db_checksum_t); i++)
				{
					payload.checksum[i] = i;
				}
				sendNotifKeyDBChecksum(&payload, &session);
			}
			else
			{
				/* some processing of request */
				notif_response_t payload;
				
				payload.response = RESP_OK;
				payload.reqNum = 0;
				
				sendNotifResponse(&payload, &session);

			}
			session.transNum++;
		}

		closeTLSConnection(session.tlsID);
	}
	
	return(0);
}


