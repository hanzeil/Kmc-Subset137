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
	request_t request;
	bool_t stop = FALSE;
	response_t response;
	uint32_t i = 0U;

	memset(&session, 0, sizeof(session_t));

	startServerTLS(&session.tlsID, atoi(argv[1]));

	while(1)
	{
		listenForTLSClient(session.tlsID);

		initAppSession(&session, 0xff, 0xAABBCCDD);

		debug_print("----------------------------------------------------------\n");
		debug_print("----------------------------------------------------------\n");


		while(stop == FALSE)
		{
			waitForRequestFromKMCToKMAC(&request, &session);

			debug_print("Request received : %d\n", request.msgType);

			switch(request.msgType)
			{
			case(NOTIF_END_OF_UPDATE):
				stop = TRUE;
				break;
			case(CMD_REQUEST_KEY_DB_CHECKSUM):
				/* evaluate crc */
				for(i=0U; i<sizeof(response.checksum); i++)
				{
					response.checksum[i] = i;
				}
				sendNotifKeyDBChecksum(&response, &session);
				break;
			case(CMD_DELETE_ALL_KEYS):
				response.notif.reason = RESP_OK;
				response.notif.reqNum = 0;
				sendNotifResponse(&response, &session);
				break;
			default:
				/* some processing of request */
				response.notif.reason = RESP_OK;
				response.notif.reqNum = request.reqNum;

				for(i = 0U; i < request.reqNum; i++)
				{
					response.notif.notificationList[i] = 0U;
				}
				
				sendNotifResponse(&response, &session);
				break;
			}
			session.transNum++;
			request.reqNum = 0;
			debug_print("----------------------------------------------------------\n");
			debug_print("----------------------------------------------------------\n");
			
		}
		stop = FALSE;
		closeTLSConnection(session.tlsID);
	}
	
	return(0);
}





