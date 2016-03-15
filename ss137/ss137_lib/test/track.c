#include <stdio.h>     /* for fopen, snprintf, etc... */
#include <string.h>    /* for memmove, memcmp, memset */
#include <arpa/inet.h> /* for htons, etc.. */
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>
#include <libgen.h>

#include "utils.h"
#include "net_utils.h"
#include "msg_definitions.h"
#include "ss137_lib.h"

#define RSA_CA_CERT    "./cert/cacert.pem"         /**< RSA root CA Certificate pathname */
#define RSA_KEY        "./cert/track_key.pem"      /**< RSA Key pathname */
#define RSA_CERT       "./cert/track_cert.pem"     /**< RSA Certificate pathname */

ss137_lib_configuration_t ss137_lib_config =
{
	RSA_CA_CERT,
	RSA_KEY,
	RSA_CERT,
	{0x11223344, "127.0.0.1"},
	{
		{0xAABBCCDD, "127.0.0.1"}
	}
};

int main(int argc, char *argv[])
{
	session_t session;
	request_t request;
	bool_t stop = FALSE;
	response_t response;
	uint32_t i = 0U;
	uint32_t exp_etcs_id = 0U;

	memset(&session, 0, sizeof(session_t));

	if(startServerTLS() != SUCCESS)
	{
		exit(1);
	}

	while(1)
	{
		if(listenForTLSClient(&session.tlsID, &exp_etcs_id) != SUCCESS)
		{
			exit(1);
		}

		if(initAppSession(&session, 0xff, exp_etcs_id) != SUCCESS)
		{
			closeTLSConnection(session.tlsID);
			continue;
		}

		log_print("----------------------------------------------------------\n");
		log_print("----------------------------------------------------------\n");

		while(stop == FALSE)
		{
			if(waitForRequestFromKMCToKMAC(&request, &session) != SUCCESS)
			{
				stop = TRUE;
				continue;
			}

			log_print("Request received : %d\n", request.msgType);

			switch(request.msgType)
			{
			case(NOTIF_END_OF_UPDATE):
				stop = TRUE;
				break;
			case(CMD_REQUEST_KEY_DB_CHECKSUM):
				/* evaluate crc */
				for(i=0U; i<sizeof(response.dbChecksumPayload.checksum); i++)
				{
					response.dbChecksumPayload.checksum[i] = i;
				}
				sendNotifKeyDBChecksum(&response, &session);
				break;
			case(CMD_DELETE_ALL_KEYS):
				response.notifPayload.reason = RESP_OK;
				response.notifPayload.reqNum = 0;
				if(sendNotifResponse(&response, &session) != SUCCESS)
				{
					stop = TRUE;
					continue;
				}
				break;
			default:
				/* some processing of request */
				response.notifPayload.reason = RESP_OK;
				response.notifPayload.reqNum = request.reqNum;

				for(i = 0U; i < request.reqNum; i++)
				{
					response.notifPayload.notificationList[i] = 0U;
				}
				
				if(sendNotifResponse(&response, &session) != SUCCESS)
				{
					stop = TRUE;
					log_print("End of update message received \n");
					continue;
				}

				break;
			}
			session.transNum++;
			request.reqNum = 0;
			log_print("----------------------------------------------------------\n");
			log_print("----------------------------------------------------------\n");
			sleep(2U);
		}
		stop = FALSE;
		closeTLSConnection(session.tlsID);
	}
	
	return(0);
}





