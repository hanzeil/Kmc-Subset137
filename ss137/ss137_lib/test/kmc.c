#include <stdio.h>     /* for fopen, snprintf, etc... */
#include <string.h>    /* for memmove, memcmp, memset */
#include <arpa/inet.h> /* for htons, etc.. */
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/time.h>

#include "utils.h"
#include "net_utils.h"
#include "msg_definitions.h"
#include "ss137_lib.h"

#define RSA_CA_CERT    "./cert/cacert.pem"   /**< RSA root CA Certificate pathname */
#define RSA_CERT       "./cert/kmc_cert.pem" /**< RSA Certificate pathname */
#define RSA_KEY        "./cert/kmc_key.pem"  /**< RSA Key pathname */

k_struct_t k_struct =
{
		K_LENGTH,
		{
				0xaabbccdd,
				0xddeeff00,
		},
		0xaabbccdd,
		{
			0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 077,
			0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 077,
			0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 077
		},
		1,
		{
			0xaabbccdd,
		},
		0x00000000,
		0xffffffff
};

k_ident_t k_ident =
{
		0xaabbccdd,
		0xddeeff00
};

k_validity_t k_validity =
{
		{
				0xaabbccdd,
				0xddeeff00
		},
		0x00000000,
		0xffffffff
};


k_entity_t k_entity =
{
		{
				0xaabbccdd,
				0xddeeff00
		},
		1,
		{
			0xaabbccdd
		}
};

ss137_lib_configuration_t ss137_lib_config =
{
	RSA_CA_CERT,
	RSA_KEY,
	RSA_CERT,
	{0xAABBCCDD, "127.0.0.1"},
	{
		{0x11223344, "127.0.0.1"}
	}
};

int main(int argc, char *argv[])
{
	session_t session;
	request_t request;
	response_t response;
	uint32_t i = 0U;

	memset(&session, 0, sizeof(session_t));

	startClientTLS(&session.tlsID);

	connectToTLSServer(session.tlsID, ss137_lib_config.kmsEntitiesId[0].ip);

	if(initAppSession(&session, 0x3, ss137_lib_config.kmsEntitiesId[0].expEtcsId) != SUCCESS)
	{
		closeTLSConnection(session.tlsID);
	}
	else
	{

		request.reqNum = 1;
		log_print("----------------------------------------------------------\n");
		log_print("----------------------------------------------------------\n");
		/* first transaction */
		for(i = 0U; i < atoi(argv[1]); i++)
		{
			memmove(request.kStructList, &k_struct, sizeof(k_struct_t));
			if(performAddKeysTransaction(&response, &session, &request) != SUCCESS)
			{
				break;
			}

			log_print("----------------------------------------------------------\n");
			log_print("----------------------------------------------------------\n");
			
			memmove(request.kIdentList, &k_ident, sizeof(k_ident_t));
			if(performDelKeysTransaction(&response, &session, &request)!= SUCCESS)
			{
				break;
			}

			log_print("----------------------------------------------------------\n");
			log_print("----------------------------------------------------------\n");
			
			memmove(request.kValidityList, &k_validity, sizeof(k_validity_t));
			if(performUpKeyValiditiesTransaction(&response, &session, &request)!= SUCCESS)
			{
				break;
			}

			log_print("----------------------------------------------------------\n");
			log_print("----------------------------------------------------------\n");
			
			memmove(request.kEntityList, &k_entity, sizeof(k_entity_t));
			if(performUpKeyEntitiesTransaction(&response, &session, &request)!= SUCCESS)
			{
				break;
			}

			log_print("----------------------------------------------------------\n");
			log_print("----------------------------------------------------------\n");
			
			if(performDeleteAllKeysTransaction(&response, &session)!= SUCCESS)
			{
				break;
			}

			log_print("----------------------------------------------------------\n");
			log_print("----------------------------------------------------------\n");
			
			if(performReqDBChecksumTransaction(&response, &session)!= SUCCESS)
			{
				break;
			}

			log_print("----------------------------------------------------------\n");
			log_print("----------------------------------------------------------\n");
			
		}
		
		endAppSession(&session);
		
		closeTLSConnection(session.tlsID);
	}
	
	return(0);
}


	

