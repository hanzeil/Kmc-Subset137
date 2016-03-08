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

int main(int argc, char *argv[])
{
	session_t session;
	request_t request;
	response_t response;
	uint32_t i = 0U;

	memset(&session, 0, sizeof(session_t));

	startClientTLS(&session.tlsID);

	connectToTLSServer(session.tlsID, argv[1], atoi(argv[2]));

	if(initAppSession(&session, 0x3, 0x11223344) == OP_NOK)
	{
		closeTLSConnection(session.tlsID);
	}
	else
	{

		request.reqNum = 1;
		debug_print("----------------------------------------------------------\n");
		debug_print("----------------------------------------------------------\n");
		/* first transaction */
		for(i = 0U; i < atoi(argv[3]); i++)
		{
			memmove(request.kStructList, &k_struct, sizeof(k_struct_t));
			performAddKeysOperation(&session, &response, &request);
			
			debug_print("----------------------------------------------------------\n");
			debug_print("----------------------------------------------------------\n");
			
			memmove(request.kIdentList, &k_ident, sizeof(k_ident_t));
			performDelKeysOperation(&session, &response, &request);
			
			debug_print("----------------------------------------------------------\n");
			debug_print("----------------------------------------------------------\n");
			
			memmove(request.kValidityList, &k_validity, sizeof(k_validity_t));
			performUpKeyValiditiesOperation(&session, &response, &request);
			
			debug_print("----------------------------------------------------------\n");
			debug_print("----------------------------------------------------------\n");
			
			memmove(request.kEntityList, &k_entity, sizeof(k_entity_t));
			performUpKeyEntitiesOperation(&session, &response, &request);
			
			debug_print("----------------------------------------------------------\n");
			debug_print("----------------------------------------------------------\n");
			
			performDeleteAllKeysOperation(&session,	&response);
			
			debug_print("----------------------------------------------------------\n");
			debug_print("----------------------------------------------------------\n");
			
			performReqDBChecksumOperation(&session,	&response);
			
			debug_print("----------------------------------------------------------\n");
			debug_print("----------------------------------------------------------\n");
			
		}
		
		endAppSession(&session);
		
		closeTLSConnection(session.tlsID);
	}
	
	return(0);
}


	

