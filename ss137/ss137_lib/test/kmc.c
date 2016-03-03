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
	session_t session;
	int32_t sock;

	memset(&session, 0, sizeof(session_t));
		
	initClientConnection(&session.tls_des, &sock, argv[1], atoi(argv[2]));

	initAppSession(0x44556677, &session);
	
	endAppSession(&session);

	return(0);
}
