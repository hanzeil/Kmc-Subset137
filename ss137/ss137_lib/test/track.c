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
	int32_t sock = 0;
	session_t session;

	memset(&session, 0, sizeof(session_t));
		
	initServerConnection(&session.tls_des, &sock, atoi(argv[1]));

	initAppSession(0x11223344, &session);
	
	/* endAppSession(&session); */

	return(0);
}
