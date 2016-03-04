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
	notif_response_t notification_list;

	memset(&session, 0, sizeof(session_t));

	startClientTLS(&session.tls_id);

	connectToTLSServer(session.tls_id, argv[1], atoi(argv[2]));

	initAppSession(0x11223344, &session);

	/* first transaction */
	sendCmdDeleteAllKeys(&session);

	waitForNotifResponse(&session, &notification_list);
	session.transNum++;

	/* second transaction */
	sendCmdDeleteAllKeys(&session);

	waitForNotifResponse(&session, &notification_list);
	session.transNum++;
	
	endAppSession(&session);

	closeTLSConnection(session.tls_id);

	return(0);
}

	

