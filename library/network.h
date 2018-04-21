#ifndef WEBSTER_NETWORK_HH
#define WEBSTER_NETWORK_HH


#include "internal.h"
#include <netdb.h>


int webster_lookupIPv4(
	const char *host,
	struct sockaddr_in *address );

int webster_receive(
	webster_input_t *input,
	int timeout );


#endif // WEBSTER_NETWORK_HH