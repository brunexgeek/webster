#ifndef WEBSTER_NETWORK_HH
#define WEBSTER_NETWORK_HH


#include "internal.h"
#include <netdb.h>


int network_open(
	void **channel );

int network_close(
	void *channel );

int network_receive(
	void *channel,
	uint8_t *buffer,
    size_t *size,
	int timeout );

int network_send(
	void *channel,
	const uint8_t *buffer,
    size_t size );

int network_accept(
	void *channel,
	void **client );

int network_listen(
	void *channel,
	const char *host,
    int port,
	int maxClients );

#endif // WEBSTER_NETWORK_HH