#include "internal.h"
#include "network.h"
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>


int webster_releaseMessage(
	webster_message_t *message );


int WebsterCreate(
    webster_server_t *server,
	int maxClients )
{
	if (server == NULL) return WBERR_INVALID_ARGUMENT;

	if (maxClients <= 0 || maxClients >= WEBSTER_MAX_CONNECTIONS)
		maxClients = WEBSTER_MAX_CONNECTIONS;

	*server = (webster_server_t) calloc(1, sizeof(struct webster_server_t_));
	if (*server == NULL) return WBERR_MEMORY_EXHAUSTED;

	(*server)->channel = NULL;
	(*server)->port = -1;
	(*server)->host = NULL;
	(*server)->pfd.events = POLLIN;
	(*server)->bufferSize = HTTP_MAX_HEADER;

	return WBERR_OK;
}


int WebsterDestroy(
    webster_server_t *server )
{
	if (server == NULL || *server == NULL) return WBERR_INVALID_ARGUMENT;

	WebsterStop(server);

	if ((*server)->host != NULL) free((*server)->host);
	free(*server);
	*server = NULL;

	return WBERR_OK;
}


int WebsterStart(
	webster_server_t *server,
    const char *host,
    int port )
{
	if (server == NULL || *server == NULL) return WBERR_INVALID_ARGUMENT;

	int result = network_open(&(*server)->channel);
	if (result != WBERR_OK) return result;

	return network_listen((*server)->channel, host, port, (*server)->maxClients);
}


int WebsterStop(
    webster_server_t *server )
{
	if (server == NULL || *server == NULL) return WBERR_INVALID_ARGUMENT;

	network_close((*server)->channel);
	(*server)->channel = NULL;

	return WBERR_OK;
}


int WebsterAccept(
    webster_server_t *server,
	webster_client_t *remote )
{
	if (server == NULL || remote == NULL) return WBERR_INVALID_ARGUMENT;

	void *client = NULL;
	int result = network_accept((*server)->channel, &client);
	if (result != WBERR_OK) return result;

	*remote = (struct webster_client_t_*) calloc(1,
		sizeof(struct webster_client_t_) + (size_t) (*server)->bufferSize * 2 );
	if (*remote == NULL)
	{
		network_close(client);
		return WBERR_MEMORY_EXHAUSTED;
	}

	(*remote)->channel = client;
	(*remote)->port = 0;
	(*remote)->host = NULL;
	(*remote)->resource = NULL;
	(*remote)->pfd.events = POLLIN;

	return WBERR_OK;
}


int WebsterSetOption(
	webster_server_t *server,
    int option,
    int value )
{
	if (server == NULL || *server == NULL) return WBERR_INVALID_ARGUMENT;

	if (option == WBO_BUFFER_SIZE)
	{
		if (value < 1024 || value > 1024 * 1024 * 10) value = WEBSTER_MAX_HEADER;
		(*server)->bufferSize = value;
	}
	else
		return WBERR_INVALID_ARGUMENT;

	return WBERR_OK;
}


int WebsterGetOption(
	webster_server_t *server,
    int option,
    int *value )
{
	if (server == NULL || *server == NULL || value == NULL) return WBERR_INVALID_ARGUMENT;

	if (option == WBO_BUFFER_SIZE)
		*value = (*server)->bufferSize;
	else
		return WBERR_INVALID_ARGUMENT;

	return WBERR_OK;
}