#include "internal.h"
#include "network.h"
#include <stdlib.h>
#include <string.h>


int WebsterConnect(
    webster_client_t *client,
    const char *host,
    int port,
	const char *resource )
{
	if (client == NULL || port < 0 || port > 0xFFFF)
		return WBERR_INVALID_ARGUMENT;
	if (host == NULL || host[0] == 0)
		host = "127.0.0.1";
	if (resource == NULL || resource[0] == 0)
		resource = "/";

	size_t hostLen = strlen(host);
	size_t resourceLen = strlen(resource);

	// allocate memory for everything
	*client = (struct webster_client_t_*) calloc(1, sizeof(struct webster_client_t_)
		+ hostLen + 1 + resourceLen + 1);
	if (*client == NULL) return WBERR_MEMORY_EXHAUSTED;

	// try to connect with the remote host
	int result = network_open( &(*client)->channel );
	if (result != WBERR_OK) goto ESCAPE;
	result = network_connect((*client)->channel, host, port);
	if (result != WBERR_OK) goto ESCAPE;

	(*client)->port = port;
	(*client)->host = (char*) (*client) + sizeof(struct webster_client_t_);
	strcpy((*client)->host, host);
	(*client)->resource = (*client)->host + hostLen + 1;
	strcpy((*client)->resource, resource);
	(*client)->pfd.events = POLLIN;

	return WBERR_OK;

ESCAPE:
	if (*client != NULL)
	{
		if ((*client)->channel != NULL) network_close((*client)->channel);
		free(*client);
		*client = NULL;
	}
	return result;
}


int webster_releaseMessage(
	webster_message_t *message );


int WebsterCommunicate(
    webster_client_t *client,
    webster_handler_t *callback,
    void *data )
{
	struct webster_message_t_ request, response;
	uint8_t *buffers = (uint8_t*) malloc(WEBSTER_MAX_HEADER * 2);
	if (buffers == NULL) return WBERR_MEMORY_EXHAUSTED;

	memset(&request, 0, sizeof(struct webster_message_t_));
	request.channel = (*client)->channel;
	request.buffer.data = buffers;
	request.buffer.size = WEBSTER_MAX_HEADER;
	request.type = WBMT_REQUEST;
	request.header.resource = (*client)->resource;
	request.body.expected = -1;

	memset(&response, 0, sizeof(struct webster_message_t_));
	response.channel = (*client)->channel;
	response.buffer.data = buffers + WEBSTER_MAX_HEADER;
	response.buffer.size = WEBSTER_MAX_HEADER;
	response.type = WBMT_RESPONSE;
	response.body.expected = -1;

	callback(&request, &response, data);

	webster_releaseMessage(&request);
	webster_releaseMessage(&response);
	free(buffers);

	return WBERR_OK;
}


int WebsterDisconnect(
    webster_client_t *client )
{
	network_close((*client)->channel);
	free(*client);
	*client = NULL;
	return WBERR_OK;
}
