//#include <webster/api.h>
#include "internal.h"
#include "network.h"
#include <stdlib.h>
#include <string.h>


static char *duplicate(
	const char *text )
{
	if (text == NULL || text[0] == 0) return NULL;
	size_t size = strlen(text) + 1;
	char *s = (char*) malloc(size);
	if (s != NULL)
	{
		strcpy(s, text);
		s[size - 1] = 0; // to be sure
	}
	return s;
}


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

	*client = (struct webster_client_t_*) calloc(1, sizeof(struct webster_client_t_));
	if (*client == NULL) return WBERR_MEMORY_EXHAUSTED;

	int result = network_open( &(*client)->channel );
	if (result != WBERR_OK) return result;
	result = network_connect((*client)->channel, host, port);
	if (result != WBERR_OK)
	{
		network_close((*client)->channel);
		return result;
	}
	(*client)->port = port;
	(*client)->host = duplicate(host);
	(*client)->resource = duplicate(resource);
	(*client)->pfd.events = POLLIN;

	return WBERR_OK;
}


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

	return WBERR_OK;
}


int WebsterDisconnect(
    webster_client_t *client )
{
	network_close((*client)->channel);
	return WBERR_OK;
}
