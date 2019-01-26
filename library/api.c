#include "internal.h"
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include "network.h"

#ifndef WB_WINDOWS
#include <sys/time.h>
#endif


static const char *HTTP_METHODS[] =
{
    "",
    "GET",
    "HEAD",
    "POST",
    "PUT",
    "DELETE",
    "CONNECT",
    "OPTIONS",
    "TRACE",
	"PATCH",
};


WEBSTER_PRIVATE webster_memory_t memory = { NULL, NULL, NULL };


static int webster_releaseMessage(
	webster_message_t *message );


static char *cloneString(
    const char *text )
{
    if (text == NULL) return NULL;
    size_t len = strlen(text);
    char *clone = (char*) malloc(len + 1);
    strcpy(clone, text);
    return clone;
}


int WebsterInitialize(
    webster_memory_t *mem,
	webster_network_t *net )
{
	if (mem != NULL && (mem->malloc == NULL || mem->free == NULL))
		return WBERR_INVALID_ARGUMENT;

	if (mem != NULL)
	{
		memory.malloc = mem->malloc;
		memory.calloc = mem->calloc;
		memory.free = mem->free;
	}
	else
	{
		memory.malloc = malloc;
		memory.calloc = calloc;
		memory.free = free;
	}

	int result = network_setImpl(net);
	if (result != WBERR_OK) goto ESCAPE;
	result = WBNET_INITIALIZE(&memory);
	if (result != WBERR_OK) goto ESCAPE;

	return WBERR_OK;
ESCAPE:
	WebsterTerminate();
	return result;
}


int WebsterTerminate()
{
	if (WBNET_TERMINATE != NULL) WBNET_TERMINATE();
	network_resetImpl();
	memory.malloc = NULL;
	memory.calloc = NULL;
	memory.free = NULL;

	return WBERR_OK;
}


int WebsterParseURL(
	const char *url,
	webster_target_t **target )
{
	return http_parseTarget(url, target);
}


int WebsterFreeURL(
    webster_target_t *target )
{
	return http_freeTarget(target);
}


//
// Client API
//


int WebsterConnect(
    webster_client_t **client,
    int scheme,
	const char *host,
    int port )
{
	if (client == NULL)
		return WBERR_INVALID_CLIENT;
	if (port < 0 || port > 0xFFFF)
		return WBERR_INVALID_PORT;
	if (host == NULL || host[0] == 0)
		return WBERR_INVALID_HOST;
	if (!WB_IS_VALID_SCHEME(scheme))
		return WBERR_INVALID_SCHEME;

	// allocate memory for everything
	*client = (struct webster_client_t_*) memory.calloc(1, sizeof(struct webster_client_t_));
	if (*client == NULL) return WBERR_MEMORY_EXHAUSTED;

	// try to connect with the remote host
	int result = WBNET_OPEN( &(*client)->channel );
	if (result != WBERR_OK) goto ESCAPE;
	result = WBNET_CONNECT((*client)->channel, scheme, host, port);
	if (result != WBERR_OK) goto ESCAPE;

	(*client)->host       = cloneString(host);
	(*client)->port       = port;
	(*client)->bufferSize = WBL_DEF_BUFFER_SIZE;

	return WBERR_OK;

ESCAPE:
	if (*client != NULL)
	{
		if ((*client)->channel != NULL) WBNET_CLOSE((*client)->channel);
		memory.free(*client);
		*client = NULL;
	}
	return result;
}


int WebsterCommunicate(
    webster_client_t *client,
    char *path,
    char *query,
    webster_handler_t *callback,
    void *data )
{
	webster_target_t url;
	url.type = WBRT_ORIGIN;
	url.path = path;
	url.query = query;
	return WebsterCommunicateURL(client, &url, callback, data);
}


int WebsterCommunicateURL(
    webster_client_t *client,
    webster_target_t *url,
    webster_handler_t *callback,
    void *data )
{
	if (client == NULL) return WBERR_INVALID_CLIENT;
	if (callback == NULL) return WBERR_INVALID_ARGUMENT;
	//if (url == NULL || !WB_IS_VALID_URL(url->type)) return WBERR_INVALID_URL;

	struct webster_message_t_ request, response;
	uint8_t *buffers = (uint8_t*) memory.malloc(client->bufferSize * 2);
	if (buffers == NULL) return WBERR_MEMORY_EXHAUSTED;

	memset(&request, 0, sizeof(struct webster_message_t_));
	request.type = WBMT_REQUEST;
	request.channel = client->channel;
	request.buffer.data = buffers;
	request.buffer.data[0] = 0;
	request.buffer.size = (int) client->bufferSize;
	request.header.method = WBM_GET;
	request.client = client;
	request.header.target = url;

	memset(&response, 0, sizeof(struct webster_message_t_));
	response.type = WBMT_RESPONSE;
	response.channel = client->channel;
	response.buffer.data = buffers + client->bufferSize;
	response.buffer.data[0] = 0;
	response.buffer.size = (int) client->bufferSize;
	response.header.method = WBM_NONE;
	response.client = client;
	response.header.target = url;

	callback(&request, &response, data);

	if (request.header.target != url) http_freeTarget(request.header.target);
	if (response.header.target != url) http_freeTarget(response.header.target);

	webster_releaseMessage(&request);
	webster_releaseMessage(&response);
	memory.free(buffers);

	return WBERR_OK;
}


int WebsterDisconnect(
    webster_client_t *client )
{
	if (client == NULL) return WBERR_INVALID_CLIENT;

	WBNET_CLOSE(client->channel);
	memory.free(client->host);
	memory.free(client);
	return WBERR_OK;
}


//
// Server API
//



int WebsterCreate(
    webster_server_t **server,
	int maxClients )
{
	if (server == NULL) return WBERR_INVALID_SERVER;

	if (maxClients <= 0 || maxClients >= WBL_MAX_CONNECTIONS)
		maxClients = WBL_MAX_CONNECTIONS;

	*server = (webster_server_t*) calloc(1, sizeof(struct webster_server_t_));
	if (*server == NULL) return WBERR_MEMORY_EXHAUSTED;

	(*server)->channel = NULL;
	(*server)->port = -1;
	(*server)->host = NULL;
	(*server)->bufferSize = WBL_DEF_BUFFER_SIZE;

	return WBERR_OK;
}


int WebsterDestroy(
    webster_server_t *server )
{
	if (server == NULL) return WBERR_INVALID_SERVER;

	WebsterStop(server);

	if (server->host != NULL) memory.free(server->host);
	memory.free(server);

	return WBERR_OK;
}


int WebsterStart(
	webster_server_t *server,
    const char *host,
    int port )
{
	if (server == NULL) return WBERR_INVALID_SERVER;

	int result = WBNET_OPEN(&server->channel);
	if (result != WBERR_OK) return result;

	return WBNET_LISTEN(server->channel, host, port, server->maxClients);
}


int WebsterStop(
    webster_server_t *server )
{
	if (server == NULL) return WBERR_INVALID_SERVER;

	WBNET_CLOSE(server->channel);
	server->channel = NULL;

	return WBERR_OK;
}


int WebsterAccept(
    webster_server_t *server,
	webster_client_t **remote )
{
	if (server == NULL) return WBERR_INVALID_SERVER;
	if (remote == NULL) return WBERR_INVALID_CLIENT;

	void *client = NULL;
	int result = WBNET_ACCEPT(server->channel, &client);
	if (result != WBERR_OK) return result;

	*remote = (struct webster_client_t_*) calloc(1, sizeof(struct webster_client_t_));
	if (*remote == NULL)
	{
		WBNET_CLOSE(client);
		return WBERR_MEMORY_EXHAUSTED;
	}

	(*remote)->channel = client;
	(*remote)->port = 0;
	(*remote)->host = NULL;
	(*remote)->bufferSize = server->bufferSize;

	return WBERR_OK;
}


int WebsterSetOption(
	webster_server_t *server,
    int option,
    int value )
{
	if (server == NULL) return WBERR_INVALID_SERVER;

	if (option == WBO_BUFFER_SIZE)
	{
		if (value < WBL_MIN_BUFFER_SIZE || value > WBL_MAX_BUFFER_SIZE) value = WBL_DEF_BUFFER_SIZE;
		server->bufferSize = (uint32_t) (value & 0x7FFFFFFF);
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
	if (server == NULL) return WBERR_INVALID_SERVER;
	if (value == NULL) return WBERR_INVALID_ARGUMENT;

	if (option == WBO_BUFFER_SIZE)
		*value = (int) server->bufferSize;
	else
		return WBERR_INVALID_ARGUMENT;

	return WBERR_OK;
}


//
// Request and response API
//


static int webster_releaseMessage(
	webster_message_t *message )
{
	if (message == NULL) return WBERR_INVALID_ARGUMENT;
	http_releaseFields(&message->header);

	return WBERR_OK;
}


static size_t webster_getTime()
{
	struct timeval info;
	gettimeofday(&info, NULL);
	return (size_t) (info.tv_usec / 1000 + info.tv_sec * 1000);
}


/**
 * @brief Read data from the network channel until the buffer is full or there's
 * no more data to read.
 */
static int webster_receive(
	webster_message_t *input,
	int timeout,
	int isHeader )
{
	// if we have data in the buffer, just return success
	if (input->buffer.pending > 0) return WBERR_OK;
	input->buffer.pending = 0;

	// Note: when reading input data we leave room in the buffer for a null-terminator
	//       so we can use the function 'WebsterReadString'.

	// when reading header data, we have 'timeout' milliseconds to receive the
	// entire HTTP header
	int recvTimeout = (timeout >= 0) ? timeout : 0;
	if (isHeader) recvTimeout = 50;

	size_t startTime = webster_getTime();

	while (input->buffer.pending < input->buffer.size)
	{
		uint32_t bytes = (uint32_t) input->buffer.size - (uint32_t) input->buffer.pending - 1;
		// receive new data and adjust pending information
		int result = WBNET_RECEIVE(input->channel, input->buffer.data + input->buffer.pending, &bytes, recvTimeout);
		// only keep trying if receiving header data
		if (result == WBERR_TIMEOUT && isHeader) continue;

		if (result == WBERR_OK)
		{
			input->buffer.pending += (int) bytes;
			input->buffer.current = input->buffer.data;
			// ensure we have a null-terminator at the end
			*(input->buffer.current + input->buffer.pending) = 0;

			if (isHeader)
			{
				if (strstr((char*)input->buffer.current, "\r\n\r\n") != NULL) return WBERR_OK;
				if (webster_getTime() - startTime > (size_t)timeout) return WBERR_TIMEOUT;
			}
			else
				return WBERR_OK;
		}
		else
			return result;
	}

	return WBERR_OK;
}


static int webster_writeBuffer(
	webster_message_t *output,
	const uint8_t *buffer,
    int size )
{
	if (output == NULL) return WBERR_INVALID_MESSAGE;
	if (size == 0 || buffer == NULL) return WBERR_OK;

	// ensures the current pointer is valid
	if (output->buffer.current == NULL)
	{
		output->buffer.current = output->buffer.data;
		output->buffer.pending = 0;
	}

	// fragment input data through recursive calls until the data size fits the internal buffer
	int offset = 0;
	int result = WBERR_OK;
	int fit = output->buffer.size - (int)(output->buffer.current - output->buffer.data);
	while (size > fit)
	{
		result = webster_writeBuffer(output, buffer + offset, fit);
		size -= fit;
		offset += fit;
		fit = output->buffer.size - (int)(output->buffer.current - output->buffer.data);
		if (result != WBERR_OK) return result;
	}

	memcpy(output->buffer.current, buffer + offset, (size_t) size);
	output->buffer.current += size;

	// send pending data if the buffer is full
	if (output->buffer.current >= output->buffer.data + output->buffer.size)
	{
		result = WBNET_SEND(output->channel, output->buffer.data, (uint32_t) output->buffer.size);
		output->buffer.current = output->buffer.data;
	}

	return result;
}


static int webster_writeString(
	webster_message_t *output,
	const char *text )
{
	if (text == NULL) return WBERR_INVALID_ARGUMENT;
	return webster_writeBuffer(output, (uint8_t*) text, (int) strlen(text));
}


static int webster_writeChar(
	webster_message_t *output,
	char value )
{
	return webster_writeBuffer(output, (uint8_t*) &value, 1);
}


static int webster_writeInteger(
	webster_message_t *output,
	int value )
{
	if (output == NULL) return WBERR_INVALID_MESSAGE;
	char temp[16] = { 0 };
	snprintf(temp, sizeof(temp) - 1, "%d", value);
	return webster_writeBuffer(output, (uint8_t*) temp, (int) strlen(temp));
}


static int webster_receiveHeader(
	webster_message_t *input )
{
	int result = webster_receive(input, WBL_READ_TIMEOUT, 1);
	if (result != WBERR_OK) return result;

	// no empty line means the HTTP header is longer than WEBSTER_MAX_HEADER
	char *ptr = strstr((char*) input->buffer.data, "\r\n\r\n");
	if (ptr == NULL) return WBERR_TOO_LONG;
	*(ptr + 3) = 0;
	// remember the last position
	input->buffer.current = (uint8_t*) ptr + 4;
	input->buffer.pending = input->buffer.pending - (int) ( (uint8_t*) ptr + 4 - input->buffer.data );

	// parse HTTP header fields and retrieve the content length
	result = http_parse((char*)input->buffer.data, input->type, input);
	input->header.contentLength = input->body.expected;
	return result;
}


int WebsterWaitEvent(
    webster_message_t *input,
    webster_event_t *event )
{
	if (input == NULL) return WBERR_INVALID_MESSAGE;
	if (event == NULL) return WBERR_INVALID_ARGUMENT;

	event->size = 0;
	event->type = 0;
	int result = 0;

	if (input->state == WBS_IDLE)
	{
		result = webster_receiveHeader(input);
		if (result == WBERR_OK)
		{
			event->type = WBT_HEADER;
			event->size = (int) strlen((char*)input->buffer.data) + 1;
			input->state = WBS_HEADER;
		}
		return result;
	}
	else
	if (input->state == WBS_HEADER || input->state == WBS_BODY)
	{
		if (input->body.expected == 0)
		{
			input->state = WBS_COMPLETE;
			return WBERR_COMPLETE;
		}

		// TODO: should not receive more data than expected
		result = webster_receive(input, WBL_READ_TIMEOUT, 0);
		if (result == WBERR_OK)
		{
			// truncate any extra bytes beyond content length
			if (input->body.expected >= 0 && input->buffer.pending > input->body.expected)
			{
				input->buffer.pending = input->body.expected;
				input->buffer.data[input->buffer.pending] = 0;
				// we still have some data to return?
				if (input->buffer.pending == 0)
				{
					input->state = WBS_COMPLETE;
					return WBERR_COMPLETE;
				}
			}
			event->type = WBT_BODY;
			event->size = input->buffer.pending;
			input->state = WBS_BODY;
			input->body.expected -= input->buffer.pending;
		}

		return result;
	}

	return WBERR_COMPLETE;
}


int WebsterGetHeader(
    webster_message_t *input,
    const webster_header_t **header )
{
	if (input == NULL) return WBERR_INVALID_MESSAGE;
	if (header == NULL) return WBERR_INVALID_ARGUMENT;

	*header = &input->header;

	return WBERR_OK;
}


int WebsterGetStringField(
    webster_message_t *input,
	int id,
	const char *name,
    const char **value )
{
	if (input == NULL) return WBERR_INVALID_MESSAGE;
	if (value == 0 || (name == NULL && id == WBFI_NON_STANDARD))
		return WBERR_INVALID_ARGUMENT;
	if (id < 0 || id > WBFI_WWW_AUTHENTICATE)
		return WBERR_INVALID_ARGUMENT;

	if (name != NULL)
	{
		id = WBFI_NON_STANDARD;
		webster_field_info_t *finfo = http_getFieldID(name);
		if (finfo != NULL) id = finfo->id;
	}

	const webster_field_t *field = NULL;
	if (id == WBFI_NON_STANDARD)
		field = http_getFieldByName(&input->header, name);
	else
		field = http_getFieldById(&input->header, id);

	if (field == NULL) return WBERR_NO_DATA;
	*value = field->value;
	return WBERR_OK;
}


int WebsterGetIntegerField(
    webster_message_t *input,
    int id,
    const char *name,
    int *value )
{
	const char *temp = NULL;
	int result = WebsterGetStringField(input, id, name, &temp);
	if (result != WBERR_OK) return result;

	*value = atoi(temp);
	return WBERR_OK;
}


int WebsterReadData(
    webster_message_t *input,
    const uint8_t **buffer,
	int *size )
{
	if (input == NULL) return WBERR_INVALID_MESSAGE;
	if (buffer == NULL || size == NULL) return WBERR_INVALID_ARGUMENT;

	if (input->buffer.pending <= 0 || input->buffer.current == NULL) return WBERR_NO_DATA;

	*buffer = input->buffer.current;
	*size = input->buffer.pending;

	input->buffer.current = NULL;
	input->buffer.pending = 0;

	return WBERR_OK;
}


int WebsterReadString(
    webster_message_t *input,
    const char **buffer )
{
	if (input == NULL) return WBERR_INVALID_MESSAGE;
	if (buffer == NULL) return WBERR_INVALID_ARGUMENT;

	if (input->buffer.pending <= 0 || input->buffer.current == NULL) return WBERR_NO_DATA;

	// the function 'webster_receive' is supposed to put a null-terminator
	// at the end of the data, but we want to be sure (better safe than sorry)
	*(input->buffer.current + input->buffer.pending) = 0;
	*buffer = (char*) input->buffer.current;

	input->buffer.current = NULL;
	input->buffer.pending = 0;

	return WBERR_OK;
}


int WebsterSetStatus(
    webster_message_t *output,
    int status )
{
	if (output == NULL) return WBERR_INVALID_MESSAGE;
	output->header.status = status;
	return WBERR_OK;
}


int WebsterSetMethod(
    webster_message_t *output,
    int method )
{
	if (output == NULL) return WBERR_INVALID_MESSAGE;
	if (!WB_IS_VALID_METHOD(method)) return WBERR_INVALID_HTTP_METHOD;
	output->header.method = method;
	return WBERR_OK;
}


static int webster_writeStatusLine(
	webster_message_t *output )
{
	if (output == NULL) return WBERR_INVALID_MESSAGE;
	if (output->state != WBS_IDLE) return WBERR_INVALID_STATE;
	output->state = WBS_HEADER;

	const char *message = NULL;
	if (output->header.status == 0)
		output->header.status = 200;

	message = http_statusMessage(output->header.status);

	webster_writeString(output, "HTTP/1.1 ");
	webster_writeInteger(output, output->header.status);
	webster_writeChar(output, ' ');
	webster_writeString(output, message);
	webster_writeString(output, "\r\n");
	return WBERR_OK;
}


static int webster_writeResourceLine(
	webster_message_t *output )
{
	if (output == NULL) return WBERR_INVALID_MESSAGE;
	if (output->state != WBS_IDLE) return WBERR_INVALID_STATE;
	output->state = WBS_HEADER;

	if (!WB_IS_VALID_METHOD(output->header.method))
		output->header.method = WBM_GET;

	webster_writeString(output, HTTP_METHODS[output->header.method]);
	webster_writeChar(output, ' ');

	switch (output->header.target->type)
	{
		case WBRT_ABSOLUTE:
			if (output->header.target->scheme == WBP_HTTPS)
				webster_writeString(output, "https://");
			else
				webster_writeString(output, "http://");
			webster_writeString(output, output->header.target->host);
			webster_writeChar(output, ':');
			webster_writeInteger(output, output->header.target->port);
			if (output->header.target->path[0] != '/')
				webster_writeChar(output, '/');
			webster_writeString(output, output->header.target->path);
			if (output->header.target->query != NULL)
			{
				webster_writeChar(output, '&');
				webster_writeString(output, output->header.target->query);
			}
			break;
		case WBRT_ORIGIN:
			webster_writeString(output, output->header.target->path);
			if (output->header.target->query != NULL)
			{
				webster_writeChar(output, '&');
				webster_writeString(output, output->header.target->query);
			}
			break;
		case WBRT_ASTERISK:
			webster_writeChar(output, '*');
			break;
		case WBRT_AUTHORITY:
			webster_writeString(output, output->header.target->host);
			webster_writeChar(output, ':');
			webster_writeInteger(output, output->header.target->port);
			break;
		default:
			return WBERR_INVALID_RESOURCE;
	}

	webster_writeString(output, " HTTP/1.1\r\n");

	return WBERR_OK;
}


static int webster_commitFirstLine(
	webster_message_t *output )
{
	int result;

	if (output->type == WBMT_RESPONSE)
		result = webster_writeStatusLine(output);
	else
		result = webster_writeResourceLine(output);
	if (result != WBERR_OK) return result;
	output->state = WBS_HEADER;

	return WBERR_OK;
}


int WebsterSetStringField(
    webster_message_t *output,
    const char *name,
    const char *value )
{
	if (output == NULL) return WBERR_INVALID_MESSAGE;
	if (name == NULL || name[0] == 0 || value == NULL) return WBERR_INVALID_ARGUMENT;
	if (output->state >= WBS_BODY) return WBERR_INVALID_STATE;

	int result = WBERR_OK;
	if (output->state == WBS_IDLE)
	{
		result = webster_commitFirstLine(output);
		if (result != WBERR_OK) return result;
	}

	// TODO: evaluate field value

	webster_field_info_t *finfo = http_getFieldID(name);
	if (finfo != NULL && finfo->id == WBFI_CONTENT_LENGTH)
		output->body.expected = atoi(value);

	if (finfo != NULL)
		return http_addFieldById(&output->header, finfo->id, value);
	else
		return http_addFieldByName(&output->header, name, value);
}


int WebsterSetIntegerField(
    webster_message_t *output,
    const char *name,
    int value )
{
	char temp[12];
	snprintf(temp, sizeof(temp) - 1, "%d", value);
	return WebsterSetStringField(output, name, temp);
}


int WebsterRemoveField(
    webster_message_t *output,
    const char *name )
{
	if (output == NULL) return WBERR_INVALID_MESSAGE;
	if (name == NULL) return WBERR_INVALID_ARGUMENT;

	http_removeField(&output->header, name);
	return WBERR_OK;
}


static void webster_commitHeaderFields(
    webster_message_t *output )
{
	webster_field_t *field = output->header.fields;
	while (field != NULL)
	{
		webster_writeString(output, field->name);
		webster_writeString(output, ": ");
		webster_writeString(output, field->value);
		webster_writeString(output, "\r\n");
		field = field->next;
	}
	webster_writeBuffer(output, (const uint8_t*)"\r\n", 2);
	output->state = WBS_BODY;
}


int WebsterWriteData(
    webster_message_t *output,
    const uint8_t *buffer,
    int size )
{
	if (output == NULL) return WBERR_INVALID_MESSAGE;
	if (buffer == NULL) return WBERR_INVALID_ARGUMENT;
	if (output->state == WBS_COMPLETE) return WBERR_INVALID_STATE;

	int result = 0;

	if (output->state == WBS_IDLE)
	{
		result = webster_commitFirstLine(output);
		if (result != WBERR_OK) return result;
	}

	if (output->state == WBS_HEADER)
	{
		// set 'tranfer-encoding' to chunked if required
		if (http_getFieldById(&output->header, WBFI_CONTENT_LENGTH) == NULL)
		{
			output->flags |= WBMF_CHUNKED;
			// TODO: merge with previously set value, if any
			WebsterSetStringField(output, "transfer-encoding", "chunked");
		}
		if (output->type == WBMT_REQUEST &&
			http_getFieldById(&output->header, WBFI_HOST) == NULL &&
			output->client != NULL)
		{
			static const size_t HOST_LEN = WBL_MAX_HOST_NAME + 1 + 5; // host + ':' + port
			char host[HOST_LEN + 1];
			snprintf(host, HOST_LEN, "%s:%d", output->client->host, output->client->port);
			host[HOST_LEN] = 0;
			WebsterSetStringField(output, "host", host);
		}
		webster_commitHeaderFields(output);
	}

	// ignores empty writes
	if (size <= 0) return WBERR_OK;

	// check whether we're using chuncked transfer encoding
	if (output->flags & WBMF_CHUNKED)
	{
		char temp[16];
		snprintf(temp, sizeof(temp) - 1, "%X\r\n", size);
		temp[15] = 0;
		webster_writeBuffer(output, (const uint8_t*) temp, (int) strlen(temp));
	}
	// write data
	webster_writeBuffer(output, buffer, size);
	// append the block terminator, if using chuncked transfer encoding
	if (output->flags & WBMF_CHUNKED)
		webster_writeBuffer(output, (const uint8_t*) "\r\n", 2);

	return WBERR_OK;
}


WEBSTER_EXPORTED int WebsterWriteString(
    webster_message_t *output,
    const char *text )
{
	return WebsterWriteData(output, (uint8_t*) text, (int) strlen(text));
}


int WebsterFlush(
	webster_message_t *output )
{
	if (output == NULL) return WBERR_INVALID_MESSAGE;
	if (output->state == WBS_COMPLETE) return WBERR_INVALID_STATE;

	// ensure we are done with the HTTP header
	if (output->state != WBS_BODY)
		WebsterWriteData(output, (uint8_t*) "", 0);
	// send all remaining body data
	if (output->buffer.current > output->buffer.data)
	{
		WBNET_SEND(output->channel, output->buffer.data, (uint32_t) (output->buffer.current - output->buffer.data));
		output->buffer.current = output->buffer.data;
	}

	return WBERR_OK;
}


int WebsterFinish(
	webster_message_t *output )
{
	if (output == NULL) return WBERR_INVALID_MESSAGE;
	if (output->state == WBS_COMPLETE) return WBERR_INVALID_STATE;

	WebsterFlush(output);

	// send the last marker if using chunked transfer encoding
	if (output->flags & WBMF_CHUNKED)
		WBNET_SEND(output->channel, (const uint8_t*) "0\r\n\r\n", 5);
	// we are done sending data now
	output->state = WBS_COMPLETE;

	return WBERR_OK;
}


WEBSTER_EXPORTED int WebsterGetState(
	webster_message_t *message,
    int *state )
{
	if (message == NULL) return WBERR_INVALID_MESSAGE;
	if (state == NULL) return WBERR_INVALID_ARGUMENT;

	*state = message->state;

	return WBERR_OK;
}
