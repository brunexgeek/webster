#include "internal.h"
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include "network.h"


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
    "TRACE"
};


WEBSTER_PRIVATE webster_memory_t memory = { NULL, NULL, NULL };


static int webster_releaseMessage(
	webster_message_t *message );


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

	int result = WebsterSetNetworkImpl(net);
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
	WebsterResetNetworkImpl();
	memory.malloc = NULL;
	memory.calloc = NULL;
	memory.free = NULL;

	return WBERR_OK;
}


int WebsterParseURL(
	const char *url,
	int *proto,
	char **host,
	int *port,
	char **resource )
{
	if (url == NULL || url[0] == 0) return WBERR_INVALID_ARGUMENT;

	if (tolower(url[0]) == 'h' &&
		tolower(url[1]) == 't' &&
		tolower(url[2]) == 't' &&
		tolower(url[3]) == 'p' &&
		(tolower(url[4]) == 's' || url[4] == ':'))
	{
		// extract the host name
		char *hb = strstr(url, "://");
		if (hb == NULL) return WBERR_INVALID_URL;
		hb += 3;
		char *he = hb;
		while (*he != ':' && *he != '/' && *he != 0) ++he;
		if (hb == he) return WBERR_INVALID_URL;

		char *rb = he;
		char *re = NULL;

		// extract the port number, if any
		char *pb = he;
		char *pe = NULL;
		if (*pb == ':')
		{
			pe = ++pb;
			while (*pe >= '0' && *pe <= '9') ++pe;
			if (pb == pe || (pe - pb) > 5) return WBERR_INVALID_URL;
			rb = pe;
		}

		// extract the resource
		if (*rb == '/')
		{
			re = ++rb;
			while (*re != 0) ++re;
		}
		if (re != NULL && *re != 0) return WBERR_INVALID_URL;

		// return the protocol
		if (proto != NULL)
		{
			if (url[4] == ':')
				*proto = WBP_HTTP;
			else
				*proto = WBP_HTTPS;
		}

		// return the port number, if any
		if (port != NULL)
		{
			if (pe != NULL)
			{
				*port = 0;
				int mult = 1;
				while (--pe >= pb)
				{
					*port += (int) (*pe - '0') * mult;
					mult *= 10;
				}
				if (*port > 65535) return WBERR_INVALID_URL;
			}
			else
				*port = -1;
		}

		// return the host
		if (host != NULL)
		{
			*host = memory.calloc(1, he - hb + 1);
			if (*host != NULL) strncpy(*host, hb, he - hb);
		}

		// return the resource, if any
		if (resource != NULL)
		{
			if (re != NULL)
			{
				*resource = memory.calloc(1, re - rb + 1);
				if (*resource != NULL) strncpy(*resource, rb, re - rb);
			}
			else
				*resource = NULL;
		}

		return WBERR_OK;
	}

	return WBERR_INVALID_URL;
}


//
// Client API
//


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
	int result = WBNET_OPEN( &(*client)->channel );
	if (result != WBERR_OK) goto ESCAPE;
	result = WBNET_CONNECT((*client)->channel, host, port);
	if (result != WBERR_OK) goto ESCAPE;

	(*client)->port = port;
	(*client)->host = (char*) (*client) + sizeof(struct webster_client_t_);
	strcpy((*client)->host, host);
	(*client)->resource = (*client)->host + hostLen + 1;
	strcpy((*client)->resource, resource);
	(*client)->bufferSize = WEBSTER_MAX_HEADER;

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
    webster_handler_t *callback,
    void *data )
{
	struct webster_message_t_ request, response;
	uint8_t *buffers = (uint8_t*) memory.malloc((*client)->bufferSize * 2);
	if (buffers == NULL) return WBERR_MEMORY_EXHAUSTED;

	memset(&request, 0, sizeof(struct webster_message_t_));
	request.channel = (*client)->channel;
	request.buffer.data = buffers;
	request.buffer.data[0] = 0;
	request.buffer.size = (*client)->bufferSize;
	request.type = WBMT_REQUEST;
	request.header.method = WBM_GET;
	request.body.expected = -1;
	request.header.resource = (*client)->resource;

	memset(&response, 0, sizeof(struct webster_message_t_));
	response.channel = (*client)->channel;
	response.buffer.data = buffers + (*client)->bufferSize;
	response.buffer.data[0] = 0;
	response.buffer.size = (*client)->bufferSize;
	response.type = WBMT_RESPONSE;
	response.header.method = WBM_NONE;
	response.body.expected = -1;

	callback(&request, &response, data);

	webster_releaseMessage(&request);
	webster_releaseMessage(&response);
	memory.free(buffers);

	return WBERR_OK;
}


int WebsterDisconnect(
    webster_client_t *client )
{
	WBNET_CLOSE((*client)->channel);
	memory.free(*client);
	*client = NULL;
	return WBERR_OK;
}


//
// Server API
//



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
	(*server)->bufferSize = WEBSTER_MAX_HEADER;

	return WBERR_OK;
}


int WebsterDestroy(
    webster_server_t *server )
{
	if (server == NULL || *server == NULL) return WBERR_INVALID_ARGUMENT;

	WebsterStop(server);

	if ((*server)->host != NULL) memory.free((*server)->host);
	memory.free(*server);
	*server = NULL;

	return WBERR_OK;
}


int WebsterStart(
	webster_server_t *server,
    const char *host,
    int port )
{
	if (server == NULL || *server == NULL) return WBERR_INVALID_ARGUMENT;

	int result = WBNET_OPEN(&(*server)->channel);
	if (result != WBERR_OK) return result;

	return WBNET_LISTEN((*server)->channel, host, port, (*server)->maxClients);
}


int WebsterStop(
    webster_server_t *server )
{
	if (server == NULL || *server == NULL) return WBERR_INVALID_ARGUMENT;

	WBNET_CLOSE((*server)->channel);
	(*server)->channel = NULL;

	return WBERR_OK;
}


int WebsterAccept(
    webster_server_t *server,
	webster_client_t *remote )
{
	if (server == NULL || remote == NULL) return WBERR_INVALID_ARGUMENT;

	void *client = NULL;
	int result = WBNET_ACCEPT((*server)->channel, &client);
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
	(*remote)->resource = NULL;
	(*remote)->bufferSize = (*server)->bufferSize;

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
		(*server)->bufferSize = (uint32_t) (value & 0x7FFFFFFF);
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
		*value = (int) (*server)->bufferSize;
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


static int webster_receive(
	webster_message_t *input,
	int timeout )
{
	// if we have data in the buffer, just return success
	if (input->buffer.pending > 0) return WBERR_OK;

	// Note: when reading input data we leave room in the buffer for a null-terminator
	//       so we can use the function 'WebsterReadString'.

	// receive new data and adjust pending information
	uint32_t bytes = (uint32_t) input->buffer.size - 1;
	int result = WBNET_RECEIVE(input->channel, input->buffer.data, &bytes, timeout);
	if (result < 0) return result;
	input->buffer.pending = (int) bytes;
	input->buffer.current = input->buffer.data;
	// ensure we have a null-terminator at the end
	*(input->buffer.current + input->buffer.pending) = 0;

	return WBERR_OK;
}


static int webster_writeOrSend(
	webster_message_t *output,
	const uint8_t *buffer,
    int size )
{
	if (size == 0 || buffer == NULL) return WBERR_OK;

	// TODO: change algorithm to always fill the internal buffer before send (keep consistent 'packet' sizes)

	// ensures the current pointer is valid
	if (output->buffer.current == NULL)
		output->buffer.current = output->buffer.data;
	else
	// send any pending data if the given one does not fit the internal buffer
	if (output->buffer.current > output->buffer.data && output->buffer.current + size > output->buffer.data + output->buffer.size)
	{
		WBNET_SEND(output->channel, output->buffer.data, (uint32_t) (output->buffer.current - output->buffer.data));
		output->buffer.current = output->buffer.data;
	}

	// if the data does not fit the internal buffer at all, send immediately;
	// otherwise, copy the data to the intenal buffer
	if (size > (int) output->buffer.size)
		WBNET_SEND(output->channel, buffer, (uint32_t) size);
	else
	{
		memcpy(output->buffer.current, buffer, (size_t) size);
		output->buffer.current += size;
	}

	return WBERR_OK;
}


static int webster_receiveHeader(
	webster_message_t *input )
{
	int result = webster_receive(input, WEBSTER_READ_TIMEOUT);
	if (result != WBERR_OK) return result;

	// no empty line means the HTTP header is longer than WEBSTER_MAX_HEADER
	char *ptr = strstr((char*) input->buffer.data, "\r\n\r\n");
	if (ptr == NULL || (char*) input->buffer.data + WEBSTER_MAX_HEADER < ptr) return WBERR_TOO_LONG;
	*(ptr)     = ' ';
	*(ptr + 1) = ' ';
	*(ptr + 2) = ' ';
	*(ptr + 3) = 0;
	// remember the last position
	input->buffer.current = (uint8_t*) ptr + 4;
	input->buffer.pending = input->buffer.pending - (int) ( (uint8_t*) ptr + 4 - input->buffer.data );

	// parse HTTP header fields and retrieve the content length
	result = http_parseHeader((char*)input->buffer.data, input);
	input->header.contentLength = input->body.expected;
	return result;
}


int WebsterWaitEvent(
    webster_message_t *input,
    webster_event_t *event )
{
	if (input == NULL || event == NULL) return WBERR_INVALID_ARGUMENT;

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
		if (input->body.expected == 0) return WBERR_COMPLETE;

		result = webster_receive(input, WEBSTER_READ_TIMEOUT);
		if (result == WBERR_OK)
		{
			// truncate any extra byte beyond content length
			if (input->body.size + input->buffer.pending > input->body.expected)
			{
				input->buffer.pending = input->body.expected - input->body.size;
				// we still have some data to return?
				if (input->buffer.pending <= 0)
				{
					input->state = WBS_COMPLETE;
					input->buffer.pending = 0;
					return WBERR_NO_DATA;
				}
			}
			event->type = WBT_BODY;
			event->size = input->buffer.pending;
			input->state = WBS_BODY;
			input->body.size += input->buffer.pending;
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
	if (input == NULL || header == NULL) return WBERR_INVALID_ARGUMENT;

	*header = &input->header;

	return WBERR_OK;
}


int WebsterGetStringField(
    webster_message_t *input,
	int id,
	const char *name,
    const char **value )
{
	if (input == NULL || value == 0 || (name == NULL && id != WBFI_NON_STANDARD))
		return WBERR_INVALID_ARGUMENT;
	if (id < 0 || id > WBFI_WWW_AUTHENTICATE)
		return WBERR_INVALID_ARGUMENT;

	if (name != NULL) id = http_getFieldID(name);

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
	if (input == NULL || buffer == NULL || size == NULL) return WBERR_INVALID_ARGUMENT;

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
	if (input == NULL || buffer == NULL) return WBERR_INVALID_ARGUMENT;

	if (input->buffer.pending <= 0 || input->buffer.current == NULL) return WBERR_NO_DATA;

	// the 'webster_receive' function is supposed to put a null-terminator
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
	if (output == NULL) return WBERR_INVALID_ARGUMENT;

	output->header.status = status;

	return WBERR_OK;
}


int WebsterSetMethod(
    webster_message_t *output,
    int method )
{
	if (output == NULL) return WBERR_INVALID_ARGUMENT;

	if (method >= WBM_GET && method <= WBM_TRACE)
		output->header.method = method;

	return WBERR_OK;
}


static int webster_writeStatusLine(
	webster_message_t *output )
{
	if (output == NULL) return WBERR_INVALID_ARGUMENT;
	if (output->state != WBS_IDLE) return WBERR_INVALID_STATE;
	output->state = WBS_HEADER;

	const char *message = NULL;
	if (output->header.status == 0)
	{
		output->header.status = 200;
		message = "OK";
	}
	else
		message = http_statusMessage(output->header.status);

	char temp[128];
	snprintf(temp, sizeof(temp) - 1, "HTTP/1.1 %d %s\r\n", output->header.status, message);
	return webster_writeOrSend(output, (uint8_t*) temp, (int) strlen(temp));
}


static int webster_writeResourceLine(
	webster_message_t *output )
{
	if (output == NULL) return WBERR_INVALID_ARGUMENT;
	if (output->state != WBS_IDLE) return WBERR_INVALID_STATE;
	output->state = WBS_HEADER;

	if (output->header.method < WBM_GET || output->header.method > WBM_TRACE)
		output->header.method = WBM_GET;

	char temp[128];
	snprintf(temp, sizeof(temp) - 1, "%s %s HTTP/1.1\r\n", HTTP_METHODS[output->header.method], output->header.resource);
	return webster_writeOrSend(output, (uint8_t*) temp, (int) strlen(temp));
}


int WebsterSetStringField(
    webster_message_t *output,
    const char *name,
    const char *value )
{
	if (output == NULL || name == NULL || name[0] == 0 || value == NULL) return WBERR_INVALID_ARGUMENT;
	if (output->state >= WBS_BODY) return WBERR_INVALID_STATE;

	int result = WBERR_OK;
	if (output->state == WBS_IDLE)
	{
		if (output->type == WBMT_RESPONSE)
			result = webster_writeStatusLine(output);
		else
			result = webster_writeResourceLine(output);
		if (result != WBERR_OK) return result;
	}

	char temp[128] = { 0 };
	strncpy(temp, name, sizeof(temp) - 1);
	// change the field name to lowercase
    for (char *p = temp; *p; ++p) *p = (char) tolower(*p);
	// remove trailing whitespaces
	name = http_removeTrailing(temp);
	// check if we have any whitespace
	for (const char *p = name; *p != 0; ++p)
		if (*p == ' ') return WBERR_INVALID_HEADER_FIELD;

	// TODO: evaluate field value

	int fid = http_getFieldID(name);
	if (fid == WBFI_CONTENT_LENGTH)
		output->body.expected = atoi(value);

	return http_addField(&output->header, fid, temp, value);
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


static void webster_commitHeaderFields(
    webster_message_t *output )
{
	webster_field_t *field = output->header.fields;
	while (field != NULL)
	{
		const char *name = field->name;
		const char *value = field->value;

		webster_writeOrSend(output, (const uint8_t*) name, (int) strlen(name));
		webster_writeOrSend(output, (const uint8_t*) ": ", 2);
		webster_writeOrSend(output, (const uint8_t*) value, (int) strlen(value));
		webster_writeOrSend(output, (const uint8_t*) "\r\n", 2);

		field = field->next;
	}
	webster_writeOrSend(output, (const uint8_t*)"\r\n", 2);
	output->state = WBS_BODY;
}


int WebsterWriteData(
    webster_message_t *output,
    const uint8_t *buffer,
    int size )
{
	if (output == NULL || buffer == NULL) return WBERR_INVALID_ARGUMENT;
	if (output->state == WBS_COMPLETE) return WBERR_INVALID_STATE;

	int result = 0;

	if (output->state == WBS_IDLE)
	{
		if (output->type == WBMT_RESPONSE)
			result = webster_writeStatusLine(output);
		else
			result = webster_writeResourceLine(output);
		if (result != WBERR_OK) return result;
	}

	if (output->state == WBS_HEADER)
	{
		// if 'content-length' is not specified, we set 'tranfer-encoding' to chunked
		if (output->body.expected < 0)
			WebsterSetStringField(output, "transfer-encoding", "chunked");
		webster_commitHeaderFields(output);
	}

	// ignores empty writes
	if (size <= 0) return WBERR_OK;

	// check whether we're using chuncked transfer encoding
	if (output->body.expected < 0)
	{
		char temp[16];
		snprintf(temp, sizeof(temp) - 1, "%X\r\n", size);
		temp[15] = 0;
		webster_writeOrSend(output, (const uint8_t*) temp, (int) strlen(temp));
	}
	// write data
	webster_writeOrSend(output, buffer, size);
	// append the block terminator, if using chuncked transfer encoding
	if (output->body.expected < 0)
		webster_writeOrSend(output, (const uint8_t*) "\r\n", 2);

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
	if (output == NULL) return WBERR_INVALID_ARGUMENT;

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
	if (output == NULL) return WBERR_INVALID_ARGUMENT;

	WebsterFlush(output);

	// send the last marker if using chunked transfer encoding
	if (output->body.expected < 0)
		WBNET_SEND(output->channel, (const uint8_t*) "0\r\n\r\n", 5);
	// we are done sending data now
	output->state = WBS_COMPLETE;

	return WBERR_OK;
}


WEBSTER_EXPORTED int WebsterGetInputState(
	webster_message_t *input,
    int *state )
{
	if (input == NULL || state == NULL) return WBERR_INVALID_ARGUMENT;

	*state = input->state;

	return WBERR_OK;
}


WEBSTER_EXPORTED int WebsterGetOutputState(
	webster_message_t *output,
    int *state )
{
	if (output == NULL || state == NULL) return WBERR_INVALID_ARGUMENT;

	*state = output->state;

	return WBERR_OK;
}

