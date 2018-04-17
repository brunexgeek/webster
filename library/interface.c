#include "interface.h"

#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <signal.h>
#include <fcntl.h>
#include <errno.h>
#include <stdarg.h>

int WebsterCreate(
    webster_server_t *server,
	int maxClients )
{
	if (server == NULL) return WBERR_INVALID_ARGUMENT;

	if (maxClients <= 0 || maxClients >= WEBSTER_MAX_CONNECTIONS)
		maxClients = WEBSTER_MAX_CONNECTIONS;

	*server = (webster_server_t) calloc(1, sizeof(struct webster_server_t_) +
		sizeof(webster_remote_t) * (size_t) maxClients);
	if (*server == NULL) return WBERR_MEMORY_EXHAUSTED;

	(*server)->socket = -1;
	(*server)->port = -1;
	(*server)->maxClients = maxClients;
	(*server)->remotes = (webster_remote_t*) ((char*) *server + sizeof(struct webster_server_t_));
	(*server)->host = NULL;
	(*server)->handler = NULL;

	for (int i = 0; i < maxClients; ++i)
		(*server)->remotes[i].socket = -1;

	return WBERR_OK;
}


int WebsterDestroy(
    webster_server_t *server )
{
	if (server == NULL || *server == NULL) return WBERR_INVALID_ARGUMENT;

	WebsterStop(server);

	if ((*server)->host != NULL) free((*server)->host);
	free(*server);
	server = NULL;

	return WBERR_OK;
}


static int webster_lookupIPv4(
	const char *host,
	struct sockaddr_in *address )
{
	int result = 0;

	if (address == NULL) return WBERR_INVALID_ARGUMENT;
	if (host == NULL || host[0] == 0) host = "127.0.0.1";

    // get an IPv4 address from hostname
	struct addrinfo aiHints, *aiInfo;
    memset(&aiHints, 0, sizeof(aiHints));
	aiHints.ai_family = AF_INET;
	aiHints.ai_socktype = SOCK_STREAM;
	aiHints.ai_protocol = IPPROTO_TCP;
	result = getaddrinfo( host, NULL, &aiHints, &aiInfo );
	if (result != 0 || aiInfo->ai_addr->sa_family != AF_INET)
	{
		if (result == 0) freeaddrinfo(aiInfo);
		return WBERR_INVALID_ADDRESS;
	}
    // copy address information
    memcpy(address, (struct sockaddr_in*) aiInfo->ai_addr, sizeof(struct sockaddr_in));
	freeaddrinfo(aiInfo);

    return WBERR_OK;
}


int WebsterStart(
	webster_server_t *server,
    const char *host,
    int port )
{
	if (server == NULL || *server == NULL) return WBERR_INVALID_ARGUMENT;

	struct sockaddr_in address;
	webster_lookupIPv4(host, &address);
	(*server)->socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if ((*server)->socket == -1) return WBERR_SOCKET;

	// allow socket descriptor to be reuseable
	int on = 1;
	setsockopt((*server)->socket, SOL_SOCKET,  SO_REUSEADDR, (char *)&on, sizeof(int));

	address.sin_port = htons( (uint16_t) port );
	if (bind((*server)->socket, (const struct sockaddr*) &address, sizeof(const struct sockaddr_in)) != 0)
	{
		close((*server)->socket);
		(*server)->socket = -1;
		return WBERR_SOCKET;
	}

	// listen for incoming connections
	if ( listen((*server)->socket, (*server)->maxClients) != 0 )
	{
		shutdown((*server)->socket, SHUT_RDWR);
		close((*server)->socket);
		(*server)->socket = -1;
		return WBERR_SOCKET;
	}

	return WBERR_OK;
}


int WebsterStop(
    webster_server_t *server )
{
	if (server == NULL || *server == NULL) return WBERR_INVALID_ARGUMENT;

	shutdown((*server)->socket, SHUT_RDWR);
	close((*server)->socket);

	// wait for each worker thread to finish
	for (size_t i = 0; i < (size_t) (*server)->maxClients; ++i)
	{
		webster_remote_t *remote = (*server)->remotes + i;

		if (remote->thread == 0 || remote->socket < 0) continue;

		pthread_join( remote->thread, NULL );
		shutdown( remote->socket, SHUT_RDWR );
		close( remote->socket );

		remote->thread = 0;
		remote->socket = -1;
	}

	return WBERR_OK;
}


int WebsterSetHandler(
    webster_server_t *server,
    const char* mime,
    webster_handler_t *handler )
{
	(void) mime;

	if (server == NULL || *server == NULL || handler == NULL) return WBERR_INVALID_ARGUMENT;

	(*server)->handler = handler;

	return WBERR_OK;
}


static void *webster_thread(
	void *data )
{
	webster_thread_data_t *temp = (webster_thread_data_t*) data;

	printf("[Thread %p] Started\n", data);

	temp->server->handler(&temp->request, &temp->response, temp->data);

	shutdown(temp->remote->socket, SHUT_RDWR);
	close(temp->remote->socket);

	if (temp->request.header.fields != NULL) free(temp->request.header.fields);
	temp->remote->socket = -1;
	temp->remote->thread = 0;
	free(temp);

	printf("[Thread %p] Finished\n", data);

	return NULL;
}


int WebsterAccept(
    webster_server_t *server,
	void *data )
{
	if (server == NULL || *server == NULL) return WBERR_INVALID_ARGUMENT;

	struct sockaddr_in address;
	socklen_t addressLength = sizeof(address);
	int current = accept((*server)->socket, (struct sockaddr *) &address, &addressLength);

	if (current == EAGAIN || current == EWOULDBLOCK)
		return WBERR_NO_CLIENT;
	else
	if (current < 0)
		return WBERR_SOCKET;
	else
	{
		// search for a free slot
		int i = 0;
		for (; i < (*server)->maxClients; ++i)
			if ( (*server)->remotes[i].socket == -1 ) break;

		if (i < (*server)->maxClients)
		{
			webster_thread_data_t *temp = (webster_thread_data_t*) calloc(1, sizeof(webster_thread_data_t));
			if (temp != NULL)
			{
				(*server)->remotes[i].socket = current;

				temp->server = *server;
				temp->remote = (*server)->remotes + i;
				temp->request.socket = temp->remote->socket;
				temp->response.socket = temp->remote->socket;
				temp->data = data;

				int result = pthread_create(&(*server)->remotes[i].thread, NULL, webster_thread, temp);

				if (result != 0)
				{
					free(temp);
					(*server)->remotes[i].socket = -1;
				}
			}
		}

		if (i >= (*server)->maxClients || (*server)->remotes[i].socket == 0)
		{
			shutdown(current, SHUT_RDWR);
			close(current);
		}
	}

	return WBERR_OK;
}


int WebsterWait(
    webster_input_t *input,
    int *type,
    int *size )
{
	if (size == NULL || type == NULL) return WBERR_INVALID_ARGUMENT;

	*size = 0;
	*type = 0;

	uint8_t hasHeader = (input->header.status != 0 || input->header.method != 0);

	if (hasHeader && input->contentLength <= input->received) return WBERR_COMPLETE;

	// check if we need to retrieve more data
	if (hasHeader || input->buffer.pending == 0)
	{
		ssize_t bytes = recv(input->socket, input->buffer.start, sizeof(input->buffer.start), 0);
		if (bytes < 0)
		{
			if (bytes == EWOULDBLOCK || bytes == EAGAIN) return WBERR_NO_DATA;
			printf("Socket error: %s", strerror( (int)bytes));
			return WBERR_SOCKET;
		}
		if (bytes < 0) return WBERR_SOCKET;

		input->received += bytes;
		input->buffer.pending = (int) bytes;
		input->buffer.current = input->buffer.start;
	}

	// check whether we're receiving headers
	if (hasHeader == 0)
	{
		input->contentLength = 0;
		input->received = 0;

		char *ptr = strstr((char*)input->buffer.start, "\r\n\r\n");
		if (ptr == NULL) return WBERR_TOO_LONG;
		*(ptr)     = ' ';
		*(ptr + 1) = ' ';
		*(ptr + 2) = ' ';
		*(ptr + 3) = 0;
		*type = WB_TYPE_HEADER;
		strcpy(input->header.data, (char*) input->buffer.start);
		// remember the last position
		input->buffer.current = (uint8_t*) ptr + 4;
		input->buffer.pending = input->buffer.pending - (int) ( (uint8_t*) ptr + 4 - input->buffer.start );

		// parse HTTP header fields and retrieve the content length
		return http_parseHeader(&input->header, &input->contentLength);
	}
	else
	{
		*type = WB_TYPE_BODY;
		*size = (int) input->buffer.pending;
		return WBERR_OK;
	}

	return WBERR_COMPLETE;
}


int WebsterGetHeaderFields(
    webster_input_t *input,
    const webster_field_t **fields,
    int *count )
{
	if (input == NULL || (fields == NULL && count == NULL)) return WBERR_INVALID_ARGUMENT;

	if (fields != NULL) *fields = (webster_field_t*) input->header.fields;
	if (count != NULL) *count = input->header.count;

	return WBERR_OK;
}


int WebsterGetData(
    webster_input_t *input,
    const uint8_t **buffer,
	int *size )
{
	if (input == NULL || buffer == NULL) return WBERR_INVALID_ARGUMENT;

	if (input->buffer.pending <= 0 || input->buffer.current == NULL) return WBERR_NO_DATA;

	*buffer = input->buffer.current;
	*size = input->buffer.pending;

	input->buffer.current = NULL;
	input->buffer.pending = 0;

	return WBERR_OK;
}


WEBSTER_EXPORTED int WebsterSetStatus(
    webster_output_t *output,
    int status )
{
	if (output == NULL) return WBERR_INVALID_ARGUMENT;

	output->status = status;

	return WBERR_OK;
}


static int webster_writeStatusLine(
	webster_output_t *output )
{
	if (output == NULL) return WBERR_INVALID_ARGUMENT;
	if (output->sent > 0) return WBERR_OK;

	const char *message = http_statusMessage(output->status);
	if (message == NULL)
	{
		output->status = 200;
		message = "OK";
	}

	char buffer[128];
	snprintf(buffer, sizeof(buffer) - 1, "HTTP/1.1 %d %s\r\n", output->status, message);
	int result = (int) send(output->socket, buffer, strlen(buffer), 0);
	if (result < 0) return WBERR_SOCKET;

	output->sent += result;
	return WBERR_OK;
}


WEBSTER_EXPORTED int WebsterWriteHeaderField(
    webster_output_t *output,
    const char *name,
    const char *value )
{
	if (output == NULL || name == NULL || name[0] == 0 || value == NULL) return WBERR_INVALID_ARGUMENT;

	int result = WBERR_OK;
	if (output->sent == 0)
	{
		result = webster_writeStatusLine(output);
		if (result != WBERR_OK) return result;
	}

	for (const char *p = name; *p != 0; ++p)
		if (*p == ' ') return WBERR_BAD_RESPONSE;

	// TODO: evaluate field value

	snprintf(output->temp, sizeof(output->temp) - 1, "%s: %s\r\n", name, value);
	result = (int) send(output->socket, output->temp, strlen(output->temp), 0);
	if (result < 0) return WBERR_SOCKET;

	return WBERR_OK;
}


WEBSTER_EXPORTED int WebsterWriteData(
    webster_output_t *output,
    const uint8_t *buffer,
    int size )
{
	(void) buffer;
	(void) size;

	int result = (int) send(output->socket, buffer, size, 0);
	if (result < 0) return WBERR_SOCKET;

	return WBERR_OK;
}


int WebsterWriteString(
    webster_output_t *output,
    const char *format,
    ... )
{
	if (output == NULL || format == NULL) return WBERR_INVALID_ARGUMENT;

	va_list args;
	va_start(args, format);
	size_t length = snprintf(output->temp, sizeof(output->temp) - 1, format, args);
	va_end(args);

	return WebsterWriteData(output, output->temp, length);
}


int WebsterFree(
    void *ptr )
{
	(void) ptr;

	return WBERR_OK;
}