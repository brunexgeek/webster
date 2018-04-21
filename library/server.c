#include "internal.h"
#include "network.h"
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>


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
	(*server)->pfd.events = POLLIN;

	(*server)->options.bufferSize = HTTP_MAX_HEADER;

	if (pthread_mutex_init(&(*server)->mutex, NULL) != 0)
	{
		free(*server);
		return WBERR_MEMORY_EXHAUSTED;
	}

	for (int i = 0; i < maxClients; ++i)
		(*server)->remotes[i].socket = -1;

	return WBERR_OK;
}


int WebsterDestroy(
    webster_server_t *server )
{
	if (server == NULL || *server == NULL) return WBERR_INVALID_ARGUMENT;

	WebsterStop(server);

	pthread_mutex_destroy(&(*server)->mutex);
	if ((*server)->host != NULL) free((*server)->host);
	free(*server);
	server = NULL;

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

	(*server)->pfd.fd = (*server)->socket;

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

		pthread_mutex_lock(&(*server)->mutex);
		int ignore = remote->thread == 0 || remote->socket < 0;
		pthread_mutex_unlock(&(*server)->mutex);

		if (ignore) continue;

		// TODO: set variable to escape the thread loop
		pthread_join( remote->thread, NULL );
		shutdown( remote->socket, SHUT_RDWR );
		close( remote->socket );

		pthread_mutex_lock(&(*server)->mutex);
		remote->thread = 0;
		remote->socket = -1;
		pthread_mutex_unlock(&(*server)->mutex);
	}

	return WBERR_OK;
}


static void *webster_thread(
	void *data )
{
	webster_thread_data_t *temp = (webster_thread_data_t*) data;

	printf("[Thread %p] Started\n", data);

	temp->handler(&temp->request, &temp->response, temp->data);

	WebsterFlush(&temp->response);
	if (temp->response.body.expected <= 0)
		send(temp->response.socket, "0\r\n\r\n", 5, MSG_NOSIGNAL);

	shutdown(temp->remote->socket, SHUT_RDWR);
	close(temp->remote->socket);

	if (temp->request.header.fields != NULL) free(temp->request.header.fields);

	pthread_mutex_lock(&(temp->server)->mutex);
	pthread_t thread = temp->remote->thread;
    temp->remote->thread = 0;
	temp->remote->socket = -1;
	pthread_mutex_unlock(&(temp->server)->mutex);

	free(temp);
	pthread_detach(thread);

	printf("[Thread %p] Finished\n", data);

	return NULL;
}


int WebsterAccept(
    webster_server_t *server,
	webster_handler_t *handler,
	void *data )
{
	if (server == NULL || *server == NULL || handler == NULL) return WBERR_INVALID_ARGUMENT;

	int result = poll(&(*server)->pfd, 1, 1000);
	if (result == 0)
		return WBERR_TIMEOUT;
	else
	if (result < 0)
		return WBERR_SOCKET;

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
			webster_thread_data_t *temp = (webster_thread_data_t*) calloc(1,
				sizeof(webster_thread_data_t) + (size_t) (*server)->options.bufferSize * 2 );
			if (temp != NULL)
			{
				(*server)->remotes[i].socket = current;

				temp->server = *server;
				temp->remote = (*server)->remotes + i;
				temp->handler = handler;
				temp->data = data;

				temp->request.socket = temp->remote->socket;
				temp->request.pfd.events = POLLIN;
				temp->request.pfd.fd = temp->remote->socket;
				temp->request.buffer.data = (uint8_t*) temp + sizeof(webster_thread_data_t);
				temp->request.buffer.size = (size_t) (*server)->options.bufferSize;

				temp->response.buffer.data = temp->request.buffer.data + temp->request.buffer.size;
				temp->response.buffer.size = (size_t) (*server)->options.bufferSize;
				temp->response.socket = temp->remote->socket;

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


int WebsterSetOption(
	webster_server_t *server,
    int option,
    int value )
{
	if (server == NULL || *server == NULL) return WBERR_INVALID_ARGUMENT;

	if (option == WBO_BUFFER_SIZE)
	{
		value *= 1024;
		if (value < 1024 || value > 1024 * 1024 * 10) value = WEBSTER_MAX_HEADER;
		(*server)->options.bufferSize = value;
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
		*value = (*server)->options.bufferSize;
	else
		return WBERR_INVALID_ARGUMENT;

	return WBERR_OK;
}