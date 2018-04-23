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

	*server = (webster_server_t) calloc(1, sizeof(struct webster_server_t_) +
		sizeof(webster_remote_t) * (size_t) maxClients);
	if (*server == NULL) return WBERR_MEMORY_EXHAUSTED;

	(*server)->channel = NULL;
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
		(*server)->remotes[i].channel = NULL;

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

	int result = network_open(&(*server)->channel);
	if (result != WBERR_OK) return result;

	return network_listen((*server)->channel, host, port, (*server)->maxClients);
}


int WebsterStop(
    webster_server_t *server )
{
	if (server == NULL || *server == NULL) return WBERR_INVALID_ARGUMENT;

	network_close((*server)->channel);

	// wait for each worker thread to finish
	for (size_t i = 0; i < (size_t) (*server)->maxClients; ++i)
	{
		webster_remote_t *remote = (*server)->remotes + i;

		pthread_mutex_lock(&(*server)->mutex);
		int ignore = remote->thread == 0 || remote->channel == NULL;
		pthread_mutex_unlock(&(*server)->mutex);

		if (ignore) continue;

		// TODO: set variable to escape the thread loop
		pthread_join( remote->thread, NULL );
		network_close(remote->channel);

		pthread_mutex_lock(&(*server)->mutex);
		remote->thread = 0;
		remote->channel = NULL;
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
		network_send(temp->response.channel, (const uint8_t*) "0\r\n\r\n", 5);

	network_close(temp->remote->channel);

	pthread_mutex_lock(&(temp->server)->mutex);
	pthread_t thread = temp->remote->thread;
    temp->remote->thread = 0;
	temp->remote->channel = NULL;
	pthread_mutex_unlock(&(temp->server)->mutex);

	webster_releaseMessage(&temp->request);
	webster_releaseMessage(&temp->response);
	free(temp);
	pthread_detach(thread);

	printf("[Thread %p] Finished\n", data);

	return NULL;
}


static int webster_nextSlot(
	webster_server_t *server )
{
	int i = 0;
	for (; i < (*server)->maxClients; ++i)
		if ( (*server)->remotes[i].channel == NULL ) break;
	if (i >= (*server)->maxClients) return WBERR_MAX_CLIENTS;

	return i;
}


int WebsterAccept(
    webster_server_t *server,
	webster_handler_t *handler,
	void *data )
{
	if (server == NULL || *server == NULL || handler == NULL) return WBERR_INVALID_ARGUMENT;

	int i = webster_nextSlot(server);
	if (i < 0) return i;

	void *client = NULL;
	int result = network_accept((*server)->channel, &client);
	if (result != WBERR_OK) return result;

	webster_thread_data_t *temp = (webster_thread_data_t*) calloc(1,
		sizeof(webster_thread_data_t) + (size_t) (*server)->options.bufferSize * 2 );
	if (temp != NULL)
	{
		(*server)->remotes[i].channel = client;

		temp->server = *server;
		temp->remote = (*server)->remotes + i;
		temp->handler = handler;
		temp->data = data;

		temp->request.channel = temp->remote->channel;
		temp->request.buffer.data = (uint8_t*) temp + sizeof(webster_thread_data_t);
		temp->request.buffer.size = (size_t) (*server)->options.bufferSize;

		temp->response.buffer.data = temp->request.buffer.data + temp->request.buffer.size;
		temp->response.buffer.size = (size_t) (*server)->options.bufferSize;
		temp->response.channel = temp->remote->channel;

		int result = pthread_create(&(*server)->remotes[i].thread, NULL, webster_thread, temp);
		if (result != 0)
		{
			free(temp);
			(*server)->remotes[i].channel = NULL;
			network_close(client);
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