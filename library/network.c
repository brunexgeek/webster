#define _POSIX_C_SOURCE 200112L

#include <sys/types.h>
#include "network.h"
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>


typedef struct
{
	int socket;
	struct pollfd poll;
} webster_channel_t;


static int network_lookupIPv4(
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


static int network_open(
	void **channel )
{
	if (channel == NULL) return WBERR_INVALID_ARGUMENT;

	*channel = calloc(1, sizeof(webster_channel_t));
	if (*channel == NULL) return WBERR_MEMORY_EXHAUSTED;

	webster_channel_t *chann = (webster_channel_t*) *channel;

	chann->socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (chann->socket == -1) return WBERR_SOCKET;
	chann->poll.fd = chann->socket;
	chann->poll.events = POLLIN;

	// allow socket descriptor to be reuseable
	int on = 1;
	setsockopt(chann->socket, SOL_SOCKET,  SO_REUSEADDR, (char *)&on, sizeof(int));

	return WBERR_OK;
}


static int network_close(
	void *channel )
{
	if (channel == NULL) return WBERR_INVALID_ARGUMENT;

	webster_channel_t *chann = (webster_channel_t*) channel;

	shutdown(chann->socket, SHUT_RDWR);
	close(chann->socket);
	chann->socket = chann->poll.fd = 0;
	free(channel);

	return WBERR_OK;
}


static int network_connect(
	void *channel,
	const char *host,
    int port )
{
	if (channel == NULL || host == NULL || (port < 0 && port > 0xFFFF))
		return WBERR_INVALID_ARGUMENT;

	webster_channel_t *chann = (webster_channel_t*) channel;

	struct sockaddr_in address;
	network_lookupIPv4(host, &address);

	address.sin_port = htons( (uint16_t) port );
	if (connect(chann->socket, (const struct sockaddr*) &address, sizeof(const struct sockaddr_in)) != 0)
	{
		network_close(channel);
		return WBERR_SOCKET;
	}

	return WBERR_OK;
}


static int network_receive(
	void *channel,
	uint8_t *buffer,
    uint32_t *size,
	int timeout )
{
	if (buffer == NULL || size == NULL || *size == 0) return WBERR_INVALID_ARGUMENT;

	webster_channel_t *chann = (webster_channel_t*) channel;

	// wait for data arrive
	int result = poll(&chann->poll, 1, timeout);
	if (result == 0)
		return WBERR_TIMEOUT;
	else
	if (result < 0)
		return WBERR_SOCKET;

	ssize_t bytes = recv(chann->socket, buffer, (size_t) *size, 0);
	if (bytes < 0)
	{
		if (bytes == EWOULDBLOCK || bytes == EAGAIN) return WBERR_NO_DATA;
		return WBERR_SOCKET;
	}
	*size = (uint32_t) bytes;

	return WBERR_OK;
}


static int network_send(
	void *channel,
	const uint8_t *buffer,
    uint32_t size )
{
	if (buffer == NULL || size == 0) return WBERR_INVALID_ARGUMENT;

	webster_channel_t *chann = (webster_channel_t*) channel;

	if (send(chann->socket, buffer, (size_t) size, MSG_NOSIGNAL) != 0)
		return WBERR_SOCKET;

	return WBERR_OK;
}


static int network_accept(
	void *channel,
	void **client )
{
	if (channel == NULL || client == NULL) return WBERR_INVALID_ARGUMENT;

	webster_channel_t *chann = (webster_channel_t*) channel;

	int result = poll(&chann->poll, 1, 1000);
	if (result == 0)
		return WBERR_TIMEOUT;
	else
	if (result < 0)
		return WBERR_SOCKET;

	*client = calloc(1, sizeof(webster_channel_t));
	if (*client == NULL) return WBERR_MEMORY_EXHAUSTED;

	struct sockaddr_in address;
	socklen_t addressLength = sizeof(address);
	int socket = accept(chann->socket, (struct sockaddr *) &address, &addressLength);

	if (socket < 0)
	{
		free(*client);
		*client = NULL;
		if (socket == EAGAIN || socket == EWOULDBLOCK)
			return WBERR_NO_CLIENT;
		else
			return WBERR_SOCKET;
	}

	((webster_channel_t*)*client)->socket = socket;
	((webster_channel_t*)*client)->poll.fd = socket;
	((webster_channel_t*)*client)->poll.events = POLLIN;

	return WBERR_OK;
}


static int network_listen(
	void *channel,
	const char *host,
    int port,
	int maxClients )
{
	if (channel == NULL || host == NULL || (port < 0 && port > 0xFFFF))
		return WBERR_INVALID_ARGUMENT;

	webster_channel_t *chann = (webster_channel_t*) channel;

	struct sockaddr_in address;
	network_lookupIPv4(host, &address);

	address.sin_port = htons( (uint16_t) port );
	if (bind(chann->socket, (const struct sockaddr*) &address, sizeof(const struct sockaddr_in)) != 0)
	{
		network_close(channel);
		return WBERR_SOCKET;
	}

	// listen for incoming connections
	if ( listen(chann->socket, maxClients) != 0 )
	{
		network_close(channel);
		return WBERR_SOCKET;
	}

	return WBERR_OK;
}


static webster_network_t DEFAULT_IMPL =
{
	network_open,
	network_close,
	network_connect,
	network_receive,
	network_send,
	network_accept,
	network_listen
};

WEBSTER_PRIVATE webster_network_t networkImpl =
{
	network_open,
	network_close,
	network_connect,
	network_receive,
	network_send,
	network_accept,
	network_listen
};


int WebsterSetNetworkImpl(
	webster_network_t *impl )
{
	if (impl == NULL ||
		impl->open == NULL ||
		impl->close == NULL ||
		impl->connect == NULL ||
		impl->receive == NULL ||
		impl->send == NULL ||
		impl->accept == NULL ||
		impl->listen == NULL)
		return WBERR_INVALID_ARGUMENT;

	networkImpl.open    = impl->open;
	networkImpl.close   = impl->close;
	networkImpl.connect = impl->connect;
	networkImpl.receive = impl->receive;
	networkImpl.send    = impl->send;
	networkImpl.accept  = impl->accept;
	networkImpl.listen  = impl->listen;
	return WBERR_OK;
}


int WebsterResetNetworkImpl()
{
	networkImpl.open    = DEFAULT_IMPL.open;
	networkImpl.close   = DEFAULT_IMPL.close;
	networkImpl.connect = DEFAULT_IMPL.connect;
	networkImpl.receive = DEFAULT_IMPL.receive;
	networkImpl.send    = DEFAULT_IMPL.send;
	networkImpl.accept  = DEFAULT_IMPL.accept;
	networkImpl.listen  = DEFAULT_IMPL.listen;
	return WBERR_OK;
}