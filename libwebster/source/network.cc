#define _POSIX_C_SOURCE 200112L

#include <sys/types.h>
#include "network.hh"

#ifdef WB_WINDOWS
#include <winsock2.h>
#if (_WIN32_WINNT > 0x0501 || WINVER > 0x0501)
#include <WS2tcpip.h>
#endif
#pragma comment(lib, "ws2_32.lib")
typedef SSIZE_T ssize_t;
#else
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <poll.h>
#endif

#include <string.h>
#include <errno.h>
#include <stdlib.h>


#if defined(WB_WINDOWS) && (_WIN32_WINNT <= 0x0501 || WINVER <= 0x0501)
HINSTANCE winSocketLib;

// Note: on Windows XP or older, the functions 'getaddrinfo' and 'freeaddrinfo'
//       should be loaded manually.

getaddrinfo_f getaddrinfo;

freeaddrinfo_f freeaddrinfo;

#endif

static webster_memory_t memory = { NULL, NULL, NULL };

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


static int network_initialize(
	webster_memory_t *mem )
{
	memory.malloc = mem->malloc;
	memory.calloc = mem->calloc;
	memory.free   = mem->free;

	#ifdef WB_WINDOWS
	int err = 0;

	WORD wVersionRequested;
	WSADATA wsaData;
	wVersionRequested = MAKEWORD( 2, 0 );
	err = WSAStartup( wVersionRequested, &wsaData );
	if(err != 0) return WBERR_SOCKET;

	#if (_WIN32_WINNT <= 0x0501 || WINVER <= 0x0501)
	winSocketLib = LoadLibrary( "WS2_32.dll" );
	if (winSocketLib == NULL) return WBERR_SOCKET;

	getaddrinfo = NULL;
	freeaddrinfo = NULL

	getaddrinfo = (getaddrinfo_f)GetProcAddress(winSocketLib, "getaddrinfo");
	if (getaddrinfo == NULL) return;

	freeaddrinfo = (freeaddrinfo_f)GetProcAddress(winSocketLib, "freeaddrinfo");
	if (freeaddrinfo == NULL) return;
	#endif

	#endif // __WINDOWS__

	return WBERR_OK;
}


static int network_terminate()
{
	memory.malloc = NULL;
	memory.malloc = NULL;
	memory.free   = NULL;

	#ifdef WB_WINDOWS
	#if (_WIN32_WINNT <= 0x0501 || WINVER <= 0x0501)
	getaddrinfo = NULL;
	freeaddrinfo = NULL;
	#endif
	WSACleanup();
	#endif

	return WBERR_OK;
}


static int network_open(
	void **channel )
{
	if (channel == NULL) return WBERR_INVALID_CHANNEL;

	*channel = memory.calloc(1, sizeof(webster_channel_t));
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
	if (channel == NULL) return WBERR_INVALID_CHANNEL;

	webster_channel_t *chann = (webster_channel_t*) channel;

	#ifdef WB_WINDOWS
	shutdown(chann->socket, SD_BOTH);
	closesocket(chann->socket);
	#else
	shutdown(chann->socket, SHUT_RDWR);
	close(chann->socket);
	#endif

	chann->socket = chann->poll.fd = 0;
	memory.free(channel);

	return WBERR_OK;
}


static int network_connect(
	void *channel,
	int scheme,
	const char *host,
    int port )
{
	if (channel == NULL)
		return WBERR_INVALID_CHANNEL;
	if (port < 0 && port > 0xFFFF)
		return WBERR_INVALID_PORT;
	if (host == NULL || host[0] == 0)
		return WBERR_INVALID_HOST;
	if (scheme != WBP_HTTP)
		return WBERR_INVALID_SCHEME;

	webster_channel_t *chann = (webster_channel_t*) channel;

	struct sockaddr_in address;
	network_lookupIPv4(host, &address);

	address.sin_port = htons( (uint16_t) port );
	if (connect(chann->socket, (const struct sockaddr*) &address, sizeof(const struct sockaddr_in)) != 0)
		return WBERR_SOCKET;

	return WBERR_OK;
}


static int network_receive(
	void *channel,
	uint8_t *buffer,
    uint32_t *size,
	int timeout )
{
	if (channel == NULL) return WBERR_INVALID_CHANNEL;
	if (buffer == NULL || size == NULL || *size == 0) return WBERR_INVALID_ARGUMENT;

	webster_channel_t *chann = (webster_channel_t*) channel;
	uint32_t bufferSize = *size;
	*size = 0;

	// wait for data arrive
	#ifdef WB_WINDOWS
	int result = WSAPoll(&chann->poll, 1, timeout);
	#else
	int result = poll(&chann->poll, 1, timeout);
	#endif
	if (result == 0) return WBERR_TIMEOUT;
	if (result < 0) return WBERR_SOCKET;

	ssize_t bytes = recv(chann->socket, buffer, (size_t) bufferSize, 0);
	if (bytes == ECONNRESET || bytes == EPIPE || bytes == ENOTCONN)
		return WBERR_NOT_CONNECTED;
	else
	if (bytes < 0)
	{
		*size = 0;
		if (bytes == EWOULDBLOCK || bytes == EAGAIN) return WBERR_NO_DATA;
		return WBERR_SOCKET;
	}
	*size = (uint32_t) bytes;
	if (bytes == 0) return WBERR_TIMEOUT;

	return WBERR_OK;
}


static int network_send(
	void *channel,
	const uint8_t *buffer,
    uint32_t size )
{
	if (channel == NULL) return WBERR_INVALID_CHANNEL;
	if (buffer == NULL || size == 0) return WBERR_INVALID_ARGUMENT;

	webster_channel_t *chann = (webster_channel_t*) channel;

	#ifdef WB_WINDOWS
	int flags = 0;
	#else
	int flags = MSG_NOSIGNAL;
	#endif
	ssize_t result = send(chann->socket, buffer, (size_t) size, flags);
	if (result == ECONNRESET || result == EPIPE || result == ENOTCONN)
		return WBERR_NOT_CONNECTED;
	else
	if (result < 0)
		return WBERR_SOCKET;

	return WBERR_OK;
}


static int network_accept(
	void *channel,
	void **client )
{
	if (channel == NULL) return WBERR_INVALID_CHANNEL;
	if (client == NULL) return WBERR_INVALID_ARGUMENT;

	webster_channel_t *chann = (webster_channel_t*) channel;

	#ifdef WB_WINDOWS
	int result = WSAPoll(&chann->poll, 1, 1000);
	#else
	int result = poll(&chann->poll, 1, 1000);
	#endif
	if (result == 0)
		return WBERR_TIMEOUT;
	else
	if (result < 0)
		return WBERR_SOCKET;

	*client = memory.calloc(1, sizeof(webster_channel_t));
	if (*client == NULL) return WBERR_MEMORY_EXHAUSTED;

	struct sockaddr_in address;
	#ifdef WB_WINDOWS
	size_t addressLength;
	#else
	socklen_t addressLength;
	#endif
	addressLength = sizeof(address);
	int socket = accept(chann->socket, (struct sockaddr *) &address, &addressLength);

	if (socket < 0)
	{
		memory.free(*client);
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
	if (channel == NULL)
		return WBERR_INVALID_CHANNEL;
	if ( host == NULL || host[0] == 0)
		return WBERR_INVALID_HOST;
	if (port < 0 && port > 0xFFFF)
		return WBERR_INVALID_PORT;

	webster_channel_t *chann = (webster_channel_t*) channel;

	struct sockaddr_in address;
	network_lookupIPv4(host, &address);

	address.sin_port = htons( (uint16_t) port );
	if (bind(chann->socket, (const struct sockaddr*) &address, sizeof(const struct sockaddr_in)) != 0)
		return WBERR_SOCKET;

	// listen for incoming connections
	if ( listen(chann->socket, maxClients) != 0 )
		return WBERR_SOCKET;

	return WBERR_OK;
}


static webster_network_t DEFAULT_IMPL =
{
	network_initialize,
	network_terminate,
	network_open,
	network_close,
	network_connect,
	network_receive,
	network_send,
	network_accept,
	network_listen
};

WEBSTER_PRIVATE webster_network_t networkImpl = { NULL, NULL, NULL, NULL, NULL, NULL,
	NULL, NULL, NULL };


int network_setImpl(
	webster_network_t *impl )
{
	if (impl == NULL) impl = &DEFAULT_IMPL;

	if (impl->initialize == NULL ||
		impl->terminate == NULL ||
		impl->open == NULL ||
		impl->close == NULL ||
		impl->connect == NULL ||
		impl->receive == NULL ||
		impl->send == NULL ||
		impl->accept == NULL ||
		impl->listen == NULL)
		return WBERR_INVALID_ARGUMENT;

	networkImpl.initialize = impl->initialize;
	networkImpl.terminate  = impl->terminate;
	networkImpl.open       = impl->open;
	networkImpl.close      = impl->close;
	networkImpl.connect    = impl->connect;
	networkImpl.receive    = impl->receive;
	networkImpl.send       = impl->send;
	networkImpl.accept     = impl->accept;
	networkImpl.listen     = impl->listen;
	return WBERR_OK;
}


int network_resetImpl()
{
	networkImpl.initialize = NULL;
	networkImpl.terminate  = NULL;
	networkImpl.open       = NULL;
	networkImpl.close      = NULL;
	networkImpl.connect    = NULL;
	networkImpl.receive    = NULL;
	networkImpl.send       = NULL;
	networkImpl.accept     = NULL;
	networkImpl.listen     = NULL;
	return WBERR_OK;
}
