/*
 *   Copyright 2016-2023 Bruno Costa
 *   <https://github.com/brunexgeek/webster>
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 */

#ifndef WEBSTER_NO_DEFAULT_NETWORK

#include "socket.hh"  // AUTO-REMOVE

#ifdef WB_WINDOWS
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
typedef SSIZE_T ssize_t;
#else
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <poll.h>
#include <fcntl.h>
#endif

#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <memory>

namespace webster {

std::shared_ptr<SocketNetwork> DEFAULT_NETWORK = std::make_shared<SocketNetwork>();

inline int get_error()
{
#ifdef WB_WINDOWS
	int error = WSAGetLastError();
	switch (error)
	{
		case WSAEADDRINUSE:
			return EADDRINUSE;
		case WSAENOTSOCK:
			return ENOTSOCK;
		case WSAECONNRESET:
			return ECONNRESET;
		case WSAENOTCONN:
			return ENOTCONN;
		case WSAECONNREFUSED:
			return ECONNREFUSED;
		case WSAETIMEDOUT:
			return ETIMEDOUT;
		case WSAEWOULDBLOCK:
			return EWOULDBLOCK;
		case WSAENOBUFS:
			return ENOBUFS;
		case WSAENETUNREACH:
			return ENETUNREACH;
		case WSAEINPROGRESS:
			return EINPROGRESS;
		default:
			return error;
	}
#else
	return errno;
#endif
}

inline int translate_error( int code = 0 )
{
	if (code == 0) code = get_error();
	switch (code)
	{
		case EACCES:
			return WBERR_PERMISSION;
		case EADDRINUSE:
			return WBERR_ADDRESS_IN_USE;
		case ENOTSOCK:
			return WBERR_INVALID_CHANNEL;
		case ECONNRESET:
		case EPIPE:
		case ENOTCONN:
			return WBERR_NOT_CONNECTED;
		case ECONNREFUSED:
			return WBERR_REFUSED;
		case ETIMEDOUT:
		case EWOULDBLOCK:
#if EWOULDBLOCK != EAGAIN
		case EAGAIN:
#endif
			return WBERR_TIMEOUT;
		case EINTR:
			return WBERR_SIGNAL;
		case EMFILE:
		case ENFILE:
			return WBERR_NO_RESOURCES;
		case ENOBUFS:
		case ENOMEM:
			return WBERR_MEMORY_EXHAUSTED;
		case ENETUNREACH:
			return WBERR_UNREACHABLE;
		case EINPROGRESS:
			return WBERR_IN_PROGRESS;
		default:
			return WBERR_SOCKET;
	}
}

inline int poll( struct pollfd &pfd, int &timeout, bool ignore_signal = true )
{
	if (timeout < 0) timeout = 0;
	pfd.revents = 0;
#ifdef WB_WINDOWS
	auto start = tick();
	int result = WSAPoll(&pfd, 1, timeout);
	timeout -= (int) (tick() - start);
#else
	int result;
	do
	{
		auto start = tick();
		result = ::poll(&pfd, 1, timeout);
		int elapsed = (int) (tick() - start);
		timeout -= elapsed;
		if (result >= 0 || !ignore_signal || get_error() != EINTR) break;
	} while (timeout > 0);
#endif
	if (timeout < 0) timeout = 0;
	if (result == 0) return WBERR_TIMEOUT;
	if (get_error() == EINTR) return WBERR_SIGNAL;
	if (result < 0) return WBERR_SOCKET;
	return WBERR_OK;
}

struct SocketChannel : public Channel
{
	#ifdef WB_WINDOWS
	SOCKET socket;
	#else
	int socket;
	#endif
	struct pollfd poll;
};

struct addrinfo_container
{
	struct addrinfo *ptr;

	addrinfo_container( struct addrinfo *ptr ) : ptr(ptr) {}
	~addrinfo_container() { if (ptr) freeaddrinfo(ptr); };
};

static struct addrinfo* resolve( const char *host )
{
	if (host == nullptr || *host == 0) host = "127.0.0.1";

    // get an IPv4 address from hostname
	struct addrinfo aiHints, *aiInfo;
    memset(&aiHints, 0, sizeof(aiHints));
	aiHints.ai_family = AF_INET;
	aiHints.ai_socktype = SOCK_STREAM;
	aiHints.ai_protocol = IPPROTO_TCP;
	int result = getaddrinfo(host, nullptr, &aiHints, &aiInfo);
	if (result != 0) return nullptr;
    // copy address information
    return aiInfo;
}

SocketNetwork::SocketNetwork()
{
	#ifdef WB_WINDOWS
	int err = 0;
	WORD wVersionRequested;
	WSADATA wsaData;
	wVersionRequested = MAKEWORD( 2, 2 );

	err = WSAStartup( wVersionRequested, &wsaData );
	if (err != 0 || LOBYTE(wsaData.wVersion) != 2 || HIBYTE(wsaData.wVersion) != 2)
	{
		if (err == 0) WSACleanup();
	}
	#endif
}

int SocketNetwork::set_non_blocking( Channel *channel )
{
	SocketChannel *chann = (SocketChannel*) channel;
#ifdef WB_WINDOWS
	u_long flags = 1;
	int result = ioctlsocket(chann->socket, FIONBIO, &flags);
#else
	int flags = fcntl(chann->socket, F_GETFL, 0);
	int result = fcntl(chann->socket, F_SETFL, flags | O_NONBLOCK);
#endif
	return (result == 0) ? WBERR_OK : WBERR_SOCKET;
}

int SocketNetwork::set_reusable( Channel *channel )
{
	SocketChannel *chann = (SocketChannel*) channel;
#ifdef WB_WINDOWS
	int opt = SO_EXCLUSIVEADDRUSE;
#else
	int opt = SO_REUSEADDR;
#endif
	int value = 1;
	value = ::setsockopt(chann->socket, SOL_SOCKET,  opt, (char *)&value, sizeof(int));
	return (value == 0) ? WBERR_OK : WBERR_SOCKET;
}

int SocketNetwork::open( Channel **channel, Type type )
{
	(void) type;

	if (channel == nullptr) return WBERR_INVALID_CHANNEL;

	*channel = new(std::nothrow) SocketChannel();
	if (*channel == nullptr) return WBERR_MEMORY_EXHAUSTED;

	SocketChannel *chann = (SocketChannel*) *channel;

	chann->socket = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (chann->socket < 0) return translate_error();
	chann->poll.fd = chann->socket;
	chann->poll.events = POLLIN;

	if (type == Network::SERVER)
	{
		// allow socket descriptor to be reusable
		set_reusable(chann);
	}

	return WBERR_OK;
}

int SocketNetwork::close( Channel *channel )
{
	if (channel == nullptr) return WBERR_INVALID_CHANNEL;

	SocketChannel *chann = (SocketChannel*) channel;

	#ifdef WB_WINDOWS
	::shutdown(chann->socket, SD_BOTH);
	::closesocket(chann->socket);
	#else
	::shutdown(chann->socket, SHUT_RDWR);
	::close(chann->socket);
	#endif
	delete channel;

	return WBERR_OK;
}

int SocketNetwork::connect( Channel *channel, int scheme, const char *host, int port, int timeout )
{
	if (channel == nullptr)
		return WBERR_INVALID_CHANNEL;
	if (port < 0 && port > 0xFFFF)
		return WBERR_INVALID_PORT;
	if (scheme == WBS_AUTO)
		scheme = (port == 443) ? WBS_HTTPS : WBS_HTTP;
	if (scheme != WBS_HTTP)
		return WBERR_INVALID_SCHEME;
	if (timeout < 0) timeout = 0;

	SocketChannel *chann = (SocketChannel*) channel;

	addrinfo_container addrs(resolve(host));
	addrinfo *addr = nullptr;
	for (addr = addrs.ptr; addr != nullptr && addr->ai_family != AF_INET; addr = addr->ai_next);
	if (addr == nullptr) return WBERR_INVALID_ADDRESS;

	sockaddr_in address;
	address = *((sockaddr_in*) addr->ai_addr);
	address.sin_port = htons( (uint16_t) port );

	int result = set_non_blocking(chann);
	if (result != WBERR_OK) return result;

	result = ::connect(chann->socket, (const struct sockaddr*) &address, sizeof(const struct sockaddr_in));
	if (result < 0)
	{
		int code = get_error();
		if (code != EINPROGRESS && code != EWOULDBLOCK)
			return translate_error(code);
	}

	chann->poll.events = POLLOUT;
	result = webster::poll(chann->poll, timeout);
	if (result != WBERR_OK) return result;
	return WBERR_OK;
}

int SocketNetwork::receive( Channel *channel, uint8_t *buffer, int size, int *received, int timeout )
{
	if (channel == nullptr) return WBERR_INVALID_CHANNEL;
	if (buffer == nullptr || received == nullptr || size <= 0) return WBERR_INVALID_ARGUMENT;
	if (timeout < 0) timeout = 0;
	*received = 0;

	SocketChannel *chann = (SocketChannel*) channel;

	chann->poll.events = POLLIN;
	int result = webster::poll(chann->poll, timeout);
	if (result != WBERR_OK) return result;

	auto bytes = ::recv(chann->socket, (char *) buffer, size, 0);
	if (bytes <= 0)
	{
		if (bytes == 0) return WBERR_NOT_CONNECTED;
		return translate_error();
	}
	*received = (int) bytes;

	return WBERR_OK;
}

int SocketNetwork::send( Channel *channel, const uint8_t *buffer, int size, int timeout )
{
	if (channel == nullptr) return WBERR_INVALID_CHANNEL;
	if (buffer == nullptr || size <= 0) return WBERR_INVALID_ARGUMENT;
	if (timeout < 0) timeout = 0;

	SocketChannel *chann = (SocketChannel*) channel;

	#ifdef WB_WINDOWS
	int flags = 0;
	int sent = 0;
	int pending = size;
	int bytes = 0;
	#else
	int flags = MSG_NOSIGNAL;
	ssize_t sent = 0;
	ssize_t pending = size;
	ssize_t bytes = 0;
	#endif

	do
	{
		bytes = ::send(chann->socket, (const char *) buffer, pending, flags);
		if (bytes < 0)
		{
			int code = get_error();
			if (code == EWOULDBLOCK || code ==  EAGAIN || code == EINTR)
			{
				if (timeout == 0) return WBERR_TIMEOUT;
				chann->poll.events = POLLOUT;
				int result = webster::poll(chann->poll, timeout);
				if (result != WBERR_OK) return result;
				continue;
			}
			return translate_error(code);
		}
		sent += bytes;
		buffer += bytes;
		pending -= bytes;
	} while (sent < size && timeout > 0);

	if (sent < size) return WBERR_TIMEOUT;
	return WBERR_OK;
}

#if 0
static std::string get_address( struct sockaddr_in &addr )
{
	char output[16] = {0};
	uint8_t *octets = (uint8_t*) &addr.sin_addr;
	snprintf(output, sizeof(output) - 1, "%d.%d.%d.%d", octets[0], octets[1], octets[2], octets[3]);
	return output;
}
#endif

int SocketNetwork::accept( Channel *channel, Channel **client, int timeout )
{
	if (channel == nullptr) return WBERR_INVALID_CHANNEL;
	if (client == nullptr) return WBERR_INVALID_ARGUMENT;
	if (timeout < 0) timeout = 0;

	SocketChannel *chann = (SocketChannel*) channel;

	// wait for connections
	chann->poll.events = POLLIN;
	int result = webster::poll(chann->poll, timeout, false);
	if (result != WBERR_OK) return result;

	*client = new(std::nothrow) SocketChannel();
	if (*client == nullptr) return WBERR_MEMORY_EXHAUSTED;

	struct sockaddr_in address;
	#ifdef WB_WINDOWS
	int addressLength;
	SOCKET socket;
	#else
	socklen_t addressLength;
	int socket;
	#endif
	addressLength = sizeof(address);
	socket = ::accept(chann->socket, (struct sockaddr *) &address, &addressLength);
	if (socket < 0)
	{
		delete (SocketChannel*) *client;
		*client = nullptr;
		return translate_error();
	}
	((SocketChannel*)*client)->socket = socket;
	((SocketChannel*)*client)->poll.fd = socket;
	((SocketChannel*)*client)->poll.events = POLLIN;

	// allow socket descriptor to be reusable
	set_reusable(chann);
	// use non-blocking operations
	result = set_non_blocking(chann);
	if (result == WBERR_OK) return result;

	return WBERR_OK;
}

int SocketNetwork::listen( Channel *channel, const char *host, int port, int maxClients )
{
	if (channel == nullptr)
		return WBERR_INVALID_CHANNEL;
	if (port < 0 && port > 0xFFFF)
		return WBERR_INVALID_PORT;

	SocketChannel *chann = (SocketChannel*) channel;

	addrinfo_container addrs(resolve(host));
	addrinfo *addr = nullptr;
	for (addr = addrs.ptr; addr != nullptr && addr->ai_family != AF_INET; addr = addr->ai_next);
	if (addr == nullptr) return WBERR_INVALID_ADDRESS;

	sockaddr_in address;
	address = *((sockaddr_in*) addr->ai_addr);
	address.sin_port = htons( (uint16_t) port );

	if (::bind(chann->socket, (const struct sockaddr*) &address, sizeof(struct sockaddr_in)) != 0)
		return translate_error();

	// listen for incoming connections
	if ( ::listen(chann->socket, maxClients) != 0 )
		return translate_error();

	return WBERR_OK;
}

} // namespace webster

#endif // !WEBSTER_NO_DEFAULT_NETWORK
