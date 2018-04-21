#include "network.h"
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>
#include <errno.h>


int webster_lookupIPv4(
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


int webster_receive(
	webster_input_t *input,
	int timeout )
{
	// if we have data in the buffer, just return success
	if (input->buffer.pending > 0) return WBERR_OK;

	// wait for data arrive
	int result = poll(&input->pfd, 1, timeout);
	if (result == 0)
		return WBERR_TIMEOUT;
	else
	if (result < 0)
		return WBERR_SOCKET;

	// Note: when reading input data we leave room in the buffer for a null-terminator
	//       so we can use the function 'WebsterReadString'.

	// receive new data and adjust pending information
	ssize_t bytes = recv(input->socket, input->buffer.data, input->buffer.size - 1, 0);
	if (bytes < 0)
	{
		if (bytes == EWOULDBLOCK || bytes == EAGAIN) return WBERR_NO_DATA;
		return WBERR_SOCKET;
	}
	input->buffer.pending = (int) bytes;
	input->buffer.current = input->buffer.data;
	// ensure we have a null-terminator at the end
	*(input->buffer.current + input->buffer.pending) = 0;

	return WBERR_OK;
}
