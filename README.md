# Webster

Lightweight HTTP server and client API. It implements the [RFC-7230 - Message Syntax and Routing](https://tools.ietf.org/html/rfc7230) on top of POSIX socket API. You can change the communication channel reimplementing some internal functions.

Webster enables you to communicate with HTTP servers and implement your own HTTP server. It automatically parses request headers and also simplify creating response headers. The input/output body data is handled as a stream (with chunked transfer encoding or not): to transmit data, you call write functions; to receive data, you call read functions. This enables you to handle large amount of data using less memory.

However, Webster do not:
* Handle header fields according to [RFC-7231 - Semantics and Content](https://tools.ietf.org/html/rfc7231).
* Communicate through SSL/TLS natively. You need to use some 3rd-party library (e.g. [mbedTLS](https://tls.mbed.org)).

The library also includes three sample programs in the ``bin`` directory:

* ``client_sample.c``: simple client program that send a request and print the response;
* ``server_sample.c``: simple server program that echoes information about the request;
* ``server.c``: more elaborated server program that implements directory indexing.

## Client implementation

To send a message to a HTTP server, just create a client entity and start the communication:

``` c
webster_client_t client;
// connect to 'http://duckduckgo.com/'
if (WebsterConnect(&client, WBP_HTTP, "duckduckgo.com", 80, "/") == WBERR_OK)
{
    // start the communication
    WebsterCommunicate(&client, clientHandler, NULL);
    WebsterDisconnect(&client);
}
```

In the example above, the ``clientHandler`` is the function which send and receive data. That function looks like this:

``` c
int clientHandler(
    webster_message_t *request,
    webster_message_t *response,
    void *data )
{
    // send a HTTP request
    WebsterSetIntegerField(request, "content-length", 0);
    WebsterFinish(request);

    webster_event_t event;
    const webster_header_t *header;
    do
    {
        // wait for response data
        int result = WebsterWaitEvent(response, &event);
        if (result == WBERR_COMPLETE) break;
        if (result == WBERR_NO_DATA) continue;
        if (result != WBERR_OK) return 0;

        if (result == WBERR_OK)
        {
            // check if received the HTTP header
            if (event.type ==  WBT_HEADER)
            {
                printf("Waiting for body\n");
            }
            else
            // check if we received the HTTP body (or part of it)
            if (event.type == WBT_BODY)
            {
                const uint8_t *ptr = NULL;
                int size = 0;
                WebsterReadData(response, &ptr, &size);
                for (int i = 0; i < size; ++i)
                {
                    if (i != 0 && i % 8 == 0) printf("\n");
                    printf("%02X ", ptr[i]);
                }
            }
        }
    } while (1);

    return WBERR_OK;

}
```

The source file ``bin/client_sample.c`` contains a complete example of a client program.

## Server implementation

The server keeps listening for connections and handle each one of them. To start the server, do something like:

``` c
webster_server_t server;
if (WebsterCreate(&server, 100) == WBERR_OK)
{
    if (WebsterStart(&server, "127.0.0.1", 7000) == WBERR_OK)
    {
        while (serverState == SERVER_RUNNING)
        {
            webster_client_t remote;
            // accept a pending connection
            if (WebsterAccept(&server, &remote) != WBERR_OK) continue;
            // process the remote connection
            WebsterCommunicate(&remote, serverHandler, NULL);
            WebsterDisconnect(&remote);
        }
    }
    WebsterDestroy(&server);
}
```

Note that the server also uses ``WebsterCommunicate`` since remote connections are client entities. In the example above, the ``serverHandler`` is the function which receive the request and send the response to the client. This handler have the same signature of the client handler. For more details in the server implementation, see the file ``bin/server_sample.c``.

## Features

The following list contains some of the features of HTTP 1.1 specified in RFC-7230. The marked ones are currently implemented.

- [x] Request target in origin form ([RFC-7230 5.3.1](https://tools.ietf.org/html/rfc7230#section-5.3.1))
- [x] Request target in absolute form ([RFC-7230 5.3.2](https://tools.ietf.org/html/rfc7230#section-5.3.2))
- [x] Request target in authority form ([RFC-7230 5.3.3](https://tools.ietf.org/html/rfc7230#section-5.3.3))
- [x] Request target in arterisk form ([RFC-7230 5.3.4](https://tools.ietf.org/html/rfc7230#section-5.3.4))
- [x] Receive messages without transfer encoding ([RFC-7230 3.2.2](https://tools.ietf.org/html/rfc7230#section-3.2.2))
- [x] Send messages without transfer encoding
- [ ] Receive chunked messages ([RFC-7230 4.1](https://tools.ietf.org/html/rfc7230#section-4.1))
- [x] Send chunked messages
- [x] Add 'host' header automatically ([RFC-7230 5.4](https://tools.ietf.org/html/rfc7230#section-5.4))

## Limitations

* You cannot have multiple header fields with the same name ([RFC-7230 3.2.2 Field order](https://tools.ietf.org/html/rfc7230#section-3.2.2))

## Roadmap

* Ensure compatibility with Windows
* Documentation
* HTTP authentication ([RFC-7235](https://tools.ietf.org/html/rfc7235))