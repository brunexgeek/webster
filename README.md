# Webster

Lightweight HTTP server and client API compatible with C99. It implements the [RFC-7230 - Message Syntax and Routing](https://tools.ietf.org/html/rfc7230) on top of POSIX socket API. You can change the communication channel specifying custom network functions (check `WebsterInitialize` function).

Webster enables you to communicate with HTTP servers and implement your own HTTP server. It automatically parses request headers and also simplify creating response headers. The input/output body data is handled as a stream (with chunked transfer encoding or not): to transmit data, you call write functions; to receive data, you call read functions. This enables you to handle large amount of data using less memory.

However, Webster do not:
* Handle header fields according to [RFC-7231 - Semantics and Content](https://tools.ietf.org/html/rfc7231).
* Communicate through SSL/TLS natively. You need to use some 3rd-party library (e.g. [mbedTLS](https://tls.mbed.org)).

The repository also includes three programs in the ``examples`` directory:

* ``client.c``: simple client program that send a request and print the response;
* ``echo.c``: simple server program that echoes information about the request;
* ``listing.c``: more elaborated server program that implements directory indexing.

## Client implementation

To send a message to a HTTP server, just create a client entity and start the communication:

``` c
webster_client_t client;
// connect to duckduckgo.com:80
if (WebsterConnect(&client, WBP_HTTP, "duckduckgo.com", 80) == WBERR_OK)
{
    // start the communication with path "/"
    WebsterCommunicate(&client, "/", NULL, clientHandler, NULL);
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
    WebsterSetStringField(request, "connection", "close");
    WebsterFinish(request);

    webster_event_t event;
    const webster_header_t *header;
    do
    {
        // wait for response data
        int result = WebsterWaitEvent(response, &event);
        if (result == WBERR_COMPLETE) break;
        if (result == WBERR_NO_DATA) continue;
        if (result != WBERR_OK) break;

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
                    if (i != 0 && i % 32 == 0) printf("\n");
                    printf("%02X ", ptr[i]);
                }
            }
        }
    } while (1);

    WebsterFinish(response);

    return WBERR_OK;
}
```

The source file ``examples/client.c`` contains a complete example of a client program.

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
            webster_client_t *remote = NULL;
            int result = WebsterAccept(server, &remote);
            if (result == WBERR_OK)
            {
                // you problably should handle the client request in another thread
                WebsterCommunicateURL(remote, NULL, main_serverHandler, NULL);
                WebsterDisconnect(remote);
            }
            else
            if (result != WBERR_TIMEOUT) break;
        }
    }
    WebsterDestroy(&server);
}
```

Note that the server also uses ``WebsterCommunicate`` since remote connections are client entities. In the example above, the ``serverHandler`` is the function which receive the request and send the response to the client. This handler have the same signature of the client handler. For more details in the server implementation, see the file ``examples/echo.c``.

## Features

The following list contains some of the features of HTTP 1.1 specified in RFC-7230. The marked ones are currently implemented.

- [x] Receive non-chuncked messages
- [ ] Receive chunked messages ([RFC-7230 4.1 Chunked Transfer Coding](https://tools.ietf.org/html/rfc7230#section-4.1))
- [x] Send non-chuncked messages
- [x] Send chunked messages ([RFC-7230 4.1 Chunked Transfer Coding](https://tools.ietf.org/html/rfc7230#section-4.1))
- [x] Add 'host' header automatically ([RFC-7230 5.4 Host](https://tools.ietf.org/html/rfc7230#section-5.4))

## Limitations

* You cannot have multiple header fields with the same name ([RFC-7230 3.2.2 Field order](https://tools.ietf.org/html/rfc7230#section-3.2.2))

## Roadmap

* Ensure compatibility with Windows
* Documentation
* HTTP authentication ([RFC-7235](https://tools.ietf.org/html/rfc7235))