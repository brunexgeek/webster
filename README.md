# Webster

Lightweight HTTP server and client API. It implements the [RFC-7230 - Message Syntax and Routing](https://tools.ietf.org/html/rfc7230) on top of POSIX socket API. You can change the communication channel reimplementing some internal functions.

Webster enables you to:
* Read and write header data
* Read and write body data as stream (bytes or strings)

However, Webster do not:
* Handle header fields according to [RFC-7231 - Semantics and Content](https://tools.ietf.org/html/rfc7231)
* Communicate through SSL/TLS natively. You have to integrate with some 3rd-party library (e.g. [mbedTLS](https://tls.mbed.org))

## Client example

To send a message to a HTTP server, just create a client entity and start the communication:

``` c
webster_client_t client;
// connect to 'http://google.com/'
if (WebsterConnect(&client, "google.com", 80, "/") == WBERR_OK)
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
    WebsterSetStringField(request, "host", "google.com");
    WebsterSetIntegerField(request, "content-length", 0);
    WebsterFlush(request);

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

## Server example

The server keeps listening for connections and handle each one of them in separated threads. To start the server, do something like:

``` c
webster_server_t server;
if (WebsterCreate(&server, 100) == WBERR_OK)
{
    if (WebsterStart(&server, "0.0.0.0", 7000) == WBERR_OK)
    {
        while (serverState == SERVER_RUNNING)
            WebsterAccept(&server, serverHandler, NULL);
    }
    WebsterDestroy(&server);
}
```

In the example above, the ``serverHandler`` is the function which receive the request and send the response to the client. This handler have the same signature of the client handler. For more details in the server implementation, see the file ``bin/server_sample.c``.

## Limitations

* You cannot have multiples header fields with the same name ([RFC-7230 3.2.2 Field order](https://tools.ietf.org/html/rfc7230#section-3.2.2))

## Roadmap

* Request URI decoding
* HTTP Basic authentication