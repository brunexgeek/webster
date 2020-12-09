# Webster  ![GitHub](https://img.shields.io/github/license/brunexgeek/webster) [![Build Status](https://img.shields.io/endpoint.svg?url=https%3A%2F%2Factions-badge.atrox.dev%2Fbrunexgeek%2Fwebster%2Fbadge%3Fref%3Dmaster&label=build&logo=none)](https://actions-badge.atrox.dev/brunexgeek/webster/goto?ref=master)

Lightweight library to create HTTP servers and clients in C++11. It implements the [RFC-7230 - Message Syntax and Routing](https://tools.ietf.org/html/rfc7230) on top of POSIX socket API, however you can change the communication channel by specifying a custom network stack.

Webster enables you to communicate with HTTP servers or implement your own HTTP server. It automatically parses requests and also simplify creating responses. The input/output body data is handled as a stream: to transmit data, you call write functions; to receive data, you call read functions. This enables you to handle large amounts of data using small buffers.

To use Webster you can link with `libwebster` static library or include the files ``webster.cc`` and ``webster.hh`` in your project. The file ``webster.cc`` is an almagamation of the files contained in the ``source`` directory.

The repository also includes three programs in the ``examples`` directory:

* ``client.cc``: simple client program that send a request and print the response;
* ``echo.cc``: simple server program that echoes information about the request;
* ``indexing.cc``: more elaborated server program that implements directory indexing. Works only in GNU/Linux for now.

## Client implementation

To send a message to an HTTP server, just create an `HttpClient` object and start the communication:

``` c++
// create a listener using a function
HttpListener listener(my_client_handler);
// create the HTTP client
HttpClient client;
if (client.open("http://duckduckgo.com:80/") == WBERR_OK)
{
    // use the listener to send a request to "/"
    client.communicate("/", listener);
    client.close();
}
```

In the example above, the ``my_client_handler`` is the function which send the request and receive the response. That function looks like this:

``` c++
int my_client_handler( Message &request, Message &response )
{
    // send a HTTP request
    request.header.fields["Connection"] = "close";
    request.header.fields.set(WBFI_CONTENT_LENGTH, 0);
    request.finish();

    // wait until the message body is ready to be read
    response.ready();
    // read response body as text
    const char *ptr = nullptr;
    while (response.read(&ptr) == WBERR_OK)
        std::cout << ptr << std::endl;

    return WBERR_OK;
}
```

You can also implement a listener by specializing the class ``HttpListener`` with a new implementation for ``operator()``. This way you can have a statefull listener.

``` c++
struct MyListener : public HttpListener
{
	int operator()( Message &request, Message &response )
	{
        ...
    }
};
```

## Server implementation

The server keeps listening for connections and handle each one of them. To start the server, do something like:

``` c++
HttpServer server;
if (server.start("http://localhost:7000") == WBERR_OK)
{
    HttpListener listener(my_server_handler);
    while (is_running)
    {
        HttpClient *remote = nullptr;
        // wait for connections (uses `read_timeout`from `Parameters` class)
        int result = server.accept(&remote);
        if (result == WBERR_OK)
        {
            // keep processing requests until some error occurs
            while ((result = remote->communicate(listener)) == WBERR_OK);
            // close the client (optional, closed by destructor) and destroy the object
            remote->close();
            delete remote;
        }
        else
        // `HttpServer::accept` will return `WBERR_TIMEOUT` if there were no connections
        if (result != WBERR_TIMEOUT)
            break;
    }
    server.stop();
}
```

In the example above, the ``my_server_handler`` is the function which receive the request and send the response to the client. This listener have the same signature of the client listener, however the request must be read (not written). For more details in the server implementation, see the files ``examples/echo.cc`` and ``examples/indexing.cc``.

## Limitations

* You cannot have multiple header fields with the same name ([RFC-7230 3.2.2 Field order](https://tools.ietf.org/html/rfc7230#section-3.2.2))
* The library do not handle header fields according to [RFC-7231 - Semantics and Content](https://tools.ietf.org/html/rfc7231).
* Support for SSL/TLS communication is not provided natively. You need to specialize the ``Network`` class using a 3rd-party library (e.g. [mbedTLS](https://tls.mbed.org)).
## Roadmap

* Documentation
* Specialize ``Network`` for HTTPS using [mbedTLS](https://tls.mbed.org)