# Webster  ![GitHub](https://img.shields.io/github/license/brunexgeek/webster)

Lightweight framework to create HTTP servers and clients in C++11. It implements the [RFC-7230 - Message Syntax and Routing](https://tools.ietf.org/html/rfc7230) on top of POSIX socket API, however you can change the communication channel by specifying custom network stack. There is only two files to include in your projects: ``webster.cc`` and ``webster.hh``.

Webster enables you to communicate with HTTP servers or implement your own HTTP server. It automatically parses requests and also simplify creating responses. The input/output body data is handled as a stream: to transmit data, you call write functions; to receive data, you call read functions. This enables you to handle large amount of data using less memory.

However, Webster do not:
* Handle header fields according to [RFC-7231 - Semantics and Content](https://tools.ietf.org/html/rfc7231).
* Communicate through SSL/TLS natively. You need to use some 3rd-party library (e.g. [mbedTLS](https://tls.mbed.org)).

The repository also includes three programs in the ``examples`` directory:

* ``client.cc``: simple client program that send a request and print the response;
* ``echo.cc``: simple server program that echoes information about the request;
* ``indexing.cc``: more elaborated server program that implements directory indexing. Works only in GNU/Linux for now.

## Client implementation

To send a message to a HTTP server, just create a client object and start the communication:

``` c++
// parse the URL
Target target;
Target::parse("http://duckduckgo.com:80/", target);
// create the handler using a function
Handler handler(my_client_handler);
Client client;
if (client.connect(target) == WBERR_OK)
{
    // use the handler to send a request to "/"
    client.communicate("/", handler);
    client.disconnect();
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

    // wait for response headers
    response.wait();
    // read response body as text
    const char *ptr = nullptr;
    while (response.read(&ptr) == WBERR_OK)
        std::cout << ptr << std::endl;

    return WBERR_OK;
}
```

It's also possible to implement a handler by specializing the class ``Handler`` with a new implementation for ``operator()``.

``` c++
struct MyHandler : public Handler
{
	int operator()( Message &request, Message &response )
	{
        ...
    }
};
```

The directory ``examples`` contains some example programs for client and server.

## Server implementation

The server keeps listening for connections and handle each one of them. To start the server, do something like:

``` c++
Target target;
Target::parse("localhost:7000", target);
Server server;
if (server.start(target) == WBERR_OK)
{
    EchoHandler handler(my_server_handler);
    while (is_running)
    {
        std::shared_ptr<Client> remote;
        int result = server.accept(remote);
        if (result == WBERR_OK)
        {
            remote->communicate("", handler);
            remote->disconnect();
        }
        else
        if (result != WBERR_TIMEOUT) break;
    }
}
server.stop();
```

In the example above, the ``my_server_handler`` is the function which receive the request and send the response to the client. This handler have the same signature of the client handler, however the request must be read not written. For more details in the server implementation, see the file ``examples/echo.cc`` or ``examples/indexing.cc``.

## Features

The following list contains some of the features of HTTP 1.1 specified in RFC-7230. The marked ones are currently implemented.

- [x] Receive non-chunked messages
- [ ] Receive chunked messages ([RFC-7230 4.1 Chunked Transfer Coding](https://tools.ietf.org/html/rfc7230#section-4.1))
- [x] Send non-chuncked messages
- [x] Send chunked messages ([RFC-7230 4.1 Chunked Transfer Coding](https://tools.ietf.org/html/rfc7230#section-4.1))
- [x] Add 'host' header automatically ([RFC-7230 5.4 Host](https://tools.ietf.org/html/rfc7230#section-5.4))

## Limitations

* You cannot have multiple header fields with the same name ([RFC-7230 3.2.2 Field order](https://tools.ietf.org/html/rfc7230#section-3.2.2))

## Roadmap

* Documentation
* Improve chunked data implementation