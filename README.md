# Webster

Lightweight HTTP server/client API. It implement the [RFC-7230 - Message Syntax and Routing](https://tools.ietf.org/html/rfc7230) on top of POSIX socket API. You can change the communication channel reimplementing some intenal functions.

Webster enables you to:
* Read and write header data
* Get and set header fields
* Read and write body data as stream (bytes or strings)

However, Webster do not:
* Handle header fields according to [RFC-7231 - Semantics and Content](https://tools.ietf.org/html/rfc7231)
* Communicate through SSL/TLS natively. You have to integrate with some 3rd-party library (e.g. [mbedTLS](https://tls.mbed.org))

## Limitations

* You cannot have multiples header fields with the same name

## Roadmap

* Client API implementation
* Request URI decoding
* HTTP Basic authentication