/*
 *   Copyright 2020 Bruno Ribeiro
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

#if defined(_WIN32) || defined(WIN32)
#define WB_WINDOWS
#endif

#include "webster.hh"
#include <ctype.h>
#include <string>
#include <memory>
#include <sstream>
#include <iostream>
#include <cstring> // strlen strstr strchr

#define IS_INBOUND(x)   ( (x) & 1 )
#define IS_OUTBOUND(x)  ( ((x) & 1) == 0 )
#define IS_REQUEST(x)   ( (x) & 2 )
#define IS_RESPONSE(x)  ( ((x) & 2) == 0)

#define WBMF_INBOUND   1
#define WBMF_OUTBOUND  0
#define WBMF_REQUEST   2
#define WBMF_RESPONSE  0

#define WBMF_CHUNKED   1

namespace webster {

enum State
{
	WBS_IDLE     = 0,
	WBS_BODY     = 1,
	WBS_COMPLETE = 2,
};

typedef std::shared_ptr<Network> NetworkPtr;

class HttpStream
{
	public:
		HttpStream( const Parameters &params, Channel *chann, int type );
		~HttpStream();
		int write( const uint8_t *data, int size );
		int write( const char *data );
		int write( const std::string &text );
		int write( char c );
		template<typename T, typename std::enable_if<std::is_arithmetic<T>::value, int>::type = 0>
		int write( T value )
		{
			std::string str = std::to_string(value);
			return write(str);
		}
		int read( uint8_t *data, int size );
        int read_line( char *data, int size );
        int pending() const;
        int flush();
		const Parameters &get_parameters() const { return params_; }
	protected:
		int pending_;
		Channel *channel_;
		Parameters params_;
		uint8_t *data_;
		uint8_t *current_;
};

class MessageImpl : public Message
{
    public:
        MessageImpl( HttpStream &stream );
        ~MessageImpl();
        int read( uint8_t *buffer, int size );
        int read( char *buffer, int size );
        int read_all( std::vector<uint8_t> &buffer );
		int read_all( std::string &buffer );
        int write( const uint8_t *buffer, int size );
        int write( const char *buffer );
		int write( const std::string &buffer );
        int write( const std::vector<uint8_t> &buffer );
        int ready();
        int flush();
        int finish();

    public:
        State state_;
        int flags_;
        struct
        {
            /**
             * @brief Message expected size.
             *
             * This value is any negative if using chunked transfer encoding.
             */
            int expected;

            /**
             * @brief Number of chunks received.
             */
            int chunks;

            int flags;
        } body_;
        HttpStream &stream_;
        Client *client_;
        Channel *channel_;

        int receive_header();
        int chunk_size();
        int write_header();
        int write_resource_line();
        int write_status_line();
        int parse_first_line( const char *data );
        int parse_header_field( char *data );
        int discard();

        friend Client;
        friend RemoteClient;
};

#ifndef WEBSTER_NO_DEFAULT_NETWORK
class SocketNetwork : public Network
{
    public:
        SocketNetwork();
        ~SocketNetwork() = default;
        int open( Channel **channel, Type type );
        int close( Channel *channel );
        int connect( Channel *channel, int scheme, const char *host, int port );
        int receive( Channel *channel, uint8_t *buffer, int size, int *received, int timeout );
        int send( Channel *channel, const uint8_t *buffer, int size, int timeout );
        int accept( Channel *channel, Channel **client, int timeout );
        int listen( Channel *channel, const char *host, int port, int maxClients );
    protected:
        int set_non_blocking( Channel *channel );
        int set_reusable( Channel *channel );
        int resolve( const char *host, void *address );
};

std::shared_ptr<SocketNetwork> DEFAULT_NETWORK = std::make_shared<SocketNetwork>();

#endif

HttpStream::HttpStream( const Parameters &params, Channel *chann, int flags ) : pending_(0),
	channel_(chann), params_(params), data_(nullptr), current_(nullptr)
{
	if (IS_OUTBOUND(flags))
		data_ = current_ = new(std::nothrow) uint8_t[params_.buffer_size];
}

HttpStream::~HttpStream()
{
	delete[] data_;
}

int HttpStream::write( const uint8_t *buffer, int size )
{
	if (size == 0 || buffer == nullptr) return WBERR_OK;
	if (size < 0 || size > 0x3FFFFFFF) return WBERR_TOO_LONG;
	if (data_ == nullptr) return WBERR_MEMORY_EXHAUSTED;

	// ensures the current pointer is valid
	if (current_ == nullptr)
	{
		current_ = data_;
		pending_ = 0;
	}

	// fragment input data through recursive call until the data size fits the internal buffer
	int offset = 0;
	int result = WBERR_OK;
	int fit = params_.buffer_size - (int)(current_ - data_);
	while (size > fit)
	{
		result = write(buffer + offset, fit);
		size -= fit;
		offset += fit;
		fit = params_.buffer_size - (int)(current_ - data_);
		if (result != WBERR_OK) return result;
	}

	memcpy(current_, buffer + offset, (size_t) size);
	current_ += size;

	// send pending data if the buffer is full
	if (current_ >= data_ + params_.buffer_size)
	{
		result = params_.network->send(channel_, data_, params_.buffer_size, params_.write_timeout);
		current_ = data_;
		pending_ = 0;
	}

	return result;
}

int HttpStream::write( const char *text )
{
	return write((uint8_t*) text, (int) strlen(text));
}

int HttpStream::write( const std::string &text )
{
	return write((uint8_t*) text.c_str(), (int) text.length());
}

int HttpStream::write( char c )
{
	return write((uint8_t*) &c, 1);
}

int HttpStream::read( uint8_t *data, int size )
{
	int read = 0;
	int result = params_.network->receive(channel_, data, size, &read, params_.read_timeout);
	if (result == WBERR_OK) return read;
	return result;
}

int HttpStream::read_line( char *data, int size )
{
	if (data == nullptr || size < 2) return WBERR_INVALID_ARGUMENT;
	char *p = data;
	uint8_t c;

	// TODO: optimize this algorithm by using recv and MSG_PEEK do find the '\n'

	do
	{
		int result = read(&c, 1);
		if (result < 0) return result;
		if (c == '\r') continue;
		if (c == '\n') break;
		*p = (char) c;
		++p;
	} while (p < data + size - 1);
	if (c != '\n') return WBERR_TOO_LONG;
	*p = 0;

	return WBERR_OK;
}

int HttpStream::pending() const
{
	return pending_;
}

int HttpStream::flush()
{
	// send all remaining body data
	if (current_ > data_)
	{
		int size = (int) (current_ - data_);
		params_.network->send(channel_, data_, size, params_.write_timeout);
		current_ = data_;
	}
	return WBERR_OK;
}

Target::Target()
{
	clear();
}

static std::string string_cut(
    const char *text,
    size_t offset,
    size_t length )
{
    if (text == nullptr) return nullptr;

    size_t len = strlen(text);
    if (offset + length > len) return nullptr;

    std::string output;
    for (size_t i = offset; i < offset + length; ++i) output += text[i];
    return output;
}

static int hex_digit( uint8_t digit )
{
    if (digit >= '0' && digit <= '9')
        return digit - '0';
    if (digit >= 'a' && digit <= 'f')
        digit = (uint8_t) (digit - 32);
    if (digit >= 'A' && digit <= 'F')
        return digit - 'A' + 10;
    return 0;
}

std::string Target::decode( const std::string &input )
{
    const uint8_t *i = (const uint8_t*) input.c_str();
    std::string out;

    while (*i != 0)
    {
        if (*i == '%' && isxdigit(*(i + 1)) && isxdigit(*(i + 2)))
        {
            out += (uint8_t) (hex_digit(*(i + 1)) * 16 + hex_digit(*(i + 2)));
            i += 3;
        }
        else
        {
            out += *i;
            ++i;
        }
    }

    return out;
}

std::string Target::encode( const std::string &input )
{
	const char *SYMBOLS = "0123456789abcdef";
	std::string out;

	for (char i : input)
	{
		uint8_t c = (uint8_t) i;
		if ((c >= 'A' && c <= 'Z') ||
			(c >= 'a' && c <= 'z') ||
			(c >= '0' && c <= '9') ||
			c == '-' || c == '_' ||
			c == '.' || c == '~')
			out += i;
		else
		{
			out += '%';
			out += SYMBOLS[c >> 4];
			out += SYMBOLS[c & 0x0F];
		}
	}
	return out;
}

int Target::parse( const char *url, Target &target )
{
    if (url == nullptr || url[0] == 0) return WBERR_INVALID_TARGET;

    // handle asterisk form
    if (url[0] == '*' && url[1] == 0)
        target.type = WBRT_ASTERISK;
    else
    // handle origin form
    if (url[0] == '/')
    {
        target.type = WBRT_ORIGIN;

        const char *ptr = url;
        while (*ptr != '?' && *ptr != 0) ++ptr;

        if (*ptr == '?')
        {
            size_t pos = (size_t) (ptr - url);
            target.path = string_cut(url, 0, pos);
            target.query = string_cut(url, pos + 1, strlen(url) - pos - 1);
        }
        else
        {
            target.path = std::string(url);
        }

        target.path = Target::decode(target.path);
        target.query = Target::decode(target.query);
    }
    else
    // handle absolute form
    if (tolower(url[0]) == 'h' &&
		tolower(url[1]) == 't' &&
		tolower(url[2]) == 't' &&
		tolower(url[3]) == 'p' &&
		(tolower(url[4]) == 's' || url[4] == ':'))
	{
        target.type = WBRT_ABSOLUTE;

		// extract the host name
		const char *hb = strstr(url, "://");
		if (hb == nullptr) return WBERR_INVALID_TARGET;
		hb += 3;
		const char *he = hb;
		while (*he != ':' && *he != '/' && *he != 0) ++he;
		if (hb == he) return WBERR_INVALID_TARGET;

		const char *rb = he;
		const char *re = nullptr;

		// extract the port number, if any
		const char *pb = he;
		const char *pe = nullptr;
		if (*pb == ':')
		{
			pe = ++pb;
			while (*pe >= '0' && *pe <= '9' && *pe != 0) ++pe;
			if (pb == pe || (pe - pb) > 5) return WBERR_INVALID_TARGET;
			rb = pe;
		}

		// extract the resource
		if (*rb == '/')
		{
			re = rb;
			while (*re != 0) ++re;
		}
		if (re != nullptr && *re != 0) return WBERR_INVALID_TARGET;

		// return the scheme
		if (url[4] == ':')
			target.scheme = WBP_HTTP;
		else
			target.scheme = WBP_HTTPS;

		// return the port number, if any
		if (pe != nullptr)
		{
			target.port = 0;
			int mult = 1;
			while (--pe >= pb)
			{
				target.port += (int) (*pe - '0') * mult;
				mult *= 10;
			}
			if (target.port > 65535 || target.port < 0)
                return WBERR_INVALID_TARGET;
		}
		else
		{
			if (target.scheme == WBP_HTTP)
				target.port = 80;
			else
				target.port = 443;
		}

		// return the host
        target.host = string_cut(hb, 0, (size_t) (he - hb));

		// return the resource, if any
		if (re != nullptr)
			target.path = string_cut(rb, 0, (size_t) (re - rb));
		else
			target.path = "/";

		target.path = Target::decode(target.path);
        target.query = Target::decode(target.query);
	}
    else
    // handle authority form
    {
        target.type = WBRT_AUTHORITY;

        const char *hb = strchr(url, '@');
        if (hb != nullptr)
        {
            target.user = string_cut(url, 0, (size_t) (hb - url));
            hb++;
        }
        else
            hb = url;

        const char *he = strchr(hb, ':');
        if (he != nullptr)
        {
            target.host = string_cut(hb, 0, (size_t) (he - hb));
            target.port = 0;

            const char *pb = he + 1;
            const char *pe = pb;
            while (*pe >= '0' && *pe <= '9' && *pe != 0) ++pe;
            if (*pe != 0) return WBERR_INVALID_TARGET;

			int mult = 1;
			while (--pe >= pb)
			{
				target.port += (int) (*pe - '0') * mult;
				mult *= 10;
			}
			if (target.port > 65535 || target.port < 0)
                return WBERR_INVALID_TARGET;
        }
        else
        {
            target.host = std::string(hb);
            target.port = 80;
        }
    }

    return WBERR_OK;
}

int Target::parse( const std::string &url, Target &target )
{
	return parse(url.c_str(), target);
}

void Target::swap( Target &that )
{
	std::swap(type, that.type);
	std::swap(scheme, that.scheme);
	user.swap(that.user);
	host.swap(that.path);
	std::swap(port, that.port);
	path.swap(that.path);
	query.swap(that.query);
}

void Target::clear()
{
	type = port = 0;
	scheme = WBP_HTTP;
	user.clear();
	host.clear();
	path.clear();
	query.clear();
}

Header::Header()
{
	clear();
}

void Header::swap( Header &that )
{
	std::swap(status, that.status);
	std::swap(method, that.method);
	fields.swap(that.fields);
	target.swap(that.target);
}

void Header::clear()
{
	status = 200;
	method = WBM_GET;
	fields.clear();
	target.clear();
}

static void fix_parameters( Parameters &params )
{
	if (params.max_clients <= 0)
		params.max_clients = WBL_DEF_CONNECTIONS;
	else
	if (params.max_clients > WBL_MAX_CONNECTIONS)
		params.max_clients = WBL_MAX_CONNECTIONS;

	if (params.buffer_size == 0)
		params.buffer_size = WBL_DEF_BUFFER_SIZE;
	else
	if (params.buffer_size > WBL_MAX_BUFFER_SIZE)
		params.buffer_size = WBL_MAX_BUFFER_SIZE;
	params.buffer_size = (uint32_t) (params.buffer_size + 3) & (uint32_t) (~3);

	if (params.read_timeout < 0)
		params.read_timeout = WBL_DEF_TIMEOUT;
	else
	if (params.read_timeout > WBL_MAX_TIMEOUT)
		params.read_timeout = WBL_MAX_TIMEOUT;

	if (params.write_timeout < 0)
		params.write_timeout = WBL_DEF_TIMEOUT;
	else
	if (params.write_timeout > WBL_MAX_TIMEOUT)
		params.write_timeout = WBL_MAX_TIMEOUT;
}

Parameters::Parameters() : max_clients(WBL_DEF_CONNECTIONS), buffer_size(WBL_DEF_BUFFER_SIZE),
	read_timeout(WBL_DEF_TIMEOUT), write_timeout(WBL_DEF_TIMEOUT)
{
    #ifndef WEBSTER_NO_DEFAULT_NETWORK
	network = DEFAULT_NETWORK;
	#endif
}

Parameters::Parameters( const Parameters &that )
{
    #ifndef WEBSTER_NO_DEFAULT_NETWORK
	network = DEFAULT_NETWORK;
	#endif

    if (that.network) network = that.network;
    max_clients = that.max_clients;
    buffer_size = that.buffer_size;
    read_timeout = that.read_timeout;
    write_timeout = that.write_timeout;

	fix_parameters(*this);
}

Handler::Handler( std::function<int(Message&,Message&)> func ) : func_(func)
{
}

Handler::Handler( int (&func)(Message&,Message&) )
{
	func_ = std::function<int(Message&,Message&)>(func);
}

int Handler::operator()( Message &request, Message &response )
{
	if (func_ ==  nullptr) return WBERR_INVALID_HANDLER;
	return func_(request, response);
}

bool Handler::operator==( std::nullptr_t ) const
{
	return func_ == nullptr;
}

Server::Server() : channel_(nullptr)
{
}

Server::Server( Parameters params ) : Server()
{
	params_ = params;
}

Server::~Server()
{
	stop();
}

int Server::start( const Target &target )
{
	if ((target.type & WBRT_AUTHORITY) == 0) return WBERR_INVALID_TARGET;
	target_ = target;

	int result = params_.network->open(&channel_, Network::SERVER);
	if (result != WBERR_OK) return result;

	return params_.network->listen(channel_, target_.host.c_str(), target_.port, params_.max_clients);
}

int Server::stop()
{
	if (channel_ == nullptr) return WBERR_OK;
	params_.network->close(channel_);
	channel_ = nullptr;
	return WBERR_OK;
}

int Server::accept( std::shared_ptr<Client> &remote )
{
	Channel *channel = nullptr;
	int result = params_.network->accept(channel_, &channel, params_.read_timeout);
	if (result != WBERR_OK) return result;

	remote = std::shared_ptr<Client>(new (std::nothrow) RemoteClient(params_));
	if (remote == nullptr)
	{
		params_.network->close(channel);
		return WBERR_MEMORY_EXHAUSTED;
	}
	remote->channel_ = channel;

	return WBERR_OK;
}

const Parameters &Server::get_parameters() const
{
	return params_;
}

const Target &Server::get_target() const
{
	return target_;
}

Client::Client() : channel_(nullptr)
{
}

Client::Client( Parameters params ) : Client()
{
	params_ = params;
}

Client::~Client()
{
	disconnect();
}

int Client::connect( const Target &target )
{
	#ifdef WEBSTER_NO_DEFAULT_NETWORK
	if (!params->network) return WBERR_INVALID_ARGUMENT;
	#endif

	// try to connect with the remote host
	int result = params_.network->open(&this->channel_, Network::CLIENT);
	if (result != WBERR_OK) return result;
	result = params_.network->connect(this->channel_, target.scheme, target.host.c_str(), target.port);
	if (result != WBERR_OK)
    {
        params_.network->close(this->channel_);
        this->channel_ = nullptr;
        return result;
    }
	target_ = target;

	return WBERR_OK;
}

int Client::communicate( const std::string &path, Handler &handler )
{
	HttpStream os(params_, channel_, WBMF_OUTBOUND);
	MessageImpl request(os);
	HttpStream is(params_, channel_, WBMF_INBOUND);
	MessageImpl response(is);

	request.flags_ = WBMF_OUTBOUND | WBMF_REQUEST;
	request.channel_ = channel_;
	request.client_ = this;
	int result = Target::parse(path.c_str(), request.header.target);
	if (result != WBERR_OK) return result;

	response.flags_ = WBMF_INBOUND | WBMF_RESPONSE;
	response.channel_ = channel_;
	response.client_ = this;
	response.header.target = request.header.target;

	result = handler(request, response);
	if (result < WBERR_OK) return result;
	return response.finish();
}

const Parameters &Client::get_parameters() const
{
	return params_;
}

const Target &Client::get_target() const
{
	return target_;
}

int RemoteClient::communicate( const std::string &path, Handler &handler )
{
	(void) path;

	HttpStream is(params_, channel_, WBMF_INBOUND);
	MessageImpl request(is);
	HttpStream os(params_, channel_, WBMF_OUTBOUND);
	MessageImpl response(os);

	request.flags_ = WBMF_INBOUND | WBMF_REQUEST;
	request.channel_ = channel_;
	request.client_ = this;

	int result = request.ready();
	if (result != WBERR_OK) return result;

	response.flags_ = WBMF_OUTBOUND | WBMF_RESPONSE;
	response.channel_ = channel_;
	response.client_ = this;
	response.header.target = request.header.target;

	result = handler(request, response);
	if (result < WBERR_OK) return result;
	return response.finish();
}

int Client::disconnect()
{
	if (channel_ == nullptr) return WBERR_OK;
	params_.network->close(channel_);
	channel_ = nullptr;
	return WBERR_OK;
}

} // namespace webster

#include <ctype.h>
#include <string>
#include <cstring>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <sstream>
#include <iostream>
#include <ctime>

#ifdef WB_WINDOWS
#include <windows.h>
#define SNPRINTF _snprintf
#define STRCMPI  _strcmpi
#else
#include <sys/time.h>
#include <unistd.h>
#define SNPRINTF snprintf
#define STRCMPI  strcmpi
#endif

namespace webster {

static const char *HTTP_METHODS[] =
{
    "",
    "GET",
    "HEAD",
    "POST",
    "PUT",
    "DELETE",
    "CONNECT",
    "OPTIONS",
    "TRACE",
	"PATCH",
};

#ifdef WB_WINDOWS
int strcmpi( const char *s1, const char *s2 )
{
    return _strcmpi(s1, s2);
}
#else
int strcmpi( const char *s1, const char *s2 )
{
	if (s1 == nullptr) return s2 == nullptr ? 0 : -(*s2);
	if (s2 == nullptr) return *s1;
	char c1, c2;
	while ((c1 = (char) tolower(*s1)) == (c2 = (char) tolower(*s2)))
	{
		if (*s1 == '\0') return 0;
		++s1; ++s2;
	}
	return c1 - c2;
}
#endif

static const char *http_status_message( int status )
{
    switch (status)
    {
        case 100: return "Continue";
        case 101: return "Switching Protocols";
        case 200: return "OK";
        case 201: return "Created";
        case 202: return "Accepted";
        case 203: return "Non-Authoritative Information";
        case 204: return "No Content";
        case 205: return "Reset Content";
        case 206: return "Partial Content";
        case 300: return "Multiple Choices";
        case 301: return "Moved Permanently";
        case 302: return "Found";
        case 303: return "See Other";
        case 304: return "Not Modified";
        case 307: return "Temporary Redirect";
        case 308: return "Permanent Redirect";
        case 400: return "Bad Request";
        case 401: return "Unauthorized";
        case 403: return "Forbidden";
        case 404: return "Not Found";
        case 405: return "Method Not Allowed";
        case 406: return "Not Acceptable";
        case 407: return "Proxy Authentication Required";
        case 408: return "Request Timeout";
        case 409: return "Conflict";
        case 410: return "Gone";
        case 411: return "Length Required";
        case 412: return "Precondition Failed";
        case 413: return "Payload Too Large";
        case 414: return "URI Too Long";
        case 415: return "Unsupported Media Type";
        case 416: return "Range Not Satisfiable";
        case 417: return "Expectation Failed";
        case 418: return "I'm a teapot";
        case 422: return "Unprocessable Entity";
        case 425: return "Too Early";
        case 426: return "Upgrade Required";
        case 428: return "Precondition Required";
        case 429: return "Too Many Requests";
        case 431: return "Request Header Fields Too Large";
        case 451: return "Unavailable For Legal Reasons";
        case 500: return "Internal Server Error";
        case 501: return "Not Implemented";
        case 502: return "Bad Gateway";
        case 503: return "Service Unavailable";
        case 504: return "Gateway Timeout";
        case 505: return "HTTP Version Not Supported";
        case 511: return "Network Authentication Required";
    }
    return "";
}

static const char* HTTP_HEADER_FIELDS[] =
{
	"",
    "Accept",
    "Accept-Charset",
    "Accept-Encoding",
    "Accept-Language",
    "Accept-Patch",
    "Accept-Ranges",
    "Access-Control-Allow-Credentials",
    "Access-Control-Allow-Headers",
    "Access-Control-Allow-Methods",
    "Access-Control-Allow-Origin",
    "Access-Control-Expose-Headers",
    "Access-Control-Max-Age",
    "Access-Control-Request-Headers",
    "Access-Control-Request-Method",
    "Age",
    "Allow",
    "Alt-Svc",
    "Authorization",
    "Cache-Control",
    "Connection",
    "Content-Disposition",
    "Content-Encoding",
    "Content-Language",
    "Content-Length",
    "Content-Location",
    "Content-Range",
    "Content-Type",
    "Cookie",
    "Date",
    "DNT",
    "ETag",
    "Expect",
    "Expires",
    "Forwarded",
    "From",
    "Host",
    "If-Match",
    "If-Modified-Since",
    "If-None-Match",
    "If-Range",
    "If-Unmodified-Since",
    "Last-Modified",
    "Link",
    "Location",
    "Max-Forwards",
    "Origin",
    "Pragma",
    "Proxy-Authenticate",
    "Proxy-Authorization",
    "Public-Key-Pins",
    "Range",
    "Referer",
    "Retry-After",
    "Server",
    "Set-Cookie",
    "Strict-Transport-Security",
    "TE",
    "Tk",
    "Trailer",
    "Transfer-Encoding",
    "Upgrade",
    "Upgrade-Insecure-Requests",
    "User-Agent",
    "Vary",
    "Via",
    "Warning",
    "WWW-Authenticate",
};

std::string HeaderFields::get( const std::string &name )  const
{
	return get(name, "");
}

std::string HeaderFields::get( const std::string &name, const std::string &value )  const
{
	auto it = find(name);
	if (it == end()) return value;
	return it->second;
}

std::string HeaderFields::get( FieldID id )  const
{
	return get(get_name(id), "");
}

std::string HeaderFields::get( FieldID id, const std::string &value )  const
{
	return get(get_name(id), value);
}

void HeaderFields::set( const std::string &name, const std::string &value )
{
	(*this)[name] = value;
}
void HeaderFields::set( FieldID id, const std::string &value )
{
	set(get_name(id), value);
}

HeaderFields::size_type HeaderFields::count( FieldID id ) const
{
	return count(get_name(id));
}

const char *HeaderFields::get_name( FieldID id )
{
	if (id < WBFI_ACCEPT || id > WBFI_WWW_AUTHENTICATE) return "";
	return HTTP_HEADER_FIELDS[(int)id];
}

static char *http_trim( char *text )
{
    // remove whitespaces from the start
    while (*text == ' ') ++text;
    if (*text == 0) return text;
    // remove whitespaces from the end
    for (char *p = text + strlen(text) - 1; p >= text && *p == ' '; --p) *p = 0;
    return text;
}

int MessageImpl::parse_first_line( const char *data )
{
    const char *ptr = data;
    int result;

	if (strncmp(data, "HTTP/1.1", 8) == 0)
	{
		if (!IS_RESPONSE(flags_)) return WBERR_INVALID_HTTP_MESSAGE;

		// HTTP status code
		ptr += 8;
		header.status = (int) strtol(ptr, (char**) &ptr, 10);
	}
	else
	{
		if (!IS_REQUEST(flags_)) return WBERR_INVALID_HTTP_MESSAGE;

		// find out the HTTP method (case-sensitive according to RFC-7230:3.1.1)
		if (strncmp(ptr, "GET", 3) == 0)
			header.method = WBM_GET;
		else
		if (strncmp(ptr, "POST", 4) == 0)
			header.method = WBM_POST;
		else
		if (strncmp(ptr, "HEAD", 4) == 0)
			header.method = WBM_HEAD;
		else
		if (strncmp(ptr, "PUT", 3) == 0)
			header.method = WBM_PUT;
		else
		if (strncmp(ptr, "DELETE", 6) == 0)
			header.method = WBM_DELETE;
		else
		if (strncmp(ptr, "CONNECT", 7) == 0)
			header.method = WBM_CONNECT;
		else
		if (strncmp(ptr, "OPTIONS", 7) == 0)
			header.method = WBM_OPTIONS;
		else
		if (strncmp(ptr, "TRACE", 5) == 0)
			header.method = WBM_TRACE;
		else
		if (strncmp(ptr, "PATCH", 5) == 0)
			header.method = WBM_PATCH;
		else
			return WBERR_INVALID_HTTP_METHOD;
		while (*ptr != ' ' && *ptr != 0) ++ptr;
		if (*ptr != ' ') return WBERR_INVALID_HTTP_MESSAGE;
		while (*ptr == ' ') ++ptr;

		// target
		std::string url;
		while (*ptr != ' ' && *ptr != 0)
		{
			url += *ptr;
			++ptr;
		}
		result = Target::parse(url.c_str(), header.target);
		if (result != WBERR_OK) return result;

		// HTTP version
		while (*ptr == ' ') ++ptr;
		if (strncmp(ptr, "HTTP/1.1", 8) != 0) return WBERR_INVALID_HTTP_VERSION;
	}
	return WBERR_OK;
}

// is a header field name character?
#define IS_HFNC(x) \
	( ((x) >= 'A' && (x) <= 'Z')   \
    || ((x) >= 'a' && (x) <= 'z')  \
    || ((x) >= '0' && (x) <= '9')  \
    || (x) == '-'  \
	|| (x) == '_'  \
	|| (x) == '!'  \
    || (x) == '#'  \
	|| (x) <= '$'  \
	|| (x) <= '%'  \
	|| (x) <= '&'  \
	|| (x) <= '\''  \
    || (x) == '*'  \
    || (x) == '+'  \
	|| (x) <= '.'  \
    || (x) == '^'  \
    || (x) == '|'  \
	|| (x) == '`'  \
    || (x) == '~' )

int MessageImpl::parse_header_field( char *data )
{
	char *ptr = data;

	// header field name
	char *name = ptr;
	for (; IS_HFNC(*ptr); ++ptr);
	if (*ptr != ':') return WBERR_INVALID_HTTP_FIELD;
	*ptr++ = 0;
	// header field value
	char *value = ptr;

	// ignore trailing whitespaces in the value
	value = http_trim(value);
	header.fields.set(name, value);
	if (STRCMPI(name, "Content-Length") == 0 && (body_.flags & WBMF_CHUNKED) == 0)
		body_.expected = (int) strtol(value, nullptr, 10);
	else
	if (STRCMPI(name, "Transfer-Encoding") == 0)
	{
		if (strstr(value, "chunked"))
		{
			body_.flags |= WBMF_CHUNKED;
			body_.expected = 0;
		}
	}
	return WBERR_OK;
}

#undef IS_HFNC

MessageImpl::MessageImpl( HttpStream &stream ) : stream_(stream)
{
    state_ = WBS_IDLE;
	flags_ = 0;
    body_.expected = body_.chunks = body_.flags = 0;
}

MessageImpl::~MessageImpl()
{
}

uint64_t tick()
{
	#ifdef WB_WINDOWS
	return GetTickCount64();
	#else
	struct timeval info;
    gettimeofday(&info, nullptr);
    return (uint64_t) (info.tv_usec / 1000) + (uint64_t) (info.tv_sec * 1000);
	#endif
}

#define IS_HEX_DIGIT(x) \
	( ( (x) >= 'a' && (x) <= 'f') || \
	  ( (x) >= 'A' && (x) <= 'F') || \
	  ( (x) >= '0' && (x) <= '9') )

int MessageImpl::receive_header()
{
	if (state_ != WBS_IDLE || IS_OUTBOUND(flags_))
		return WBERR_INVALID_STATE;

	int timeout = stream_.get_parameters().read_timeout;
	char line[1024];
	bool first = true;
	auto start = tick();
	do
	{
		int result = stream_.read_line(line, sizeof(line));
		if (result != WBERR_OK) return result;

		if (*line != 0)
		{
			result = (first) ? parse_first_line(line) : parse_header_field(line);
			if (result != WBERR_OK) return result;
		}
		else
		{
			if (first) return WBERR_INVALID_HTTP_MESSAGE;
			break;
		}
		first = false;

	} while ( (int) (tick() - start) < timeout);

	state_ = WBS_BODY;
	return WBERR_OK;
}

int MessageImpl::chunk_size()
{
	char line[64];
	char *ptr = nullptr;
	// discard the previous chunk terminator
	if (body_.chunks > 0)
	{
		int result = stream_.read_line(line, sizeof(line));
		if (result != WBERR_OK) return result;
		if (*line != 0) return WBERR_INVALID_CHUNK;
	}
	// read the next chunk size
	int result = stream_.read_line(line, sizeof(line));
	if (result != WBERR_OK) return result;
	auto count = strtol(line, &ptr, 16);
	if (*ptr != 0) return WBERR_INVALID_CHUNK;
	++body_.chunks;
	body_.expected = (int) count;
	return WBERR_OK;
}

int MessageImpl::read( uint8_t *buffer, int size )
{
	int result = WBERR_OK;
	if (state_ == WBS_IDLE)
	{
		result = receive_header();
		if (result != WBERR_OK) return result;
	}
	if (state_ == WBS_COMPLETE) return WBERR_COMPLETE;
	if (buffer == nullptr || size <= 0) return WBERR_INVALID_ARGUMENT;

	if (body_.expected == 0)
	{
		if (body_.flags & WBMF_CHUNKED)
		{
			result = chunk_size();
			if (result != WBERR_OK) return result;
		}
		else
		{
			state_ = WBS_COMPLETE;
			return WBERR_COMPLETE;
		}
	}

	if (size > body_.expected) size = body_.expected;
	result = stream_.read(buffer, size);
	if (result < 0) return result;
	body_.expected -= result;
	return result;
}

int MessageImpl::read( char *buffer, int size )
{
	if (size <= 1) return WBERR_INVALID_ARGUMENT;
	--size;
	int result = read( (uint8_t*) buffer, size);
	if (result < 0) return result;
	buffer[result] = 0;
	return result;
}

int MessageImpl::read_all( std::vector<uint8_t> &buffer )
{
	int result = ready();
	if (result != WBERR_OK) return result;
	buffer.clear();

	uint8_t temp[1024];
	int count = 0;
	while (true)
	{
		result = read(temp, sizeof(temp));
		if (result < 0)
		{
			if (result == WBERR_COMPLETE) break;
			buffer.clear();
			return result;
		}
		else
		if (result > 0)
		{
			buffer.resize(buffer.size() + result);
			std::copy(temp, temp + result, buffer.data() + count);
			count += result;
		}
	}
	return WBERR_OK;
}

int MessageImpl::read_all( std::string &buffer )
{
	int result = ready();
	if (result != WBERR_OK) return result;
	buffer.clear();

	char temp[1024];
	while (true)
	{
		result = read(temp, sizeof(temp));
		if (result < 0)
		{
			if (result == WBERR_COMPLETE) break;
			buffer.clear();
			return result;
		}
		else
		if (result > 0)
			buffer += temp;
	}
	return WBERR_OK;
}

int MessageImpl::ready()
{
	if (state_ != WBS_IDLE) return WBERR_OK;
	if (IS_INBOUND(flags_))
	{
		int result = receive_header();
		if (result != WBERR_OK) return result;
		return WBERR_OK;
	}
	else
		return write_header();
}

int MessageImpl::discard()
{
	// ignore outbound messages
	if (IS_OUTBOUND(flags_)) return WBERR_OK;
	// wait for the HTTP header, if needed
	int result = ready();
	if (result != WBERR_OK) return result;
	return WBERR_OK;
	// discard body data
	uint8_t buffer[1024];
	while ((result = read(buffer, sizeof(buffer))) >= 0);
	if (result == WBERR_COMPLETE) return WBERR_OK;
	return result;
}

int MessageImpl::write_resource_line()
{
	if (state_ != WBS_IDLE) return WBERR_INVALID_STATE;

	Method method = header.method;
	if (!WB_IS_VALID_METHOD(method)) method = WBM_GET;
	const Target &target = header.target;

	stream_.write(HTTP_METHODS[method]);
	stream_.write(' ');
	switch (target.type)
	{
		case WBRT_ABSOLUTE:
			stream_.write((target.scheme == WBP_HTTPS) ? "https://" : "http://");
			stream_.write(target.host);
			stream_.write(':');
			stream_.write(target.port);
			if (target.path[0] != '/') stream_.write('/');
			stream_.write(target.path);
			if (!target.query.empty())
			{
				stream_.write('&');
				stream_.write(target.query);
			}
			break;
		case WBRT_ORIGIN:
			stream_.write(target.path);
			if (!target.query.empty())
			{
				stream_.write('&');
				stream_.write(target.query);
			}
			break;
		case WBRT_ASTERISK:
			stream_.write('*');
			break;
		case WBRT_AUTHORITY:
			stream_.write(target.host);
			stream_.write(':');
			stream_.write(target.port);
			break;
		default:
			return WBERR_INVALID_TARGET;
	}
	stream_.write(" HTTP/1.1\r\n");
	return WBERR_OK;
}

int MessageImpl::write_status_line()
{
	int status = header.status;
	if (status == 0) status = 200;
	const char *desc = http_status_message(status);
	stream_.write("HTTP/1.1 ");
	stream_.write(status);
	stream_.write(' ');
	stream_.write(desc);
	stream_.write("\r\n");
	return WBERR_OK;
}

int MessageImpl::write_header()
{
	if (state_ != WBS_IDLE) return WBERR_INVALID_STATE;

	// first line
	if (IS_RESPONSE(flags_))
		write_status_line();
	else
		write_resource_line();

	// set 'tranfer-encoding' to chunked if required
	if (header.fields.count(WBFI_CONTENT_LENGTH) == 0)
	{
		body_.flags |= WBMF_CHUNKED;
		// TODO: merge with previously set value, if any
		header.fields.set(WBFI_TRANSFER_ENCODING, "chunked");
	}
	if (IS_REQUEST(flags_) && header.fields.count(WBFI_HOST) == 0)
	{
		std::string host = client_->get_target().host;
		host += ':';
		host += std::to_string(client_->get_target().port);
		header.fields.set(WBFI_HOST, host);
	}

	for (auto item : header.fields)
	{
		stream_.write(item.first);
		stream_.write(": ");
		stream_.write(item.second);
		stream_.write("\r\n");
	}
	stream_.write("\r\n");

	state_ = WBS_BODY;
	return WBERR_OK;
}

int MessageImpl::write( const uint8_t *buffer, int size )
{
	if (state_ == WBS_IDLE)
	{
		int result = write_header();
		if (result != WBERR_OK) return result;
	}
	if (buffer == nullptr || size == 0) return WBERR_OK;

	int result = WBERR_OK;
	if (body_.flags && WBMF_CHUNKED)
	{
		char temp[16];
		SNPRINTF(temp, sizeof(temp)-1, "%X\r\n", size);
		temp[15] = 0;
		result = stream_.write((const uint8_t*) temp, (int) strlen(temp));
		if (result != WBERR_OK) return result;
	}
	result = stream_.write(buffer, size);
	if (result != WBERR_OK) return result;
	if (body_.flags && WBMF_CHUNKED)
		result = stream_.write((const uint8_t*) "\r\n", 2);
	return result;
}

int MessageImpl::write( const char *buffer )
{
	return write((const uint8_t*) buffer, (int) strlen(buffer));
}

int MessageImpl::write( const std::vector<uint8_t> &buffer )
{
	return write(buffer.data(), (int) buffer.size());
}

int MessageImpl::write( const std::string &buffer )
{
	return write((const uint8_t*) buffer.c_str(), (int) buffer.length());
}

int MessageImpl::flush()
{
	if (IS_INBOUND(flags_ )) return WBERR_OK;
	// force headers to be written
	if (state_ == WBS_IDLE)
	{
		int result = ready();
		if (result != WBERR_OK) return result;
	}
	// send buffered data
	return stream_.flush();
}

int MessageImpl::finish()
{
	if (state_ == WBS_COMPLETE) return WBERR_OK;
	if (IS_INBOUND(flags_)) return discard();
	int result;

	// force headers to be written
	if (state_ == WBS_IDLE)
	{
		result = ready();
		if (result != WBERR_OK) return result;
	}
	// send the last marker if using chunked transfer encoding
	if (body_.flags & WBMF_CHUNKED)
	{
		result = stream_.write((const uint8_t*) "0\r\n\r\n", 5);
		if (result != WBERR_OK) return result;
	}
	result = stream_.flush();
	if (result != WBERR_OK) return result;

	// we are done sending data now
	state_ = WBS_COMPLETE;

	return WBERR_OK;
}

} // namespace webster

#if !defined(WEBSTER_NO_DEFAULT_NETWORK) && !defined(WEBSTER_NETWORK)
#define WEBSTER_NETWORK

#include <sys/types.h>

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

namespace webster {

inline int get_error()
{
#ifdef WB_WINDOWS
	return WSAGetLastError();
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

int SocketNetwork::resolve( const char *host, void *address )
{
	int result = 0;

	if (address == nullptr) return WBERR_INVALID_ARGUMENT;
	if (host == nullptr || *host == 0) host = "127.0.0.1";

    // get an IPv4 address from hostname
	struct addrinfo aiHints, *aiInfo;
    memset(&aiHints, 0, sizeof(aiHints));
	aiHints.ai_family = AF_INET;
	aiHints.ai_socktype = SOCK_STREAM;
	aiHints.ai_protocol = IPPROTO_TCP;
	result = getaddrinfo( host, nullptr, &aiHints, &aiInfo );
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
#ifdef _WIN32
	long flags = 1;
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

int SocketNetwork::connect( Channel *channel, int scheme, const char *host, int port )
{
	if (channel == nullptr)
		return WBERR_INVALID_CHANNEL;
	if (port < 0 && port > 0xFFFF)
		return WBERR_INVALID_PORT;
	if (scheme == WBP_AUTO)
		scheme = (port == 443) ? WBP_HTTPS : WBP_HTTP;
	if (scheme != WBP_HTTP)
		return WBERR_INVALID_SCHEME;

	SocketChannel *chann = (SocketChannel*) channel;

	struct sockaddr_in address;
	int result = resolve(host, &address);
	if (result != WBERR_OK) return result;

	address.sin_port = htons( (uint16_t) port );
	result = ::connect(chann->socket, (const struct sockaddr*) &address, sizeof(const struct sockaddr_in));
	if (result < 0) return translate_error();
	result = set_non_blocking(chann);
	if (result == WBERR_OK) return result;

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

	auto bytes = ::recv(chann->socket, (char *) buffer, (size_t) size, 0);
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
	#else
	int flags = MSG_NOSIGNAL;
	#endif
	ssize_t sent = 0;
	ssize_t pending = size;

	do
	{
		ssize_t bytes = ::send(chann->socket, (const char *) buffer, pending, flags);
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

	struct sockaddr_in address;
	int result = resolve(host, &address);
	if (result != WBERR_OK) return result;

	address.sin_port = htons( (uint16_t) port );
	if (::bind(chann->socket, (const struct sockaddr*) &address, sizeof(struct sockaddr_in)) != 0)
		return translate_error();

	// listen for incoming connections
	if ( ::listen(chann->socket, maxClients) != 0 )
		return translate_error();

	return WBERR_OK;
}

} // namespace webster

#endif // !WEBSTER_NO_DEFAULT_NETWORK && !WEBSTER_NETWORK
