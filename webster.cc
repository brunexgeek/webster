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

#define _POSIX_C_SOURCE 200112L

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

namespace webster {

std::shared_ptr<SocketNetwork> DEFAULT_NETWORK = std::make_shared<SocketNetwork>();

Target::Target() : type(0), scheme(WBP_HTTP), port(80)
{
}

static std::string string_cut(
    const char *text,
    size_t offset,
    size_t length )
{
    if (text == NULL) return NULL;

    size_t len = strlen(text);
    if (offset + length > len) return NULL;

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
    if (url == nullptr || url[0] == 0) return WBERR_INVALID_URL;

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
		if (hb == NULL) return WBERR_INVALID_URL;
		hb += 3;
		const char *he = hb;
		while (*he != ':' && *he != '/' && *he != 0) ++he;
		if (hb == he) return WBERR_INVALID_URL;

		const char *rb = he;
		const char *re = NULL;

		// extract the port number, if any
		const char *pb = he;
		const char *pe = NULL;
		if (*pb == ':')
		{
			pe = ++pb;
			while (*pe >= '0' && *pe <= '9' && *pe != 0) ++pe;
			if (pb == pe || (pe - pb) > 5) return WBERR_INVALID_URL;
			rb = pe;
		}

		// extract the resource
		if (*rb == '/')
		{
			re = rb;
			while (*re != 0) ++re;
		}
		if (re != NULL && *re != 0) return WBERR_INVALID_URL;

		// return the scheme
		if (url[4] == ':')
			target.scheme = WBP_HTTP;
		else
			target.scheme = WBP_HTTPS;

		// return the port number, if any
		if (pe != NULL)
		{
			target.port = 0;
			int mult = 1;
			while (--pe >= pb)
			{
				target.port += (int) (*pe - '0') * mult;
				mult *= 10;
			}
			if (target.port > 65535 || target.port < 0)
                return WBERR_INVALID_URL;
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
		if (re != NULL)
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
        if (hb != NULL)
        {
            target.user = string_cut(url, 0, (size_t) (hb - url));
            hb++;
        }
        else
            hb = url;

        const char *he = strchr(hb, ':');
        if (he != NULL)
        {
            target.host = string_cut(hb, 0, (size_t) (he - hb));
            target.port = 0;

            const char *pb = he + 1;
            const char *pe = pb;
            while (*pe >= '0' && *pe <= '9' && *pe != 0) ++pe;
            if (*pe != 0) return WBERR_INVALID_URL;

			int mult = 1;
			while (--pe >= pb)
			{
				target.port += (int) (*pe - '0') * mult;
				mult *= 10;
			}
			if (target.port > 65535 || target.port < 0)
                return WBERR_INVALID_URL;
        }
        else
        {
            target.host = std::string(hb);
            target.port = 80;
        }
    }

    return WBERR_OK;
}

Header::Header() : content_length(0), status(200), method(WBM_GET) {}

Parameters::Parameters() : max_clients(WBL_DEF_CONNECTIONS), buffer_size(WBL_DEF_BUFFER_SIZE),
	read_timeout(WBL_DEF_TIMEOUT)
{
    #ifdef WEBSTER_NO_DEFAULT_NETWORK
	network = nullptr;
	#else
	network = DEFAULT_NETWORK;
	#endif
}

Parameters::Parameters( const Parameters &that )
{
    #ifdef WEBSTER_NO_DEFAULT_NETWORK
	network = nullptr;
	#else
	network = DEFAULT_NETWORK;
	#endif

    if (that.network) network = that.network;
    max_clients = that.max_clients;
    buffer_size = (uint32_t) (that.buffer_size + 3) & (uint32_t) (~3);
    read_timeout = that.read_timeout;

	if (max_clients <= 0)
		max_clients = WBL_DEF_CONNECTIONS;
	else
	if (max_clients > WBL_MAX_CONNECTIONS)
		max_clients = WBL_MAX_CONNECTIONS;

	if (buffer_size == 0)
		buffer_size = WBL_DEF_BUFFER_SIZE;
	else
	if (buffer_size > WBL_MAX_BUFFER_SIZE)
		buffer_size = WBL_MAX_BUFFER_SIZE;

	if (read_timeout <= 0)
		read_timeout = WBL_DEF_TIMEOUT;
	else
	if (read_timeout > WBL_MAX_TIMEOUT)
		read_timeout = WBL_MAX_TIMEOUT;
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
	Channel *channel = NULL;
	int result = params_.network->accept(channel_, &channel);
	if (result != WBERR_OK) return result;

	remote = std::shared_ptr<Client>(new (std::nothrow) RemoteClient(params_));
	if (remote == NULL)
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
        return result;
    }
	target_ = target;

	return WBERR_OK;
}

int Client::communicate( const std::string &path, Handler &handler )
{
	MessageImpl request;
	MessageImpl response;

	request.flags_ = WBMT_OUTBOUND | WBMT_REQUEST;
	request.channel_ = channel_;
	request.client_ = this;
	int result = Target::parse(path.c_str(), request.header.target);
	if (result != WBERR_OK) return result;

	response.flags_ = WBMT_INBOUND | WBMT_RESPONSE;
	response.channel_ = channel_;
	response.client_ = this;
	response.header.target = request.header.target;

	result = handler(request, response);
	if (result > 0) result = 0;
	result = response.finish();

	return result;
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

	MessageImpl request;
	MessageImpl response;

	request.flags_ = WBMT_INBOUND | WBMT_REQUEST;
	request.channel_ = channel_;
	request.client_ = this;

	int result = request.receiveHeader(params_.read_timeout);

	if (result != WBERR_OK) return result;
	response.flags_ = WBMT_OUTBOUND | WBMT_RESPONSE;
	response.channel_ = channel_;
	response.client_ = this;
	response.header.target = request.header.target;

	result = handler(request, response);
	if (result > 0) result = 0;

	result = response.finish();

	return result;
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

const char *http_statusMessage( int status )
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
/*
webster_field_info_t HTTP_HEADER_FIELDS[] =
{
    { "Accept"                          , WBFI_ACCEPT },
    { "Accept-Charset"                  , WBFI_ACCEPT_CHARSET },
    { "Accept-Encoding"                 , WBFI_ACCEPT_ENCODING },
    { "Accept-Language"                 , WBFI_ACCEPT_LANGUAGE },
    { "Accept-Patch"                    , WBFI_ACCEPT_PATCH },
    { "Accept-Ranges"                   , WBFI_ACCEPT_RANGES },
    { "Access-Control-Allow-Credentials", WBFI_ACCESS_CONTROL_ALLOW_CREDENTIALS },
    { "Access-Control-Allow-Headers"    , WBFI_ACCESS_CONTROL_ALLOW_HEADERS },
    { "Access-Control-Allow-Methods"    , WBFI_ACCESS_CONTROL_ALLOW_METHODS },
    { "Access-Control-Allow-Origin"     , WBFI_ACCESS_CONTROL_ALLOW_ORIGIN },
    { "Access-Control-Expose-Headers"   , WBFI_ACCESS_CONTROL_EXPOSE_HEADERS },
    { "Access-Control-Max-Age"          , WBFI_ACCESS_CONTROL_MAX_AGE },
    { "Access-Control-Request-Headers"  , WBFI_ACCESS_CONTROL_REQUEST_HEADERS },
    { "Access-Control-Request-Method"   , WBFI_ACCESS_CONTROL_REQUEST_METHOD },
    { "Age"                             , WBFI_AGE },
    { "Allow"                           , WBFI_ALLOW },
    { "Alt-Svc"                         , WBFI_ALT_SVC },
    { "Authorization"                   , WBFI_AUTHORIZATION },
    { "Cache-Control"                   , WBFI_CACHE_CONTROL },
    { "Connection"                      , WBFI_CONNECTION },
    { "Content-Disposition"             , WBFI_CONTENT_DISPOSITION },
    { "Content-Encoding"                , WBFI_CONTENT_ENCODING },
    { "Content-Language"                , WBFI_CONTENT_LANGUAGE },
    { "Content-Length"                  , WBFI_CONTENT_LENGTH },
    { "Content-Location"                , WBFI_CONTENT_LOCATION },
    { "Content-Range"                   , WBFI_CONTENT_RANGE },
    { "Content-Type"                    , WBFI_CONTENT_TYPE },
    { "Cookie"                          , WBFI_COOKIE },
    { "Date"                            , WBFI_DATE },
    { "DNT"                             , WBFI_DNT },
    { "ETag"                            , WBFI_ETAG },
    { "Expect"                          , WBFI_EXPECT },
    { "Expires"                         , WBFI_EXPIRES },
    { "Forwarded"                       , WBFI_FORWARDED },
    { "From"                            , WBFI_FROM },
    { "Host"                            , WBFI_HOST },
    { "If-Match"                        , WBFI_IF_MATCH },
    { "If-Modified-Since"               , WBFI_IF_MODIFIED_SINCE },
    { "If-None-Match"                   , WBFI_IF_NONE_MATCH },
    { "If-Range"                        , WBFI_IF_RANGE },
    { "If-Unmodified-Since"             , WBFI_IF_UNMODIFIED_SINCE },
    { "Last-Modified"                   , WBFI_LAST_MODIFIED },
    { "Link"                            , WBFI_LINK },
    { "Location"                        , WBFI_LOCATION },
    { "Max-Forwards"                    , WBFI_MAX_FORWARDS },
    { "Origin"                          , WBFI_ORIGIN },
    { "Pragma"                          , WBFI_PRAGMA },
    { "Proxy-Authenticate"              , WBFI_PROXY_AUTHENTICATE },
    { "Proxy-Authorization"             , WBFI_PROXY_AUTHORIZATION },
    { "Public-Key-Pins"                 , WBFI_PUBLIC_KEY_PINS },
    { "Range"                           , WBFI_RANGE },
    { "Referer"                         , WBFI_REFERER },
    { "Retry-After"                     , WBFI_RETRY_AFTER },
    { "Server"                          , WBFI_SERVER },
    { "Set-Cookie"                      , WBFI_SET_COOKIE },
    { "Strict-Transport-Security"       , WBFI_STRICT_TRANSPORT_SECURITY },
    { "TE"                              , WBFI_TE },
    { "Tk"                              , WBFI_TK },
    { "Trailer"                         , WBFI_TRAILER },
    { "Transfer-Encoding"               , WBFI_TRANSFER_ENCODING },
    { "Upgrade"                         , WBFI_UPGRADE },
    { "Upgrade-Insecure-Requests"       , WBFI_UPGRADE_INSECURE_REQUESTS },
    { "User-Agent"                      , WBFI_USER_AGENT },
    { "Vary"                            , WBFI_VARY },
    { "Via"                             , WBFI_VIA },
    { "Warning"                         , WBFI_WARNING },
    { "WWW-Authenticate"                , WBFI_WWW_AUTHENTICATE },
};
*/

char *http_removeTrailing( char *text )
{
    // remove whitespaces from the start
    while (*text == ' ') ++text;
    if (*text == 0) return text;
    // remove whitespaces from the end
    for (char *p = text + strlen(text) - 1; p >= text && *p == ' '; --p) *p = 0;
    return text;
}

int MessageImpl::parse( char *data )
{
    static const int STATE_FIRST_LINE = 1;
    static const int STATE_HEADER_FIELD = 2;
    static const int STATE_COMPLETE = 3;

    int state = STATE_FIRST_LINE;
    char *ptr = data;
    char *token = ptr;
    int result;

    body_.expected = 0;
    body_.chunks = 0;

    while (state != STATE_COMPLETE || *ptr == 0)
    {
        // process the first line
        if (state == STATE_FIRST_LINE)
        {
            for (token = ptr; *ptr != ' ' && *ptr != 0; ++ptr);
            if (*ptr != ' ') return WBERR_INVALID_HTTP_MESSAGE;
            *ptr++ = 0;

            if (strcmp(token, "HTTP/1.1") == 0)
            {
                if (!(flags_ & WBMT_RESPONSE)) return WBERR_INVALID_HTTP_MESSAGE;

                // HTTP status code
                for (token = ptr; *ptr >= '0' && *ptr <= '9'; ++ptr);
                if (*ptr != ' ') return WBERR_INVALID_HTTP_MESSAGE;
                *ptr++ = 0;
                header.status = (int) strtol(token, nullptr, 10);
                // HTTP status message
                for (token = ptr; *ptr != '\r' && *ptr != 0; ++ptr);
                if (ptr[0] != '\r' || ptr[1] != '\n')
                    return WBERR_INVALID_HTTP_MESSAGE;
                *ptr++ = 0;
                ++ptr;

                state = STATE_HEADER_FIELD;
            }
            else
            {
                if (!(flags_ & WBMT_REQUEST)) return WBERR_INVALID_HTTP_MESSAGE;

                // find out the HTTP method (case-sensitive according to RFC-7230:3.1.1)
                if (strcmp(token, "GET") == 0)
                    header.method = WBM_GET;
                else
                if (strcmp(token, "POST") == 0)
                    header.method = WBM_POST;
                else
                if (strcmp(token, "HEAD") == 0)
                    header.method = WBM_HEAD;
                else
                if (strcmp(token, "PUT") == 0)
                    header.method = WBM_PUT;
                else
                if (strcmp(token, "DELETE") == 0)
                    header.method = WBM_DELETE;
                else
                if (strcmp(token, "CONNECT") == 0)
                    header.method = WBM_CONNECT;
                else
                if (strcmp(token, "OPTIONS") == 0)
                    header.method = WBM_OPTIONS;
                else
                if (strcmp(token, "TRACE") == 0)
                    header.method = WBM_TRACE;
                else
                if (strcmp(token, "PATCH") == 0)
                    header.method = WBM_PATCH;
                else
                    return WBERR_INVALID_HTTP_METHOD;

                // target
                for (token = ptr; *ptr != ' ' && *ptr != 0; ++ptr);
                if (*ptr != ' ') return WBERR_INVALID_HTTP_MESSAGE;
                *ptr++ = 0;
                result = Target::parse(token, header.target);
                if (result != WBERR_OK) return result;

                // HTTP version
                for (token = ptr; *ptr != '\r' && *ptr != 0; ++ptr);
                if (ptr[0] != '\r' || ptr[1] != '\n') return WBERR_INVALID_HTTP_MESSAGE;
                *ptr++ = 0;
                ++ptr;
                if (strcmp(token, "HTTP/1.1") != 0) return WBERR_INVALID_HTTP_VERSION;

                state = STATE_HEADER_FIELD;
            }
        }
        else
        // process each header field
        if (state == STATE_HEADER_FIELD)
        {
            if (ptr[0] == '\r' && ptr[1] == 0)
            {
                state = STATE_COMPLETE;
                continue;
            }

            // header field name
            char *name = ptr;
            for (; IS_HFNC(*ptr); ++ptr);
            if (*ptr != ':') return WBERR_INVALID_HTTP_MESSAGE;
            *ptr++ = 0;
            // header field value
            char *value = ptr;
            for (; *ptr != '\r' && *ptr != 0; ++ptr);
            if (ptr[0] != '\r' || ptr[1] != '\n') return WBERR_INVALID_HTTP_MESSAGE;
            if ((size_t)(ptr - value) > WBL_MAX_FIELD_VALUE) return WBERR_INVALID_VALUE;
            *ptr++ = 0;
            ++ptr;

            // ignore trailing whitespaces in the value
            value = http_removeTrailing(value);
            header.fields.insert( std::pair<std::string, std::string>(name, value) );
            if (STRCMPI(name, "Content-Length") == 0 && (body_.flags & WBMF_CHUNKED) == 0)
            {
                header.content_length = (int) strtol(value, nullptr, 10);
                body_.expected = header.content_length;
            }
            else
            if (STRCMPI(name, "Transfer-Encoding") == 0)
            {
                if (strstr(value, "chunked"))
				{
					body_.flags |= WBMF_CHUNKED;
                    body_.expected = -1;
				}
            }
        }
        else
            break;
    }

    return WBERR_OK;
}

MessageImpl::MessageImpl( int buffer_size )
{
    if (buffer_size < WBL_MIN_BUFFER_SIZE)
        buffer_size = WBL_MIN_BUFFER_SIZE;
    else
    if (buffer_size > WBL_MAX_BUFFER_SIZE)
        buffer_size = WBL_MAX_BUFFER_SIZE;
    size_t size = (buffer_size + 3) & (uint32_t) (~3);

    state_ = WBS_IDLE;
	flags_ = 0;
    body_.expected = body_.chunks = body_.flags = 0;
    buffer_.data = buffer_.current = (uint8_t*) new(std::nothrow) uint8_t[size]();
	//if (!message->buffer.data) return WBERR_MEMORY_EXHAUSTED;
    buffer_.size = (int) size;
    buffer_.pending = 0;
}

MessageImpl::~MessageImpl()
{
    if (buffer_.data != nullptr) delete[] buffer_.data;
}

static uint64_t webster_tick()
{
	#ifdef WB_WINDOWS
	return GetTickCount64();
	#else
	struct timeval info;
    gettimeofday(&info, NULL);
    return (uint64_t) (info.tv_usec / 1000) + (uint64_t) (info.tv_sec * 1000);
	#endif
}

/**
 * Read data until we find the header terminator or the internal buffer is full.
 */
int MessageImpl::receiveHeader( int timeout )
{
	if (state_ != WBS_IDLE) return WBERR_INVALID_STATE;
	state_ = WBS_HEADER;

	char *ptr = NULL;
	int result = 0;

	if (timeout < 0) timeout = 0;

	// ignore any pending data
	buffer_.pending = 0;

	// Note: when reading input data we leave room in the buffer for a null-terminator
	//       so we can manipulate its content as a string.

	while (true)
	{
		uint32_t bytes = (uint32_t) buffer_.size - (uint32_t) buffer_.pending - 1;
		if (bytes == 0) return WBERR_TOO_LONG;

		// receive new data and adjust pending information
		uint64_t startTime = webster_tick();
		result = client_->get_parameters().network->receive(channel_, buffer_.data + buffer_.pending, &bytes, timeout);
		if (timeout > 0) timeout = timeout - (int) (webster_tick() - startTime);

		if (result == WBERR_OK)
		{
			buffer_.pending += (int) bytes;
			buffer_.current = buffer_.data;
			// ensure we have a null-terminator at the end
			*(buffer_.current + buffer_.pending) = 0;
			ptr = (char*) strstr((const char*)buffer_.current, "\r\n\r\n");
			if (ptr != NULL) break;
		}
		else
		if (result != WBERR_TIMEOUT && result != WBERR_SIGNAL)
			return result;

		if (timeout <= 0) return WBERR_TIMEOUT;
	}

	*(ptr + 3) = 0;
	// remember the last position
	buffer_.current = (uint8_t*) ptr + 4;
	buffer_.pending = buffer_.pending - (int) ( (uint8_t*) ptr + 4 - buffer_.data );
	// parse HTTP header fields and retrieve the content length
	result = parse((char*)buffer_.data);
	if (result != WBERR_OK) return result;
	header.content_length = body_.expected;
	body_.expected -= buffer_.pending;

	return WBERR_OK;
}

int MessageImpl::chunkSize( int timeout )
{
    (void) timeout;
	#if 0
	uint64_t startTime = webster_tick();
	int result = 0;
	uint8_t buffer[64];
	uint32_t bytes = 0;

	if (body_.chunks > 0)
	{
		// receive the terminator of the previous chunk
		bytes = 2;
		result = input->client->config.net->receive(input->channel, buffer, &bytes, timeout);
		if (timeout > 0) timeout = timeout - (int) (webster_tick() - startTime);
	}
	return WBERR_OK;
	#endif
	return WBERR_INVALID_CHUNK;
}

/**
 * Read data until the internal buffer is full or there's no more data to read.
 */
int MessageImpl::receiveBody( int timeout )
{
	if (state_ != WBS_HEADER && state_ != WBS_BODY) return WBERR_INVALID_STATE;
	state_ = WBS_BODY;
	if (timeout < 0) timeout = 0;

	// if not expecting any data, just return success
	if (body_.expected == 0)
	{
		if ((body_.flags & WBMF_CHUNKED) == 0)
			return WBERR_COMPLETE;
		else
		{
			int result = chunkSize(timeout);
			if (result != WBERR_OK) return result;
			if (body_.expected == 0) return WBERR_COMPLETE;
		}
	}
	// if we still have data in the buffer, just return success
	if (buffer_.pending > 0) return WBERR_OK;

	buffer_.pending = 0;

	// Note: when reading input data we leave room in the buffer for a null-terminator
	//       so we can manipulate its content as a string.
	uint32_t bytes = (uint32_t) buffer_.size - (uint32_t) buffer_.pending - 1;
	// prevent reading more that's supposed to
	if (body_.expected >= 0 && bytes > (uint32_t) body_.expected)
		bytes = (uint32_t) body_.expected;

	// receive new data and adjust pending information
	int result = client_->get_parameters().network->receive(channel_, buffer_.data + buffer_.pending, &bytes, timeout);
	if (result == WBERR_OK)
	{
		body_.expected -= (int) bytes;
		buffer_.pending += (int) bytes;
		buffer_.current = buffer_.data;
		// ensure we have a null-terminator at the end
		*(buffer_.current + buffer_.pending) = 0;
	}
	return result;
}

int MessageImpl::read( const uint8_t **buffer, int *size )
{
	int result = WBERR_OK;
	if (state_ == WBS_IDLE)
	{
		result = receiveHeader(client_->get_parameters().read_timeout);
		if (result != WBERR_OK) return result;
	}
	if (buffer == NULL || size == NULL) return WBERR_INVALID_ARGUMENT;

	if (buffer_.pending <= 0 || buffer_.current == NULL)
	{
		result = receiveBody(client_->get_parameters().read_timeout);
		if (result != WBERR_OK) return result;
	}
	if (buffer_.pending <= 0 || buffer_.current == NULL) return WBERR_NO_DATA;

	*buffer = buffer_.current;
	*size = buffer_.pending;

	buffer_.current = NULL;
	buffer_.pending = 0;

	return WBERR_OK;
}

int MessageImpl::read( const char **buffer )
{
	const uint8_t *ptr = nullptr;
	int size = 0;
	int result = read(&ptr, &size);
	*buffer = (const char *) ptr;
	return result;
}

int MessageImpl::read( std::string &buffer )
{
	const char *ptr;
	int result = read(&ptr);
	buffer = ptr;
	return result;
}

int MessageImpl::writeData( const uint8_t *buffer, int size )
{
	if (size == 0 || buffer == NULL) return WBERR_OK;

	// ensures the current pointer is valid
	if (buffer_.current == NULL)
	{
		buffer_.current = buffer_.data;
		buffer_.pending = 0;
	}

	// fragment input data through recursive call until the data size fits the internal buffer
	int offset = 0;
	int result = WBERR_OK;
	int fit = buffer_.size - (int)(buffer_.current - buffer_.data);
	while (size > fit)
	{
		result = writeData(buffer + offset, fit);
		size -= fit;
		offset += fit;
		fit = buffer_.size - (int)(buffer_.current - buffer_.data);
		if (result != WBERR_OK) return result;
	}

	memcpy(buffer_.current, buffer + offset, (size_t) size);
	buffer_.current += size;

	// send pending data if the buffer is full
	if (buffer_.current >= buffer_.data + buffer_.size)
	{
		result = client_->get_parameters().network->send(channel_, buffer_.data, (uint32_t) buffer_.size);
		buffer_.current = buffer_.data;
	}

	return result;
}

int MessageImpl::writeString( const std::string &text )
{
	return writeData((uint8_t*) text.c_str(), (int) text.length());
}

int MessageImpl::compute_resource_line( std::stringstream &ss ) const
{
	if (state_ != WBS_IDLE) return WBERR_INVALID_STATE;

	Method method = header.method;
	if (!WB_IS_VALID_METHOD(method)) method = WBM_GET;
	const Target &target = header.target;

	ss << HTTP_METHODS[method] << ' ';
	switch (target.type)
	{
		case WBRT_ABSOLUTE:
			ss << ((target.scheme == WBP_HTTPS) ? "https://" : "http://");
			ss << target.host << ':' << target.port;
			if (target.path[0] != '/') ss << '/';
				ss << target.path;
			if (!target.query.empty())
				ss << '&' << target.query;
			break;
		case WBRT_ORIGIN:
			ss << target.path;
			if (!target.query.empty())
				ss << '&' << target.query;
			break;
		case WBRT_ASTERISK:
			ss << '*';
			break;
		case WBRT_AUTHORITY:
			ss << target.host << ':' << target.port;
			break;
		default:
			return WBERR_INVALID_RESOURCE;
	}
	ss << " HTTP/1.1\r\n";
	return WBERR_OK;
}

int MessageImpl::compute_status_line( std::stringstream &ss ) const
{
	int status = header.status;
	if (status == 0) status = 200;
	const char *desc = http_statusMessage(status);
	ss << "HTTP/1.1 " << status << ' ' << desc << "\r\n";
	return WBERR_OK;
}

int MessageImpl::writeHeader()
{
	if (state_ != WBS_IDLE) return WBERR_INVALID_STATE;

	std::stringstream ss;

	// first line
	if (flags_ & WBMT_RESPONSE)
		compute_status_line(ss);
	else
		compute_resource_line(ss);

	// set 'tranfer-encoding' to chunked if required
	auto it = header.fields.find("Content-Length");
	if (it == header.fields.end())
	{
		body_.flags |= WBMF_CHUNKED;
		// TODO: merge with previously set value, if any
		header.fields["Transfer-Encoding"] = "chunked";
	}
	if (flags_ & WBMT_REQUEST && header.fields.count("Host") == 0)
		header.fields["Host"] = client_->get_target().host + ':' + std::to_string(client_->get_target().port);

	for (auto item : header.fields)
		ss << item.first << ": " << item.second << "\r\n";
	ss << "\r\n";

	writeString(ss.str());
	state_ = WBS_BODY;
	return WBERR_OK;
}

int MessageImpl::write( const uint8_t *buffer, int size )
{
	if (state_ == WBS_IDLE) writeHeader();
	if (buffer == nullptr || size == 0) return WBERR_OK;

	int result = WBERR_OK;
	if (body_.flags && WBMF_CHUNKED)
	{
		char temp[16];
		SNPRINTF(temp, sizeof(temp)-1, "%X\r\n", size);
		temp[15] = 0;
		result = writeData((const uint8_t*) temp, (int) strlen(temp));
		if (result != WBERR_OK) return result;
	}
	result = writeData(buffer, size);
	if (result != WBERR_OK) return result;
	if (body_.flags && WBMF_CHUNKED)
		result = writeData((const uint8_t*) "\r\n", 2);
	return result;

}

int MessageImpl::write( const char *buffer )
{
	return write((const uint8_t*) buffer, (int) strlen(buffer));
}

int MessageImpl::write( const std::string &text )
{
	return write((const uint8_t*) text.c_str(), (int) text.length());
}

int MessageImpl::flush()
{
	if (state_ == WBS_COMPLETE) return WBERR_INVALID_STATE;

	// ensure we are done with the HTTP header
	if (state_ != WBS_BODY) write(nullptr, 0);
	// send all remaining body data
	if (buffer_.current > buffer_.data)
	{
		client_->get_parameters().network->send(channel_, buffer_.data, (uint32_t) (buffer_.current - buffer_.data));
		buffer_.current = buffer_.data;
	}
	return WBERR_OK;
}

int MessageImpl::finish()
{
	if (state_ == WBS_COMPLETE) return WBERR_INVALID_STATE;
	if (flags_ & WBMT_INBOUND)
    {
        int result = WBERR_OK;
        const uint8_t *ptr;
        int size;
        while ((result = read(&ptr, &size)) == WBERR_OK);
        if (result != WBERR_COMPLETE) return result;
        return WBERR_OK;
    }

	int result = flush();
	if (result != WBERR_OK) return result;

	// send the last marker if using chunked transfer encoding
	if (body_.flags & WBMF_CHUNKED)
		client_->get_parameters().network->send(channel_, (const uint8_t*) "0\r\n\r\n", 5);
	// we are done sending data now
	state_ = WBS_COMPLETE;

	return WBERR_OK;
}

} // namespace webster

#undef IS_HFNC

#if !defined(WEBSTER_NO_DEFAULT_NETWORK) && !defined(WEBSTER_NETWORK)
#define WEBSTER_NETWORK

#include <sys/types.h>

#ifdef WB_WINDOWS
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
typedef SSIZE_T ssize_t;
CRITICAL_SECTION network_mutex;
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

namespace webster {

struct SocketChannel : public Channel
{
	#ifdef WB_WINDOWS
	SOCKET socket;
	#else
	int socket;
	#endif
	struct pollfd poll;
};

static int network_lookupIPv4( const char *host, struct sockaddr_in *address )
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

int SocketNetwork::open( Channel **channel, Type type )
{
	(void) type;

	if (channel == NULL) return WBERR_INVALID_CHANNEL;

	*channel = new(std::nothrow) SocketChannel();
	if (*channel == NULL) return WBERR_MEMORY_EXHAUSTED;

	SocketChannel *chann = (SocketChannel*) *channel;

	chann->socket = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (chann->socket == -1) return WBERR_SOCKET;
	chann->poll.fd = chann->socket;
	chann->poll.events = POLLIN;

	// allow socket descriptor to be reuseable
	int on = 1;
	::setsockopt(chann->socket, SOL_SOCKET,  SO_REUSEADDR, (char *)&on, sizeof(int));

	return WBERR_OK;
}

int SocketNetwork::close( Channel *channel )
{
	if (channel == NULL) return WBERR_INVALID_CHANNEL;

	SocketChannel *chann = (SocketChannel*) channel;

	#ifdef WB_WINDOWS
	::shutdown(chann->socket, SD_BOTH);
	::closesocket(chann->socket);
	#else
	::shutdown(chann->socket, SHUT_RDWR);
	::close(chann->socket);
	#endif

	chann->socket = chann->poll.fd = 0;
	delete channel;

	return WBERR_OK;
}

int SocketNetwork::connect( Channel *channel, int scheme, const char *host, int port )
{
	if (channel == NULL)
		return WBERR_INVALID_CHANNEL;
	if (port < 0 && port > 0xFFFF)
		return WBERR_INVALID_PORT;
	if (host == nullptr || host[0] == 0)
		return WBERR_INVALID_HOST;
	if (scheme != WBP_HTTP)
		return WBERR_INVALID_SCHEME;

	SocketChannel *chann = (SocketChannel*) channel;

	struct sockaddr_in address;
	network_lookupIPv4(host, &address);

	address.sin_port = htons( (uint16_t) port );
	if (::connect(chann->socket, (const struct sockaddr*) &address, sizeof(const struct sockaddr_in)) != 0)
		return WBERR_SOCKET;

	return WBERR_OK;
}

int SocketNetwork::receive( Channel *channel, uint8_t *buffer, uint32_t *size, int timeout )
{
	if (channel == NULL) return WBERR_INVALID_CHANNEL;
	if (buffer == NULL || size == NULL || *size == 0) return WBERR_INVALID_ARGUMENT;
	if (timeout < 0) timeout = -1;

	SocketChannel *chann = (SocketChannel*) channel;
	uint32_t bufferSize = *size;
	*size = 0;
	chann->poll.revents = 0;

	// wait for data
	#ifdef WB_WINDOWS
	int result = WSAPoll(&chann->poll, 1, timeout);
	#else
	int result = ::poll(&chann->poll, 1, timeout);
	#endif
	if (result == 0) return WBERR_TIMEOUT;
	if (result == EINTR) return WBERR_SIGNAL;
	if (result < 0) return WBERR_SOCKET;

	ssize_t bytes = ::recv(chann->socket, (char *) buffer, (size_t) bufferSize, 0);
	if (bytes == ECONNRESET || bytes == EPIPE || bytes == ENOTCONN || bytes == 0)
		return WBERR_NOT_CONNECTED;
	else
	if (bytes < 0)
	{
		*size = 0;
		if (bytes == EWOULDBLOCK || bytes == EAGAIN) return WBERR_NO_DATA;
		return WBERR_SOCKET;
	}
	*size = (uint32_t) bytes;

	return WBERR_OK;
}

int SocketNetwork::send( Channel *channel, const uint8_t *buffer, uint32_t size )
{
	if (channel == NULL) return WBERR_INVALID_CHANNEL;
	if (buffer == NULL || size == 0) return WBERR_INVALID_ARGUMENT;

	SocketChannel *chann = (SocketChannel*) channel;

	#ifdef WB_WINDOWS
	int flags = 0;
	#else
	int flags = MSG_NOSIGNAL;
	#endif
	ssize_t result = ::send(chann->socket, (const char *) buffer, (size_t) size, flags);
	if (result == ECONNRESET || result == EPIPE || result == ENOTCONN)
		return WBERR_NOT_CONNECTED;
	else
	if (result < 0)
		return WBERR_SOCKET;

	return WBERR_OK;
}

int SocketNetwork::accept( Channel *channel, Channel **client )
{
	if (channel == NULL) return WBERR_INVALID_CHANNEL;
	if (client == NULL) return WBERR_INVALID_ARGUMENT;

	SocketChannel *chann = (SocketChannel*) channel;

	#ifdef WB_WINDOWS
	int result = WSAPoll(&chann->poll, 1, 10000);
	#else
	int result = poll(&chann->poll, 1, 10000);
	#endif
	if (result == 0) return WBERR_TIMEOUT;
	if (result == EINTR) return WBERR_SIGNAL;
	if (result < 0) return WBERR_SOCKET;

	*client = new(std::nothrow) SocketChannel();
	if (*client == NULL) return WBERR_MEMORY_EXHAUSTED;

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
		delete (SocketChannel*)*client;
		*client = NULL;
		if (socket == EAGAIN || socket == EWOULDBLOCK)
			return WBERR_NO_CLIENT;
		else
			return WBERR_SOCKET;
	}

	((SocketChannel*)*client)->socket = socket;
	((SocketChannel*)*client)->poll.fd = socket;
	((SocketChannel*)*client)->poll.events = POLLIN;

	return WBERR_OK;
}

int SocketNetwork::listen( Channel *channel, const char *host, int port, int maxClients )
{
	if (channel == NULL)
		return WBERR_INVALID_CHANNEL;
	if ( host == NULL || host[0] == 0)
		return WBERR_INVALID_HOST;
	if (port < 0 && port > 0xFFFF)
		return WBERR_INVALID_PORT;

	SocketChannel *chann = (SocketChannel*) channel;

	struct sockaddr_in address;
	network_lookupIPv4(host, &address);

	address.sin_port = htons( (uint16_t) port );
	if (::bind(chann->socket, (const struct sockaddr*) &address, sizeof(const struct sockaddr_in)) != 0)
		return WBERR_SOCKET;

	// listen for incoming connections
	if ( ::listen(chann->socket, maxClients) != 0 )
		return WBERR_SOCKET;

	return WBERR_OK;
}

} // namespace webster

#endif // !WEBSTER_NO_DEFAULT_NETWORK && !WEBSTER_NETWORK