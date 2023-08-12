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


#include <webster.hh> // AUTO-REMOVE
#include "http.hh"    // AUTO-REMOVE
#include "http1.hh"   // AUTO-REMOVE
#include "stream.hh"  // AUTO-REMOVE
#include "network.hh" // AUTO-REMOVE
#include <sstream>

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

const char *http_method( int value )
{
    if (value >= WBM_GET && value <= WBM_PATCH)
        return HTTP_METHODS[value];
    return "";
}

const char *http_status_message( int status )
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

Header::Header()
{
	clear();
}

Header::Header(Header &&that)
{
	swap(that);
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

HttpListener::HttpListener( std::function<int(Message&,Message&)> func ) : func_(func)
{
}

HttpListener::HttpListener( int (&func)(Message&,Message&) )
{
	func_ = std::function<int(Message&,Message&)>(func);
}

HttpListener::HttpListener(HttpListener &&func) : func_(func.func_)
{
	func.func_ = nullptr;
}

int HttpListener::operator()( Message &request, Message &response )
{
	if (func_ ==  nullptr) return WBERR_INVALID_HANDLER;
	return func_(request, response);
}

HttpClient::HttpClient( ClientType type, Client *client ) : client_(client), proto_(WBCP_HTTP_1), type_(type)
{
}

HttpClient::~HttpClient()
{
    close();
}

int HttpClient::open( const char *url, const Parameters &params )
{
    Target target;
    int result = Target::parse(url, target);
    if (result != WBERR_OK) return result;
    return open(target, params);
}

int HttpClient::open( const Target &url, const Parameters &params )
{
    if (client_ != nullptr)
        return WBERR_ALREADY_CONNECTED;
    if ((url.type & WBRT_AUTHORITY) == 0)
        return WBERR_INVALID_TARGET;

    client_ = new(std::nothrow) Client(params);
    if (client_ == nullptr)
        return WBERR_MEMORY_EXHAUSTED;
    int result = client_->connect(url);
    if (result != WBERR_OK)
    {
        delete client_;
        client_ = nullptr;
        return result;
    }
    return WBERR_OK;
}

int HttpClient::close()
{
    delete client_;
	client_ = nullptr;
    return WBERR_OK;
}

int HttpClient::communicate( const std::string &path, HttpListener &listener )
{
    if (proto_ != WBCP_HTTP_1)
        return WBERR_INVALID_PROTOCOL;
    if (client_ == nullptr)
        return WBERR_INVALID_STATE;

    if (type_ == WBCT_LOCAL)
        return communicate_local(path, listener);
    else
        return communicate_remote(listener);
}

int HttpClient::communicate( HttpListener &listener )
{
    if (proto_ != WBCP_HTTP_1)
        return WBERR_INVALID_PROTOCOL;
    if (client_ == nullptr)
        return WBERR_INVALID_STATE;

    if (type_ == WBCT_LOCAL)
        return communicate_local(client_->get_target().path, listener);
    else
        return communicate_remote(listener);
}

int HttpClient::communicate_local( const std::string &path, HttpListener &listener )
{
    DataStream os(*client_, StreamType::OUTBOUND);
	DataStream is(*client_, StreamType::INBOUND);

	http_v1::MessageImpl request(os, nullptr, WBMF_OUTBOUND | WBMF_REQUEST);
	int result = Target::parse(path, request.header.target);
	if (result != WBERR_OK) return result;

	http_v1::MessageImpl response(is, &request, WBMF_INBOUND | WBMF_RESPONSE);
	response.header.target = request.header.target;

    try {
	    result = listener(request, response);
    } catch (...)
    {
        result = WBERR_CPP_EXCEPTION;
    }
    int tmp = request.finish();
    if (tmp == WBERR_OK)
        tmp = response.finish();

    if (tmp < WBERR_OK && result == WBERR_OK) return tmp;
	if (result < WBERR_OK) return result;

    bool closing = response.header.fields.get(WBFI_CONNECTION) == "close";
    return (closing) ? WBERR_COMPLETE : WBERR_OK;
}

int HttpClient::communicate_remote( HttpListener &listener )
{
    DataStream is(*client_, StreamType::INBOUND);
    DataStream os(*client_, StreamType::OUTBOUND);

    http_v1::MessageImpl request(is, nullptr, WBMF_INBOUND | WBMF_REQUEST);
    int result = request.ready();
    if (result != WBERR_OK) return result;

    bool closing = request.header.fields.get(WBFI_CONNECTION) == "close";

    http_v1::MessageImpl response(os, &request, WBMF_OUTBOUND | WBMF_RESPONSE);
    response.header.target = request.header.target;

    try {
	    result = listener(request, response);
    } catch (...)
    {
        result = WBERR_CPP_EXCEPTION;
    }
    int tmp = request.finish();
    if (tmp == WBERR_OK)
        tmp = response.finish();

    if (tmp < WBERR_OK && result == WBERR_OK) return tmp;
	if (result < WBERR_OK) return result;

    return (closing) ? WBERR_COMPLETE : WBERR_OK;
}

ClientType HttpClient::get_type() const
{
    return type_;
}

Protocol HttpClient::get_protocol() const
{
	return proto_;
}

Client *HttpClient::get_client()
{
	return client_;
}

//
// HttpServer
//

HttpServer::HttpServer() : server_(nullptr)
{
    server_ = new(std::nothrow) Server();
}

HttpServer::HttpServer( Parameters params ) : server_(nullptr)
{
    server_ = new(std::nothrow) Server(params);
}

HttpServer::~HttpServer()
{
    delete server_;
}

int HttpServer::start( const Target &target )
{
    if (server_ == nullptr) return WBERR_MEMORY_EXHAUSTED;
    return server_->start(target);
}

int HttpServer::start( const std::string &target )
{
    if (server_ == nullptr) return WBERR_MEMORY_EXHAUSTED;
    Target temp;
    int result = Target::parse(target, temp);
    if (result != WBERR_OK) return result;
    return server_->start(temp);
}

int HttpServer::stop()
{
    if (server_ == nullptr) return WBERR_MEMORY_EXHAUSTED;
    return server_->stop();
}

int HttpServer::accept( HttpClient **remote )
{
    if (server_ == nullptr) return WBERR_MEMORY_EXHAUSTED;

    Client *temp = nullptr;
    int result = server_->accept(&temp);
    if (result != WBERR_OK) return result;

    *remote = new(std::nothrow) HttpClient(WBCT_REMOTE, temp);
    if (*remote == nullptr)
    {
        delete temp;
        return WBERR_MEMORY_EXHAUSTED;
    }

    return WBERR_OK;
}

const Parameters &HttpServer::get_parameters() const
{
    static const Parameters params;
    if (server_ == nullptr) return params;
    return server_->get_parameters();
}

const Target &HttpServer::get_target() const
{
    static const Target target;
    if (server_ == nullptr) return target;
    return server_->get_target();
}

std::string QueryFields::serialize() const
{
    if (size() == 0) return "";

    std::stringstream stream;
    size_t count = 0;
    for (const auto &item : *this)
    {
        if (count++ > 0) stream << '&';
        stream << item.first << '=' << item.second;
    }

    return stream.str();
}

int QueryFields::deserialize(const std::string &query)
{
    if (query.empty()) return WBERR_OK;

    const char *ptr = query.c_str();
    while (*ptr != 0)
    {
        std::string name;
        std::string value;
        while (*ptr != '=' && *ptr != '&' && *ptr != 0) name += *ptr++;
        if (name.empty()) return WBERR_INVALID_ARGUMENT;

        if (*ptr == '=')
        {
            ++ptr;
            while (*ptr != '&' && *ptr != 0) value += *ptr++;
        }
        emplace(name, value);

        if (*ptr == 0)
            break;
        else
        if (*ptr == '&')
        {
            ++ptr;
            continue;
        }

        return WBERR_INVALID_ARGUMENT;
    }

    return WBERR_OK;
}

} // namespace webster
