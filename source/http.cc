#include <webster.hh>
#include "http.hh"
#include "http1.hh"
#include "stream.hh"

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

namespace webster {
namespace http {

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

HttpClient::HttpClient() : impl_(nullptr)
{
    impl_ = new(std::nothrow) v1::HttpClient();
}

HttpClient::~HttpClient()
{
    delete impl_;
}

int HttpClient::open( const char *url, const Parameters &params )
{
    if (impl_ == nullptr) return WBERR_MEMORY_EXHAUSTED;
    return impl_->open(url, params);
}

int HttpClient::open( const Target &url, const Parameters &params )
{
    if (impl_ == nullptr) return WBERR_MEMORY_EXHAUSTED;
    return impl_->open(url, params);
}

int HttpClient::close()
{
    if (impl_ == nullptr) return WBERR_MEMORY_EXHAUSTED;
    return impl_->close();
}

int HttpClient::communicate( Handler &handler )
{
    if (impl_ == nullptr) return WBERR_MEMORY_EXHAUSTED;
    int result = impl_->communicate(handler);
    // TODO: handle upgrades
    return result;
}

Protocol HttpClient::get_protocol() const
{
    if (impl_ == nullptr) return WBCP_NONE;
	return impl_->get_protocol();
}

} // namespace http
} // namespace webster
