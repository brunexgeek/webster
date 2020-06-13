#include <webster/api.hh>
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

int http_parse( char *data, int type, Message &message )
{
    static const int STATE_FIRST_LINE = 1;
    static const int STATE_HEADER_FIELD = 2;
    static const int STATE_COMPLETE = 3;

    int state = STATE_FIRST_LINE;
    char *ptr = data;
    char *token = ptr;
    int result;

    Header &header = message.header;
    message.body_.expected = 0;
    message.body_.chunks = 0;

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
                if (!(type & WBMT_RESPONSE)) return WBERR_INVALID_HTTP_MESSAGE;

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
                if (!(type & WBMT_REQUEST)) return WBERR_INVALID_HTTP_MESSAGE;

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
            if (STRCMPI(name, "Content-Length") == 0)
            {
                message.header.content_length = (int) strtol(value, nullptr, 10);
                message.body_.expected = message.header.content_length;
            }
            else
            if (STRCMPI(name, "Transfer-Encoding") == 0)
            {
                if (strstr(value, "chunked"))
				{
					message.body_.flags |= WBMF_CHUNKED;
                    message.body_.expected = -1;
				}
            }
        }
        else
            break;
    }

    return WBERR_OK;
}

Message::Message( int buffer_size )
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
int Message::receiveHeader( int timeout )
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
		result = client_->params_.network->receive(channel_, buffer_.data + buffer_.pending, &bytes, timeout);
		if (timeout > 0) timeout = timeout - (int) (webster_tick() - startTime);

		if (result == WBERR_OK)
		{
			buffer_.pending += (int) bytes;
			buffer_.current = buffer_.data;
			// ensure we have a null-terminator at the end
			*(buffer_.current + buffer_.pending) = 0;
			ptr = strstr((char*)buffer_.current, "\r\n\r\n");
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
	result = http_parse((char*)buffer_.data, flags_, *this);
	if (result != WBERR_OK) return result;
	header.content_length = body_.expected;
	body_.expected -= buffer_.pending;
	std::cout << "Expected " <<  header.content_length << std::endl;

	return WBERR_OK;
}

int Message::chunkSize( int timeout )
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
int Message::receiveBody( int timeout )
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
std::cout << "Receiving " << bytes << " bytes of data [expected " << body_.expected << std::endl;
	// receive new data and adjust pending information
	int result = client_->params_.network->receive(channel_, buffer_.data + buffer_.pending, &bytes, timeout);
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

int Message::read( const uint8_t **buffer, int *size )
{
	int result = WBERR_OK;
	if (state_ == WBS_IDLE)
	{
		result = receiveHeader(client_->params_.read_timeout);
		std::cout << "Got header!\n";
		if (result != WBERR_OK) return result;
	}
	if (buffer == NULL || size == NULL) return WBERR_INVALID_ARGUMENT;

	if (buffer_.pending <= 0 || buffer_.current == NULL)
	{
		result = receiveBody(client_->params_.read_timeout);
		if (result != WBERR_OK) return result;
	}
	if (buffer_.pending <= 0 || buffer_.current == NULL) return WBERR_NO_DATA;

	*buffer = buffer_.current;
	*size = buffer_.pending;

	buffer_.current = NULL;
	buffer_.pending = 0;

	return WBERR_OK;
}

int Message::read( const char **buffer )
{
	const uint8_t *ptr = nullptr;
	int size = 0;
	int result = read(&ptr, &size);
	*buffer = (const char *) ptr;
	return result;
}

int Message::read( std::string &buffer )
{
	const char *ptr;
	int result = read(&ptr);
	buffer = ptr;
	return result;
}

int Message::writeData( const uint8_t *buffer, int size )
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
		result = client_->params_.network->send(channel_, buffer_.data, (uint32_t) buffer_.size);
		buffer_.current = buffer_.data;
	}

	return result;
}

int Message::writeString( const std::string &text )
{
	return writeData((uint8_t*) text.c_str(), (int) text.length());
}

static int compute_resource_line( const Message &message, std::stringstream &ss )
{
	if (message.state_ != WBS_IDLE) return WBERR_INVALID_STATE;

	Method method = message.header.method;
	if (!WB_IS_VALID_METHOD(method)) method = WBM_GET;
	const Target &target = message.header.target;

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

static int compute_status_line( const Message &message, std::stringstream &ss )
{
	int status = message.header.status;
	if (status == 0) status = 200;
	const char *desc = http_statusMessage(status);
	ss << "HTTP/1.1 " << status << ' ' << desc << "\r\n";
	return WBERR_OK;
}

int Message::writeHeader()
{
	if (state_ != WBS_IDLE) return WBERR_INVALID_STATE;

	std::stringstream ss;

	// first line
	if (flags_ & WBMT_RESPONSE)
		compute_status_line(*this, ss);
	else
		compute_resource_line(*this, ss);

	// set 'tranfer-encoding' to chunked if required
	auto it = header.fields.find("Content-Length");
	if (it == header.fields.end())
	{
		body_.flags |= WBMF_CHUNKED;
		// TODO: merge with previously set value, if any
		header.fields["Transfer-Encoding"] = "chunked";
	}
	if (flags_ & WBMT_REQUEST && header.fields.count("Host") == 0)
		header.fields["Host"] = client_->target_.host + ':' + std::to_string(client_->target_.port);

	for (auto item : header.fields)
		ss << item.first << ": " << item.second << "\r\n";
	ss << "\r\n";
std::cerr << ss.str() << std::endl;
	writeString(ss.str());
	state_ = WBS_BODY;
	return WBERR_OK;
}

int Message::write( const uint8_t *buffer, int size )
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

int Message::write( const char *buffer )
{
	return write((const uint8_t*) buffer, (int) strlen(buffer));
}

int Message::write( const std::string &text )
{
	return write((const uint8_t*) text.c_str(), (int) text.length());
}

int Message::flush()
{
	if (state_ == WBS_COMPLETE) return WBERR_INVALID_STATE;

	// ensure we are done with the HTTP header
	if (state_ != WBS_BODY) write(nullptr, 0);
	// send all remaining body data
	if (buffer_.current > buffer_.data)
	{
		client_->params_.network->send(channel_, buffer_.data, (uint32_t) (buffer_.current - buffer_.data));
		buffer_.current = buffer_.data;
	}
	return WBERR_OK;
}

int Message::finish()
{
	if (state_ == WBS_COMPLETE) return WBERR_INVALID_STATE;
	if (!(flags_ & WBMT_OUTBOUND)) return WBERR_OK;

	int result = flush();
	if (result != WBERR_OK) return result;

	// send the last marker if using chunked transfer encoding
	if (body_.flags & WBMF_CHUNKED)
		client_->params_.network->send(channel_, (const uint8_t*) "0\r\n\r\n", 5);
	// we are done sending data now
	state_ = WBS_COMPLETE;

	return WBERR_OK;
}

} // namespace webster

#undef IS_HFNC