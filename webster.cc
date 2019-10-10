#define _POSIX_C_SOURCE 200112L

#include "webster.h"
#include <string>

#if defined(_WIN32) || defined(WIN32)
#define WB_WINDOWS
#endif


#define WBMT_UNKNOWN    0x00
#define WBMT_REQUEST    0x01
#define WBMT_RESPONSE   0x02

#define WBMF_CHUNKED    0x01


static webster_memory_t memory = { NULL, NULL, NULL };


struct webster_client_t_
{
	void *channel;
	std::string host;
	int port;
    uint32_t bufferSize;

    webster_client_t_() : channel(NULL), port(-1), bufferSize(WBL_DEF_BUFFER_SIZE) {}
    ~webster_client_t_() { }
};


struct webster_server_t_
{
    void *channel;
    std::string host;
    int port;
    int maxClients;
    uint32_t bufferSize;

    webster_server_t_() : channel(NULL), port(-1), maxClients(WBL_DEF_CONNECTIONS), bufferSize(WBL_DEF_BUFFER_SIZE) {}
    ~webster_server_t_() {}
};


/*************
 * HTTP stack
 *************/

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <map>


// is a header field name character?
#define IS_HFNC(x) \
    ((x) == '!'  \
    || ((x) >= '#' && (x) <= '\'')  \
    || (x) == '*'  \
    || (x) == '+'  \
    || (x) == '-'  \
    || (x) == '^'  \
    || (x) == '_'  \
    || (x) == '|'  \
    || (x) == '~'  \
    || ((x) >= 'A' && (x) <= 'Z')  \
    || ((x) >= 'a' && (x) <= 'z')  \
    || ((x) >= '0' && (x) <= '9'))


typedef struct
{
    const char *name;
    int id;
} webster_field_info_t;


typedef std::map<int, std::string> standard_field_map;
typedef std::map<std::string, std::string> custom_field_map;

struct webster_header_t
{
    webster_target_t *target;
    int status;
    int method;
    int content_length;
    standard_field_map s_fields;
    custom_field_map c_fields;

    webster_header_t();
    ~webster_header_t();

    const std::string *field( const int id ) const;

    const std::string *field( const std::string &name ) const;

    int field(
        const int id,
        const std::string &value );

    int field(
        const std::string &name,
        const std::string &value );

    int remove( const std::string &name );

    int count() const;
};



struct webster_message_t_
{
    /**
     * @brief Current state of the message.
     *
     * The machine state if defined by @c WBS_* macros.
     */
    int state;

    /**
     * Pointer to the opaque entity representing the network channel.
     */
    void *channel;

    /**
     * @brief Message type (WBMT_REQUEST or WBMT_RESPONSE).
     */
    int type;

    int flags;

    struct
    {
        /**
         * @brief Message expected size.
         *
         * This value is less than zero if using chunked transfer encoding.
         */
        int expected;

        /**
         * @brief Amount of bytes until the end of the current chunk.
         */
        int chunkSize;
    } body;

    struct
    {
        /**
         *  Pointer to the buffer content.
         */
        uint8_t *data;

        /**
         * Size of the buffer in bytes.
         */
        int size;

        /**
         * Pointer to the buffer position in the buffer content.
         */
        uint8_t *current;

        /**
         * Amount of useful data from the current position.
         */
        int pending;
    } buffer;

    /**
     * HTTP header
     */
    webster_header_t header;

    struct webster_client_t_ *client;

    webster_message_t_( int size );
    ~webster_message_t_();
};


WEBSTER_PRIVATE
const char *http_statusMessage(
    int status );

WEBSTER_PRIVATE
int http_getFieldID(
    const char *name );

WEBSTER_PRIVATE
const char *http_getFieldName(
    int id );

WEBSTER_PRIVATE
int http_parseTarget(
    const char *url,
    webster_target_t **target );

WEBSTER_PRIVATE
int http_parse(
    char *data,
    int type,
    webster_message_t *message );

WEBSTER_PRIVATE
int http_freeTarget(
    webster_target_t *target );


webster_field_info_t HTTP_HEADER_FIELDS[] =
{
    { "accept"                          , WBFI_ACCEPT },
    { "accept-charset"                  , WBFI_ACCEPT_CHARSET },
    { "accept-encoding"                 , WBFI_ACCEPT_ENCODING },
    { "accept-language"                 , WBFI_ACCEPT_LANGUAGE },
    { "accept-patch"                    , WBFI_ACCEPT_PATCH },
    { "accept-ranges"                   , WBFI_ACCEPT_RANGES },
    { "access-control-allow-credentials", WBFI_ACCESS_CONTROL_ALLOW_CREDENTIALS },
    { "access-control-allow-headers"    , WBFI_ACCESS_CONTROL_ALLOW_HEADERS },
    { "access-control-allow-methods"    , WBFI_ACCESS_CONTROL_ALLOW_METHODS },
    { "access-control-allow-origin"     , WBFI_ACCESS_CONTROL_ALLOW_ORIGIN },
    { "access-control-expose-headers"   , WBFI_ACCESS_CONTROL_EXPOSE_HEADERS },
    { "access-control-max-age"          , WBFI_ACCESS_CONTROL_MAX_AGE },
    { "access-control-request-headers"  , WBFI_ACCESS_CONTROL_REQUEST_HEADERS },
    { "access-control-request-method"   , WBFI_ACCESS_CONTROL_REQUEST_METHOD },
    { "age"                             , WBFI_AGE },
    { "allow"                           , WBFI_ALLOW },
    { "alt-svc"                         , WBFI_ALT_SVC },
    { "authorization"                   , WBFI_AUTHORIZATION },
    { "cache-control"                   , WBFI_CACHE_CONTROL },
    { "connection"                      , WBFI_CONNECTION },
    { "content-disposition"             , WBFI_CONTENT_DISPOSITION },
    { "content-encoding"                , WBFI_CONTENT_ENCODING },
    { "content-language"                , WBFI_CONTENT_LANGUAGE },
    { "content-length"                  , WBFI_CONTENT_LENGTH },
    { "content-location"                , WBFI_CONTENT_LOCATION },
    { "content-range"                   , WBFI_CONTENT_RANGE },
    { "content-type"                    , WBFI_CONTENT_TYPE },
    { "cookie"                          , WBFI_COOKIE },
    { "date"                            , WBFI_DATE },
    { "dnt"                             , WBFI_DNT },
    { "etag"                            , WBFI_ETAG },
    { "expect"                          , WBFI_EXPECT },
    { "expires"                         , WBFI_EXPIRES },
    { "forwarded"                       , WBFI_FORWARDED },
    { "from"                            , WBFI_FROM },
    { "host"                            , WBFI_HOST },
    { "if-match"                        , WBFI_IF_MATCH },
    { "if-modified-since"               , WBFI_IF_MODIFIED_SINCE },
    { "if-none-match"                   , WBFI_IF_NONE_MATCH },
    { "if-range"                        , WBFI_IF_RANGE },
    { "if-unmodified-since"             , WBFI_IF_UNMODIFIED_SINCE },
    { "last-modified"                   , WBFI_LAST_MODIFIED },
    { "link"                            , WBFI_LINK },
    { "location"                        , WBFI_LOCATION },
    { "max-forwards"                    , WBFI_MAX_FORWARDS },
    { "origin"                          , WBFI_ORIGIN },
    { "pragma"                          , WBFI_PRAGMA },
    { "proxy-authenticate"              , WBFI_PROXY_AUTHENTICATE },
    { "proxy-authorization"             , WBFI_PROXY_AUTHORIZATION },
    { "public-key-pins"                 , WBFI_PUBLIC_KEY_PINS },
    { "range"                           , WBFI_RANGE },
    { "referer"                         , WBFI_REFERER },
    { "retry-after"                     , WBFI_RETRY_AFTER },
    { "server"                          , WBFI_SERVER },
    { "set-cookie"                      , WBFI_SET_COOKIE },
    { "strict-transport-security"       , WBFI_STRICT_TRANSPORT_SECURITY },
    { "te"                              , WBFI_TE },
    { "tk"                              , WBFI_TK },
    { "trailer"                         , WBFI_TRAILER },
    { "transfer-encoding"               , WBFI_TRANSFER_ENCODING },
    { "upgrade"                         , WBFI_UPGRADE },
    { "upgrade-insecure-requests"       , WBFI_UPGRADE_INSECURE_REQUESTS },
    { "user-agent"                      , WBFI_USER_AGENT },
    { "vary"                            , WBFI_VARY },
    { "via"                             , WBFI_VIA },
    { "warning"                         , WBFI_WARNING },
    { "www-authenticate"                , WBFI_WWW_AUTHENTICATE },
};


/*
 * webster_header_t
 */

webster_header_t::webster_header_t() : target(NULL), status(0), method(WBM_NONE)
{
}


webster_header_t::~webster_header_t()
{

}


const std::string *webster_header_t::field( const std::string &name ) const
{
	std::string tmp = name;
	for (size_t i = 0, t = tmp.length(); i < t; ++i)
		tmp[i] = (char) tolower(tmp[i]);

    custom_field_map::const_iterator it = c_fields.find(tmp);
    if (it != c_fields.end()) return &(it->second);
    return NULL;
}


const std::string *webster_header_t::field( const int id ) const
{
    standard_field_map::const_iterator it = s_fields.find(id);
    if (it != s_fields.end()) return &(it->second);
    return NULL;
}


int webster_header_t::field(
    const int id,
    const std::string &value )
{
    if (c_fields.size() + s_fields.size() >= WBL_MAX_FIELDS)
        return WBERR_TOO_MANY_FIELDS;

    s_fields[id] = value;
	return WBERR_OK;
}

int webster_header_t::field(
    const std::string &name,
    const std::string &value )
{
    if (c_fields.size() + s_fields.size() >= WBL_MAX_FIELDS)
        return WBERR_TOO_MANY_FIELDS;

    std::string temp = name;
    for (size_t i = 0, t = temp.size(); i < t; ++i)
    {
        if (!IS_HFNC(temp[i])) return WBERR_INVALID_ARGUMENT;
        temp[i] = (char) tolower(temp[i]);
    }

    int id = http_getFieldID(temp.c_str());
    if (id != WBFI_NON_STANDARD)
        return field(id, value);

    c_fields[temp] = value;
	return WBERR_OK;
}


int webster_header_t::remove(
    const std::string &name )
{
    std::string temp = name;
    for (size_t i = 0, t = temp.size(); i < t; ++i)
    {
        if (!IS_HFNC(temp[i])) return WBERR_INVALID_ARGUMENT;
        temp[i] = (char) tolower(temp[i]);
    }

    int id = http_getFieldID(temp.c_str());
    if (id != WBFI_NON_STANDARD)
    {
        standard_field_map::iterator it = s_fields.find(id);
        if (it != s_fields.end()) s_fields.erase(it);
    }
    else
    {
        custom_field_map::iterator it = c_fields.find(name);
        if (it != c_fields.end()) c_fields.erase(it);
    }

    return WBERR_OK;
}

int webster_header_t::count() const
{
    return (int) s_fields.size() + (int) c_fields.size();
}


/*
 * webster_message_t_
 */

webster_message_t_::webster_message_t_( int size ) : state(WBS_IDLE), channel(NULL),
    type(WBMT_UNKNOWN), flags(0), client(NULL)
{
    size = (size + 3) & (~3);
    if (size < WBL_MIN_BUFFER_SIZE)
        size = WBL_MIN_BUFFER_SIZE;
    else
    if (size > WBL_MAX_BUFFER_SIZE)
        size = WBL_MAX_BUFFER_SIZE;

    body.expected = body.chunkSize = 0;
    // FIXME: can be NULL
    buffer.data = buffer.current = new(std::nothrow) uint8_t[size];
    buffer.data[0] = 0;
    buffer.size = size;
    buffer.pending = 0;
}


webster_message_t_::~webster_message_t_()
{
    delete[] buffer.data;
}


/*
 * HTTP parser
 */

static char *cloneString(
    const char *text )
{
    if (text == NULL) return NULL;
    size_t len = strlen(text);
    char *output = (char*) memory.malloc(len + 1);
    strcpy(output, text);
    return output;
}


static char *subString(
    const char *text,
    size_t offset,
    size_t length )
{
    if (text == NULL) return NULL;

    size_t len = strlen(text);
    if (offset + length > len) return NULL;

    char *output = (char*) memory.malloc(length + 1);
    if (output == NULL) return NULL;
    memcpy(output, text + offset, length);
    output[length] = 0;
    return output;
}


const char *http_statusMessage(
    int status )
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


int http_getFieldID(
    const char *name )
{
	if (name == NULL || name[0] == 0) return WBFI_NON_STANDARD;

    char temp[WBL_MAX_FIELD_NAME + 1];
    size_t i = 0;
    for (size_t t = strlen(name); i < t; ++i)
    {
        temp[i] = name[i];
        if (temp[i] >= 'A' && temp[i] <= 'Z') temp[i] = (char) (temp[i] + 32);
    }
    temp[i] = 0;

    int first = 0;
    int last = sizeof(HTTP_HEADER_FIELDS) / sizeof(webster_field_info_t) - 1;

    while (first <= last)
	{
		int current = (first + last) / 2;
		int dir = strcmp(temp, HTTP_HEADER_FIELDS[current].name);
		if (dir == 0) return HTTP_HEADER_FIELDS[current].id;
		if (dir < 0)
			last = current - 1;
		else
			first = current + 1;
	}

	return WBFI_NON_STANDARD;
}


const char *http_getFieldName(
    int id )
{
	if (id == WBFI_NON_STANDARD) return NULL;

	int first = 0;
    int last = sizeof(HTTP_HEADER_FIELDS) / sizeof(webster_field_info_t) - 1;

    while (first <= last)
	{
		int current = (first + last) / 2;
		if (id == HTTP_HEADER_FIELDS[current].id)
            return HTTP_HEADER_FIELDS[current].name;
		if (id < HTTP_HEADER_FIELDS[current].id)
			last = current - 1;
		else
			first = current + 1;
	}

	return NULL;
}


char *http_removeTrailing(
    char *text )
{
    // remove whitespaces from the start
    while (*text == ' ') ++text;
    if (*text == 0) return text;
    // remove whitespaces from the end
    for (char *p = text + strlen(text) - 1; p >= text && *p == ' '; --p) *p = 0;
    return text;
}


static int hexDigit(
    uint8_t digit )
{
    if (digit >= '0' && digit <= '9')
        return digit - '0';
    if (digit >= 'a' && digit <= 'f')
        digit = (uint8_t) (digit - 32);
    if (digit >= 'A' && digit <= 'F')
        return digit - 'A' + 10;
    return 0;
}


static char * http_decodeUrl(
    char *text )
{
    if (text == NULL) return NULL;

    uint8_t *i = (uint8_t*) text;
    uint8_t *o = (uint8_t*) text;
    while (*i != 0)
    {
        if (*i == '%' && isxdigit(*(i + 1)) && isxdigit(*(i + 2)))
        {
            *o = (uint8_t) (hexDigit(*(i + 1)) * 16 + hexDigit(*(i + 2)));
            i += 3;
            ++o;
        }
        else
        {
            *o = *i;
            ++i;
            ++o;
        }
    }
    *o = 0;

    return text;
}


struct webster_context_t
{
    const char *content;
    size_t length;
    const char *current;
};


int http_parseTarget(
    const char *url,
    webster_target_t **output )
{
    if (url == NULL || url[0] == 0 || output == NULL) return WBERR_INVALID_URL;

    // TODO: change to make an allocation for all fields
    *output = (webster_target_t*) memory.calloc(1, sizeof(webster_target_t));
    if (*output == NULL) return WBERR_MEMORY_EXHAUSTED;
    webster_target_t *target = *output;

    // handle asterisk form
    if (url[0] == '*' && url[1] == 0)
        target->type = WBRT_ASTERISK;
    else
    // handle origin form
    if (url[0] == '/')
    {
        target->type = WBRT_ORIGIN;

        const char *ptr = url;
        while (*ptr != '?' && *ptr != 0) ++ptr;

        if (*ptr == '?')
        {
            size_t pos = (size_t) (ptr - url);
            target->path = subString(url, 0, pos);
            target->query = subString(url, pos + 1, strlen(url) - pos - 1);
        }
        else
        {
            target->path = cloneString(url);
        }

        http_decodeUrl(target->path);
        http_decodeUrl(target->query);
    }
    else
    // handle absolute form
    if (tolower(url[0]) == 'h' &&
		tolower(url[1]) == 't' &&
		tolower(url[2]) == 't' &&
		tolower(url[3]) == 'p' &&
		(tolower(url[4]) == 's' || url[4] == ':'))
	{
        target->type = WBRT_ABSOLUTE;

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
			target->scheme = WBP_HTTP;
		else
			target->scheme = WBP_HTTPS;

		// return the port number, if any
		if (pe != NULL)
		{
			target->port = 0;
			int mult = 1;
			while (--pe >= pb)
			{
				target->port += (int) (*pe - '0') * mult;
				mult *= 10;
			}
			if (target->port > 65535 || target->port < 0)
                return WBERR_INVALID_URL;
		}
		else
		{
			if (target->scheme == WBP_HTTP)
				target->port = 80;
			else
				target->port = 443;
		}

		// return the host
        target->host = subString(hb, 0, (size_t) (he - hb));

		// return the resource, if any
		if (re != NULL)
			target->path = subString(rb, 0, (size_t) (re - rb));
		else
			target->path = cloneString("/");

		http_decodeUrl(target->path);
        http_decodeUrl(target->query);
	}
    else
    // handle authority form
    {
        target->type = WBRT_AUTHORITY;

        const char *hb = strchr(url, '@');
        if (hb != NULL)
        {
            target->user = subString(url, 0, (size_t) (hb - url));
            hb++;
        }
        else
            hb = url;

        const char *he = strchr(hb, ':');
        if (he != NULL)
        {
            target->host = subString(hb, 0, (size_t) (he - hb));
            target->port = 0;

            const char *pb = he + 1;
            const char *pe = pb;
            while (*pe >= '0' && *pe <= '9' && *pe != 0) ++pe;
            if (*pe != 0) return WBERR_INVALID_URL;

			int mult = 1;
			while (--pe >= pb)
			{
				target->port += (int) (*pe - '0') * mult;
				mult *= 10;
			}
			if (target->port > 65535 || target->port < 0)
                return WBERR_INVALID_URL;
        }
        else
        {
            target->host = cloneString(hb);
            target->port = 80;
        }
    }

    return WBERR_OK;
}


int http_freeTarget(
    webster_target_t *target )
{
    if (target == NULL) return WBERR_INVALID_URL;

    switch (target->type)
    {
        case WBRT_ORIGIN:
            if (target->path != NULL)
                memory.free(target->path);
            if (target->query != NULL)
                memory.free(target->query);
            break;

        case WBRT_ABSOLUTE:
            if (target->user != NULL)
                memory.free(target->user);
            if (target->host != NULL)
                memory.free(target->host);
            if (target->path != NULL)
                memory.free(target->path);
            if (target->query != NULL)
                memory.free(target->query);
            break;

        case WBRT_AUTHORITY:
            if (target->user != NULL)
                memory.free(target->user);
            if (target->host != NULL)
                memory.free(target->host);
            break;

        case WBRT_ASTERISK:
            break;

        default:
            return WBERR_INVALID_URL;
    }

    memory.free(target);

    return WBERR_OK;
}


int http_parse(
    char *data,
    int type,
    webster_message_t *message )
{
    static const int STATE_FIRST_LINE = 1;
    static const int STATE_HEADER_FIELD = 2;
    static const int STATE_COMPLETE = 3;

    int state = STATE_FIRST_LINE;
    char *ptr = data;
    char *token = ptr;
    int result;

    webster_header_t *header = &message->header;
    message->body.expected = 0;
    message->body.chunkSize = 0;

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
                if (type != WBMT_RESPONSE) return WBERR_INVALID_HTTP_MESSAGE;

                // HTTP status code
                for (token = ptr; *ptr >= '0' && *ptr <= '9'; ++ptr);
                if (*ptr != ' ') return WBERR_INVALID_HTTP_MESSAGE;
                *ptr++ = 0;
                header->status = atoi(token);
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
                if (type != WBMT_REQUEST) return WBERR_INVALID_HTTP_MESSAGE;

                // find out the HTTP method (case-sensitive according to RFC-7230:3.1.1)
                if (strcmp(token, "GET") == 0)
                    header->method = WBM_GET;
                else
                if (strcmp(token, "POST") == 0)
                    header->method = WBM_POST;
                else
                if (strcmp(token, "HEAD") == 0)
                    header->method = WBM_HEAD;
                else
                if (strcmp(token, "PUT") == 0)
                    header->method = WBM_PUT;
                else
                if (strcmp(token, "DELETE") == 0)
                    header->method = WBM_DELETE;
                else
                if (strcmp(token, "CONNECT") == 0)
                    header->method = WBM_CONNECT;
                else
                if (strcmp(token, "OPTIONS") == 0)
                    header->method = WBM_OPTIONS;
                else
                if (strcmp(token, "TRACE") == 0)
                    header->method = WBM_TRACE;
                else
                if (strcmp(token, "PATCH") == 0)
                    header->method = WBM_PATCH;
                else
                    return WBERR_INVALID_HTTP_METHOD;

                // target
                for (token = ptr; *ptr != ' ' && *ptr != 0; ++ptr);
                if (*ptr != ' ') return WBERR_INVALID_HTTP_MESSAGE;
                *ptr++ = 0;
                result = http_parseTarget(token, &header->target);
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
            *ptr++ = 0;
            ++ptr;

            // change the field name to lowercase
            char *p;
            for (p = name; *p && *p != ' '; ++p) *p = (char) tolower(*p);
            // ignore trailing whitespces in the value
            value = http_removeTrailing(value);
            // get the field ID, if any
            int id = http_getFieldID(name);
            if (id != WBFI_NON_STANDARD)
            {
                header->field(id, value);

                // if is 'content-length' field, get the value
                if (id == WBFI_CONTENT_LENGTH)
                    message->body.expected = atoi(value);
                else
                if (id == WBFI_TRANSFER_ENCODING && strstr(value, "chunked"))
                    message->flags |= WBMF_CHUNKED;
            }
            else
                header->field(name, value);
        }
        else
            break;
    }

    return WBERR_OK;
}

#undef IS_HFNC

/*************
 * Network stack
 *************/


#define WBNET_INITIALIZE  networkImpl.initialize
#define WBNET_TERMINATE   networkImpl.terminate
#define WBNET_OPEN        networkImpl.open
#define WBNET_CLOSE       networkImpl.close
#define WBNET_CONNECT     networkImpl.connect
#define WBNET_RECEIVE     networkImpl.receive
#define WBNET_SEND        networkImpl.send
#define WBNET_ACCEPT      networkImpl.accept
#define WBNET_LISTEN      networkImpl.listen

extern webster_network_t networkImpl;

WEBSTER_PRIVATE int network_setImpl(
	webster_network_t *impl );

WEBSTER_PRIVATE int network_resetImpl();

#include <sys/types.h>


#ifdef WB_WINDOWS
#include <winsock2.h>
#if (_WIN32_WINNT > 0x0501 || WINVER > 0x0501)
#include <ws2tcpip.h>
#endif
#pragma comment(lib, "ws2_32.lib")
typedef SSIZE_T ssize_t;
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


#if defined(WB_WINDOWS) && (_WIN32_WINNT <= 0x0501 || WINVER <= 0x0501)
// Note: on Windows XP or older, the functions 'getaddrinfo' and 'freeaddrinfo'
//       should be loaded manually.

HINSTANCE winSocketLib;
getaddrinfo_f getaddrinfo;
freeaddrinfo_f freeaddrinfo;
#endif


typedef struct
{
	#ifdef WB_WINDOWS
	SOCKET socket;
	#else
	int socket;
	#endif
	struct pollfd poll;
} webster_channel_t;


static int network_lookupIPv4(
	const char *host,
	struct sockaddr_in *address )
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


static int network_initialize(
	webster_memory_t *mem )
{
	memory.malloc = mem->malloc;
	memory.calloc = mem->calloc;
	memory.free   = mem->free;

	#ifdef WB_WINDOWS
	int err = 0;

	WORD wVersionRequested;
	WSADATA wsaData;
	wVersionRequested = MAKEWORD( 2, 0 );
	err = WSAStartup( wVersionRequested, &wsaData );
	if(err != 0) return WBERR_SOCKET;

	#if (_WIN32_WINNT <= 0x0501 || WINVER <= 0x0501)
	winSocketLib = LoadLibrary( "WS2_32.dll" );
	if (winSocketLib == NULL) return WBERR_SOCKET;

	getaddrinfo = NULL;
	freeaddrinfo = NULL

	getaddrinfo = (getaddrinfo_f)GetProcAddress(winSocketLib, "getaddrinfo");
	if (getaddrinfo == NULL) return;

	freeaddrinfo = (freeaddrinfo_f)GetProcAddress(winSocketLib, "freeaddrinfo");
	if (freeaddrinfo == NULL) return;
	#endif

	#endif // __WINDOWS__

	return WBERR_OK;
}


static int network_terminate()
{
	memory.malloc = NULL;
	memory.calloc = NULL;
	memory.free   = NULL;

	#ifdef WB_WINDOWS
	#if (_WIN32_WINNT <= 0x0501 || WINVER <= 0x0501)
	getaddrinfo = NULL;
	freeaddrinfo = NULL;
	#endif
	WSACleanup();
	#endif

	return WBERR_OK;
}


static int network_open(
	void **channel )
{
	if (channel == NULL) return WBERR_INVALID_CHANNEL;

	*channel = memory.calloc(1, sizeof(webster_channel_t));
	if (*channel == NULL) return WBERR_MEMORY_EXHAUSTED;

	webster_channel_t *chann = (webster_channel_t*) *channel;

	chann->socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (chann->socket == -1) return WBERR_SOCKET;
	chann->poll.fd = chann->socket;
	chann->poll.events = POLLIN;

	// allow socket descriptor to be reuseable
	int on = 1;
	setsockopt(chann->socket, SOL_SOCKET,  SO_REUSEADDR, (char *)&on, sizeof(int));

	return WBERR_OK;
}


static int network_close(
	void *channel )
{
	if (channel == NULL) return WBERR_INVALID_CHANNEL;

	webster_channel_t *chann = (webster_channel_t*) channel;

	#ifdef WB_WINDOWS
	shutdown(chann->socket, SD_BOTH);
	closesocket(chann->socket);
	#else
	shutdown(chann->socket, SHUT_RDWR);
	close(chann->socket);
	#endif

	chann->socket = chann->poll.fd = 0;
	memory.free(channel);

	return WBERR_OK;
}


static int network_connect(
	void *channel,
	int scheme,
	const char *host,
    int port )
{
	if (channel == NULL)
		return WBERR_INVALID_CHANNEL;
	if (port < 0 && port > 0xFFFF)
		return WBERR_INVALID_PORT;
	if (host == NULL || host[0] == 0)
		return WBERR_INVALID_HOST;
	if (scheme != WBP_HTTP)
		return WBERR_INVALID_SCHEME;

	webster_channel_t *chann = (webster_channel_t*) channel;

	struct sockaddr_in address;
	network_lookupIPv4(host, &address);

	address.sin_port = htons( (uint16_t) port );
	if (connect(chann->socket, (const struct sockaddr*) &address, sizeof(const struct sockaddr_in)) != 0)
		return WBERR_SOCKET;

	return WBERR_OK;
}


static int network_receive(
	void *channel,
	uint8_t *buffer,
    uint32_t *size,
	int timeout )
{
	if (channel == NULL) return WBERR_INVALID_CHANNEL;
	if (buffer == NULL || size == NULL || *size == 0) return WBERR_INVALID_ARGUMENT;
	if (timeout < 0) timeout = -1;

	webster_channel_t *chann = (webster_channel_t*) channel;
	uint32_t bufferSize = *size;
	*size = 0;

	// wait for data arrive
	#ifdef WB_WINDOWS
	int result = WSAPoll(&chann->poll, 1, timeout);
	#else
	int result = poll(&chann->poll, 1, timeout);
	#endif
	if (result == 0) return WBERR_TIMEOUT;
	if (result == EINTR) return WBERR_SIGNAL;
	if (result < 0) return WBERR_SOCKET;

	ssize_t bytes = recv(chann->socket, (char *) buffer, (size_t) bufferSize, 0);
	if (bytes == ECONNRESET || bytes == EPIPE || bytes == ENOTCONN)
		return WBERR_NOT_CONNECTED;
	else
	if (bytes < 0)
	{
		*size = 0;
		if (bytes == EWOULDBLOCK || bytes == EAGAIN) return WBERR_NO_DATA;
		return WBERR_SOCKET;
	}
	*size = (uint32_t) bytes;
	if (bytes == 0) return WBERR_TIMEOUT;

	return WBERR_OK;
}


static int network_send(
	void *channel,
	const uint8_t *buffer,
    uint32_t size )
{
	if (channel == NULL) return WBERR_INVALID_CHANNEL;
	if (buffer == NULL || size == 0) return WBERR_INVALID_ARGUMENT;

	webster_channel_t *chann = (webster_channel_t*) channel;

	#ifdef WB_WINDOWS
	int flags = 0;
	#else
	int flags = MSG_NOSIGNAL;
	#endif
	ssize_t result = send(chann->socket, (const char *) buffer, (size_t) size, flags);
	if (result == ECONNRESET || result == EPIPE || result == ENOTCONN)
		return WBERR_NOT_CONNECTED;
	else
	if (result < 0)
		return WBERR_SOCKET;

	return WBERR_OK;
}


static int network_accept(
	void *channel,
	void **client )
{
	if (channel == NULL) return WBERR_INVALID_CHANNEL;
	if (client == NULL) return WBERR_INVALID_ARGUMENT;

	webster_channel_t *chann = (webster_channel_t*) channel;

	#ifdef WB_WINDOWS
	int result = WSAPoll(&chann->poll, 1, 1000);
	#else
	int result = poll(&chann->poll, 1, 1000);
	#endif
	if (result == 0) return WBERR_TIMEOUT;
	if (result == EINTR) return WBERR_SIGNAL;
	if (result < 0) return WBERR_SOCKET;

	*client = memory.calloc(1, sizeof(webster_channel_t));
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
	socket = accept(chann->socket, (struct sockaddr *) &address, &addressLength);

	if (socket < 0)
	{
		memory.free(*client);
		*client = NULL;
		if (socket == EAGAIN || socket == EWOULDBLOCK)
			return WBERR_NO_CLIENT;
		else
			return WBERR_SOCKET;
	}

	((webster_channel_t*)*client)->socket = socket;
	((webster_channel_t*)*client)->poll.fd = socket;
	((webster_channel_t*)*client)->poll.events = POLLIN;

	return WBERR_OK;
}


static int network_listen(
	void *channel,
	const char *host,
    int port,
	int maxClients )
{
	if (channel == NULL)
		return WBERR_INVALID_CHANNEL;
	if ( host == NULL || host[0] == 0)
		return WBERR_INVALID_HOST;
	if (port < 0 && port > 0xFFFF)
		return WBERR_INVALID_PORT;

	webster_channel_t *chann = (webster_channel_t*) channel;

	struct sockaddr_in address;
	network_lookupIPv4(host, &address);

	address.sin_port = htons( (uint16_t) port );
	if (bind(chann->socket, (const struct sockaddr*) &address, sizeof(const struct sockaddr_in)) != 0)
		return WBERR_SOCKET;

	// listen for incoming connections
	if ( listen(chann->socket, maxClients) != 0 )
		return WBERR_SOCKET;

	return WBERR_OK;
}


static webster_network_t DEFAULT_IMPL =
{
	network_initialize,
	network_terminate,
	network_open,
	network_close,
	network_connect,
	network_receive,
	network_send,
	network_accept,
	network_listen
};

WEBSTER_PRIVATE webster_network_t networkImpl = { NULL, NULL, NULL, NULL, NULL, NULL,
	NULL, NULL, NULL };


int network_setImpl(
	webster_network_t *impl )
{
	if (impl == NULL) impl = &DEFAULT_IMPL;

	if (impl->initialize == NULL ||
		impl->terminate == NULL ||
		impl->open == NULL ||
		impl->close == NULL ||
		impl->connect == NULL ||
		impl->receive == NULL ||
		impl->send == NULL ||
		impl->accept == NULL ||
		impl->listen == NULL)
		return WBERR_INVALID_ARGUMENT;

	networkImpl.initialize = impl->initialize;
	networkImpl.terminate  = impl->terminate;
	networkImpl.open       = impl->open;
	networkImpl.close      = impl->close;
	networkImpl.connect    = impl->connect;
	networkImpl.receive    = impl->receive;
	networkImpl.send       = impl->send;
	networkImpl.accept     = impl->accept;
	networkImpl.listen     = impl->listen;
	return WBERR_OK;
}


int network_resetImpl()
{
	networkImpl.initialize = NULL;
	networkImpl.terminate  = NULL;
	networkImpl.open       = NULL;
	networkImpl.close      = NULL;
	networkImpl.connect    = NULL;
	networkImpl.receive    = NULL;
	networkImpl.send       = NULL;
	networkImpl.accept     = NULL;
	networkImpl.listen     = NULL;
	return WBERR_OK;
}



/*************
 * Webster API
 *************/


#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <iostream>


#ifdef WB_WINDOWS
#include <windows.h>
#define SNPRINTF _snprintf
#else
#include <sys/time.h>
#define SNPRINTF snprintf
#endif


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


int WebsterInitialize(
    webster_memory_t *mem,
	webster_network_t *net )
{
	if (mem != NULL && (mem->malloc == NULL || mem->free == NULL))
		return WBERR_INVALID_ARGUMENT;

	if (mem != NULL)
	{
		memory.malloc = mem->malloc;
		memory.calloc = mem->calloc;
		memory.free = mem->free;
	}
	else
	{
		memory.malloc = malloc;
		memory.calloc = calloc;
		memory.free = free;
	}

	int result = network_setImpl(net);
	if (result != WBERR_OK) goto ESCAPE;
	result = WBNET_INITIALIZE(&memory);
	if (result != WBERR_OK) goto ESCAPE;

	return WBERR_OK;
ESCAPE:
	WebsterTerminate();
	return result;
}


int WebsterTerminate()
{
	if (WBNET_TERMINATE != NULL) WBNET_TERMINATE();
	network_resetImpl();
	memory.malloc = NULL;
	memory.calloc = NULL;
	memory.free = NULL;

	return WBERR_OK;
}


int WebsterParseURL(
	const char *url,
	webster_target_t **target )
{
	return http_parseTarget(url, target);
}


int WebsterFreeURL(
    webster_target_t *target )
{
	return http_freeTarget(target);
}


//
// Client API
//


int WebsterConnect(
    webster_client_t **client,
    int scheme,
	const char *host,
    int port )
{
	if (client == NULL)
		return WBERR_INVALID_CLIENT;
	if (port < 0 || port > 0xFFFF)
		return WBERR_INVALID_PORT;
	if (host == NULL || host[0] == 0)
		return WBERR_INVALID_HOST;
	if (!WB_IS_VALID_SCHEME(scheme))
		return WBERR_INVALID_SCHEME;

	// allocate memory for everything
	*client = new(std::nothrow) webster_client_t_();
	if (*client == NULL) return WBERR_MEMORY_EXHAUSTED;

	// try to connect with the remote host
	int result = WBNET_OPEN( &(*client)->channel );
	if (result != WBERR_OK) goto ESCAPE;
	result = WBNET_CONNECT((*client)->channel, scheme, host, port);
	if (result != WBERR_OK) goto ESCAPE;

	(*client)->host = host;
	(*client)->port = port;

	return WBERR_OK;

ESCAPE:
	if (*client != NULL)
	{
		if ((*client)->channel != NULL) WBNET_CLOSE((*client)->channel);
		delete *client;
		*client = NULL;
	}
	return result;
}


int WebsterCommunicate(
    webster_client_t *client,
    const char *path,
    const char *query,
    webster_handler_t *callback,
    void *data )
{
	webster_target_t url;
	url.type = WBRT_ORIGIN;
	url.path = (char*) path;
	url.query = (char*) query;
	return WebsterCommunicateURL(client, &url, callback, data);
}


int WebsterCommunicateURL(
    webster_client_t *client,
    webster_target_t *url,
    webster_handler_t *callback,
    void *data )
{
	if (client == NULL) return WBERR_INVALID_CLIENT;
	if (callback == NULL) return WBERR_INVALID_ARGUMENT;
	//if (url == NULL || !WB_IS_VALID_URL(url->type)) return WBERR_INVALID_URL;

	webster_message_t_ request(client->bufferSize);
	webster_message_t_ response(client->bufferSize);

	//memset(&request, 0, sizeof(struct webster_message_t_));
	request.type = WBMT_REQUEST;
	request.channel = client->channel;
	request.header.method = WBM_GET;
	request.client = client;
	request.header.target = url;

	//memset(&response, 0, sizeof(struct webster_message_t_));
	response.type = WBMT_RESPONSE;
	response.channel = client->channel;
	response.client = client;
	response.header.target = url;

	callback(&request, &response, data);

	if (request.header.target != url) http_freeTarget(request.header.target);
	if (response.header.target != url) http_freeTarget(response.header.target);

	return WBERR_OK;
}


int WebsterDisconnect(
    webster_client_t *client )
{
	if (client == NULL) return WBERR_INVALID_CLIENT;

	WBNET_CLOSE(client->channel);
	delete client;
	return WBERR_OK;
}


//
// Server API
//



int WebsterCreate(
    webster_server_t **server,
	int maxClients )
{
	if (server == NULL) return WBERR_INVALID_SERVER;

	if (maxClients <= 0 || maxClients >= WBL_MAX_CONNECTIONS)
		maxClients = WBL_MAX_CONNECTIONS;

	*server = new(std::nothrow) webster_server_t_();
	if (*server == NULL) return WBERR_MEMORY_EXHAUSTED;

	return WBERR_OK;
}


int WebsterDestroy(
    webster_server_t *server )
{
	if (server == NULL) return WBERR_INVALID_SERVER;

	WebsterStop(server);
	delete server;

	return WBERR_OK;
}


int WebsterStart(
	webster_server_t *server,
    const char *host,
    int port )
{
	if (server == NULL) return WBERR_INVALID_SERVER;

	int result = WBNET_OPEN(&server->channel);
	if (result != WBERR_OK) return result;

	return WBNET_LISTEN(server->channel, host, port, server->maxClients);
}


int WebsterStop(
    webster_server_t *server )
{
	if (server == NULL) return WBERR_INVALID_SERVER;

	WBNET_CLOSE(server->channel);
	server->channel = NULL;

	return WBERR_OK;
}


int WebsterAccept(
    webster_server_t *server,
	webster_client_t **remote )
{
	if (server == NULL) return WBERR_INVALID_SERVER;
	if (remote == NULL) return WBERR_INVALID_CLIENT;

	void *client = NULL;
	int result = WBNET_ACCEPT(server->channel, &client);
	if (result != WBERR_OK) return result;

	*remote = new(std::nothrow) webster_client_t_();
	if (*remote == NULL)
	{
		WBNET_CLOSE(client);
		return WBERR_MEMORY_EXHAUSTED;
	}

	(*remote)->channel = client;
	(*remote)->bufferSize = server->bufferSize;

	return WBERR_OK;
}


int WebsterSetOption(
	webster_server_t *server,
    int option,
    int value )
{
	if (server == NULL) return WBERR_INVALID_SERVER;

	if (option == WBO_BUFFER_SIZE)
	{
		if (value < WBL_MIN_BUFFER_SIZE || value > WBL_MAX_BUFFER_SIZE) value = WBL_DEF_BUFFER_SIZE;
		server->bufferSize = (uint32_t) (value & 0x7FFFFFFF);
	}
	else
		return WBERR_INVALID_ARGUMENT;

	return WBERR_OK;
}


int WebsterGetOption(
	webster_server_t *server,
    int option,
    int *value )
{
	if (server == NULL) return WBERR_INVALID_SERVER;
	if (value == NULL) return WBERR_INVALID_ARGUMENT;

	if (option == WBO_BUFFER_SIZE)
		*value = (int) server->bufferSize;
	else
		return WBERR_INVALID_ARGUMENT;

	return WBERR_OK;
}


//
// Request and response API
//


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
 * @brief Read data from the network channel until the buffer is full or there's
 * no more data to read.
 */
static int webster_receive(
	webster_message_t *input,
	int timeout,
	int isHeader )
{
	// if we have data in the buffer, just return success
	if (input->buffer.pending > 0) return WBERR_OK;
	input->buffer.pending = 0;

	// Note: when reading input data we leave room in the buffer for a null-terminator
	//       so we can use the function 'WebsterReadString'.

	// when reading header data, we have 'timeout' milliseconds to receive the
	// entire HTTP header
	int recvTimeout = (timeout >= 0) ? timeout : 0;
	if (isHeader) recvTimeout = 50;

	uint64_t startTime = webster_tick();

	while (input->buffer.pending < input->buffer.size)
	{
		uint32_t bytes = (uint32_t) input->buffer.size - (uint32_t) input->buffer.pending - 1;
		// receive new data and adjust pending information
		int result = WBNET_RECEIVE(input->channel, input->buffer.data + input->buffer.pending, &bytes, recvTimeout);

		// only keep trying if expecting header data
		if (result == WBERR_TIMEOUT)
		{
			if (isHeader && webster_tick() - startTime < (size_t)timeout)
				continue;
			return WBERR_TIMEOUT;
		}
		else
		if (result != WBERR_OK) return result;

		input->buffer.pending += (int) bytes;
		input->buffer.current = input->buffer.data;
		// ensure we have a null-terminator at the end
		*(input->buffer.current + input->buffer.pending) = 0;

		if (isHeader == 0) return WBERR_OK;
		if (strstr((char*)input->buffer.current, "\r\n\r\n") != NULL) return WBERR_OK;
		if (webster_tick() - startTime > (size_t)timeout) return WBERR_TIMEOUT;
	}

	return WBERR_OK;
}


static int webster_writeBuffer(
	webster_message_t *output,
	const uint8_t *buffer,
    int size )
{
	if (output == NULL) return WBERR_INVALID_MESSAGE;
	if (size == 0 || buffer == NULL) return WBERR_OK;

	// ensures the current pointer is valid
	if (output->buffer.current == NULL)
	{
		output->buffer.current = output->buffer.data;
		output->buffer.pending = 0;
	}

	// fragment input data through recursive calls until the data size fits the internal buffer
	int offset = 0;
	int result = WBERR_OK;
	int fit = output->buffer.size - (int)(output->buffer.current - output->buffer.data);
	while (size > fit)
	{
		result = webster_writeBuffer(output, buffer + offset, fit);
		size -= fit;
		offset += fit;
		fit = output->buffer.size - (int)(output->buffer.current - output->buffer.data);
		if (result != WBERR_OK) return result;
	}

	memcpy(output->buffer.current, buffer + offset, (size_t) size);
	output->buffer.current += size;

	// send pending data if the buffer is full
	if (output->buffer.current >= output->buffer.data + output->buffer.size)
	{
		result = WBNET_SEND(output->channel, output->buffer.data, (uint32_t) output->buffer.size);
		output->buffer.current = output->buffer.data;
	}

	return result;
}


static int webster_writeString(
	webster_message_t *output,
	const char *text )
{
	if (text == NULL) return WBERR_INVALID_ARGUMENT;
	return webster_writeBuffer(output, (uint8_t*) text, (int) strlen(text));
}


static int webster_writeChar(
	webster_message_t *output,
	char value )
{
	return webster_writeBuffer(output, (uint8_t*) &value, 1);
}


static int webster_writeInteger(
	webster_message_t *output,
	int value )
{
	if (output == NULL) return WBERR_INVALID_MESSAGE;
	char temp[16] = { 0 };
	SNPRINTF(temp, sizeof(temp)-1, "%d", value);
	return webster_writeBuffer(output, (uint8_t*) temp, (int) strlen(temp));
}


static int webster_receiveHeader(
	webster_message_t *input )
{
	int result = webster_receive(input, WBL_READ_TIMEOUT, 1);
	if (result != WBERR_OK) return result;

	// no empty line means the HTTP header is longer than WEBSTER_MAX_HEADER
	char *ptr = strstr((char*) input->buffer.data, "\r\n\r\n");
	if (ptr == NULL) return WBERR_TOO_LONG;
	*(ptr + 3) = 0;
	// remember the last position
	input->buffer.current = (uint8_t*) ptr + 4;
	input->buffer.pending = input->buffer.pending - (int) ( (uint8_t*) ptr + 4 - input->buffer.data );
	// parse HTTP header fields and retrieve the content length
	result = http_parse((char*)input->buffer.data, input->type, input);
	input->header.content_length = input->body.expected;
	return result;
}


int WebsterWaitEvent(
    webster_message_t *input,
    webster_event_t *event )
{
	if (input == NULL) return WBERR_INVALID_MESSAGE;
	if (event == NULL) return WBERR_INVALID_ARGUMENT;

	event->size = 0;
	event->type = 0;
	int result = 0;

	if (input->state == WBS_IDLE)
	{
		result = webster_receiveHeader(input);
		if (result == WBERR_OK)
		{
			event->type = WBT_HEADER;
			event->size = (int) strlen((char*)input->buffer.data) + 1;
			input->state = WBS_HEADER;
		}
		return result;
	}
	else
	if (input->state == WBS_HEADER || input->state == WBS_BODY)
	{
		if (input->body.expected == 0)
		{
			input->state = WBS_COMPLETE;
			return WBERR_COMPLETE;
		}

		// TODO: should not receive more data than expected
		result = webster_receive(input, WBL_READ_TIMEOUT, 0);
		if (result == WBERR_OK)
		{
			// truncate any extra bytes beyond content length
			if (input->body.expected >= 0 && input->buffer.pending > input->body.expected)
			{
				input->buffer.pending = input->body.expected;
				input->buffer.data[input->buffer.pending] = 0;
				// we still have some data to return?
				if (input->buffer.pending == 0)
				{
					input->state = WBS_COMPLETE;
					return WBERR_COMPLETE;
				}
			}
			event->type = WBT_BODY;
			event->size = input->buffer.pending;
			input->state = WBS_BODY;
			input->body.expected -= input->buffer.pending;
		}

		return result;
	}

	return WBERR_COMPLETE;
}


int WebsterGetStringField(
    webster_message_t *input,
	int id,
	const char *name,
    const char **value )
{
	if (input == NULL) return WBERR_INVALID_MESSAGE;
	if (value == 0 || (name == NULL && id == WBFI_NON_STANDARD))
		return WBERR_INVALID_ARGUMENT;
	if (id < 0 || id > WBFI_WWW_AUTHENTICATE)
		return WBERR_INVALID_ARGUMENT;

	if (name != NULL)
	{
		id = WBFI_NON_STANDARD;
		int fid = http_getFieldID(name);
		if (fid != WBFI_NON_STANDARD) id = fid;
	}

	const std::string *result = NULL;
	if (id == WBFI_NON_STANDARD)
		result = input->header.field(name);
	else
		result = input->header.field(id);

	if (result == NULL) return WBERR_NO_DATA;
	*value = result->c_str();
	return WBERR_OK;
}


int WebsterGetIntegerField(
    webster_message_t *input,
    int id,
    const char *name,
    int *value )
{
	const char *temp = NULL;
	int result = WebsterGetStringField(input, id, name, &temp);
	if (result != WBERR_OK) return result;

	*value = atoi(temp);
	return WBERR_OK;
}


int WebsterIterateField(
    webster_message_t *input,
    int index,
    int *id,
    const char **name,
    const char **value )
{
	if (index < 0) return WBERR_INVALID_ARGUMENT;
	if (index >= input->header.count()) return WBERR_INVALID_ARGUMENT;
	if (id == NULL && name == NULL && value == NULL) return WBERR_OK;

	if (index < (int) input->header.s_fields.size())
	{
		int i = 0;
		standard_field_map::const_iterator it = input->header.s_fields.begin();
		for (; i < index && it != input->header.s_fields.end(); ++it, ++i);
		if (i != index) return WBERR_INVALID_ARGUMENT;

		if (id != NULL) *id = it->first;
		if (name != NULL) *name = http_getFieldName(it->first);
		if (value != NULL) *value = it->second.c_str();
		return WBERR_OK;
	}
	else
	{
		int i = (int) input->header.s_fields.size();
		custom_field_map::const_iterator it = input->header.c_fields.begin();
		for (; i < index && it != input->header.c_fields.end(); ++it, ++i);
		if (i != index) return WBERR_INVALID_ARGUMENT;

		if (name != NULL) *name = it->first.c_str();
		if (id != NULL) *id = http_getFieldID(it->first.c_str());
		if (value != NULL) *value = it->second.c_str();
		return WBERR_OK;
	}
}


int WebsterReadData(
    webster_message_t *input,
    const uint8_t **buffer,
	int *size )
{
	if (input == NULL) return WBERR_INVALID_MESSAGE;
	if (buffer == NULL || size == NULL) return WBERR_INVALID_ARGUMENT;

	if (input->buffer.pending <= 0 || input->buffer.current == NULL) return WBERR_NO_DATA;

	*buffer = input->buffer.current;
	*size = input->buffer.pending;

	input->buffer.current = NULL;
	input->buffer.pending = 0;

	return WBERR_OK;
}


int WebsterReadString(
    webster_message_t *input,
    const char **buffer )
{
	if (input == NULL) return WBERR_INVALID_MESSAGE;
	if (buffer == NULL) return WBERR_INVALID_ARGUMENT;

	if (input->buffer.pending <= 0 || input->buffer.current == NULL) return WBERR_NO_DATA;

	// the function 'webster_receive' is supposed to put a null-terminator
	// at the end of the data, but we want to be sure (better safe than sorry)
	*(input->buffer.current + input->buffer.pending) = 0;
	*buffer = (char*) input->buffer.current;

	input->buffer.current = NULL;
	input->buffer.pending = 0;

	return WBERR_OK;
}


int WebsterSetStatus(
    webster_message_t *output,
    int status )
{
	if (output == NULL) return WBERR_INVALID_MESSAGE;
	output->header.status = status;
	return WBERR_OK;
}


int WebsterSetMethod(
    webster_message_t *output,
    int method )
{
	if (output == NULL) return WBERR_INVALID_MESSAGE;
	if (!WB_IS_VALID_METHOD(method)) return WBERR_INVALID_HTTP_METHOD;
	output->header.method = method;
	return WBERR_OK;
}


int WebsterGetStatus(
    webster_message_t *output,
    int *status )
{
	if (output == NULL || status == NULL) return WBERR_INVALID_MESSAGE;
	*status = output->header.status;
	return WBERR_OK;
}


int WebsterGetMethod(
    webster_message_t *output,
    int *method )
{
	if (output == NULL || method == NULL) return WBERR_INVALID_MESSAGE;
	*method = output->header.method;
	return WBERR_OK;
}

int WebsterGetTarget(
    webster_message_t *output,
    const webster_target_t **target )
{
	if (output == NULL || target == NULL) return WBERR_INVALID_MESSAGE;
	*target = output->header.target;
	return WBERR_OK;
}


static int webster_writeStatusLine(
	webster_message_t *output )
{
	if (output == NULL) return WBERR_INVALID_MESSAGE;
	if (output->state != WBS_IDLE) return WBERR_INVALID_STATE;
	output->state = WBS_HEADER;

	const char *message = NULL;
	if (output->header.status == 0)
		output->header.status = 200;

	message = http_statusMessage(output->header.status);

	webster_writeString(output, "HTTP/1.1 ");
	webster_writeInteger(output, output->header.status);
	webster_writeChar(output, ' ');
	webster_writeString(output, message);
	webster_writeString(output, "\r\n");
	return WBERR_OK;
}


static int webster_writeResourceLine(
	webster_message_t *output )
{
	if (output == NULL) return WBERR_INVALID_MESSAGE;
	if (output->state != WBS_IDLE) return WBERR_INVALID_STATE;
	output->state = WBS_HEADER;

	if (!WB_IS_VALID_METHOD(output->header.method))
		output->header.method = WBM_GET;

	webster_writeString(output, HTTP_METHODS[output->header.method]);
	webster_writeChar(output, ' ');

	switch (output->header.target->type)
	{
		case WBRT_ABSOLUTE:
			if (output->header.target->scheme == WBP_HTTPS)
				webster_writeString(output, "https://");
			else
				webster_writeString(output, "http://");
			webster_writeString(output, output->header.target->host);
			webster_writeChar(output, ':');
			webster_writeInteger(output, output->header.target->port);
			if (output->header.target->path[0] != '/')
				webster_writeChar(output, '/');
			webster_writeString(output, output->header.target->path);
			if (output->header.target->query != NULL)
			{
				webster_writeChar(output, '&');
				webster_writeString(output, output->header.target->query);
			}
			break;
		case WBRT_ORIGIN:
			webster_writeString(output, output->header.target->path);
			if (output->header.target->query != NULL)
			{
				webster_writeChar(output, '&');
				webster_writeString(output, output->header.target->query);
			}
			break;
		case WBRT_ASTERISK:
			webster_writeChar(output, '*');
			break;
		case WBRT_AUTHORITY:
			webster_writeString(output, output->header.target->host);
			webster_writeChar(output, ':');
			webster_writeInteger(output, output->header.target->port);
			break;
		default:
			return WBERR_INVALID_RESOURCE;
	}

	webster_writeString(output, " HTTP/1.1\r\n");

	return WBERR_OK;
}


static int webster_commitFirstLine(
	webster_message_t *output )
{
	int result;

	if (output->type == WBMT_RESPONSE)
		result = webster_writeStatusLine(output);
	else
		result = webster_writeResourceLine(output);
	if (result != WBERR_OK) return result;
	output->state = WBS_HEADER;

	return WBERR_OK;
}


int WebsterSetStringField(
    webster_message_t *output,
    const char *name,
    const char *value )
{
	if (output == NULL) return WBERR_INVALID_MESSAGE;
	if (name == NULL || name[0] == 0 || value == NULL) return WBERR_INVALID_ARGUMENT;
	if (output->state >= WBS_BODY) return WBERR_INVALID_STATE;

	int result = WBERR_OK;
	if (output->state == WBS_IDLE)
	{
		result = webster_commitFirstLine(output);
		if (result != WBERR_OK) return result;
	}

	// TODO: evaluate field value

	int id = http_getFieldID(name);
	if (id == WBFI_CONTENT_LENGTH)
		output->body.expected = atoi(value);

	if (id != WBFI_NON_STANDARD)
		return output->header.field(id, value);
	else
		return output->header.field(name, value);
}


int WebsterSetIntegerField(
    webster_message_t *output,
    const char *name,
    int value )
{
	char temp[12];
	SNPRINTF(temp, sizeof(temp)-1, "%d", value);
	return WebsterSetStringField(output, name, temp);
}


int WebsterRemoveField(
    webster_message_t *output,
    const char *name )
{
	if (output == NULL) return WBERR_INVALID_MESSAGE;
	if (name == NULL) return WBERR_INVALID_ARGUMENT;

	output->header.remove(name);
	return WBERR_OK;
}


static void webster_commitHeaderFields(
    webster_message_t *output )
{
	// write standard fields
	for (standard_field_map::const_iterator it = output->header.s_fields.begin();
		 it != output->header.s_fields.end(); ++it)
	{
		const char *name = http_getFieldName(it->first);
		if (name == NULL) continue;

		webster_writeString(output, name);
		webster_writeString(output, ": ");
		webster_writeString(output, it->second.c_str());
		webster_writeString(output, "\r\n");
	}
	// write standard fields
	for (custom_field_map::const_iterator it = output->header.c_fields.begin();
		 it != output->header.c_fields.end(); ++it)
	{
		webster_writeString(output, it->first.c_str());
		webster_writeString(output, ": ");
		webster_writeString(output, it->second.c_str());
		webster_writeString(output, "\r\n");
	}

	webster_writeBuffer(output, (const uint8_t*)"\r\n", 2);
	output->state = WBS_BODY;
}


int WebsterWriteData(
    webster_message_t *output,
    const uint8_t *buffer,
    int size )
{
	if (output == NULL) return WBERR_INVALID_MESSAGE;
	if (buffer == NULL) return WBERR_INVALID_ARGUMENT;
	if (output->state == WBS_COMPLETE) return WBERR_INVALID_STATE;

	int result = 0;

	if (output->state == WBS_IDLE)
	{
		result = webster_commitFirstLine(output);
		if (result != WBERR_OK) return result;
	}

	if (output->state == WBS_HEADER)
	{
		// set 'tranfer-encoding' to chunked if required
		if (output->header.field(WBFI_CONTENT_LENGTH) == NULL)
		{
			output->flags |= WBMF_CHUNKED;
			// TODO: merge with previously set value, if any
			WebsterSetStringField(output, "transfer-encoding", "chunked");
		}
		if (output->type == WBMT_REQUEST &&
			output->header.field(WBFI_HOST) == NULL &&
			output->client != NULL)
		{
			static const size_t HOST_LEN = WBL_MAX_HOST_NAME + 1 + 5; // host + ':' + port
			char host[HOST_LEN + 1];
			SNPRINTF(host, HOST_LEN, "%s:%d", output->client->host.c_str(), output->client->port);
			host[HOST_LEN] = 0;
			WebsterSetStringField(output, "host", host);
		}
		webster_commitHeaderFields(output);
	}

	// ignores empty writes
	if (size <= 0) return WBERR_OK;

	// check whether we're using chuncked transfer encoding
	if (output->flags & WBMF_CHUNKED)
	{
		char temp[16];
		SNPRINTF(temp, sizeof(temp)-1, "%X\r\n", size);
		temp[15] = 0;
		webster_writeBuffer(output, (const uint8_t*) temp, (int) strlen(temp));
	}
	// write data
	webster_writeBuffer(output, buffer, size);
	// append the block terminator, if using chuncked transfer encoding
	if (output->flags & WBMF_CHUNKED)
		webster_writeBuffer(output, (const uint8_t*) "\r\n", 2);

	return WBERR_OK;
}


WEBSTER_EXPORTED int WebsterWriteString(
    webster_message_t *output,
    const char *text )
{
	return WebsterWriteData(output, (uint8_t*) text, (int) strlen(text));
}


int WebsterFlush(
	webster_message_t *output )
{
	if (output == NULL) return WBERR_INVALID_MESSAGE;
	if (output->state == WBS_COMPLETE) return WBERR_INVALID_STATE;

	// ensure we are done with the HTTP header
	if (output->state != WBS_BODY)
		WebsterWriteData(output, (uint8_t*) "", 0);
	// send all remaining body data
	if (output->buffer.current > output->buffer.data)
	{
		WBNET_SEND(output->channel, output->buffer.data, (uint32_t) (output->buffer.current - output->buffer.data));
		output->buffer.current = output->buffer.data;
	}

	return WBERR_OK;
}


int WebsterFinish(
	webster_message_t *output )
{
	if (output == NULL) return WBERR_INVALID_MESSAGE;
	if (output->state == WBS_COMPLETE) return WBERR_INVALID_STATE;

	WebsterFlush(output);

	// send the last marker if using chunked transfer encoding
	if (output->flags & WBMF_CHUNKED)
		WBNET_SEND(output->channel, (const uint8_t*) "0\r\n\r\n", 5);
	// we are done sending data now
	output->state = WBS_COMPLETE;

	return WBERR_OK;
}


WEBSTER_EXPORTED int WebsterGetState(
	webster_message_t *message,
    int *state )
{
	if (message == NULL) return WBERR_INVALID_MESSAGE;
	if (state == NULL) return WBERR_INVALID_ARGUMENT;

	*state = message->state;

	return WBERR_OK;
}
