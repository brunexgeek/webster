/*
 *   Copyright 2019 Bruno Ribeiro
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

#include "webster.h"
#include <stdlib.h>

#if defined(_WIN32) || defined(WIN32)
#define WB_WINDOWS
#endif


#define WBMF_CHUNKED    0x01


static webster_memory_t memory = { NULL, NULL, NULL, NULL };


struct webster_client_t_
{
	void *channel;
	const webster_target_t *target;
    webster_config_t config;
};


struct webster_server_t_
{
    void *channel;
    webster_config_t config;
};


#include <ctype.h>
#include <string.h>


#ifdef WB_WINDOWS
#define STRCMPI      _strcmpi
#else
#define STRCMPI      strcmpi
#endif


#ifndef WB_WINDOWS

static int strcmpi(const char *s1, const char *s2)
{
	if (s1 == NULL) return s2 == NULL ? 0 : -(*s2);
	if (s2 == NULL) return *s1;

	char c1, c2;
	while ((c1 = (char) tolower(*s1)) == (c2 = (char) tolower(*s2)))
	{
		if (*s1 == '\0') return 0;
		++s1; ++s2;
	}

	return c1 - c2;
}

#endif


static char *string_duplicate(
    const char *text )
{
    if (text == NULL) return NULL;
    size_t len = strlen(text);
    char *output = (char*) memory.malloc(len + 1);
    strcpy(output, text);
    return output;
}


static char *string_cut(
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


/*************
 * HTTP stack
 *************/

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>


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

typedef struct
{
	char *name;
	int id;
	char *value;
} webster_field_t ;


typedef struct
{
    webster_target_t *target;
    int status;
    int method;
    int content_length;
	struct
	{
		webster_field_t *head;
		int count;
		int total;
	} fields;
} webster_header_t;

static const char *get_field_by_id( webster_header_t *header, int id );
static const char *get_field_by_name( webster_header_t *header, const char *name );
static int set_field_by_id( webster_header_t *header, int id, const char *value );
static int set_field_by_name( webster_header_t *header, const char *name, const char *value );
static int remove_field_by_id( webster_header_t *header, int id );
static int remove_field_by_name( webster_header_t *header, const char *name );


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
};


static const char *http_statusMessage( int status );
static int http_get_field_id( const char *name );
static const char *http_get_field_name( int id );
static int http_parse_target( const char *url, webster_target_t **target );
static int http_parse( char *data, int type, webster_message_t *message );
static int http_free_target( webster_target_t *target );


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


/*
 * webster_header_t
 */


static const char *get_field_by_name( webster_header_t *header, const char *name )
{
	for (int i = 0; i < header->fields.count; ++i)
	{
		if (header->fields.head[i].id != WBFI_NON_STANDARD)
			continue;
		if (STRCMPI(header->fields.head[i].name, name) == 0)
			return header->fields.head[i].value;
	}
	return NULL;
}


static const char *get_field_by_id( webster_header_t *header, int id )
{
	if (id == WBFI_NON_STANDARD) return NULL;

	for (int i = 0; i < header->fields.count; ++i)
	{
		if (header->fields.head[i].id == id)
			return header->fields.head[i].value;
	}
	return NULL;
}


static int grow_fields( webster_header_t *header )
{
	int total = header->fields.total + WBL_DEF_FIELD_GROW;
	webster_field_t *tmp = memory.realloc(header->fields.head, (size_t) total * sizeof(webster_field_t));
	if (tmp != NULL)
	{
		header->fields.head = tmp;
		header->fields.total = total;
		return 1;
	}
	return 0;
}


static int set_field_by_id( webster_header_t *header, int id, const char *value )
{
	if (header->fields.count + header->fields.count >= WBL_MAX_FIELDS)
		return WBERR_TOO_MANY_FIELDS;

	if (header->fields.count == header->fields.total && !grow_fields(header))
		return WBERR_MEMORY_EXHAUSTED;

	webster_field_t *field = &header->fields.head[ header->fields.count++ ];
	field->id = id;
	field->name = NULL;
	field->value = string_duplicate(value);

	return WBERR_OK;
}


static int set_field_by_name( webster_header_t *header, const char *name, const char *value )
{
	if (header->fields.count + header->fields.count >= WBL_MAX_FIELDS)
		return WBERR_TOO_MANY_FIELDS;

	if (header->fields.count == header->fields.total && !grow_fields(header))
		return WBERR_MEMORY_EXHAUSTED;

	// check whether the name is standard
    int id = http_get_field_id(name);
    if (id != WBFI_NON_STANDARD)
	{
        return set_field_by_id(header, id, value);
	}

	// check for invalid characters
	for (size_t i = 0; name[i] != 0; ++i)
    {
        if (!IS_HFNC(name[i])) return WBERR_INVALID_HEADER_FIELD;
    }

	webster_field_t *field = &header->fields.head[ header->fields.count++ ];
	field->id = WBFI_NON_STANDARD;
	field->name = string_duplicate(name);
	field->value = string_duplicate(value);

	return WBERR_OK;
}


static int remove_field_by_id( webster_header_t *header, int id )
{
	int index = WBL_MAX_FIELDS + 1;

	for (index = 0; index < header->fields.count; ++index)
	{
		if (header->fields.head[index].id == id) break;
	}
	if (index >= header->fields.count) return WBERR_OK;

	webster_field_t *field = &header->fields.head[index];
	if (field->name) memory.free(field->name);
	if (field->value) memory.free(field->value);
	field->id = WBFI_NON_STANDARD;
	field->name = NULL;
	field->value = NULL;

	return WBERR_OK;
}


static int remove_field_by_name( webster_header_t *header, const char *name )
{
	int index = WBL_MAX_FIELDS + 1;

	for (index = 0; index < header->fields.count; ++index)
	{
		if (STRCMPI(header->fields.head[index].name, name) == 0) break;
	}
	if (index >= header->fields.count) return WBERR_OK;

	webster_field_t *field = &header->fields.head[index];
	if (field->name) memory.free(field->name);
	if (field->value) memory.free(field->value);
	field->id = WBFI_NON_STANDARD;
	field->name = NULL;
	field->value = NULL;

	return WBERR_OK;
}


/*
 * webster_message_t_
 */


static int message_initialize( struct webster_message_t_ *message, uint32_t size )
{
	memset(message, 0, sizeof(struct webster_message_t_));

    size = (size + 3) & (uint32_t) (~3);
    if (size < WBL_MIN_BUFFER_SIZE)
        size = WBL_MIN_BUFFER_SIZE;
    else
    if (size > WBL_MAX_BUFFER_SIZE)
        size = WBL_MAX_BUFFER_SIZE;

    message->body.expected = message->body.chunks = 0;
    // FIXME: can be NULL
    message->buffer.data = message->buffer.current = (uint8_t*) memory.malloc(size);
	if (!message->buffer.data) return WBERR_MEMORY_EXHAUSTED;
    message->buffer.data[0] = 0;
    message->buffer.size = (int) size;
    message->buffer.pending = 0;

	return WBERR_OK;
}


static void message_terminate( struct webster_message_t_ *message )
{
	for (int i = 0; i < message->header.fields.count; ++i)
	{
		webster_field_t *field = message->header.fields.head + i;
		if (field->name) memory.free(field->name);
		if (field->value) memory.free(field->value);
	}
	memory.free(message->header.fields.head);

    if (message->buffer.data) memory.free(message->buffer.data);
	memset(message, 0, sizeof(struct webster_message_t_));
}


/*
 * HTTP parser
 */


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


int http_get_field_id(
    const char *name )
{
	if (name == NULL || name[0] == 0) return WBFI_NON_STANDARD;

    int first = 0;
    int last = sizeof(HTTP_HEADER_FIELDS) / sizeof(webster_field_info_t) - 1;

    while (first <= last)
	{
		int current = (first + last) / 2;
		int dir = STRCMPI(name, HTTP_HEADER_FIELDS[current].name);
		if (dir == 0) return HTTP_HEADER_FIELDS[current].id;
		if (dir < 0)
			last = current - 1;
		else
			first = current + 1;
	}

	return WBFI_NON_STANDARD;
}


const char *http_get_field_name(
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


int http_parse_target(
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
            target->path = string_cut(url, 0, pos);
            target->query = string_cut(url, pos + 1, strlen(url) - pos - 1);
        }
        else
        {
            target->path = string_duplicate(url);
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
        target->host = string_cut(hb, 0, (size_t) (he - hb));

		// return the resource, if any
		if (re != NULL)
			target->path = string_cut(rb, 0, (size_t) (re - rb));
		else
			target->path = string_duplicate("/");

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
            target->user = string_cut(url, 0, (size_t) (hb - url));
            hb++;
        }
        else
            hb = url;

        const char *he = strchr(hb, ':');
        if (he != NULL)
        {
            target->host = string_cut(hb, 0, (size_t) (he - hb));
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
            target->host = string_duplicate(hb);
            target->port = 80;
        }
    }

    return WBERR_OK;
}


int http_free_target(
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
    message->body.chunks = 0;

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
                result = http_parse_target(token, &header->target);
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

            // ignore trailing whitespaces in the value
            value = http_removeTrailing(value);
            // get the field ID, if any
            int id = http_get_field_id(name);
            if (id != WBFI_NON_STANDARD)
            {
                set_field_by_id(header, id, value);

                // if is 'content-length' field, get the value
                if (id == WBFI_CONTENT_LENGTH)
                    message->body.expected = atoi(value);
                else
                if (id == WBFI_TRANSFER_ENCODING && strstr(value, "chunked"))
				{
					message->body.flags |= WBMF_CHUNKED;
                    message->body.expected = -1;
				}
            }
            else
                set_field_by_name(header, name, value);
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

#ifndef WEBSTER_NO_DEFAULT_NETWORK

#include <sys/types.h>


#ifdef WB_WINDOWS
#include <winsock2.h>
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


static int network_initialize()
{
	int result = WBERR_OK;

	#ifdef WB_WINDOWS
	int err = 0;
	static int initialized = 0;
	WORD wVersionRequested;
	WSADATA wsaData;
	wVersionRequested = MAKEWORD( 2, 2 );

	EnterCriticalSection(&network_mutex);

	if (!initialized)
	{
		err = WSAStartup( wVersionRequested, &wsaData );
		if (err != 0 || LOBYTE(wsaData.wVersion) != 2 || HIBYTE(wsaData.wVersion) != 2)
		{
			if (err == 0) WSACleanup();
			result = WBERR_SOCKET;
		}
		else
			initialized = 1;
	}

	LeaveCriticalSection(&network_mutex);

	#endif // __WINDOWS__

	return result;
}


static int network_open(
	void **channel )
{
	if (channel == NULL) return WBERR_INVALID_CHANNEL;

	int result = network_initialize();
	if (result != WBERR_OK) return result;

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
	// wait for data
	#ifdef WB_WINDOWS
	int result = WSAPoll(&chann->poll, 1, timeout);
	#else
	int result = poll(&chann->poll, 1, timeout);
	#endif
	if (result == 0) return WBERR_TIMEOUT;
	if (result == EINTR) return WBERR_SIGNAL;
	if (result < 0) return WBERR_SOCKET;

	ssize_t bytes = recv(chann->socket, (char *) buffer, (size_t) bufferSize, 0);
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
	int result = WSAPoll(&chann->poll, 1, 10000);
	#else
	int result = poll(&chann->poll, 1, 10000);
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


static webster_network_t DEFAULT_NETWORK =
{
	network_open,
	network_close,
	network_connect,
	network_receive,
	network_send,
	network_accept,
	network_listen
};

#endif // !WEBSTER_NO_DEFAULT_NETWORK

/*************
 * Webster API
 *************/


#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>


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
    const webster_memory_t *mem )
{
	if (mem && (!mem->malloc || !mem->free || !mem->calloc || !mem->realloc))
		return WBERR_INVALID_ARGUMENT;

	if (mem != NULL)
	{
		memory.malloc = mem->malloc;
		memory.calloc = mem->calloc;
		memory.realloc = mem->realloc;
		memory.free = mem->free;
	}
	else
	{
		memory.malloc = malloc;
		memory.calloc = calloc;
		memory.realloc = realloc;
		memory.free = free;
	}

	#ifdef WB_WINDOWS
	InitializeCriticalSection(&network_mutex);
	#endif

	return WBERR_OK;
}


int WebsterTerminate()
{
	memory.malloc = NULL;
	memory.calloc = NULL;
	memory.realloc = NULL;
	memory.free = NULL;

	#ifdef WB_WINDOWS
	DeleteCriticalSection(&network_mutex);
	#endif

	return WBERR_OK;
}


int WebsterParseURL(
	const char *url,
	webster_target_t **target )
{
	return http_parse_target(url, target);
}


int WebsterFreeURL(
    webster_target_t *target )
{
	return http_free_target(target);
}


//
// Client API
//


static void copy_config( const webster_config_t *from, webster_config_t *to )
{
	memset(to, 0, sizeof(webster_config_t));

	#ifndef WEBSTER_NO_DEFAULT_NETWORK
	to->net = &DEFAULT_NETWORK;
	#endif

	if (from)
	{
		if (from->net) to->net = from->net;
		to->max_clients = from->max_clients;
		to->buffer_size = (uint32_t) (from->buffer_size + 3) & (uint32_t) (~3);
		to->read_timeout = from->read_timeout;
	}

	if (to->max_clients <= 0)
		to->max_clients = WBL_DEF_CONNECTIONS;
	else
	if (to->max_clients > WBL_MAX_CONNECTIONS)
		to->max_clients = WBL_MAX_CONNECTIONS;

	if (to->buffer_size == 0)
		to->buffer_size = WBL_DEF_BUFFER_SIZE;
	else
	if (to->buffer_size > WBL_MAX_BUFFER_SIZE)
		to->buffer_size = WBL_MAX_BUFFER_SIZE;

	if (to->read_timeout <= 0)
		to->read_timeout = WBL_DEF_TIMEOUT;
	else
	if (to->read_timeout > WBL_MAX_TIMEOUT)
		to->read_timeout = WBL_DEF_TIMEOUT;
}


int WebsterConnect(
    webster_client_t **client,
    const webster_target_t *target,
    const webster_config_t *config )
{
	if (client == NULL)
		return WBERR_INVALID_CLIENT;
	#ifdef WEBSTER_NO_DEFAULT_NETWORK
	if (config && !config->net)
		return WBERR_INVALID_ARGUMENT;
	#endif

	*client = (struct webster_client_t_*) memory.calloc(1, sizeof(struct webster_client_t_));
	if (*client == NULL) return WBERR_MEMORY_EXHAUSTED;
	(*client)->target = target;

	copy_config(config, &(*client)->config);

	// try to connect with the remote host
	int result = (*client)->config.net->open( &(*client)->channel );
	if (result != WBERR_OK) goto ESCAPE;
	result = (*client)->config.net->connect((*client)->channel, target->scheme, target->host, target->port);
	if (result != WBERR_OK) goto ESCAPE;

	return WBERR_OK;

ESCAPE:
	if (*client != NULL)
	{
		if ((*client)->channel != NULL) (*client)->config.net->close((*client)->channel);
		memory.free(*client);
		*client = NULL;
	}
	return result;
}


int WebsterCommunicate(
    webster_client_t *client,
    webster_target_t *url,
    webster_handler_t *callback,
    void *data )
{
	int result;
	if (client == NULL) return WBERR_INVALID_CLIENT;
	if (callback == NULL) return WBERR_INVALID_ARGUMENT;

	struct webster_message_t_ request;
	result = message_initialize(&request, client->config.buffer_size);
	if (result != WBERR_OK) return result;
	struct webster_message_t_ response;
	result = message_initialize(&response, client->config.buffer_size);
	if (result != WBERR_OK)
	{
		message_terminate(&request);
		return result;
	}

	request.type = WBMT_REQUEST;
	request.channel = client->channel;
	request.header.method = WBM_GET;
	request.client = client;
	request.header.target = url;

	response.type = WBMT_RESPONSE;
	response.channel = client->channel;
	response.client = client;
	response.header.target = url;

	callback(&request, &response, data);

	if (request.header.target != url) http_free_target(request.header.target);
	if (response.header.target != url) http_free_target(response.header.target);

	message_terminate(&request);
	message_terminate(&response);

	return WBERR_OK;
}


int WebsterDisconnect(
    webster_client_t *client )
{
	if (client == NULL) return WBERR_INVALID_CLIENT;

	client->config.net->close(client->channel);
	memory.free(client);
	return WBERR_OK;
}


//
// Server API
//


int WebsterCreate(
    webster_server_t **server,
	const webster_config_t *config )
{
	if (server == NULL) return WBERR_INVALID_SERVER;

	#ifdef WEBSTER_NO_DEFAULT_NETWORK
	if (config && !config->net)
		return WBERR_INVALID_ARGUMENT;
	#endif

	*server = (struct webster_server_t_*) memory.calloc(1, sizeof(struct webster_server_t_));
	if (*server == NULL) return WBERR_MEMORY_EXHAUSTED;

	copy_config(config, &(*server)->config);

	return WBERR_OK;
}


int WebsterDestroy(
    webster_server_t *server )
{
	if (server == NULL) return WBERR_INVALID_SERVER;

	WebsterStop(server);
	memory.free(server);

	return WBERR_OK;
}


int WebsterStart(
	webster_server_t *server,
    const webster_target_t *target )
{
	if (server == NULL)
		return WBERR_INVALID_SERVER;
	if (target == NULL || (target->type & WBRT_AUTHORITY) == 0)
		return WBERR_INVALID_TARGET;

	int result = server->config.net->open(&server->channel);
	if (result != WBERR_OK) return result;

	return server->config.net->listen(server->channel, target->host, target->port, server->config.max_clients);
}


int WebsterStop(
    webster_server_t *server )
{
	if (server == NULL) return WBERR_INVALID_SERVER;

	server->config.net->close(server->channel);
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
	int result = server->config.net->accept(server->channel, &client);
	if (result != WBERR_OK) return result;

	*remote = (struct webster_client_t_*) memory.calloc(1, sizeof(struct webster_client_t_));
	if (*remote == NULL)
	{
		server->config.net->close(client);
		return WBERR_MEMORY_EXHAUSTED;
	}

	(*remote)->channel = client;
	copy_config(&server->config, &(*remote)->config);

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
 * Read data until we find the header terminator or the internal buffer is full.
 */
static int webster_receiveHeader(
	webster_message_t *input,
	int timeout )
{
	char *ptr = NULL;
	int result = 0;

	if (input == NULL) return WBERR_INVALID_MESSAGE;
	if (timeout < 0) timeout = 0;

	// ignore any pending data
	input->buffer.pending = 0;

	// Note: when reading input data we leave room in the buffer for a null-terminator
	//       so we can manipulate its content as a string.

	while (1)
	{
		uint32_t bytes = (uint32_t) input->buffer.size - (uint32_t) input->buffer.pending - 1;
		if (bytes == 0) return WBERR_TOO_LONG;

		// receive new data and adjust pending information
		uint64_t startTime = webster_tick();
		result = input->client->config.net->receive(input->channel, input->buffer.data + input->buffer.pending, &bytes, timeout);
		if (timeout > 0) timeout = timeout - (int) (webster_tick() - startTime);

		if (result == WBERR_OK)
		{
			input->buffer.pending += (int) bytes;
			input->buffer.current = input->buffer.data;
			// ensure we have a null-terminator at the end
			*(input->buffer.current + input->buffer.pending) = 0;
			ptr = strstr((char*)input->buffer.current, "\r\n\r\n");
			if (ptr != NULL) break;
		}
		else
		if (result != WBERR_TIMEOUT && result != WBERR_SIGNAL)
			return result;

		if (timeout <= 0) return WBERR_TIMEOUT;
	}

	*(ptr + 3) = 0;
	// remember the last position
	input->buffer.current = (uint8_t*) ptr + 4;
	input->buffer.pending = input->buffer.pending - (int) ( (uint8_t*) ptr + 4 - input->buffer.data );
	// parse HTTP header fields and retrieve the content length
	result = http_parse((char*)input->buffer.data, input->type, input);
	input->header.content_length = input->body.expected;

	return WBERR_OK;
}


/**
 * Ensure we have at least the specificed amount of data in the reading buffer.
 */
static int webster_ensure( webster_message_t *input, int size, int timeout )
{
	if (size <= input->buffer.pending) return WBERR_OK;
	if (size > input->buffer.size) return WBERR_MEMORY_EXHAUSTED;

	size = size - input->buffer.pending;
	int avail = (int) (input->buffer.current - input->buffer.data) + input->buffer.pending - input->buffer.size;
	if (size < avail)
	{
		memmove(input->buffer.data, input->buffer.current, (size_t) input->buffer.pending);
		input->buffer.current = input->buffer.data;
	}

	// receive new data and adjust pending information
	uint32_t bytes = (uint32_t) size;
	int result = input->client->config.net->receive(input->channel, input->buffer.current + input->buffer.pending, &bytes, timeout);
	if (result != WBERR_OK) return result;
	if ((int) bytes != size) return WBERR_NO_DATA;
	return WBERR_OK;
}


static int webster_chunkSize( webster_message_t *input, int timeout )
{
	#if 0
	uint64_t startTime = webster_tick();
	int result = 0;
	uint8_t buffer[64];
	uint32_t bytes = 0;

	if (input->body.chunks > 0)
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
static int webster_receiveBody(
	webster_message_t *input,
	int *count,
	int timeout )
{
	if (count == NULL || input == NULL) return WBERR_INVALID_ARGUMENT;
	if (timeout < 0) timeout = 0;

	// if not expecting any data, just return success
	if (input->body.expected == 0)
	{
		if ((input->body.flags & WBMF_CHUNKED) == 0)
			return WBERR_COMPLETE;
		else
		{
			int result = webster_chunkSize(input, timeout);
			if (result != WBERR_OK) return result;
			if (input->body.expected == 0) return WBERR_COMPLETE;
		}
	}
	// if we still have data in the buffer, just return success
	if (input->buffer.pending > 0) return WBERR_OK;

	input->buffer.pending = 0;
	*count = 0;

	// Note: when reading input data we leave room in the buffer for a null-terminator
	//       so we can manipulate its content as a string.
	uint32_t bytes = (uint32_t) input->buffer.size - (uint32_t) input->buffer.pending - 1;
	// prevent reading more that's supposed to
	if (input->body.expected >= 0 && bytes > (uint32_t) input->body.expected) bytes = (uint32_t) input->body.expected;

	// receive new data and adjust pending information
	int result = input->client->config.net->receive(input->channel, input->buffer.data + input->buffer.pending, &bytes, timeout);

	if (result == WBERR_OK)
	{
		input->buffer.pending += (int) bytes;
		input->buffer.current = input->buffer.data;
		// ensure we have a null-terminator at the end
		*(input->buffer.current + input->buffer.pending) = 0;
	}
	return result;
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

	// fragment input data through recursive call until the data size fits the internal buffer
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
		result = output->client->config.net->send(output->channel, output->buffer.data, (uint32_t) output->buffer.size);
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
	int64_t value )
{
	if (output == NULL) return WBERR_INVALID_MESSAGE;
	char temp[24] = { 0 };
	#ifdef WB_WINDOWS
	SNPRINTF(temp, sizeof(temp)-1, "%lld", value);
	#else
	SNPRINTF(temp, sizeof(temp)-1, "%ld", value);
	#endif
	return webster_writeBuffer(output, (uint8_t*) temp, (int) strlen(temp));
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
		result = webster_receiveHeader(input, input->client->config.read_timeout);
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
		int count = 0;
		result = webster_receiveBody(input, &count, input->client->config.read_timeout);
		if (result == WBERR_OK)
		{
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
		int fid = http_get_field_id(name);
		if (fid != WBFI_NON_STANDARD) id = fid;
	}

	if (id == WBFI_NON_STANDARD)
		*value = get_field_by_name(&input->header, name);
	else
		*value = get_field_by_id(&input->header, id);

	if (*value == NULL) return WBERR_NO_DATA;
	return WBERR_OK;
}


int WebsterGetIntegerField(
    webster_message_t *input,
    int id,
    const char *name,
    int64_t *value )
{
	if (value == NULL) return WBERR_INVALID_ARGUMENT;

	const char *temp = NULL;
	char *ptr = NULL;
	int result = WebsterGetStringField(input, id, name, &temp);
	if (result != WBERR_OK) return result;

	#ifdef WB_WINDOWS
	*value = strtoll(temp, &ptr, 10);
	#else
	*value = strtol(temp, &ptr, 10);
	#endif

	if (ptr == temp) return WBERR_INVALID_VALUE;

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
	if (index < (int) input->header.fields.count)
	{
		if (id == NULL && name == NULL && value == NULL) return WBERR_OK;

		webster_field_t *field = input->header.fields.head + index;
		if (id != NULL) *id = field->id;
		if (name != NULL)
		{
			if (field->id == WBFI_NON_STANDARD)
				*name = field->name;
			else
				*name = http_get_field_name(field->id);
		}
		if (value != NULL) *value = field->value;
		return WBERR_OK;
	}

	return WBERR_INVALID_ARGUMENT;
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

	int id = http_get_field_id(name);
	if (id == WBFI_CONTENT_LENGTH)
		output->body.expected = atoi(value);

	if (id != WBFI_NON_STANDARD)
		return set_field_by_id(&output->header, id, value);
	else
		return set_field_by_name(&output->header, name, value);
}


int WebsterSetIntegerField(
    webster_message_t *output,
    const char *name,
    int64_t value )
{
	char temp[24] = { 0 };
	#ifdef WB_WINDOWS
	SNPRINTF(temp, sizeof(temp)-1, "%lld", value);
	#else
	SNPRINTF(temp, sizeof(temp)-1, "%ld", value);
	#endif
	return WebsterSetStringField(output, name, temp);
}


int WebsterRemoveField(
    webster_message_t *output,
    const char *name )
{
	if (output == NULL) return WBERR_INVALID_MESSAGE;
	if (name == NULL) return WBERR_INVALID_ARGUMENT;

	int id = http_get_field_id(name);
	if (id != WBFI_NON_STANDARD)
		remove_field_by_id(&output->header, id);
	else
		remove_field_by_name(&output->header, name);
	return WBERR_OK;
}


static void webster_commitHeaderFields(
    webster_message_t *output )
{
	for (int i = 0; i < output->header.fields.count; ++i)
	{
		webster_field_t *field = output->header.fields.head + i;

		if (field->id == WBFI_NON_STANDARD)
		{
			if (!field->name) continue;
			webster_writeString(output, field->name);
		}
		else
		{
			const char *name = http_get_field_name(field->id);
			if (name == NULL) continue;
			webster_writeString(output, name);
		}

		webster_writeString(output, ": ");
		webster_writeString(output, field->value);
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
		if (get_field_by_id(&output->header, WBFI_CONTENT_LENGTH) == NULL)
		{
			output->body.flags |= WBMF_CHUNKED;
			// TODO: merge with previously set value, if any
			WebsterSetStringField(output, "Transfer-Encoding", "chunked");
		}
		if (output->type == WBMT_REQUEST &&
			get_field_by_id(&output->header, WBFI_HOST) == NULL &&
			output->client != NULL)
		{
			static const size_t HOST_LEN = WBL_MAX_HOST_NAME + 1 + 5; // host + ':' + port
			char host[HOST_LEN + 1];
			SNPRINTF(host, HOST_LEN, "%s:%d", output->client->target->host, output->client->target->port);
			host[HOST_LEN] = 0;
			WebsterSetStringField(output, "Host", host);
		}
		webster_commitHeaderFields(output);
	}

	// ignores empty writes
	if (size <= 0) return WBERR_OK;

	// check whether we're using chuncked transfer encoding
	if (output->body.flags & WBMF_CHUNKED)
	{
		char temp[16];
		SNPRINTF(temp, sizeof(temp)-1, "%X\r\n", size);
		temp[15] = 0;
		webster_writeBuffer(output, (const uint8_t*) temp, (int) strlen(temp));
	}
	// write data
	webster_writeBuffer(output, buffer, size);
	// append the block terminator, if using chuncked transfer encoding
	if (output->body.flags & WBMF_CHUNKED)
		webster_writeBuffer(output, (const uint8_t*) "\r\n", 2);

	return WBERR_OK;
}


int WebsterWriteString(
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
		output->client->config.net->send(output->channel, output->buffer.data, (uint32_t) (output->buffer.current - output->buffer.data));
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
	if (output->body.flags & WBMF_CHUNKED)
		output->client->config.net->send(output->channel, (const uint8_t*) "0\r\n\r\n", 5);
	// we are done sending data now
	output->state = WBS_COMPLETE;

	return WBERR_OK;
}


int WebsterGetState(
	webster_message_t *message,
    int *state )
{
	if (message == NULL) return WBERR_INVALID_MESSAGE;
	if (state == NULL) return WBERR_INVALID_ARGUMENT;

	*state = message->state;

	return WBERR_OK;
}
