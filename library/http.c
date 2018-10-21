#include "http.h"
#include "internal.h"
#include <string.h>
#include <webster/api.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>


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
    if (name == NULL || name[0] == 0 || name[0] < 'a' || name[0] > 'z') return 0;

    switch (name[0])
    {
        case 'a':
            if (name[1] == 'c')
            {
                if (name[2] == 'c' && name[3] == 'e')
                {
                    if (strcmp(name, "accept") == 0)                            return WBFI_ACCEPT;
                    if (strcmp(name, "accept-charset") == 0)                    return WBFI_ACCEPT_CHARSET;
                    if (strcmp(name, "accept-encoding") == 0)                   return WBFI_ACCEPT_ENCODING;
                    if (strcmp(name, "accept-language") == 0)                   return WBFI_ACCEPT_LANGUAGE;
                    if (strcmp(name, "accept-patch") == 0)                      return WBFI_ACCEPT_PATCH;
                    if (strcmp(name, "accept-ranges") == 0)                     return WBFI_ACCEPT_RANGES;
                }
                if (strcmp(name, "access-control-allow-credentials") == 0)  return WBFI_ACCESS_CONTROL_ALLOW_CREDENTIALS;
                if (strcmp(name, "access-control-allow-headers") == 0)      return WBFI_ACCESS_CONTROL_ALLOW_HEADERS;
                if (strcmp(name, "access-control-allow-methods") == 0)      return WBFI_ACCESS_CONTROL_ALLOW_METHODS;
                if (strcmp(name, "access-control-allow-origin") == 0)       return WBFI_ACCESS_CONTROL_ALLOW_ORIGIN;
                if (strcmp(name, "access-control-max-age") == 0)            return WBFI_ACCESS_CONTROL_MAX_AGE;
                if (strcmp(name, "access-control-expose-headers") == 0)     return WBFI_ACCESS_CONTROL_EXPOSE_HEADERS;
                if (strcmp(name, "access-control-request-headers") == 0)    return WBFI_ACCESS_CONTROL_REQUEST_HEADERS;
                if (strcmp(name, "access-control-request-method") == 0)     return WBFI_ACCESS_CONTROL_REQUEST_METHOD;
            }
            if (strcmp(name, "authorization") == 0)                     return WBFI_AUTHORIZATION;
            if (strcmp(name, "age") == 0)                               return WBFI_AGE;
            if (strcmp(name, "allow") == 0)                             return WBFI_ALLOW;
            if (strcmp(name, "alt-svc") == 0)                           return WBFI_ALT_SVC;
            break;
        case 'c':
            if (strcmp(name, "content-length") == 0)                    return WBFI_CONTENT_LENGTH;
            if (strcmp(name, "content-type") == 0)                      return WBFI_CONTENT_TYPE;
            if (strcmp(name, "cookie") == 0)                            return WBFI_COOKIE;
            if (strcmp(name, "cache-control") == 0)                     return WBFI_CACHE_CONTROL;
            if (strcmp(name, "connection") == 0)                        return WBFI_CONNECTION;
            if (strcmp(name, "content-disposition") == 0)               return WBFI_CONTENT_DISPOSITION;
            if (strcmp(name, "content-encoding") == 0)                  return WBFI_CONTENT_ENCODING;
            if (strcmp(name, "content-language") == 0)                  return WBFI_CONTENT_LANGUAGE;
            if (strcmp(name, "content-location") == 0)                  return WBFI_CONTENT_LOCATION;
            if (strcmp(name, "content-range") == 0)                     return WBFI_CONTENT_RANGE;
            break;
        case 'd':
            if (strcmp(name, "date") == 0)                              return WBFI_DATE;
            if (strcmp(name, "dnt") == 0)                               return WBFI_DNT;
            break;
        case 'e':
            if (strcmp(name, "etag") == 0)                              return WBFI_ETAG;
            if (strcmp(name, "expires") == 0)                           return WBFI_EXPIRES;
            if (strcmp(name, "expect") == 0)                            return WBFI_EXPECT;
            break;
        case 'f':
            if (strcmp(name, "forwarded") == 0)                         return WBFI_FORWARDED;
            if (strcmp(name, "from") == 0)                              return WBFI_FROM;
            break;
        case 'h':
            if (strcmp(name, "host") == 0)                              return WBFI_HOST;
            break;
        case 'i':
            if (strcmp(name, "if-match") == 0)                          return WBFI_IF_MATCH;
            if (strcmp(name, "if-modified-since") == 0)                 return WBFI_IF_MODIFIED_SINCE;
            if (strcmp(name, "if-none-match") == 0)                     return WBFI_IF_NONE_MATCH;
            if (strcmp(name, "if-range") == 0)                          return WBFI_IF_RANGE;
            if (strcmp(name, "if-unmodified-since") == 0)               return WBFI_IF_UNMODIFIED_SINCE;
            break;
        case 'l':
            if (strcmp(name, "last-modified") == 0)                     return WBFI_LAST_MODIFIED;
            if (strcmp(name, "link") == 0)                              return WBFI_LINK;
            if (strcmp(name, "location") == 0)                          return WBFI_LOCATION;
            break;
        case 'm':
            if (strcmp(name, "max-forwards") == 0)                      return WBFI_MAX_FORWARDS;
            break;
        case 'o':
            if (strcmp(name, "origin") == 0)                            return WBFI_ORIGIN;
            break;
        case 'p':
            if (strcmp(name, "pragma") == 0)                            return WBFI_PRAGMA;
            if (strcmp(name, "proxy-authenticate") == 0)                return WBFI_PROXY_AUTHENTICATE;
            if (strcmp(name, "proxy-authorization") == 0)               return WBFI_PROXY_AUTHORIZATION;
            if (strcmp(name, "public-key-pins") == 0)                   return WBFI_PUBLIC_KEY_PINS;
            break;
        case 'r':
            if (strcmp(name, "referer") == 0)                           return WBFI_REFERER;
            if (strcmp(name, "range") == 0)                             return WBFI_RANGE;
            if (strcmp(name, "retry-after") == 0)                       return WBFI_RETRY_AFTER;
            break;
        case 's':
            if (strcmp(name, "server") == 0)                            return WBFI_SERVER;
            if (strcmp(name, "set-cookie") == 0)                        return WBFI_SET_COOKIE;
            if (strcmp(name, "strict-transport-security") == 0)         return WBFI_STRICT_TRANSPORT_SECURITY;
            break;
        case 't':
            if (strcmp(name, "transfer-encoding") == 0)                 return WBFI_TRANSFER_ENCODING;
            if (strcmp(name, "te") == 0)                                return WBFI_TE;
            if (strcmp(name, "tk") == 0)                                return WBFI_TK;
            if (strcmp(name, "trailer") == 0)                           return WBFI_TRAILER;
            break;
        case 'u':
            if (strcmp(name, "user-agent") == 0)                        return WBFI_USER_AGENT;
            if (strcmp(name, "upgrade") == 0)                           return WBFI_UPGRADE;
            if (strcmp(name, "upgrade-insecure-requests") == 0)         return WBFI_UPGRADE_INSECURE_REQUESTS;
            break;
        case 'v':
            if (strcmp(name, "vary") == 0)                              return WBFI_VARY;
            if (strcmp(name, "via") == 0)                               return WBFI_VIA;
            break;
        case 'w':
            if (strcmp(name, "www-authenticate") == 0)                  return WBFI_WWW_AUTHENTICATE;
            if (strcmp(name, "warning") == 0)                           return WBFI_WARNING;
    }

    return 0;
}


const webster_field_t *http_getFieldByName(
    const webster_header_t *header,
    const char *name )
{
    for (int i = 0; i < header->fieldCount; ++i)
        if (strcmp(header->fields[i].name, name) == 0)
            return header->fields + i;

    return NULL;
}


const webster_field_t *http_getFieldById(
    const webster_header_t *header,
    int id )
{
    for (int i = 0; i < header->fieldCount; ++i)
        if (header->fields[i].id == id)
            return header->fields + i;

    return NULL;
}


// TODO: ensure the field does not exists
int http_addField(
    webster_header_t *header,
    int id,
	const char *name,
    const char *value )
{
	size_t size = sizeof(webster_field_t) + strlen(value) + 1 + strlen(name) + 1;
	webster_field_t *field = (webster_field_t*) malloc(size);
	if (field == NULL) return WBERR_MEMORY_EXHAUSTED;
    field->name = (char*) field + sizeof(webster_field_t);
    field->value = field->name + strlen(name) + 1;

	field->id = id;
	strcpy(field->name, name);
	strcpy(field->value, value);
	field->next = NULL;

	if (header->fields == NULL)
		header->fields = field;
	else
	{
		webster_field_t *tail = header->fields;
		while (tail->next != NULL) tail = tail->next;
		tail->next = field;
	}
	++header->fieldCount;

	return WBERR_OK;
}


void http_releaseFields(
    webster_header_t *header )
{
    webster_field_t *ptr = NULL;
    webster_field_t *field = header->fields;
	while (field != NULL)
    {
        ptr = field;
        field = field->next;
        free(ptr);
    }
    header->fields = NULL;
    header->fieldCount = 0;
}

static int tokenize(
    char *buffer,
    const char *delimiter,
    char terminator,
    char **tokens,
    size_t size )
{
    size_t count = 0;
    char *ptr = buffer;
    char *start = buffer;
    int useless = 1;

    memset(tokens, 0, sizeof(char*) * size);

    for (; count < size; ++ptr)
    {
        char current = *ptr;

        if (strchr(delimiter, *ptr) != NULL)
        {
            if (useless) continue;

            *ptr = 0;
            tokens[count++] = start;
            start = ptr + 1;
            useless = 1;
        }
        else
        {
            useless = 0;
            if (*ptr == '\r') *ptr = 0;
        }

        if (current == terminator || current == 0) break;
    }

    return (int) count;
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


int http_parseHeader(
    char *data,
    struct webster_message_t_ *message )
{
    webster_field_t *field = NULL;
    webster_field_t *next = NULL;
    char *ptr = NULL;
    char *tokens[128];

    webster_header_t *header = &message->header;

    // find the first header field
    ptr = strstr(data, "\r\n");
    if (ptr == NULL) return WBERR_INVALID_HTTP_MESSAGE;
    ptr += 2;

    // reset content length to zero
    message->body.expected = 0;

    int count = tokenize((char*) data, " \n", '\n', tokens, 8);

    if (message->type == WBMT_REQUEST)
    {
        if (count != 3) return WBERR_INVALID_HTTP_MESSAGE;

        // we only accept HTTP 1.1 messages
        if (strcmp(tokens[2], "HTTP/1.1") != 0) return WBERR_INVALID_HTTP_VERSION;

        // find out the HTTP method (case-sensitive according to RFC-7230:3.1.1)
        if (strcmp(tokens[0], "GET") == 0)
            header->method = WBM_GET;
        else
        if (strcmp(tokens[0], "POST") == 0)
            header->method = WBM_POST;
        else
        if (strcmp(tokens[0], "HEAD") == 0)
            header->method = WBM_HEAD;
        else
        if (strcmp(tokens[0], "PUT") == 0)
            header->method = WBM_PUT;
        else
        if (strcmp(tokens[0], "DELETE") == 0)
            header->method = WBM_DELETE;
        else
        if (strcmp(tokens[0], "CONNECT") == 0)
            header->method = WBM_CONNECT;
        else
        if (strcmp(tokens[0], "OPTIONS") == 0)
            header->method = WBM_OPTIONS;
        else
        if (strcmp(tokens[0], "TRACE") == 0)
            header->method = WBM_TRACE;
        else
            return WBERR_INVALID_HTTP_METHOD;

        header->resource = tokens[1];
        header->query = NULL;
        char *tmp = strchr(header->resource, '?');
        if (tmp != NULL)
        {
            header->query = tmp + 1;
            *tmp = 0;
        }
    }
    else
    {
        // we only accept HTTP 1.1 messages
        if (strcmp(tokens[0], "HTTP/1.1") != 0) return WBERR_INVALID_HTTP_VERSION;
        header->status = atoi(tokens[1]);
    }

    // parse up to 128 fields
    count = tokenize(ptr, "\n", 0, tokens, 128);
    if (count == 0) return WBERR_INVALID_HTTP_MESSAGE;
    int isChunked = 0;

    // parse HTTP fields (case-insensitive according to RFC-7230:3.2)
    for (int i = 0; i < count; ++i)
    {
        char *p = NULL;

        // split the line in half
        char *value = strchr(tokens[i], ':');
        if (value == NULL || *tokens[i] == ' ' || value <= tokens[i] || *(value-1) == ' ') goto ESCAPE;
        *value = 0;
        ++value;
        // change the field name to lowercase
        for (p = tokens[i]; *p && *p != ' '; ++p) *p = (char) tolower(*p);
        if (*p == ' ') goto ESCAPE;
        // ignore trailing whitespces in the value
        value = http_removeTrailing(value);
        // get the field ID, if any
        int id = http_getFieldID(tokens[i]);

        if (http_addField(header, id, tokens[i], value) != WBERR_OK) goto ESCAPE;

        // if is 'content-length' field, get the value
        if (id == WBFI_CONTENT_LENGTH)
            message->body.expected = atoi(value);
        else
        if (id == WBFI_TRANSFER_ENCODING && strstr(value, "chunked"))
            isChunked = 1;
    }
    header->fieldCount = count;

    // check whether chunked transfer encoding is enabled
    if (isChunked && message->body.expected == 0)
        message->body.expected = -1;

    return WBERR_OK;
ESCAPE:
    field = header->fields;
    while (field != NULL)
    {
        next = field->next;
        free(field);
        field = next;
    }
    header->fields = NULL;
    return WBERR_INVALID_HEADER_FIELD;
}
