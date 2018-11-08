#include "http.h"
#include "internal.h"
#include <string.h>
#include <webster/api.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>


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


extern webster_memory_t memory;


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


static char *cloneString(
    const char *text )
{
    if (text == NULL) return NULL;
    size_t len = strlen(text);
    char *output = memory.malloc(len + 1);
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

    char *output = memory.malloc(length + 1);
    if (output == NULL) return NULL;
    memcpy(output, text + offset, length);
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

#if 1

webster_field_info_t *http_getFieldID(
    const char *name )
{
	if (name == NULL || name[0] == 0) return NULL;

	int first = 0;
    int last = sizeof(HTTP_HEADER_FIELDS) / sizeof(webster_field_info_t) - 1;

    while (first <= last)
	{
		int current = (first + last) / 2;
		int dir = strcmp(name, HTTP_HEADER_FIELDS[current].name);
		if (dir == 0) return &HTTP_HEADER_FIELDS[current];
		if (dir < 0)
			last = current - 1;
		else
			first = current + 1;
	}

	return NULL;
}


webster_field_info_t *http_getFieldName(
    int id )
{
	if (id == WBFI_NON_STANDARD) return NULL;

	int first = 0;
    int last = sizeof(HTTP_HEADER_FIELDS) / sizeof(webster_field_info_t) - 1;

    while (first <= last)
	{
		int current = (first + last) / 2;
		if (id == HTTP_HEADER_FIELDS[current].id)
            return &HTTP_HEADER_FIELDS[current];
		if (id < HTTP_HEADER_FIELDS[current].id)
			last = current - 1;
		else
			first = current + 1;
	}

	return WBFI_NON_STANDARD;
}


#else
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
#endif

const webster_field_t *http_getFieldByName(
    const webster_header_t *header,
    const char *name )
{
    webster_field_t *field = header->fields;
    while (field != NULL)
    {
        if (strcmp(field->name, name) == 0) return field;
        field = field->next;
    }

    return NULL;
}


const webster_field_t *http_getFieldById(
    const webster_header_t *header,
    int id )
{
    webster_field_t *field = header->fields;
    while (field != NULL)
    {
        if (field->id == id) return field;
        field = field->next;
    }

    return NULL;
}


int http_addFieldById(
    webster_header_t *header,
	int id,
    const char *value )
{
    if (header == NULL || value == NULL)
        return WBERR_INVALID_ARGUMENT;
    if (header->fieldCount >= WBL_MAX_FIELDS)
        return WBERR_TOO_MANY_FIELDS;

    webster_field_info_t *finfo = http_getFieldName(id);
    if (finfo == NULL) return WBERR_INVALID_ARGUMENT;

    // allocate memory for the field
	size_t size = sizeof(webster_field_t) + strlen(value) + 1;
	webster_field_t *field = (webster_field_t*) memory.calloc(1, size);
	if (field == NULL) return WBERR_MEMORY_EXHAUSTED;
    field->value = (char*) field + sizeof(webster_field_t);
    // fill field information
	field->id = id;
    field->name = finfo->name;
    field->next = NULL;
	strcpy((char*)field->value, value);

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

// TODO: ensure the field does not exists
int http_addFieldByName(
    webster_header_t *header,
    const char *name,
    const char *value )
{
    if (name == NULL || value == NULL || header == NULL)
        return WBERR_INVALID_ARGUMENT;
    if (header->fieldCount >= WBL_MAX_FIELDS)
        return WBERR_TOO_MANY_FIELDS;

    size_t nameLen  = strlen(name);
    size_t valueLen = strlen(value);
    if (nameLen > WBL_MAX_FIELD_NAME)
        return WBERR_INVALID_ARGUMENT;

    // allocate memory for the field
	webster_field_t *field = (webster_field_t*) memory.calloc(1,
        nameLen + 1 + valueLen + 1 + sizeof(webster_header_t));
	if (field == NULL) return WBERR_MEMORY_EXHAUSTED;
    field->value = (char*) field + sizeof(webster_field_t);
    field->name  = field->value + valueLen + 1;

    // fill field information
    field->id = WBFI_NON_STANDARD;
    field->next = NULL;
    strncpy((char*) field->value, value, valueLen);
    strncpy((char*) field->name, name, nameLen);
    for (char *p = (char*) field->name; *p; ++p)
    {
        if (!IS_HFNC(*p))
        {
            memory.free(field);
            return WBERR_INVALID_ARGUMENT;
        }
        *p = (char) tolower(*p);
    }

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


void http_removeField(
    webster_header_t *header,
    const char *name )
{
    webster_field_t *prev = NULL;
    webster_field_t *field = header->fields;
    while (field != NULL)
    {
        if (strcmp(field->name, name) == 0) break;
        prev = field;
        field = field->next;
    }

    if (field == NULL) return;
    if (prev == NULL)
        header->fields = field->next;
    else
        prev->next = field->next;
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
        memory.free(ptr);
    }
    header->fields = NULL;
    header->fieldCount = 0;
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


#define STATE_FIRST_LINE     1
#define STATE_HEADER_FIELD   2
#define STATE_COMPLETE       3


int http_parseTarget(
    const char *url,
    webster_target_t **output )
{
    if (url == NULL || url[0] == 0 || output == NULL) return WBERR_INVALID_URL;

    // TODO: change to make an allocation for all fields
    *output = memory.calloc(1, sizeof(webster_target_t));
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
            target->origin.path = subString(url, 0, pos);
            target->origin.query = subString(url, pos + 1, strlen(url) - pos - 1);
        }
        else
        {
            target->origin.path = cloneString(url);
        }

        http_decodeUrl(target->origin.path);
        http_decodeUrl(target->origin.query);
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
		char *hb = strstr(url, "://");
		if (hb == NULL) return WBERR_INVALID_URL;
		hb += 3;
		char *he = hb;
		while (*he != ':' && *he != '/' && *he != 0) ++he;
		if (hb == he) return WBERR_INVALID_URL;

		char *rb = he;
		char *re = NULL;

		// extract the port number, if any
		char *pb = he;
		char *pe = NULL;
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
			target->absolute.scheme = WBP_HTTP;
		else
			target->absolute.scheme = WBP_HTTPS;

		// return the port number, if any
		if (pe != NULL)
		{
			target->absolute.port = 0;
			int mult = 1;
			while (--pe >= pb)
			{
				target->absolute.port += (int) (*pe - '0') * mult;
				mult *= 10;
			}
			if (target->absolute.port > 65535 || target->authority.port < 0)
                return WBERR_INVALID_URL;
		}
		else
		{
			if (target->absolute.scheme == WBP_HTTP)
				target->absolute.port = 80;
			else
				target->absolute.port = 443;
		}

		// return the host
        target->absolute.host = subString(hb, 0, (size_t) (he - hb));

		// return the resource, if any
		if (re != NULL)
			target->absolute.path = subString(rb, 0, (size_t) (re - rb));
		else
			target->absolute.path = cloneString("/");

		http_decodeUrl(target->absolute.path);
        http_decodeUrl(target->absolute.query);
	}
    else
    // handle authority form
    {
        target->type = WBRT_AUTHORITY;

        const char *hb = strchr(url, '@');
        if (hb != NULL)
        {
            target->authority.user = subString(url, 0, (size_t) (hb - url));
            hb++;
        }
        else
            hb = url;

        const char *he = strchr(hb, ':');
        if (he != NULL)
        {
            target->authority.host = subString(hb, 0, (size_t) (he - hb));
            target->authority.port = 0;

            const char *pb = he + 1;
            const char *pe = pb;
            while (*pe >= '0' && *pe <= '9' && *pe != 0) ++pe;
            if (*pe != 0) return WBERR_INVALID_URL;

			int mult = 1;
			while (--pe >= pb)
			{
				target->authority.port += (int) (*pe - '0') * mult;
				mult *= 10;
			}
			if (target->authority.port > 65535 || target->authority.port < 0)
                return WBERR_INVALID_URL;
        }
        else
        {
            target->authority.host = cloneString(hb);
            target->authority.port = 80;
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
            if (target->origin.path != NULL)
                memory.free(target->origin.path);
            if (target->origin.query != NULL)
                memory.free(target->origin.query);
            break;

        case WBRT_ABSOLUTE:
            if (target->absolute.user != NULL)
                memory.free(target->absolute.user);
            if (target->absolute.host != NULL)
                memory.free(target->absolute.host);
            if (target->absolute.path != NULL)
                memory.free(target->absolute.path);
            if (target->absolute.query != NULL)
                memory.free(target->absolute.query);
            break;

        case WBRT_AUTHORITY:
            if (target->authority.user != NULL)
                memory.free(target->authority.user);
            if (target->authority.host != NULL)
                memory.free(target->authority.host);
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
    int state = STATE_FIRST_LINE;
    char *ptr = data;
    char *token = ptr;
    int result;
    int isChunked = 0;

    webster_header_t *header = &message->header;
    header->fieldCount = 0;
    message->body.expected = 0;

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
            webster_field_info_t *finfo = http_getFieldID(name);
            if (finfo != NULL)
            {
                http_addFieldById(header, finfo->id, value);

                // if is 'content-length' field, get the value
                if (finfo->id == WBFI_CONTENT_LENGTH)
                    message->body.expected = atoi(value);
                else
                if (finfo->id == WBFI_TRANSFER_ENCODING && strstr(value, "chunked"))
                    isChunked = 1;
            }
            else
                http_addFieldByName(header, name, value);

            header->fieldCount++;
        }
        else
            break;
    }

    // check whether chunked transfer encoding is enabled
    if (isChunked && message->body.expected == 0)
        message->body.expected = -1;

    return WBERR_OK;
}
