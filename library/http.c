#include "http.h"
#include <string.h>
#include <webster/api.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>


struct http_status_t {
    int status;
    const char *message;
};


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


static char *http_removeTrailing(
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
    http_header_t *header,
    uint32_t *contentLength )
{
    char *ptr = NULL;
    char *tokens[128];

    // reset content length
    *contentLength = 0;

    int count = tokenize((char*) header->data, " \n", '\n', tokens, 8);
    if (count != 3) return WBERR_BAD_REQUEST;

    if (strcmp(tokens[2], "HTTP/1.1") != 0) return WBERR_BAD_REQUEST;

    for (char *p = tokens[0]; *p; ++p) *p = (char) tolower(*p);

    if (strcmp(tokens[0], "get") == 0)
        header->method = WB_METHOD_GET;
    else
    if (strcmp(tokens[0], "post") == 0)
        header->method = WB_METHOD_POST;
    else
    if (strcmp(tokens[0], "head") == 0)
        header->method = WB_METHOD_HEAD;
    else
    if (strcmp(tokens[0], "put") == 0)
        header->method = WB_METHOD_PUT;
    else
    if (strcmp(tokens[0], "delete") == 0)
        header->method = WB_METHOD_DELETE;
    else
    if (strcmp(tokens[0], "connect") == 0)
        header->method = WB_METHOD_CONNECT;
    else
    if (strcmp(tokens[0], "options") == 0)
        header->method = WB_METHOD_OPTIONS;
    else
    if (strcmp(tokens[0], "trace") == 0)
        header->method = WB_METHOD_TRACE;

    header->resource = tokens[1];

    // point to the first field
    ptr = tokens[2] + 9;
    if (*ptr == 0) ++ptr;
    // parse up to 128 fields
    count = tokenize(ptr, "\n", 0, tokens, 128);
    if (count == 0) return WBERR_BAD_REQUEST;
    // allocate memory for the field array
    header->fields = (http_field_t*) calloc( (size_t) count, sizeof(http_field_t) );
    if (header->fields == NULL) return WBERR_MEMORY_EXHAUSTED;

    for (int i = 0; i < count; ++i)
    {
        char *half = strchr(tokens[i], ':');

        if (half == NULL || *tokens[i] == ' ' || half <= tokens[i] || *(half-1) == ' ')
        {
            free(header->fields);
            header->fields = NULL;
            return WBERR_BAD_REQUEST;
        }

        // split the line in half
        *half = 0;
        header->fields[i].name = tokens[i];
        header->fields[i].value = half + 1;
        // ignore trailing whitespces
        header->fields[i].name = http_removeTrailing(header->fields[i].name);
        header->fields[i].value = http_removeTrailing(header->fields[i].value);
        // change the field name to lowercase
        for (char *p = tokens[i]; *p; ++p) *p = (char) tolower(*p);

        // if is 'content-length' field, get the value
        if (strcmp(header->fields[i].name, "content-length") == 0)
            *contentLength = (uint32_t) atoi(header->fields[i].value);
    }

    header->count = count;

    return WBERR_OK;
}