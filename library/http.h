#ifndef WEBSTER_HTTP_H
#define WEBSTER_HTTP_H


#include <webster/api.h>
#include <stddef.h>
#include <stdint.h>


#define HTTP_MAX_HEADER       (4 * 1024)


const char *http_statusMessage(
    int status );


int http_parseHeader(
    char *data,
	webster_header_t *header,
    int *contentLength );


#endif // #ifndef WEBSTER_HTTP_H