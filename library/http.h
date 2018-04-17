#ifndef WEBSTER_HTTP_H
#define WEBSTER_HTTP_H


#include <stddef.h>
#include <stdint.h>


#define HTTP_MAX_HEADER       (4 * 1024)


typedef struct 
{
    const char *name;
    const char *value;    
} http_field_t;


typedef struct
{
    char data[HTTP_MAX_HEADER];

    int status;

    int method;

    /**
     * Resource URI. This variable point to @c start memory.
     */
    char *resource;

    /**
     * Array of header fields. Name and value for each field point to
     * @c data memory.
     */
    http_field_t *fields;

    /**
     * Number of entries in @c fields array.
     */
    int count;
} http_header_t;


const char *http_statusMessage(
    int status );


int http_parseHeader(
	http_header_t *header,
    uint32_t *contentLength );


#endif // #ifndef WEBSTER_HTTP_H