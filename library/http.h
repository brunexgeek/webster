#ifndef WEBSTER_HTTP_H
#define WEBSTER_HTTP_H


#include <webster/api.h>
#include <stddef.h>
#include <stdint.h>
#include "internal.h"


#define HTTP_MAX_HEADER       (4 * 1024)


const char *http_statusMessage(
    int status );

int http_getFieldID(
    const char *name );

const webster_field_t *http_getFieldById(
    const webster_header_t *header,
    int id );

const webster_field_t *http_getFieldByName(
    const webster_header_t *header,
    const char *name );

int http_addField(
    webster_header_t *header,
    int id,
	const char *name,
    const char *value );

void http_releaseFields(
    webster_header_t *header );

char *http_removeTrailing(
    char *text );

int http_parseHeader(
    char *data,
    struct webster_message_t_ *message );


#endif // #ifndef WEBSTER_HTTP_H