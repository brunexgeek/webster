#ifndef WEBSTER_HTTP_H
#define WEBSTER_HTTP_H


#include <webster/api.h>
#include <stddef.h>
#include <stdint.h>
#include "internal.h"


typedef struct
{
    const char *name;
    int id;
} webster_field_info_t;


WEBSTER_PRIVATE
const char *http_statusMessage(
    int status );

WEBSTER_PRIVATE
webster_field_info_t *http_getFieldID(
    const char *name );

WEBSTER_PRIVATE
webster_field_info_t *http_getFieldName(
    int id );

WEBSTER_PRIVATE
const webster_field_t *http_getFieldById(
    const webster_header_t *header,
    int id );

WEBSTER_PRIVATE
const webster_field_t *http_getFieldByName(
    const webster_header_t *header,
    const char *name );

WEBSTER_PRIVATE
int http_addFieldById(
    webster_header_t *header,
	int id,
    const char *value );

WEBSTER_PRIVATE
int http_addFieldByName(
    webster_header_t *header,
    const char *name,
    const char *value );

WEBSTER_PRIVATE
void http_removeField(
    webster_header_t *header,
    const char *name );

WEBSTER_PRIVATE
void http_releaseFields(
    webster_header_t *header );

WEBSTER_PRIVATE
char *http_removeTrailing(
    char *text );

WEBSTER_PRIVATE
int http_parseHeader(
    char *data,
    struct webster_message_t_ *message );

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

#endif // #ifndef WEBSTER_HTTP_H
