#ifndef WEBSTER_HTTP_H
#define WEBSTER_HTTP_H


#include <webster/api.h>
#include <stddef.h>
#include <stdint.h>
#include "internal.hh"


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
const std::string *http_getField(
    const webster_header_t *header,
    const int id );

WEBSTER_PRIVATE
const std::string *http_getField(
    const webster_header_t *header,
    const std::string &name );

WEBSTER_PRIVATE
int http_addField(
    webster_header_t *header,
	int id,
    const std::string &value );

WEBSTER_PRIVATE
int http_addField(
    webster_header_t *header,
	const std::string &name,
    const std::string &value );

WEBSTER_PRIVATE
int http_removeField(
    webster_header_t *header,
    const std::string &name );

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

WEBSTER_PRIVATE
int http_parseChunk(
    webster_message_t *input );

#endif // #ifndef WEBSTER_HTTP_H
