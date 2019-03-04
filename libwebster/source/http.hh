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
char *http_removeTrailing(
    char *text );

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
