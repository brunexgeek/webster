#ifndef WEBSTER_API_H
#define WEBSTER_API_H


#if BUILDING_WEBSTER && defined(_MSC_VER)
#define WEBSTER_EXPORTED __declspec(dllexport)
#elif BUILDING_WEBSTER
#define WEBSTER_EXPORTED __attribute__((__visibility__("default")))
#elif defined(_MSC_VER)
#define WEBSTER_EXPORTED __declspec(dllimport)
#else
#define WEBSTER_EXPORTED
#endif


#include <stdint.h>


#define WBERR_OK                         0
#define WBERR_INVALID_ARGUMENT           1
#define WBERR_MEMORY_EXHAUSTED           2
#define WBERR_INVALID_ADDRESS            3
#define WBERR_SOCKET                     4
#define WBERR_NO_CLIENT                  5
#define WBERR_COMPLETE                   6
#define WBERR_TOO_LONG                   7
#define WBERR_BAD_REQUEST                8
#define WBERR_NO_DATA                    9
#define WBERR_BAD_RESPONSE               10
#define WBERR_TIMEOUT                    11

#define WBT_HEADER                   1
#define WBT_BODY                     2
#define WBT_EMPTY                    3

#define WBM_GET                          1
#define WBM_HEAD                         2
#define WBM_POST                         3
#define WBM_PUT                          4
#define WBM_DELETE                       5
#define WBM_CONNECT                      6
#define WBM_OPTIONS                      7
#define WBM_TRACE                        8

#define WBO_BUFFER_SIZE                  1

struct webster_server_t_;
typedef struct webster_server_t_ *webster_server_t;

struct webster_client_t_;
typedef struct webster_client_t_ *webster_client_t;

struct webster_input_t_;
typedef struct webster_input_t_ webster_input_t;

struct webster_output_t_;
typedef struct webster_output_t_ webster_output_t;

typedef struct
{
    char *name;
    char *value;
} webster_field_t;

typedef struct
{
    /**
     * Event type.
     */
    int type;

    /**
     * Size of the payload.
     */
    int size;
} webster_event_t;

typedef struct
{
    char *resource;
    char *message;
    int status;
    int method;
    int contentLength;
    webster_field_t *fields;
    int fieldCount;
} webster_header_t;

typedef int (webster_handler_t)(
    webster_input_t *request,
    webster_output_t *response,
    void *data );

typedef int (webster_callback_t)(
    webster_output_t *request,
    webster_input_t *response,
    void *data );


#ifdef __cplusplus
extern "C" {
#endif


WEBSTER_EXPORTED int WebsterCreate(
    webster_server_t *server,
    int maxClients );

WEBSTER_EXPORTED int WebsterDestroy(
    webster_server_t *server );

WEBSTER_EXPORTED int WebsterConnect(
    webster_client_t *client,
    const char *host,
    int port );

WEBSTER_EXPORTED int WebsterCommunicate(
    webster_client_t *client,
    webster_callback_t *callback,
    void *data );

WEBSTER_EXPORTED int WebsterDisconnect(
    webster_client_t *client );

WEBSTER_EXPORTED int WebsterStart(
    webster_server_t *server,
    const char *host,
    int port );

WEBSTER_EXPORTED int WebsterStop(
    webster_server_t *server );

WEBSTER_EXPORTED int WebsterAccept(
    webster_server_t *server,
    webster_handler_t *handler,
    void *data );

WEBSTER_EXPORTED int WebsterWaitEvent(
    webster_input_t *input,
    webster_event_t *event );

WEBSTER_EXPORTED int WebsterGetHeader(
    webster_input_t *input,
    const webster_header_t **header );

WEBSTER_EXPORTED int WebsterReadData(
    webster_input_t *input,
    const uint8_t **buffer,
    int *size );

WEBSTER_EXPORTED int WebsterReadString(
    webster_input_t *input,
    const char **buffer );

WEBSTER_EXPORTED int WebsterSetStatus(
    webster_output_t *output,
    int status );

WEBSTER_EXPORTED int WebsterWriteField(
    webster_output_t *output,
    const char *name,
    const char *value );

WEBSTER_EXPORTED int WebsterWriteIntField(
    webster_output_t *output,
    const char *name,
    int value );

// TODO: must fail if writing more data it's supposed to (content-length)
WEBSTER_EXPORTED int WebsterWriteData(
    webster_output_t *output,
    const uint8_t *buffer,
    int size );
// TODO: must fail if writing more data it's supposed to (content-length)
WEBSTER_EXPORTED int WebsterWriteString(
    webster_output_t *output,
    const char *text );

WEBSTER_EXPORTED int WebsterFlush(
	webster_output_t *output );

WEBSTER_EXPORTED int WebsterSetOption(
	webster_server_t *server,
    int option,
    int value );

WEBSTER_EXPORTED int WebsterGetOption(
	webster_server_t *server,
    int option,
    int *value );

#ifdef __cplusplus
}
#endif


#endif // WEBSTER_API_H