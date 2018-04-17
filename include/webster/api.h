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

#define WB_TYPE_HEADER                   1
#define WB_TYPE_BODY                     2
#define WB_TYPE_EMPTY                    3

#define WB_METHOD_GET                    1
#define WB_METHOD_HEAD                   2
#define WB_METHOD_POST                   3
#define WB_METHOD_PUT                    4
#define WB_METHOD_DELETE                 5
#define WB_METHOD_CONNECT                6
#define WB_METHOD_OPTIONS                7
#define WB_METHOD_TRACE                  8


struct webster_server_t_;
typedef struct webster_server_t_ *webster_server_t;

struct webster_client_t_;
typedef struct webster_client_t_ *webster_client_t;

struct webster_input_t_;
typedef struct webster_input_t_ webster_input_t;

struct webster_output_t_;
typedef struct webster_output_t_ webster_output_t;

typedef struct webster_header_t_
{
    const char *name;
    const char *value;
} webster_field_t;

typedef int (webster_handler_t)(
    webster_input_t *request,
    webster_output_t *response,
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

WEBSTER_EXPORTED int WebsterDisconnect(
    webster_client_t *client );

WEBSTER_EXPORTED int WebsterStart(
    webster_server_t *server,
    const char *host,
    int port );

WEBSTER_EXPORTED int WebsterStop(
    webster_server_t *server );

WEBSTER_EXPORTED int WebsterSetHandler(
    webster_server_t *server,
    const char* mime,
    webster_handler_t *handler );

WEBSTER_EXPORTED int WebsterAccept(
    webster_server_t *server,
    void *data );

WEBSTER_EXPORTED int WebsterWait(
    webster_input_t *input,
    int *type,
    int *size );

WEBSTER_EXPORTED int WebsterGetHeaderFields(
    webster_input_t *input,
    const webster_field_t **fields,
    int *count );

WEBSTER_EXPORTED int WebsterGetData(
    webster_input_t *input,
    const uint8_t **buffer,
    int *size );

WEBSTER_EXPORTED int WebsterSetStatus(
    webster_output_t *output,
    int status );

WEBSTER_EXPORTED int WebsterWriteHeaderField(
    webster_output_t *output,
    const char *name,
    const char *value );

WEBSTER_EXPORTED int WebsterWriteData(
    webster_output_t *output,
    const uint8_t *buffer,
    int size );

WEBSTER_EXPORTED int WebsterWriteString(
    webster_output_t *output,
    const char *format,
    ... );

WEBSTER_EXPORTED int WebsterFree(
    void *ptr );

#ifdef __cplusplus
}
#endif


#endif // WEBSTER_API_H