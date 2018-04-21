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
#define WBERR_INVALID_STATE              12

#define WBT_HEADER                       1
#define WBT_BODY                         2
#define WBT_EMPTY                        3

#define WBM_GET                          1
#define WBM_HEAD                         2
#define WBM_POST                         3
#define WBM_PUT                          4
#define WBM_DELETE                       5
#define WBM_CONNECT                      6
#define WBM_OPTIONS                      7
#define WBM_TRACE                        8

#define WBS_IDLE                         0
#define WBS_HEADER                       1
#define WBS_BODY                         2
#define WBS_COMPLETE                     3

#define WBO_BUFFER_SIZE                  1

#define WBFI_ACCEPT                                   1
#define WBFI_ACCEPT_CHARSET                           2
#define WBFI_ACCEPT_ENCODING                          3
#define WBFI_ACCEPT_LANGUAGE                          4
#define WBFI_ACCEPT_PATCH                             5
#define WBFI_ACCEPT_RANGES                            6
#define WBFI_ACCESS_CONTROL_ALLOW_CREDENTIALS         7
#define WBFI_ACCESS_CONTROL_ALLOW_HEADERS             8
#define WBFI_ACCESS_CONTROL_ALLOW_METHODS             9
#define WBFI_ACCESS_CONTROL_ALLOW_ORIGIN              10
#define WBFI_ACCESS_CONTROL_EXPOSE_HEADERS            11
#define WBFI_ACCESS_CONTROL_MAX_AGE                   12
#define WBFI_ACCESS_CONTROL_REQUEST_HEADERS           13
#define WBFI_ACCESS_CONTROL_REQUEST_METHOD            14
#define WBFI_AGE                                      15
#define WBFI_ALLOW                                    16
#define WBFI_ALT_SVC                                  17
#define WBFI_AUTHORIZATION                            18
#define WBFI_CACHE_CONTROL                            19
#define WBFI_CONNECT                                  20
#define WBFI_CONNECTION                               21
#define WBFI_CONTENT_DISPOSITION                      23
#define WBFI_CONTENT_ENCODING                         24
#define WBFI_CONTENT_LANGUAGE                         25
#define WBFI_CONTENT_LENGTH                           26
#define WBFI_CONTENT_LOCATION                         27
#define WBFI_CONTENT_RANGE                            28
#define WBFI_CONTENT_TYPE                             29
#define WBFI_COOKIE                                   30
#define WBFI_DATE                                     31
#define WBFI_DNT                                      32
#define WBFI_ETAG                                     33
#define WBFI_EXPECT                                   34
#define WBFI_EXPIRES                                  35
#define WBFI_FORWARDED                                36
#define WBFI_FROM                                     37
#define WBFI_HOST                                     38
#define WBFI_IF_MATCH                                 39
#define WBFI_IF_MODIFIED_SINCE                        40
#define WBFI_IF_NONE_MATCH                            41
#define WBFI_IF_RANGE                                 42
#define WBFI_IF_UNMODIFIED_SINCE                      43
#define WBFI_LAST_MODIFIED                            44
#define WBFI_LINK                                     45
#define WBFI_LOCATION                                 46
#define WBFI_MAX_FORWARDS                             47
#define WBFI_OPTIONS                                  48
#define WBFI_ORIGIN                                   49
#define WBFI_PRAGMA                                   50
#define WBFI_PROXY_AUTHENTICATE                       51
#define WBFI_PROXY_AUTHORIZATION                      52
#define WBFI_PUBLIC_KEY_PINS                          53
#define WBFI_RANGE                                    54
#define WBFI_REFERER                                  55
#define WBFI_RETRY_AFTER                              56
#define WBFI_SET_COOKIE                               57
#define WBFI_STRICT_TRANSPORT_SECURITY                58
#define WBFI_TE                                       59
#define WBFI_TK                                       60
#define WBFI_TRAILER                                  61
#define WBFI_TRANSFER_ENCODING                        62
#define WBFI_UPGRADE                                  63
#define WBFI_UPGRADE_INSECURE_REQUESTS                64
#define WBFI_USER_AGENT                               65
#define WBFI_VARY                                     66
#define WBFI_VIA                                      67
#define WBFI_WARNING                                  68
#define WBFI_WWW_AUTHENTICATE                         69


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
    int id;
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

/*
 * HTTP client API
 */


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


/*
 * HTTP server API
 */


WEBSTER_EXPORTED int WebsterCreate(
    webster_server_t *server,
    int maxClients );

WEBSTER_EXPORTED int WebsterDestroy(
    webster_server_t *server );

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


/*
 * Request and response API
 */

WEBSTER_EXPORTED int WebsterWaitEvent(
    webster_input_t *input,
    webster_event_t *event );

WEBSTER_EXPORTED int WebsterGetHeader(
    webster_input_t *input,
    const webster_header_t **header );

WEBSTER_EXPORTED int WebsterGetStrField(
    webster_input_t *input,
    const char *name,
    int fieldId,
    const char **value );

WEBSTER_EXPORTED int WebsterGetIntField(
    webster_input_t *input,
    const char *name,
    int fieldId,
    int *value );

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

WEBSTER_EXPORTED int WebsterGetInputState(
	webster_input_t *input,
    int *state );

WEBSTER_EXPORTED int WebsterGetOutputState(
	webster_output_t *output,
    int *state );

#ifdef __cplusplus
}
#endif


#endif // WEBSTER_API_H