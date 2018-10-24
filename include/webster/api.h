#ifndef WEBSTER_API_H
#define WEBSTER_API_H


#if BUILDING_WEBSTER && (defined(_MSC_VER) || defined(WIN32) || defined(_WIN32))
#define WEBSTER_EXPORTED __declspec(dllexport)
#elif BUILDING_WEBSTER
#define WEBSTER_EXPORTED __attribute__((__visibility__("default")))
#elif defined(_MSC_VER) || defined(WIN32) || defined(_WIN32)
#define WEBSTER_EXPORTED __declspec(dllimport)
#else
#define WEBSTER_EXPORTED
#endif

#if defined(_MSC_VER) || defined(WIN32) || defined(_WIN32)
#define WEBSTER_PRIVATE
#else
#define WEBSTER_PRIVATE __attribute__((__visibility__("hidden")))
#endif

#include <stdint.h>
#include <stddef.h>


#define WBERR_OK                         0
#define WBERR_INVALID_ARGUMENT           -1
#define WBERR_MEMORY_EXHAUSTED           -2
#define WBERR_INVALID_ADDRESS            -3
#define WBERR_SOCKET                     -4
#define WBERR_NO_CLIENT                  -5
#define WBERR_COMPLETE                   -6
#define WBERR_TOO_LONG                   -7
#define WBERR_NO_DATA                    -9
#define WBERR_BAD_RESPONSE               -10
#define WBERR_TIMEOUT                    -11
#define WBERR_INVALID_STATE              -12
#define WBERR_MAX_CLIENTS                -13
#define WBERR_INVALID_HTTP_METHOD        -14
#define WBERR_INVALID_HEADER_FIELD       -15
#define WBERR_INVALID_HTTP_VERSION       -16
#define WBERR_INVALID_HTTP_MESSAGE       -17
#define WBERR_INVALID_URL                -18

#define WBT_HEADER                       1
#define WBT_BODY                         2
#define WBT_EMPTY                        3

#define WBM_NONE                         0
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

/*#define WBO_UNKNOWN                      0
#define WBO_REQUEST_RESPONSE             1
#define WBO_RESPONSE_REQUEST             2*/

#define WBO_BUFFER_SIZE                  1

#define WBFI_NON_STANDARD                             0
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
#define WBFI_AGE                                      15 // RFC-7234
#define WBFI_ALLOW                                    16
#define WBFI_ALT_SVC                                  17
#define WBFI_AUTHORIZATION                            18
#define WBFI_CACHE_CONTROL                            19
#define WBFI_CONNECTION                               20
#define WBFI_CONTENT_DISPOSITION                      21
#define WBFI_CONTENT_ENCODING                         22
#define WBFI_CONTENT_LANGUAGE                         23
#define WBFI_CONTENT_LENGTH                           24
#define WBFI_CONTENT_LOCATION                         25
#define WBFI_CONTENT_RANGE                            26
#define WBFI_CONTENT_TYPE                             27
#define WBFI_COOKIE                                   28
#define WBFI_DATE                                     29
#define WBFI_DNT                                      30
#define WBFI_ETAG                                     31
#define WBFI_EXPECT                                   32
#define WBFI_EXPIRES                                  33
#define WBFI_FORWARDED                                34
#define WBFI_FROM                                     35
#define WBFI_HOST                                     36
#define WBFI_IF_MATCH                                 37
#define WBFI_IF_MODIFIED_SINCE                        38
#define WBFI_IF_NONE_MATCH                            39
#define WBFI_IF_RANGE                                 40
#define WBFI_IF_UNMODIFIED_SINCE                      41
#define WBFI_LAST_MODIFIED                            42
#define WBFI_LINK                                     43
#define WBFI_LOCATION                                 44
#define WBFI_MAX_FORWARDS                             45
#define WBFI_OPTIONS                                  46
#define WBFI_ORIGIN                                   47
#define WBFI_PRAGMA                                   48
#define WBFI_PROXY_AUTHENTICATE                       49
#define WBFI_PROXY_AUTHORIZATION                      50
#define WBFI_PUBLIC_KEY_PINS                          51
#define WBFI_RANGE                                    52
#define WBFI_REFERER                                  53
#define WBFI_RETRY_AFTER                              54
#define WBFI_SERVER                                   55
#define WBFI_SET_COOKIE                               56
#define WBFI_STRICT_TRANSPORT_SECURITY                57
#define WBFI_TE                                       58
#define WBFI_TK                                       59
#define WBFI_TRAILER                                  60
#define WBFI_TRANSFER_ENCODING                        61
#define WBFI_UPGRADE                                  62
#define WBFI_UPGRADE_INSECURE_REQUESTS                63
#define WBFI_USER_AGENT                               64
#define WBFI_VARY                                     65
#define WBFI_VIA                                      66
#define WBFI_WARNING                                  67
#define WBFI_WWW_AUTHENTICATE                         68

#define WBP_HTTP         1
#define WBP_HTTPS        2

#define WB_IS_VALID_METHOD(x)  ( (x) >= WBM_GET && (x) <= WBM_TRACE )

struct webster_server_t_;
typedef struct webster_server_t_ *webster_server_t;

struct webster_client_t_;
typedef struct webster_client_t_ *webster_client_t;

struct webster_message_t_;
typedef struct webster_message_t_ webster_message_t;

typedef struct webster_field_t_
{
    int id;
    char *name;
    char *value;
    struct webster_field_t_ *next;
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
    char *query;
    char *message;
    int status;
    int method;
    int contentLength;
    webster_field_t *fields;
    int fieldCount;
} webster_header_t;

typedef int (webster_handler_t)(
    webster_message_t *request,
    webster_message_t *response,
    void *data );


typedef struct
{
    void *(*malloc)(size_t size);
    void *(*calloc)(size_t count, size_t size);
    void (*free)(void *ptr);
} webster_memory_t;


typedef int webster_network_initialize(
    webster_memory_t *memory );

typedef int webster_network_terminate();

typedef int webster_network_open(
	void **channel );

typedef int webster_network_close(
	void *channel );

typedef int webster_network_connect(
	void *channel,
	const char *host,
    int port );

typedef int webster_network_receive(
	void *channel,
	uint8_t *buffer,
    uint32_t *size,
	int timeout );

typedef int webster_network_send(
	void *channel,
	const uint8_t *buffer,
    uint32_t size );

typedef int webster_network_accept(
	void *channel,
	void **client );

typedef int webster_network_listen(
	void *channel,
	const char *host,
    int port,
	int maxClients );

typedef struct
{
    webster_network_initialize *initialize;
    webster_network_terminate *terminate;
	webster_network_open *open;
	webster_network_close *close;
	webster_network_connect *connect;
	webster_network_receive *receive;
	webster_network_send *send;
	webster_network_accept *accept;
	webster_network_listen *listen;
} webster_network_t;


#ifdef __cplusplus
extern "C" {
#endif


WEBSTER_EXPORTED int WebsterInitialize(
    webster_memory_t *mem,
	webster_network_t *net );

WEBSTER_EXPORTED int WebsterTerminate();

WEBSTER_EXPORTED int WebsterParseURL(
    const char *url,
    int *proto,
    char **host,
    int *port,
    char **resource );

/*
 * HTTP client API
 */

WEBSTER_EXPORTED int WebsterConnect(
    webster_client_t *client,
    const char *host,
    int port,
    const char *resource );

WEBSTER_EXPORTED int WebsterCommunicate(
    webster_client_t *client,
    webster_handler_t *callback,
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
	webster_client_t *remote );

WEBSTER_EXPORTED int WebsterSetOption(
	webster_server_t *server,
    int option,
    int value );

WEBSTER_EXPORTED int WebsterGetOption(
	webster_server_t *server,
    int option,
    int *value );


/*
 * Request and response API
 */

WEBSTER_EXPORTED int WebsterWaitEvent(
    webster_message_t *input,
    webster_event_t *event );

WEBSTER_EXPORTED int WebsterGetHeader(
    webster_message_t *input,
    const webster_header_t **header );

WEBSTER_EXPORTED int WebsterGetStringField(
    webster_message_t *input,
    int id,
    const char *name,
    const char **value );

WEBSTER_EXPORTED int WebsterGetIntegerField(
    webster_message_t *input,
    int id,
    const char *name,
    int *value );

WEBSTER_EXPORTED int WebsterReadData(
    webster_message_t *input,
    const uint8_t **buffer,
    int *size );

WEBSTER_EXPORTED int WebsterReadString(
    webster_message_t *input,
    const char **buffer );

WEBSTER_EXPORTED int WebsterGetInputState(
	webster_message_t *input,
    int *state );

WEBSTER_EXPORTED int WebsterSetStatus(
    webster_message_t *output,
    int status );

WEBSTER_EXPORTED int WebsterSetMethod(
    webster_message_t *output,
    int method );

WEBSTER_EXPORTED int WebsterSetStringField(
    webster_message_t *output,
    const char *name,
    const char *value );

WEBSTER_EXPORTED int WebsterSetIntegerField(
    webster_message_t *output,
    const char *name,
    int value );

// TODO: must fail if writing more data it's supposed to (content-length)
WEBSTER_EXPORTED int WebsterWriteData(
    webster_message_t *output,
    const uint8_t *buffer,
    int size );
// TODO: must fail if writing more data it's supposed to (content-length)
WEBSTER_EXPORTED int WebsterWriteString(
    webster_message_t *output,
    const char *text );

WEBSTER_EXPORTED int WebsterFlush(
	webster_message_t *output );

WEBSTER_EXPORTED int WebsterFinish(
	webster_message_t *output );

WEBSTER_EXPORTED int WebsterGetOutputState(
	webster_message_t *output,
    int *state );


#ifdef __cplusplus
}
#endif


#endif // WEBSTER_API_H