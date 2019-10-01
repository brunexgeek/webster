#ifndef WEBSTER_API_H
#define WEBSTER_API_H


#if BUILDING_WEBSTER && BUILDING_DYNAMIC && (defined(_MSC_VER) || defined(WIN32) || defined(_WIN32))
#define WEBSTER_EXPORTED __declspec(dllexport)
#elif BUILDING_WEBSTER && BUILDING_DYNAMIC
#define WEBSTER_EXPORTED __attribute__((__visibility__("default")))
#elif defined(_MSC_VER) || defined(WIN32) || defined(_WIN32)
#define WEBSTER_EXPORTED
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
#define WBERR_INVALID_SCHEME             -19
#define WBERR_INVALID_HOST               -20
#define WBERR_INVALID_PORT               -21
#define WBERR_INVALID_CHANNEL            -22
#define WBERR_INVALID_RESOURCE           -23
#define WBERR_INVALID_CLIENT             -24
#define WBERR_INVALID_SERVER             -25
#define WBERR_INVALID_MESSAGE            -26
#define WBERR_TOO_MANY_FIELDS            -27
#define WBERR_INVALID_CHUNK              -28
#define WBERR_NOT_CONNECTED              -29
#define WBERR_SIGNAL                     -30

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
#define WBM_PATCH                        9

#define WBS_IDLE                         0
#define WBS_HEADER                       1
#define WBS_BODY                         2
#define WBS_COMPLETE                     3

#define WBO_BUFFER_SIZE                  1

#define WBFI_NON_STANDARD                               0
#define WBFI_ACCEPT                                    10
#define WBFI_ACCEPT_CHARSET                            20
#define WBFI_ACCEPT_ENCODING                           30
#define WBFI_ACCEPT_LANGUAGE                           40
#define WBFI_ACCEPT_PATCH                              50
#define WBFI_ACCEPT_RANGES                             60
#define WBFI_ACCESS_CONTROL_ALLOW_CREDENTIALS          70
#define WBFI_ACCESS_CONTROL_ALLOW_HEADERS              80
#define WBFI_ACCESS_CONTROL_ALLOW_METHODS              90
#define WBFI_ACCESS_CONTROL_ALLOW_ORIGIN              100
#define WBFI_ACCESS_CONTROL_EXPOSE_HEADERS            110
#define WBFI_ACCESS_CONTROL_MAX_AGE                   120
#define WBFI_ACCESS_CONTROL_REQUEST_HEADERS           130
#define WBFI_ACCESS_CONTROL_REQUEST_METHOD            140
#define WBFI_AGE                                      150 // RFC-7234
#define WBFI_ALLOW                                    160
#define WBFI_ALT_SVC                                  170
#define WBFI_AUTHORIZATION                            180
#define WBFI_CACHE_CONTROL                            190
#define WBFI_CONNECTION                               200
#define WBFI_CONTENT_DISPOSITION                      210
#define WBFI_CONTENT_ENCODING                         220
#define WBFI_CONTENT_LANGUAGE                         230
#define WBFI_CONTENT_LENGTH                           240
#define WBFI_CONTENT_LOCATION                         250
#define WBFI_CONTENT_RANGE                            260
#define WBFI_CONTENT_TYPE                             270
#define WBFI_COOKIE                                   280
#define WBFI_DATE                                     290
#define WBFI_DNT                                      300
#define WBFI_ETAG                                     310
#define WBFI_EXPECT                                   320
#define WBFI_EXPIRES                                  330
#define WBFI_FORWARDED                                340
#define WBFI_FROM                                     350
#define WBFI_HOST                                     360
#define WBFI_IF_MATCH                                 370
#define WBFI_IF_MODIFIED_SINCE                        380
#define WBFI_IF_NONE_MATCH                            390
#define WBFI_IF_RANGE                                 400
#define WBFI_IF_UNMODIFIED_SINCE                      410
#define WBFI_LAST_MODIFIED                            420
#define WBFI_LINK                                     430
#define WBFI_LOCATION                                 440
#define WBFI_MAX_FORWARDS                             450
#define WBFI_ORIGIN                                   470
#define WBFI_PRAGMA                                   480
#define WBFI_PROXY_AUTHENTICATE                       490
#define WBFI_PROXY_AUTHORIZATION                      500
#define WBFI_PUBLIC_KEY_PINS                          510
#define WBFI_RANGE                                    520
#define WBFI_REFERER                                  530
#define WBFI_RETRY_AFTER                              540
#define WBFI_SERVER                                   550
#define WBFI_SET_COOKIE                               560
#define WBFI_STRICT_TRANSPORT_SECURITY                570
#define WBFI_TE                                       580
#define WBFI_TK                                       590
#define WBFI_TRAILER                                  600
#define WBFI_TRANSFER_ENCODING                        610
#define WBFI_UPGRADE                                  620
#define WBFI_UPGRADE_INSECURE_REQUESTS                630
#define WBFI_USER_AGENT                               640
#define WBFI_VARY                                     650
#define WBFI_VIA                                      660
#define WBFI_WARNING                                  670
#define WBFI_WWW_AUTHENTICATE                         680

#define WBRT_ORIGIN      1
#define WBRT_ABSOLUTE    2
#define WBRT_AUTHORITY   3
#define WBRT_ASTERISK    4

#define WBP_HTTP         1
#define WBP_HTTPS        2

#define WB_IS_VALID_METHOD(x)  ( (x) >= WBM_GET && (x) <= WBM_PATCH )
#define WB_IS_VALID_SCHEME(x)  ( (x) == WBP_HTTP || (x) == WBP_HTTPS )
#define WB_IS_VALID_URL(x)     ( (x) >= WBRT_ORIGIN && (x) <= WBRT_ASTERISK )

#define WBL_MAX_FIELD_NAME     128
#define WBL_MAX_FIELD_VALUE    4096
#define WBL_MAX_FIELDS         128
#define WBL_MAX_HOST_NAME      255
#define WBL_MIN_BUFFER_SIZE    128
#define WBL_MAX_BUFFER_SIZE    (10 * 1024 * 1024)
#define WBL_DEF_BUFFER_SIZE    (1024 * 4) // 4KB
#define WBL_MAX_CONNECTIONS    1000
#define WBL_DEF_CONNECTIONS    200
#define WBL_READ_TIMEOUT       10000


struct webster_server_t_;
typedef struct webster_server_t_ webster_server_t;

struct webster_client_t_;
typedef struct webster_client_t_ webster_client_t;

struct webster_message_t_;
typedef struct webster_message_t_ webster_message_t;

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
    int type;
    int scheme;
    char *user;
    char *host;
    int port;
    char *path;
    char *query;
} webster_target_t;

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
    int scheme,
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
    webster_target_t **target );

WEBSTER_EXPORTED int WebsterFreeURL(
    webster_target_t *target );

/*
 * HTTP client API
 */

WEBSTER_EXPORTED int WebsterConnect(
    webster_client_t **client,
    int scheme,
    const char *host,
    int port );

WEBSTER_EXPORTED int WebsterCommunicate(
    webster_client_t *client,
    char *path,
    char *query,
    webster_handler_t *callback,
    void *data );

WEBSTER_EXPORTED int WebsterCommunicateURL(
    webster_client_t *client,
    webster_target_t *url,
    webster_handler_t *callback,
    void *data );

WEBSTER_EXPORTED int WebsterDisconnect(
    webster_client_t *client );


/*
 * HTTP server API
 */

WEBSTER_EXPORTED int WebsterCreate(
    webster_server_t **server,
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
	webster_client_t **remote );

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

WEBSTER_EXPORTED int WebsterIterateField(
    webster_message_t *input,
    int index,
    int *id,
    const char **name,
    const char **value );

WEBSTER_EXPORTED int WebsterReadData(
    webster_message_t *input,
    const uint8_t **buffer,
    int *size );

WEBSTER_EXPORTED int WebsterReadString(
    webster_message_t *input,
    const char **buffer );

WEBSTER_EXPORTED int WebsterSetStatus(
    webster_message_t *output,
    int status );

WEBSTER_EXPORTED int WebsterSetMethod(
    webster_message_t *output,
    int method );

WEBSTER_EXPORTED int WebsterGetStatus(
    webster_message_t *output,
    int *status );

WEBSTER_EXPORTED int WebsterGetMethod(
    webster_message_t *output,
    int *method );

WEBSTER_EXPORTED int WebsterGetTarget(
    webster_message_t *output,
    const webster_target_t **target );

WEBSTER_EXPORTED int WebsterSetStringField(
    webster_message_t *output,
    const char *name,
    const char *value );

WEBSTER_EXPORTED int WebsterSetIntegerField(
    webster_message_t *output,
    const char *name,
    int value );

WEBSTER_EXPORTED int WebsterRemoveField(
    webster_message_t *output,
    const char *name );

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

WEBSTER_EXPORTED int WebsterGetState(
	webster_message_t *message,
    int *state );


#ifdef __cplusplus
}
#endif


#endif // WEBSTER_API_H
