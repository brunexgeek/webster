/*
 *   Copyright 2020 Bruno Ribeiro
 *   <https://github.com/brunexgeek/webster>
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 */

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
#include <functional>
#include <string>
#include <atomic>

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
#define WBERR_INVALID_TARGET             -31
#define WBERR_INVALID_VALUE              -32

#define WBT_HEADER                       1
#define WBT_BODY                         2
#define WBT_EMPTY                        3

#define WBMT_INBOUND                     1
#define WBMT_OUTBOUND                    2
#define WBMT_REQUEST                     4
#define WBMT_RESPONSE                    8

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

#define WBRT_ORIGIN      0x01
#define WBRT_AUTHORITY   0x02
#define WBRT_ABSOLUTE    (WBRT_ORIGIN + 0x04 + WBRT_AUTHORITY)
#define WBRT_ASTERISK    0x08

#define WBP_AUTO         0
#define WBP_HTTP         1
#define WBP_HTTPS        2

#define WB_IS_VALID_METHOD(x)  ( (x) >= WBM_GET && (x) <= WBM_PATCH )
#define WB_IS_VALID_SCHEME(x)  ( (x) >= WBP_AUTO && (x) <= WBP_HTTPS )
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
#define WBL_DEF_FIELD_INITIAL  16
#define WBL_DEF_FIELD_GROW     8
#define WBL_DEF_TIMEOUT        10000 // 10 sec
#define WBL_MAX_TIMEOUT        120000 // 120 sec

#define WBMF_CHUNKED    0x01

#include <memory>
#include <map>
#include <string>

namespace webster {

struct Target
{
    int type;
    int scheme;
    std::string user;
    std::string host;
    int port;
    std::string path;
    std::string query;

    Target();
    static int parse( const char *url, Target &target );
};

enum Method
{
    WBM_NONE    = 0,
    WBM_GET     = 1,
    WBM_HEAD    = 2,
    WBM_POST    = 3,
    WBM_PUT     = 4,
    WBM_DELETE  = 5,
    WBM_CONNECT = 6,
    WBM_OPTIONS = 7,
    WBM_TRACE   = 8,
    WBM_PATCH   = 9,
};

WEBSTER_PRIVATE int strcmpi(const char *s1, const char *s2);

struct less
{
    typedef std::string first_argument_type;
    typedef std::string second_argument_type;
    typedef bool result_type;

    bool operator() (const std::string& x, const std::string& y) const
    {
        return strcmpi(x.c_str(), y.c_str()) < 0;
    }
};

struct Header
{
    int content_length;
    Target target;
    int status;
    std::map<std::string, std::string, webster::less> fields;
    Method method;

    Header();
};

class Client;

class Channel {};

class Network
{
    public:
        enum Type { CLIENT, SERVER };
        virtual int open( Channel **channel, Type type ) = 0;
        virtual int close( Channel *channel ) = 0;
        virtual int connect( Channel *channel, int scheme, const char *host, int port ) = 0;
        virtual int receive( Channel *channel, uint8_t *buffer, uint32_t *size, int timeout ) = 0;
        virtual int send( Channel *channel, const uint8_t *buffer, uint32_t size ) = 0;
        virtual int accept( Channel *channel, Channel **client ) = 0;
        virtual int listen( Channel *channel, const char *host, int port, int maxClients ) = 0;
};

#ifndef WEBSTER_NO_DEFAULT_NETWORK
class SocketNetwork : public Network
{
    public:
        SocketNetwork();
        ~SocketNetwork() = default;
        int open( Channel **channel, Type type );
        int close( Channel *channel );
        int connect( Channel *channel, int scheme, const char *host, int port );
        int receive( Channel *channel, uint8_t *buffer, uint32_t *size, int timeout );
        int send( Channel *channel, const uint8_t *buffer, uint32_t size );
        int accept( Channel *channel, Channel **client );
        int listen( Channel *channel, const char *host, int port, int maxClients );
};
#endif

struct Parameters
{
    Parameters();
    Parameters( const Parameters &that );

    /**
     * Pointer to custom network functions. If NULL uses the default implementation.
     */
    std::shared_ptr<Network> network;

    /**
     * Maximum number of concurrent remote clients (server only).
     */
    int max_clients;

    /**
     * Size in bytes of the message internal buffer (read and write).
     */
    uint32_t buffer_size;

    /**
     * Read timeout in milliseconds (between 1 and ``WBL_MAX_TIMEOUT``).
     */
    int read_timeout;
};
/*
class Message
{
    public:
        Header header;
        virtual ~Message() = default;
        virtual int read( const uint8_t **buffer, int *size ) = 0;
        virtual int read( const char **buffer ) = 0;
        virtual int read( std::string &buffer ) = 0;
        virtual int write( const uint8_t *buffer, int size ) = 0;
        virtual int write( const char *buffer ) = 0;
        virtual int write( const std::string &buffer ) = 0;
        virtual void flush() = 0;
};*/

class Message
{
    public:
        Header header;
		Message(  int buffer_size = WBL_DEF_BUFFER_SIZE );
        ~Message() = default;
        int read( const uint8_t **buffer, int *size );
        int read( const char **buffer );
        int read( std::string &buffer );
        int write( const uint8_t *buffer, int size );
        int write( const char *buffer );
        int write( const std::string &buffer );
        int flush();
        int finish();

    public:
        /**
         * @brief Current state of the message.
         *
         * The machine state if defined by @c WBS_* macros.
         */
        int state_;

        /**
         * @brief Message type (WBMT_INBOUND or WBMT_OUTBOUND).
         */
        int flags_;

        struct
        {
            /**
             * @brief Message expected size.
             *
             * This value is any negative if using chunked transfer encoding.
             */
            int expected;

            /**
             * @brief Number of chunks received.
             */
            int chunks;

            int flags;
        } body_;

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
        } buffer_;
        Client *client_;
        Channel *channel_;

        int receiveHeader( int timeout );
        int chunkSize( int timeout );
        int receiveBody( int timeout );
        int writeData( const uint8_t *buffer, int size );
        int writeString( const std::string &text );
        int writeHeader();
        int write_resource_line();
};

typedef std::function<int(Message&,Message&,void*)> Handler;

WEBSTER_EXPORTED class Server
{
    public:
        Server();
        Server( Parameters params );
        virtual ~Server() = default;
        virtual int bind( const std::string &path, Handler handler );
        virtual int start( const Target &target );
        virtual int stop();
        virtual int accept( Client **remote );
    protected:
        Parameters params_;
        Channel *channel_;
        Target target_;
        Handler handler_;
};

WEBSTER_EXPORTED class Client
{
    public:
        Client();
        Client( Parameters params );
        virtual ~Client() = default;
        virtual int connect( const Target &target );
        virtual int communicate( const std::string &path, Handler handler, void *data = nullptr );
        virtual int disconnect();
    public:
        Parameters params_;
        Channel *channel_;
        Target target_;
};

class RemoteClient : public Client
{
    public:
        RemoteClient( Parameters params ) : Client(params) {}
        ~RemoteClient() = default;
        int communicate( const std::string &path, Handler handler, void *data = nullptr ) override;
};

extern std::shared_ptr<SocketNetwork> DEFAULT_NETWORK;

} // namespace webster

#endif // WEBSTER_API_H
