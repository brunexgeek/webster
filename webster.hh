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
#define WBERR_INVALID_HTTP_METHOD        -14
#define WBERR_INVALID_HTTP_VERSION       -16
#define WBERR_INVALID_HTTP_MESSAGE       -17
#define WBERR_INVALID_TARGET             -18
#define WBERR_INVALID_SCHEME             -19
#define WBERR_INVALID_HOST               -20
#define WBERR_INVALID_PORT               -21
#define WBERR_INVALID_CHANNEL            -22
#define WBERR_INVALID_CHUNK              -28
#define WBERR_NOT_CONNECTED              -29
#define WBERR_SIGNAL                     -30
#define WBERR_INVALID_HTTP_FIELD         -32
#define WBERR_INVALID_HANDLER            -33
#define WBERR_NOT_IMPLEMENTED            -34
#define WBERR_NO_RESOURCES               -35

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

enum FieldID
{
    WBFI_NON_STANDARD = 0,
    WBFI_ACCEPT,
    WBFI_ACCEPT_CHARSET,
    WBFI_ACCEPT_ENCODING,
    WBFI_ACCEPT_LANGUAGE,
    WBFI_ACCEPT_PATCH,
    WBFI_ACCEPT_RANGES,
    WBFI_ACCESS_CONTROL_ALLOW_CREDENTIALS,
    WBFI_ACCESS_CONTROL_ALLOW_HEADERS,
    WBFI_ACCESS_CONTROL_ALLOW_METHODS,
    WBFI_ACCESS_CONTROL_ALLOW_ORIGIN,
    WBFI_ACCESS_CONTROL_EXPOSE_HEADERS,
    WBFI_ACCESS_CONTROL_MAX_AGE,
    WBFI_ACCESS_CONTROL_REQUEST_HEADERS,
    WBFI_ACCESS_CONTROL_REQUEST_METHOD,
    WBFI_AGE, // RFC-7234
    WBFI_ALLOW,
    WBFI_ALT_SVC,
    WBFI_AUTHORIZATION,
    WBFI_CACHE_CONTROL,
    WBFI_CONNECTION,
    WBFI_CONTENT_DISPOSITION,
    WBFI_CONTENT_ENCODING,
    WBFI_CONTENT_LANGUAGE,
    WBFI_CONTENT_LENGTH,
    WBFI_CONTENT_LOCATION,
    WBFI_CONTENT_RANGE,
    WBFI_CONTENT_TYPE,
    WBFI_COOKIE,
    WBFI_DATE,
    WBFI_DNT,
    WBFI_ETAG,
    WBFI_EXPECT,
    WBFI_EXPIRES,
    WBFI_FORWARDED,
    WBFI_FROM,
    WBFI_HOST,
    WBFI_IF_MATCH,
    WBFI_IF_MODIFIED_SINCE,
    WBFI_IF_NONE_MATCH,
    WBFI_IF_RANGE,
    WBFI_IF_UNMODIFIED_SINCE,
    WBFI_LAST_MODIFIED,
    WBFI_LINK,
    WBFI_LOCATION,
    WBFI_MAX_FORWARDS,
    WBFI_ORIGIN,
    WBFI_PRAGMA,
    WBFI_PROXY_AUTHENTICATE,
    WBFI_PROXY_AUTHORIZATION,
    WBFI_PUBLIC_KEY_PINS,
    WBFI_RANGE,
    WBFI_REFERER,
    WBFI_RETRY_AFTER,
    WBFI_SERVER,
    WBFI_SET_COOKIE,
    WBFI_STRICT_TRANSPORT_SECURITY,
    WBFI_TE,
    WBFI_TK,
    WBFI_TRAILER,
    WBFI_TRANSFER_ENCODING,
    WBFI_UPGRADE,
    WBFI_UPGRADE_INSECURE_REQUESTS,
    WBFI_USER_AGENT,
    WBFI_VARY,
    WBFI_VIA,
    WBFI_WARNING,
    WBFI_WWW_AUTHENTICATE,
};

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

uint64_t tick();

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
    Target( const Target &that ) = default;
    Target( Target &&that ) = default;
    Target &operator=( const Target &that ) = default;
    static int parse( const char *url, Target &target ); // TODO: make this dynamic
    static std::string encode( const std::string & value );
    static std::string decode( const std::string & value );
    void swap( Target &that );
    void clear();
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

class HeaderFields : public std::map<std::string, std::string, webster::less>
{
    public:
        using std::map<std::string, std::string, webster::less>::count;
        std::string get( const std::string &name )  const;
        std::string get( FieldID id )  const;
        std::string get( const std::string &name, const std::string &value )  const;
        std::string get( FieldID id, const std::string &value )  const;
        template<typename T, typename std::enable_if<std::is_integral<T>::value, int>::type = 0>
        T get( const std::string &name, T value )  const
        {
            auto it = find(name);
            if (it == end()) return value;
            return (T) strtol(it->second.c_str(), nullptr, 10);
        }
        template<typename T, typename std::enable_if<std::is_integral<T>::value, int>::type = 0>
        T get( FieldID id, T value ) const
        {
            return get(get_name(id), value);
        }
        void set( const std::string &name, const std::string &value );
        void set( FieldID id, const std::string &value );
        template<typename T, typename std::enable_if<std::is_integral<T>::value, int>::type = 0>
        void set( const std::string &name, T value )
        {
            set(name, std::to_string(value));
        }
        template<typename T, typename std::enable_if<std::is_integral<T>::value, int>::type = 0>
        void set( FieldID id, T value )
        {
            set(get_name(id), std::to_string(value));
        }
        size_t count( FieldID id ) const;
        static const char *get_name( FieldID id );
};

struct Header
{
    int content_length;
    Target target;
    int status;
    HeaderFields fields;
    Method method;

    Header();
    Header( const Header & ) = default;
    Header( Header && ) = default;
    Header &operator=( const Header & ) = default;
    void swap( Header &that );
    void clear();
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
        virtual int receive( Channel *channel, uint8_t *buffer, int *size, int timeout ) = 0;
        virtual int send( Channel *channel, const uint8_t *buffer, int *size, int timeout ) = 0;
        virtual int accept( Channel *channel, Channel **client, int timeout ) = 0;
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
        int receive( Channel *channel, uint8_t *buffer, int *size, int timeout );
        int send( Channel *channel, const uint8_t *buffer, int *size, int timeout );
        int accept( Channel *channel, Channel **client, int timeout );
        int listen( Channel *channel, const char *host, int port, int maxClients );
    protected:
        int set_non_blocking( Channel *channel );
        int set_reusable( Channel *channel );
        int resolve( const char *host, void *address );
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

class Message
{
    public:
        Header header;
        virtual ~Message() = default;
        virtual int read( uint8_t *buffer, int *size ) = 0;
        virtual int read( char *buffer, int size ) = 0;
        //virtual int read( std::string &buffer ) = 0;
        virtual int write( const uint8_t *buffer, int size ) = 0;
        virtual int write( const char *buffer ) = 0;
        virtual int write( const std::string &buffer ) = 0;
        virtual int wait() = 0;
        virtual int flush() = 0;
        virtual int finish() = 0;
};

//typedef std::function<int(Message&,Message&)> Handler;
class Handler
{
    public:
        Handler() = default;
        Handler( const Handler & ) = default;
        Handler( Handler && ) = default;
        Handler( std::function<int(Message&,Message&)> );
        Handler( int (&func)(Message&,Message&) );
        virtual int operator()(Message&, Message&);
        bool operator==( std::nullptr_t ) const;
    protected:
        std::function<int(Message&,Message&)> func_;
};

WEBSTER_EXPORTED class Server
{
    public:
        Server();
        Server( Parameters params );
        virtual ~Server();
        virtual int start( const Target &target );
        virtual int stop();
        virtual int accept( std::shared_ptr<Client> &remote );
        virtual const Parameters &get_parameters() const;
        virtual const Target &get_target() const;
    protected:
        Parameters params_;
        Channel *channel_;
        Target target_;
};

WEBSTER_EXPORTED class Client
{
    public:
        friend Server;
        Client();
        Client( Parameters params );
        virtual ~Client();
        virtual int connect( const Target &target );
        virtual int communicate( const std::string &path, Handler &handler ); // TODO: create version which receives 'Target' instead of string
        virtual int disconnect();
        virtual const Parameters &get_parameters() const;
        virtual const Target &get_target() const;
    protected:
        Parameters params_;
        Channel *channel_;
        Target target_;
};

class RemoteClient : public Client
{
    public:
        RemoteClient( Parameters params ) : Client(params) {}
        ~RemoteClient() = default;
        int communicate( const std::string &path, Handler &handler ) override;
};

typedef std::shared_ptr<Network> NetworkPtr;

class HttpStream
{
	public:
		HttpStream( NetworkPtr net, Channel *chann, int type, int size = WBL_DEF_BUFFER_SIZE );
		~HttpStream();
		int write( const uint8_t *data, int size );
		int write( const char *data );
		int write( const std::string &text );
		int read( uint8_t *data, int *size );
        int read_line( char *data, int size );
        int pending() const;
        int flush();
	protected:
		uint8_t *current_;
		int pending_;
		int size_;
		Channel *channel_;
		NetworkPtr net_;
		uint8_t *data_;
};

typedef std::shared_ptr<HttpStream> HttpStreamPtr;

class MessageImpl : public Message
{
    public:
		MessageImpl( HttpStream &stream, int buffer_size = WBL_DEF_BUFFER_SIZE );
        ~MessageImpl();
        int read( uint8_t *buffer, int *size );
        int read( char *buffer, int size );
        //int read( std::string &buffer );
        int write( const uint8_t *buffer, int size );
        int write( const char *buffer );
        int write( const std::string &buffer );
        int wait();
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

        HttpStream &stream_;
        Client *client_;
        Channel *channel_;

        int receive_header( int timeout );
        int chunk_size( int timeout );
        int write_header();
        int write_resource_line();
        int compute_resource_line( std::stringstream &ss ) const;
        int compute_status_line( std::stringstream &ss ) const;
        int parse_first_line( const char *data );
        int parse_header_field( char *data );

        friend Client;
        friend RemoteClient;
};

extern std::shared_ptr<SocketNetwork> DEFAULT_NETWORK;

} // namespace webster

#endif // WEBSTER_API_H
