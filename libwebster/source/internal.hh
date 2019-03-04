#ifndef WEBSTER_INTERNAL_HH
#define WEBSTER_INTERNAL_HH


//#include "http.hh"
#include <webster/api.h>
#include <map>
#include <string>


#if defined(_WIN32) || defined(WIN32)
#define WB_WINDOWS
#endif


#define WBMT_UNKNOWN    0x00
#define WBMT_REQUEST    0x01
#define WBMT_RESPONSE   0x02

#define WBMF_CHUNKED    0x01


struct webster_custom_field_t
{
    std::string name;
    std::string value;
};

//typedef std::map<std::string, webster_custom_field_t> custom_field_map;
typedef std::map<std::string, std::string> custom_field_map;


struct webster_standard_field_t
{
    int id;
    std::string value;
};

//typedef std::map<int, webster_standard_field_t> standard_field_map;
typedef std::map<int, std::string> standard_field_map;


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
};


struct webster_client_t_
{
	void *channel;
	char *host;
	int port;
    uint32_t bufferSize;
};


struct webster_server_t_
{
    void *channel;
    char *host;
    int port;
    int maxClients;
    uint32_t bufferSize;
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

    webster_message_t_( size_t size );
    ~webster_message_t_();
};


#endif // WEBSTER_INTERNAL_HH
