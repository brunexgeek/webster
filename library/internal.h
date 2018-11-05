#ifndef WEBSTER_INTERNAL_HH
#define WEBSTER_INTERNAL_HH


#include "http.h"
#include <webster/api.h>


#if defined(_WIN32) || defined(WIN32)
#define WB_WINDOWS
#endif


#define WBMT_UNKNOWN    0x00
#define WBMT_REQUEST    0x01
#define WBMT_RESPONSE   0x02


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

    struct
    {
        /**
         * @brief Message expected size.
         *
         * This value is less than zero if using chunked transfer encoding.
         */
        int expected;
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
};


#endif // WEBSTER_INTERNAL_HH
