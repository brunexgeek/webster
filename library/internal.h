#ifndef WEBSTER_INTERNAL_HH
#define WEBSTER_INTERNAL_HH


#include "http.h"
#include <sys/socket.h>
#include <webster/api.h>
#include <pthread.h>
#include <poll.h>
#include <stdbool.h>


#define WEBSTER_MAX_CONNECTIONS     1000
#define WEBSTER_MAX_HEADER          (1024 * 4) // 4KB
#define WEBSTER_READ_TIMEOUT        10000

#define GET_DATA_POINTER(ptr, type) ( (uint8_t*) (x) + sizeof(type) )


typedef struct
{
    void *channel;
    pthread_t thread;
} webster_remote_t ;


struct webster_server_t_
{
    void *channel;
    char *host;
    int port;
    int maxClients;
    struct pollfd pfd;
    webster_remote_t *remotes;
    pthread_mutex_t mutex;
    struct
    {
        int bufferSize;
    } options;
};


struct webster_message_t_
{
    bool isInput;
    int state;
    void *channel;
    struct
    {
        int size;
        int expected;
    } body;
    struct
    {
        uint8_t *data;
        size_t size;
        uint8_t *current;
        int pending;
    } buffer;
    webster_header_t header;
};


typedef struct
{
    struct webster_server_t_ *server;
    webster_remote_t *remote;
    struct webster_message_t_ request;
    struct webster_message_t_ response;
    webster_handler_t *handler;
    void *data;
} webster_thread_data_t;







#endif // WEBSTER_INTERNAL_HH