#ifndef WEBSTER_INTERFACE_HH
#define WEBSTER_INTERFACE_HH


#include "http.h"
#include <sys/socket.h>
#include <webster/api.h>
#include <pthread.h>


#define WEBSTER_MAX_CONNECTIONS     1000
#define WEBSTER_MAX_HEADER          (1024 * 4) // 4KB


typedef struct
{
    int socket;
    pthread_t thread;
} webster_remote_t ;


struct webster_server_t_
{
    int socket;
    char *host;
    int port;
    int maxClients;
    webster_remote_t *remotes;
    webster_handler_t *handler;
};


struct webster_input_t_
{
    ssize_t received;
    uint32_t contentLength;
    int socket;
    int method;
    struct
    {
        uint8_t start[WEBSTER_MAX_HEADER];
        uint8_t *current;
        int pending;
    } buffer;
    http_header_t header;
};


struct webster_output_t_
{
    int sent;
    uint32_t contentLength;
    int socket;
    int status;
    char temp[WEBSTER_MAX_HEADER];
};


typedef struct
{
    struct webster_server_t_ *server;
    webster_remote_t *remote;
    struct webster_input_t_ request;
    struct webster_output_t_ response;
    void *data;
} webster_thread_data_t;







#endif // WEBSTER_INTERFACE_HH