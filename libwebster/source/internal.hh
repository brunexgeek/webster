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


struct webster_client_t_
{
	void *channel;
	std::string host;
	int port;
    uint32_t bufferSize;

    webster_client_t_();
    ~webster_client_t_();
};


struct webster_server_t_
{
    void *channel;
    std::string host;
    int port;
    int maxClients;
    uint32_t bufferSize;

    webster_server_t_();
    ~webster_server_t_();
};


#endif // WEBSTER_INTERNAL_HH
