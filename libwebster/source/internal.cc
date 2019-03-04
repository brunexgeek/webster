#include "internal.hh"



webster_client_t_::webster_client_t_() : channel(NULL), port(-1),
    bufferSize(WBL_DEF_BUFFER_SIZE)
{
}


webster_client_t_::~webster_client_t_()
{
}


webster_server_t_::webster_server_t_() : channel(NULL), port(-1),
    maxClients(WBL_MAX_CONNECTIONS/3), bufferSize(WBL_DEF_BUFFER_SIZE)
{
}


webster_server_t_::~webster_server_t_()
{
}