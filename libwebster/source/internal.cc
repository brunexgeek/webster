#include "internal.hh"



webster_header_t::webster_header_t() : target(NULL), status(0), method(WBM_NONE)
{
}


webster_header_t::~webster_header_t()
{

}


webster_message_t_::webster_message_t_( size_t size ) : state(WBS_IDLE), channel(NULL),
    type(WBMT_UNKNOWN), flags(0), client(NULL)
{
    body.expected = body.chunkSize = 0;
    buffer.data = buffer.current = new(std::nothrow) uint8_t[size];
    buffer.data[0] = 0;
    buffer.size = size;
    buffer.pending = 0;
}


webster_message_t_::~webster_message_t_()
{
    delete[] buffer.data;
}