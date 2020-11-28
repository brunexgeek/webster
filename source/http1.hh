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
#ifndef WEBSTER_HTTP1_HH
#define WEBSTER_HTTP1_HH

#include <webster.hh>
#include "stream.hh"

const int WBMF_INBOUND  = 1;
const int WBMF_OUTBOUND = 0;
const int WBMF_REQUEST  = 2;
const int WBMF_RESPONSE = 0;

namespace webster {
namespace http_v1 {

enum State
{
	WBS_IDLE     = 0,
	WBS_BODY     = 1,
	WBS_COMPLETE = 2,
};

class MessageImpl : public Message
{
    public:
        MessageImpl( DataStream &stream, int flags = 0 );
        ~MessageImpl();
        int read( uint8_t *buffer, int size );
        int read( char *buffer, int size );
        int read_all( std::vector<uint8_t> &buffer );
		int read_all( std::string &buffer );
        int write( const uint8_t *buffer, int size );
        int write( const char *buffer );
		int write( const std::string &buffer );
        int write( const std::vector<uint8_t> &buffer );
        int ready();
        int flush();
        int finish();

    protected:
        int flags_;
        State state_;
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
        DataStream &stream_;
        char *line_;

        int receive_header();
        int chunk_size();
        int write_header();
        int write_resource_line();
        int write_status_line();
        int parse_first_line( const char *data );
        int parse_header_field( char *data );
        int discard();
};

} // namespace http_v1
} // namespace webster

#endif // WEBSTER_HTTP1_HH