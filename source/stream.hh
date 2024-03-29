/*
 *   Copyright 2016-2023 Bruno Costa
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

#ifndef WEBSTER_STREAM_HH
#define WEBSTER_STREAM_HH

#include <webster.hh>

namespace webster {

enum LineEnding
{
	WBLE_EVENT, // line ending for SSE messages (\r, \n, \r\n)
	WBLE_HTTP   // line ending for HTTP messages (\r\n)
};

enum class StreamType
{
	INBOUND,
	OUTBOUND
};

/**
 * Utility class used to read and write data in network channels.
 */
class DataStream
{
	public:
		DataStream( Client &client, StreamType type );
		~DataStream();
		int write( const uint8_t *data, int size );
		int write( const char *data );
		int write( const std::string &text );
		int write( char c );
		template<typename T, typename std::enable_if<std::is_arithmetic<T>::value, int>::type = 0>
		int write( T value ) { return write(std::to_string(value)); }
		int read( uint8_t *data, int size );
        int read_line( char *data, int size );
        int flush();
		const Parameters &get_parameters() const;
		const Client &get_client();

	protected:
		Client &client_;
		uint8_t *data_;
		StreamType type_;
		int count_; // amount of data in the buffer
		int bufsize_;
};

} // namespace 'webster'

#endif // WEBSTER_STREAM_HH