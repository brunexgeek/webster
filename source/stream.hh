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

#include <webster.hh>

namespace webster {

class HttpStream
{
	public:
		HttpStream( const Parameters &params, Channel *chann, int type );
		~HttpStream();
		int write( const uint8_t *data, int size );
		int write( const char *data );
		int write( const std::string &text );
		int write( char c );
		template<typename T, typename std::enable_if<std::is_arithmetic<T>::value, int>::type = 0>
		int write( T value )
		{
			std::string str = std::to_string(value);
			return write(str);
		}
		int read( uint8_t *data, int size );
        int read_line( char *data, int size );
        int pending() const;
        int flush();
		const Parameters &get_parameters() const { return params_; }
	protected:
		int pending_;
		Channel *channel_;
		Parameters params_;
		uint8_t *data_;
		uint8_t *current_;
};

} // namespace 'webster'
