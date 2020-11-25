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
#include "stream.hh"
#include <cstring>

#define IS_INBOUND(x)   ( (x) & 1 )
#define IS_OUTBOUND(x)  ( ((x) & 1) == 0 )

namespace webster {

HttpStream::HttpStream( const Parameters &params, Channel *chann, int flags ) : pending_(0),
	channel_(chann), params_(params), data_(nullptr), current_(nullptr)
{
	if (IS_OUTBOUND(flags))
		data_ = current_ = new(std::nothrow) uint8_t[params_.buffer_size];
}

HttpStream::~HttpStream()
{
	delete[] data_;
}

int HttpStream::write( const uint8_t *buffer, int size )
{
	if (size == 0 || buffer == nullptr) return WBERR_OK;
	if (size < 0 || size > 0x3FFFFFFF) return WBERR_TOO_LONG;
	if (data_ == nullptr) return WBERR_MEMORY_EXHAUSTED;

	// ensures the current pointer is valid
	if (current_ == nullptr)
	{
		current_ = data_;
		pending_ = 0;
	}

	// fragment input data through recursive call until the data size fits the internal buffer
	int offset = 0;
	int result = WBERR_OK;
	int fit = params_.buffer_size - (int)(current_ - data_);
	while (size > fit)
	{
		result = write(buffer + offset, fit);
		size -= fit;
		offset += fit;
		fit = params_.buffer_size - (int)(current_ - data_);
		if (result != WBERR_OK) return result;
	}

	memcpy(current_, buffer + offset, (size_t) size);
	current_ += size;

	// send pending data if the buffer is full
	if (current_ >= data_ + params_.buffer_size)
	{
		result = params_.network->send(channel_, data_, params_.buffer_size, params_.write_timeout);
		current_ = data_;
		pending_ = 0;
	}

	return result;
}

int HttpStream::write( const char *text )
{
	return write((uint8_t*) text, (int) strlen(text));
}

int HttpStream::write( const std::string &text )
{
	return write((uint8_t*) text.c_str(), (int) text.length());
}

int HttpStream::write( char c )
{
	return write((uint8_t*) &c, 1);
}

int HttpStream::read( uint8_t *data, int size )
{
	int read = 0;
	int result = params_.network->receive(channel_, data, size, &read, params_.read_timeout);
	if (result == WBERR_OK) return read;
	return result;
}

int HttpStream::read_line( char *data, int size )
{
	if (data == nullptr || size < 2) return WBERR_INVALID_ARGUMENT;
	char *p = data;
	uint8_t c;

	// TODO: optimize this algorithm by using recv and MSG_PEEK do find the '\n'

	do
	{
		int result = read(&c, 1);
		if (result < 0) return result;
		if (c == '\r') continue;
		if (c == '\n') break;
		*p = (char) c;
		++p;
	} while (p < data + size - 1);
	if (c != '\n') return WBERR_TOO_LONG;
	*p = 0;

	return WBERR_OK;
}

int HttpStream::pending() const
{
	return pending_;
}

int HttpStream::flush()
{
	// send all remaining body data
	if (current_ > data_)
	{
		int size = (int) (current_ - data_);
		params_.network->send(channel_, data_, size, params_.write_timeout);
		current_ = data_;
	}
	return WBERR_OK;
}

} // namespace 'webster'