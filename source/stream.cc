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

namespace webster {

DataStream::DataStream( Client &client, StreamType type ) : pending_(0),
	client_(client), data_(nullptr), current_(nullptr), type_(type)
{
	if (type == StreamType::OUTBOUND)
		data_ = current_ = new(std::nothrow) uint8_t[client_.get_parameters().buffer_size];
}

DataStream::~DataStream()
{
	delete[] data_;
}

int DataStream::write( const uint8_t *buffer, int size )
{
	if (type_ != StreamType::OUTBOUND) return WBERR_INVALID_CHANNEL;
	if (size == 0 || buffer == nullptr) return WBERR_OK;
	if (size < 0 || size > 0x3FFFFFFF) return WBERR_TOO_LONG;
	if (data_ == nullptr) return WBERR_MEMORY_EXHAUSTED;
	auto &params = client_.get_parameters();

	// ensures the current pointer is valid
	if (current_ == nullptr)
	{
		current_ = data_;
		pending_ = 0;
	}

	// fragment input data through recursive call until the data size fits the internal buffer
	int offset = 0;
	int result = WBERR_OK;
	int fit = client_.get_parameters().buffer_size - (int)(current_ - data_);
	while (size > fit)
	{
		result = write(buffer + offset, fit);
		size -= fit;
		offset += fit;
		fit = params.buffer_size - (int)(current_ - data_);
		if (result != WBERR_OK) return result;
	}

	memcpy(current_, buffer + offset, (size_t) size);
	current_ += size;

	// send pending data if the buffer is full
	if (current_ >= data_ + params.buffer_size)
	{
		result = params.network->send(client_.get_channel(), data_, params.buffer_size, params.write_timeout);
		current_ = data_;
		pending_ = 0;
	}

	return result;
}

int DataStream::write( const char *text )
{
	return write((uint8_t*) text, (int) strlen(text));
}

int DataStream::write( const std::string &text )
{
	return write((uint8_t*) text.c_str(), (int) text.length());
}

int DataStream::write( char c )
{
	return write((uint8_t*) &c, 1);
}

int DataStream::read( uint8_t *data, int size )
{
	if (type_ != StreamType::INBOUND) return WBERR_INVALID_CHANNEL;
	auto &params = client_.get_parameters();
	int read = 0;
	int result = params.network->receive(client_.get_channel(), data, size, &read, params.read_timeout);
	if (result == WBERR_OK) return read;
	return result;
}

int DataStream::read_line( char *data, int size )
{
	if (type_ != StreamType::INBOUND) return WBERR_INVALID_CHANNEL;
	if (data == nullptr || size < 2) return WBERR_INVALID_ARGUMENT;
	char *p = data;
	uint8_t c;

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

int DataStream::pending() const
{
	return pending_;
}

int DataStream::flush()
{
	// send all remaining body data
	if (type_ == StreamType::OUTBOUND && current_ > data_)
	{
		auto &params = client_.get_parameters();
		int size = (int) (current_ - data_);
		params.network->send(client_.get_channel(), data_, size, params.write_timeout);
		current_ = data_;
	}
	return WBERR_OK;
}

} // namespace 'webster'