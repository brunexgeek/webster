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
#include "network.hh"
#include <cstring>
#include <iostream>

namespace webster {

DataStream::DataStream( Client &client, StreamType type ) : pending_(0),
	client_(client), type_(type)
{
	data_ = current_ = start_ = new(std::nothrow) uint8_t[client_.get_parameters().buffer_size];
}

DataStream::~DataStream()
{
	delete[] data_;
}

int DataStream::write( const uint8_t *buffer, int size )
{
	if (type_ != StreamType::OUTBOUND)
		return WBERR_WRITE_ONLY;
	if (size == 0 || buffer == nullptr)
		return WBERR_OK;
	if (size < 0 || size > 0x3FFFFFFF)
		return WBERR_TOO_LONG;
	if (data_ == nullptr)
		return WBERR_MEMORY_EXHAUSTED;

	auto &params = client_.get_parameters();
	int result = WBERR_OK;

	// send all data that doesn't fits the internal buffer with some room
	int fit = params.buffer_size - (int)(current_ - data_);
	if (size >= fit)
	{
		flush();
		while (size > (int) params.buffer_size)
		{
			result = params.network->send(client_.get_channel(), buffer, params.buffer_size, params.write_timeout);
			if (result != WBERR_OK) return result;
			buffer += params.buffer_size;
			size -= params.buffer_size;
		}
	}
	// copy the remaining data to the internal buffer
	if (size > 0)
	{
		memcpy(current_, buffer, (size_t) size);
		current_ += size;
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

int DataStream::read( uint8_t *buffer, int size )
{
	if (type_ != StreamType::INBOUND)
		return WBERR_READ_ONLY;

	// check whether there's any buffered data
	if (start_ < current_)
	{
		int fit = std::min((int) (current_ - start_), size);
		std::cerr << "Getting " << fit << " bytes from internal buffer\n";
		memcpy(buffer, start_, fit);
		start_ += fit;
		std::cerr << "Remaining bytes: " << (current_ - start_) << '\n';
		if (start_ == current_)
			start_ = current_ = data_;
		return fit;
	}

	auto &params = client_.get_parameters();
	int read = 0;
	int result = params.network->receive(client_.get_channel(), buffer, size, &read, params.read_timeout);
	if (result == WBERR_OK) return read;
	return result;
}

int DataStream::read_line( char *buffer, int size )
{
	if (type_ != StreamType::INBOUND)
		return WBERR_READ_ONLY;
	if (buffer == nullptr || size < 2)
		return WBERR_INVALID_ARGUMENT;

	char *p = buffer;
	uint8_t c, v = 0;
	auto &params = client_.get_parameters();

	// TODO: limit the line length

	do
	{
		// fill the internal buffer
		if (start_ == current_)
		{
			start_ = data_;
			int read = 0;
			int result = params.network->receive(client_.get_channel(), data_, params.buffer_size, &read, params.read_timeout);
			if (result != WBERR_OK)
			{
				*buffer = 0;
				return result;
			}
			current_ = data_ + read;
		}

		c = *start_++;
		if (c == '\r') continue;
		if (c == '\n') break;
		*p = (char) (v = c);
		++p;
	} while (p < buffer + size - 1);
	*p = 0;

	if (c != '\n') return WBERR_TOO_LONG;

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

const Parameters &DataStream::get_parameters() const
{
	return client_.get_parameters();
}

const Client &DataStream::get_client()
{
	return client_;
}

} // namespace 'webster'