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

#include <cstring>

#include "stream.hh"  // AUTO-REMOVE
#include "network.hh" // AUTO-REMOVE

namespace webster {

DataStream::DataStream( Client &client, StreamType type ) : client_(client),
	type_(type), count_(0), bufsize_(0)
{
	bufsize_ = client_.get_parameters().buffer_size;
	data_ = new(std::nothrow) uint8_t[bufsize_];
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
	int fit = bufsize_ - count_;
	if (size >= fit)
	{
		result = flush();
		if (result != WBERR_OK) return result;
		while (size > (int) bufsize_)
		{
			result = params.network->send(client_.get_channel(), buffer, bufsize_, params.write_timeout);
			if (result != WBERR_OK) return result;
			buffer += bufsize_;
			size -= bufsize_;
		}
	}
	// copy the remaining data to the internal buffer
	if (size > 0)
	{
		memcpy(data_ + count_, buffer, (size_t) size);
		count_ += size;
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
	if (count_ > 0)
	{
		int fit = std::min(count_, size);
		memcpy(buffer, data_, fit);
		count_ -= fit;
		// move the remaining data to the start of the internal buffer
		if (count_ > 0)
			memmove(data_, data_ + fit, count_);
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
	if (buffer == nullptr || size < 1)
		return WBERR_INVALID_ARGUMENT;

	auto &params = client_.get_parameters();

	do
	{
		// looks for the line delimiter
		if (count_ > 0)
		{
			data_[count_] = 0;
			const uint8_t *p = (const uint8_t*) strstr( (const char*) data_, "\r\n");
			if (p != nullptr)
			{
				int len = (int) (p - data_);
				if (len > size - 1) return WBERR_TOO_LONG;
				// copy the line
				memcpy(buffer, data_, len);
				buffer[len] = 0;
				count_ -= len + 2;
				// move the remaining data to the start of the internal buffer
				memmove(data_, p + 2, count_);
				data_[count_] = 0;
				return WBERR_OK;
			}
		}
		// fill the internal buffer
		if (count_ < bufsize_)
		{
			int bytes = (int) (bufsize_ - count_) - 1;
			if (bytes == 0) return WBERR_TOO_LONG;

			int result = params.network->receive(client_.get_channel(), data_ + count_, bytes, &bytes, params.read_timeout);
			if (result != WBERR_OK)
			{
				*buffer = 0;
				return result;
			}

			count_ += bytes;
		}
	} while (true);
}

int DataStream::flush()
{
	// send all remaining body data
	if (type_ == StreamType::OUTBOUND && count_ > 0)
	{
		auto &params = client_.get_parameters();
		int result = params.network->send(client_.get_channel(), data_, count_, params.write_timeout);
		if (result != WBERR_OK) return result;
		count_ = 0;
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