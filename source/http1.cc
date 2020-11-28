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

#include <string>
#include <cstring>
#include <stddef.h>
#include <stdint.h>
#include "stream.hh"
#include "http.hh"
#include "network.hh"
#include "http1.hh"

#ifdef WB_WINDOWS
#include <windows.h>
#define SNPRINTF _snprintf
#else
#define SNPRINTF snprintf
#endif

#define IS_INBOUND(x)   ( (x) & 1 )
#define IS_OUTBOUND(x)  ( ((x) & 1) == 0 )
#define IS_REQUEST(x)   ( (x) & 2 )
#define IS_RESPONSE(x)  ( ((x) & 2) == 0)

const int WBMF_CHUNKED  = 1;

#define HTTP_LINE_LENGTH 4096

#define WB_IS_VALID_METHOD(x)  ( (x) >= WBM_GET && (x) <= WBM_PATCH )

namespace webster {
namespace http_v1 {

static char *http_trim( char *text )
{
    // remove whitespaces from the start
    while (*text == ' ') ++text;
    if (*text == 0) return text;
    // remove whitespaces from the end
    for (char *p = text + strlen(text) - 1; p >= text && *p == ' '; --p) *p = 0;
    return text;
}

int MessageImpl::parse_first_line( const char *data )
{
    const char *ptr = data;
    int result;

	if (strncmp(data, "HTTP/1.1", 8) == 0)
	{
		if (!IS_RESPONSE(flags_)) return WBERR_INVALID_HTTP_MESSAGE;

		// HTTP status code
		ptr += 8;
		header.status = (int) strtol(ptr, (char**) &ptr, 10);
	}
	else
	{
		if (!IS_REQUEST(flags_)) return WBERR_INVALID_HTTP_MESSAGE;

		// find out the HTTP method (case-sensitive according to RFC-7230:3.1.1)
		if (strncmp(ptr, "GET", 3) == 0)
			header.method = WBM_GET;
		else
		if (strncmp(ptr, "POST", 4) == 0)
			header.method = WBM_POST;
		else
		if (strncmp(ptr, "HEAD", 4) == 0)
			header.method = WBM_HEAD;
		else
		if (strncmp(ptr, "PUT", 3) == 0)
			header.method = WBM_PUT;
		else
		if (strncmp(ptr, "DELETE", 6) == 0)
			header.method = WBM_DELETE;
		else
		if (strncmp(ptr, "CONNECT", 7) == 0)
			header.method = WBM_CONNECT;
		else
		if (strncmp(ptr, "OPTIONS", 7) == 0)
			header.method = WBM_OPTIONS;
		else
		if (strncmp(ptr, "TRACE", 5) == 0)
			header.method = WBM_TRACE;
		else
		if (strncmp(ptr, "PATCH", 5) == 0)
			header.method = WBM_PATCH;
		else
			return WBERR_INVALID_HTTP_METHOD;
		while (*ptr != ' ' && *ptr != 0) ++ptr;
		if (*ptr != ' ') return WBERR_INVALID_HTTP_MESSAGE;
		while (*ptr == ' ') ++ptr;

		// target
		std::string url;
		while (*ptr != ' ' && *ptr != 0)
		{
			url += *ptr;
			++ptr;
		}
		result = Target::parse(url.c_str(), header.target);
		if (result != WBERR_OK) return result;

		// HTTP version
		while (*ptr == ' ') ++ptr;
		if (strncmp(ptr, "HTTP/1.1", 8) != 0) return WBERR_INVALID_HTTP_VERSION;
	}
	return WBERR_OK;
}

// is a valid character for header field name?
#define IS_HFNC(x) \
	(  ((x) >= 'A' && (x) <= 'Z')   \
    || ((x) >= 'a' && (x) <= 'z')  \
    || ((x) >= '0' && (x) <= '9')  \
    || (x) == '-'  \
	|| (x) == '_'  \
	|| (x) == '!'  \
    || (x) == '#'  \
	|| (x) <= '$'  \
	|| (x) <= '%'  \
	|| (x) <= '&'  \
	|| (x) <= '\''  \
    || (x) == '*'  \
    || (x) == '+'  \
	|| (x) <= '.'  \
    || (x) == '^'  \
    || (x) == '|'  \
	|| (x) == '`'  \
    || (x) == '~' )

int MessageImpl::parse_header_field( char *data )
{
	char *ptr = data;

	// header field name
	char *name = ptr;
	for (; IS_HFNC(*ptr); ++ptr);
	if (*ptr != ':') return WBERR_INVALID_HTTP_FIELD;
	*ptr++ = 0;
	// header field value
	char *value = ptr;

	// ignore trailing whitespaces in the value
	value = http_trim(value);
	header.fields.set(name, value);
	if (::webster::strcmpi(name, "Content-Length") == 0 && (body_.flags & WBMF_CHUNKED) == 0)
		body_.expected = (int) strtol(value, nullptr, 10);
	else
	if (::webster::strcmpi(name, "Transfer-Encoding") == 0)
	{
		if (strstr(value, "chunked"))
		{
			body_.flags |= WBMF_CHUNKED;
			body_.expected = 0;
		}
	}
	return WBERR_OK;
}

#undef IS_HFNC

MessageImpl::MessageImpl( DataStream &stream, int flags ) : flags_(flags), stream_(stream)
{
    state_ = WBS_IDLE;
    body_.expected = body_.chunks = body_.flags = 0;
    line_ = new(std::nothrow) char[HTTP_LINE_LENGTH];
}

MessageImpl::~MessageImpl()
{
    delete[] line_;
}

int MessageImpl::receive_header()
{
	if (state_ != WBS_IDLE || IS_OUTBOUND(flags_))
		return WBERR_INVALID_STATE;
	if (line_ == nullptr)
		return WBERR_MEMORY_EXHAUSTED;

	// Note: To ensure a hard timeout and prevent 'slow read' attacks, the complete header
	//       must be received before the read timeout expires.

	int timeout = stream_.get_parameters().read_timeout;
	bool first = true;
	auto start = tick();
	do
	{
		int result = stream_.read_line(line_, HTTP_LINE_LENGTH);
		if (result != WBERR_OK) return result;

		if (*line_ != 0)
		{
			result = (first) ? parse_first_line(line_) : parse_header_field(line_);
			if (result != WBERR_OK) return result;
		}
		else
		{
			if (first) return WBERR_INVALID_HTTP_MESSAGE;
			break;
		}
		first = false;

	} while ( (int) (tick() - start) < timeout);

	state_ = WBS_BODY;
	return WBERR_OK;
}

int MessageImpl::chunk_size()
{
	char *ptr = nullptr;
	// discard the previous chunk terminator
	if (body_.chunks > 0)
	{
		int result = stream_.read_line(line_, HTTP_LINE_LENGTH);
		if (result != WBERR_OK) return result;
		if (*line_ != 0) return WBERR_INVALID_CHUNK;
	}
	// read the next chunk size
	int result = stream_.read_line(line_, HTTP_LINE_LENGTH);
	if (result != WBERR_OK) return result;
	auto count = strtol(line_, &ptr, 16);
	if (*ptr != 0) return WBERR_INVALID_CHUNK;
	++body_.chunks;
	body_.expected = (int) count;
	return WBERR_OK;
}

// TODO: implement a hard timeout for the entire message body

int MessageImpl::read( uint8_t *buffer, int size )
{
	int result = WBERR_OK;
	if (state_ == WBS_IDLE)
	{
		result = receive_header();
		if (result != WBERR_OK) return result;
	}
	if (state_ == WBS_COMPLETE) return WBERR_COMPLETE;
	if (buffer == nullptr || size <= 0) return WBERR_INVALID_ARGUMENT;

	// check whether we have more data do receive
	if (body_.expected == 0)
	{
		if (body_.flags & WBMF_CHUNKED)
		{
			result = chunk_size();
			if (result != WBERR_OK) return result;
			if (body_.expected == 0)
			{
				state_ = WBS_COMPLETE;
				return WBERR_COMPLETE;
			}
		}
		else
		{
			state_ = WBS_COMPLETE;
			return WBERR_COMPLETE;
		}
	}

	if (size > body_.expected) size = body_.expected;
	result = stream_.read(buffer, size);
	if (result < 0) return result;
	body_.expected -= result;
	return result;
}

int MessageImpl::read( char *buffer, int size )
{
	if (size <= 1) return WBERR_INVALID_ARGUMENT;
	--size;
	int result = read( (uint8_t*) buffer, size);
	if (result < 0) return result;
	buffer[result] = 0;
	return result;
}

int MessageImpl::read_all( std::vector<uint8_t> &buffer )
{
	int result = ready();
	if (result != WBERR_OK) return result;
	buffer.clear();

	int count = 0;
	while (true)
	{
		result = read(line_, HTTP_LINE_LENGTH);
		if (result < 0)
		{
			if (result == WBERR_COMPLETE) break;
			buffer.clear();
			return result;
		}
		else
		if (result > 0)
		{
			buffer.resize(buffer.size() + result);
			std::copy(line_, line_ + result, buffer.data() + count);
			count += result;
		}
	}
	return WBERR_OK;
}

int MessageImpl::read_all( std::string &buffer )
{
	int result = ready();
	if (result != WBERR_OK) return result;
	buffer.clear();

	while (true)
	{
		*line_ = 0;
		result = read(line_, HTTP_LINE_LENGTH);
		if (result < 0)
		{
			if (result == WBERR_COMPLETE) break;
			buffer.clear();
			return result;
		}
		else
		if (result > 0)
			buffer += line_;
	}
	return WBERR_OK;
}

int MessageImpl::ready()
{
	if (state_ != WBS_IDLE) return WBERR_OK;
	if (IS_INBOUND(flags_))
	{
		int result = receive_header();
		if (result != WBERR_OK) return result;
		return WBERR_OK;
	}
	else
		return write_header();
}

int MessageImpl::discard()
{
	// ignore outbound messages
	if (IS_OUTBOUND(flags_)) return WBERR_OK;
	// wait for the HTTP header, if needed
	int result = ready();
	if (result != WBERR_OK) return result;
	return WBERR_OK;

	// TODO: implement a better way to discard bytes instead of copying to some buffer

	// discard body data
	while ((result = read((uint8_t*)line_, HTTP_LINE_LENGTH)) >= 0);
	if (result == WBERR_COMPLETE) return WBERR_OK;
	return result;
}

int MessageImpl::write_resource_line()
{
	if (state_ != WBS_IDLE) return WBERR_INVALID_STATE;

	Method method = header.method;
	if (!WB_IS_VALID_METHOD(method)) method = WBM_GET;
	const Target &target = header.target;

	stream_.write(http_method(method));
	stream_.write(' ');
	switch (target.type)
	{
		case WBRT_ABSOLUTE:
			stream_.write((target.scheme == WBS_HTTPS) ? "https://" : "http://");
			stream_.write(target.host);
			stream_.write(':');
			stream_.write(target.port);
			if (target.path[0] != '/') stream_.write('/');
			stream_.write(target.path);
			if (!target.query.empty())
			{
				stream_.write('&');
				stream_.write(target.query);
			}
			break;
		case WBRT_ORIGIN:
			stream_.write(target.path);
			if (!target.query.empty())
			{
				stream_.write('&');
				stream_.write(target.query);
			}
			break;
		case WBRT_ASTERISK:
			stream_.write('*');
			break;
		case WBRT_AUTHORITY:
			stream_.write(target.host);
			stream_.write(':');
			stream_.write(target.port);
			break;
		default:
			return WBERR_INVALID_TARGET;
	}
	stream_.write(" HTTP/1.1\r\n");
	return WBERR_OK;
}

int MessageImpl::write_status_line()
{
	int status = header.status;
	if (status == 0) status = 200;
	const char *desc = http_status_message(status);
	stream_.write("HTTP/1.1 ");
	stream_.write(status);
	stream_.write(' ');
	stream_.write(desc);
	stream_.write("\r\n");
	return WBERR_OK;
}

int MessageImpl::write_header()
{
	if (state_ != WBS_IDLE) return WBERR_INVALID_STATE;

	// first line
	if (IS_RESPONSE(flags_))
		write_status_line();
	else
		write_resource_line();

	// set 'tranfer-encoding' to chunked if required
	if (header.fields.count(WBFI_CONTENT_LENGTH) == 0)
	{
		body_.flags |= WBMF_CHUNKED;
		// TODO: merge with previously set value, if any
		header.fields.set(WBFI_TRANSFER_ENCODING, "chunked");
	}
	if (IS_REQUEST(flags_) && header.fields.count(WBFI_HOST) == 0)
	{
		std::string host = stream_.get_client().get_target().host;
		host += ':';
		host += std::to_string(stream_.get_client().get_target().port);
		header.fields.set(WBFI_HOST, host);
	}

	for (auto item : header.fields)
	{
		stream_.write(item.first);
		stream_.write(": ");
		stream_.write(item.second);
		stream_.write("\r\n");
	}
	stream_.write("\r\n");

	state_ = WBS_BODY;
	return WBERR_OK;
}

int MessageImpl::write( const uint8_t *buffer, int size )
{
	if (state_ == WBS_IDLE)
	{
		int result = write_header();
		if (result != WBERR_OK) return result;
	}
	if (buffer == nullptr || size == 0) return WBERR_OK;

	int result = WBERR_OK;
	if (body_.flags && WBMF_CHUNKED)
	{
		char temp[16];
		SNPRINTF(temp, sizeof(temp)-1, "%X\r\n", size);
		temp[15] = 0;
		result = stream_.write((const uint8_t*) temp, (int) strlen(temp));
		if (result != WBERR_OK) return result;
	}
	result = stream_.write(buffer, size);
	if (result != WBERR_OK) return result;
	if (body_.flags && WBMF_CHUNKED)
		result = stream_.write((const uint8_t*) "\r\n", 2);
	return result;
}

int MessageImpl::write( const char *buffer )
{
	return write((const uint8_t*) buffer, (int) strlen(buffer));
}

int MessageImpl::write( const std::vector<uint8_t> &buffer )
{
	return write(buffer.data(), (int) buffer.size());
}

int MessageImpl::write( const std::string &buffer )
{
	return write((const uint8_t*) buffer.c_str(), (int) buffer.length());
}

int MessageImpl::flush()
{
	if (IS_INBOUND(flags_ )) return WBERR_OK;
	// force headers to be written
	if (state_ == WBS_IDLE)
	{
		int result = ready();
		if (result != WBERR_OK) return result;
	}
	// send buffered data
	return stream_.flush();
}

int MessageImpl::finish()
{
	if (state_ == WBS_COMPLETE) return WBERR_OK;
	if (IS_INBOUND(flags_)) return discard();
	int result;

	// force headers to be written
	if (state_ == WBS_IDLE)
	{
		result = ready();
		if (result != WBERR_OK) return result;
	}
	// send the last marker if using chunked transfer encoding
	if (body_.flags & WBMF_CHUNKED)
	{
		result = stream_.write((const uint8_t*) "0\r\n\r\n", 5);
		if (result != WBERR_OK) return result;
	}
	result = stream_.flush();
	if (result != WBERR_OK) return result;

	// we are done sending data now
	state_ = WBS_COMPLETE;

	return WBERR_OK;
}

} // namespace http_v1
} // namespace webster
