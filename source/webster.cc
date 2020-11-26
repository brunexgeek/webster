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

#if defined(_WIN32) || defined(WIN32)
#define WB_WINDOWS
#endif

#include <webster.hh>
#include <ctype.h>
#include <string>
#include <memory>
#include <sstream>
#include <iostream>
#include <cstring> // strlen strstr strchr
#include <chrono>

#include "network.hh"
#include "stream.hh"
#include "http1.hh"

namespace webster {

typedef std::shared_ptr<Network> NetworkPtr;

extern std::shared_ptr<SocketNetwork> DEFAULT_NETWORK;

uint64_t tick()
{
    auto now = std::chrono::steady_clock::now().time_since_epoch();
	return std::chrono::duration_cast<std::chrono::milliseconds>(now).count();
}

Target::Target()
{
	clear();
}

static std::string string_cut(
    const char *text,
    size_t offset,
    size_t length )
{
    if (text == nullptr) return nullptr;

    size_t len = strlen(text);
    if (offset + length > len) return nullptr;

    std::string output;
    for (size_t i = offset; i < offset + length; ++i) output += text[i];
    return output;
}

static int hex_digit( uint8_t digit )
{
    if (digit >= '0' && digit <= '9')
        return digit - '0';
    if (digit >= 'a' && digit <= 'f')
        digit = (uint8_t) (digit - 32);
    if (digit >= 'A' && digit <= 'F')
        return digit - 'A' + 10;
    return 0;
}

std::string Target::decode( const std::string &input )
{
    const uint8_t *i = (const uint8_t*) input.c_str();
    std::string out;

    while (*i != 0)
    {
        if (*i == '%' && isxdigit(*(i + 1)) && isxdigit(*(i + 2)))
        {
            out += (uint8_t) (hex_digit(*(i + 1)) * 16 + hex_digit(*(i + 2)));
            i += 3;
        }
        else
        {
            out += *i;
            ++i;
        }
    }

    return out;
}

std::string Target::encode( const std::string &input )
{
	const char *SYMBOLS = "0123456789abcdef";
	std::string out;

	for (char i : input)
	{
		uint8_t c = (uint8_t) i;
		if ((c >= 'A' && c <= 'Z') ||
			(c >= 'a' && c <= 'z') ||
			(c >= '0' && c <= '9') ||
			c == '-' || c == '_' ||
			c == '.' || c == '~')
			out += i;
		else
		{
			out += '%';
			out += SYMBOLS[c >> 4];
			out += SYMBOLS[c & 0x0F];
		}
	}
	return out;
}

int Target::parse( const char *url, Target &target )
{
    if (url == nullptr || url[0] == 0) return WBERR_INVALID_TARGET;

    // handle asterisk form
    if (url[0] == '*' && url[1] == 0)
        target.type = WBRT_ASTERISK;
    else
    // handle origin form
    if (url[0] == '/')
    {
        target.type = WBRT_ORIGIN;

        const char *ptr = url;
        while (*ptr != '?' && *ptr != 0) ++ptr;

        if (*ptr == '?')
        {
            size_t pos = (size_t) (ptr - url);
            target.path = string_cut(url, 0, pos);
            target.query = string_cut(url, pos + 1, strlen(url) - pos - 1);
        }
        else
        {
            target.path = std::string(url);
        }

        target.path = Target::decode(target.path);
        target.query = Target::decode(target.query);
    }
    else
    // handle absolute form
    if (tolower(url[0]) == 'h' &&
		tolower(url[1]) == 't' &&
		tolower(url[2]) == 't' &&
		tolower(url[3]) == 'p' &&
		(tolower(url[4]) == 's' || url[4] == ':'))
	{
        target.type = WBRT_ABSOLUTE;

		// extract the host name
		const char *hb = strstr(url, "://");
		if (hb == nullptr) return WBERR_INVALID_TARGET;
		hb += 3;
		const char *he = hb;
		while (*he != ':' && *he != '/' && *he != 0) ++he;
		if (hb == he) return WBERR_INVALID_TARGET;

		const char *rb = he;
		const char *re = nullptr;

		// extract the port number, if any
		const char *pb = he;
		const char *pe = nullptr;
		if (*pb == ':')
		{
			pe = ++pb;
			while (*pe >= '0' && *pe <= '9' && *pe != 0) ++pe;
			if (pb == pe || (pe - pb) > 5) return WBERR_INVALID_TARGET;
			rb = pe;
		}

		// extract the resource
		if (*rb == '/')
		{
			re = rb;
			while (*re != 0) ++re;
		}
		if (re != nullptr && *re != 0) return WBERR_INVALID_TARGET;

		// return the scheme
		if (url[4] == ':')
			target.scheme = WBS_HTTP;
		else
			target.scheme = WBS_HTTPS;

		// return the port number, if any
		if (pe != nullptr)
		{
			target.port = 0;
			int mult = 1;
			while (--pe >= pb)
			{
				target.port += (int) (*pe - '0') * mult;
				mult *= 10;
			}
			if (target.port > 65535 || target.port < 0)
                return WBERR_INVALID_TARGET;
		}
		else
		{
			if (target.scheme == WBS_HTTP)
				target.port = 80;
			else
				target.port = 443;
		}

		// return the host
        target.host = string_cut(hb, 0, (size_t) (he - hb));

		// return the resource, if any
		if (re != nullptr)
			target.path = string_cut(rb, 0, (size_t) (re - rb));
		else
			target.path = "/";

		target.path = Target::decode(target.path);
        target.query = Target::decode(target.query);
	}
    else
    // handle authority form
    {
        target.type = WBRT_AUTHORITY;

        const char *hb = strchr(url, '@');
        if (hb != nullptr)
        {
            target.user = string_cut(url, 0, (size_t) (hb - url));
            hb++;
        }
        else
            hb = url;

        const char *he = strchr(hb, ':');
        if (he != nullptr)
        {
            target.host = string_cut(hb, 0, (size_t) (he - hb));
            target.port = 0;

            const char *pb = he + 1;
            const char *pe = pb;
            while (*pe >= '0' && *pe <= '9' && *pe != 0) ++pe;
            if (*pe != 0) return WBERR_INVALID_TARGET;

			int mult = 1;
			while (--pe >= pb)
			{
				target.port += (int) (*pe - '0') * mult;
				mult *= 10;
			}
			if (target.port > 65535 || target.port < 0)
                return WBERR_INVALID_TARGET;
        }
        else
        {
            target.host = std::string(hb);
            target.port = 80;
        }
    }

    return WBERR_OK;
}

int Target::parse( const std::string &url, Target &target )
{
	return parse(url.c_str(), target);
}

void Target::swap( Target &that )
{
	std::swap(type, that.type);
	std::swap(scheme, that.scheme);
	user.swap(that.user);
	host.swap(that.path);
	std::swap(port, that.port);
	path.swap(that.path);
	query.swap(that.query);
}

void Target::clear()
{
	type = port = 0;
	scheme = WBS_HTTP;
	user.clear();
	host.clear();
	path.clear();
	query.clear();
}

static void fix_parameters( Parameters &params )
{
	if (params.max_clients <= 0)
		params.max_clients = WBL_DEF_CONNECTIONS;
	else
	if (params.max_clients > WBL_MAX_CONNECTIONS)
		params.max_clients = WBL_MAX_CONNECTIONS;

	if (params.buffer_size == 0)
		params.buffer_size = WBL_DEF_BUFFER_SIZE;
	else
	if (params.buffer_size > WBL_MAX_BUFFER_SIZE)
		params.buffer_size = WBL_MAX_BUFFER_SIZE;
	params.buffer_size = (uint32_t) (params.buffer_size + 3) & (uint32_t) (~3);

	if (params.read_timeout < 0)
		params.read_timeout = WBL_DEF_TIMEOUT;
	else
	if (params.read_timeout > WBL_MAX_TIMEOUT)
		params.read_timeout = WBL_MAX_TIMEOUT;

	if (params.write_timeout < 0)
		params.write_timeout = WBL_DEF_TIMEOUT;
	else
	if (params.write_timeout > WBL_MAX_TIMEOUT)
		params.write_timeout = WBL_MAX_TIMEOUT;
}

Parameters::Parameters() : max_clients(WBL_DEF_CONNECTIONS), buffer_size(WBL_DEF_BUFFER_SIZE),
	read_timeout(WBL_DEF_TIMEOUT), write_timeout(WBL_DEF_TIMEOUT), connect_timeout(WBL_DEF_TIMEOUT * 2)
{
    #ifndef WEBSTER_NO_DEFAULT_NETWORK
	network = DEFAULT_NETWORK;
	#endif
}

Parameters::Parameters( const Parameters &that )
{
    #ifndef WEBSTER_NO_DEFAULT_NETWORK
	network = DEFAULT_NETWORK;
	#endif

    if (that.network) network = that.network;
    max_clients = that.max_clients;
    buffer_size = that.buffer_size;
    read_timeout = that.read_timeout;
    write_timeout = that.write_timeout;
    connect_timeout = that.connect_timeout;

	fix_parameters(*this);
}

Server::Server() : channel_(nullptr)
{
}

Server::Server( Parameters params ) : Server()
{
	params_ = params;
}

Server::~Server()
{
	stop();
}

int Server::start( const Target &target )
{
	if ((target.type & WBRT_AUTHORITY) == 0) return WBERR_INVALID_TARGET;
	target_ = target;

	int result = params_.network->open(&channel_, Network::SERVER);
	if (result != WBERR_OK) return result;

	return params_.network->listen(channel_, target_.host.c_str(), target_.port, params_.max_clients);
}

int Server::stop()
{
	if (channel_ == nullptr) return WBERR_OK;
	params_.network->close(channel_);
	channel_ = nullptr;
	return WBERR_OK;
}

int Server::accept( std::shared_ptr<Client> &remote )
{
	Channel *channel = nullptr;
	int result = params_.network->accept(channel_, &channel, params_.read_timeout);
	if (result != WBERR_OK) return result;

	remote = std::shared_ptr<Client>(new (std::nothrow) Client(params_, WBCT_REMOTE));
	if (remote == nullptr)
	{
		params_.network->close(channel);
		return WBERR_MEMORY_EXHAUSTED;
	}
	remote->channel_ = channel;

	return WBERR_OK;
}

const Parameters &Server::get_parameters() const
{
	return params_;
}

const Target &Server::get_target() const
{
	return target_;
}

Client::Client( ClientType type ) : channel_(nullptr), proto_(WBCP_HTTP_1), type_(type)
{
}

Client::Client( Parameters params, ClientType type ) : Client(type)
{
	params_ = params;
}

Client::~Client()
{
	disconnect();
}

int Client::connect( const Target &target )
{
	#ifdef WEBSTER_NO_DEFAULT_NETWORK
	if (!params->network) return WBERR_INVALID_ARGUMENT;
	#endif

	// try to connect with the remote host
	int result = params_.network->open(&this->channel_, Network::CLIENT);
	if (result != WBERR_OK) return result;
	result = params_.network->connect(this->channel_, target.scheme, target.host.c_str(), target.port,
		params_.connect_timeout );
	if (result != WBERR_OK)
    {
        params_.network->close(this->channel_);
        this->channel_ = nullptr;
        return result;
    }
	target_ = target;

	return WBERR_OK;
}

int Client::get_protocol() const
{
	return proto_;
}

Channel *Client::get_channel()
{
	return channel_;
}

ClientType Client::get_type() const
{
	return type_;
}

bool Client::is_connected() const
{
	return channel_ != nullptr;
}

const Parameters &Client::get_parameters() const
{
	return params_;
}

const Target &Client::get_target() const
{
	return target_;
}

int Client::disconnect()
{
	if (channel_ == nullptr) return WBERR_OK;
	params_.network->close(channel_);
	channel_ = nullptr;
	return WBERR_OK;
}

} // namespace webster


