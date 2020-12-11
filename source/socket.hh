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
#if !defined(WEBSTER_NO_DEFAULT_NETWORK) && !defined(WEBSTER_SOCKET_HH)
#define WEBSTER_SOCKET_HH

#include <webster.hh> // AUTO-REMOVE

namespace webster {

class SocketNetwork : public Network
{
    public:
        SocketNetwork();
        ~SocketNetwork() = default;
        int open( Channel **channel, Type type );
        int close( Channel *channel );
        int connect( Channel *channel, int scheme, const char *host, int port, int timeout );
        int receive( Channel *channel, uint8_t *buffer, int size, int *received, int timeout );
        int send( Channel *channel, const uint8_t *buffer, int size, int timeout );
        int accept( Channel *channel, Channel **client, int timeout );
        int listen( Channel *channel, const char *host, int port, int maxClients );
    protected:
        int set_non_blocking( Channel *channel );
        int set_reusable( Channel *channel );
};

} // namespace webster

#endif // !WEBSTER_NO_DEFAULT_NETWORK && !WEBSTER_SOCKET_HH