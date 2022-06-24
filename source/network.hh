/*
 *   Copyright 2016-2022 Bruno Ribeiro
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

#ifndef WEBSTER_NETWORK_HH
#define WEBSTER_NETWORK_HH

#include <webster.hh> // AUTO-REMOVE

namespace webster {

class Server;

class Client
{
    public:
        friend Server;
        Client( ClientType type = WBCT_LOCAL );
        Client( Parameters params, ClientType type = WBCT_LOCAL );
        ~Client();
        int connect( const Target &target );
        int disconnect();
        const Parameters &get_parameters() const;
        const Target &get_target() const;
        bool is_connected() const;
        Channel *get_channel();
        ClientType get_type() const;

    protected:
        Parameters params_;
        Channel *channel_;
        Target target_;
        ClientType type_;
};

class Server
{
    public:
        Server();
        Server( Parameters params );
        virtual ~Server();
        virtual int start( const Target &target );
        virtual int stop();
        virtual int accept( Client **remote );
        virtual const Parameters &get_parameters() const;
        virtual const Target &get_target() const;
    protected:
        Parameters params_;
        Channel *channel_;
        Target target_;
};

} // namespace webster

#endif // WEBSTER_NETWORK_HH