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

#include <webster/api.hh>
#include <iostream>
#include <cstring>

using webster::Message;
using webster::Parameters;
using webster::Target;
using webster::Client;
using webster::Handler;
using webster::Method;

static int main_clientHandler(
    Message &request,
    Message &response,
    void *data )
{
    (void) data;
    (void) response;

    std::cout << "Request to " << request.header.target.path << std::endl;
    request.header.fields["Content-Length"] = "0";
    request.finish();

    const char *ptr = nullptr;
    while (true)
    {
        int result = response.read(&ptr);
        std::cerr << "read is " << result << std::endl;
        if (result != WBERR_OK) break;
        std::cout << "received " << strlen(ptr) << std::endl;
        //std::cout << ptr << std::endl;
    }

    return WBERR_OK;
}


#include <string.h>
int main( int argc, char **argv )
{
    (void) argc;
    (void) argv;

    Parameters params;
    Client client(params);
    Target target;
    if (Target::parse("http://duckduckgo.com:80/", target) != WBERR_OK) return 1;
    if (client.connect(target) == WBERR_OK)
    {
        client.communicate("/", main_clientHandler);
        client.disconnect();
    }
    else
        std::cout << "Failed!\n";

    return 0;
}