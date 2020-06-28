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
    Message &response )
{
    std::cout << "--- Request to " << request.header.target.path << std::endl;
    request.header.fields["Content-Length"] = "0";
    request.finish();

    response.ready();
    std::cout << "--- Expected " << response.header.fields.get(WBFI_CONTENT_LENGTH) << std::endl;
    #if 0
    char ptr[1024];
    while (response.read(ptr, sizeof(ptr)) >= 0)
        std::cout << ptr << std::endl;
    #else
    std::string buffer;
    if (response.read_all(buffer) == WBERR_OK)
        std::cout << buffer << std::endl;
    #endif

    return WBERR_OK;
}


#include <string.h>
int main( int argc, char **argv )
{
    (void) argc;
    (void) argv;

    const char *url = "http://duckduckgo.com:80/";
    if (argc > 1) url = argv[1];

    Parameters params;
    Client client(params);
    Target target;
    Handler handler(main_clientHandler);
    if (Target::parse(url, target) != WBERR_OK) return 1;
    if (client.connect(target) == WBERR_OK)
    {
        client.communicate(target.path, handler);
        client.disconnect();
    }
    else
        std::cout << "Failed!\n";

    return 0;
}