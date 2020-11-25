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

using namespace webster::http;
using webster::Parameters;
using webster::Target;
using webster::Client;

static int main_clientHandler(
    Message &request,
    Message &response )
{
    std::cout << "--- Request to " << request.header.target.path << std::endl;
    request.header.fields["Content-Length"] = "0";
    request.finish();

    int result = response.ready();
    if (result != WBERR_OK)
    {
        std::cerr << "Error " << result << std::endl;
        return result;
    }
    std::cout << "--- Expected " << response.header.fields.get(WBFI_CONTENT_LENGTH) << std::endl;
    #if 0
    // read in blocks with application buffer
    char ptr[1024];
    while (response.read(ptr, sizeof(ptr)) >= 0)
        std::cout << ptr << std::endl;
    #else
    // read everything with Webster internal buffer
    std::string buffer;
    result = response.read_all(buffer);
    if (result == WBERR_OK)
        std::cout << buffer << std::endl;
    else
        std::cerr << "Error reading data " << result << std::endl;
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
        webster::http::v1::Manager http(&client, &handler);
        http.communicate(target.path);
        client.disconnect();
    }
    else
        std::cout << "Failed!\n";

    return 0;
}