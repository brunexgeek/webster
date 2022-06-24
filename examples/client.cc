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

#include <webster.hh>
#include <iostream>
#include <cstring>

#define PROGRAM_TITLE     "Sample HTTP Client"

using namespace webster;

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

    if (response.header.fields.count(WBFI_CONTENT_LENGTH))
        std::cout << "--- Expected " << response.header.fields.get(WBFI_CONTENT_LENGTH) << " bytes" << std::endl;
    else
        std::cout << "--- Expected chunked data" << std::endl;

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

    std::cerr << PROGRAM_TITLE << std::endl;
	std::cerr << "Using Webster " << WEBSTER_VERSION << std::endl;

    const char *url = "http://duckduckgo.com:80/";
    if (argc > 1) url = argv[1];

    HttpClient client;
    int result = client.open(url);
    if (result == WBERR_OK)
    {
        HttpListener listener(main_clientHandler);
        client.communicate(listener);
        client.close();
    }
    else
        std::cerr << "Failed with " << result << "!\n";

    return 0;
}