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
#include <limits.h>
#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <iostream>

#if defined(_WIN32) || defined(WIN32)
#include <Windows.h>
#else
#include <linux/limits.h>
#endif

#define SERVER_RUNNING    1
#define SERVER_STOPPING   2

#define PROGRAM_TITLE     "Sample HTTP Server"

using namespace webster;

static int serverState = SERVER_RUNNING;

static const char *HTTP_METHODS[] =
{
    "",
    "GET",
    "HEAD",
    "POST",
    "PUT",
    "DELETE",
    "CONNECT",
    "OPTIONS",
    "TRACE"
};


#if defined(_WIN32) || defined(WIN32)

static BOOL WINAPI main_signalHandler(
  _In_ DWORD dwCtrlType )
{
	(void) dwCtrlType;
	serverState = SERVER_STOPPING;
	return TRUE;
}

#else

static void main_signalHandler(
	int handle )
{
	(void) handle;
	if (serverState == SERVER_STOPPING) exit(1);
	serverState = SERVER_STOPPING;
}

#endif


struct EchoHandler
{
	int operator()(
		Message &request,
		Message &response )
	{
		// discards the body
		const uint8_t *buffer;
		int size;
		while (request.read(&buffer, &size) == WBERR_OK);
	std::cout << "Received everything!\n";
		response.header.status = 200;
		response.header.fields["Content-Type"] = "text/html";
		response.write("<html><head><title>");
		response.write(PROGRAM_TITLE);
		response.write("</title></head><body>");

		response.write("<p>Received <strong>");
		response.write(HTTP_METHODS[request.header.method]);
		response.write("</strong> request to <tt style='color: blue'>");
		response.write(request.header.target.path);
		response.write("</tt>");
		if (!request.header.target.query.empty())
		{
			response.write(" with query <tt style='color: blue'>");
			response.write(request.header.target.query);
			response.write("</tt>");
		}
		response.write("</p>");

		response.write("<style type='text/css'>td, th {border: 1px solid #666; padding: .2em} </style>");
		response.write("<table><tr><th>Header field</th><th>Value</th></tr>");
		for (auto &item : request.header.fields)
		{
			response.write("<tr><td>");
			response.write(item.first);
			response.write("</td><td>");
			response.write(item.second);
			response.write("</td></tr>");
		}
		response.write("</body></table></html>");

		response.finish();
		return WBERR_OK;
	}
};

int main(int argc, char* argv[])
{
    (void) argc;
    (void) argv;

	#if defined(_WIN32) || defined(WIN32)

	SetConsoleCtrlHandler(main_signalHandler, TRUE);

	#else

	// install the signal handler to stop the server with CTRL + C
	struct sigaction act;
	sigemptyset(&act.sa_mask);
	sigaddset(&act.sa_mask, SIGINT);
	act.sa_flags = 0;
    act.sa_handler = main_signalHandler;
    sigaction(SIGINT, &act, NULL);

	#endif

	printf(PROGRAM_TITLE "\n");

	Parameters params;
	Server server(params);
	Target target;
	target.type = WBRT_AUTHORITY;
	target.host = "localhost";
	target.port = 7000;
	if (server.start(target) == WBERR_OK)
	{
		EchoHandler handler;
		while (serverState == SERVER_RUNNING)
		{
			std::shared_ptr<Client> remote;
			int result = server.accept(remote);
			if (result == WBERR_OK)
			{
				remote->communicate("", handler);
				remote->disconnect();
			}
			else
			if (result != WBERR_TIMEOUT) break;
		}
	}
	server.stop();
	std::cerr << "Server terminated!\n";

    return 0;
}
