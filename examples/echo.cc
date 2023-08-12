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

#include <webster.hh>
#include <limits.h>
#include <signal.h>
#include <cstring>
#include <iostream>

#ifdef WB_WINDOWS
#include <windows.h>
#else
#include <linux/limits.h>
#endif

#define PROGRAM_TITLE     "Sample HTTP Server"

using namespace webster;

// Bootstrap's 'asterisk' icon (under MIT license)
// https://icons.getbootstrap.com/icons/asterisk/
static const char *ICON = "<svg width='1em' height='1em' viewBox='0 0 16 16' class='bi bi-asterisk'"
	" fill='currentColor' xmlns='http://www.w3.org/2000/svg'><path fill-rule='evenodd' d='M8 0a1 1 "
	"0 0 1 1 1v5.268l4.562-2.634a1 1 0 1 1 1 1.732L10 8l4.562 2.634a1 1 0 1 1-1 1.732L9 9.732V15a1 "
	"1 0 1 1-2 0V9.732l-4.562 2.634a1 1 0 1 1-1-1.732L6 8 1.438 5.366a1 1 0 0 1 1-1.732L7 6.268V1a1"
	" 1 0 0 1 1-1z'/></svg>";

static bool is_running = true;

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
	is_running = true;
	return TRUE;
}

#else

static void main_signalHandler(
	int handle )
{
	(void) handle;
	if (is_running == false) exit(1);
	is_running = true;
}

#endif

struct EchoListener : public webster::HttpListener
{
	int operator()( webster::Message &request, webster::Message &response )
	{
		request.finish();
		std::cerr << "  Request to " << request.header.target.path << std::endl;

		if (request.header.target.path == "/favicon.ico")
		{
			response.header.status = 200;
			response.header.fields.set("Content-Type", "image/svg+xml");
			response.header.fields.set("Content-Length", strlen(ICON));
			response.write(ICON);
			return WBERR_OK;
		}

		response.header.status = 200;
		response.header.fields["Content-Type"] = "text/html";
		response << "<html><head><title>" << PROGRAM_TITLE << "</title><meta charset='utf-8'/></head><body>";

		response << "<p>Received <strong>" << HTTP_METHODS[request.header.method] <<
			"</strong> request to <tt style='color: blue'>" << request.header.target.path <<
			"</tt>";
		if (!request.header.target.query.empty())
		{
			response << " with query <tt style='color: blue'>" << request.header.target.query << "</tt>";
		}
		response << "</p>";

		// query parameters
		if (!request.header.target.query.empty())
		{
			QueryFields qf;
			qf.deserialize(request.header.target.query);

			response << "<style type='text/css'>td, th {border: 1px solid #666; padding: .2em} </style>" <<
				"<table><tr><th>Query field</th><th>Value</th></tr>";
			for (auto &item : qf)
			{
				response << "<tr><td>" << item.first << "</td><td>" << item.second << "</td></tr>";
			}
			std::string data;
			request.read_all(data);
			response << "</table></body>" << "<b>Body (" << data.length() << " bytes):</b>" << data << "</html>";
		}

		// header fields
		response << "<style type='text/css'>td, th {border: 1px solid #666; padding: .2em} </style>" <<
			"<table><tr><th>Header field</th><th>Value</th></tr>";
		for (auto &item : request.header.fields)
		{
			response << "<tr><td>" << item.first << "</td><td>" << item.second << "</td></tr>";
		}
		std::string data;
		request.read_all(data);
		response << "</table></body>" << "<b>Body (" << data.length() << " bytes):</b>" << data << "</html>";
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

	// install the signal listener to stop the server with CTRL + C
	struct sigaction act;
	sigemptyset(&act.sa_mask);
	sigaddset(&act.sa_mask, SIGINT);
	act.sa_flags = 0;
    act.sa_handler = main_signalHandler;
    sigaction(SIGINT, &act, NULL);

	#endif

	std::cerr << PROGRAM_TITLE << std::endl;
	std::cerr << "Using Webster " << WEBSTER_VERSION << std::endl;

	Parameters params;
	//params.buffer_size = 88;
	HttpServer server(params);
	if (server.start("http://localhost:7000") == WBERR_OK)
	{
		EchoListener listener;
		while (is_running)
		{
			HttpClient *remote = nullptr;
			// wait for connections (uses `read_timeout`from `Parameters` class)
			int result = server.accept(&remote);
			if (result == WBERR_OK)
			{
				std::cerr << "Connection stabilished" << std::endl;

				// keep processing requests until some error occurs
				while (is_running && (result = remote->communicate(listener)) == WBERR_OK);
				// close the client (optional, closed by destructor) and destroy the object
				remote->close();
				delete remote;

				std::cerr << "Connection closed" << std::endl;
			}
			else
			// `HttpServer::accept` will return `WBERR_TIMEOUT` if there were no connections
			if (result != WBERR_TIMEOUT)
				break;
		}
	}
	server.stop();
	std::cerr << "Server terminated!\n";

    return 0;
}
