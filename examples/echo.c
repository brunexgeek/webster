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

#include <webster.h>
#include <limits.h>
#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32) || defined(WIN32)
#include <Windows.h>
#else
#include <linux/limits.h>
#endif

#define SERVER_RUNNING    1
#define SERVER_STOPPING   2

#define PROGRAM_TITLE     "Sample HTTP Server"


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


static int main_serverHandler(
    webster_message_t *request,
    webster_message_t *response,
    void *data )
{
	(void) data;

	webster_event_t event;
	const webster_target_t *target = NULL;
	int result = 0;
	int method = 0;

	do
	{
		// wait for some request data
		result = WebsterWaitEvent(request, &event);
		//printf("WebsterWaitEvent = %d\n", result);
		if (result == WBERR_COMPLETE) break;
		if (result == WBERR_NO_DATA) continue;
		if (result != WBERR_OK) return 0;

		if (result == WBERR_OK)
		{
			// check if received the HTTP header
			if (event.type ==  WBT_HEADER)
			{
				WebsterGetMethod(request, &method);
				WebsterGetTarget(request, &target);
				printf("%s %s\n", HTTP_METHODS[method], target->path);
				// print all HTTP header fields
				const char *name;
				const char *value;
				int index = 0;
				while (WebsterIterateField(request, index++, NULL, &name, &value) == WBERR_OK)
					printf("  %s: '%s'\n", name, value);
			}
			else
			// check if we received the HTTP body (or part of it)
			if (event.type == WBT_BODY)
			{
				const uint8_t *ptr = NULL;
				int size = 0;
				WebsterReadData(request, &ptr, &size);
				for (int i = 0; i < size; ++i)
				{
					if (i != 0 && i % 8 == 0) printf("\n");
					printf("%02X ", ptr[i]);
				}
			}
		}
	} while (1);

	// doing it again, but not necessary if the first call succeed
	result = WebsterGetTarget(request, &target);
	if (result != WBERR_OK) return result;
	result = WebsterGetMethod(request, &method);
	if (result != WBERR_OK) return result;

    WebsterWriteString(response, "<html><head><title>");
    WebsterWriteString(response, PROGRAM_TITLE);
    WebsterWriteString(response, "</title></head><body>");

    WebsterSetStatus(response, 200);
    WebsterSetStringField(response, "Content-Type", "text/html");
    WebsterWriteString(response, "<p>Received <strong>");
    WebsterWriteString(response, HTTP_METHODS[method]);
    WebsterWriteString(response, "</strong> request to <tt style='color: blue'>");
    WebsterWriteString(response, target->path);
    WebsterWriteString(response, "</tt>");
	if (target->query != NULL)
	{
		WebsterWriteString(response, " with query <tt style='color: blue'>");
		WebsterWriteString(response, target->query);
		WebsterWriteString(response, "</tt>");
	}
	WebsterWriteString(response, "</p>");

    WebsterWriteString(response, "<style type='text/css'>td, th {border: 1px solid #666; padding: .2em} </style>");
    WebsterWriteString(response, "<table><tr><th>Header field</th><th>Value</th></tr>");
	const char *name;
	const char *value;
	int index = 0;
	while (WebsterIterateField(request, index++, NULL, &name, &value) == WBERR_OK)
	{
        WebsterWriteString(response, "<tr><td>");
        WebsterWriteString(response, name);
        WebsterWriteString(response, "</td><td>");
        WebsterWriteString(response, value);
        WebsterWriteString(response, "</td></tr>");
	}
	WebsterWriteString(response, "</body></table></html>");

	WebsterFinish(response);
	return WBERR_OK;
}


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

	webster_server_t *server = NULL;

	printf(PROGRAM_TITLE "\n");

	WebsterInitialize(NULL);
	if (WebsterCreate(&server, NULL) == WBERR_OK)
	{
		webster_target_t *target;
		WebsterParseURL("0.0.0.0:7000", &target);
		if (WebsterStart(server, target) == WBERR_OK)
		{
			while (serverState == SERVER_RUNNING)
			{
				webster_client_t *remote = NULL;
				int result = WebsterAccept(server, &remote);
				if (result == WBERR_OK)
				{
					WebsterCommunicate(remote, NULL, main_serverHandler, NULL);
					WebsterDisconnect(remote);
				}
				else
				if (result != WBERR_TIMEOUT) break;
			}
		}
		WebsterDestroy(server);
	}
	WebsterTerminate();
	printf("Server terminated!\n");

    return 0;
}
