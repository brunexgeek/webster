#include <webster/api.h>
#include <limits.h>
#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <linux/limits.h>


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
	const webster_header_t *header;
	int result = 0;

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
				if (WebsterGetHeader(request, &header) == WBERR_OK)
				{
					printf("%s %s\n", HTTP_METHODS[header->method], header->resource);
					// print all HTTP header fields
					webster_field_t *field = header->fields;
					while (field != NULL)
					{
						printf("  %s: '%s'\n", field->name, field->value);
						field = field->next;
					}
				}
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
	result = WebsterGetHeader(request, &header);
	if (result != WBERR_OK) return result;

    WebsterWriteString(response, "<html><head><title>");
    WebsterWriteString(response, PROGRAM_TITLE);
    WebsterWriteString(response, "</title></head><body>");

    WebsterSetStatus(response, 200);
    WebsterSetStringField(response, "Content-Type", "text/html");
    WebsterWriteString(response, "<p>Received <strong>");
    WebsterWriteString(response, HTTP_METHODS[header->method]);
    WebsterWriteString(response, "</strong> request to <tt style='color: blue'>");
    WebsterWriteString(response, header->resource);
    WebsterWriteString(response, "</tt>!</p>");

    WebsterWriteString(response, "<style type='text/css'>td, th {border: 1px solid #666; padding: .2em} </style>");
    WebsterWriteString(response, "<table><tr><th>Header field</th><th>Value</th></tr>");
    webster_field_t *field = header->fields;
    while (field != NULL)
    {
        WebsterWriteString(response, "<tr><td>");
        WebsterWriteString(response, field->name);
        WebsterWriteString(response, "</td><td>");
        WebsterWriteString(response, field->value);
        WebsterWriteString(response, "</td></tr>");
        field = field->next;
    }
    WebsterWriteString(response, "</body></table></html>");

	WebsterFinish(response);
	return WBERR_OK;
}


int main(int argc, char* argv[])
{
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

	webster_server_t server;

	printf(PROGRAM_TITLE "\n");

	if (WebsterCreate(&server, 100) == WBERR_OK)
	{
		if (WebsterStart(&server, "0.0.0.0", 7000) == WBERR_OK)
		{
			while (serverState == SERVER_RUNNING)
			{
				webster_client_t remote;
				if (WebsterAccept(&server, &remote) != WBERR_OK) continue;
				WebsterCommunicate(&remote, main_serverHandler, NULL);
				WebsterDisconnect(&remote);
			}
		}
		WebsterDestroy(&server);
	}

	printf("Server terminated!\n");

    return 0;
}
