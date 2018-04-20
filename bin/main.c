#include <webster/api.h>
#include <stdio.h>
#include <signal.h>
#include <setjmp.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <linux/limits.h>


#define SERVER_RUNNING    1
#define SERVER_STOPPING   2


static int serverState = SERVER_RUNNING;

static char rootDirectory[PATH_MAX];


static void main_signalHandler(
	int handle )
{
	(void) handle;
	serverState = SERVER_STOPPING;
}


static int main_handlerFunction(
    webster_input_t *request,
    webster_output_t *response,
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
		if (result == WBERR_COMPLETE) break;

		// check if we have data
		if (result == WBERR_NO_DATA) continue;

		if (result == WBERR_OK)
		{
			// check if received the HTTP header
			if (event.type ==  WB_TYPE_HEADER)
			{
				if (WebsterGetHeader(request, &header) == WBERR_OK)
				{
					printf("Requested resource: %s\n", header->resource);
					// print all HTTP header fields
					for (int i = 0; i < header->fieldCount; ++i)
						printf("  %s: '%s'\n", header->fields[i].name, header->fields[i].value);
				}
			}
			else
			// check if we received the HTTP body (or part of it)
			if (event.type == WB_TYPE_BODY)
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

	// assume HTTP 404
	WebsterSetStatus(response, 404);

	// doing it again, but not necessary if the first call succeed
	result = WebsterGetHeader(request, &header);
	if (result != WBERR_OK) return result;
	// build the local file name
	char *fileName = NULL;
	char temp[512];
	strncpy(temp, rootDirectory, sizeof(temp) - 1);
	strncat(temp, header->resource, sizeof(temp) - 1);
	fileName = realpath(temp, NULL);

	struct stat info;
	if (stat(fileName, &info) != 0) return WBERR_OK;
	if ((info.st_mode & S_IFREG) == 0)
	{
		snprintf(temp, sizeof(temp) - 1, "%d", 12);
		WebsterWriteHeaderField(response, "Content-Length", temp);
		WebsterWriteString(response, "Invalid file");
		return WBERR_OK;
	}

	printf("Request completed! Returning data from %s\n", fileName);

	if (fileName != NULL && strstr(fileName, rootDirectory) == fileName)
	{
		char buffer[1024];

		WebsterSetStatus(response, 200);

		snprintf(temp, sizeof(temp) - 1, "%d", (int) info.st_size);
		WebsterWriteHeaderField(response, "Content-Length", temp);
		printf("Content length is %s\n", temp);

		FILE *fp = fopen(fileName, "rb");
		if (fp != NULL)
		{
			size_t read = 0;
			do {
				read = fread(buffer, 1, sizeof(buffer), fp);
				if (read > 0) WebsterWriteData(response, (uint8_t*) buffer, (int) read);
			} while (read > 0);
			fclose(fp);
		}

		free(fileName);
	}

	return 0;
}


int main(int argc, char* argv[])
{
	// install the signal handler to stop the server with CTRL + C
	struct sigaction act;
	sigemptyset(&act.sa_mask);
	sigaddset(&act.sa_mask, SIGINT);
	act.sa_flags = 0;
    act.sa_handler = main_signalHandler;
    sigaction(SIGINT, &act, NULL);

	if (argc == 2)
		realpath(argv[1], rootDirectory);
	else
		realpath(".", rootDirectory);

	webster_server_t server;

	printf("Webster HTTP Server\n");
	printf("Root directory is %s\n", rootDirectory);

	if (WebsterCreate(&server, 100) == WBERR_OK)
	{
		if (WebsterStart(&server, "127.0.0.1", 7000) == WBERR_OK)
		{
			while (serverState == SERVER_RUNNING)
				WebsterAccept(&server, main_handlerFunction, NULL);
		}
		WebsterDestroy(&server);
	}

	printf("Server terminated!\n");

    return 0;
}
