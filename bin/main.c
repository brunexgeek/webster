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


static int handlerFunction(
    webster_input_t *request,
    webster_output_t *response,
    void *data )
{
	(void) data;

	int type, size;

	do
	{
		// wait for some request data
		int result = WebsterWait(request, &type, &size);

		// check if we have data
		if (result == WBERR_NO_DATA) continue;

		if (result == WBERR_OK)
		{
			// check if received the HTTP header
			if (type ==  WB_TYPE_HEADER)
			{
				const char *resource = NULL;
				if (WebsterGetResource(request, &resource) == WBERR_OK)
					printf("Requested resource: %s\n", resource);
				// print all HTTP header fields
				int count = 0;
				const webster_field_t *headers;
				if (WebsterGetHeaderFields(request, &headers, &count) == WBERR_OK)
				{
					for (int i = 0; i < count; ++i)
						printf("  %s: '%s'\n", headers[i].name, headers[i].value);
				}
			}
			else
			// check if we received the HTTP body (or part of it)
			if (type == WB_TYPE_BODY)
			{
				const uint8_t *ptr = NULL;
				int size = 0;
				WebsterGetData(request, &ptr, &size);
				for (int i = 0; i < size; ++i)
				{
					if (i != 0 && i % 8 == 0) printf("\n");
					printf("%02X ", ptr[i]);
				}
				printf("Received %d bytes\n", size);
			}
		}
		else
		if (result == WBERR_COMPLETE)
		{
			WebsterSetStatus(response, 404);

			const char *resource = NULL;
			char *fileName = NULL;
			if (WebsterGetResource(request, &resource) == WBERR_OK)
			{
				char temp[512];
				strncpy(temp, rootDirectory, sizeof(temp) - 1);
				strncat(temp, resource, sizeof(temp) - 1);
				fileName = realpath(temp, NULL);

				printf("Request completed! Returning data from %s\n", fileName);

				if (fileName != NULL && strstr(fileName, rootDirectory) == fileName)
				{
					char buffer[1024];
					struct stat info;

					WebsterSetStatus(response, 200);

					if (stat(fileName, &info) == 0)
					{
						snprintf(buffer, sizeof(buffer) - 1, "%d", (int) info.st_size);
						WebsterWriteHeaderField(response, "Content-Length", buffer);
						printf("Content length is %s\n", buffer);
					}

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
			}

			break;
		}
		else
			break;

	} while (1);

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
				WebsterAccept(&server, handlerFunction, NULL);
		}
		WebsterDestroy(&server);
	}

	printf("Server terminated!\n");

    return 0;
}
