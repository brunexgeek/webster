#define _POSIX_C_SOURCE 200112L

#include <webster/api.h>
#include <limits.h>
#include <stdio.h>
#include <signal.h>
#include <setjmp.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <linux/limits.h>
#include <dirent.h>


#define SERVER_RUNNING    1
#define SERVER_STOPPING   2

#define PROGRAM_TITLE     "Webster HTTP Server"


static int serverState = SERVER_RUNNING;

static char rootDirectory[PATH_MAX];

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


static void main_signalHandler(
	int handle )
{
	(void) handle;
	serverState = SERVER_STOPPING;
}


static void main_downloadFile(
	webster_message_t *response,
	const char *fileName,
	int contentLength )
{
	if (fileName == NULL || strstr(fileName, rootDirectory) != fileName) return;

	char buffer[1024];

	WebsterSetStatus(response, 200);
	WebsterSetIntegerField(response, "Content-Length", contentLength);
	WebsterSetStringField(response, "Server", PROGRAM_TITLE);

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

	printf("Returned %d bytes from %s\n", contentLength, fileName);
}


static void main_listDirectory(
	webster_message_t *response,
	const char *fileName )
{
	static const char *DIR_FORMAT = "<li><strong><a href='%s/%s'>[%s]</a></strong></li>";
	static const char *FIL_FORMAT = "<li><a href='%s/%s'>%s</a></li>";

	char temp[1024];

	WebsterSetStringField(response, "Server", PROGRAM_TITLE);

	snprintf(temp, sizeof(temp) - 1, "<html><head><title>" PROGRAM_TITLE
		"</title></head><body style='font-family: monospace; font-size: 16px; line-height: 22px;'><ul><h1>%s</h1>", fileName);
	WebsterWriteString(response, temp);

	DIR *dr = opendir(fileName);
	struct dirent *de = NULL;
	if (dr != NULL)
	{
		int length = (int) strlen(rootDirectory);
		while ((de = readdir(dr)) != NULL)
		{
			const char *format;
			if (de->d_type == DT_DIR)
				format = DIR_FORMAT;
			else
			if (de->d_type == DT_REG)
				format = FIL_FORMAT;
			else
				continue;

			snprintf(temp, sizeof(temp) - 1, format, fileName + length, de->d_name, de->d_name);
			temp[sizeof(temp) - 1] = 0;
			WebsterWriteString(response, temp);
		}
	}
	closedir(dr);

	WebsterWriteString(response, "</ul></body>");
}


static int main_serverHandler(
    webster_message_t *request,
    webster_message_t *response,
    void *data )
{
	(void) data;

	#if 0
	if (requests > 1) return 0;
	++requests;
	#endif

	webster_event_t event;
	const webster_header_t *header;
	int result = 0;

	do
	{
		// wait for some request data
		result = WebsterWaitEvent(request, &event);
		printf("WebsterWaitEvent = %d\n", result);
		if (result == WBERR_COMPLETE) break;
        if (result == WBERR_TIMEOUT) return 0;
		if (result == WBERR_NO_DATA) continue;

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
				printf("Waiting for body\n");
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
	if (info.st_mode & S_IFREG)
	{
		WebsterSetStatus(response, 200);
		main_downloadFile(response, fileName, (int) info.st_size);
	}
	else
	if (info.st_mode & S_IFDIR)
	{
		WebsterSetStatus(response, 200);
		main_listDirectory(response, fileName);
	}
	else
	{
		WebsterSetIntegerField(response, "Content-Length", 14);
		WebsterWriteString(response, "Invalid entity");
	}

	free(fileName);
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

	printf(PROGRAM_TITLE "\n");
	printf("Root directory is %s\n", rootDirectory);

	if (WebsterCreate(&server, 100) == WBERR_OK)
	{
		if (WebsterStart(&server, "0.0.0.0", 7000) == WBERR_OK)
		{
			while (serverState == SERVER_RUNNING)
				WebsterAccept(&server, main_serverHandler, NULL);
		}
		WebsterDestroy(&server);
	}

	printf("Server terminated!\n");

    return 0;
}
