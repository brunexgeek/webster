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


static void main_signalHandler(
	int handle )
{
	(void) handle;
	serverState = SERVER_STOPPING;
}


static void main_downloadFile(
	webster_output_t *response,
	const char *fileName,
	int contentLength )
{
	if (fileName == NULL || strstr(fileName, rootDirectory) != fileName) return;

	char buffer[1024];

	WebsterSetStatus(response, 200);
	WebsterWriteIntField(response, "Content-Length", contentLength);
	WebsterWriteStringField(response, "Server", PROGRAM_TITLE);

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
	webster_output_t *response,
	const char *fileName )
{
	static const char *DIR_FORMAT = "<li><strong><a href='%s/%s'>[%s]</a></strong></li>";
	static const char *FIL_FORMAT = "<li><a href='%s/%s'>%s</a></li>";

	char temp[2048];

	WebsterWriteStringField(response, "Server", PROGRAM_TITLE);

	snprintf(temp, sizeof(temp) - 1, "<html><head><title>" PROGRAM_TITLE
		"</title></head><body style='font-family: monospace; font-size: 16px;'><ul><h1>%s</h1>", fileName);
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
			temp[2047] = 0;
			WebsterWriteString(response, temp);
			printf("%s\n", de->d_name);
		}
	}
	closedir(dr);

	WebsterWriteString(response, "</ul></body>");
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
			if (event.type ==  WBT_HEADER)
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
		WebsterWriteIntField(response, "Content-Length", 14);
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
