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


struct mime_t
{
	const char *extension;
	const char *mime;
};


static const struct mime_t MIME_TABLE[] =
{
	{ "7z"   , "application/x-7z-compressed" },
	{ "aac"  , "audio/aac" },
	{ "avi"  , "video/x-msvideo" },
	{ "bmp"  , "image/bmp" },
	{ "bz"   , "application/x-bzip" },
	{ "bz2"  , "application/x-bzip2" },
	{ "csh"  , "text/plain" },
	{ "css"  , "text/css" },
	{ "csv"  , "text/csv" },
	{ "gif"  , "image/gif" },
	{ "htm"  , "text/html" },
	{ "html" , "text/html" },
	{ "jpeg" , "text/html" },
	{ "jpg"  , "image/jpeg" },
	{ "js"   , "application/javascript" },
	{ "json" , "application/json" },
	{ "mp3"  , "audio/mp3" },
	{ "mp4"  , "video/mp4" },
	{ "mpeg" , "video/mpeg" },
	{ "oga"  , "audio/ogg" },
	{ "ogg"  , "audio/ogg" },
	{ "ogv"  , "video/ogg" },
	{ "png"  , "image/png" },
	{ "pdf"  , "application/pdf" },
	{ "rar"  , "application/x-rar-compressed" },
	{ "sh"   , "text/plain" },
	{ "svg"  , "image/svg+xml" },
	{ "tar"  , "application/x-tar" },
	{ "tif"  , "image/tiff" },
	{ "tiff" , "image/tiff" },
	{ "txt"  , "text/plain" },
	{ "wav"  , "audio/wav" },
	{ "weba" , "audio/webm" },
	{ "webm" , "video/webm" },
	{ "webp" , "image/webp" },
	{ "xml"  , "application/xml" },
	{ "zip"  , "application/zip" },
};
#define MIME_COUNT   sizeof(MIME_TABLE) / sizeof(struct mime_t)


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


static const char *main_getMime(
	const char *fileName )
{
	static const char *DEFAULT_MIME = "application/octet-stream";
	if (fileName == NULL || fileName[0] == 0) return DEFAULT_MIME;
	const char *ptr = strrchr(fileName, '.');
	if (ptr == NULL || ++ptr == 0) return DEFAULT_MIME;

	int first = 0;
    int last = MIME_COUNT - 1;

    while (first <= last)
	{
		int current = (first + last) / 2;
		int dir = strcmp(ptr, MIME_TABLE[current].extension);
		if (dir == 0) return MIME_TABLE[current].mime;
		if (dir < 0)
			last = current - 1;
		else
			first = current + 1;
	}

	return DEFAULT_MIME;
}


static void main_downloadFile(
	webster_message_t *response,
	const char *fileName,
	int contentLength )
{
	if (fileName == NULL || strstr(fileName, rootDirectory) != fileName) return;

	char buffer[1024];

	const char *mime = main_getMime(fileName);
	printf("Requested '%s' (%s) with %d bytes\n", fileName, mime, contentLength);

	WebsterSetStatus(response, 200);
	WebsterSetIntegerField(response, "Content-Length", contentLength);
	WebsterSetStringField(response, "Content-Type", mime);
	WebsterSetStringField(response, "Cache-Control", "max-age=10, must-revalidate");
	WebsterSetStringField(response, "Content-Encoding", "identity");
	WebsterSetStringField(response, "Server", PROGRAM_TITLE);

	size_t sent = 0;
	FILE *fp = fopen(fileName, "rb");
	if (fp != NULL)
	{
		size_t read = 0;
		do {
			read = fread(buffer, 1, sizeof(buffer), fp);
			if (read > 0)
			{
				if (WebsterWriteData(response, (uint8_t*) buffer, (int) read) == WBERR_OK) sent += read;
			}
		} while (read > 0);
		fclose(fp);
	}

	printf("Returned %d bytes\n", (int) sent);
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
	// build the local file name
	char *fileName = NULL;
	char temp[512];
	strncpy(temp, rootDirectory, sizeof(temp) - 1);
	strncat(temp, header->resource, sizeof(temp) - 1);
	fileName = realpath(temp, NULL);

	result = WBERR_OK;
	struct stat info;
	if (fileName == NULL || stat(fileName, &info) != 0) result = WBERR_INVALID_ARGUMENT;
	if (result == WBERR_OK && info.st_mode & S_IFREG)
	{
		const char *accept = NULL;
		if (WebsterGetStringField(request, 0, "accept", &accept) == WBERR_OK)
		{
			const char *mime = main_getMime(fileName);
			// a very simple (and not recomended) way to check the accepted types
			if (strstr(accept, mime) == NULL && strstr(accept, "*/*") == NULL)
			{
				WebsterSetStatus(response, 406);
				WebsterSetStringField(response, "content-type", mime);
				WebsterSetIntegerField(response, "content-length", (int) strlen(mime));
				WebsterWriteString(response, mime);
			}
			else
			{
				WebsterSetStatus(response, 200);
				main_downloadFile(response, fileName, (int) info.st_size);
			}
		}
		else
		{
			WebsterSetStatus(response, 500);
			WebsterSetIntegerField(response, "content-length", 0);
		}
	}
	else
	if (result == WBERR_OK && info.st_mode & S_IFDIR)
	{
		WebsterSetStatus(response, 200);
		main_listDirectory(response, fileName);
	}
	else
	{
		WebsterSetStatus(response, 404);
		WebsterSetIntegerField(response, "Content-Length", 18);
		WebsterWriteString(response, "<h1>Not found</h1>");
	}

	WebsterFinish(response);
	if (fileName != NULL) free(fileName);
	printf("\n");
	return result;
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
