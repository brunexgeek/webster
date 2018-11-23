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

#define HTML_BEGIN "<html><head><meta charset='UTF-8'><title>" PROGRAM_TITLE "</title></head>" \
	"<style type='text/css'>html{font-family: sans-serif; font-size: 16px;} " \
	"a{text-decoration: none}</style><body>"

#define DIR_FORMAT "<tr><td><img src='https://svn.apache.org/icons/folder.gif'>" \
	"</td><td><strong><a href='%s/%s'>%s/</a></strong></div></td><td></td></tr>"

#define FIL_FORMAT "<tr><td><img src='https://svn.apache.org/icons/unknown.gif'>" \
	"</td><td><a href='%s/%s'>%s</a></td><td>%.1f %c</td></tr>"

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
	{ "jpeg" , "image/jpeg" },
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
	if (serverState == SERVER_STOPPING) exit(1);
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


struct dir_entry
{
	int type;
	char *fileName;
	size_t size;
};


static int compareDirEntry(
	const void *first,
	const void *second )
{
	const struct dir_entry *a = (const struct dir_entry *) first;
	const struct dir_entry *b = (const struct dir_entry *) second;

	if (a->type != b->type)
	{
		if (a->type == DT_DIR)
			return -1;
		else
			return 1;
	}
	return strcmp(a->fileName, b->fileName);
}


static void enumerateFiles(
	const char *path,
	struct dir_entry **entries,
	int *count )
{
	DIR *dr = opendir(path);
	struct dirent *de = NULL;
	if (dr == NULL) return;

	*count = 0;
	while ((de = readdir(dr)) != NULL) (*count)++;
	(*count)--; // ignore '.'
	if (*count < 0)
	{
		closedir(dr);
		return;
	}
	rewinddir(dr);

	*entries = (struct dir_entry *) malloc( (size_t) *count * sizeof(struct dir_entry));
	if (*entries == NULL)
	{
		closedir(dr);
		return;
	}
	printf("Found %d files at '%s'\n", *count, path);

	int i = 0;
	while ((de = readdir(dr)) != NULL)
	{
		if (de->d_name[0] == '.' && de->d_name[1] == 0) continue;
		(*entries)[i].fileName = strdup(de->d_name);
		(*entries)[i].size = 0;
		(*entries)[i].type = de->d_type;
		if (++i >= *count) break;
	}
	closedir(dr);

	qsort(*entries, (size_t) *count, sizeof(struct dir_entry), compareDirEntry);
}


static void main_listDirectory(
	webster_message_t *response,
	const char *path )
{
	char temp[1024];

	WebsterSetStringField(response, "Server", PROGRAM_TITLE);

	WebsterWriteString(response, HTML_BEGIN);
	WebsterWriteString(response, "<h1>");
	WebsterWriteString(response, path);
	WebsterWriteString(response, "</h1><table>");

	size_t length = strlen(rootDirectory);
	struct dir_entry *entries;
	int total;
	enumerateFiles(path, &entries, &total);
	if (total > 0)
	{
		int i = 0;
		for (; i < total; ++i)
		{
			if (entries[i].fileName == NULL) continue;

			if (entries[i].type == DT_DIR)
				snprintf(temp, sizeof(temp) - 1, DIR_FORMAT,
					path + length,
					entries[i].fileName,
					entries[i].fileName);
			else
			if (entries[i].type == DT_REG)
			{
				// build the absolute file name
				strncpy(temp, path, sizeof(temp) - 1);
				strncat(temp, "/", sizeof(temp) - 1);
				strncat(temp, entries[i].fileName, sizeof(temp) - 1);
				temp[sizeof(temp) - 1] = 0;
				// get the file information
				struct stat info;
				memset(&info, 0, sizeof(struct stat));
				stat(temp, &info);
				// make the file size human-readable
				char unit = 'b';
				float size = (float) info.st_size;
				if (info.st_size > 1024 * 1024)
				{
					unit = 'M';
					size = (float) info.st_size / (1024.0F * 1024.0F);
				}
				else
				if (info.st_size > 1024)
				{
					unit = 'K';
					size = (float) info.st_size / 1024.0F;
				}

				snprintf(temp, sizeof(temp) - 1, FIL_FORMAT,
					path + length,
					entries[i].fileName,
					entries[i].fileName,
					size,
					unit);
			}
			else
				continue;
			temp[sizeof(temp) - 1] = 0;
			WebsterWriteString(response, temp);
			free(entries[i].fileName);
		}
		free(entries);
	}

	WebsterWriteString(response, "</table><hr/>");
}


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
					printf("%s %s\n", HTTP_METHODS[header->method], header->target->path);
					// print all HTTP header fields
					webster_field_t *field = header->fields;
					while (field != NULL)
					{
						printf("  %s: '%s'\n", field->name, field->value);
						field = field->next;
					}
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
	strncat(temp, header->target->path, sizeof(temp) - 1);
	fileName = realpath(temp, NULL);

	result = WBERR_OK;
	struct stat info;
	if (fileName == NULL || stat(fileName, &info) != 0) result = WBERR_INVALID_ARGUMENT;
	if (result == WBERR_OK && info.st_mode & S_IFREG)
	{
		const char *accept = NULL;
		if (WebsterGetStringField(request, WBFI_ACCEPT, NULL, &accept) == WBERR_OK)
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

#include <sys/time.h>

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

	webster_server_t *server = NULL;

	printf(PROGRAM_TITLE "\n");
	printf("Root directory is %s\n", rootDirectory);

	if (WebsterInitialize(NULL, NULL) == WBERR_OK)
	{
		if (WebsterCreate(&server, 100) == WBERR_OK)
		{
			if (WebsterStart(server, "0.0.0.0", 7000) == WBERR_OK)
			{
				while (serverState == SERVER_RUNNING)
				{
					webster_client_t *remote = NULL;
					if (WebsterAccept(server, &remote) != WBERR_OK) continue;
					// you problably should handle the client request in another thread
					WebsterCommunicateURL(remote, NULL, main_serverHandler, NULL);
					WebsterDisconnect(remote);
				}
			}
			WebsterDestroy(server);
		}
		WebsterTerminate();
	}

	printf("Server terminated!\n");

    return 0;
}
