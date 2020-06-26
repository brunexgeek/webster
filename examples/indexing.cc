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

#include <webster.hh>
#include <limits.h>
#include <stdio.h>
#include <signal.h>
#include <setjmp.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <ctype.h>
#include <iostream>
#include <memory>
#include "ctpl.hh"

#ifdef _WIN32
#include <Windows.h>
#define PATH_LENGTH  MAX_PATH
#define STRCMPI      webster::strcmpi
#else
#include <unistd.h>
#include <linux/limits.h>
#include <dirent.h>
#define PATH_LENGTH  PATH_MAX
#define STRCMPI      webster::strcmpi
#endif


#define SERVER_RUNNING    1
#define SERVER_STOPPING   2

#define PROGRAM_TITLE     "Webster HTTP Server"

/*
 * Public domain icons from <https://svn.apache.org/icons/>.
 */

#define DIR_CSS ".icon-folder{width:20px;height:22px;background-image: url(data:image/gif;base64," \
	"R0lGODlhFAAWAMIAAP/////Mmcz//5lmMzMzMwAAAAAAAAAAACH+TlRoaXMgYXJ0IGlzIGluIHRo" \
	"ZSBwdWJsaWMgZG9tYWluLiBLZXZpbiBIdWdoZXMsIGtldmluaEBlaXQuY29tLCBTZXB0ZW1iZXIg" \
	"MTk5NQAh+QQBAAACACwAAAAAFAAWAAADVCi63P4wyklZufjOErrvRcR9ZKYpxUB6aokGQyzHKxyO" \
	"9RoTV54PPJyPBewNSUXhcWc8soJOIjTaSVJhVphWxd3CeILUbDwmgMPmtHrNIyxM8Iw7AQA7);}"

#define FIL_CSS ".icon-file{width:20px;height:22px;background-image: url(data:image/gif;base64," \
	"R0lGODlhFAAWAMIAAP///8z//5mZmTMzMwAAAAAAAAAAAAAAACH+TlRoaXMgYXJ0IGlzIGluIHRo" \
	"ZSBwdWJsaWMgZG9tYWluLiBLZXZpbiBIdWdoZXMsIGtldmluaEBlaXQuY29tLCBTZXB0ZW1iZXIg" \
	"MTk5NQAh+QQBAAABACwAAAAAFAAWAAADUDi6vPEwDECrnSO+aTvPEddVIriN1wWJKDG48IlSRG0T" \
	"8kwJvIBLOkvvxwoCfDnjkaisIIHNZdL4LAarUSm0iY12uUwvcdArm3mvyG3N/iUAADs=);}"

#define BACK_CSS ".icon-back{width:20px;height:22px;background-image: url(data:image/gif;base64," \
	"R0lGODlhFAAWAMIAAP///8z//5mZmWZmZjMzMwAAAAAAAAAAACH+TlRoaXMgYXJ0IGlzIGluIHRo" \
	"ZSBwdWJsaWMgZG9tYWluLiBLZXZpbiBIdWdoZXMsIGtldmluaEBlaXQuY29tLCBTZXB0ZW1iZXIg" \
	"MTk5NQAh+QQBAAABACwAAAAAFAAWAAADSxi63P4jEPJqEDNTu6LO3PVpnDdOFnaCkHQGBTcqRRxu" \
	"WG0v+5LrNUZQ8QPqeMakkaZsFihOpyDajMCoOoJAGNVWkt7QVfzokc+LBAA7);}"

#define HTML_BEGIN "<html><head><meta charset='UTF-8'><title>" PROGRAM_TITLE "</title></head>" \
	"<style type='text/css'>html{font-family: sans-serif; font-size: 16px;}" \
	"a{text-decoration: none}" DIR_CSS FIL_CSS BACK_CSS "</style><body>"

#define HTML_END "</body></html>"

#define DIR_FORMAT "<tr><td><div class='icon-folder'></div>" \
	"</td><td><a href='%s/%s'>%s/</a></div></td><td></td></tr>"

#define FIL_FORMAT "<tr><td><div class='icon-file'></div>" \
	"</td><td><a href='%s/%s'>%s</a></td><td>%.1f %c</td></tr>"

#define PAR_FORMAT "<tr><td><div class='icon-back'></div>" \
	"</td><td><a href='%s/..'>Parent directory</a></div></td><td></td></tr>"

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

using namespace webster;

static int serverState = SERVER_RUNNING;

static char *rootDirectory;

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
		int dir = STRCMPI(ptr, MIME_TABLE[current].extension);
		if (dir == 0) return MIME_TABLE[current].mime;
		if (dir < 0)
			last = current - 1;
		else
			first = current + 1;
	}

	return DEFAULT_MIME;
}


static void main_downloadFile(
	Message &response,
	const char *fileName,
	int contentLength )
{
	if (fileName == NULL || strstr(fileName, rootDirectory) != fileName) return;

	char buffer[1024];

	const char *mime = main_getMime(fileName);
	printf("Requested '%s' (%s) with %d bytes\n", fileName, mime, contentLength);

	response.header.status= 200;
	response.header.fields["Content-Length"] = std::to_string(contentLength);
	response.header.fields["Content-Type"] = mime;
	response.header.fields["Cache-Control"] = "max-age=10, must-revalidate";
	response.header.fields["Content-Encoding"] = "identity";
	response.header.fields["Server"] = PROGRAM_TITLE;

	size_t sent = 0;
	FILE *fp = fopen(fileName, "rb");
	if (fp != NULL)
	{
		size_t read = 0;
		do {
			read = fread(buffer, 1, sizeof(buffer), fp);
			if (read > 0)
			{
				if (response.write( (uint8_t*) buffer, (int) read) == WBERR_OK) sent += read;
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
	(*count)--; // ignore '..'
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
		if (de->d_name[0] == '.')
		{
			if (de->d_name[1] == 0) continue;
			if (de->d_name[1] == '.' && de->d_name[2] == 0) continue;
		}
		(*entries)[i].fileName = strdup(de->d_name);
		(*entries)[i].size = 0;
		(*entries)[i].type = de->d_type;
		if (++i >= *count) break;
	}
	closedir(dr);

	qsort(*entries, (size_t) *count, sizeof(struct dir_entry), compareDirEntry);
}


static void main_listDirectory(
	Message &response,
	const char *path )
{
	char temp[2048];
	size_t length = strlen(rootDirectory);

	response.header.fields["Server"] = PROGRAM_TITLE;
	response.write( HTML_BEGIN);
	response.write( "<h1>Index of ");
	if (*(path + length) == 0)
		response.write("/");
	else
		response.write(path + length);
	response.write("</h1><table>");

	// parent directory
	if (*(path + length) != 0)
	{
		temp[0] = 0;
		snprintf(temp, sizeof(temp) - 1, PAR_FORMAT, path + length);
		response.write(temp);
	}

	struct dir_entry *entries = NULL;
	int total = 0;
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
			{
				free(entries[i].fileName);
				continue;
			}
			temp[sizeof(temp) - 1] = 0;
			response.write(temp);
			free(entries[i].fileName);
		}
		free(entries);
	}

	response.write("</table><hr/>");
	response.write(HTML_END);
}


static int main_serverHandler(
    Message &request,
    Message &response  )
{
	request.finish();

	Target target = request.header.target;
	// build the local file name
	char *fileName = nullptr;
	{
		std::string temp;
		temp += rootDirectory;
		temp += target.path;
		temp = Target::decode(temp);
		fileName = realpath(temp.c_str(), nullptr);
	}

	int result = WBERR_OK;
	struct stat info;
	if (fileName == NULL || stat(fileName, &info) != 0) result = WBERR_INVALID_ARGUMENT;
	if (result == WBERR_OK && info.st_mode & S_IFREG)
	{
		const std::string accept;
		const char *mime = main_getMime(fileName);
		auto it = request.header.fields.find("Accept");

		// a very simple (and not recomended) way to check the accepted types
		if (it != request.header.fields.end() && (it->second.find(mime) == std::string::npos && it->second.find("*/*") == std::string::npos))
		{
			response.header.status = 406;
			response.header.fields["Content-Type"] = mime;
			response.header.fields["Content-Length"] = std::to_string(strlen(mime));
			response.write(mime);
		}
		else
		{
			response.header.status = 200;
			main_downloadFile(response, fileName, (int) info.st_size);
		}
	}
	else
	if (result == WBERR_OK && info.st_mode & S_IFDIR)
	{
		response.header.status = 200;
		main_listDirectory(response, fileName);
	}
	else
	{
		response.header.status = 404;
		response.header.fields["Content-Length"] = "18";
		response.write("<h1>Not found</h1>");
	}

	response.finish();
	if (fileName != NULL) free(fileName);
	printf("\n");
	return result;
}

#include <sys/time.h>

static void process( int id, std::shared_ptr<Client> remote, Handler &handler )
{
	(void) id;
	remote->communicate("", handler);
	remote->disconnect();
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
		rootDirectory = realpath(argv[1], nullptr);
	else
		rootDirectory = realpath(".", nullptr);
	if (rootDirectory == nullptr)
	{
		std::cerr << "ERROR: Invalid path" << std::endl;
		return 1;
	}

	printf(PROGRAM_TITLE "\n");
	printf("Root directory is %s\n", rootDirectory);

	ctpl::thread_pool pool(2);

	Handler handler(main_serverHandler);
	Server server;
	Target target;
	if (Target::parse("0.0.0.0:7000", target) != WBERR_OK) return 1;
	if (server.start(target) == WBERR_OK)
	{
		while (serverState == SERVER_RUNNING)
		{
			std::shared_ptr<Client> remote;
			int result = server.accept(remote);
			if (result == WBERR_OK)
				pool.push(process, remote, handler);
			else
			if (result != WBERR_TIMEOUT) break;
		}
	}
	server.stop();
	pool.stop();

	printf("Server terminated!\n");

    return 0;
}
