#include <webster/api.h>
#include <stdio.h>
#include <string.h>


static int handlerFunction(
    webster_input_t *request,
    webster_output_t *response,
    void *data )
{
	int type, size;

	do
	{
		int result = WebsterWait(request, &type, &size);
		if (result == WBERR_NO_DATA)
		{
			printf("Waiting\n");
			continue;
		}
		else
		if (result == WBERR_OK)
		{
			if (type ==  WB_TYPE_HEADER)
			{
				printf("Received HTTP header\n");

				int count = 0;
				const webster_field_t *headers;
				WebsterGetHeaderFields(request, &headers, &count);
				for (int i = 0; i < count; ++i)
					printf("%20s -> %s\n", headers[i].name, headers[i].value);
			}
			else
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
			printf("Completed\n");
			WebsterSetStatus(response, 200);
			WebsterWriteHeaderField(response, "Content-Length", "5");
			WebsterWriteData(response, "Teste", 5);
			break;
		}
		else
			break;

	} while (1);

	return 0;
}

int tokenize(
	char *buffer,
	const char *delimiter,
	char terminator,
	char **tokens,
	int size );


int main(int argc, char* argv[])
{
	webster_server_t server;

	printf("Let's do this!\n");

	if (WebsterCreate(&server, 100) == WBERR_OK)
	{
		WebsterSetHandler(&server, "text/plain", handlerFunction);

		if (WebsterStart(&server, "127.0.0.1", 7000) == WBERR_OK)
		{
			int c = 0;
			while (c++ < 1) WebsterAccept(&server, NULL);
		}
		fflush(stdout);
		WebsterDestroy(&server);
	}



    return 0;
}
