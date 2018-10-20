#include <webster/api.h>
#include <stdio.h>


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


static int clientHandler(
    webster_message_t *request,
    webster_message_t *response,
    void *data )
{
	(void) data;

    // send a HTTP request
    WebsterSetStringField(request, "host", "google.com");
    WebsterSetIntegerField(request, "content-length", 0);
    WebsterFinish(request);

    printf("Request sent!\n");

	webster_event_t event;
	const webster_header_t *header;
	do
	{
		// wait for response data
		int result = WebsterWaitEvent(response, &event);
		if (result == WBERR_COMPLETE) break;
		if (result == WBERR_NO_DATA) continue;
        if (result != WBERR_OK) return 0;

		if (result == WBERR_OK)
		{
			// check if received the HTTP header
			if (event.type ==  WBT_HEADER)
			{
				if (WebsterGetHeader(response, &header) == WBERR_OK)
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
				WebsterReadData(response, &ptr, &size);
				for (int i = 0; i < size; ++i)
				{
					if (i != 0 && i % 8 == 0) printf("\n");
					printf("%02X ", ptr[i]);
				}
			}
		}
	} while (1);

    return WBERR_OK;
}


int main( int argc, char **argv )
{
	(void) argc;
	(void) argv;

    webster_client_t client;
    if (WebsterConnect(&client, "google.com", 80, "/") == WBERR_OK)
    {
        WebsterCommunicate(&client, clientHandler, NULL);
        WebsterDisconnect(&client);
    }
    else
        printf("Failed!\n");
    return 0;
}