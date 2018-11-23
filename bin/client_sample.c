#include <webster/api.h>
#include <stdio.h>


static int main_clientHandler(
    webster_message_t *request,
    webster_message_t *response,
    void *data )
{
    (void) data;

    // send a HTTP request
    WebsterSetIntegerField(request, "content-length", 0);
    WebsterSetStringField(request, "connection", "close");
    WebsterFinish(request);

    printf("Request sent!\n");

    int received = 0;
    int result = 0;
    int j = 0;
    webster_event_t event;
    const webster_header_t *header;
    do
    {
        // wait for response data
        result = WebsterWaitEvent(response, &event);
        if (result == WBERR_COMPLETE) break;
        if (result == WBERR_NO_DATA) continue;
        if (result != WBERR_OK) break;

        if (result == WBERR_OK)
        {
            // check if received the HTTP header
            if (event.type ==  WBT_HEADER)
            {
                if (WebsterGetHeader(response, &header) == WBERR_OK)
                {
                    printf("HTTP/1.1 %d\n", header->status);
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
                received += size;
                for (int i = 0; i < size; ++i, ++j)
                {
                    if (j != 0 && j % 32 == 0) printf("\n");
                    printf("%02x ", ptr[i]);
                }
            }
        }
    } while (1);

    WebsterFinish(response);

    printf("\nReceived %d bytes (%d)\n", received, result);

    return WBERR_OK;
}

int http_parse(
    char *data,
    int type,
    webster_header_t *message );

#include <string.h>
int main( int argc, char **argv )
{
    (void) argc;
    (void) argv;

    WebsterInitialize(NULL, NULL);

    webster_target_t *url;
    WebsterParseURL("/", &url);

    webster_client_t *client = NULL;
    if (WebsterConnect(&client, WBP_HTTP, "duckduckgo.com", 80) == WBERR_OK)
    {
        WebsterCommunicateURL(client, url, main_clientHandler, NULL);
        WebsterDisconnect(client);
    }
    else
        printf("Failed!\n");

    WebsterFreeURL(url);
    WebsterTerminate();

    return 0;
}