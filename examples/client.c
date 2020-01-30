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

#include <webster.h>
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
				int status = 0;
				WebsterGetStatus(response, &status);
				printf("HTTP/1.1 %d\n", status);
				// print all HTTP header fields
				const char *name;
				const char *value;
				int index = 0;
				while (WebsterIterateField(response, index++, NULL, &name, &value) == WBERR_OK)
					printf("  %s: '%s'\n", name, value);
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


#include <string.h>
int main( int argc, char **argv )
{
    (void) argc;
    (void) argv;

    WebsterInitialize(NULL);

    webster_target_t *url;
    WebsterParseURL("http://duckduckgo.com:80/", &url);

    webster_client_t *client = NULL;
    if (WebsterConnect(&client, url, NULL) == WBERR_OK)
    {
        WebsterCommunicate(client, url, main_clientHandler, NULL);
        WebsterDisconnect(client);
    }
    else
        printf("Failed!\n");

    WebsterFreeURL(url);
    WebsterTerminate();

    return 0;
}