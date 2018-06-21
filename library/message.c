#include "internal.h"
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <signal.h>
#include <fcntl.h>
#include <errno.h>
#include <stdarg.h>
#include "network.h"


int webster_releaseMessage(
	webster_message_t *message )
{
	if (message == NULL) return WBERR_INVALID_ARGUMENT;
	http_releaseFields(&message->header);
	return WBERR_OK;
}


static int webster_receive(
	webster_message_t *input,
	int timeout )
{
	// if we have data in the buffer, just return success
	if (input->buffer.pending > 0) return WBERR_OK;

	// Note: when reading input data we leave room in the buffer for a null-terminator
	//       so we can use the function 'WebsterReadString'.

	// receive new data and adjust pending information
	size_t bytes = input->buffer.size - 1;
	int result = network_receive(input->channel, input->buffer.data, &bytes, timeout);
	if (result < 0) return result;
	input->buffer.pending = (int) bytes;
	input->buffer.current = input->buffer.data;
	// ensure we have a null-terminator at the end
	*(input->buffer.current + input->buffer.pending) = 0;

	return WBERR_OK;
}


static int webster_writeOrSend(
	webster_message_t *output,
	const uint8_t *buffer,
    int size )
{
	if (size == 0 || buffer == NULL) return WBERR_OK;

	// TODO: change algorithm to always fill the internal buffer before send (keep consistent 'packet' sizes)

	// ensures the current pointer is valid
	if (output->buffer.current == NULL)
		output->buffer.current = output->buffer.data;
	else
	// send any pending data if the given one does not fit the internal buffer
	if (output->buffer.current > output->buffer.data && output->buffer.current + size > output->buffer.data + output->buffer.size)
	{
		network_send(output->channel, output->buffer.data, (size_t) (output->buffer.current - output->buffer.data));
		output->buffer.current = output->buffer.data;
	}

	// if the data does not fit the internal buffer at all, send immediately;
	// otherwise, copy the data to the intenal buffer
	if (size > (int) output->buffer.size)
		network_send(output->channel, buffer, (size_t) size);
	else
	{
		memcpy(output->buffer.current, buffer, (size_t) size);
		output->buffer.current += size;
	}

	return WBERR_OK;
}


static int webster_receiveHeader(
	webster_message_t *input )
{
	int result = webster_receive(input, WEBSTER_READ_TIMEOUT);
	if (result != WBERR_OK) return result;

	// no empty line means the HTTP header is longer than WEBSTER_MAX_HEADER
	char *ptr = strstr((char*) input->buffer.data, "\r\n\r\n");
	if (ptr == NULL || (char*) input->buffer.data + WEBSTER_MAX_HEADER < ptr) return WBERR_TOO_LONG;
	*(ptr)     = ' ';
	*(ptr + 1) = ' ';
	*(ptr + 2) = ' ';
	*(ptr + 3) = 0;
	// remember the last position
	input->buffer.current = (uint8_t*) ptr + 4;
	input->buffer.pending = input->buffer.pending - (int) ( (uint8_t*) ptr + 4 - input->buffer.data );

	// parse HTTP header fields and retrieve the content length
	result = http_parseHeader((char*)input->buffer.data, &input->header, &input->body.expected);
	input->header.contentLength = input->body.expected;
	return result;
}


int WebsterWaitEvent(
    webster_message_t *input,
    webster_event_t *event )
{
	if (input == NULL || event == NULL) return WBERR_INVALID_ARGUMENT;

	event->size = 0;
	event->type = 0;
	int result = 0;

	if (input->state == WBS_IDLE)
	{
		result = webster_receiveHeader(input);
		if (result == WBERR_OK)
		{
			event->type = WBT_HEADER;
			event->size = (int) strlen((char*)input->buffer.data) + 1;
			input->state = WBS_HEADER;
		}
		return result;
	}
	else
	if (input->state == WBS_HEADER || input->state == WBS_BODY)
	{
		if (input->body.expected == 0) return WBERR_COMPLETE;

		result = webster_receive(input, WEBSTER_READ_TIMEOUT);
		if (result == WBERR_OK)
		{
			// truncate any extra byte beyond content length
			if (input->body.size + input->buffer.pending > input->body.expected)
			{
				input->buffer.pending = input->body.expected - input->body.size;
				// we still have some data to return?
				if (input->buffer.pending <= 0)
				{
					input->state = WBS_COMPLETE;
					input->buffer.pending = 0;
					return WBERR_NO_DATA;
				}
			}
			event->type = WBT_BODY;
			event->size = input->buffer.pending;
			input->state = WBS_BODY;
			input->body.size += input->buffer.pending;
			input->body.expected -= input->buffer.pending;
		}

		return result;
	}

	return WBERR_COMPLETE;
}


int WebsterGetHeader(
    webster_message_t *input,
    const webster_header_t **header )
{
	if (input == NULL || header == NULL) return WBERR_INVALID_ARGUMENT;

	*header = &input->header;

	return WBERR_OK;
}


int WebsterGetStringField(
    webster_message_t *input,
	int id,
	const char *name,
    const char **value )
{
	if (input == NULL || value == 0 || (name == NULL && id != WBFI_NON_STANDARD))
		return WBERR_INVALID_ARGUMENT;
	if (id < 0 || id > WBFI_WWW_AUTHENTICATE)
		return WBERR_INVALID_ARGUMENT;

	if (name != NULL) id = http_getFieldID(name);

	const webster_field_t *field = NULL;
	if (id == WBFI_NON_STANDARD)
		field = http_getFieldByName(&input->header, name);
	else
		field = http_getFieldById(&input->header, id);

	if (field == NULL) return WBERR_NO_DATA;
	*value = field->value;
	return WBERR_OK;
}


int WebsterGetIntegerField(
    webster_message_t *input,
    int id,
    const char *name,
    int *value )
{
	const char *temp = NULL;
	int result = WebsterGetStringField(input, id, name, &temp);
	if (result != WBERR_OK) return result;

	*value = atoi(temp);
	return WBERR_OK;
}


int WebsterReadData(
    webster_message_t *input,
    const uint8_t **buffer,
	int *size )
{
	if (input == NULL || buffer == NULL || size == NULL) return WBERR_INVALID_ARGUMENT;

	if (input->buffer.pending <= 0 || input->buffer.current == NULL) return WBERR_NO_DATA;

	*buffer = input->buffer.current;
	*size = input->buffer.pending;

	input->buffer.current = NULL;
	input->buffer.pending = 0;

	return WBERR_OK;
}


int WebsterReadString(
    webster_message_t *input,
    const char **buffer )
{
	if (input == NULL || buffer == NULL) return WBERR_INVALID_ARGUMENT;

	if (input->buffer.pending <= 0 || input->buffer.current == NULL) return WBERR_NO_DATA;

	// the 'webster_receive' function is supposed to put a null-terminator
	// at the end of the data, but we want to be sure (better safe than sorry)
	*(input->buffer.current + input->buffer.pending) = 0;
	*buffer = (char*) input->buffer.current;

	input->buffer.current = NULL;
	input->buffer.pending = 0;

	return WBERR_OK;
}


int WebsterSetStatus(
    webster_message_t *output,
    int status )
{
	if (output == NULL) return WBERR_INVALID_ARGUMENT;

	output->header.status = status;

	return WBERR_OK;
}


static int webster_writeStatusLine(
	webster_message_t *output )
{
	if (output == NULL) return WBERR_INVALID_ARGUMENT;
	if (output->state != WBS_IDLE) return WBERR_INVALID_STATE;
	output->state = WBS_HEADER;

	const char *message = NULL;
	if (output->header.status == 0)
	{
		output->header.status = 200;
		message = "OK";
	}
	else
		message = http_statusMessage(output->header.status);

	char temp[128];
	snprintf(temp, sizeof(temp) - 1, "HTTP/1.1 %d %s\r\n", output->header.status, message);
	return webster_writeOrSend(output, (uint8_t*) temp, (int) strlen(temp));
}


int WebsterSetStringField(
    webster_message_t *output,
    const char *name,
    const char *value )
{
	if (output == NULL || name == NULL || name[0] == 0 || value == NULL) return WBERR_INVALID_ARGUMENT;
	if (output->state >= WBS_BODY) return WBERR_INVALID_STATE;

	int result = WBERR_OK;
	if (output->state == WBS_IDLE)
	{
		result = webster_writeStatusLine(output);
		if (result != WBERR_OK) return result;
	}

	char temp[128] = { 0 };
	strncpy(temp, name, sizeof(temp) - 1);
	// change the field name to lowercase
    for (char *p = temp; *p; ++p) *p = (char) tolower(*p);
	// remove trailing whitespaces
	name = http_removeTrailing(temp);
	// check if we have any whitespace
	for (const char *p = name; *p != 0; ++p)
		if (*p == ' ') return WBERR_INVALID_HEADER_FIELD;

	// TODO: evaluate field value

	int fid = http_getFieldID(name);
	if (fid == WBFI_CONTENT_LENGTH)
		output->body.expected = atoi(value);

	return http_addField(&output->header, fid, temp, value);
}


int WebsterSetIntegerField(
    webster_message_t *output,
    const char *name,
    int value )
{
	char temp[12];
	snprintf(temp, sizeof(temp) - 1, "%d", value);
	return WebsterSetStringField(output, name, temp);
}


static void webster_commitHeaderFields(
    webster_message_t *output )
{
	webster_field_t *field = output->header.fields;
	while (field != NULL)
	{
		const char *name = field->name;
		const char *value = field->value;

		webster_writeOrSend(output, (const uint8_t*) name, (int) strlen(name));
		webster_writeOrSend(output, (const uint8_t*) ": ", 2);
		webster_writeOrSend(output, (const uint8_t*) value, (int) strlen(value));
		webster_writeOrSend(output, (const uint8_t*) "\r\n", 2);

		field = field->next;
	}
	webster_writeOrSend(output, (const uint8_t*)"\r\n", 2);
	output->state = WBS_BODY;
}


int WebsterWriteData(
    webster_message_t *output,
    const uint8_t *buffer,
    int size )
{
	if (output == NULL || buffer == NULL) return WBERR_INVALID_ARGUMENT;
	if (output->state == WBS_COMPLETE) return WBERR_INVALID_STATE;

	int result = 0;

	if (output->state == WBS_IDLE)
	{
		result = webster_writeStatusLine(output);
		if (result != WBERR_OK) return result;
	}

	if (output->state == WBS_HEADER)
	{
		// if 'content-length' is not specified, we set 'tranfer-encoding' to chunked
		if (output->body.expected <= 0)
			WebsterSetStringField(output, "transfer-encoding", "chunked");
		webster_commitHeaderFields(output);
	}

	// ignores empty writes
	if (size <= 0) return WBERR_OK;

	// check whether we're using chuncked transfer encoding
	if (output->body.expected <= 0)
	{
		char temp[16];
		snprintf(temp, sizeof(temp) - 1, "%X\r\n", size);
		temp[15] = 0;
		webster_writeOrSend(output, (const uint8_t*) temp, (int) strlen(temp));
	}
	// write data
	webster_writeOrSend(output, buffer, size);
	// append the block terminator, if using chuncked transfer encoding
	if (output->body.expected <= 0)
		webster_writeOrSend(output, (const uint8_t*) "\r\n", 2);

	return WBERR_OK;
}


WEBSTER_EXPORTED int WebsterWriteString(
    webster_message_t *output,
    const char *text )
{
	return WebsterWriteData(output, (uint8_t*) text, (int) strlen(text));
}


int WebsterFlush(
	webster_message_t *output )
{
	if (output == NULL) return WBERR_INVALID_ARGUMENT;

	if (output->state != WBS_BODY)
	{
		WebsterWriteData(output, (uint8_t*) "", 0);
	}

	if (output->buffer.current > output->buffer.data)
	{
		network_send(output->channel, output->buffer.data, (size_t) (output->buffer.current - output->buffer.data));
		output->buffer.current = output->buffer.data;
	}

	return WBERR_OK;
}


WEBSTER_EXPORTED int WebsterGetInputState(
	webster_message_t *input,
    int *state )
{
	if (input == NULL || state == NULL) return WBERR_INVALID_ARGUMENT;

	*state = input->state;

	return WBERR_OK;
}


WEBSTER_EXPORTED int WebsterGetOutputState(
	webster_message_t *output,
    int *state )
{
	if (output == NULL || state == NULL) return WBERR_INVALID_ARGUMENT;

	*state = output->state;

	return WBERR_OK;
}