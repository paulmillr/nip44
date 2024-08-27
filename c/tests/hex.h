/*
* Copyright (c) 2024 Vaughn Nugent
*
* Package: noscrypt
* File: hex.h
*
* This library is free software; you can redistribute it and/or
* modify it under the terms of the GNU Lesser General Public License
* as published by the Free Software Foundation; either version 2.1
* of the License, or  (at your option) any later version.
*
* This library is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
* Lesser General Public License for more details.
*
* You should have received a copy of the GNU Lesser General Public License
* along with noscrypt. If not, see http://www.gnu.org/licenses/.
*/


#ifndef HEX_HELPERS_H
#define HEX_HELPERS_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <nc-util.h>

/* Deferred list of span_t to be freed on exit */
static span_t _hdeferList[20];
static size_t _hdeferListIndex = 0;

/* 
	Allocates a span_t and decodes the hexadecimal string into it's binary
	representation. The string must be a valid hexadecimal string and the length
	and may not be NULL. The length may be known at compile time and can be used
    to assert the length of the string literal.
	@param hexLiteral The hexadecimal string to decode
	@param strLen The length of the string
*/
#define FromHexString(str, len) _fromHexString(str, sizeof(str) - 1); STATIC_ASSERT(sizeof(str)/2 == len && len > 0, "Invalid length hex string literal");

static span_t __allocHexBytes(size_t length)
{
	span_t hexBytes;

	length /= 2;

	hexBytes.data = malloc(length);

	if(!hexBytes.data)
	{
		return hexBytes;
	}

	hexBytes.size = length;
	/* add new value to deferred cleanup list */
	_hdeferList[_hdeferListIndex++] = hexBytes;
	return hexBytes;
}

static span_t _fromHexString(const char* hexLiteral, uint32_t strLen)
{
	span_t hexBytes;
	size_t i;

	if(!hexLiteral)
	{
		ncSpanInit(&hexBytes, NULL, 0);
		return hexBytes;
	}

	/* alloc the raw bytes */
	hexBytes = __allocHexBytes(strLen);

	/* read every 2 chars into  */
	for (i = 0; i < strLen; i += 2)
	{
		/* slice string into smaller 2 char strings then parse */
		char byteString[3] = { '\0' };

		byteString[0] = hexLiteral[i];
		byteString[1] = hexLiteral[i + 1];

		hexBytes.data[i / 2] = (uint8_t)strtol(byteString, NULL, 16);
	}
	
	return hexBytes;
}

/*
	Frees all the span_t that were allocated by the 
	FromHexString function. To be called at the end of 
	the program.
*/
static void FreeHexBytes(void)
{
	while(_hdeferListIndex > 0)
	{
		free(_hdeferList[--_hdeferListIndex].data);
		memset(&_hdeferList[_hdeferListIndex], 0, sizeof(span_t));
	}
}

/*
* Prints the value of the buffer as a hexadecimal string
* @param bytes The buffer to print
* @param len The length of the buffer
*/
static void PrintHexRaw(void* bytes, size_t len)
{
	size_t i;
	for (i = 0; i < len; i++)
	{
		printf("%02x", ((uint8_t*)bytes)[i]);
	}

	puts("\n");
}

/*
* Prints the value of the span_t as a hexadecimal string
* @param hexBytes A pointer to the span_t structure to print the value of
*/
static void PrintHexBytes(span_t hexBytes)
{
	if (ncSpanIsValid(hexBytes))
	{
		PrintHexRaw(hexBytes.data, hexBytes.size);
	}
	else
	{
		puts("NULL");		
	}
}


#endif /* !HEX_HELPERS_H */


