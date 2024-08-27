/*
* Copyright (c) 2024 Vaughn Nugent
*
* Package: noscrypt
* File: hkdf.c
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


#include "hkdf.h"

#define HKDF_MIN(a, b) (a < b ? a : b)

STATIC_ASSERT(HKDF_IN_BUF_SIZE > SHA256_DIGEST_SIZE, "HDK Buffer must be at least the size of the underlying hashing alg output")

static _nc_fn_inline void debugValidateHandler(const struct nc_hkdf_fn_cb_struct* handler)
{
	DEBUG_ASSERT(handler != NULL)
	DEBUG_ASSERT(handler->update != NULL)
	DEBUG_ASSERT(handler->finish != NULL)
}

/*
* The following functions implements the HKDF expand function using an existing
* HMAC function.
*
* This follows the guidence from RFC 5869: https://tools.ietf.org/html/rfc5869
*/

cstatus_t hkdfExpandProcess(
	const struct nc_hkdf_fn_cb_struct* handler,
	void* ctx,
	cspan_t info,
	span_t okm
)
{
	cstatus_t result;
	cspan_t tSpan, counterSpan;
	uint32_t tLen, okmOffset;
	uint8_t counter[1];
	uint8_t t[HKDF_IN_BUF_SIZE];

	debugValidateHandler(handler);

	ncCryptoSecureZero(t, sizeof(t));

	tLen = 0;				/* T(0) is an empty string(zero length) */
	okmOffset = 0;
	counter[0] = 1;			/* counter is offset by 1 for init */
	result = CSTATUS_FAIL;	/* Start in fail state */

	/* span over counter value that points to the counter buffer */
	ncSpanInitC(&counterSpan, counter, sizeof(counter));

	/* Compute T(N) = HMAC(prk, T(n-1) | info | n) */
	while (okmOffset < okm.size)
	{
		ncSpanInitC(&tSpan, t, tLen);

		if (handler->update(ctx, tSpan) != CSTATUS_OK)
		{
			goto Exit;
		}

		if (handler->update(ctx, info) != CSTATUS_OK)
		{
			goto Exit;
		}

		if (handler->update(ctx, counterSpan) != CSTATUS_OK)
		{
			goto Exit;
		}

		/* 
		* Write current hash state to t buffer. It is known
		* that the t buffer must be at least the size of the
		* underlying hash function output.
		*/
		if (handler->finish(ctx, t) != CSTATUS_OK)
		{
			goto Exit;
		}

		/* tlen becomes the hash size or remaining okm size */
		tLen = HKDF_MIN(ncSpanGetSize(okm) - okmOffset, SHA256_DIGEST_SIZE);

		DEBUG_ASSERT(tLen <= sizeof(t));

		/* write the T buffer back to okm and advance okmOffset by tLen */
		ncSpanAppend(okm, &okmOffset, t, tLen);

		/* increment counter */
		(*counter)++;
	}

	result = CSTATUS_OK;	/* HMAC operation completed, so set success */

Exit:

	return result;
}
