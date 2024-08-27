/*
* Copyright (c) 2024 Vaughn Nugent
*
* Package: noscrypt
* File: hkdf.h
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

#pragma once

#ifndef _NC_HKDF_H
#define _NC_HKDF_H

#include "nc-util.h"
#include "nc-crypto.h"

/*
* IMPORTANT:
*	The HKDF_IN_BUF_SIZE defintion sets the internal stack buffer size to use
*	during fallback HKDF_Expand operations.
*
*	128 bytes should be more than enough for most use cases, without going 
*	overboard. Could be dialed in better for specific use cases later.
*/

#ifndef HKDF_IN_BUF_SIZE
	#define HKDF_IN_BUF_SIZE	0x80	
#endif


/* typedefs for hdkf callback functions */

typedef cstatus_t (*hmac_hash_fn)(void* ctx, cspan_t data);
typedef cstatus_t (*hmac_finish_fn)(void* ctx, sha256_t hmacOut32);

struct nc_hkdf_fn_cb_struct
{
	hmac_hash_fn update;
	hmac_finish_fn finish;
};

cstatus_t hkdfExpandProcess(
	const struct nc_hkdf_fn_cb_struct* handler,
	void* ctx,
	cspan_t info,
	span_t okm
);

#endif /* !_NC_HKDF_H */
