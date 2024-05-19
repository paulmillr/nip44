/*
* Copyright (c) 2024 Vaughn Nugent
*
* Package: noscrypt
* File: impl/monocypher.c
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


/*
*  This file handles some fallbacks that may not be available on 
*	some platforms. More specifically:
*		- Secure memset 0
* 		- Chacha20 cipher
* 
*/

#ifdef NC_ENABLE_MONOCYPHER

#include <monocypher.h>

#include "nc-util.h"

/* Export secure memse0 */
#ifndef _IMPL_SECURE_ZERO_MEMSET

	/* export cytpo wipe function as is */
	#define _IMPL_SECURE_ZERO_MEMSET crypto_wipe	
#endif

/* Export Chacha20 */
#ifndef _IMPL_CHACHA20_CRYPT

	#define _IMPL_CHACHA20_CRYPT _mc_chacha20_crypt

	_IMPLSTB cstatus_t _mc_chacha20_crypt(
		const uint8_t* key,
		const uint8_t* nonce,
		const uint8_t* input,
		uint8_t* output,
		uint32_t dataLen
	)
	{
		_overflow_check(dataLen)

		/*
		* Function returns the next counter value which is not
		* needed for noscrypt as encryptions are one-shot, and 
		* require a new nonce for each encryption.
		* 
		* ITEF function uses a 12byte nonce which is required for
		* nip-44 compliant encryption.
		*/
		crypto_chacha20_ietf(
			output,
			input,
			(size_t)dataLen,
			key,
			nonce,
			0x00			/* Counter always starts at 0 */
		);

		return CSTATUS_OK;
	}

#endif

#endif /* !NC_ENABLE_MONOCYPHER */