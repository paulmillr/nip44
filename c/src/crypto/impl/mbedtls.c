/*
* Copyright (c) 2024 Vaughn Nugent
*
* Package: noscrypt
* File: mbedtls.c
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
* This file contains implemntation functions for the required 
* cryptography primitives of noscrypt. This file stubs functionality
* using the Mbed-TLS library, if the builder desires to link against
* it. 
*/

#ifdef MBEDTLS_CRYPTO_LIB

/* Inline errors on linux in header files on linux */
#ifndef inline
	#define inline __inline
#endif

#include <mbedtls/md.h>
#include <mbedtls/hkdf.h>
#include <mbedtls/hmac_drbg.h>
#include <mbedtls/sha256.h>
#include <mbedtls/chacha20.h>
#include <mbedtls/constant_time.h>

#ifndef inline
	#undef inline
#endif


_IMPLSTB const mbedtls_md_info_t* _mbed_sha256_alg(void)
{
	const mbedtls_md_info_t* info;
	/* Get sha256 md info for hdkf operations */
	info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
	DEBUG_ASSERT2(info != NULL, "Expected SHA256 md info pointer to be valid")
	return info;
}

#if SIZE_MAX < UINT64_MAX
	#define _ssize_guard_int(x) if(x > SIZE_MAX) return 1;
#else
	#define _ssize_guard_int(x)
#endif

#ifndef _IMPL_CHACHA20_CRYPT
	
	/* Export chacha20 computation */
	#define _IMPL_CHACHA20_CRYPT _mbed_chacha20_encrypt	

	_IMPLSTB cstatus_t _mbed_chacha20_encrypt(
		const uint8_t* key,
		const uint8_t* nonce,
		const uint8_t* input,
		uint8_t* output,
		uint32_t dataLen
	)
	{
		_overflow_check(dataLen)

		/* Counter always starts at 0 */
		return mbedtls_chacha20_crypt(
			key, 
			nonce, 
			0x00u,		/* nip-44 counter version */
			dataLen, 
			input, 
			output
		) == 0 ? CSTATUS_OK : CSTATUS_FAIL;
	}

#endif

/* Export sha256 if not already defined */
#ifndef _IMPL_CRYPTO_SHA256_DIGEST	
	
	#define _IMPL_CRYPTO_SHA256_DIGEST			_mbed_sha256_digest	

	_IMPLSTB cstatus_t _mbed_sha256_digest(const cspan_t* data, sha256_t digestOut32)
	{
		_overflow_check(data->size)

		return mbedtls_sha256(
			data->data, 
			data->size, 
			digestOut32, 
			0				/* Set 0 for sha256 mode */
		) == 0 ? CSTATUS_OK : CSTATUS_FAIL;
	}

#endif

/* Export Sha256 hmac if not already defined by other libs */
#ifndef _IMPL_CRYPTO_SHA256_HMAC

	#define _IMPL_CRYPTO_SHA256_HMAC			_mbed_sha256_hmac

	_IMPLSTB cstatus_t _mbed_sha256_hmac(const cspan_t* key, const cspan_t* data, sha256_t hmacOut32)
	{
		_overflow_check(data->size)

		/* Keys should never be large enough for this to matter, but sanity check. */
		DEBUG_ASSERT2(key->size < SIZE_MAX, "Expected key size to be less than SIZE_MAX")

		return mbedtls_md_hmac(
			_mbed_sha256_alg(),
			key->data, 
			key->size,
			data->data, 
			data->size,
			hmacOut32
		) == 0 ? CSTATUS_OK : CSTATUS_FAIL;
	}
#endif

/* Export hkdf expand if not already defined */
#ifndef _IMPL_CRYPTO_SHA256_HKDF_EXPAND

	#define _IMPL_CRYPTO_SHA256_HKDF_EXPAND		_mbed_sha256_hkdf_expand

	_IMPLSTB cstatus_t _mbed_sha256_hkdf_expand(const cspan_t* prk, const cspan_t* info, span_t* okm)
	{
		/* These sizes should never be large enough to overflow on <64bit platforms, but sanity check */
		DEBUG_ASSERT(okm->size < SIZE_MAX)
		DEBUG_ASSERT(prk->size < SIZE_MAX)
		DEBUG_ASSERT(info->size < SIZE_MAX)

		return mbedtls_hkdf_expand(
			_mbed_sha256_alg(),
			prk->data, 
			prk->size,
			info->data, 
			info->size,
			okm->data, 
			okm->size
		) == 0 ? CSTATUS_OK : CSTATUS_FAIL;
	}

#endif

/* Export fixed-time compare if not already defined */
#ifndef _IMPL_CRYPTO_FIXED_TIME_COMPARE

	#define _IMPL_CRYPTO_FIXED_TIME_COMPARE		_mbed_fixed_time_compare

	/* fixed-time memcmp */
	_IMPLSTB uint32_t _mbed_fixed_time_compare(const uint8_t* a, const uint8_t* b, uint32_t size)
	{
		_ssize_guard_int(size)

		return (uint32_t)mbedtls_ct_memcmp(a, b, size);
	}
#endif

#endif