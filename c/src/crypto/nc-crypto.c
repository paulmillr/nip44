/*
* Copyright (c) 2024 Vaughn Nugent
*
* Package: noscrypt
* File: nc-crypto.c
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

#include "nc-util.h"
#include "nc-crypto.h"

/*
*  Functions are not forced inline, just suggested.
*  So unless it becomes a performance issue, I will leave
*  most/all impl functions inline and let the compiler 
*  decide.
*/

#define _IMPLSTB static _nc_fn_inline

/*
* Impl .c files may define the following macros for function implementations:
* 
*		_IMPL_SECURE_ZERO_MEMSET			secure memset 0 function
*		_IMPL_CHACHA20_CRYPT				chacha20 cipher function
*		_IMPL_CRYPTO_FIXED_TIME_COMPARE		fixed time compare function
*		_IMPL_CRYPTO_SHA256_HMAC			sha256 hmac function
*		_IMPL_CRYPTO_SHA256_DIGEST			standard sha256 digest function
* 		_IMPL_CRYPTO_SHA256_HKDF_EXPAND		hkdf expand function
* 		_IMPL_CRYPTO_SHA256_HKDF_EXTRACT	hkdf extract function
* 
* Macros are used to allow the preprocessor to select the correct implementation
* or raise errors if no implementation is defined.
* 
* Implementation functions can assume inputs have been checked/sanitized by the
* calling function, and should return CSTATUS_OK on success, CSTATUS_FAIL on failure.
*/


/*
* Prioritize embedded builds with mbedtls
*/
#include "impl/mbedtls.c"

/*
* Include openssl as an alternative default 
* implementation
*/
#include "impl/openssl.c"

/*
* Include win32 platform specific fallback support 
* using bcrypt.
*/
#include "impl/bcrypt.c"

/*
* Handle default implementations of secure 
* memset 0 functions for each platform.
*/
#ifndef _IMPL_SECURE_ZERO_MEMSET
   /* only incude bzero if libc version greater than 2.25 */
	#if defined(__GLIBC__) && defined(__GLIBC_MINOR__) && __GLIBC__ >= 2 && __GLIBC_MINOR__ >= 25
		/*
		*	When using libc, we can use explicit_bzero
		*	as secure memset implementation.
		* 
		*	https://sourceware.org/glibc/manual/2.39/html_mono/libc.html#Erasing-Sensitive-Data
		*/
		#include <string.h>
		extern void explicit_bzero(void* block, size_t len);
		#define _IMPL_SECURE_ZERO_MEMSET explicit_bzero
	#endif
#endif

/*
* Finally fall back to monocipher to handle some
* that are not provided by other libraries.
*
* Platform specific opimizations are considered
* "better" than monocypher options, so this is
* added as a last resort. Momocypher is "correct"
* and portable, but not optimized for any specific
* platform.
*/
#include "impl/monocypher.c"


#ifdef _IMPL_CRYPTO_SHA256_HMAC

	/*
	* If a library does not provide a HKDF extract function,
	* we can just use the HMAC function as a fallback.
	*
	* This is a fallback because another library may provide
	* a more optimized implementation.
	*/

	#ifndef _IMPL_CRYPTO_SHA256_HKDF_EXTRACT 

		#define _IMPL_CRYPTO_SHA256_HKDF_EXTRACT		_fallbackHkdfExtract

		_IMPLSTB cstatus_t _fallbackHkdfExtract(const cspan_t* salt, const cspan_t* ikm, sha256_t prk)
		{
			return _IMPL_CRYPTO_SHA256_HMAC(salt, ikm, prk);
		}

	#endif /* !_IMPL_CRYPTO_SHA256_HKDF_EXTRACT */
	
#endif /* _IMPL_CRYPTO_SHA256_HMAC */

/* Fallback for fixed time comparison for all platforms */
#ifndef _IMPL_CRYPTO_FIXED_TIME_COMPARE

	#pragma message("Warning: No fixed time compare implementation defined, using fallback. This may not be secure on all platforms")

	#define _IMPL_CRYPTO_FIXED_TIME_COMPARE	_fallbackFixedTimeCompare

	/*
	* This implemntation is a slightly simplified version of 
	* MBed TLS constant time memcmp function, knowm to be a 32bit 
	* integer size
	*/

	static uint32_t _fallbackFixedTimeCompare(const uint8_t* a, const uint8_t* b, uint32_t size)
	{
		size_t i;
		uint32_t result;
		uint8_t O;
		volatile const uint8_t* A, * B;		

		result = 0;
		O = 0;
		A = (volatile const uint8_t*)a;
		B = (volatile const uint8_t*)b;

		/* Compare each byte */
		for(i = 0; i < size; i++)
		{
			/* Handle volatile read */
			O |= (A[i] ^ B[i]);

			result |= O;
		}

		return result;
	}

#endif /* !_IMPL_CRYPTO_FIXED_TIME_COMPARE */


/*
* Internal function implementations that perform
* basic checking and call the correct implementation
* for the desired crypto impl.
* 
* The following functions MUST be assumed to 
* perform basic input validation. Since these apis are 
* internal, debug asserts are used to ensure the
* function has been used correctly.
*/

void ncCryptoSecureZero(void* ptr, uint32_t size)
{
	DEBUG_ASSERT2(ptr != NULL, "Expected ptr to be non-null")

#ifndef _IMPL_SECURE_ZERO_MEMSET
	#error "No secure memset implementation defined"
#endif /* _IMPL_SECURE_ZERO_MEMSET */

	_IMPL_SECURE_ZERO_MEMSET(ptr, size);
}

uint32_t ncCryptoFixedTimeComp(const uint8_t* a, const uint8_t* b, uint32_t size)
{
	DEBUG_ASSERT2(a != NULL, "Expected a to be non-null")
	DEBUG_ASSERT2(b != NULL, "Expected b to be non-null")

#ifndef _IMPL_CRYPTO_FIXED_TIME_COMPARE
	#error "No fixed time compare implementation defined"
#endif /* !_IMPL_CRYPTO_FIXED_TIME_COMPARE */

	return _IMPL_CRYPTO_FIXED_TIME_COMPARE(a, b, size);
}

cstatus_t ncCryptoDigestSha256(const cspan_t* data, sha256_t digestOut32)
{
	/* Debug arg validate */
	DEBUG_ASSERT2(data != NULL && data->data != NULL,	"Expected data to be non-null")
	DEBUG_ASSERT2(digestOut32 != NULL,					"Expected digestOut32 to be non-null")

#ifndef _IMPL_CRYPTO_SHA256_DIGEST
	#error "No SHA256 implementation defined"
#endif /* !_IMPL_CRYPTO_SHA256_DIGEST */

	return _IMPL_CRYPTO_SHA256_DIGEST(data, digestOut32);
}

cstatus_t ncCryptoHmacSha256(const cspan_t* key, const cspan_t* data, sha256_t hmacOut32)
{
	/* Debug arg validate */
	DEBUG_ASSERT2(key != NULL && key->data != NULL,			"Expected key to be non-null")
	DEBUG_ASSERT2(data != NULL && data->data != NULL,		"Expected data to be non-null")
	DEBUG_ASSERT2(hmacOut32 != NULL && data->data != NULL,	"Expected hmacOut32 to be non-null")

#ifndef _IMPL_CRYPTO_SHA256_HMAC
	#error "No SHA256 HMAC implementation defined"
#endif /* !_IMPL_CRYPTO_SHA256_HMAC */

	return _IMPL_CRYPTO_SHA256_HMAC(key, data, hmacOut32);
}

cstatus_t ncCryptoSha256HkdfExpand(const cspan_t* prk, const cspan_t* info, span_t* okm)
{
	/* Debug arg validate */
	DEBUG_ASSERT2(prk != NULL && prk->data != NULL,		"Expected prk to be non-null")
	DEBUG_ASSERT2(info != NULL && info->data != NULL,	"Expected info to be non-null")
	DEBUG_ASSERT2(okm != NULL && okm->data != NULL,		"Expected okm to be non-null")

	/*
	* RFC 5869: 2.3
	* "length of output keying material in octets (<= 255 * HashLen)"
	* 
	* important as the counter is 1 byte, so it cannot overflow
	*/

	if(okm->size > (uint32_t)(0xFFu * SHA256_DIGEST_SIZE))
	{
		return CSTATUS_FAIL;
	}

#ifndef _IMPL_CRYPTO_SHA256_HKDF_EXPAND
	#error "No SHA256 HKDF expand implementation defined"
#endif /* !_IMPL_CRYPTO_SHA256_HKDF_EXPAND */
	
	return _IMPL_CRYPTO_SHA256_HKDF_EXPAND(prk, info, okm);
}

cstatus_t ncCryptoSha256HkdfExtract(const cspan_t* salt, const cspan_t* ikm, sha256_t prk)
{
	/* Debug arg validate */
	DEBUG_ASSERT2(salt != NULL, "Expected salt to be non-null")
	DEBUG_ASSERT2(ikm  != NULL, "Expected ikm to be non-null")
	DEBUG_ASSERT2(prk  != NULL, "Expected prk to be non-null")

#ifndef _IMPL_CRYPTO_SHA256_HKDF_EXTRACT
	#error "No SHA256 HKDF extract implementation defined"
#endif /* !_IMPL_CRYPTO_SHA256_HKDF_EXTRACT */
	
	return _IMPL_CRYPTO_SHA256_HKDF_EXTRACT(salt, ikm, prk);
}

cstatus_t ncCryptoChacha20(
	const uint8_t key[CHACHA_KEY_SIZE],
	const uint8_t nonce[CHACHA_NONCE_SIZE],
	const uint8_t* input,
	uint8_t* output,
	uint32_t dataSize
)
{
	DEBUG_ASSERT2(key != NULL,		"Expected key to be non-null")
	DEBUG_ASSERT2(nonce != NULL,	"Expected nonce to be non-null")
	DEBUG_ASSERT2(input != NULL,	"Expected input to be non-null")
	DEBUG_ASSERT2(output != NULL,	"Expected output to be non-null")

#ifndef _IMPL_CHACHA20_CRYPT
	#error "No chacha20 implementation defined"
#endif /* !_IMPL_CHACHA20_CRYPT */

	return _IMPL_CHACHA20_CRYPT(key, nonce, input, output, dataSize);
}
