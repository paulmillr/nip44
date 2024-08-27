/*
* Copyright (c) 2024 Vaughn Nugent
*
* Package: noscrypt
* File: providers/openssl.c
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


/* Setup openssl */
#ifdef OPENSSL_CRYPTO_LIB

#include <openssl/crypto.h>

#define _OSSL_FAIL(x) if(!(x)) return CSTATUS_FAIL;

#define ossl_md_sha256() EVP_MD_fetch(NULL, "SHA2-256", NULL)
#define ossl_evp_fetch_chacha20() EVP_CIPHER_fetch(NULL, "ChaCha20", NULL)
#define ossl_mac_fetch_hmac() EVP_MAC_fetch(NULL, "hmac", NULL)

#ifndef _IMPL_SECURE_ZERO_MEMSET

	#define _IMPL_SECURE_ZERO_MEMSET			_ossl_secure_zero_memset

	_IMPLSTB void _ossl_secure_zero_memset(void* ptr, size_t size)
	{
		_overflow_check(size)

		OPENSSL_cleanse(ptr, size);
	}
#endif

#ifndef _IMPL_CRYPTO_FIXED_TIME_COMPARE

	#define _IMPL_CRYPTO_FIXED_TIME_COMPARE		_ossl_fixed_time_compare

	_IMPLSTB uint32_t _ossl_fixed_time_compare(const uint8_t* a, const uint8_t* b, uint32_t size)
	{
		int result;

		/* Size checks are required for platforms that have integer sizes under 32bit */
		_overflow_check(size)

		result = CRYPTO_memcmp(a, b, size);

		return (uint32_t)result;
	}

#endif /* _IMPL_CRYPTO_FIXED_TIME_COMPARE */


#ifndef _IMPL_CRYPTO_SHA256_DIGEST	

	#include <openssl/sha.h>

	#define _IMPL_CRYPTO_SHA256_DIGEST			_ossl_sha256_digest	

	_IMPLSTB cstatus_t _ossl_sha256_digest(cspan_t data, sha256_t digestOut32)
	{
		_overflow_check(data.size);

		DEBUG_ASSERT(digestOut32 != NULL);
		DEBUG_ASSERT(ncSpanIsValidC(data));

		_OSSL_FAIL(
			SHA256(
				ncSpanGetOffsetC(data, 0),
				ncSpanGetSizeC(data),
				digestOut32
			)
		);

		return CSTATUS_OK;
	}

#endif

#ifndef _IMPL_CRYPTO_SHA256_HMAC

	#include <openssl/hmac.h>

	/* Export function */
	#define _IMPL_CRYPTO_SHA256_HMAC			_ossl_hmac_sha256	
	
	_IMPLSTB cstatus_t _ossl_hmac_sha256(cspan_t key, cspan_t data, sha256_t hmacOut32)
	{
		unsigned int hmacLen;

		_overflow_check(key.size)
		_overflow_check(data.size)

		hmacLen = sizeof(sha256_t);

		_OSSL_FAIL(
			HMAC(
				ossl_md_sha256(),
				ncSpanGetOffsetC(key, 0),
				ncSpanGetSizeC(key),
				ncSpanGetOffsetC(data, 0),
				ncSpanGetSizeC(data),
				hmacOut32,
				&hmacLen
			)
		);
		
		/* digest length should match the actual digest size */
		DEBUG_ASSERT(hmacLen == sizeof(sha256_t));

		return CSTATUS_OK;
	}

#endif /* !_IMPL_CRYPTO_SHA256_HMAC */

#ifndef _IMPL_CRYPTO_SHA256_HKDF_EXPAND
	
	#include <openssl/evp.h>

	#define _IMPL_CRYPTO_SHA256_HKDF_EXPAND		_ossl_sha256_hkdf_expand

	struct ossl_hmac_state {
		EVP_MAC_CTX* libCtx;
		OSSL_PARAM params[2];
		cspan_t prk; 
	};

	static cstatus_t _ossl_hmac_init(const struct ossl_hmac_state* osslCtx)
	{
		DEBUG_ASSERT(ncSpanIsValidC(osslCtx->prk));
		DEBUG_ASSERT(osslCtx->params != NULL);

		_OSSL_FAIL(
			EVP_MAC_init(
				osslCtx->libCtx,
				ncSpanGetOffsetC(osslCtx->prk, 0),
				ncSpanGetSizeC(osslCtx->prk),
				osslCtx->params
			)
		);

		return CSTATUS_OK;
	}

	static cstatus_t _ossl_hkdf_update(void* ctx, cspan_t data)
	{
		const struct ossl_hmac_state* osslCtx;

		DEBUG_ASSERT(ctx != NULL);
		_overflow_check(data.size);

		osslCtx = (const struct ossl_hmac_state*)ctx;

		DEBUG_ASSERT(osslCtx->libCtx != NULL);

		_OSSL_FAIL(
			EVP_MAC_update(
				osslCtx->libCtx,
				ncSpanGetOffsetC(data, 0),
				ncSpanGetSizeC(data)
			)
		);
		
		return CSTATUS_OK;
	}

	static cstatus_t _ossl_hkdf_finish(void* ctx, sha256_t hmacOut32)
	{
		const struct ossl_hmac_state* osslCtx;
		size_t hmacSize;

		DEBUG_ASSERT(ctx != NULL);
		DEBUG_ASSERT(hmacOut32 != NULL);

		osslCtx = (const struct ossl_hmac_state*)ctx;
		hmacSize = 0;

		DEBUG_ASSERT(osslCtx->libCtx != NULL);

		_OSSL_FAIL(
			EVP_MAC_final(
				osslCtx->libCtx,
				hmacOut32,
				&hmacSize,
				sizeof(sha256_t)
			)
		);

		/* When configured for sha256, should always be the same size in/out */
		DEBUG_ASSERT(hmacSize == sizeof(sha256_t));		

		/* 
		* Context must be re-initalized after finalize
		* See lifecycle https://docs.openssl.org/3.0/man7/life_cycle-mac/#copyright
		*/

		return _ossl_hmac_init(osslCtx);
	}
	

	_IMPLSTB cstatus_t _ossl_sha256_hkdf_expand(cspan_t prk, cspan_t info, span_t okm)
	{
		EVP_MAC* mac;
		cstatus_t result;
		struct ossl_hmac_state hkdfState;
		struct nc_hkdf_fn_cb_struct handler;		

		result = CSTATUS_FAIL;

		handler.update = _ossl_hkdf_update;
		handler.finish = _ossl_hkdf_finish;
	
		_overflow_check(prk.size);
		_overflow_check(info.size);
		_overflow_check(okm.size);

		hkdfState.params[0] = OSSL_PARAM_construct_utf8_string("digest", "sha256", 0);
		hkdfState.params[1] = OSSL_PARAM_construct_end();

		hkdfState.prk = prk;

		/*
		* Silly openssl stuff. Enable hmac with sha256 using the system default
		* security provider. The one-shot flag must also be disabled (0) because
		* we need to call update multiple times.
		*/

		mac = ossl_mac_fetch_hmac();

		if (mac == NULL)
		{
			goto Cleanup;
		}

		hkdfState.libCtx = EVP_MAC_CTX_new(mac);

		if (hkdfState.libCtx == NULL)
		{
			goto Cleanup;
		}

		if (_ossl_hmac_init(&hkdfState) != CSTATUS_OK)
		{
			goto Cleanup;
		}

		DEBUG_ASSERT(EVP_MAC_CTX_get_mac_size(hkdfState.libCtx) == sizeof(sha256_t));

		/* Pass the library  */
		result = hkdfExpandProcess(&handler, &hkdfState, info, okm);

	Cleanup:
		
		if (hkdfState.libCtx) EVP_MAC_CTX_free(hkdfState.libCtx);
		if (mac) EVP_MAC_free(mac);

		return result;
	}

#endif /* !_IMPL_CRYPTO_SHA256_HKDF_EXPAND */

#ifndef _IMPL_CHACHA20_CRYPT

    #include <openssl/evp.h>

	#define _IMPL_CHACHA20_CRYPT _ossl_chacha20_crypt

	_IMPLSTB cstatus_t _ossl_cipher_core(
		const EVP_CIPHER* cipher,
		cspan_t key,
		cspan_t iv,
		cspan_t input,
		span_t output
	)
	{
		cstatus_t result;
		EVP_CIPHER_CTX* ctx;
		int tempLen, osslResult;

		DEBUG_ASSERT2(ncSpanGetSize(output) <= ncSpanGetSizeC(input), "Output buffer must be equal or larger than the input buffer");
		DEBUG_ASSERT(cipher != NULL);

		DEBUG_ASSERT((uint32_t)EVP_CIPHER_get_key_length(cipher) == ncSpanGetSizeC(key));
		DEBUG_ASSERT((uint32_t)EVP_CIPHER_iv_length(cipher) == ncSpanGetSizeC(iv));

		result = CSTATUS_FAIL;

		ctx = EVP_CIPHER_CTX_new();

		if (ctx == NULL)
		{
			goto Cleanup;
		}

		osslResult = EVP_EncryptInit_ex2(
			ctx, 
			cipher, 
			ncSpanGetOffsetC(key, 0),
			ncSpanGetOffsetC(iv, 0),
			NULL
		);

		if (!osslResult)
		{
			goto Cleanup;
		}

		osslResult = EVP_EncryptUpdate(
			ctx,
			ncSpanGetOffset(output, 0),
			&tempLen,
			ncSpanGetOffsetC(input, 0),
			ncSpanGetSizeC(input)
		);

		if (!osslResult)
		{
			goto Cleanup;
		}

		/*
		* We can't get a pointer outside the range of the 
		* output buffer
		*/
		if (((uint32_t)tempLen) < ncSpanGetSize(output))
		{
			if (!EVP_EncryptFinal_ex(ctx, ncSpanGetOffset(output, tempLen), &tempLen))
			{
				goto Cleanup;
			}
		}

		result = CSTATUS_OK;

	Cleanup:

		if (ctx) EVP_CIPHER_CTX_free(ctx);

		return result;
	}

	_IMPLSTB cstatus_t _ossl_chacha20_crypt(
		const uint8_t* key,
		const uint8_t* nonce,
		const uint8_t* input,
		uint8_t* output,
		uint32_t dataLen
	)
	{
		cstatus_t result;
		EVP_CIPHER* cipher;
		uint8_t chaChaIv[CHACHA_NONCE_SIZE + 4];
		cspan_t keySpan, nonceSpan, inputSpan;
		span_t outputSpan;

		result = CSTATUS_FAIL;

		/*
		* RFC 7539 ChaCha20 requires a 16 byte initialization vector. A 
		* counter value is preprended to the nonce to make up the 16 byte 
		* size.
		*
		* The counter is always set to 0 for the nonce.
		*/

		ncCryptoSecureZero(chaChaIv, sizeof(chaChaIv));
		MEMMOV(chaChaIv + 4, nonce, CHACHA_NONCE_SIZE);

		ncSpanInitC(&keySpan, key, CHACHA_KEY_SIZE);
		ncSpanInitC(&nonceSpan, chaChaIv, sizeof(chaChaIv));
		ncSpanInitC(&inputSpan, input, dataLen);
		ncSpanInit(&outputSpan, output, dataLen);

		cipher = ossl_evp_fetch_chacha20();

		if (cipher == NULL)
		{
			goto Cleanup;
		}

		result = _ossl_cipher_core(
			cipher, 
			keySpan, 
			nonceSpan, 
			inputSpan, 
			outputSpan
		);

	Cleanup:
		
		if (cipher) EVP_CIPHER_free(cipher);

		return result;
	}

#endif

#endif	/*!OPENSSL_CRYPTO_LIB */