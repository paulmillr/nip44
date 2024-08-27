/*
* Copyright (c) 2024 Vaughn Nugent
*
* Package: noscrypt
* File: providers/bcrypt.c
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
*	This file provides as many fallback implementations on Windows plaforms
*	as possible using the bcrypt library. This file should be included behind
*	other libarry implementations, as it is a fallback.
*/

#ifdef _NC_IS_WINDOWS

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <bcrypt.h>

#define IF_BC_FAIL(x) if(!BCRYPT_SUCCESS(x)) 
#define BC_FAIL(x) if(!BCRYPT_SUCCESS(x)) return CSTATUS_FAIL;

struct _bcrypt_ctx
{
	BCRYPT_ALG_HANDLE hAlg;
	BCRYPT_HASH_HANDLE hHash;
};

_IMPLSTB NTSTATUS _bcInitSha256(struct _bcrypt_ctx* ctx, DWORD flags)
{
	NTSTATUS result;

	result = BCryptOpenAlgorithmProvider(
		&ctx->hAlg, 
		BCRYPT_SHA256_ALGORITHM, 
		NULL, 
		flags
	);

	/*
	*  If operation failed, ensure the algorithm handle is null
	* to make free code easier to cleanup
	*/
	if (!BCRYPT_SUCCESS(result))
	{
		ctx->hAlg = NULL;
	}

	return result;
}

_IMPLSTB NTSTATUS _bcCreateHmac(struct _bcrypt_ctx* ctx, cspan_t key)
{
	/*
	 * NOTE: 
	 * I am not explicitly managing the update object buffer. By setting 
	 * the update object to NULL, and length to 0, the buffer will be
	 * managed by the bcrypt library.
	 * 
	 * See: https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptcreatehash
	 */

	return BCryptCreateHash(
		ctx->hAlg, 
		&ctx->hHash, 
		NULL, 
		0, 
		(uint8_t*)ncSpanGetOffsetC(key, 0), 
		ncSpanGetSizeC(key),
		BCRYPT_HASH_REUSABLE_FLAG	/* Enable reusable for expand function */
	);
}

_IMPLSTB NTSTATUS _bcCreate(struct _bcrypt_ctx* ctx)
{
	cspan_t key;
	
	/* Zero out key span for 0 size and NULL data ptr */
	SecureZeroMemory(&key, sizeof(cspan_t));

	return _bcCreateHmac(ctx, key);
}

_IMPLSTB NTSTATUS _bcHashDataRaw(const struct _bcrypt_ctx* ctx, const uint8_t* data, uint32_t len)
{
	return BCryptHashData(ctx->hHash, (uint8_t*)data, len, 0);
}

_IMPLSTB NTSTATUS _bcHashData(const struct _bcrypt_ctx* ctx, cspan_t data)
{
	return _bcHashDataRaw(
		ctx, 
		ncSpanGetOffsetC(data, 0),
		ncSpanGetSizeC(data)
	);
}

_IMPLSTB NTSTATUS _bcFinishHash(const struct _bcrypt_ctx* ctx, sha256_t digestOut32)
{
	return BCryptFinishHash(ctx->hHash, digestOut32, sizeof(sha256_t), 0);
}

_IMPLSTB void _bcDestroyCtx(struct _bcrypt_ctx* ctx)
{
	/* Free the update memory if it was allocated */
	if(ctx->hHash) BCryptDestroyHash(ctx->hHash);
	
	/* Close the algorithm provider */
	if (ctx->hAlg) BCryptCloseAlgorithmProvider(ctx->hAlg, 0);

	ctx->hHash = NULL;
	ctx->hAlg = NULL;	
}

#ifndef _IMPL_SECURE_ZERO_MEMSET
	/*
	* On Windows, we can use SecureZeroMemory
	* as platform zeroing function.
	*
	* NOTE:
	* SecureZeroMemory2 uses volitle function argument
	* pointers, which is a contested mehtod of compiler
	* optimization prevention. GNU seems to oppose this method
	*
	* https://learn.microsoft.com/en-us/windows/win32/memory/winbase-securezeromemory2
	*/
	#define _IMPL_SECURE_ZERO_MEMSET SecureZeroMemory
#endif /* !_IMPL_SECURE_ZERO_MEMSET */

/*
* Provide win32 fallback for sha256 digest if needed
*/

#ifndef _IMPL_CRYPTO_SHA256_DIGEST
	
	/* Export function fallack */
	#define _IMPL_CRYPTO_SHA256_DIGEST			_bcrypt_sha256_digest	

	_IMPLSTB cstatus_t _bcrypt_sha256_digest(cspan_t data, sha256_t digestOut32)
	{
		cstatus_t result;
		struct _bcrypt_ctx ctx;

		result = CSTATUS_FAIL;	/* Start in fail state */

		IF_BC_FAIL(_bcInitSha256(&ctx, 0)) goto Exit;

		IF_BC_FAIL(_bcCreate(&ctx)) goto Exit;

		IF_BC_FAIL(_bcHashData(&ctx, data)) goto Exit;
	
		IF_BC_FAIL(_bcFinishHash(&ctx, digestOut32)) goto Exit;

		result = CSTATUS_OK;	/* Hash operation completed, so set success */

	Exit:

		_bcDestroyCtx(&ctx);

		return result;
	}

#endif /* !_IMPL_CRYPTO_SHA256_DIGEST */

#ifndef _IMPL_CRYPTO_SHA256_HMAC

	/* Export function */
	#define _IMPL_CRYPTO_SHA256_HMAC				_bcrypt_hmac_sha256	
	
	_IMPLSTB cstatus_t _bcrypt_hmac_sha256(cspan_t key, cspan_t data, sha256_t hmacOut32)
	{
		cstatus_t result;
		struct _bcrypt_ctx ctx;

		result = CSTATUS_FAIL;		/* Start in fail state */

		/* Init context with hmac flag set */
		IF_BC_FAIL(_bcInitSha256(&ctx, BCRYPT_ALG_HANDLE_HMAC_FLAG)) goto Exit;

		IF_BC_FAIL(_bcCreateHmac(&ctx, key)) goto Exit;

		IF_BC_FAIL(_bcHashData(&ctx, data)) goto Exit;

		IF_BC_FAIL(_bcFinishHash(&ctx, hmacOut32)) goto Exit;

		result = CSTATUS_OK;	/* HMAC operation completed, so set success */

	Exit:
		
		_bcDestroyCtx(&ctx);

		return result;
	}

#endif /* !_IMPL_CRYPTO_SHA256_HMAC */

/*
* Provide a fallback HKDF expand function using the
* HMAC function as a base.
*/

#ifndef _IMPL_CRYPTO_SHA256_HKDF_EXPAND

	#define _IMPL_CRYPTO_SHA256_HKDF_EXPAND		_bcrypt_fallback_hkdf_expand

	static cstatus_t _bcrypt_hkdf_update(void* ctx, cspan_t data)
	{
		DEBUG_ASSERT(ctx != NULL)

		BC_FAIL(_bcHashData((struct _bcrypt_ctx*)ctx, data))
		return CSTATUS_OK;
	}

	static cstatus_t _bcrypt_hkdf_finish(void* ctx, sha256_t hmacOut32)
	{
		DEBUG_ASSERT(ctx != NULL);
		DEBUG_ASSERT(hmacOut32 != NULL);

		BC_FAIL(_bcFinishHash((struct _bcrypt_ctx*)ctx, hmacOut32))
		return CSTATUS_OK;
	}

	_IMPLSTB cstatus_t _bcrypt_fallback_hkdf_expand(cspan_t prk, cspan_t info, span_t okm)
	{
		cstatus_t result;
		struct _bcrypt_ctx ctx;
		struct nc_hkdf_fn_cb_struct handler;

		handler.update = _bcrypt_hkdf_update;
		handler.finish = _bcrypt_hkdf_finish;

		/* Init bcrypt */
		BC_FAIL(_bcInitSha256(&ctx, BCRYPT_ALG_HANDLE_HMAC_FLAG))

		BC_FAIL(_bcCreateHmac(&ctx, prk))

		/*
		* NOTE! Hmac reusable flag must be set to allow for multiple
		* calls to the finish function without losing the context.
		*/

		result = hkdfExpandProcess(&handler, &ctx, info, okm);

		_bcDestroyCtx(&ctx);

		return result;
	}

#endif /* !_IMPL_CRYPTO_SHA256_HKDF_EXPAND */

#endif /* _NC_IS_WINDOWS */