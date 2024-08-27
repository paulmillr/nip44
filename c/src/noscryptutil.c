/*
* Copyright (c) 2024 Vaughn Nugent
*
* Package: noscrypt
* File: noscryptutil.h
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


#include <stdlib.h>

#include "nc-util.h"
#include "nc-crypto.h"

#include <noscryptutil.h>

/*
* Validation macros
*/

#ifdef NC_EXTREME_COMPAT
	#error "Utilities library must be disabled when using extreme compat mode"
#endif /* NC_EXTREME_COMPAT */

#define MIN_PADDING_SIZE		0x20u
#define NIP44_VERSION_SIZE		0x01u
#define NIP44_PT_LEN_SIZE		sizeof(uint16_t)
#define NIP44_NONCE_SIZE		NC_NIP44_IV_SIZE

/*
* minimum size for a valid nip44 payload
* 1 byte version + 32 byte nonce + 32 byte mac + 2 byte ptSize + 32bytes minimum length
*/
#define NIP44_MIN_PAYLOAD_SIZE  (NIP44_VERSION_SIZE + 0x20 + 0x02 + 0x20 + 0x02)

/*
* Max payload size is the maximum size of the encrypted message
* 1 byte version + 32 byte nonce + 32 byte mac + maximum ciphertext size
*/
#define NIP44_MAX_PAYLOAD_SIZE (NIP44_VERSION_SIZE + 0x20 + 0x20 + NIP44_MAX_ENC_MESSAGE_SIZE)

/*
* The minimum ciphertext size is the minimum padded size + the minimum
* size of the plaintext length field
*/
#define NIP44_MIN_CIPHERTEXT_SIZE (MIN_PADDING_SIZE + NIP44_PT_LEN_SIZE)


#define _nc_mem_free(x) if(x != NULL) { free(x); x = NULL; }
#define _nc_mem_alloc(elements, size) calloc(elements, size)
#define ZERO_FILL ncCryptoSecureZero

#ifndef NC_INPUT_VALIDATION_OFF
	#define CHECK_INVALID_ARG(x, argPos) if(x == NULL) return NCResultWithArgPosition(E_INVALID_ARG, argPos);
	#define CHECK_NULL_ARG(x, argPos) if(x == NULL) return NCResultWithArgPosition(E_NULL_PTR, argPos);
	#define CHECK_ARG_RANGE(x, min, max, argPos) if(x < min || x > max) return NCResultWithArgPosition(E_ARGUMENT_OUT_OF_RANGE, argPos);
	#define CHECK_ARG_IS(exp, argPos) if(!(exp)) return NCResultWithArgPosition(E_INVALID_ARG, argPos);
#else
	/* empty macros */
	#define CHECK_INVALID_ARG(x)
	#define CHECK_NULL_ARG(x, argPos) 
	#define CHECK_ARG_RANGE(x, min, max, argPos) 
	#define CHECK_ARG_IS(is, expected, argPos)
#endif /* !NC_DISABLE_INPUT_VALIDATION */

#ifdef _NC_IS_WINDOWS
	
	#include <math.h>

	/* performs a log2 on integer types */
	#define _math_int_log2(x)	(uint32_t)log2((double)x)

#else
	/* 
	* GCC/clang does not expose log2 so we can use the __builtin_clz
	* to find leading zeros of an integer and subtract that from 31 
	* (bit positions) for int32 
	*/
	static _nc_fn_inline uint32_t _math_int_log2(uint32_t val)
	{
		DEBUG_ASSERT(val < UINT32_MAX);

		return 31 - __builtin_clz(val);
	}
#endif

/* Currently were on nip44 version 2 */
static const uint8_t Nip44VersionValue[1] = { 0x02u };

struct cipher_buffer_state {
	
	cspan_t input;
	span_t output;

	cspan_t actualOutput;
};

struct nc_util_enc_struct {

	uint32_t _flags;

	NCEncryptionArgs encArgs;

	struct cipher_buffer_state buffer;
};

static _nc_fn_inline span_t _ncUtilAllocSpan(uint32_t count, size_t size)
{
	span_t span;

#if SIZE_MAX < UINT32_MAX

	if (count > SIZE_MAX)
	{
		return span;
	}

#endif

	ncSpanInit(
		&span, 
		_nc_mem_alloc((size_t)count, size),
		(uint32_t)count
	);

	return span;
}

static _nc_fn_inline void _ncUtilZeroSpan(span_t span)
{
	ZERO_FILL(span.data, span.size);
}

static _nc_fn_inline void _ncUtilFreeSpan(span_t span)
{
	_nc_mem_free(span.data);
}

static _nc_fn_inline uint32_t _calcNip44PtPadding(uint32_t plaintextSize)
{
	uint32_t chunk, nextPower, factor;

	/*
	* Taken from https://github.com/nostr-protocol/nips/blob/master/44.md
	*
	* I believe the idea is to add consisten padding for some better 
	* disgusing of the plainText data.
	*/

	if (plaintextSize <= MIN_PADDING_SIZE)
	{
		return MIN_PADDING_SIZE;
	}

	/* Safe to subtract because pt > 0 */
	nextPower = _math_int_log2(plaintextSize - 1);

	nextPower += 1u;

	nextPower = 1 << nextPower;

	if (nextPower <= 256u)
	{
		chunk = 32u;
	}
	else 
	{
		chunk = nextPower / 8u;
	}
	
	factor = plaintextSize - 1;

	factor /= chunk;

	factor += 1;

	return chunk * factor;
}

static _nc_fn_inline uint32_t _calcNip44TotalOutSize(uint32_t inputSize)
{
	uint32_t bufferSize;

	/*
	* Buffer size for nip44 is calculated as follows:
	*   1 byte for the version
	*   32 bytes for the nonce
	*   2 bytes for the length of the plainText
	*   ... padding size
	*   32 bytes for the MAC
	*/

	bufferSize = NIP44_VERSION_SIZE;

	bufferSize += NIP44_NONCE_SIZE;

	bufferSize += NIP44_PT_LEN_SIZE;

	bufferSize += _calcNip44PtPadding(inputSize);

	bufferSize += NC_ENCRYPTION_MAC_SIZE;

	return bufferSize;
}

static _nc_fn_inline span_t _nip44GetMacData(span_t payload)
{
	DEBUG_ASSERT(payload.size > NIP44_VERSION_SIZE + NC_ENCRYPTION_MAC_SIZE);

	/*
	* The nip44 mac is computed over the nonce+encrypted ciphertext
	* 
	* the ciphertext is the entire message buffer, so it includes 
	* version, nonce, data, padding, and mac space available.
	* 
	* This function will return a span that points to the nonce+data 
	* segment of the buffer for mac computation.
	* 
	* The nonce sits directly after the version byte, ct is after,
	* and the remaining 32 bytes are for the mac. So that means 
	* macData = ct.size - version.size + mac.size
	*/

	return ncSpanSlice(
		payload,
		NIP44_VERSION_SIZE,
		ncSpanGetSize(payload) - (NIP44_VERSION_SIZE + NC_ENCRYPTION_MAC_SIZE)
	);
}

static _nc_fn_inline span_t _nip44GetMacOutput(span_t payload)
{
	DEBUG_ASSERT(payload.size > NC_ENCRYPTION_MAC_SIZE);

	/*
	* Mac is the final 32 bytes of the ciphertext buffer
	*/
	return ncSpanSlice(
		payload,
		ncSpanGetSize(payload) - NC_ENCRYPTION_MAC_SIZE,
		NC_ENCRYPTION_MAC_SIZE
	);
}

static _nc_fn_inline int _nip44ParseSegments(
	cspan_t payload, 
	cspan_t* nonce,
	cspan_t* mac,
	cspan_t* macData,
	cspan_t* cipherText
)
{
	if (ncSpanGetSizeC(payload) < NIP44_MIN_PAYLOAD_SIZE)
	{
		return 0;
	}

	/* slice after the version and before the mac segments */
	*nonce = ncSpanSliceC(
		payload,
		NIP44_VERSION_SIZE,
		NIP44_NONCE_SIZE
	);

	/*
	* Mac is the final 32 bytes of the ciphertext buffer
	*/
	*mac = ncSpanSliceC(
		payload,
		ncSpanGetSizeC(payload) - NC_ENCRYPTION_MAC_SIZE,
		NC_ENCRYPTION_MAC_SIZE
	);

	/*
	* The mac data is the nonce+ct segment of the buffer for mac computation.
	*/
	*macData = ncSpanSliceC(
		payload,
		NIP44_VERSION_SIZE,
		ncSpanGetSizeC(payload) - (NIP44_VERSION_SIZE + NC_ENCRYPTION_MAC_SIZE)
	);

	/*
	* Ciphertext is after the nonce segment and before the mac segment
	*/
	*cipherText = ncSpanSliceC(
		payload,
		NIP44_VERSION_SIZE + NIP44_NONCE_SIZE,
		ncSpanGetSizeC(payload) - (NIP44_VERSION_SIZE + NIP44_NONCE_SIZE + NC_ENCRYPTION_MAC_SIZE)
	);

	return 1;
}


static _nc_fn_inline void _cipherPublishOutput(NCUtilCipherContext* buffer, uint32_t offset, uint32_t size)
{
	span_t slice;

	DEBUG_ASSERT(ncSpanIsValid(buffer->buffer.output));

	if (size == 0)
	{
		ncSpanInitC(&buffer->buffer.actualOutput, NULL, 0);
	}
	else
	{
		/* use slice for debug guards */
		slice = ncSpanSlice(buffer->buffer.output, offset, size);

		/* init readonly span from mutable */
		ncSpanInitC(
			&buffer->buffer.actualOutput, 
			ncSpanGetOffset(slice, 0), 
			ncSpanGetSize(slice)
		);
	}	
}

/*
* I want the encryption/decyption functions to be indempodent
* meaning all mutations that happen can be repeated without
* side effects. IE no perminent state changes that can't be
* undone.
*/

static NCResult _nip44EncryptCompleteCore(
	const NCContext* libContext,
	const NCSecretKey* sk,
	const NCPublicKey* pk,
	NCUtilCipherContext* state
)
{

	NCResult result;
	cspan_t plainText;
	span_t macData, macOutput, message;
	uint32_t outPos;
	uint8_t ptSize[NIP44_PT_LEN_SIZE];
	uint8_t hmacKeyOut[NC_ENCRYPTION_MAC_SIZE];
	NCEncryptionArgs encArgs;

	outPos = 0;
	encArgs = state->encArgs;
	plainText = state->buffer.input;
	
	/*
	* Output buffer may be reused for multiple operations
	* so it may be larger than the actual output size but 
	* it is always guaranteed to be large enough to hold the
	* output data.
	* 
	* slice has debug guards to ensure output is large enough
	*/
	message = ncSpanSlice(
		state->buffer.output, 
		0, 
		_calcNip44TotalOutSize(plainText.size)
	);

	DEBUG_ASSERT(encArgs.version == NC_ENC_VERSION_NIP44);

	ZERO_FILL(hmacKeyOut, sizeof(hmacKeyOut));

	/* Get the nonce/iv size so we know how much nonce data to write */
	result = NCUtilCipherGetIvSize(state);
	DEBUG_ASSERT(result > 0);

	/* Start by appending the version number */
	ncSpanAppend(message, &outPos, Nip44VersionValue, sizeof(Nip44VersionValue));

	/* next is nonce data */
	ncSpanAppend(message, &outPos, encArgs.nonceData, (uint32_t)result);

	/* 
	* Assert the output points to the end of the nonce segment 
	* for nip44 this is exactly 33 bytes. This assert also doubles
	* to check the output of NCUtilCipherGetIvSize() to ensure
	* it's returning the correct size for nip44
	*/
	DEBUG_ASSERT(outPos == 1 + NIP44_NONCE_SIZE);

	/*
	* Assign the hmac key from the stack buffer. Since the args structure
	* is copied, it won't leak the address to the stack buffer.
	*
	* Should always return success for nip44 because all properties are valid
	* addresses.
	*/

	result = NCEncryptionSetPropertyEx(
		&encArgs,
		NC_ENC_SET_NIP44_MAC_KEY,
		hmacKeyOut,
		sizeof(hmacKeyOut)
	);

	DEBUG_ASSERT(result == NC_SUCCESS);

	/*
	* So this is the tricky part. The encryption operation appens directly
	* on the ciphertext segment
	*
	* All current implementations allow overlapping input and output buffers
	* so we can assign the pt segment on the encryption args
	*/

	/*
	* Since the message size and padding bytes will get encrypted,
	* the buffer should currently point to the start of the encryption segment
	*
	* The size of the data to encrypt is the padded size plus the size of the
	* plainText size field.
	*/

	result = NCEncryptionSetData(
		&encArgs,
		ncSpanGetOffset(message, outPos),	/* in place encryption */
		ncSpanGetOffset(message, outPos),
		NIP44_PT_LEN_SIZE + _calcNip44PtPadding(plainText.size) 	/* Plaintext + pt size must be encrypted */
	);

	DEBUG_ASSERT(result == NC_SUCCESS);

	/* big endian plaintext size */
	ptSize[0] = (uint8_t)(ncSpanGetSizeC(plainText) >> 8);
	ptSize[1] = (uint8_t)(ncSpanGetSizeC(plainText) & 0xFF);

	/*
	* Written position must point to the end of the padded ciphertext
	* area which the plaintext is written to.
	*
	* The plaintext data will be encrypted in place. The encrypted
	* data is the entired padded region containing the leading byte count
	* the plaintext data, followed by zero padding.
	*/

	ncSpanWrite(message, outPos, ptSize, sizeof(ptSize));

	ncSpanWrite(
		message,
		outPos + NIP44_PT_LEN_SIZE,		/* write pt directly after length */
		ncSpanGetOffsetC(plainText, 0),
		ncSpanGetSizeC(plainText)
	);

	/* 
	* Move position pointer directly after final padding bytes
	*/
	outPos += encArgs.dataSize;

	result = NCEncrypt(libContext, sk, pk, &encArgs);

	if (result != NC_SUCCESS)
	{
		return result;
	}

	/*
		MAC is computed over the nonce+encrypted data
		this helper captures that data segment into a span
	*/

	macData = _nip44GetMacData(message);
	macOutput = _nip44GetMacOutput(message);

	result = NCComputeMac(
		libContext,
		hmacKeyOut,
		ncSpanGetOffset(macData, 0),
		ncSpanGetSize(macData),
		ncSpanGetOffset(macOutput, 0)
	);

	if (result != NC_SUCCESS)
	{
		return result;
	}

	outPos += NC_ENCRYPTION_MAC_SIZE;

	DEBUG_ASSERT2(outPos == ncSpanGetSize(message), "Buffer under/overflow detected");

	/* publish all message bytes to output */
	_cipherPublishOutput(state, 0, outPos);

	/* zero hmac key before returning */
	ZERO_FILL(hmacKeyOut, sizeof(hmacKeyOut));

	return NC_SUCCESS;
}

static NCResult _nip44DecryptCompleteCore(
	const NCContext* libContext,
	const NCSecretKey* recvKey,
	const NCPublicKey* sendKey,
	NCUtilCipherContext* state
)
{
	NCResult result;
	NCMacVerifyArgs macArgs;
	NCEncryptionArgs encArgs;
	cspan_t macData, macValue, nonce, payload, cipherText;
	span_t output;
	uint16_t ptSize;

	DEBUG_ASSERT(libContext && recvKey && sendKey && state);
	DEBUG_ASSERT(state->encArgs.version == NC_ENC_VERSION_NIP44);
	DEBUG_ASSERT(ncSpanGetSizeC(state->buffer.input) >= NIP44_MIN_PAYLOAD_SIZE);

	/* ensure decryption mode */
	DEBUG_ASSERT(state->_flags & NC_UTIL_CIPHER_MODE_DECRYPT);

	/* store local stack copy for safe mutation */
	encArgs = state->encArgs;
	payload = state->buffer.input;
	output = state->buffer.output;

	/*
	* Copy the input buffer to the output buffer because the 
	* decryption happens in-place and needs a writable buffer
	* 
	* After the operation is complete, we will assign the actual plaintext 
	* data to the actual output buffer
	*/

	DEBUG_ASSERT2(ncSpanIsValid(output), "Output buffer was not allocated");

	if (!_nip44ParseSegments(payload, &nonce, &macValue, &macData, &cipherText))
	{
		return E_CIPHER_INVALID_FORMAT;
	}

	/* Verify mac if the user allowed it */
	if ((state->_flags & NC_UTIL_CIPHER_MAC_NO_VERIFY) == 0)
	{
		DEBUG_ASSERT(ncSpanGetSizeC(macValue) == NC_ENCRYPTION_MAC_SIZE);
		DEBUG_ASSERT(ncSpanGetSizeC(macData) > NIP44_NONCE_SIZE + MIN_PADDING_SIZE);

		/* Assign the mac data to the mac verify args */
		macArgs.mac32 = ncSpanGetOffsetC(macValue, 0);
		macArgs.nonce32 = ncSpanGetOffsetC(nonce, 0);
		
		/* message for verifying a mac in nip44 is the nonce+ciphertext */
		macArgs.payload = ncSpanGetOffsetC(macData, 0);
		macArgs.payloadSize = ncSpanGetSizeC(macData);

		/* Verify the mac */
		result = NCVerifyMac(libContext, recvKey, sendKey, &macArgs);

		/* When the mac is invlaid */
		if (result == E_OPERATION_FAILED)
		{
			return E_CIPHER_MAC_INVALID;
		}
		/* argument errors */
		else if (result != NC_SUCCESS)
		{
			return result;
		}
	}

	/* 
	* manually assign nonce because it's a constant pointer which
	* is not allowed when calling setproperty 
	*/
	encArgs.nonceData = ncSpanGetOffsetC(nonce, 0);

	DEBUG_ASSERT2(cipherText.size >= MIN_PADDING_SIZE, "Cipertext segment was parsed incorrectly. Too small");
	
	result = NCEncryptionSetData(
		&encArgs,
		ncSpanGetOffsetC(cipherText, 0),
		ncSpanGetOffset(output, 0),			/*decrypt ciphertext and write directly to the output buffer */
		ncSpanGetSizeC(cipherText)
	);

	DEBUG_ASSERT(result == NC_SUCCESS);

	/*
	* If decryption was successful, the data should be written 
	* directly to the output buffer
	*/
	result = NCDecrypt(libContext, recvKey, sendKey, &encArgs);

	if (result != NC_SUCCESS)
	{
		return result;
	}

	/*
	* Parse CT length and assign the output buffer.
	* 
	* PT size is stored at the beginning of the ciphertext
	* segment and is 2 bytes in size, big endian.
	*/

	ptSize = (uint16_t)(output.data[0] << 8 | output.data[1]);

	/*
	* If the PT is corrupted or set maliciously, it can overrun
	* the current buffer. The PT size must be less than the
	* ciphertext size.
	*/
	if (!ncSpanIsValidRange(output, NIP44_PT_LEN_SIZE, ptSize))
	{
		return E_OPERATION_FAILED;
	}

	/*
	* actual output span should now point to the decrypted plaintext
	* data segment
	*/
	_cipherPublishOutput(state, NIP44_PT_LEN_SIZE, ptSize);

	DEBUG_ASSERT(ncSpanGetSizeC(state->buffer.actualOutput) < ncSpanGetSizeC(cipherText));

	return NC_SUCCESS;
}

NC_EXPORT NCResult NC_CC NCUtilGetEncryptionPaddedSize(uint32_t encVersion, uint32_t plaintextSize)
{
	switch (encVersion)
	{
	default:
		return E_VERSION_NOT_SUPPORTED;

	case NC_ENC_VERSION_NIP04:
		return plaintextSize;

	case NC_ENC_VERSION_NIP44:

		/*
		* Ensure the plaintext size if a nip44 message does not exceed the maximum size
		*/
		CHECK_ARG_IS(plaintextSize - 1 <= NIP44_MAX_ENC_MESSAGE_SIZE, 1);

		return (NCResult)(_calcNip44PtPadding(plaintextSize));
	}
}

NC_EXPORT NCResult NC_CC NCUtilGetEncryptionBufferSize(uint32_t encVersion, uint32_t plaintextSize)
{

	switch (encVersion)
	{
	default:
		return E_VERSION_NOT_SUPPORTED;

		/*
		* NIP-04 simply uses AES to 1:1 encrypt the plainText
		* to ciphertext.
		*/
	case NC_ENC_VERSION_NIP04:
		return plaintextSize;

	case NC_ENC_VERSION_NIP44:
		return (NCResult)(_calcNip44TotalOutSize(plaintextSize));
	}
}


NC_EXPORT NCUtilCipherContext* NC_CC NCUtilCipherAlloc(uint32_t encVersion, uint32_t flags)
{
	NCUtilCipherContext* encCtx;

	/*
	* Alloc context on heap
	*/
	encCtx = (NCUtilCipherContext*)_nc_mem_alloc(1, sizeof(NCUtilCipherContext));

	if (encCtx != NULL)
	{
		/* 
		* Technically I should be using the NCEncSetProperty but this 
		* is an acceptable shortcut for now, may break in future 
		*/
		encCtx->encArgs.version = encVersion;
		encCtx->_flags = flags;
	}

	return encCtx;
}

NC_EXPORT void NC_CC NCUtilCipherFree(NCUtilCipherContext* encCtx)
{
	if (!encCtx) 
	{
		return;
	}

	/*
	* If zero on free flag is set, we can zero all output memory 
	* before returning the buffer back to the heap
	*/
	if ((encCtx->_flags & NC_UTIL_CIPHER_ZERO_ON_FREE) > 0 && ncSpanIsValid(encCtx->buffer.output)) 
	{
		_ncUtilZeroSpan(encCtx->buffer.output);
	}

	/* Free output buffers (null buffers are allowed) */
	_ncUtilFreeSpan(encCtx->buffer.output);

	/* context can be released */
	_nc_mem_free(encCtx);
}

NC_EXPORT NCResult NC_CC NCUtilCipherInit(
	NCUtilCipherContext* encCtx,
	const uint8_t* inputData,
	uint32_t inputSize
)
{
	NCResult outputSize;

	CHECK_NULL_ARG(encCtx, 0);
	CHECK_NULL_ARG(inputData, 1);

	if ((encCtx->_flags & NC_UTIL_CIPHER_MODE) == NC_UTIL_CIPHER_MODE_DECRYPT)
	{
		/*
		* Validate the input data for proper format for 
		* the current state version
		*/
		switch (encCtx->encArgs.version)
		{
		case NC_ENC_VERSION_NIP44:
		{
			if (inputSize < NIP44_MIN_PAYLOAD_SIZE)
			{
				return E_CIPHER_BAD_INPUT_SIZE;
			}

			if (inputSize > NIP44_MAX_PAYLOAD_SIZE)
			{
				return E_CIPHER_BAD_INPUT_SIZE;
			}

			/* Ensure the first byte is a valid version */
			if (inputData[0] != Nip44VersionValue[0])
			{
				return E_VERSION_NOT_SUPPORTED;
			}

			break;
		}
		default:
			return E_VERSION_NOT_SUPPORTED;
		}

		/*
		* Alloc a the output buffer to be the same size as the input
		* data for decryption because the output will always be equal
		* or smaller than the input data. This is an over-alloc but 
		* that should be fine
		*/

		outputSize = inputSize;
	}
	else
	{
		/*
		* Calculate the correct output size to store the encryption
		* data for the given state version
		*/
		outputSize = NCUtilGetEncryptionBufferSize(encCtx->encArgs.version, inputSize);

		if (outputSize < 0)
		{
			return E_CIPHER_BAD_INPUT_SIZE;
		}
	}

	DEBUG_ASSERT(outputSize > 0);

	/*
	* If the buffer was previously allocated, the reuseable flag
	* must be set to allow the buffer to be re-used for another
	* operation.
	*/

	if (ncSpanIsValid(encCtx->buffer.output))
	{
		CHECK_ARG_IS((encCtx->_flags & NC_UTIL_CIPHER_REUSEABLE) > 0, 0);

		/*
		* if the existing buffer is large enough to hold the new 
		* data reuse it, otherwise free it and allocate a new buffer
		*/

		if (outputSize <= ncSpanGetSize(encCtx->buffer.output))
		{
			_ncUtilZeroSpan(encCtx->buffer.output);

			goto AssignInputAndExit;
		}
		else
		{
			_ncUtilFreeSpan(encCtx->buffer.output);
		}
	}

	/* Alloc output buffer within the struct */
	encCtx->buffer.output = _ncUtilAllocSpan((uint32_t)outputSize, sizeof(uint8_t));

	if (!ncSpanIsValid(encCtx->buffer.output))
	{
		return E_OUT_OF_MEMORY;
	}

AssignInputAndExit:

	/* Confirm output was allocated */
	DEBUG_ASSERT(ncSpanIsValid(encCtx->buffer.output));

	/* Assign the input data span to point to the assigned input data */
	ncSpanInitC(&encCtx->buffer.input, inputData, inputSize);

	return NC_SUCCESS;
}

NC_EXPORT NCResult NC_CC NCUtilCipherGetFlags(const NCUtilCipherContext* ctx)
{
	CHECK_NULL_ARG(ctx, 0);

	return (NCResult)(ctx->_flags);
}

NC_EXPORT NCResult NC_CC NCUtilCipherGetOutputSize(const NCUtilCipherContext* encCtx)
{
	CHECK_NULL_ARG(encCtx, 0);

	if (!ncSpanIsValidC(encCtx->buffer.actualOutput))
	{
		return E_CIPHER_NO_OUTPUT;
	}

	return (NCResult)(ncSpanGetSizeC(encCtx->buffer.actualOutput));
}

NC_EXPORT NCResult NC_CC NCUtilCipherReadOutput(
	const NCUtilCipherContext* encCtx,
	uint8_t* output,
	uint32_t outputSize
)
{
	CHECK_NULL_ARG(encCtx, 0);
	CHECK_NULL_ARG(output, 1);

	if (!ncSpanIsValidC(encCtx->buffer.actualOutput))
	{
		return E_CIPHER_NO_OUTPUT;
	}

	/* Buffer must be as large as the output data  */
	CHECK_ARG_RANGE(outputSize, ncSpanGetSizeC(encCtx->buffer.actualOutput), UINT32_MAX, 2);

	ncSpanReadC(
		encCtx->buffer.actualOutput,
		output,
		outputSize
	);

	return (NCResult)(ncSpanGetSizeC(encCtx->buffer.actualOutput));
}

NC_EXPORT NCResult NC_CC NCUtilCipherSetProperty(
	NCUtilCipherContext* ctx,
	uint32_t property,
	uint8_t* value,
	uint32_t valueLen
)
{	
	CHECK_NULL_ARG(ctx, 0)

	/* All other arguments are verified */
	return NCEncryptionSetPropertyEx(
		&ctx->encArgs, 
		property, 
		value, 
		valueLen
	);
}

NC_EXPORT NCResult NC_CC NCUtilCipherUpdate(
	NCUtilCipherContext* encCtx,
	const NCContext* libContext,
	const NCSecretKey* sk,
	const NCPublicKey* pk
)
{
	CHECK_NULL_ARG(encCtx, 0);
	CHECK_NULL_ARG(libContext, 1);
	CHECK_NULL_ARG(sk, 2);
	CHECK_NULL_ARG(pk, 3);

	/* Make sure input & output buffers have been assigned/allocated */
	if (!ncSpanIsValid(encCtx->buffer.output))
	{
		return E_INVALID_CONTEXT;
	}
	if (!ncSpanIsValidC(encCtx->buffer.input))
	{
		return E_INVALID_CONTEXT;
	}

	/* Reset output data pointer incase it has been moved */
	_cipherPublishOutput(encCtx, 0, 0);

	switch (encCtx->encArgs.version)
	{
	case NC_ENC_VERSION_NIP44:

		if ((encCtx->_flags & NC_UTIL_CIPHER_MODE) == NC_UTIL_CIPHER_MODE_DECRYPT)
		{
			return _nip44DecryptCompleteCore(libContext, sk, pk, encCtx);
		}
		else
		{
			/* Ensure the user manually specified a nonce buffer for encryption mode */
			if (!encCtx->encArgs.nonceData)
			{
				return E_CIPHER_BAD_NONCE;
			}

			return _nip44EncryptCompleteCore(libContext, sk, pk, encCtx);
		}

	default:
		return E_VERSION_NOT_SUPPORTED;
	}
}

NC_EXPORT NCResult NC_CC NCUtilCipherGetIvSize(const NCUtilCipherContext* encCtx)
{
	uint32_t ivSize;

	CHECK_NULL_ARG(encCtx, 0);

	ivSize = NCEncryptionGetIvSize(encCtx->encArgs.version);

	return ivSize == 0
		? E_VERSION_NOT_SUPPORTED
		: (NCResult)ivSize;
}
