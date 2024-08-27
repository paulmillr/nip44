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

/*
* This header includes some optional high-level nostr crypto utility functions
* for much easer app development.
*/

#pragma once

#ifndef NOSCRYPTUTIL_H
#define NOSCRYPTUTIL_H

#ifdef __cplusplus
extern "C" {
#endif 

#include "noscrypt.h"

#define E_OUT_OF_MEMORY					-10

#define E_CIPHER_INVALID_FORMAT			-11
#define E_CIPHER_BAD_NONCE				-12
#define E_CIPHER_MAC_INVALID			-13
#define E_CIPHER_NO_OUTPUT				-14
#define E_CIPHER_BAD_INPUT				-15
#define E_CIPHER_BAD_INPUT_SIZE			-16

#define NC_UTIL_CIPHER_MODE				0x01u

#define NC_UTIL_CIPHER_MODE_ENCRYPT		0x00u
#define NC_UTIL_CIPHER_MODE_DECRYPT		0x01u
#define NC_UTIL_CIPHER_ZERO_ON_FREE		0x02u
#define NC_UTIL_CIPHER_MAC_NO_VERIFY	0x04u
#define NC_UTIL_CIPHER_REUSEABLE		0x08u

/*
* The encryption context structure. This structure is used to store the state 
* of the encryption operation. The structure is opaque and should not be accessed 
* directly.
*/
typedef struct nc_util_enc_struct NCUtilCipherContext;

/*
* Gets the size of the padded buffer required for an encryption operation.
* @param encVersion The encryption specification version to use
* @param plaintextSize The size of the plaintext buffer in bytes
* @return The size of the padded buffer in bytes
*/
NC_EXPORT NCResult NC_CC NCUtilGetEncryptionPaddedSize(uint32_t encVersion, uint32_t plaintextSize);

/*
* Gets the size of the payload buffer required for an encryption operation.
* @param encVersion The encryption specification version to use
* @param plaintextSize The size of the plaintext buffer in bytes
* @return The size of the payload buffer in bytes
* @note The payload buffer is the final buffer to be sent to a nostr user. For nip04 this 
* is a raw AES message, for nip44 this is a mucher lager buffer. See the nostr specifications
* for more information.
*/
NC_EXPORT NCResult NC_CC NCUtilGetEncryptionBufferSize(uint32_t encVersion, uint32_t plaintextSize);

/*
* Allocates a new encryption context and sets the encryption version and flags. The encryption context
* must be freed with NCUtilCipherFree when it is no longer needed.
* @param encVersion The encryption specification version to use
* @param flags The flags to set on the encryption context
* @return A valid pointer to an encryption context or NULL if the operation failed
*/
NC_EXPORT NCUtilCipherContext* NC_CC NCUtilCipherAlloc(uint32_t encVersion, uint32_t flags);

/*
* Initializes the cipher context with the input data and size. This function will 
 internally allocate a the required output buffer for the cipher operation. You may only call
 this function once.
* @param encCtx A valid pointer to an allocated encryption context
* @param inputData A pointer to the input data for the Cipher
* @param inputSize The size of the input data
* @return NC_SUCCESS if the operation was successful, otherwise an error code. Use NCParseErrorCode to
the error code and positional argument that caused the error
*/
NC_EXPORT NCResult NC_CC NCUtilCipherInit(
	NCUtilCipherContext* encCtx,
	const uint8_t* inputData,
	uint32_t inputSize
);

/*
* Frees the encryption context and clears the memory if the NC_UTIL_CIPHER_ZERO_ON_FREE
* flag is set.
* @param encCtx A valid pointer to an allocated encryption context to free
*/
NC_EXPORT void NC_CC NCUtilCipherFree(NCUtilCipherContext* encCtx);

/*
* Gets the output size of the encryption context. This function will return the size of 
* the output buffer that will be written to when calling NCUtilCipherReadOutput.
* @param encCtx A valid pointer to an allocated encryption context
* @return The size of the output buffer in bytes
*/
NC_EXPORT NCResult NC_CC NCUtilCipherGetOutputSize(const NCUtilCipherContext* encCtx);

/*
* Reads the output buffer from the encryption context. This function will copy the output
* buffer to the output buffer provided. The output buffer must be at least the size of the
* output buffer returned by NCUtilCipherGetOutputSize.
* @param encCtx A valid pointer to an initialized encryption context
* @param output A pointer to the output buffer to copy the output to
* @param outputSize The size of the output buffer in bytes
* @returns The number of bytes written to the output buffer or an error code. Use NCParseErrorCode
* to get the error code and positional argument that caused the error
*/
NC_EXPORT NCResult NC_CC NCUtilCipherReadOutput(
	const NCUtilCipherContext* encCtx,
	uint8_t* output,
	uint32_t outputSize
);

/*
* Sets a property on the encryption context. Equivalent to calling NCEncryptionSetPropertyEx
* @param ctx A valid pointer to an encryption context
* @param property The property to set
* @param value A pointer to the value to set
* @param valueLen The length of the value
* @return NC_SUCCESS if the operation was successful, otherwise an error code. Use NCParseErrorCode to
* get the error code and positional argument that caused the error
*/
NC_EXPORT NCResult NC_CC NCUtilCipherSetProperty(
	NCUtilCipherContext* ctx,
	uint32_t property,
	uint8_t* value,
	uint32_t valueLen
);

/*
* Gets the flags set on the encryption context during initialization.
* @param ctx A valid pointer to an encryption context
* @return The flags set on the encryption context cast to a NCResult, or 
* an error code if the context is invalid. Use NCParseErrorCode to get the error code
* and positional argument that caused the error.
*/
NC_EXPORT NCResult NC_CC NCUtilCipherGetFlags(const NCUtilCipherContext* ctx);

/*
* Performs the desired Cipher option once. This may either cause an encryption 
* or decryption operation to be performed. Regardless of the operation, input data
* is consumed and output data is produced. 
* @param encCtx A valid pointer to an initialized encryption context
* @param libContext A valid pointer to an NCContext structure
* @param sk A valid pointer to the sender's private key
* @param pk A valid pointer to the receivers public key
* @return NC_SUCCESS if the operation was successful, otherwise an error code. Use NCParseErrorCode to
* get the error code and positional argument that caused the error.
* @note This function should only be called once. However it is indempotent and deterministic
* so the exact same operation should happen if called again.
*/
NC_EXPORT NCResult NC_CC NCUtilCipherUpdate(
	NCUtilCipherContext* encCtx,
	const NCContext* libContext,
	const NCSecretKey* sk,
	const NCPublicKey* pk
);

/*
* Gets the size of the IV(nonce) required for the encryption context.
* @param encCtx A valid pointer to an initialized encryption context
* @return The size of the IV in bytes, or a negative error code if the context 
* is invalid, or the version is not supported. Use NCParseErrorCode to get the error code
* and positional argument that caused the error.
*/
NC_EXPORT NCResult NC_CC NCUtilCipherGetIvSize(const NCUtilCipherContext* encCtx);

#ifdef __cplusplus
}
#endif

#endif /* NOSCRYPTUTIL_H */