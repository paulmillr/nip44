/*
* Copyright (c) 2024 Vaughn Nugent
*
* Package: noscrypt
* File: noscrypt.h
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
* noscrypt is a an open-source, strict C89 library that performs the basic 
* cryptographic operations found in the Nostr protocol. It is designed to be
* portable and easy to use in any C89 compatible environment. It is also designed
*/

#pragma once

#ifndef NOSCRYPT_H
#define NOSCRYPT_H

#include <stdint.h>
#include <stddef.h>
#include "platform.h"

/* Set api export calling convention (allow used to override) */
#ifndef NC_CC
	#ifdef _NC_IS_WINDOWS
		/* STD for importing to other languages such as .NET */
		#define NC_CC __stdcall
	#else
		#define NC_CC 
	#endif
#endif /*  !NC_CC */

#ifndef NC_EXPORT	/* Allow users to disable the export/impoty macro if using source code directly */
	#ifdef NOSCRYPT_EXPORTING
		#ifdef _NC_IS_WINDOWS
			#define NC_EXPORT __declspec(dllexport)
		#else
			#define NC_EXPORT __attribute__((visibility("default")))
		#endif /*  _NC_IS_WINDOWS */
	#else
		#ifdef _NC_IS_WINDOWS
			#define NC_EXPORT __declspec(dllimport)
		#else
			#define NC_EXPORT
		#endif /*  _NC_IS_WINDOWS */
	#endif /*  !NOSCRYPT_EXPORTING */
#endif /*  !NC_EXPORT */

/*
* CONSTANTS
*/
#define BIP340_PUBKEY_HEADER_BYTE		0x02
#define NIP44_MESSAGE_KEY_SIZE			0x4c	/*32 + 12 + 32 = 76 */
#define NC_ENCRYPTION_NONCE_SIZE		0x20
#define NC_SEC_KEY_SIZE					0x20
#define NC_PUBKEY_SIZE					0x20
#define NC_CONTEXT_ENTROPY_SIZE			0x20
#define NC_SHARED_SEC_SIZE				0x20
#define NC_CONV_KEY_SIZE				0x20
#define NC_HMAC_KEY_SIZE				0x20
#define NC_ENCRYPTION_MAC_SIZE			0x20
#define NC_MESSAGE_KEY_SIZE NIP44_MESSAGE_KEY_SIZE
#define NC_NIP04_AES_IV_SIZE			0x10	/* AES IV size is 16 bytes (block size) */

/*
* From spec
* https://github.com/nostr-protocol/nips/blob/master/44.md#decryption
*/
#define NIP44_MIN_ENC_MESSAGE_SIZE		0x01
#define NIP44_MAX_ENC_MESSAGE_SIZE		0xffff

#define NC_ENC_VERSION_NIP04			0x04
#define NC_ENC_VERSION_NIP44			0x2c

/*
*	ERROR CODES
* 
* Error codes are 64bit integers. The lower 8 bits are reserved for 
* the error code, and the upper 8 bits are reserved for the argument 
* position.
* 
* NCResult type is 64bit to also allow for positive return values for
* operations that return a value count.
*/

#define NC_ARG_POSITION_OFFSET		0x08
#define NC_ERROR_CODE_MASK			0xFF

#define NC_SUCCESS					0x00
#define E_NULL_PTR					-1
#define E_INVALID_ARG				-2
#define E_INVALID_CONTEXT			-3
#define E_ARGUMENT_OUT_OF_RANGE		-4
#define E_OPERATION_FAILED			-5
#define E_VERSION_NOT_SUPPORTED		-6


/* A compressed resul/return value, negative values 
are failure, 0 is success and positive values are 
defined by the operation. 
*/
typedef int64_t NCResult;

/*
 An secp256k1 secret key (aka private key buffer)
*/
typedef struct secret_key_struct {

	uint8_t key[NC_SEC_KEY_SIZE];

} NCSecretKey;

/*
  An x-only secp256k1 public key
*/
typedef struct xonly_pubkey_struct {

	uint8_t key[NC_PUBKEY_SIZE];

} NCPublicKey;

/*
	An opaque full library context object
*/
typedef struct ctx_struct {

	void* secpCtx;

} NCContext;

/*
* The encryption arguments structure. This structure is used to pass 
arguments to the encryption and decryption functions. It stores the
data buffers and required nonce used for the stream cipher.
*/
typedef struct nc_encryption_struct {

	/* The nonce used for the stream cipher. */
	const uint8_t* nonce32;

	/* Writes the hmac key to the buffer during encryption events.
	Set to NULL on decryption */
	uint8_t* hmacKeyOut32;

	/* The input data buffer to encrypt/decrypt */
	const uint8_t* inputData;

	/* The output data buffer to write data to */
	uint8_t* outputData;

	/* The size of the data buffers. Buffers must 
	* be the same size or larger than this value
	*/
	uint32_t dataSize;

	/* The version of the encryption standard to use */
	uint32_t version;

} NCEncryptionArgs;

/*
* A structure for Nip44 message authentication code verification. This structure
* is used to pass arguments to the NCVerifyMac and NCVerifyMacEx functions. 
*/
typedef struct nc_mac_verify {

	/* The message authentication code certifying the Nip44 payload */
	const uint8_t* mac32;

	/* The nonce used for the original message encryption */
	const uint8_t* nonce32;

	/* The message payload data */
	const uint8_t* payload;

	/* The size of the payload data */
	uint32_t payloadSize;

} NCMacVerifyArgs;


/*
	API FUNCTIONS
*/

/*
* A helper function to cast a buffer to a NCSecretKey struct
* @param key The buffer to cast
* @return A pointer to the NCSecretKey struct
*/
static _nc_fn_inline NCSecretKey* NCToSecKey(uint8_t key[NC_SEC_KEY_SIZE])
{
	return (NCSecretKey*)key;
}

/*
* A helper function to cast a buffer to a NCPublicKey struct
* @param key The buffer to cast
* @return A pointer to the NCPublicKey struct
*/
static _nc_fn_inline NCPublicKey* NCToPubKey(uint8_t key[NC_PUBKEY_SIZE])
{
	return (NCPublicKey*)key;
}

static _nc_fn_inline NCResult NCResultWithArgPosition(NCResult err, uint8_t argPosition)
{
	return -(((NCResult)argPosition << NC_ARG_POSITION_OFFSET) | -err);
}

/*
* Parses an error code and returns the error code and the argument position 
that caused the error.
* @param result The error code to parse
* @param argPositionOut A pointer to the argument position to write to
* @return The error code
*/
static _nc_fn_inline int NCParseErrorCode(NCResult result, uint8_t* argPositionOut)
{
	NCResult asPositive;
	int code;

	/* convert result to a positive value*/
	asPositive = -result;

	/* Get the error code from the lower 8 bits and the argument position from the upper 8 bits*/
	code = -(asPositive & NC_ERROR_CODE_MASK);
	*argPositionOut = (asPositive >> NC_ARG_POSITION_OFFSET) & 0xFF;

	return code;
}

/*--------------------------------------
*		LIB CONTEXT API
*/

/*
* Runtime check for the size of the context struct to allow 
for dynamic allocation when context size structure is not known. 
* @return The size of the context struct in bytes
*/
NC_EXPORT uint32_t NC_CC NCGetContextStructSize(void);
/*
* Initializes a context struct with the given entropy
* @param ctx A pointer to the context structure to initialize
* @param entropy The entropy to initialize the context with
* @return NC_SUCCESS if the operation was successful, otherwise an error code
*/
NC_EXPORT NCResult NC_CC NCInitContext(
	NCContext* ctx, 
	const uint8_t entropy[NC_CONTEXT_ENTROPY_SIZE]
);
/*
* Reinitializes a context struct with the given 
* @param ctx A pointer to the context structure to initialize
* @param entropy The entropy to initialize the context with
* @return NC_SUCCESS if the operation was successful, otherwise an error code
*/
NC_EXPORT NCResult NC_CC NCReInitContext(
	NCContext* ctx, 
	const uint8_t entropy[NC_CONTEXT_ENTROPY_SIZE]
);

/*
* Destroys a context struct
* @param ctx A pointer to the existing context structure to destroy
* @return NC_SUCCESS if the operation was successful, otherwise an error code
*/
NC_EXPORT NCResult NC_CC NCDestroyContext(NCContext* ctx);



/*--------------------------------------
*		HIGH LEVEL SIGNING API
*/

/*
* Gets a x-only compressed public key from the given secret key
* @param ctx A pointer to the existing library context
* @param sk A pointer to the secret key
* @param pk A pointer to the compressed public key buffer to write to
* @return NC_SUCCESS if the operation was successful, otherwise an error code
*/
NC_EXPORT NCResult NC_CC NCGetPublicKey(
	const NCContext* ctx, 
	const NCSecretKey* sk, 
	NCPublicKey* pk
);
/*
* Validates that a given secret key is valid according to the secp256k1 curve. This 
is functionally the same as calling secp256k1_ec_seckey_verify. 
* @param ctx A pointer to the existing library context
* @param sk A pointer to the secret key to verify 
* @return 1 if the secret key is valid, 0 if it is not, otherwise an error code
*/
NC_EXPORT NCResult NC_CC NCValidateSecretKey(
	const NCContext* ctx, 
	const NCSecretKey* sk
);


/*
* Signs a raw message after computing the sha256 checksum using the
given secret key and writes the signature to the sig64 buffer.
* @param ctx A pointer to the existing library context
* @param sk A pointer to the secret key to sign with
* @param random32 A pointer to the random32 buffer to use for signing
* @param data A pointer to the raw data buffer to sign
* @param dataSize The size of the raw data buffer
* @param sig64 A pointer to the 64-byte buffer to write the signature to
* @return NC_SUCCESS if the operation was successful, otherwise an error code
*/
NC_EXPORT NCResult NC_CC NCSignData(
	const NCContext* ctx,
	const NCSecretKey* sk,
	const uint8_t random32[32],
	const uint8_t* data,
	const uint32_t dataSize,
	uint8_t sig64[64]
);

/*
* Verifies a signature of a raw data buffer matches the output using the given public key.
* @param ctx A pointer to the existing library context
* @param sig64 The 64byte signature to verify
* @param data A pointer to the raw data buffer to verify
* @param dataSize The size of the raw data buffer
* @param pk A pointer to the the x-only compressed public key (x-only serialized public key)
* @return NC_SUCCESS if the signature could be verified, otherwise an error code
*/
NC_EXPORT NCResult NC_CC NCVerifyData(
	const NCContext* ctx,
	const NCPublicKey* pk,
	const uint8_t* data,
	const uint32_t dataSize,
	const uint8_t sig64[64]
);

/*--------------------------------------
*		EXTENDED SIGNING API
*/

/*
* Signs a message using the given secret key and writes the signature to the sig64 buffer
* @param ctx A pointer to the existing library context
* @param sk A pointer to the secret key to sign with
* @param random32 A pointer to the random32 buffer to use for signing
* @param digest32 A pointer to sha256 digest32 to sign
* @param sig64 A pointer to the 64-byte buffer to write the signature to
* @return NC_SUCCESS if the operation was successful, otherwise an error code
*/
NC_EXPORT NCResult NC_CC NCSignDigest(
	const NCContext* ctx,
	const NCSecretKey* sk,
	const uint8_t random32[32],
	const uint8_t digest32[32],
	uint8_t sig64[64]
);

/*
* Verifies a signature of a digest32 matches the output using the given public key.
Equivalent to calling secp256k1_schnorrsig_verify.
* @param ctx A pointer to the existing library context
* @param sig64 A pointer to the 64-byte signature to verify
* @param digest32 A pointer to a 32-byte message digest to verify
* @param pk A pointer to the the x-only compressed public key (x-only serialized public key)
* @return NC_SUCCESS if the signature could be verified, otherwise an error code
*/
NC_EXPORT NCResult NC_CC NCVerifyDigest(
	const NCContext* ctx,
	const NCPublicKey* pk,
	const uint8_t digest32[32],
	const uint8_t sig64[64]
);



/*--------------------------------------
*		HIGH LEVEL ENCRYPTION API
*/

/*
*			NOTES
* 
*	NIP-44 requires that plaintext/ciphertext must be padded in powers of 2.
*	Since this library operates on data at the binary level, and does not do 
*	ANY runtime heap allocation, it is up to the user to ensure that the 
*	plaintext/ciphertext buffers are padded properly in The NCryptoData struct
*   before calling the encryption/decryption functions.
*/

/*
* High level api for encrypting nostr messages using a secret key and a public key. Use
the NCEncryptEx functions for extended encryption functionality
* @param ctx The library context
* @param sk The secret key (the local private key)
* @param pk The compressed public key (x-only serialized public key) the other user's public key
* @param args The encryption arguments
* @return NC_SUCCESS if the operation was successful, otherwise an error code. Use NCParseErrorCode to
the error code and positional argument that caused the error
*/
NC_EXPORT NCResult NC_CC NCEncrypt(
	const NCContext* ctx, 
	const NCSecretKey* sk, 
	const NCPublicKey* pk,
	NCEncryptionArgs* args
);

/*
* High level api for decrypting nostr messages using a secret key and a public key. Use
the NCDecryptEx functions for extended decryption functionality.
* @param ctx The library context
* @param sk The secret key (the local private key)
* @param pk The compressed public key (x-only serialized public key) the other user's public key
* @param args The decryption arguments
* @return NC_SUCCESS if the operation was successful, otherwise an error code. Use NCParseErrorCode to
the error code and positional argument that caused the error
*/
NC_EXPORT NCResult NC_CC NCDecrypt(
	const NCContext* ctx, 
	const NCSecretKey* sk, 
	const NCPublicKey* pk, 
	NCEncryptionArgs* args
);

/*
* High level api for verifying a Nip44 message authentication code using a secret key 
and a public key. Use the NCVerifyMacEx functions for extended verification functionality.
* @param ctx A pointer to an existing library context
* @param sk A pointer to the secret key
* @param pk A pointer to the compressed public key (x-only serialized public key)
* @param args A pointer to the mac verification arguments
* @return NC_SUCCESS if the operation was successful, otherwise an error code. Use NCParseErrorCode to
* the error code and positional argument that caused the error
*/
NC_EXPORT NCResult NC_CC NCVerifyMac(
	const NCContext* ctx,
	const NCSecretKey* sk,
	const NCPublicKey* pk,
	NCMacVerifyArgs* args
);

/*--------------------------------------
*		EXTENDED ENCRYPTION API
*/

/*
* Computes a NIP-44 shared secret from a secret key and a public key and 
stores it in the sharedPoint buffer.
* @param ctx A pointer to the existing library context
* @param sk The secret key
* @param pk The compressed public key (x-only serialized public key)
* @param sharedPoint The buffer to store write the secret data to
* @return NC_SUCCESS if the operation was successful, otherwise an error code. Use NCParseErrorCode to
the error code and positional argument that caused the error
*/
NC_EXPORT NCResult NC_CC NCGetSharedSecret(
	const NCContext* ctx, 
	const NCSecretKey* sk, 
	const NCPublicKey* pk, 
	uint8_t sharedPoint[NC_SHARED_SEC_SIZE]
);

/*
* Computes a NIP-44 conversation key from the local secret key and the remote 
public key, and stores it in the conversationKey buffer.
* @param ctx A pointer to the existing library context
* @param sk A pointer to the the secret key
* @param pk A pointer to the compressed public key (x-only serialized public key)
* @param conversationKey The buffer to store write the conversation key to
* @return NC_SUCCESS if the operation was successful, otherwise an error code. Use NCParseErrorCode to
the error code and positional argument that caused the error
*/
NC_EXPORT NCResult NC_CC NCGetConversationKey(
	const NCContext* ctx, 
	const NCSecretKey* sk, 
	const NCPublicKey* pk, 
	uint8_t conversationKey[NC_CONV_KEY_SIZE]
);
/*
* Computes a NIP-44 conversation key a shared secret/point, and stores it in the 
conversationKey buffer.
* @param ctx A pointer to the existing library context
* @param sharedPoint A pointer to the shared secret/point
* @param conversationKey The buffer to store write the conversation key to
* @return NC_SUCCESS if the operation was successful, otherwise an error code. Use NCParseErrorCode to
the error code and positional argument that caused the error
*/
NC_EXPORT NCResult NC_CC NCGetConversationKeyEx(
	const NCContext* ctx, 
	const uint8_t sharedPoint[NC_SHARED_SEC_SIZE], 
	uint8_t conversationKey[NC_CONV_KEY_SIZE]
);

/*
* Encrypts a message using the given conversation key and writes the encrypted message to the
* output buffer. The output buffer must be at least 99 bytes in size.
* @param ctx A pointer to the existing library context
* @param conversationKey A pointer to the conversation key
* @param args A pointer to the encryption arguments structure
* @return NC_SUCCESS if the operation was successful, otherwise an error code. Use NCParseErrorCode to
the error code and positional argument that caused the error.
*/
NC_EXPORT NCResult NC_CC NCEncryptEx(
	const NCContext* ctx, 
	const uint8_t conversationKey[NC_CONV_KEY_SIZE],
	NCEncryptionArgs* args
);

/*
* Decrypts a message using the given conversation key and writes the decrypted message to the
* output buffer. 
* @param ctx A pointer to the existing library context
* @param conversationKey A pointer to the conversation key
* @param args A pointer to the decryption arguments structure
* @return NC_SUCCESS if the operation was successful, otherwise an error code. Use NCParseErrorCode to
the error code and positional argument that caused the error.
*/
NC_EXPORT NCResult NC_CC NCDecryptEx(
	const NCContext* ctx, 
	const uint8_t conversationKey[NC_CONV_KEY_SIZE], 
	NCEncryptionArgs* args
);

/*
* Verifies a Nip44 message authentication code using the given conversation key.
* @param ctx A pointer to the existing library context
* @param conversationKey A pointer to the conversation key
* @param args A pointer to the mac verification arguments
* @return NC_SUCCESS if the operation was successful, otherwise an error code. Use NCParseErrorCode to
* the error code and positional argument that caused the error.
*/
NC_EXPORT NCResult NC_CC NCVerifyMacEx(
	const NCContext* ctx,
	const uint8_t conversationKey[NC_CONV_KEY_SIZE],
	NCMacVerifyArgs* args
);

/*
* Computes a message authentication code for a given payload using the given hmacKey and writes the
* mac to the hmacOut buffer.
* @param ctx A pointer to the existing library context
* @param hmacKey A pointer to the hmac key
* @param payload A pointer to the payload data buffer
* @param payloadSize The size of the payload data buffer
* @param hmacOut A pointer to the buffer to write the mac to
* @return NC_SUCCESS if the operation was successful, otherwise an error code. Use NCParseErrorCode to
* the error code and positional argument that caused the error.
*/
NC_EXPORT NCResult NCComputeMac(
	const NCContext* ctx,
	const uint8_t hmacKey[NC_HMAC_KEY_SIZE],
	const uint8_t* payload,
	uint32_t payloadSize,
	uint8_t hmacOut[NC_ENCRYPTION_MAC_SIZE]
);

#endif /* !NOSCRYPT_H */
