
/*
* Copyright (c) 2024 Vaughn Nugent
*
* Package: noscrypt
* File: nc-crypto.h
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

#ifndef _NC_CRYPTO_H
#define _NC_CRYPTO_H

#include <stdint.h>

#define CHACHA_NONCE_SIZE		0x0cu		/* Size of 12 is set by the cipher spec */
#define CHACHA_KEY_SIZE			0x20u		/* Size of 32 is set by the cipher spec */
#define SHA256_DIGEST_SIZE		0x20u		/* Size of 32 is set by the cipher spec */

typedef uint8_t cstatus_t;
#define CSTATUS_OK				((cstatus_t)0x01u)
#define CSTATUS_FAIL			((cstatus_t)0x00u)

typedef uint8_t sha256_t[SHA256_DIGEST_SIZE];

uint32_t ncCryptoFixedTimeComp(const uint8_t* a, const uint8_t* b, uint32_t size);

void ncCryptoSecureZero(void* ptr, uint32_t size);

cstatus_t ncCryptoDigestSha256(const cspan_t* data, sha256_t digestOut32);

cstatus_t ncCryptoHmacSha256(const cspan_t* key, const cspan_t* data, sha256_t hmacOut32);

cstatus_t ncCryptoSha256HkdfExpand(const cspan_t* prk, const cspan_t* info, span_t* okm);

cstatus_t ncCryptoSha256HkdfExtract(const cspan_t* salt, const cspan_t* ikm, sha256_t prk);

cstatus_t ncCryptoChacha20(
	const uint8_t key[CHACHA_KEY_SIZE],
	const uint8_t nonce[CHACHA_NONCE_SIZE],
	const uint8_t* input,
	uint8_t* output,
	uint32_t dataSize
);

#endif /* !_NC_CRYPTO_H */
