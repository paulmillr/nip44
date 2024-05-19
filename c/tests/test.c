/*
* Copyright (c) 2024 Vaughn Nugent
*
* Package: noscrypt
* File: test.c
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

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include <noscrypt.h>
#ifdef _NC_IS_WINDOWS
	#define IS_WINDOWS
#endif

#ifdef IS_WINDOWS
    #define WIN32_LEAN_AND_MEAN
    #include <windows.h>
	#include <wincrypt.h>
#endif

#ifdef IS_WINDOWS
    /*Asserts that an internal test condition is true, otherwise aborts the test process*/
    #define TASSERT(x) if(!(x)) { printf("ERROR! Internal test assumption failed: %s. @ Line: %d\n Aborting tests...\n", #x, __LINE__); ExitProcess(1); }
#else
    /*Asserts that an internal test condition is true, otherwise aborts the test process*/
	#define TASSERT(x) if(!(x)) { printf("ERROR! Internal test assumption failed: %s. @ Line: %d\n Aborting tests...\n", #x, __LINE__); exit(1); }
#endif

/*Prints a string literal to the console*/
#define PRINTL(x) puts(x); puts("\n");
#define ENSURE(x) if(!(x)) { puts("Assumption failed!\n"); return 1; } 
#define TEST(x, expected) printf("\tTesting %s\n", #x); if(((long)x) != ((long)expected)) \
{ printf("FAILED: Expected %ld but got %ld @ callsite %s. Line: %d \n", ((long)expected), ((long)x), #x, __LINE__); return 1; }


#ifdef IS_WINDOWS
    #define ZERO_FILL(x, size) SecureZeroMemory(x, size)
#else
	#define ZERO_FILL(x, size) memset(x, 0, size)
#endif


#ifdef IS_WINDOWS
    #define memmove(dst, src, size) memmove_s(dst, size, src, size)
#else
    #include<string.h>
#endif

#define strlen32(x) (uint32_t)strlen(x)

#include "hex.h"

/*Pre-computed constants for argument errors */
#define ARG_ERROR_POS_0 E_NULL_PTR
#define ARG_ERROR_POS_1 NCResultWithArgPosition(E_NULL_PTR, 0x01)
#define ARG_ERROR_POS_2 NCResultWithArgPosition(E_NULL_PTR, 0x02)
#define ARG_ERROR_POS_3 NCResultWithArgPosition(E_NULL_PTR, 0x03)
#define ARG_ERROR_POS_4 NCResultWithArgPosition(E_NULL_PTR, 0x04)
#define ARG_ERROR_POS_5 NCResultWithArgPosition(E_NULL_PTR, 0x05)
#define ARG_ERROR_POS_6 NCResultWithArgPosition(E_NULL_PTR, 0x06)

#define ARG_RANGE_ERROR_POS_0 E_ARGUMENT_OUT_OF_RANGE
#define ARG_RANGE_ERROR_POS_1 NCResultWithArgPosition(E_ARGUMENT_OUT_OF_RANGE, 0x01)
#define ARG_RANGE_ERROR_POS_2 NCResultWithArgPosition(E_ARGUMENT_OUT_OF_RANGE, 0x02)
#define ARG_RANGE_ERROR_POS_3 NCResultWithArgPosition(E_ARGUMENT_OUT_OF_RANGE, 0x03)
#define ARG_RANGE_ERROR_POS_4 NCResultWithArgPosition(E_ARGUMENT_OUT_OF_RANGE, 0x04)
#define ARG_RANGE_ERROR_POS_5 NCResultWithArgPosition(E_ARGUMENT_OUT_OF_RANGE, 0x05)
#define ARG_RANGE_ERROR_POS_6 NCResultWithArgPosition(E_ARGUMENT_OUT_OF_RANGE, 0x06)

#define ARG_INVALID_ERROR_POS_0 E_INVALID_ARG
#define ARG_INVALID_ERROR_POS_1 NCResultWithArgPosition(E_INVALID_ARG, 0x01)
#define ARG_INVALID_ERROR_POS_2 NCResultWithArgPosition(E_INVALID_ARG, 0x02)
#define ARG_INVALID_ERROR_POS_3 NCResultWithArgPosition(E_INVALID_ARG, 0x03)
#define ARG_INVALID_ERROR_POS_4 NCResultWithArgPosition(E_INVALID_ARG, 0x04)
#define ARG_INVALID_ERROR_POS_5 NCResultWithArgPosition(E_INVALID_ARG, 0x05)
#define ARG_INVALID_ERROR_POS_6 NCResultWithArgPosition(E_INVALID_ARG, 0x06)

static int RunTests(void);
static void FillRandomData(void* pbBuffer, size_t length);
static int TestEcdsa(NCContext* context, NCSecretKey* secKey, NCPublicKey* pubKey);
static int InitKepair(NCContext* context, NCSecretKey* secKey, NCPublicKey* pubKey);
static int TestKnownKeys(NCContext* context);
static int TestCorrectEncryption(NCContext* context);

#ifndef NC_INPUT_VALIDATION_OFF
static int TestPublicApiArgumentValidation(void);
#endif

static const uint8_t zero32[32] = { 0 };

int main(void)
{
    int result;
    
    result = RunTests();

    (void)PrintHexBytes;    /*avoid unused. I use occasionally for debugging*/
    FreeHexBytes();

	return result;
}

static int RunTests(void)
{
    NCContext ctx;
    uint8_t ctxRandom[32];
    NCSecretKey secKey;
    NCPublicKey pubKey;

    PRINTL("Begining basic noscrypt tests")

    FillRandomData(ctxRandom, 32);

    /* 
     * Context struct size should aways match the size of the 
     * struct returned by NCGetContextStructSize 
     */

    TEST(NCGetContextStructSize(), sizeof(NCContext))
    TEST(NCInitContext(&ctx, ctxRandom), NC_SUCCESS)

    if (InitKepair(&ctx, &secKey, &pubKey) != 0)
    {
        return 1;
    }

    if (TestEcdsa(&ctx, &secKey, &pubKey) != 0)
    {
        return 1;
    }

    if (TestKnownKeys(&ctx) != 0)
    {
        return 1;
    }

#ifndef NC_INPUT_VALIDATION_OFF
    if (TestPublicApiArgumentValidation() != 0)
    {
        return 1;
    }
#endif

    if (TestCorrectEncryption(&ctx) != 0)
    {
        return 1;
    }

    TEST(NCDestroyContext(&ctx), NC_SUCCESS)

    PRINTL("\nSUCCESS All tests passed")

    return 0;
}

static const char* message = "Test message to sign";

static int InitKepair(NCContext* context, NCSecretKey* secKey, NCPublicKey* pubKey)
{
    PRINTL("TEST: Keypair")

    /* Get random private key */
    FillRandomData(secKey, sizeof(NCSecretKey));

    /* Ensure not empty */
    ENSURE(memcmp(zero32, secKey, 32) != 0);

    /* Ensure the key is valid, result should be 1 on success */
    TEST(NCValidateSecretKey(context, secKey), 1);

    /* Generate a public key from the secret key */
    TEST(NCGetPublicKey(context, secKey, pubKey), NC_SUCCESS);

    PRINTL("\nPASSED: Keypair tests completed")

    return 0;
}

static int TestEcdsa(NCContext* context, NCSecretKey* secKey, NCPublicKey* pubKey)
{ 
   
    uint8_t sigEntropy[32];
    uint8_t invalidSig[64];
    HexBytes* digestHex;

    PRINTL("TEST: Ecdsa")

    /*Init a new secret key with random data */
    FillRandomData(invalidSig, sizeof(invalidSig));
    FillRandomData(sigEntropy, sizeof(sigEntropy));

    /* This is the sha256 digest of the message charater buffer above */
    digestHex = FromHexString("58884db8f9b2d5583a54b44daeccf029af4dd2874aa5e3dc0e55febebab55d18", 32);

    /* Test signing just the message digest */
    {
		uint8_t sig[64];
        TEST(NCSignDigest(context, secKey, sigEntropy, digestHex->data, sig), NC_SUCCESS);
        TEST(NCVerifyDigest(context, pubKey, digestHex->data, sig), NC_SUCCESS);
    }
    
    /* Sign and verify the raw message */
    {
        uint8_t sig[64];
        TEST(NCSignData(context, secKey, sigEntropy, (uint8_t*)message, strlen32(message), sig), NC_SUCCESS);
        TEST(NCVerifyData(context, pubKey, (uint8_t*)message, strlen32(message), sig), NC_SUCCESS);
    }

    /* Tests that signing the message and it's digest result in the same signature */
	{
		uint8_t sig1[64];
		uint8_t sig2[64];

        /* Ensure operations succeed but dont print them as test cases */
        ENSURE(NCSignData(context, secKey, sigEntropy, (uint8_t*)message, strlen32(message), sig1) == NC_SUCCESS);
        ENSURE(NCSignDigest(context, secKey, sigEntropy, digestHex->data, sig2) == NC_SUCCESS);
		
        /* Perform test */
        TEST(memcmp(sig1, sig2, 64), 0);
	}

    /* Checks that the signature raw message can be verified against the digest of the message */
    {
        uint8_t sig[64];
		
        ENSURE(NCSignData(context, secKey, sigEntropy, (uint8_t*)message, strlen32(message), sig) == NC_SUCCESS);
        TEST(NCVerifyDigest(context, pubKey, digestHex->data, sig), NC_SUCCESS);

        /* Now invert test, zero signature to ensure its overwritten */
        ZERO_FILL(sig, sizeof(sig));

        ENSURE(NCSignDigest(context, secKey, sigEntropy, digestHex->data, sig) == NC_SUCCESS);
        TEST(NCVerifyData(context, pubKey, (uint8_t*)message, strlen32(message), sig), NC_SUCCESS);
	}

    /* test verification of invalid signature */
    {
        TEST(NCVerifyDigest(context, pubKey, digestHex->data, invalidSig), E_INVALID_ARG);
    }

    PRINTL("\nPASSED: Ecdsa tests completed")
	return 0;
}

#ifndef NC_INPUT_VALIDATION_OFF

static int TestPublicApiArgumentValidation(void)
{
    NCContext ctx;
    uint8_t ctxRandom[32];
    uint8_t sig64[64];
    NCSecretKey secKey;
    NCPublicKey pubKey;
    uint8_t hmacKeyOut[NC_HMAC_KEY_SIZE];
    uint8_t nonce[NC_ENCRYPTION_NONCE_SIZE];

    NCEncryptionArgs cryptoData;
    cryptoData.dataSize = sizeof(zero32);
    cryptoData.inputData = zero32;
    cryptoData.outputData = sig64; /*just an arbitrary writeable buffer*/
    cryptoData.nonce32 = nonce;
    cryptoData.hmacKeyOut32 = hmacKeyOut;
    cryptoData.version = NC_ENC_VERSION_NIP44;

    PRINTL("TEST: Public API argument validation tests")

    FillRandomData(ctxRandom, 32);
    FillRandomData(nonce, sizeof(nonce));

    /*Test null context*/
    TEST(NCInitContext(NULL, ctxRandom),    ARG_ERROR_POS_0)
    TEST(NCInitContext(&ctx, NULL),         ARG_ERROR_POS_1)

    /* actually init a context to perform tests */
    TASSERT(NCInitContext(&ctx, ctxRandom) == NC_SUCCESS);

    /*
    * Test null context
    * NOTE: This is never freed, this shouldnt be an issue 
    * for testing, but this will leak memory. (libsecp256k2 
    * allocates internally)
    */
    TEST(NCDestroyContext(NULL), ARG_ERROR_POS_0)

    /*reinit*/
    TEST(NCReInitContext(NULL, ctxRandom),  ARG_ERROR_POS_0)
    TEST(NCReInitContext(&ctx, NULL),       ARG_ERROR_POS_1)

    /*Test null secret key*/
    TEST(NCGetPublicKey(&ctx, NULL, &pubKey),   ARG_ERROR_POS_1)
    TEST(NCGetPublicKey(&ctx, &secKey, NULL),   ARG_ERROR_POS_2)

    /*Test null secret key*/
    TEST(NCValidateSecretKey(NULL, &secKey),    ARG_ERROR_POS_0)
    TEST(NCValidateSecretKey(&ctx, NULL),       ARG_ERROR_POS_1)

    /*Verify sig64 args test*/
    TEST(NCVerifyDigest(NULL, &pubKey, zero32, sig64),      ARG_ERROR_POS_0)
    TEST(NCVerifyDigest(&ctx, NULL, zero32, sig64),         ARG_ERROR_POS_1)
    TEST(NCVerifyDigest(&ctx, &pubKey, NULL, sig64),        ARG_ERROR_POS_2)
    TEST(NCVerifyDigest(&ctx, &pubKey, zero32, NULL),       ARG_ERROR_POS_3)

    /*Test verify data args*/
    TEST(NCVerifyData(NULL, &pubKey, zero32, 32, sig64),    ARG_ERROR_POS_0)
    TEST(NCVerifyData(&ctx, NULL, zero32, 32, sig64),       ARG_ERROR_POS_1)
    TEST(NCVerifyData(&ctx, &pubKey, NULL, 32, sig64),      ARG_ERROR_POS_2)
    TEST(NCVerifyData(&ctx, &pubKey, zero32, 0, sig64),     ARG_RANGE_ERROR_POS_3)
    TEST(NCVerifyData(&ctx, &pubKey, zero32, 32, NULL),     ARG_ERROR_POS_4)

    /*Test null sign data args*/
    TEST(NCSignData(NULL, &secKey, zero32, zero32, 32, sig64),  ARG_ERROR_POS_0)
    TEST(NCSignData(&ctx, NULL, zero32, zero32, 32, sig64),     ARG_ERROR_POS_1)
    TEST(NCSignData(&ctx, &secKey, NULL, zero32, 32, sig64),    ARG_ERROR_POS_2)
    TEST(NCSignData(&ctx, &secKey, zero32, NULL, 32, sig64),    ARG_ERROR_POS_3)
    TEST(NCSignData(&ctx, &secKey, zero32, zero32, 0, sig64),   ARG_RANGE_ERROR_POS_4)
    TEST(NCSignData(&ctx, &secKey, zero32, zero32, 32, NULL),   ARG_ERROR_POS_5)
   
    /*Test null sign digest args*/
    TEST(NCSignDigest(NULL, &secKey, zero32, zero32, sig64),    ARG_ERROR_POS_0)
    TEST(NCSignDigest(&ctx, NULL, zero32, zero32, sig64),       ARG_ERROR_POS_1)
    TEST(NCSignDigest(&ctx, &secKey, NULL, zero32, sig64),      ARG_ERROR_POS_2)
	TEST(NCSignDigest(&ctx, &secKey, zero32, NULL, sig64),      ARG_ERROR_POS_3)
    TEST(NCSignDigest(&ctx, &secKey, zero32, zero32, NULL),     ARG_ERROR_POS_4)

    /*Test null encrypt args*/
    TEST(NCEncrypt(NULL, &secKey, &pubKey, &cryptoData),    ARG_ERROR_POS_0)
    TEST(NCEncrypt(&ctx, NULL, &pubKey, &cryptoData),       ARG_ERROR_POS_1)
	TEST(NCEncrypt(&ctx, &secKey, NULL, &cryptoData),       ARG_ERROR_POS_2)
    TEST(NCEncrypt(&ctx, &secKey, &pubKey, NULL),           ARG_ERROR_POS_3)

    /*Test invalid data size*/
    cryptoData.dataSize = 0;
    TEST(NCEncrypt(&ctx, &secKey, &pubKey, &cryptoData), ARG_RANGE_ERROR_POS_3)
    
    /*Test null input data */
    cryptoData.dataSize = 32;
    cryptoData.inputData = NULL;
	TEST(NCEncrypt(&ctx, &secKey, &pubKey, &cryptoData), ARG_INVALID_ERROR_POS_3)

    /*Test null output data */
	cryptoData.inputData = zero32;
    cryptoData.outputData = NULL;
	TEST(NCEncrypt(&ctx, &secKey, &pubKey, &cryptoData), ARG_INVALID_ERROR_POS_3)

    /* Decrypt */
    cryptoData.dataSize = 32;
    cryptoData.inputData = zero32;
    cryptoData.outputData = sig64;

    TEST(NCDecrypt(NULL, &secKey, &pubKey, &cryptoData),    ARG_ERROR_POS_0)
    TEST(NCDecrypt(&ctx, NULL, &pubKey, &cryptoData),       ARG_ERROR_POS_1)
	TEST(NCDecrypt(&ctx, &secKey, NULL, &cryptoData),       ARG_ERROR_POS_2)
    TEST(NCDecrypt(&ctx, &secKey, &pubKey, NULL),           ARG_ERROR_POS_3)

    /* Test invalid data size */
	cryptoData.dataSize = 0;
    TEST(NCDecrypt(&ctx, &secKey, &pubKey, &cryptoData), ARG_RANGE_ERROR_POS_3)

    /* Test null input data */
	cryptoData.dataSize = 32;
    cryptoData.inputData = NULL;
	TEST(NCDecrypt(&ctx, &secKey, &pubKey, &cryptoData), ARG_INVALID_ERROR_POS_3)

    /*Test null output data */
    cryptoData.inputData = zero32;
    cryptoData.outputData = NULL;
    TEST(NCDecrypt(&ctx, &secKey, &pubKey, &cryptoData), ARG_INVALID_ERROR_POS_3)
    
    {
        uint8_t hmacDataOut[NC_ENCRYPTION_MAC_SIZE];
        TEST(NCComputeMac(NULL, hmacKeyOut, zero32, 32, hmacDataOut),   ARG_ERROR_POS_0)
        TEST(NCComputeMac(&ctx, NULL, zero32, 32, hmacDataOut),         ARG_ERROR_POS_1)
        TEST(NCComputeMac(&ctx, hmacKeyOut, NULL, 32, hmacDataOut),     ARG_ERROR_POS_2)
        TEST(NCComputeMac(&ctx, hmacKeyOut, zero32, 0, hmacDataOut),    ARG_RANGE_ERROR_POS_3)
        TEST(NCComputeMac(&ctx, hmacKeyOut, zero32, 32, NULL),          ARG_ERROR_POS_4)
    }

    {
        NCMacVerifyArgs macArgs;
        macArgs.payload = zero32;
        macArgs.payloadSize = 32;
        macArgs.mac32 = zero32;
        macArgs.nonce32 = zero32;

        TEST(NCVerifyMac(NULL, &secKey, &pubKey, &macArgs),     ARG_ERROR_POS_0)
        TEST(NCVerifyMac(&ctx, NULL, &pubKey, &macArgs),        ARG_ERROR_POS_1)
        TEST(NCVerifyMac(&ctx, &secKey, NULL, &macArgs),        ARG_ERROR_POS_2)
        TEST(NCVerifyMac(&ctx, &secKey, &pubKey, NULL),         ARG_ERROR_POS_3)

        macArgs.payload = NULL;
        TEST(NCVerifyMac(&ctx, &secKey, &pubKey, &macArgs), ARG_INVALID_ERROR_POS_3)

        macArgs.payload = zero32;
        macArgs.payloadSize = 0;
        TEST(NCVerifyMac(&ctx, &secKey, &pubKey, &macArgs), ARG_RANGE_ERROR_POS_3)
    }
    
    PRINTL("\nPASSED: Public API argument validation tests completed")

    return 0;
}

#endif 

static int TestKnownKeys(NCContext* context)
{   
    NCPublicKey pubKey;
    HexBytes* secKey1, * pubKey1, * secKey2, * pubKey2;

    PRINTL("TEST: Known keys")
    
    secKey1 = FromHexString("98c642360e7163a66cee5d9a842b252345b6f3f3e21bd3b7635d5e6c20c7ea36", sizeof(NCSecretKey));
    pubKey1 = FromHexString("0db15182c4ad3418b4fbab75304be7ade9cfa430a21c1c5320c9298f54ea5406", sizeof(NCPublicKey));

    secKey2 = FromHexString("3032cb8da355f9e72c9a94bbabae80ca99d3a38de1aed094b432a9fe3432e1f2", sizeof(NCSecretKey));
    pubKey2 = FromHexString("421181660af5d39eb95e48a0a66c41ae393ba94ffeca94703ef81afbed724e5a", sizeof(NCPublicKey));
   
    /*Test known keys*/
    TEST(NCValidateSecretKey(context, NCToSecKey(secKey1->data)), 1);

    /* Recover a public key from secret key 1 */
    TEST(NCGetPublicKey(context, NCToSecKey(secKey1->data), &pubKey), NC_SUCCESS);

    /* Ensure the public key matches the known public key value */
    TEST(memcmp(pubKey1->data, &pubKey, sizeof(pubKey)), 0);

    /* Repeat with second key */
    TEST(NCValidateSecretKey(context, (NCSecretKey*)secKey2->data), 1);
    TEST(NCGetPublicKey(context, (NCSecretKey*)secKey2->data, &pubKey), NC_SUCCESS);
    TEST(memcmp(pubKey2->data, &pubKey, sizeof(pubKey)), 0);    

    PRINTL("\nPASSED: Known keys tests completed")
    return 0;
}

#define TEST_ENC_DATA_SIZE 128

static int TestCorrectEncryption(NCContext* context)
{
    NCSecretKey secKey1;
    NCPublicKey pubKey1;
    
    NCSecretKey secKey2;
    NCPublicKey pubKey2;
  
    uint8_t hmacKeyOut[NC_HMAC_KEY_SIZE];
    uint8_t nonce[NC_ENCRYPTION_NONCE_SIZE];
    uint8_t mac[NC_ENCRYPTION_MAC_SIZE];

    uint8_t plainText[TEST_ENC_DATA_SIZE];
    uint8_t cipherText[TEST_ENC_DATA_SIZE];
    uint8_t decryptedText[TEST_ENC_DATA_SIZE];
  
    NCEncryptionArgs cryptoData;
    NCMacVerifyArgs macVerifyArgs;

    /* setup the crypto data structure */
    cryptoData.dataSize = TEST_ENC_DATA_SIZE;
    cryptoData.inputData = plainText;
    cryptoData.outputData = cipherText;
    cryptoData.nonce32 = nonce;
    cryptoData.hmacKeyOut32 = hmacKeyOut;
    cryptoData.version = NC_ENC_VERSION_NIP44;
   
    macVerifyArgs.nonce32 = nonce;    /* nonce is shared */
    macVerifyArgs.mac32 = mac;
    macVerifyArgs.payload = cipherText;
    macVerifyArgs.payloadSize = TEST_ENC_DATA_SIZE;

    PRINTL("TEST: Correct encryption")

    /* init a sending and receiving key */
    FillRandomData(&secKey1, sizeof(NCSecretKey));
    FillRandomData(&secKey2, sizeof(NCSecretKey));
    FillRandomData(plainText, sizeof(plainText));
    /* nonce is shared */
    FillRandomData(nonce, sizeof(nonce));

    ENSURE(NCValidateSecretKey(context, &secKey1) == 1);
    ENSURE(NCValidateSecretKey(context, &secKey2) == 1);

    ENSURE(NCGetPublicKey(context, &secKey1, &pubKey1) == NC_SUCCESS);
    ENSURE(NCGetPublicKey(context, &secKey2, &pubKey2) == NC_SUCCESS);

    /* Try to encrypt the data from sec1 to pub2 */
    TEST(NCEncrypt(context, &secKey1, &pubKey2, &cryptoData), NC_SUCCESS);

    /*swap cipher and plain text for decryption */
    cryptoData.inputData = cipherText;
    cryptoData.outputData = decryptedText;

    /* Try to decrypt the data from sec1 to pub2 */
    TEST(NCDecrypt(context, &secKey2, &pubKey1, &cryptoData), NC_SUCCESS);

    /* Ensure the decrypted text matches the original */
    TEST(memcmp(plainText, decryptedText, sizeof(plainText)), 0);

    /* Compute message mac on ciphertext */
    TEST(NCComputeMac(context, hmacKeyOut, cipherText, sizeof(cipherText), mac), NC_SUCCESS);

    /* Verify the mac */
    TEST(NCVerifyMac(context, &secKey1, &pubKey2, &macVerifyArgs), NC_SUCCESS);    

    PRINTL("\nPASSED: Correct encryption tests completed")
    return 0;
}

static void FillRandomData(void* pbBuffer, size_t length)
{

#ifdef IS_WINDOWS

    HCRYPTPROV hCryptProv;

    TASSERT(CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL, 0));
    TASSERT(CryptGenRandom(hCryptProv, (DWORD)length, pbBuffer))
    TASSERT(CryptReleaseContext(hCryptProv, 0));
#else
    FILE* f = fopen("/dev/urandom", "rb");
	TASSERT(f != NULL);
	TASSERT(fread(pbBuffer, 1, length, f) == length);
	fclose(f);
#endif
}
