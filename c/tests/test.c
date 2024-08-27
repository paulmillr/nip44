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
#define ENSURE(x) if(!(x)) { printf("Test assumption failed on line %d\n", __LINE__); return 1; } 
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
#define ARG_ERROR(pos) NCResultWithArgPosition(E_NULL_PTR, pos) 
#define ARG_ERROR_POS_1 ARG_ERROR(0x01)
#define ARG_ERROR_POS_2 ARG_ERROR(0x02)
#define ARG_ERROR_POS_3 ARG_ERROR(0x03)
#define ARG_ERROR_POS_4 ARG_ERROR(0x04)
#define ARG_ERROR_POS_5 ARG_ERROR(0x05)
#define ARG_ERROR_POS_6 ARG_ERROR(0x06)

#define ARG_RANGE_ERROR_POS_0 E_ARGUMENT_OUT_OF_RANGE
#define ARG_RANGE_ERROR(pos) NCResultWithArgPosition(E_ARGUMENT_OUT_OF_RANGE, pos)
#define ARG_RANGE_ERROR_POS_1 ARG_RANGE_ERROR(0x01)
#define ARG_RANGE_ERROR_POS_2 ARG_RANGE_ERROR(0x02)
#define ARG_RANGE_ERROR_POS_3 ARG_RANGE_ERROR(0x03)
#define ARG_RANGE_ERROR_POS_4 ARG_RANGE_ERROR(0x04)
#define ARG_RANGE_ERROR_POS_5 ARG_RANGE_ERROR(0x05)
#define ARG_RANGE_ERROR_POS_6 ARG_RANGE_ERROR(0x06)

#define ARG_INVALID_ERROR_POS_0 E_INVALID_ARG
#define ARG_INVALID_ERROR(pos) NCResultWithArgPosition(E_INVALID_ARG, pos)
#define ARG_INVALID_ERROR_POS_1 ARG_INVALID_ERROR(0x01)
#define ARG_INVALID_ERROR_POS_2 ARG_INVALID_ERROR(0x02)
#define ARG_INVALID_ERROR_POS_3 ARG_INVALID_ERROR(0x03)
#define ARG_INVALID_ERROR_POS_4 ARG_INVALID_ERROR(0x04)
#define ARG_INVALID_ERROR_POS_5 ARG_INVALID_ERROR(0x05)
#define ARG_INVALID_ERROR_POS_6 ARG_INVALID_ERROR(0x06)

static int RunTests(void);
static void FillRandomData(void* pbBuffer, size_t length);
static int TestEcdsa(const NCContext* context, NCSecretKey* secKey, NCPublicKey* pubKey);
static int InitKepair(const NCContext* context, NCSecretKey* secKey, NCPublicKey* pubKey);
static int TestKnownKeys(const NCContext* context);
static int TestCorrectEncryption(const NCContext* context);

#ifdef NC_ENABLE_UTILS
static int TestUtilFunctions(const NCContext * libCtx);
#endif

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
    NCContext* ctx;
    uint8_t ctxRandom[32];
    NCSecretKey secKey;
    NCPublicKey pubKey;

    PRINTL("Begining basic noscrypt tests")

    FillRandomData(ctxRandom, 32);

    /*
    * Can use the shared/global context for tests that won't modify
    * the structure
    */
    ctx = NCGetSharedContext();
    
    TEST(NCInitContext(ctx, ctxRandom), NC_SUCCESS)

    if (InitKepair(ctx, &secKey, &pubKey) != 0)
    {
        return 1;
    }

    if (TestEcdsa(ctx, &secKey, &pubKey) != 0)
    {
        return 1;
    }

    if (TestKnownKeys(ctx) != 0)
    {
        return 1;
    }

#ifndef NC_INPUT_VALIDATION_OFF

    if (TestPublicApiArgumentValidation() != 0)
    {
        return 1;
    }

#endif

    if (TestCorrectEncryption(ctx) != 0)
    {
        return 1;
    }

#ifdef NC_ENABLE_UTILS
	if (TestUtilFunctions(ctx) != 0)
	{
		return 1;
	}
#endif

    TEST(NCDestroyContext(ctx), NC_SUCCESS)

    PRINTL("\nSUCCESS All tests passed")

    return 0;
}

static const char* message = "Test message to sign";

static int InitKepair(const NCContext* context, NCSecretKey* secKey, NCPublicKey* pubKey)
{
    PRINTL("TEST: Keypair")

    /* Get random private key */
    FillRandomData(secKey, sizeof(NCSecretKey));

    /* Ensure not empty */
    ENSURE(memcmp(zero32, secKey, 32) != 0);

    /* Ensure the key is valid, result should be 1 on success */
    TEST(NCValidateSecretKey(context, secKey), NC_SUCCESS);

    /* Generate a public key from the secret key */
    TEST(NCGetPublicKey(context, secKey, pubKey), NC_SUCCESS);

    PRINTL("\nPASSED: Keypair tests completed")

    return 0;
}

static int TestEcdsa(const NCContext* context, NCSecretKey* secKey, NCPublicKey* pubKey)
{ 
   
    uint8_t sigEntropy[32];
    uint8_t invalidSig[64];
    span_t digestHex;

    PRINTL("TEST: Ecdsa")

    /*Init a new secret key with random data */
    FillRandomData(invalidSig, sizeof(invalidSig));
    FillRandomData(sigEntropy, sizeof(sigEntropy));

    /* This is the sha256 digest of the message charater buffer above */
    digestHex = FromHexString("58884db8f9b2d5583a54b44daeccf029af4dd2874aa5e3dc0e55febebab55d18", 32);

    /* Test signing just the message digest */
    {
		uint8_t sig[64];
        TEST(NCSignDigest(context, secKey, sigEntropy, digestHex.data, sig), NC_SUCCESS);
        TEST(NCVerifyDigest(context, pubKey, digestHex.data, sig), NC_SUCCESS);
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
        ENSURE(NCSignDigest(context, secKey, sigEntropy, digestHex.data, sig2) == NC_SUCCESS);
		
        /* Perform test */
        TEST(memcmp(sig1, sig2, 64), 0);
	}

    /* Checks that the signature raw message can be verified against the digest of the message */
    {
        uint8_t sig[64];
		
        ENSURE(NCSignData(context, secKey, sigEntropy, (uint8_t*)message, strlen32(message), sig) == NC_SUCCESS);
        TEST(NCVerifyDigest(context, pubKey, digestHex.data, sig), NC_SUCCESS);

        /* Now invert test, zero signature to ensure its overwritten */
        ZERO_FILL(sig, sizeof(sig));

        ENSURE(NCSignDigest(context, secKey, sigEntropy, digestHex.data, sig) == NC_SUCCESS);
        TEST(NCVerifyData(context, pubKey, (uint8_t*)message, strlen32(message), sig), NC_SUCCESS);
	}

    /* test verification of invalid signature */
    {
        TEST(NCVerifyDigest(context, pubKey, digestHex.data, invalidSig), E_INVALID_ARG);
    }

    PRINTL("\nPASSED: Ecdsa tests completed")
	return 0;
}

#ifndef NC_INPUT_VALIDATION_OFF

static int TestPublicApiArgumentValidation()
{
    NCContext* ctx;
    uint8_t ctxRandom[32];
    uint8_t sig64[64];
    NCSecretKey secKey;
    NCPublicKey pubKey;
    uint8_t hmacKeyOut[NC_HMAC_KEY_SIZE];
    uint8_t nonce[NC_NIP44_IV_SIZE];

    NCEncryptionArgs cryptoData;

    PRINTL("TEST: Public API argument validation tests")

    {
        TEST(NCEncryptionGetIvSize(NC_ENC_VERSION_NIP44), sizeof(nonce));

        /*
        * Test arguments for encryption properties
        */

		uint8_t testBuff32[32];

		TEST(NCEncryptionSetProperty(NULL, NC_ENC_SET_VERSION, NC_ENC_VERSION_NIP04), ARG_ERROR_POS_0)
		TEST(NCEncryptionSetProperty(&cryptoData, 0, 1), E_INVALID_ARG)

        TEST(NCEncryptionSetData(NULL, zero32, sig64, sizeof(zero32)), ARG_ERROR_POS_0)
		TEST(NCEncryptionSetData(&cryptoData, NULL, sig64, sizeof(zero32)), ARG_ERROR_POS_1)
		TEST(NCEncryptionSetData(&cryptoData, zero32, NULL, sizeof(zero32)), ARG_ERROR_POS_2)
		TEST(NCEncryptionSetData(&cryptoData, zero32, sig64, 0), ARG_RANGE_ERROR_POS_3)

        /* Setting the IV should fail because a version is not set*/
        TEST(NCEncryptionSetPropertyEx(&cryptoData, NC_ENC_SET_IV, nonce, sizeof(nonce)), E_VERSION_NOT_SUPPORTED);

        /* Set to nip44 to continue nip44 tests */
        TEST(NCEncryptionSetProperty(&cryptoData, NC_ENC_SET_VERSION, NC_ENC_VERSION_NIP44), NC_SUCCESS)

		TEST(NCEncryptionSetPropertyEx(&cryptoData, 0, nonce, sizeof(nonce)), E_INVALID_ARG)
		TEST(NCEncryptionSetPropertyEx(&cryptoData, NC_ENC_SET_IV, NULL, sizeof(nonce)), ARG_ERROR_POS_2)
		TEST(NCEncryptionSetPropertyEx(&cryptoData, NC_ENC_SET_IV, nonce, 0), ARG_RANGE_ERROR_POS_3)
		/* Nonce size should fail if not exactly the required nonce size */
		TEST(NCEncryptionSetPropertyEx(&cryptoData, NC_ENC_SET_IV, nonce, NC_NIP44_IV_SIZE - 1), ARG_RANGE_ERROR_POS_3)
        TEST(NCEncryptionSetPropertyEx(&cryptoData, NC_ENC_SET_IV, nonce, NC_NIP44_IV_SIZE + 1), ARG_RANGE_ERROR_POS_3)

		TEST(NCEncryptionSetPropertyEx(&cryptoData, 0, hmacKeyOut, sizeof(hmacKeyOut)), E_INVALID_ARG)
		TEST(NCEncryptionSetPropertyEx(&cryptoData, NC_ENC_SET_NIP44_MAC_KEY, NULL, sizeof(hmacKeyOut)), ARG_ERROR_POS_2)
		TEST(NCEncryptionSetPropertyEx(&cryptoData, NC_ENC_SET_NIP44_MAC_KEY, hmacKeyOut, 0), ARG_RANGE_ERROR_POS_3)
        /* Key size should fail if smaller than the required nip44 key size */
        TEST(NCEncryptionSetPropertyEx(&cryptoData, NC_ENC_SET_NIP44_MAC_KEY, hmacKeyOut, NC_HMAC_KEY_SIZE - 1), ARG_RANGE_ERROR_POS_3) 

		
        /* Test for nip04 */
        
        /* Any nip04 specific properties should fail since nip44 has already been set */
		
		TEST(NCEncryptionSetPropertyEx(&cryptoData, NC_ENC_SET_NIP04_KEY, testBuff32, sizeof(testBuff32)), E_VERSION_NOT_SUPPORTED)

		/* Set to nip04 to continue nip04 tests */
		ENSURE(NCEncryptionSetProperty(&cryptoData, NC_ENC_SET_VERSION, NC_ENC_VERSION_NIP04) == NC_SUCCESS)

		TEST(NCEncryptionSetPropertyEx(&cryptoData, NC_ENC_SET_IV, NULL, sizeof(testBuff32)), ARG_ERROR_POS_2)
		TEST(NCEncryptionSetPropertyEx(&cryptoData, NC_ENC_SET_IV, testBuff32, 0), ARG_RANGE_ERROR_POS_3)
        /* IV size should fail if not exact size IV for the version */
        TEST(NCEncryptionSetPropertyEx(&cryptoData, NC_ENC_SET_IV, testBuff32, NC_NIP04_IV_SIZE - 1), ARG_RANGE_ERROR_POS_3)
        TEST(NCEncryptionSetPropertyEx(&cryptoData, NC_ENC_SET_IV, testBuff32, NC_NIP04_IV_SIZE + 1), ARG_RANGE_ERROR_POS_3)


		TEST(NCEncryptionSetPropertyEx(&cryptoData, NC_ENC_SET_NIP04_KEY, NULL, sizeof(testBuff32)), ARG_ERROR_POS_2)
		TEST(NCEncryptionSetPropertyEx(&cryptoData, NC_ENC_SET_NIP04_KEY, testBuff32, 0), ARG_RANGE_ERROR_POS_3)
		/* Key size should fail if smaller than the required nip04 key size */
		TEST(NCEncryptionSetPropertyEx(&cryptoData, NC_ENC_SET_NIP04_KEY, testBuff32, NC_NIP04_AES_KEY_SIZE - 1), ARG_RANGE_ERROR_POS_3)
    }

    /* Prep the crypto structure for proper usage */
	ENSURE(NCEncryptionSetProperty(&cryptoData, NC_ENC_SET_VERSION, NC_ENC_VERSION_NIP44) == NC_SUCCESS);
    ENSURE(NCEncryptionSetPropertyEx(&cryptoData, NC_ENC_SET_IV, nonce, sizeof(nonce)) == NC_SUCCESS);
    ENSURE(NCEncryptionSetPropertyEx(&cryptoData, NC_ENC_SET_NIP44_MAC_KEY, hmacKeyOut, sizeof(hmacKeyOut)) == NC_SUCCESS);
	
    /* Assign the encryption material */
    ENSURE(NCEncryptionSetData(&cryptoData, zero32, sig64, sizeof(zero32)) == NC_SUCCESS);


    FillRandomData(ctxRandom, 32);
    FillRandomData(nonce, sizeof(nonce));

    /*
    * Alloc context structure on the heap before use. 
    * THIS WILL LEAK IN THE CURRENT CONFIG ALWAYS FREE UNDER NORMAL CONDITIONS 
    */
    ctx = (NCContext*)malloc(NCGetContextStructSize());
    TASSERT(ctx != NULL)

    /*Test null context*/
    TEST(NCInitContext(NULL, ctxRandom),    ARG_ERROR_POS_0)
    TEST(NCInitContext(ctx, NULL),         ARG_ERROR_POS_1)

    /* actually init a context to perform tests */
    TASSERT(NCInitContext(ctx, ctxRandom) == NC_SUCCESS);

    /*
    * Test null context
    * NOTE: This is never freed, this shouldnt be an issue 
    * for testing, but this will leak memory. (libsecp256k2 
    * allocates internally)
    */
    TEST(NCDestroyContext(NULL), ARG_ERROR_POS_0)

    /*reinit*/
    TEST(NCReInitContext(NULL, ctxRandom),      ARG_ERROR_POS_0)
    TEST(NCReInitContext(ctx, NULL),            ARG_ERROR_POS_1)

    /*Test null secret key*/
    TEST(NCGetPublicKey(ctx, NULL, &pubKey),    ARG_ERROR_POS_1)
    TEST(NCGetPublicKey(ctx, &secKey, NULL),    ARG_ERROR_POS_2)

    /*Test null secret key*/
    TEST(NCValidateSecretKey(NULL, &secKey),    ARG_ERROR_POS_0)
    TEST(NCValidateSecretKey(ctx, NULL),        ARG_ERROR_POS_1)
    /* Should fail with a zero key */
	TEST(NCValidateSecretKey(ctx, NCByteCastToSecretKey(zero32)), E_OPERATION_FAILED)

    /*Verify sig64 args test*/
    TEST(NCVerifyDigest(NULL, &pubKey, zero32, sig64),     ARG_ERROR_POS_0)
    TEST(NCVerifyDigest(ctx, NULL, zero32, sig64),         ARG_ERROR_POS_1)
    TEST(NCVerifyDigest(ctx, &pubKey, NULL, sig64),        ARG_ERROR_POS_2)
    TEST(NCVerifyDigest(ctx, &pubKey, zero32, NULL),       ARG_ERROR_POS_3)

    /*Test verify data args*/
    TEST(NCVerifyData(NULL, &pubKey, zero32, 32, sig64),   ARG_ERROR_POS_0)
    TEST(NCVerifyData(ctx, NULL, zero32, 32, sig64),       ARG_ERROR_POS_1)
    TEST(NCVerifyData(ctx, &pubKey, NULL, 32, sig64),      ARG_ERROR_POS_2)
    TEST(NCVerifyData(ctx, &pubKey, zero32, 0, sig64),     ARG_RANGE_ERROR_POS_3)
    TEST(NCVerifyData(ctx, &pubKey, zero32, 32, NULL),     ARG_ERROR_POS_4)

    /*Test null sign data args*/
    TEST(NCSignData(NULL, &secKey, zero32, zero32, 32, sig64),  ARG_ERROR_POS_0)
    TEST(NCSignData(ctx, NULL, zero32, zero32, 32, sig64),      ARG_ERROR_POS_1)
    TEST(NCSignData(ctx, &secKey, NULL, zero32, 32, sig64),     ARG_ERROR_POS_2)
    TEST(NCSignData(ctx, &secKey, zero32, NULL, 32, sig64),     ARG_ERROR_POS_3)
    TEST(NCSignData(ctx, &secKey, zero32, zero32, 0, sig64),    ARG_RANGE_ERROR_POS_4)
    TEST(NCSignData(ctx, &secKey, zero32, zero32, 32, NULL),    ARG_ERROR_POS_5)
   
    /*Test null sign digest args*/
    TEST(NCSignDigest(NULL, &secKey, zero32, zero32, sig64),    ARG_ERROR_POS_0)
    TEST(NCSignDigest(ctx, NULL, zero32, zero32, sig64),        ARG_ERROR_POS_1)
    TEST(NCSignDigest(ctx, &secKey, NULL, zero32, sig64),       ARG_ERROR_POS_2)
	TEST(NCSignDigest(ctx, &secKey, zero32, NULL, sig64),       ARG_ERROR_POS_3)
    TEST(NCSignDigest(ctx, &secKey, zero32, zero32, NULL),      ARG_ERROR_POS_4)

    /*Test null encrypt args*/
    TEST(NCEncrypt(NULL, &secKey, &pubKey, &cryptoData),    ARG_ERROR_POS_0)
    TEST(NCEncrypt(ctx, NULL, &pubKey, &cryptoData),        ARG_ERROR_POS_1)
	TEST(NCEncrypt(ctx, &secKey, NULL, &cryptoData),        ARG_ERROR_POS_2)
    TEST(NCEncrypt(ctx, &secKey, &pubKey, NULL),            ARG_ERROR_POS_3)

    /*Test invalid data size*/
    cryptoData.dataSize = 0;
    TEST(NCEncrypt(ctx, &secKey, &pubKey, &cryptoData), ARG_RANGE_ERROR_POS_3)
    
    /*Test null input data */
    cryptoData.dataSize = 32;
    cryptoData.inputData = NULL;
	TEST(NCEncrypt(ctx, &secKey, &pubKey, &cryptoData), ARG_INVALID_ERROR_POS_3)

    /*Test null output data */
	cryptoData.inputData = zero32;
    cryptoData.outputData = NULL;
	TEST(NCEncrypt(ctx, &secKey, &pubKey, &cryptoData), ARG_INVALID_ERROR_POS_3)

    /* Decrypt */
    cryptoData.dataSize = 32;
    cryptoData.inputData = zero32;
    cryptoData.outputData = sig64;

    TEST(NCDecrypt(NULL, &secKey, &pubKey, &cryptoData),    ARG_ERROR_POS_0)
    TEST(NCDecrypt(ctx, NULL, &pubKey, &cryptoData),       ARG_ERROR_POS_1)
	TEST(NCDecrypt(ctx, &secKey, NULL, &cryptoData),       ARG_ERROR_POS_2)
    TEST(NCDecrypt(ctx, &secKey, &pubKey, NULL),           ARG_ERROR_POS_3)

    /* Test invalid data size */
	cryptoData.dataSize = 0;
    TEST(NCDecrypt(ctx, &secKey, &pubKey, &cryptoData), ARG_RANGE_ERROR_POS_3)

    /* Test null input data */
	cryptoData.dataSize = 32;
    cryptoData.inputData = NULL;
	TEST(NCDecrypt(ctx, &secKey, &pubKey, &cryptoData), ARG_INVALID_ERROR_POS_3)

    /*Test null output data */
    cryptoData.inputData = zero32;
    cryptoData.outputData = NULL;
    TEST(NCDecrypt(ctx, &secKey, &pubKey, &cryptoData), ARG_INVALID_ERROR_POS_3)
    
    {
        uint8_t hmacDataOut[NC_ENCRYPTION_MAC_SIZE];
        TEST(NCComputeMac(NULL, hmacKeyOut, zero32, 32, hmacDataOut),   ARG_ERROR_POS_0)
        TEST(NCComputeMac(ctx, NULL, zero32, 32, hmacDataOut),         ARG_ERROR_POS_1)
        TEST(NCComputeMac(ctx, hmacKeyOut, NULL, 32, hmacDataOut),     ARG_ERROR_POS_2)
        TEST(NCComputeMac(ctx, hmacKeyOut, zero32, 0, hmacDataOut),    ARG_RANGE_ERROR_POS_3)
        TEST(NCComputeMac(ctx, hmacKeyOut, zero32, 32, NULL),          ARG_ERROR_POS_4)
    }

    {
        NCMacVerifyArgs macArgs;
        macArgs.payload = zero32;
        macArgs.payloadSize = 32;
        macArgs.mac32 = zero32;
        macArgs.nonce32 = zero32;

        TEST(NCVerifyMac(NULL, &secKey, &pubKey, &macArgs),     ARG_ERROR_POS_0)
        TEST(NCVerifyMac(ctx, NULL, &pubKey, &macArgs),        ARG_ERROR_POS_1)
        TEST(NCVerifyMac(ctx, &secKey, NULL, &macArgs),        ARG_ERROR_POS_2)
        TEST(NCVerifyMac(ctx, &secKey, &pubKey, NULL),         ARG_ERROR_POS_3)

        macArgs.payload = NULL;
        TEST(NCVerifyMac(ctx, &secKey, &pubKey, &macArgs), ARG_INVALID_ERROR_POS_3)

        macArgs.payload = zero32;
        macArgs.payloadSize = 0;
        TEST(NCVerifyMac(ctx, &secKey, &pubKey, &macArgs), ARG_RANGE_ERROR_POS_3)
    }
    
    PRINTL("\nPASSED: Public API argument validation tests completed")

    return 0;
}

#endif 

static int TestKnownKeys(const NCContext* context)
{   
    NCPublicKey pubKey;
    span_t secKey1, pubKey1, secKey2, pubKey2;

    PRINTL("TEST: Known keys")
    
    secKey1 = FromHexString("98c642360e7163a66cee5d9a842b252345b6f3f3e21bd3b7635d5e6c20c7ea36", sizeof(NCSecretKey));
    pubKey1 = FromHexString("0db15182c4ad3418b4fbab75304be7ade9cfa430a21c1c5320c9298f54ea5406", sizeof(NCPublicKey));

    secKey2 = FromHexString("3032cb8da355f9e72c9a94bbabae80ca99d3a38de1aed094b432a9fe3432e1f2", sizeof(NCSecretKey));
    pubKey2 = FromHexString("421181660af5d39eb95e48a0a66c41ae393ba94ffeca94703ef81afbed724e5a", sizeof(NCPublicKey));
   
    /*Test known keys*/
    TEST(NCValidateSecretKey(context, NCByteCastToSecretKey(secKey1.data)), NC_SUCCESS);

    /* Recover a public key from secret key 1 */
    TEST(NCGetPublicKey(context, NCByteCastToSecretKey(secKey1.data), &pubKey), NC_SUCCESS);

    /* Ensure the public key matches the known public key value */
    TEST(memcmp(pubKey1.data, &pubKey, sizeof(pubKey)), 0);

    /* Repeat with second key */
    TEST(NCValidateSecretKey(context, NCByteCastToSecretKey(secKey2.data)), NC_SUCCESS);
    TEST(NCGetPublicKey(context, NCByteCastToSecretKey(secKey2.data), &pubKey), NC_SUCCESS);
    TEST(memcmp(pubKey2.data, &pubKey, sizeof(pubKey)), 0);    

    PRINTL("\nPASSED: Known keys tests completed")
    return 0;
}

#define TEST_ENC_DATA_SIZE 128

static int TestCorrectEncryption(const NCContext* context)
{
    NCSecretKey secKey1;
    NCPublicKey pubKey1;
    
    NCSecretKey secKey2;
    NCPublicKey pubKey2;
  
    uint8_t hmacKeyOut[NC_HMAC_KEY_SIZE];
    uint8_t nonce[NC_NIP44_IV_SIZE];  //nonce is set by cipher spec, shoud use NCEncryptionGetIvSize() in production
    uint8_t mac[NC_ENCRYPTION_MAC_SIZE];

    uint8_t plainText[TEST_ENC_DATA_SIZE];
    uint8_t cipherText[TEST_ENC_DATA_SIZE];
    uint8_t decryptedText[TEST_ENC_DATA_SIZE];
  
    NCEncryptionArgs cryptoData;
    NCMacVerifyArgs macVerifyArgs;

    PRINTL("TEST: Correct encryption")

    ENSURE(NCEncryptionGetIvSize(NC_ENC_VERSION_NIP44) == (uint32_t)sizeof(nonce));
    ENSURE(NCEncryptionSetProperty(&cryptoData, NC_ENC_SET_VERSION, NC_ENC_VERSION_NIP44) == NC_SUCCESS);
    ENSURE(NCEncryptionSetPropertyEx(&cryptoData, NC_ENC_SET_IV, nonce, sizeof(nonce)) == NC_SUCCESS);
    ENSURE(NCEncryptionSetPropertyEx(&cryptoData, NC_ENC_SET_NIP44_MAC_KEY, hmacKeyOut, NC_HMAC_KEY_SIZE) == NC_SUCCESS);

    /* Assign the encryption material */
    ENSURE(NCEncryptionSetData(&cryptoData, plainText, cipherText, TEST_ENC_DATA_SIZE) == NC_SUCCESS);
   
    macVerifyArgs.nonce32 = nonce;    /* nonce is shared */
    macVerifyArgs.mac32 = mac;
    macVerifyArgs.payload = cipherText;
    macVerifyArgs.payloadSize = TEST_ENC_DATA_SIZE;

    /* init a sending and receiving key */
    FillRandomData(&secKey1, sizeof(NCSecretKey));
    FillRandomData(&secKey2, sizeof(NCSecretKey));
    FillRandomData(plainText, sizeof(plainText));
    /* nonce is shared */
    FillRandomData(nonce, sizeof(nonce));

    ENSURE(NCValidateSecretKey(context, &secKey1) == NC_SUCCESS);
    ENSURE(NCValidateSecretKey(context, &secKey2) == NC_SUCCESS);

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

#ifdef NC_ENABLE_UTILS

#include <noscryptutil.h>

/* Padding tests taken from the nip44 repo vectors.json file */
static const uint32_t _padTestActual[24] =      { 16, 32, 33, 37, 45, 49, 64, 65, 100, 111, 200, 250, 320, 383, 384, 400, 500, 512, 515, 700, 800, 900,  1020, 65536 };
static const uint32_t _padTestExpected[24] =    { 32, 32, 64, 64, 64, 64, 64, 96, 128, 128, 224, 256, 320, 384, 384, 448, 512, 512, 640, 768, 896, 1024, 1024, 65536 };

static int TestUtilNip44Encryption(
    const NCContext* libCtx, 
    span_t sendKey, 
    span_t recvKey, 
    span_t nonce, 
    span_t expected,
    span_t plainText
)
{
    NCPublicKey recvPubKey;
    uint8_t* outData;

    ENSURE(NCValidateSecretKey(libCtx, NCByteCastToSecretKey(sendKey.data)) == NC_SUCCESS);
    ENSURE(NCGetPublicKey(libCtx, NCByteCastToSecretKey(recvKey.data), &recvPubKey) == NC_SUCCESS);

    /* Alloc cipher in nip44 encryption mode */
    NCUtilCipherContext* ctx = NCUtilCipherAlloc(
        NC_ENC_VERSION_NIP44, 
        NC_UTIL_CIPHER_MODE_ENCRYPT | NC_UTIL_CIPHER_ZERO_ON_FREE
    );
    
    ENSURE(ctx != NULL);

    TEST(ncSpanGetSize(nonce), (uint32_t)NCUtilCipherGetIvSize(ctx));

    TEST(NCUtilCipherInit(ctx, plainText.data, plainText.size), NC_SUCCESS);

    /* Nonce is required for nip44 encryption */
    TEST(NCUtilCipherSetProperty(ctx, NC_ENC_SET_IV, nonce.data, nonce.size), NC_SUCCESS);

    /* Cipher update should return the  */
    TEST(NCUtilCipherUpdate(ctx, libCtx, NCByteCastToSecretKey(sendKey.data), &recvPubKey), NC_SUCCESS);

    NCResult cipherOutputSize = NCUtilCipherGetOutputSize(ctx);

    TEST(cipherOutputSize, expected.size);

    outData = (uint8_t*)malloc(cipherOutputSize);
    TASSERT(outData != NULL);

    /* Read the encrypted payload to test */
    TEST(NCUtilCipherReadOutput(ctx, outData, (uint32_t)cipherOutputSize), cipherOutputSize);

    /* Ensure encrypted payload matches */
    TEST(memcmp(outData, expected.data, cipherOutputSize), 0);

    free(outData);

    /* Free encryption memory */
    NCUtilCipherFree(ctx);

    return 0;
}

static int TestUtilNip44Decryption(
    const NCContext* libCtx,
    span_t sendKey,
    span_t recvKey,
    span_t payload,
	span_t expectedPt
)
{
    NCPublicKey recvPubKey;
    uint8_t* outData;

    ENSURE(NCValidateSecretKey(libCtx, NCByteCastToSecretKey(sendKey.data)) == NC_SUCCESS);
    ENSURE(NCGetPublicKey(libCtx, NCByteCastToSecretKey(recvKey.data), &recvPubKey) == NC_SUCCESS);

    /* Alloc cipher in nip44 decryption mode */
    NCUtilCipherContext* ctx = NCUtilCipherAlloc(
        NC_ENC_VERSION_NIP44,
        NC_UTIL_CIPHER_MODE_DECRYPT | NC_UTIL_CIPHER_ZERO_ON_FREE
    );

    ENSURE(ctx != NULL);

    /* submit encrypted payload for ciphertext */
    TEST(NCUtilCipherInit(ctx, payload.data, payload.size), NC_SUCCESS);

    TEST(NCUtilCipherUpdate(ctx, libCtx, NCByteCastToSecretKey(sendKey.data), &recvPubKey), NC_SUCCESS);

    NCResult plaintextSize = NCUtilCipherGetOutputSize(ctx);

    TEST(plaintextSize, expectedPt.size);

    outData = (uint8_t*)malloc(plaintextSize);

    TASSERT(outData != NULL);

    /* Read the encrypted payload to test */
    TEST(NCUtilCipherReadOutput(ctx, outData, (uint32_t)plaintextSize), plaintextSize);

    /* Ensure encrypted payload matches */
    TEST(memcmp(outData, expectedPt.data, plaintextSize), 0);

    free(outData);

    /* Free encryption memory */
    NCUtilCipherFree(ctx);

    return 0;
}

static int TestUtilFunctions(const NCContext* libCtx)
{
	PRINTL("TEST: Util functions")

	for (int i = 0; i < 24; i++)
    {
        int32_t totalSize = _padTestExpected[i] + 67;

        TEST(NCUtilGetEncryptionPaddedSize(NC_ENC_VERSION_NIP44, _padTestActual[i]), _padTestExpected[i]);
		TEST(NCUtilGetEncryptionBufferSize(NC_ENC_VERSION_NIP44, _padTestActual[i]), totalSize);
	}
    {
		PRINTL("TEST: NIP-44 util encryption")

	    /* From the nip44 vectors file */
		span_t sendKey = FromHexString("0000000000000000000000000000000000000000000000000000000000000001", sizeof(NCSecretKey));
		span_t recvKey = FromHexString("0000000000000000000000000000000000000000000000000000000000000002", sizeof(NCSecretKey));
		span_t nonce = FromHexString("0000000000000000000000000000000000000000000000000000000000000001", NC_NIP44_IV_SIZE);
        span_t payload = FromHexString("02000000000000000000000000000000000000000000000000000000000000000179ed06e5548ad3ff58ca920e6c0b4329f6040230f7e6e5641f20741780f0adc35a09794259929a02bb06ad8e8cf709ee4ccc567e9d514cdf5781af27a3e905e55b1b", 99);
		span_t plainText = FromHexString("61", 1);

        if (TestUtilNip44Encryption(libCtx, sendKey, recvKey, nonce, payload, plainText) != 0) 
        {
            return 1;
        }
    }
    {
        PRINTL("TEST: NIP-44 util decryption");

        /* From the nip44 vectors file */
        span_t sendKey = FromHexString("0000000000000000000000000000000000000000000000000000000000000001", sizeof(NCSecretKey));
        span_t recvKey = FromHexString("0000000000000000000000000000000000000000000000000000000000000002", sizeof(NCSecretKey));
        span_t payload = FromHexString("02000000000000000000000000000000000000000000000000000000000000000179ed06e5548ad3ff58ca920e6c0b4329f6040230f7e6e5641f20741780f0adc35a09794259929a02bb06ad8e8cf709ee4ccc567e9d514cdf5781af27a3e905e55b1b", 99);
		span_t plainText = FromHexString("61", 1);

        if (TestUtilNip44Decryption(libCtx, sendKey, recvKey, payload, plainText) != 0)
        {
            return 1;
        }
    }

	PRINTL("\nPASSED: Util functions tests completed")
	return 0;
}

#endif

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
