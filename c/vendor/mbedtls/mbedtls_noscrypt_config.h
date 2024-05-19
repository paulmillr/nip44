/**
 * \file config-suite-b.h
 *
 * \brief Minimal configuration for TLS NSA Suite B Profile (RFC 6460)
 */
 /*
  *  Copyright The Mbed TLS Contributors
  *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
  */
  /*
   * Minimal configuration for TLS NSA Suite B Profile (RFC 6460)
   *
   * Distinguishing features:
   * - no RSA or classic DH, fully based on ECC
   * - optimized for low RAM usage
   *
   * Possible improvements:
   * - if 128-bit security is enough, disable secp384r1 and SHA-512
   * - use embedded certs in DER format and disable PEM_PARSE_C and BASE64_C
   *
   * See README.txt for usage instructions.
   */

   /* System support */
#define MBEDTLS_HAVE_ASM
#define MBEDTLS_HAVE_TIME

/* Mbed TLS feature support */

/* Mbed TLS modules */
#define MBEDTLS_MD_C
#define MBEDTLS_HKDF_C
#define MBEDTLS_CHACHA20_C
#define MBEDTLS_SHA256_C
#define MBEDTLS_ENTROPY_C


/* Save RAM at the expense of ROM */
//#define MBEDTLS_AES_ROM_TABLES

/* Save RAM by adjusting to our exact needs */
//#define MBEDTLS_MPI_MAX_SIZE    48 // 384-bit EC curve = 48 bytes

/* Save RAM at the expense of speed, see ecp.h */
//#define MBEDTLS_ECP_WINDOW_SIZE        2
//#define MBEDTLS_ECP_FIXED_POINT_OPTIM  0

/* Significant speed benefit at the expense of some ROM */
//#define MBEDTLS_ECP_NIST_OPTIM

/*
 * You should adjust this to the exact number of sources you're using: default
 * is the "mbedtls_platform_entropy_poll" source, but you may want to add other ones.
 * Minimum is 2 for the entropy test suite.
 */
#define MBEDTLS_ENTROPY_MAX_SOURCES 2