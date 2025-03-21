 /*
 *  Self-test demonstration program
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0
 *  Copyright 2017, 2021 NXP. Not a Contribution
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */

/*******************************************************************************
 * Includes
 ******************************************************************************/

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif
#include "mbedtls/aes.h"
/*
#include "mbedtls/entropy.h"
#include "mbedtls/entropy_poll.h"
#include "mbedtls/hmac_drbg.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/dhm.h"
#include "mbedtls/gcm.h"
#include "mbedtls/ccm.h"
#include "mbedtls/cmac.h"
#include "mbedtls/md2.h"
#include "mbedtls/md4.h"
#include "mbedtls/md5.h"
#include "mbedtls/ripemd160.h"
#include "mbedtls/sha1.h"
#include "mbedtls/sha256.h"
#include "mbedtls/sha512.h"
#include "mbedtls/arc4.h"
#include "mbedtls/des.h"
#include "mbedtls/aes.h"
#include "mbedtls/camellia.h"
#include "mbedtls/aria.h"
#include "mbedtls/chacha20.h"
#include "mbedtls/poly1305.h"
#include "mbedtls/chachapoly.h"
#include "mbedtls/base64.h"
#include "mbedtls/bignum.h"
#include "mbedtls/rsa.h"
#include "mbedtls/x509.h"
#include "mbedtls/xtea.h"
#include "mbedtls/pkcs5.h"
#include "mbedtls/ecp.h"
#include "mbedtls/ecjpake.h"
#include "mbedtls/timing.h"
#include "mbedtls/nist_kw.h"
*/
#if defined(MBEDTLS_ECDH_C) && defined(MBEDTLS_ECDH_ALT) && defined(MBEDTLS_NXP_SSSAPI)
#include "mbedtls/ecdh.h"
#endif
#include <string.h>
#if defined(MBEDTLS_PLATFORM_C)
#if defined(FREESCALE_KSDK_BM)
#include "pin_mux.h"
#include "clock_config.h"
#include "board.h"

#include "fsl_debug_console.h"
#if defined(MBEDTLS_NXP_SSSAPI)
#include "sssapi_mbedtls.h"
#else
#include "ksdk_mbedtls.h"
#endif
#include "mbedtls/version.h"


#define AES_KEY_SIZE 16    // AES-128 uses a 16-byte key
#define AES_BLOCK_SIZE 16  // AES block size is 16 bytes

#define mbedtls_printf PRINTF
#define mbedtls_snprintf snprintf
#define mbedtls_exit return
#define MBEDTLS_EXIT_SUCCESS 0
#define MBEDTLS_EXIT_FAILURE 1
#else
#include "mbedtls/platform.h"
#endif
#else
#include <stdio.h>
#include <stdlib.h>
#define mbedtls_calloc     calloc
#define mbedtls_free       free
#define mbedtls_printf     printf
#define mbedtls_snprintf   snprintf
#define mbedtls_exit       exit
#define MBEDTLS_EXIT_SUCCESS EXIT_SUCCESS
#define MBEDTLS_EXIT_FAILURE EXIT_FAILURE
#endif

#if defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C)
#include "mbedtls/memory_buffer_alloc.h"
#endif

#include "fsl_device_registers.h"
/*******************************************************************************
 * Definitions
 ******************************************************************************/

#define CORE_CLK_FREQ CLOCK_GetFreq(kCLOCK_CoreSysClk)

/*******************************************************************************
 * Prototypes
 ******************************************************************************/

/*******************************************************************************
 * Variables
 ******************************************************************************/

/*******************************************************************************
 * Code
 ******************************************************************************/
#if RUN_TEST_SNPRINTF
static int test_snprintf( size_t n, const char ref_buf[10], int ref_ret )
{
    int ret;
    char buf[10] = "xxxxxxxxx";
    const char ref[10] = "xxxxxxxxx";

    ret = mbedtls_snprintf( buf, n, "%s", "123" );
    if( ret < 0 || (size_t) ret >= n )
        ret = -1;

    if( strncmp( ref_buf, buf, sizeof( buf ) ) != 0 ||
        ref_ret != ret ||
        memcmp( buf + n, ref + n, sizeof( buf ) - n ) != 0 )
    {
        return( 1 );
    }

    return( 0 );
}

static int run_test_snprintf( void )
{
    return( test_snprintf( 0, "xxxxxxxxx",  -1 ) != 0 ||
            test_snprintf( 1, "",           -1 ) != 0 ||
            test_snprintf( 2, "1",          -1 ) != 0 ||
            test_snprintf( 3, "12",         -1 ) != 0 ||
            test_snprintf( 4, "123",         3 ) != 0 ||
            test_snprintf( 5, "123",         3 ) != 0 );
}
#endif

/*
 * Check if a seed file is present, and if not create one for the entropy
 * self-test. If this fails, we attempt the test anyway, so no error is passed
 * back.
 */
#if defined(MBEDTLS_SELF_TEST) && defined(MBEDTLS_ENTROPY_C)
#if defined(MBEDTLS_ENTROPY_NV_SEED) && !defined(MBEDTLS_NO_PLATFORM_ENTROPY)
static void create_entropy_seed_file( void )
{
    int result;
    size_t output_len = 0;
    unsigned char seed_value[MBEDTLS_ENTROPY_BLOCK_SIZE];

    /* Attempt to read the entropy seed file. If this fails - attempt to write
     * to the file to ensure one is present. */
    result = mbedtls_platform_std_nv_seed_read( seed_value,
                                                    MBEDTLS_ENTROPY_BLOCK_SIZE );
    if( 0 == result )
        return;

    result = mbedtls_platform_entropy_poll( NULL,
                                            seed_value,
                                            MBEDTLS_ENTROPY_BLOCK_SIZE,
                                            &output_len );
    if( 0 != result )
        return;

    if( MBEDTLS_ENTROPY_BLOCK_SIZE != output_len )
        return;

    mbedtls_platform_std_nv_seed_write( seed_value, MBEDTLS_ENTROPY_BLOCK_SIZE );
}
#endif

int mbedtls_entropy_self_test_wrapper( int verbose )
{
#if defined(MBEDTLS_ENTROPY_NV_SEED) && !defined(MBEDTLS_NO_PLATFORM_ENTROPY)
    create_entropy_seed_file( );
#endif
    //return( mbedtls_entropy_self_test( verbose ) );
}
#endif

#if defined(MBEDTLS_SELF_TEST)
#if defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C)
int mbedtls_memory_buffer_alloc_free_and_self_test( int verbose )
{
    if( verbose != 0 )
    {
#if defined(MBEDTLS_MEMORY_DEBUG)
        mbedtls_memory_buffer_alloc_status( );
#endif
    }
    mbedtls_memory_buffer_alloc_free( );
    return( mbedtls_memory_buffer_alloc_self_test( verbose ) );
}
#endif

typedef struct
{
    const char *name;
    int ( *function )( int );
} selftest_t;

const selftest_t selftests[] =
{
#if defined(MBEDTLS_MD2_C)
	{"md2", mbedtls_md2_self_test},
#endif
#if defined(MBEDTLS_MD4_C)
	{"md4", mbedtls_md4_self_test},
#endif
#if defined(MBEDTLS_AES_C)
    {"aes", mbedtls_aes_self_test},
#endif

#if defined(MBEDTLS_CHACHA20_C)
	{"chacha20", mbedtls_chacha20_self_test},
#endif

#if defined(MBEDTLS_ECDH_C) && defined(MBEDTLS_ECDH_ALT) && defined(MBEDTLS_NXP_SSSAPI)
	{"ecdh", mbedtls_ecdh_self_test},
#endif
/* Slower test after the faster ones */
#if defined(MBEDTLS_TIMING_C)
	{"timing", mbedtls_timing_self_test},
#endif
/* Heap test comes last */
#if defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C)
	{"memory_buffer_alloc", mbedtls_memory_buffer_alloc_free_and_self_test},
#endif
	{NULL, NULL}
};
#endif /* MBEDTLS_SELF_TEST */

static int bench_print_features(void)
{
    char *text;
    mbedtls_printf("mbedTLS version %s\r\n", MBEDTLS_VERSION_STRING);
    mbedtls_printf("fsys=%d\r\n", ((CORE_CLK_FREQ)));
    mbedtls_printf("Using following implementations:\r\n");
#if defined(MBEDTLS_FREESCALE_LTC_SHA256)
    text = "LTC HW accelerated";
#elif defined(MBEDTLS_FREESCALE_MMCAU_SHA256)
    text = "MMCAU HW accelerated";
#elif defined(MBEDTLS_FREESCALE_LPC_SHA256)
    text = "LPC HW accelerated";
#elif defined(MBEDTLS_FREESCALE_CAU3_SHA256)
    text = "CAU3 HW accelerated";
#elif defined(MBEDTLS_FREESCALE_DCP_SHA256)
    text = "DCP HW accelerated";
#elif defined(MBEDTLS_FREESCALE_HASHCRYPT_SHA256)
    text = "HASHCRYPT HW accelerated";
#elif defined(MBEDTLS_FREESCALE_CAAM_SHA256)
    text = "CAAM HW accelerated";
#elif defined(MBEDTLS_NXP_SENTINEL200)
    text = "S200 HW accelerated";
#elif defined(MBEDTLS_NXP_SENTINEL300)
    text = "S300 HW accelerated";
#else
    text = "Software implementation";
#endif
    mbedtls_printf("  SHA: %s\r\n", text);
#if defined(MBEDTLS_FREESCALE_LTC_AES)
    text = "LTC HW accelerated";
#elif defined(MBEDTLS_FREESCALE_MMCAU_AES)
    text = "MMCAU HW accelerated";
#elif defined(MBEDTLS_FREESCALE_LPC_AES)
    text = "LPC HW accelerated";
#elif defined(MBEDTLS_FREESCALE_CAU3_AES)
    text = "CAU3 HW accelerated";
#elif defined(MBEDTLS_FREESCALE_DCP_AES)
    text = "DCP HW accelerated";
#elif defined(MBEDTLS_FREESCALE_HASHCRYPT_AES)
    text = "HASHCRYPT HW accelerated";
#elif defined(MBEDTLS_FREESCALE_CAAM_AES)
    text = "CAAM HW accelerated";
#elif defined(MBEDTLS_NXP_SENTINEL200)
    text = "SW AES, S200 HW accelerated CCM and CMAC";
#elif defined(MBEDTLS_NXP_SENTINEL300)
    text = "SW AES, S300 HW accelerated CCM and CMAC";
#else
    text = "Software implementation";
#endif
    mbedtls_printf("  AES: %s\r\n", text);
#if defined(MBEDTLS_FREESCALE_LTC_AES_GCM)
    text = "LTC HW accelerated";
#elif defined(MBEDTLS_FREESCALE_MMCAU_AES)
    text = "MMCAU HW accelerated";
#elif defined(MBEDTLS_FREESCALE_LPC_AES_GCM)
    text = "LPC HW accelerated";
#elif defined(MBEDTLS_FREESCALE_CAU3_AES)
    text = "CAU3 HW accelerated";
#elif defined(MBEDTLS_FREESCALE_CAAM_AES_GCM)
    text = "CAAM HW accelerated";
#else
    text = "Software implementation";
#endif
    mbedtls_printf("  AES GCM: %s\r\n", text);
#if defined(MBEDTLS_FREESCALE_LTC_DES)
    text = "LTC HW accelerated";
#elif defined(MBEDTLS_FREESCALE_MMCAU_DES)
    text = "MMCAU HW accelerated";
#elif defined(MBEDTLS_FREESCALE_CAU3_DES)
    text = "CAU3 HW accelerated";
#elif defined(MBEDTLS_FREESCALE_CAAM_DES)
    text = "CAAM HW accelerated";
#else
    text = "Software implementation";
#endif
    mbedtls_printf("  DES: %s\r\n", text);
#if defined(MBEDTLS_FREESCALE_LTC_PKHA)
    text = "LTC HW accelerated";
#elif defined(MBEDTLS_FREESCALE_CAU3_PKHA)
    text = "CAU3 HW accelerated";
#elif defined(MBEDTLS_FREESCALE_CASPER_PKHA)
    text = "CASPER HW accelerated ECC256/384/521 and RSA verify";
#elif defined(MBEDTLS_FREESCALE_CAAM_PKHA)
    text = "CAAM HW accelerated";
#elif defined(MBEDTLS_NXP_SENTINEL200)
    text = "S200 HW accelerated ECDSA and ECDH";
#elif defined(MBEDTLS_NXP_SENTINEL300)
    text = "S300 HW accelerated ECDSA and ECDH";
#else
    text = "Software implementation";
#endif
    mbedtls_printf("  Asymmetric cryptography: %s\r\n", text);

    return 0;
}


// Plaintext (must be multiple of AES_BLOCK_SIZE)
unsigned char plaintext[AES_BLOCK_SIZE] = "Hello-AES-K64!";
unsigned char ciphertext[AES_BLOCK_SIZE];
unsigned char decrypted[AES_BLOCK_SIZE];


int main(int argc, char *argv[])
{
//Credentials
// AES 128-bit key (16 bytes)
const unsigned char key[AES_KEY_SIZE] = {
	0x60, 0x3D, 0xEB, 0x10, 0x15, 0xCA, 0x71, 0xBE,
	0x2B, 0x73, 0xAE, 0xF0, 0x85, 0x7D, 0x77, 0x81
};

// 16-byte Initialization Vector (IV)
unsigned char iv[AES_BLOCK_SIZE] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
};

#if defined(MBEDTLS_SELF_TEST)
    const selftest_t *test;
#endif /* MBEDTLS_SELF_TEST */
#if !defined(FREESCALE_KSDK_BM)
    char **argp;
    int exclude_mode = 0;
#endif
    int v             = 1; /* v=1 for verbose mode */
    int suites_tested = 0, suites_failed = 0;
#if defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C) && defined(MBEDTLS_SELF_TEST)
    unsigned char buf[1000000];
#endif
    void *pointer;

#if defined(FREESCALE_KSDK_BM)
    /* HW init */
    BOARD_InitBootPins();
    BOARD_InitBootClocks();
    BOARD_InitDebugConsole();
    if( CRYPTO_InitHardware() != kStatus_Success )
    {
        mbedtls_printf( "Initialization of crypto HW failed\n" );
        mbedtls_exit( MBEDTLS_EXIT_FAILURE );
    }
#endif
    bench_print_features();

    /*
     * The C standard doesn't guarantee that all-bits-0 is the representation
     * of a NULL pointer. We do however use that in our code for initializing
     * structures, which should work on every modern platform. Let's be sure.
     */
    memset( &pointer, 0, sizeof( void * ) );
    if( pointer != NULL )
    {
        mbedtls_printf( "all-bits-zero is not a NULL pointer\n" );
        mbedtls_exit( MBEDTLS_EXIT_FAILURE );
    }

    /*
     * Make sure we have a snprintf that correctly zero-terminates
     */
#if RUN_TEST_SNPRINTF /* Test is failed for UV */
    if( run_test_snprintf() != 0 )
    {
        mbedtls_printf( "the snprintf implementation is broken\n" );
        mbedtls_exit( MBEDTLS_EXIT_FAILURE );
    }
#endif
#if !defined(FREESCALE_KSDK_BM)
    for( argp = argv + ( argc >= 1 ? 1 : argc ); *argp != NULL; ++argp )
    {
        if( strcmp( *argp, "--quiet" ) == 0 ||
            strcmp( *argp, "-q" ) == 0 )
        {
            v = 0;
        }
        else if( strcmp( *argp, "--exclude" ) == 0 ||
                 strcmp( *argp, "-x" ) == 0 )
        {
            exclude_mode = 1;
        }
        else
            break;
    }

    if( v != 0 )
        mbedtls_printf( "\n" );
#endif

#if defined(MBEDTLS_SELF_TEST)

#if defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C)
    mbedtls_memory_buffer_alloc_init( buf, sizeof(buf) );
#endif

    // AES Context
	mbedtls_aes_context aes;
	mbedtls_aes_init(&aes);

	// --- ENCRYPTION ---
	mbedtls_aes_setkey_enc(&aes, key, 128);  // Set AES-128 encryption key
	unsigned char iv_enc[AES_BLOCK_SIZE];    // Copy IV as it will be modified
	memcpy(iv_enc, iv, AES_BLOCK_SIZE);
	mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, AES_BLOCK_SIZE, iv_enc, plaintext, ciphertext);

	// --- DECRYPTION ---
	mbedtls_aes_setkey_dec(&aes, key, 128);  // Set AES-128 decryption key
	unsigned char iv_dec[AES_BLOCK_SIZE];    // Reset IV for decryption
	memcpy(iv_dec, iv, AES_BLOCK_SIZE);
	mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, AES_BLOCK_SIZE, iv_dec, ciphertext, decrypted);

	// Cleanup
	mbedtls_aes_free(&aes);

	// Null-terminate decrypted text for printing
	decrypted[AES_BLOCK_SIZE - 1] = '\0';

	mbedtls_printf("Original Text: %s\r\n", plaintext);
    mbedtls_printf("Encrypted (hex): ");
    for (int i = 0; i < AES_BLOCK_SIZE; i++) {
    	mbedtls_printf("%02X ", ciphertext[i]);
    }
    mbedtls_printf("\r\nDecrypted Text: %s\r\n", decrypted);

#if defined(FREESCALE_KSDK_BM)
    /* Run all the tests */
    for (test = selftests; test->name != NULL; test++)
    {
        if (test->function(v) != 0)
        {
            suites_failed++;
        }
        suites_tested++;
    }
#else
    if( *argp != NULL && exclude_mode == 0 )
    {
        /* Run the specified tests */
        for( ; *argp != NULL; argp++ )
        {
            for( test = selftests; test->name != NULL; test++ )
            {
                if( !strcmp( *argp, test->name ) )
                {
                    if( test->function( v )  != 0 )
                    {
                        suites_failed++;
                    }
                    suites_tested++;
                    break;
                }
            }
            if( test->name == NULL )
            {
                mbedtls_printf( "  Test suite %s not available -> failed\n\n", *argp );
                suites_failed++;
            }
        }
    }
    else
    {
        /* Run all the tests except excluded ones */
        for( test = selftests; test->name != NULL; test++ )
        {
            if( exclude_mode )
            {
                char **excluded;
                for( excluded = argp; *excluded != NULL; ++excluded )
                {
                    if( !strcmp( *excluded, test->name ) )
                        break;
                }
                if( *excluded )
                {
                    if( v )
                        mbedtls_printf( "  Skip: %s\n", test->name );
                    continue;
                }
            }
            if( test->function( v )  != 0 )
            {
                suites_failed++;
            }
            suites_tested++;
        }
    }
#endif /* FREESCALE_KSDK_BM */

#else
    (void) exclude_mode;
    mbedtls_printf( " MBEDTLS_SELF_TEST not defined.\n" );
#endif

    if( v != 0 )
    {
        mbedtls_printf( "  Executed %d test suites\n\n", suites_tested );

        if( suites_failed > 0)
        {
            mbedtls_printf( "  [ %d tests FAIL ]\n\n", suites_failed );
        }
        else
        {
            mbedtls_printf( "  [ All tests PASS ]\n\n" );
        }
#if defined(_WIN32)
        mbedtls_printf( "  Press Enter to exit this program.\n" );
        fflush( stdout ); getchar();
#endif
    }
    
    while (1)
    {
        char ch = GETCHAR();
        PUTCHAR(ch);
    }
}

