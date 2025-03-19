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
#include "mbedtls/ecdsa.h"
#include "mbedtls/ecjpake.h"
#include "mbedtls/timing.h"
#include "mbedtls/nist_kw.h"
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
// Mensaje de prueba
const char *mensaje = "Hola, este es un mensaje de prueba";

// Clave AES (128 bits = 16 bytes)
const unsigned char key[16] = "1234567890ABCDEF";
unsigned char iv[16]  = "FEDCBA0987654321";

// Buffer para resultados
unsigned char hash[32];
unsigned char cifrado[64];
unsigned char descifrado[64];

// Contextos de mbedtls
mbedtls_aes_context aes;
mbedtls_sha256_context sha256;
mbedtls_ecp_keypair keypair;
mbedtls_entropy_context entropy;
mbedtls_ctr_drbg_context ctr_drbg;

/*******************************************************************************
 * Code
 ******************************************************************************/
void aplicar_padding(const unsigned char *mensaje, unsigned char *mensaje_padded, size_t *len) {
    size_t pad = 16 - (*len % 16);
    memcpy(mensaje_padded, mensaje, *len);
    memset(mensaje_padded + *len, pad, pad);
    *len += pad;
}

void remover_padding(unsigned char *input, size_t *len) {
    size_t pad = input[*len - 1];
    if (pad > 0 && pad <= 16) {
        *len -= pad;
        input[*len] = '\0';
    }
}

void calcular_hash(const unsigned char *mensaje, size_t len) {
    mbedtls_sha256_init(&sha256);
    mbedtls_sha256_starts(&sha256, 0);
    mbedtls_sha256_update(&sha256, mensaje, len);
    mbedtls_sha256_finish(&sha256, hash);
    mbedtls_sha256_free(&sha256);
}

void cifrar_mensaje(const unsigned char *mensaje, size_t len) {
    mbedtls_aes_init(&aes);
    mbedtls_aes_setkey_enc(&aes, key, 128);

    unsigned char iv_cifrado[16];
    memcpy(iv_cifrado, iv, 16);

    mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, len, iv_cifrado, mensaje, cifrado);
    mbedtls_aes_free(&aes);
}

void descifrar_mensaje(size_t len) {
    mbedtls_aes_init(&aes);
    mbedtls_aes_setkey_dec(&aes, key, 128);

    unsigned char iv_descifrado[16];
    memcpy(iv_descifrado, iv, 16);

    mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, len, iv_descifrado, cifrado, descifrado);
    mbedtls_aes_free(&aes);
    remover_padding(descifrado, &len);
}

void firmar_mensaje() {
    unsigned char signature[64];
    size_t sig_len;

    mbedtls_ecp_keypair_init(&keypair);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    // Inicializar generador de números aleatorios
    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0);

    // Generar par de claves ECDSA
    mbedtls_ecp_group_load(&keypair.grp, MBEDTLS_ECP_DP_SECP256R1);
    mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1, &keypair, mbedtls_ctr_drbg_random, &ctr_drbg);

    // Firmar el hash
    mbedtls_ecdsa_write_signature(&keypair, MBEDTLS_MD_SHA256, hash, 32, signature, &sig_len, mbedtls_ctr_drbg_random, &ctr_drbg);

    mbedtls_printf("Firma generada correctamente (%zu bytes)\r\n", sig_len);

    mbedtls_ecp_keypair_free(&keypair);
    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);
}

int main(int argc, char *argv[])
{

    void *pointer;

#if defined(FREESCALE_KSDK_BM)
    /* HW init */
    BOARD_InitBootPins();
    BOARD_InitBootClocks();
    BOARD_InitDebugConsole();
    if( CRYPTO_InitHardware() != kStatus_Success )
    {
        mbedtls_printf( "Initialization of crypto HW failed\r\n" );
        mbedtls_exit( MBEDTLS_EXIT_FAILURE );
    }
#endif
    /*
     * The C standard doesn't guarantee that all-bits-0 is the representation
     * of a NULL pointer. We do however use that in our code for initializing
     * structures, which should work on every modern platform. Let's be sure.
     */

    mbedtls_printf("Mensaje original: %s\r\n", mensaje);

	// 1️⃣ Calcular hash
	calcular_hash((const unsigned char*)mensaje, strlen(mensaje));
	mbedtls_printf("Hash calculado con SHA-256: ");
	for (int i = 0; i < 32; i++) mbedtls_printf("%02x", hash[i]);
	mbedtls_printf("\r\n");

	// 2️⃣ Cifrar mensaje con AES-128-CBC
    size_t mensaje_len = strlen(mensaje);
    size_t padded_len = ((mensaje_len / 16) + 1) * 16;  // Asegura espacio para padding
    unsigned char mensaje_padded[padded_len];

    aplicar_padding((const unsigned char*)mensaje, mensaje_padded, &mensaje_len);
	cifrar_mensaje((const unsigned char*)mensaje, mensaje_len);
	mbedtls_printf("Mensaje cifrado: ");
	for (int i = 0; i < mensaje_len; i++) mbedtls_printf("%02x", cifrado[i]);
	mbedtls_printf("\r\n");

	// 3️⃣ Descifrar mensaje
	descifrar_mensaje(mensaje_len);
	mbedtls_printf("Mensaje descifrado: %s\r\n", descifrado);

	// 4️⃣ Firmar mensaje con ECDSA
	firmar_mensaje();

	return 0;


    memset( &pointer, 0, sizeof( void * ) );
    if( pointer != NULL )
    {
        mbedtls_printf( "all-bits-zero is not a NULL pointer\r\n" );
        mbedtls_exit( MBEDTLS_EXIT_FAILURE );
    }
    
    while (1)
    {
        char ch = GETCHAR();
        PUTCHAR(ch);
    }
}

