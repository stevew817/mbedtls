/**
 * \file psa/crypto_builtin_mac.h
 *
 * \brief Context structure declaration of the software-based driver which
 * performs MAC through the PSA Crypto driver dispatch layer.
 *
 * \note This file may not be included directly, due to a dependency on the
 * PSA hash operation context definition.
 *
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0
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
 */

#ifndef PSA_CRYPTO_BUILTIN_MAC_H
#define PSA_CRYPTO_BUILTIN_MAC_H

#include <psa/crypto_driver_common.h>
#include "mbedtls/cmac.h"

#if defined(MBEDTLS_PSA_BUILTIN_ALG_CMAC) || \
    defined(MBEDTLS_PSA_BUILTIN_ALG_HMAC)
#define MBEDTLS_PSA_BUILTIN_MAC
#endif

#if defined(PSA_WANT_ALG_HMAC)
typedef struct
{
    /** The HMAC algorithm in use */
    psa_algorithm_t alg;
    /** The hash context. */
    struct psa_hash_operation_s hash_ctx;
    /** The HMAC part of the context. */
    uint8_t opad[PSA_HMAC_MAX_HASH_BLOCK_SIZE];
} psa_hmac_internal_data_t;

#define MBEDTLS_PSA_HMAC_OPERATION_INIT {0, PSA_HASH_OPERATION_INIT, {0}}
#endif /* PSA_WANT_ALG_HMAC */

typedef struct
{
    psa_algorithm_t alg;
    unsigned int key_set : 1;
    unsigned int iv_required : 1;
    unsigned int iv_set : 1;
    unsigned int has_input : 1;
    unsigned int is_sign : 1;
    uint8_t mac_size;
    unsigned int id;
    union
    {
        unsigned dummy; /* Make the union non-empty even with no supported algorithms. */
#if defined(PSA_WANT_ALG_HMAC)
        psa_hmac_internal_data_t hmac;
#endif
#if defined(MBEDTLS_CMAC_C)
        mbedtls_cipher_context_t cmac;
#endif
    } ctx;
} mbedtls_psa_mac_operation_t;

#define MBEDTLS_PSA_MAC_OPERATION_INIT {0, {0}}

/*
 * BEYOND THIS POINT, TEST DRIVER DECLARATIONS ONLY.
 */
#if defined(PSA_CRYPTO_DRIVER_TEST)

typedef mbedtls_psa_mac_operation_t mbedtls_transparent_test_driver_mac_operation_t;
typedef mbedtls_psa_mac_operation_t mbedtls_opaque_test_driver_mac_operation_t;

#define MBEDTLS_TRANSPARENT_TEST_DRIVER_MAC_OPERATION_INIT MBEDTLS_PSA_MAC_OPERATION_INIT
#define MBEDTLS_OPAQUE_TEST_DRIVER_MAC_OPERATION_INIT MBEDTLS_PSA_MAC_OPERATION_INIT

#endif /* PSA_CRYPTO_DRIVER_TEST */

#endif /* PSA_CRYPTO_BUILTIN_MAC_H */
