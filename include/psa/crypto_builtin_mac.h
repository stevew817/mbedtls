/*
 *  Context structure declaration of the software-based driver which performs
 *  MAC through the PSA Crypto driver dispatch layer.
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

typedef struct
{
    psa_algorithm_t alg;
    /* To be fleshed out in a later commit. */
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
