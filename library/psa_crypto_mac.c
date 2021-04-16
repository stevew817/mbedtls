/*
 *  PSA MAC layer on top of Mbed TLS software crypto
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

#include "common.h"

#if defined(MBEDTLS_PSA_CRYPTO_C)

#include <psa/crypto.h>
#include "psa_crypto_core.h"
#include "psa_crypto_mac.h"
#include <mbedtls/md.h>

#include <mbedtls/error.h>
#include <string.h>

/* Use builtin defines specific to this compilation unit, since the test driver
 * relies on the software driver. */
#if( defined(MBEDTLS_PSA_BUILTIN_ALG_CMAC) || \
    ( defined(PSA_CRYPTO_DRIVER_TEST) && defined(MBEDTLS_PSA_ACCEL_ALG_CMAC) ) )
#define BUILTIN_ALG_CMAC        1
#endif
#if( defined(MBEDTLS_PSA_BUILTIN_ALG_HMAC) || \
    ( defined(PSA_CRYPTO_DRIVER_TEST) && defined(MBEDTLS_PSA_ACCEL_ALG_HMAC) ) )
#define BUILTIN_ALG_HMAC        1
#endif

#if defined(MBEDTLS_PSA_BUILTIN_ALG_HMAC) || defined(PSA_CRYPTO_DRIVER_TEST)
static size_t psa_get_hash_block_size( psa_algorithm_t alg )
{
    switch( alg )
    {
        case PSA_ALG_MD2:
            return( 16 );
        case PSA_ALG_MD4:
            return( 64 );
        case PSA_ALG_MD5:
            return( 64 );
        case PSA_ALG_RIPEMD160:
            return( 64 );
        case PSA_ALG_SHA_1:
            return( 64 );
        case PSA_ALG_SHA_224:
            return( 64 );
        case PSA_ALG_SHA_256:
            return( 64 );
        case PSA_ALG_SHA_384:
            return( 128 );
        case PSA_ALG_SHA_512:
            return( 128 );
        default:
            return( 0 );
    }
}

psa_status_t psa_hmac_abort_internal( psa_hmac_internal_data *hmac )
{
    mbedtls_platform_zeroize( hmac->opad, sizeof( hmac->opad ) );
    return( psa_hash_abort( &hmac->hash_ctx ) );
}

psa_status_t psa_hmac_setup_internal( psa_hmac_internal_data *hmac,
                                      const uint8_t *key,
                                      size_t key_length,
                                      psa_algorithm_t hash_alg )
{
    uint8_t ipad[PSA_HMAC_MAX_HASH_BLOCK_SIZE];
    size_t i;
    size_t hash_size = PSA_HASH_LENGTH( hash_alg );
    size_t block_size = psa_get_hash_block_size( hash_alg );
    psa_status_t status;

    hmac->alg = hash_alg;

    /* Sanity checks on block_size, to guarantee that there won't be a buffer
     * overflow below. This should never trigger if the hash algorithm
     * is implemented correctly. */
    /* The size checks against the ipad and opad buffers cannot be written
     * `block_size > sizeof( ipad ) || block_size > sizeof( hmac->opad )`
     * because that triggers -Wlogical-op on GCC 7.3. */
    if( block_size > sizeof( ipad ) )
        return( PSA_ERROR_NOT_SUPPORTED );
    if( block_size > sizeof( hmac->opad ) )
        return( PSA_ERROR_NOT_SUPPORTED );
    if( block_size < hash_size )
        return( PSA_ERROR_NOT_SUPPORTED );

    if( key_length > block_size )
    {
        status = psa_hash_compute( hash_alg, key, key_length,
                                   ipad, sizeof( ipad ), &key_length );
        if( status != PSA_SUCCESS )
            goto cleanup;
    }
    /* A 0-length key is not commonly used in HMAC when used as a MAC,
     * but it is permitted. It is common when HMAC is used in HKDF, for
     * example. Don't call `memcpy` in the 0-length because `key` could be
     * an invalid pointer which would make the behavior undefined. */
    else if( key_length != 0 )
        memcpy( ipad, key, key_length );

    /* ipad contains the key followed by garbage. Xor and fill with 0x36
     * to create the ipad value. */
    for( i = 0; i < key_length; i++ )
        ipad[i] ^= 0x36;
    memset( ipad + key_length, 0x36, block_size - key_length );

    /* Copy the key material from ipad to opad, flipping the requisite bits,
     * and filling the rest of opad with the requisite constant. */
    for( i = 0; i < key_length; i++ )
        hmac->opad[i] = ipad[i] ^ 0x36 ^ 0x5C;
    memset( hmac->opad + key_length, 0x5C, block_size - key_length );

    status = psa_hash_setup( &hmac->hash_ctx, hash_alg );
    if( status != PSA_SUCCESS )
        goto cleanup;

    status = psa_hash_update( &hmac->hash_ctx, ipad, block_size );

cleanup:
    mbedtls_platform_zeroize( ipad, sizeof( ipad ) );

    return( status );
}

psa_status_t psa_hmac_finish_internal( psa_hmac_internal_data *hmac,
                                       uint8_t *mac,
                                       size_t mac_size )
{
    uint8_t tmp[MBEDTLS_MD_MAX_SIZE];
    psa_algorithm_t hash_alg = hmac->alg;
    size_t hash_size = 0;
    size_t block_size = psa_get_hash_block_size( hash_alg );
    psa_status_t status;

    status = psa_hash_finish( &hmac->hash_ctx, tmp, sizeof( tmp ), &hash_size );
    if( status != PSA_SUCCESS )
        return( status );
    /* From here on, tmp needs to be wiped. */

    status = psa_hash_setup( &hmac->hash_ctx, hash_alg );
    if( status != PSA_SUCCESS )
        goto exit;

    status = psa_hash_update( &hmac->hash_ctx, hmac->opad, block_size );
    if( status != PSA_SUCCESS )
        goto exit;

    status = psa_hash_update( &hmac->hash_ctx, tmp, hash_size );
    if( status != PSA_SUCCESS )
        goto exit;

    status = psa_hash_finish( &hmac->hash_ctx, tmp, sizeof( tmp ), &hash_size );
    if( status != PSA_SUCCESS )
        goto exit;

    memcpy( mac, tmp, mac_size );

exit:
    mbedtls_platform_zeroize( tmp, hash_size );
    return( status );
}
#endif /* MBEDTLS_PSA_BUILTIN_ALG_HMAC || PSA_CRYPTO_DRIVER_TEST */

/* Implement the PSA driver MAC interface on top of mbed TLS if either the
 * software driver or the test driver requires it. */
#if defined(MBEDTLS_PSA_BUILTIN_MAC) || defined(PSA_CRYPTO_DRIVER_TEST)

#if defined(BUILTIN_ALG_CMAC)
static psa_status_t cmac_setup( mbedtls_psa_mac_operation_t *operation,
                                const psa_key_attributes_t *attributes,
                                const uint8_t *key_buffer,
                                size_t key_buffer_size )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_cipher_id_t cipher_id_tmp;
    const mbedtls_cipher_info_t * cipher_info_tmp;
    size_t key_bits = psa_get_key_bits( attributes );

    if( key_buffer_size < PSA_BITS_TO_BYTES( key_bits ) )
        return( PSA_ERROR_INVALID_ARGUMENT );

    switch( psa_get_key_type( attributes ) )
    {
#if defined(MBEDTLS_PSA_BUILTIN_KEY_TYPE_AES)
        case PSA_KEY_TYPE_AES:
            cipher_id_tmp = MBEDTLS_CIPHER_ID_AES;
            break;
#endif
#if defined(MBEDTLS_PSA_BUILTIN_KEY_TYPE_DES)
        case PSA_KEY_TYPE_DES:
            /* key_bits is 64 for Single-DES, 128 for two-key Triple-DES,
             * and 192 for three-key Triple-DES. */
            if( key_bits == 64 )
                cipher_id_tmp = MBEDTLS_CIPHER_ID_DES;
            else
                cipher_id_tmp = MBEDTLS_CIPHER_ID_3DES;
            /* mbedtls doesn't recognize two-key Triple-DES as an algorithm,
             * but two-key Triple-DES is functionally three-key Triple-DES
             * with K1=K3, so that's how we present it to mbedtls. */
            if( key_bits == 128 )
                key_bits = 192;
            break;
#endif
#if defined(MBEDTLS_PSA_BUILTIN_KEY_TYPE_CAMELLIA)
        case PSA_KEY_TYPE_CAMELLIA:
            cipher_id_tmp = MBEDTLS_CIPHER_ID_CAMELLIA;
            break;
#endif
#if defined(MBEDTLS_PSA_BUILTIN_KEY_TYPE_ARC4)
        case PSA_KEY_TYPE_ARC4:
            cipher_id_tmp = MBEDTLS_CIPHER_ID_ARC4;
            break;
#endif
#if defined(MBEDTLS_PSA_BUILTIN_KEY_TYPE_CHACHA20)
        case PSA_KEY_TYPE_CHACHA20:
            cipher_id_tmp = MBEDTLS_CIPHER_ID_CHACHA20;
            break;
#endif
        default:
            return( PSA_ERROR_NOT_SUPPORTED );
    }

    cipher_info_tmp = mbedtls_cipher_info_from_values(
                        cipher_id_tmp, (int) key_bits, MBEDTLS_MODE_ECB );

    if( cipher_info_tmp == NULL )
        return( PSA_ERROR_NOT_SUPPORTED );

    ret = mbedtls_cipher_setup( &operation->ctx.cmac, cipher_info_tmp );
    if( ret != 0 )
        goto exit;

    ret = mbedtls_cipher_cmac_starts( &operation->ctx.cmac,
                                      key_buffer,
                                      psa_get_key_bits( attributes ) );
exit:
    return( mbedtls_to_psa_error( ret ) );
}
#endif /* BUILTIN_ALG_CMAC */

/* Initialize this driver's MAC operation structure. Once this function has been
 * called, mbedtls_psa_mac_abort can run and will do the right thing. */
static psa_status_t mac_init(
    mbedtls_psa_mac_operation_t *operation,
    psa_algorithm_t alg )
{
    psa_status_t status = PSA_ERROR_NOT_SUPPORTED;

    operation->alg = PSA_ALG_FULL_LENGTH_MAC( alg );
    operation->key_set = 0;
    operation->iv_set = 0;
    operation->iv_required = 0;
    operation->has_input = 0;
    operation->is_sign = 0;

#if defined(BUILTIN_ALG_CMAC)
    if( operation->alg == PSA_ALG_CMAC )
    {
        operation->iv_required = 0;
        mbedtls_cipher_init( &operation->ctx.cmac );
        status = PSA_SUCCESS;
    }
    else
#endif /* BUILTIN_ALG_CMAC */
#if defined(BUILTIN_ALG_HMAC)
    if( PSA_ALG_IS_HMAC( operation->alg ) )
    {
        /* We'll set up the hash operation later in psa_hmac_setup_internal. */
        operation->ctx.hmac.alg = 0;
        status = PSA_SUCCESS;
    }
    else
#endif /* BUILTIN_ALG_HMAC */
    {
        if( ! PSA_ALG_IS_MAC( alg ) )
            status = PSA_ERROR_INVALID_ARGUMENT;
    }

    if( status != PSA_SUCCESS )
        memset( operation, 0, sizeof( *operation ) );
    return( status );
}

static psa_status_t mac_abort( mbedtls_psa_mac_operation_t *operation )
{
    if( operation->alg == 0 )
    {
        /* The object has (apparently) been initialized but it is not
         * in use. It's ok to call abort on such an object, and there's
         * nothing to do. */
        return( PSA_SUCCESS );
    }
    else
#if defined(BUILTIN_ALG_CMAC)
    if( operation->alg == PSA_ALG_CMAC )
    {
        mbedtls_cipher_free( &operation->ctx.cmac );
    }
    else
#endif /* BUILTIN_ALG_CMAC */
#if defined(BUILTIN_ALG_HMAC)
    if( PSA_ALG_IS_HMAC( operation->alg ) )
    {
        psa_hmac_abort_internal( &operation->ctx.hmac );
    }
    else
#endif /* BUILTIN_ALG_HMAC */
    {
        /* Sanity check (shouldn't happen: operation->alg should
         * always have been initialized to a valid value). */
        goto bad_state;
    }

    operation->alg = 0;
    operation->key_set = 0;
    operation->iv_set = 0;
    operation->iv_required = 0;
    operation->has_input = 0;
    operation->is_sign = 0;

    return( PSA_SUCCESS );

bad_state:
    /* If abort is called on an uninitialized object, we can't trust
     * anything. Wipe the object in case it contains confidential data.
     * This may result in a memory leak if a pointer gets overwritten,
     * but it's too late to do anything about this. */
    memset( operation, 0, sizeof( *operation ) );
    return( PSA_ERROR_BAD_STATE );
}

static psa_status_t mac_setup( mbedtls_psa_mac_operation_t *operation,
                               const psa_key_attributes_t *attributes,
                               const uint8_t *key_buffer,
                               size_t key_buffer_size,
                               psa_algorithm_t alg,
                               int is_sign )
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

    /* A context must be freshly initialized before it can be set up. */
    if( operation->alg != 0 )
    {
        return( PSA_ERROR_BAD_STATE );
    }

    status = mac_init( operation, alg );
    if( status != PSA_SUCCESS )
        return( status );
    if( is_sign )
        operation->is_sign = 1;

    /* Get the output length for the algorithm and key combination. None of the
     * currently supported algorithms have an output length dependent on actual
     * key size, so setting it to a bogus value is currently OK. */
    operation->mac_size =
        PSA_MAC_LENGTH( psa_get_key_type( attributes ), 0, alg );

#if defined(BUILTIN_ALG_CMAC)
    if( PSA_ALG_FULL_LENGTH_MAC( alg ) == PSA_ALG_CMAC )
    {
        status = cmac_setup( operation, attributes,
                             key_buffer, key_buffer_size );
    }
    else
#endif /* BUILTIN_ALG_CMAC */
#if defined(BUILTIN_ALG_HMAC)
    if( PSA_ALG_IS_HMAC( alg ) )
    {
        /* Sanity check. This shouldn't fail on a valid configuration. */
        if( operation->mac_size > sizeof( operation->ctx.hmac.opad ) )
        {
            status = PSA_ERROR_NOT_SUPPORTED;
            goto exit;
        }

        if( psa_get_key_type( attributes ) != PSA_KEY_TYPE_HMAC )
        {
            status = PSA_ERROR_INVALID_ARGUMENT;
            goto exit;
        }

        status = psa_hmac_setup_internal( &operation->ctx.hmac,
                                          key_buffer,
                                          key_buffer_size,
                                          PSA_ALG_HMAC_GET_HASH( alg ) );
    }
    else
#endif /* BUILTIN_ALG_HMAC */
    {
        status = PSA_ERROR_NOT_SUPPORTED;
    }

exit:
    if( status == PSA_SUCCESS )
        operation->key_set = 1;
    else
        mac_abort( operation );

    return( status );
}

static psa_status_t mac_compute(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t *input,
    size_t input_length,
    uint8_t *mac,
    size_t mac_size,
    size_t *mac_length )
{
    /* One-shot MAC has not been implemented in this PSA implementation yet. */
    (void) attributes;
    (void) key_buffer;
    (void) key_buffer_size;
    (void) alg;
    (void) input;
    (void) input_length;
    (void) mac;
    (void) mac_size;
    (void) mac_length;
    return( PSA_ERROR_NOT_SUPPORTED );
}

static psa_status_t mac_sign_setup(
    mbedtls_psa_mac_operation_t *operation,
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    psa_algorithm_t alg )
{
    return( mac_setup( operation, attributes, key_buffer, key_buffer_size, alg,
                       1 ) );
}

static psa_status_t mac_verify_setup(
    mbedtls_psa_mac_operation_t *operation,
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    psa_algorithm_t alg )
{
    return( mac_setup( operation, attributes, key_buffer, key_buffer_size, alg,
                        0 ) );
}

static psa_status_t mac_update(
    mbedtls_psa_mac_operation_t *operation,
    const uint8_t *input,
    size_t input_length )
{
    if( ! operation->key_set )
        return( PSA_ERROR_BAD_STATE );
    if( operation->iv_required && ! operation->iv_set )
        return( PSA_ERROR_BAD_STATE );
    operation->has_input = 1;

#if defined(BUILTIN_ALG_CMAC)
    if( operation->alg == PSA_ALG_CMAC )
    {
        return( mbedtls_to_psa_error(
                    mbedtls_cipher_cmac_update( &operation->ctx.cmac,
                                                input, input_length ) ) );
    }
    else
#endif /* BUILTIN_ALG_CMAC */
#if defined(BUILTIN_ALG_HMAC)
    if( PSA_ALG_IS_HMAC( operation->alg ) )
    {
        return( psa_hash_update( &operation->ctx.hmac.hash_ctx, input,
                                 input_length ) );
    }
    else
#endif /* BUILTIN_ALG_HMAC */
    {
        /* This shouldn't happen if `operation` was initialized by
         * a setup function. */
        return( PSA_ERROR_BAD_STATE );
    }
}

static psa_status_t mac_sign_finish(
    mbedtls_psa_mac_operation_t *operation,
    uint8_t *mac,
    size_t mac_size,
    size_t *mac_length )
{
    /* To be fleshed out in a subsequent commit */
    (void) operation;
    (void) mac;
    (void) mac_size;
    (void) mac_length;
    return( PSA_ERROR_NOT_SUPPORTED );
}

static psa_status_t mac_verify_finish(
    mbedtls_psa_mac_operation_t *operation,
    const uint8_t *mac,
    size_t mac_length )
{
    /* To be fleshed out in a subsequent commit */
    (void) operation;
    (void) mac;
    (void) mac_length;
    return( PSA_ERROR_NOT_SUPPORTED );
}
#endif /* MBEDTLS_PSA_BUILTIN_MAC || PSA_CRYPTO_DRIVER_TEST */

#if defined(MBEDTLS_PSA_BUILTIN_MAC)
psa_status_t mbedtls_psa_mac_compute(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t *input,
    size_t input_length,
    uint8_t *mac,
    size_t mac_size,
    size_t *mac_length )
{
    return( mac_compute( attributes, key_buffer, key_buffer_size, alg,
                         input, input_length,
                         mac, mac_size, mac_length ) );
}

psa_status_t mbedtls_psa_mac_sign_setup(
    mbedtls_psa_mac_operation_t *operation,
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    psa_algorithm_t alg )
{
    return( mac_sign_setup( operation, attributes,
                            key_buffer, key_buffer_size, alg ) );
}

psa_status_t mbedtls_psa_mac_verify_setup(
    mbedtls_psa_mac_operation_t *operation,
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    psa_algorithm_t alg )
{
    return( mac_verify_setup( operation, attributes,
                              key_buffer, key_buffer_size, alg ) );
}

psa_status_t mbedtls_psa_mac_update(
    mbedtls_psa_mac_operation_t *operation,
    const uint8_t *input,
    size_t input_length )
{
    return( mac_update( operation, input, input_length ) );
}

psa_status_t mbedtls_psa_mac_sign_finish(
    mbedtls_psa_mac_operation_t *operation,
    uint8_t *mac,
    size_t mac_size,
    size_t *mac_length )
{
    return( mac_sign_finish( operation, mac, mac_size, mac_length ) );
}

psa_status_t mbedtls_psa_mac_verify_finish(
    mbedtls_psa_mac_operation_t *operation,
    const uint8_t *mac,
    size_t mac_length )
{
    return( mac_verify_finish( operation, mac, mac_length ) );
}

psa_status_t mbedtls_psa_mac_abort(
    mbedtls_psa_mac_operation_t *operation )
{
    return( mac_abort( operation ) );
}
#endif /* MBEDTLS_PSA_BUILTIN_MAC */

 /*
  * BEYOND THIS POINT, TEST DRIVER ENTRY POINTS ONLY.
  */
#if defined(PSA_CRYPTO_DRIVER_TEST)

psa_status_t is_mac_accelerated( psa_algorithm_t alg )
{
#if defined(MBEDTLS_PSA_ACCEL_ALG_HMAC)
    if( PSA_ALG_IS_HMAC( alg ) )
        return( PSA_SUCCESS );
#endif

    switch( PSA_ALG_FULL_LENGTH_MAC( alg ) )
    {
#if defined(MBEDTLS_PSA_ACCEL_ALG_CMAC)
        case PSA_ALG_CMAC:
            return( PSA_SUCCESS );
#endif
        default:
            return( PSA_ERROR_NOT_SUPPORTED );
    }
}

psa_status_t mbedtls_transparent_test_driver_mac_compute(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t *input,
    size_t input_length,
    uint8_t *mac,
    size_t mac_size,
    size_t *mac_length )
{
    if( is_mac_accelerated( alg ) == PSA_SUCCESS )
        return( mac_compute( attributes, key_buffer, key_buffer_size, alg,
                             input, input_length,
                             mac, mac_size, mac_length ) );
    else
        return( PSA_ERROR_NOT_SUPPORTED );
}

psa_status_t mbedtls_transparent_test_driver_mac_sign_setup(
    mbedtls_transparent_test_driver_mac_operation_t *operation,
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    psa_algorithm_t alg )
{
    if( is_mac_accelerated( alg ) == PSA_SUCCESS )
        return( mac_sign_setup( operation, attributes,
                                key_buffer, key_buffer_size, alg ) );
    else
        return( PSA_ERROR_NOT_SUPPORTED );
}

psa_status_t mbedtls_transparent_test_driver_mac_verify_setup(
    mbedtls_transparent_test_driver_mac_operation_t *operation,
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    psa_algorithm_t alg )
{
    if( is_mac_accelerated( alg ) == PSA_SUCCESS )
        return( mac_verify_setup( operation, attributes,
                                  key_buffer, key_buffer_size, alg ) );
    else
        return( PSA_ERROR_NOT_SUPPORTED );
}

psa_status_t mbedtls_transparent_test_driver_mac_update(
    mbedtls_transparent_test_driver_mac_operation_t *operation,
    const uint8_t *input,
    size_t input_length )
{
    if( is_mac_accelerated( operation->alg ) == PSA_SUCCESS )
        return( mac_update( operation, input, input_length ) );
    else
        return( PSA_ERROR_BAD_STATE );
}

psa_status_t mbedtls_transparent_test_driver_mac_sign_finish(
    mbedtls_transparent_test_driver_mac_operation_t *operation,
    uint8_t *mac,
    size_t mac_size,
    size_t *mac_length )
{
    if( is_mac_accelerated( operation->alg ) == PSA_SUCCESS )
        return( mac_sign_finish( operation, mac, mac_size, mac_length ) );
    else
        return( PSA_ERROR_BAD_STATE );
}

psa_status_t mbedtls_transparent_test_driver_mac_verify_finish(
    mbedtls_transparent_test_driver_mac_operation_t *operation,
    const uint8_t *mac,
    size_t mac_length )
{
    if( is_mac_accelerated( operation->alg ) == PSA_SUCCESS )
        return( mac_verify_finish( operation, mac, mac_length ) );
    else
        return( PSA_ERROR_BAD_STATE );
}

psa_status_t mbedtls_transparent_test_driver_mac_abort(
    mbedtls_transparent_test_driver_mac_operation_t *operation )
{
    return( mac_abort( operation ) );
}

psa_status_t mbedtls_opaque_test_driver_mac_compute(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t *input,
    size_t input_length,
    uint8_t *mac,
    size_t mac_size,
    size_t *mac_length )
{
    /* Opaque driver testing is not implemented yet through this mechanism. */
    (void) attributes;
    (void) key_buffer;
    (void) key_buffer_size;
    (void) alg;
    (void) input;
    (void) input_length;
    (void) mac;
    (void) mac_size;
    (void) mac_length;
    return( PSA_ERROR_NOT_SUPPORTED );
}

psa_status_t mbedtls_opaque_test_driver_mac_sign_setup(
    mbedtls_opaque_test_driver_mac_operation_t *operation,
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    psa_algorithm_t alg )
{
    /* Opaque driver testing is not implemented yet through this mechanism. */
    (void) operation;
    (void) attributes;
    (void) key_buffer;
    (void) key_buffer_size;
    (void) alg;
    return( PSA_ERROR_NOT_SUPPORTED );
}

psa_status_t mbedtls_opaque_test_driver_mac_verify_setup(
    mbedtls_opaque_test_driver_mac_operation_t *operation,
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    psa_algorithm_t alg )
{
    /* Opaque driver testing is not implemented yet through this mechanism. */
    (void) operation;
    (void) attributes;
    (void) key_buffer;
    (void) key_buffer_size;
    (void) alg;
    return( PSA_ERROR_NOT_SUPPORTED );
}

psa_status_t mbedtls_opaque_test_driver_mac_update(
    mbedtls_opaque_test_driver_mac_operation_t *operation,
    const uint8_t *input,
    size_t input_length )
{
    /* Opaque driver testing is not implemented yet through this mechanism. */
    (void) operation;
    (void) input;
    (void) input_length;
    return( PSA_ERROR_NOT_SUPPORTED );
}

psa_status_t mbedtls_opaque_test_driver_mac_sign_finish(
    mbedtls_opaque_test_driver_mac_operation_t *operation,
    uint8_t *mac,
    size_t mac_size,
    size_t *mac_length )
{
    /* Opaque driver testing is not implemented yet through this mechanism. */
    (void) operation;
    (void) mac;
    (void) mac_size;
    (void) mac_length;
    return( PSA_ERROR_NOT_SUPPORTED );
}

psa_status_t mbedtls_opaque_test_driver_mac_verify_finish(
    mbedtls_opaque_test_driver_mac_operation_t *operation,
    const uint8_t *mac,
    size_t mac_length )
{
    /* Opaque driver testing is not implemented yet through this mechanism. */
    (void) operation;
    (void) mac;
    (void) mac_length;
    return( PSA_ERROR_NOT_SUPPORTED );
}

psa_status_t mbedtls_opaque_test_driver_mac_abort(
    mbedtls_opaque_test_driver_mac_operation_t *operation )
{
    /* Opaque driver testing is not implemented yet through this mechanism. */
    (void) operation;
    return( PSA_ERROR_NOT_SUPPORTED );
}

#endif /* PSA_CRYPTO_DRIVER_TEST */

#endif /* MBEDTLS_PSA_CRYPTO_C */
