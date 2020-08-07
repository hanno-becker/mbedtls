/*
 *  TLS 1.3 key schedule
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 ( the "License" ); you may
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

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL)

#include "mbedtls/debug.h"
#include "mbedtls/ssl.h"
#include "mbedtls/ssl_internal.h"

#include "mbedtls/hkdf.h"
#include <stdint.h>
#include <string.h>

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdlib.h>
#include <stdio.h>
#define mbedtls_printf     printf
#define mbedtls_calloc    calloc
#define mbedtls_free       free
#endif

/*
 * The mbedtls_ssl_tls1_3_hkdf_encode_label() function creates the HkdfLabel structure.
 *
 * The function assumes that the info buffer space has been
 * allocated accordingly and no further length checking is needed.
 *
 * The HkdfLabel is specified in the TLS 1.3 spec as follows:
 *
 * struct HkdfLabel {
 *   uint16 length;
 *   opaque label<7..255>;
 *   opaque context<0..255>;
 * };
 *
 * - HkdfLabel.length is Length
 * - HkdfLabel.label is "tls13 " + Label
 * - HkdfLabel.context is HashValue.
 */

static int ssl_tls1_3_hkdf_encode_label(
                            const unsigned char *label, int llen,
                            const unsigned char *hashValue, int hlen,
                            unsigned char *info, int length )
{
    unsigned char *p = info;
    const char label_prefix[] = "tls13 ";
    int total_label_len;

    total_label_len = sizeof(label_prefix) + llen;

    // create header
    *p++ = (unsigned char)( ( length >> 8 ) & 0xFF );
    *p++ = (unsigned char)( ( length >> 0 ) & 0xFF );
    *p++ = (unsigned char)( total_label_len & 0xFF );

    // copy label
    memcpy( p, label_prefix, sizeof(label_prefix) );
    p += sizeof(label_prefix);

    memcpy( p, label, llen );
    p += llen;

    // copy hash length
    *p++ = (unsigned char)( hlen & 0xFF );

    // copy hash value
    memcpy( p, hashValue, hlen );

    return( 0 );
}

/*
* The traffic keying material is generated from the following input values:
*  - A secret value
*  - A purpose value indicating the specific value being generated
*  - The length of the key
*
* The traffic keying material is generated from an input traffic
* secret value using:
*  [sender]_write_key = HKDF-Expand-Label( Secret, "key", "", key_length )
*  [sender]_write_iv  = HKDF-Expand-Label( Secret, "iv" , "", iv_length )
*
* [sender] denotes the sending side and the Secret value is provided by the function caller.
* We generate server and client side keys in a single function call.
*/
int mbedtls_ssl_tls1_3_make_traffic_keys(
                     mbedtls_md_type_t hash_alg,
                     const unsigned char *client_secret,
                     const unsigned char *server_secret,
                     int slen,
                     int keyLen, int ivLen,
                     mbedtls_ssl_key_set *keys )
{
    int ret = 0;

    keys->clientWriteKey = mbedtls_calloc( keyLen,1 );
    if( keys->clientWriteKey == NULL )
    {
        mbedtls_printf( "mbedtls_ssl_tls1_3_make_traffic_keys(): Error allocating clientWriteKey.\n" );
        return( ( MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL ) );
    }

    ret = mbedtls_ssl_tls1_3_hkdf_expand_label( hash_alg, client_secret, slen, (const unsigned char *) "key", 3,
                          (const unsigned char *)"", 0, keyLen,
                          keys->clientWriteKey, keyLen );

    if( ret < 0 )
    {
        mbedtls_printf( "mbedtls_ssl_tls1_3_make_traffic_keys(): Error for clientWriteKey %d.\n", ret );
        return( ( ret ) );
    }

    keys->serverWriteKey = mbedtls_calloc( keyLen,1 );
    if( keys->serverWriteKey == NULL )
    {
        mbedtls_printf( "mbedtls_ssl_tls1_3_make_traffic_keys(): Error allocating serverWriteKey.\n" );
        return( ( ret ) );
    }

    ret = mbedtls_ssl_tls1_3_hkdf_expand_label( hash_alg, server_secret, slen, (const unsigned char *)"key", 3,
                          (const unsigned char *)"", 0, keyLen,
                          keys->serverWriteKey, keyLen );

    if( ret < 0 )
    {
        mbedtls_printf( "mbedtls_ssl_tls1_3_make_traffic_keys(): Error for serverWriteKey %d.\n", ret );
        return( ( ret ) );
    }

    // Compute clientWriteIV
    keys->clientWriteIV = mbedtls_calloc( ivLen,1 );
    if( keys->clientWriteIV == NULL )
    {
        mbedtls_printf( "mbedtls_ssl_tls1_3_make_traffic_keys(): Error allocating clientWriteIV.\n" );
        return( ( ret ) );
    }

    ret = mbedtls_ssl_tls1_3_hkdf_expand_label( hash_alg, client_secret, slen, (const unsigned char *) "iv", 2,
                          (const unsigned char *)"", 0, ivLen,
                          keys->clientWriteIV, ivLen );

    if( ret < 0 )
    {
        mbedtls_printf( "mbedtls_ssl_tls1_3_make_traffic_keys(): Error for clientWriteIV %d.\n", ret );
        return( ( ret ) );
    }

    // Compute serverWriteIV
    keys->serverWriteIV = mbedtls_calloc( ivLen,1 );
    if( keys->serverWriteIV == NULL )
    {
        mbedtls_printf( "mbedtls_ssl_tls1_3_make_traffic_keys(): Error allocating serverWriteIV.\n" );
        return( ( ret ) );
    }

    ret = mbedtls_ssl_tls1_3_hkdf_expand_label( hash_alg, server_secret, slen, (const unsigned char *) "iv", 2,
                          (const unsigned char *)"", 0, ivLen,
                          keys->serverWriteIV, ivLen );

    if( ret < 0 )
    {
        mbedtls_printf( "mbedtls_ssl_tls1_3_make_traffic_keys(): Error for serverWriteIV %d.\n", ret );
        return( ( ret ) );
    }

#if defined(MBEDTLS_SSL_PROTO_DTLS)

    // Compute client_sn_key
    keys->client_sn_key = mbedtls_calloc( keyLen, 1 );
    if( keys->client_sn_key == NULL )
    {
        mbedtls_printf( "mbedtls_ssl_tls1_3_make_traffic_keys(): Error allocating client_sn_key.\n" );
        return( ( ret ) );
    }

    ret = mbedtls_ssl_tls1_3_hkdf_expand_label( hash_alg, client_secret, slen, (const unsigned char *) "sn", 2,
                          (const unsigned char *)"", 0, keyLen,
                          keys->client_sn_key, keyLen );

    if( ret < 0 )
    {
        mbedtls_printf( "mbedtls_ssl_tls1_3_make_traffic_keys(): Error for client_sn_key %d.\n", ret );
        return( ( ret ) );
    }

    // Compute server_sn_key
    keys->server_sn_key = mbedtls_calloc( keyLen, 1 );
    if( keys->server_sn_key == NULL )
    {
        mbedtls_printf( "mbedtls_ssl_tls1_3_make_traffic_keys(): Error allocating server_sn_key.\n" );
        return( ( ret ) );
    }

    ret = mbedtls_ssl_tls1_3_hkdf_expand_label( hash_alg, server_secret, slen, (const unsigned char *) "sn", 2,
                          (const unsigned char *)"", 0, keyLen,
                          keys->server_sn_key, keyLen );

    if( ret < 0 )
    {
        mbedtls_printf( "mbedtls_ssl_tls1_3_make_traffic_keys(): Error for server_sn_key %d.\n", ret );
        return( ( ret ) );
    }

#endif /* MBEDTLS_SSL_PROTO_DTLS */


    // Set epoch value to "undefined"
#if defined(MBEDTLS_SSL_PROTO_DTLS)
    keys->epoch = -1;
#endif /* MBEDTLS_SSL_PROTO_DTLS */

    // Set key length
    // Set IV length
    keys->keyLen = keyLen;
    keys->ivLen = ivLen;
    return( 0 );
}

int mbedtls_ssl_tls1_3_hkdf_expand_label(
                     mbedtls_md_type_t hash_alg, const unsigned char *secret,
                     int slen, const unsigned char *label, int llen,
                     const unsigned char *hashValue, int hlen, int length,
                     unsigned char *buf, int blen )
{
    int ret = 0;
    int len;
    const mbedtls_md_info_t *md;
    unsigned char *info = NULL;

    /* Compute length of info, which
         * is computed as follows:
     *
     * struct {
     *  uint16 length = Length;
     *   opaque label<7..255> = "tls13 " + Label;
     *   opaque context<0..255> = Context;
     * } HkdfLabel;
         *
         */
    len = 2 + 1 + llen + 1 + hlen + 6;

#if defined(HKDF_DEBUG)
    // ----------------------------- DEBUG ---------------------------
    mbedtls_printf( "HKDF Expand with label [tls13 " );
    for ( int i = 0; i < llen; i++ )
    {
        mbedtls_printf( "%c", label[i] );
    }
    mbedtls_printf( "] ( %d )", llen );
    mbedtls_printf( ", requested length = %d\n", blen );

    mbedtls_printf( "PRK ( %d ):", slen );
    for ( int i = 0; i < slen; i++ )
    {
        mbedtls_printf( "%02x", secret[i] );
    }
    mbedtls_printf( "\n" );

    mbedtls_printf( "Hash ( %d ):", hlen );
    for ( int i = 0; i <hlen; i++ )
    {
        mbedtls_printf( "%02x", hashValue[i] );
    }
    mbedtls_printf( "\n" );
        // ----------------------------- DEBUG ---------------------------
#endif

        info = mbedtls_calloc( len,1 );

    if( info == NULL )
    {
        mbedtls_printf( "calloc() failed in mbedtls_ssl_tls1_3_hkdf_expand_label()." );
        return( ( MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL ) );
    }

    ret = ssl_tls1_3_hkdf_encode_label( label, llen, hashValue, hlen, info, length );

    if( ret < 0 )
    {
        mbedtls_printf( "ssl_tls1_3_hkdf_encode_label(): Error %d.\n", ret );
        goto clean_up;
    }


#if defined(HKDF_DEBUG)
        // ----------------------------- DEBUG ---------------------------

        mbedtls_printf( "Info ( %d ):", len );
        for ( int i = 0; i < len; i++ )
        {
            mbedtls_printf( "%02x", info[i] );
        }
        mbedtls_printf( "\n" );

        // ----------------------------- DEBUG ---------------------------
#endif

        md = mbedtls_md_info_from_type( hash_alg );

        if( md == NULL )
        {
            mbedtls_printf( "mbedtls_md_info_from_type() failed in mbedtls_ssl_tls1_3_hkdf_expand_label()." );
            goto clean_up;
        }

    ret = mbedtls_hkdf_expand( md, secret, slen, info, len, buf, blen );

    if( ret != 0 )
    {
        mbedtls_printf( "hkdfExpand(): Error %d.\n", ret );
        goto clean_up;
    }

#if defined(HKDF_DEBUG)
    // ----------------------------- DEBUG ---------------------------

    mbedtls_printf( "Derived key ( %d ):", blen );
    for ( int i = 0; i < blen; i++ )
    {
        mbedtls_printf( "%02x", buf[i] );
    }
    mbedtls_printf( "\n" );

    // ----------------------------- DEBUG ---------------------------
#endif
clean_up:
    mbedtls_free( info );
    return( ret );
}

#endif /* MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL */
