/*
 *  Benchmark demonstration program
 *
 *  Copyright (C) 2006-2016, ARM Limited, All Rights Reserved
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
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#define mbedtls_exit       exit
#define mbedtls_printf     printf
#define mbedtls_snprintf   snprintf
#define mbedtls_free       free
#endif

#if !defined(MBEDTLS_TIMING_C)
int main( void )
{
    mbedtls_printf("MBEDTLS_TIMING_C not defined.\n");
    return( 0 );
}
#else

#include <string.h>
#include <stdlib.h>

#include "mbedtls/timing.h"

#include "mbedtls/md4.h"
#include "mbedtls/md5.h"
#include "mbedtls/ripemd160.h"
#include "mbedtls/sha1.h"
#include "mbedtls/sha256.h"
#include "mbedtls/sha512.h"
#include "mbedtls/arc4.h"
#include "mbedtls/des.h"
#include "mbedtls/aes.h"
#include "mbedtls/blowfish.h"
#include "mbedtls/camellia.h"
#include "mbedtls/gcm.h"
#include "mbedtls/ccm.h"
#include "mbedtls/cmac.h"
#include "mbedtls/havege.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/hmac_drbg.h"
#include "mbedtls/rsa.h"
#include "mbedtls/dhm.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/error.h"

#if defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C)
#include "mbedtls/memory_buffer_alloc.h"
#endif

/*
 * For heap usage estimates, we need an estimate of the overhead per allocated
 * block. ptmalloc2/3 (used in gnu libc for instance) uses 2 size_t per block,
 * so use that as our baseline.
 */
#define MEM_BLOCK_OVERHEAD  ( 2 * sizeof( size_t ) )

/*
 * Size to use for the alloc buffer if MEMORY_BUFFER_ALLOC_C is defined.
 */
#define HEAP_SIZE       (1u << 16)  // 64k

#define DFL_ITERATIONS  1024 // Default number of iterations per test
#define DFL_DURATION    1    // Default duration per test
#define DFL_BUFSIZE     1024 // Default buffer size
#define HEADER_FORMAT   "  %-24s :  "
#define TITLE_LEN       25

#define USAGE                                                           \
    "\n usage: benchmark param=<> options \n"                           \
    "\n acceptable parameters:\n"                                       \
    "    iter=%%d             default: 1024\n"                          \
    "                        #iterations for cycles / iteration benchmark\n" \
    "    duration=%%d         default: 1\n"                             \
    "                        duration in seconds for of kb / s benchmark\n"  \
    "    buf=%%d              default: 1024\n"                          \
    "                        size of buffer in bytes\n"                 \
    "\n acceptable options:\n"                                          \
    "    md4, md5, ripemd160, sha1, sha256, sha512,\n"                  \
    "    arc4, des3, des, camellia, blowfish,\n"                        \
    "    aes_cbc, aes_gcm, aes_ccm, aes_cmac, des3_cmac,\n"             \
    "    havege, ctr_drbg, hmac_drbg\n"                                 \
    "    rsa, dhm, ecdsa, ecdh.\n"

#if defined(MBEDTLS_ERROR_C)
#define PRINT_ERROR                                                     \
        mbedtls_strerror( ret, ( char * )tmp, sizeof( tmp ) );          \
        mbedtls_printf( "FAILED: %s\n", tmp );
#else
#define PRINT_ERROR                                                     \
        mbedtls_printf( "FAILED: -0x%04x\n", -ret );
#endif

typedef struct {
    char md4, md5, ripemd160, sha1, sha256, sha512,
         arc4, des3, des,
         aes_cbc, aes_gcm, aes_ccm, aes_cmac, des3_cmac,
         camellia, blowfish,
         havege, ctr_drbg, hmac_drbg,
         rsa, dhm, ecdsa, ecdh;
} todo_list;

struct options
{
    unsigned long long iterations; /* Number of iterations in second part of TIME_AND_TSC test */
    unsigned duration;             /* Duration in seconds of first part of TIME_AND_TSC test   */
    unsigned bufsize;              /* Size of buffer */

    todo_list todo;
} opt;

#define TIME_AND_TSC( TITLE, CODE )                                     \
do {                                                                    \
    unsigned long ii, jj, tsc;                                          \
                                                                        \
    mbedtls_printf( HEADER_FORMAT, TITLE );                             \
    fflush( stdout );                                                   \
                                                                        \
    if( opt.duration > 0 )                                              \
    {                                                                   \
        mbedtls_set_alarm( opt.duration );                              \
        for( ii = 1; ! mbedtls_timing_alarmed; ii++ )                   \
        {                                                               \
            CODE;                                                       \
        }                                                               \
        mbedtls_printf( "%9lu Kb/s ", ii * opt.bufsize / 1024 );        \
    }                                                                   \
                                                                        \
    if( opt.iterations > 0 )                                            \
    {                                                                   \
        tsc = mbedtls_timing_hardclock();                               \
        for( jj = 0; jj < opt.iterations; jj++ )                        \
        {                                                               \
            CODE;                                                       \
        }                                                               \
        mbedtls_printf( "%9lu cycles/byte",                             \
         ( mbedtls_timing_hardclock() - tsc ) / ( jj * opt.bufsize ) ); \
    }                                                                   \
                                                                        \
    mbedtls_printf( "\n" );                                             \
                                                                        \
} while( 0 )

#if defined(MBEDTLS_ERROR_C)
#define PRINT_ERROR                                                     \
        mbedtls_strerror( ret, ( char * )tmp, sizeof( tmp ) );          \
        mbedtls_printf( "FAILED: %s\n", tmp );
#else
#define PRINT_ERROR                                                     \
        mbedtls_printf( "FAILED: -0x%04x\n", -ret );
#endif

#if defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C) && defined(MBEDTLS_MEMORY_DEBUG)

#define MEMORY_MEASURE_INIT                                             \
    size_t max_used, max_blocks, max_bytes;                             \
    size_t prv_used, prv_blocks;                                        \
    mbedtls_memory_buffer_alloc_cur_get( &prv_used, &prv_blocks );      \
    mbedtls_memory_buffer_alloc_max_reset( );

#define MEMORY_MEASURE_PRINT( title_len )                               \
    mbedtls_memory_buffer_alloc_max_get( &max_used, &max_blocks );      \
    for( ii = 12 - title_len; ii != 0; ii-- ) mbedtls_printf( " " );    \
    max_used -= prv_used;                                               \
    max_blocks -= prv_blocks;                                           \
    max_bytes = max_used + MEM_BLOCK_OVERHEAD * max_blocks;             \
    mbedtls_printf( "%6u heap bytes", (unsigned) max_bytes );

#else
#define MEMORY_MEASURE_INIT
#define MEMORY_MEASURE_PRINT( title_len )
#endif

#define TIME_PUBLIC( TITLE, TYPE, CODE )                                \
do {                                                                    \
    unsigned long ii;                                                   \
    int ret;                                                            \
    MEMORY_MEASURE_INIT;                                                \
                                                                        \
    mbedtls_printf( HEADER_FORMAT, TITLE );                             \
    fflush( stdout );                                                   \
    mbedtls_set_alarm( 3 );                                             \
                                                                        \
    ret = 0;                                                            \
    for( ii = 1; ! mbedtls_timing_alarmed && ! ret ; ii++ )             \
    {                                                                   \
        CODE;                                                           \
    }                                                                   \
                                                                        \
    if( ret != 0 )                                                      \
    {                                                                   \
        PRINT_ERROR;                                                    \
    }                                                                   \
    else                                                                \
    {                                                                   \
        mbedtls_printf( "%6lu " TYPE "/s", ii / 3 );                    \
        MEMORY_MEASURE_PRINT( sizeof( TYPE ) + 1 );                     \
        mbedtls_printf( "\n" );                                         \
    }                                                                   \
} while( 0 )

static int myrand( void *rng_state, unsigned char *output, size_t len )
{
    size_t use_len;
    int rnd;

    if( rng_state != NULL )
        rng_state  = NULL;

    while( len > 0 )
    {
        use_len = len;
        if( use_len > sizeof(int) )
            use_len = sizeof(int);

        rnd = rand();
        memcpy( output, &rnd, use_len );
        output += use_len;
        len -= use_len;
    }

    return( 0 );
}

/*
 * Clear some memory that was used to prepare the context
 */
#if defined(MBEDTLS_ECP_C)
void ecp_clear_precomputed( mbedtls_ecp_group *grp )
{
    if( grp->T != NULL )
    {
        size_t i;
        for( i = 0; i < grp->T_size; i++ )
            mbedtls_ecp_point_free( &grp->T[i] );
        mbedtls_free( grp->T );
    }
    grp->T = NULL;
    grp->T_size = 0;
}
#else
#define ecp_clear_precomputed( g )
#endif

int main( int argc, char *argv[] )
{
    int i;
    unsigned char tmp[200];
    char title[TITLE_LEN];
#if defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C)
    unsigned char alloc_buf[HEAP_SIZE] = { 0 };
#endif
    unsigned char * buf = NULL;

    int print_usage = 0;

    opt.iterations = DFL_ITERATIONS;
    opt.duration   = DFL_DURATION;
    opt.bufsize    = DFL_BUFSIZE;

    if( argc <= 1 )
    {
        memset( &opt.todo, 1, sizeof( opt.todo ) );
    }
    else
    {
        memset( &opt.todo, 0, sizeof( opt.todo ) );

        for( i = 1; i < argc; i++ )
        {
            if( memcmp( argv[i], "iter", 4 ) == 0 )
            {
                if( ( argv[i] = strchr( argv[i], '=' ) ) == NULL )
                {
                    mbedtls_printf( USAGE );
                    print_usage = 1;
                }
                else
                {
                    argv[i]++;
                    opt.iterations = atoi( argv[i] );
                }
            }
            else if( memcmp( argv[i], "duration", 8 ) == 0 )
            {
                if( ( argv[i] = strchr( argv[i], '=' ) ) == NULL )
                {
                    mbedtls_printf( USAGE );
                    print_usage = 1;
                }
                else
                {
                    argv[i]++;
                    opt.duration = atoi( argv[i] );
                }
            }
            else if( memcmp( argv[i], "buf", 3 ) == 0 )
            {
                if( ( argv[i] = strchr( argv[i], '=' ) ) == NULL )
                {
                    mbedtls_printf( USAGE );
                    print_usage = 1;
                }
                else
                {
                    argv[i]++;
                    opt.bufsize = atoi( argv[i] );
                }
            }
            else if( strcmp( argv[i], "md4" ) == 0 )
                opt.todo.md4 = 1;
            else if( strcmp( argv[i], "md5" ) == 0 )
                opt.todo.md5 = 1;
            else if( strcmp( argv[i], "ripemd160" ) == 0 )
                opt.todo.ripemd160 = 1;
            else if( strcmp( argv[i], "sha1" ) == 0 )
                opt.todo.sha1 = 1;
            else if( strcmp( argv[i], "sha256" ) == 0 )
                opt.todo.sha256 = 1;
            else if( strcmp( argv[i], "sha512" ) == 0 )
                opt.todo.sha512 = 1;
            else if( strcmp( argv[i], "arc4" ) == 0 )
                opt.todo.arc4 = 1;
            else if( strcmp( argv[i], "des3" ) == 0 )
                opt.todo.des3 = 1;
            else if( strcmp( argv[i], "des" ) == 0 )
                opt.todo.des = 1;
            else if( strcmp( argv[i], "aes_cbc" ) == 0 )
                opt.todo.aes_cbc = 1;
            else if( strcmp( argv[i], "aes_gcm" ) == 0 )
                opt.todo.aes_gcm = 1;
            else if( strcmp( argv[i], "aes_ccm" ) == 0 )
                opt.todo.aes_ccm = 1;
            else if( strcmp( argv[i], "aes_cmac" ) == 0 )
                opt.todo.aes_cmac = 1;
            else if( strcmp( argv[i], "des3_cmac" ) == 0 )
                opt.todo.des3_cmac = 1;
            else if( strcmp( argv[i], "camellia" ) == 0 )
                opt.todo.camellia = 1;
            else if( strcmp( argv[i], "blowfish" ) == 0 )
                opt.todo.blowfish = 1;
            else if( strcmp( argv[i], "havege" ) == 0 )
                opt.todo.havege = 1;
            else if( strcmp( argv[i], "ctr_drbg" ) == 0 )
                opt.todo.ctr_drbg = 1;
            else if( strcmp( argv[i], "hmac_drbg" ) == 0 )
                opt.todo.hmac_drbg = 1;
            else if( strcmp( argv[i], "rsa" ) == 0 )
                opt.todo.rsa = 1;
            else if( strcmp( argv[i], "dhm" ) == 0 )
                opt.todo.dhm = 1;
            else if( strcmp( argv[i], "ecdsa" ) == 0 )
                opt.todo.ecdsa = 1;
            else if( strcmp( argv[i], "ecdh" ) == 0 )
                opt.todo.ecdh = 1;
            else
            {
                mbedtls_printf( "Unrecognized option: %s\n", argv[i] );
                print_usage = 1;
            }
        }

        if( print_usage == 1 )
        {
            mbedtls_printf( USAGE );
        }
    }

    mbedtls_printf( "Iterations per clock/iteration test: %llu\n", opt.iterations );
    mbedtls_printf( "Duration per data/seconds tests:     %u\n",   opt.duration );
    mbedtls_printf( "Buffer size (in bytes):              %u\n",   opt.bufsize );

    mbedtls_printf( "\n" );

#if defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C)
    mbedtls_memory_buffer_alloc_init( alloc_buf, sizeof( alloc_buf ) );
#endif

    if( ( buf = mbedtls_calloc( 1, opt.bufsize ) ) == NULL )
    {
        mbedtls_printf( "Failed to allocate buffer\n" );
        mbedtls_exit(1);
    }

    memset( buf, 0xAA, opt.bufsize );
    memset( tmp, 0xBB, sizeof( tmp ) );

#if defined(MBEDTLS_MD4_C)
    if( opt.todo.md4 )
        TIME_AND_TSC( "MD4", mbedtls_md4( buf, opt.bufsize, tmp ) );
#endif

#if defined(MBEDTLS_MD5_C)
    if( opt.todo.md5 )
        TIME_AND_TSC( "MD5", mbedtls_md5( buf, opt.bufsize, tmp ) );
#endif

#if defined(MBEDTLS_RIPEMD160_C)
    if( opt.todo.ripemd160 )
        TIME_AND_TSC( "RIPEMD160", mbedtls_ripemd160( buf, opt.bufsize, tmp ) );
#endif

#if defined(MBEDTLS_SHA1_C)
    if( opt.todo.sha1 )
        TIME_AND_TSC( "SHA-1", mbedtls_sha1( buf, opt.bufsize, tmp ) );
#endif

#if defined(MBEDTLS_SHA256_C)
    if( opt.todo.sha256 )
        TIME_AND_TSC( "SHA-256", mbedtls_sha256( buf, opt.bufsize, tmp, 0 ) );
#endif

#if defined(MBEDTLS_SHA512_C)
    if( opt.todo.sha512 )
        TIME_AND_TSC( "SHA-512", mbedtls_sha512( buf, opt.bufsize, tmp, 0 ) );
#endif

#if defined(MBEDTLS_ARC4_C)
    if( opt.todo.arc4 )
    {
        mbedtls_arc4_context arc4;
        mbedtls_arc4_init( &arc4 );
        mbedtls_arc4_setup( &arc4, tmp, 32 );
        TIME_AND_TSC( "ARC4", mbedtls_arc4_crypt( &arc4, opt.bufsize, buf, buf ) );
        mbedtls_arc4_free( &arc4 );
    }
#endif

#if defined(MBEDTLS_DES_C)
#if defined(MBEDTLS_CIPHER_MODE_CBC)
    if( opt.todo.des3 )
    {
        mbedtls_des3_context des3;
        mbedtls_des3_init( &des3 );
        mbedtls_des3_set3key_enc( &des3, tmp );
        TIME_AND_TSC( "3DES",
                mbedtls_des3_crypt_cbc( &des3, MBEDTLS_DES_ENCRYPT, opt.bufsize, tmp, buf, buf ) );
        mbedtls_des3_free( &des3 );
    }

    if( opt.todo.des )
    {
        mbedtls_des_context des;
        mbedtls_des_init( &des );
        mbedtls_des_setkey_enc( &des, tmp );
        TIME_AND_TSC( "DES",
                mbedtls_des_crypt_cbc( &des, MBEDTLS_DES_ENCRYPT, opt.bufsize, tmp, buf, buf ) );
        mbedtls_des_free( &des );
    }

#endif /* MBEDTLS_CIPHER_MODE_CBC */
#if defined(MBEDTLS_CMAC_C)
    if( opt.todo.des3_cmac )
    {
        unsigned char output[8];
        const mbedtls_cipher_info_t *cipher_info;

        memset( buf, 0, opt.bufsize );
        memset( tmp, 0, sizeof( tmp ) );

        cipher_info = mbedtls_cipher_info_from_type( MBEDTLS_CIPHER_DES_EDE3_ECB );

        TIME_AND_TSC( "3DES-CMAC",
                      mbedtls_cipher_cmac( cipher_info, tmp, 192, buf,
                      opt.bufsize, output ) );
    }
#endif /* MBEDTLS_CMAC_C */
#endif /* MBEDTLS_DES_C */

#if defined(MBEDTLS_AES_C)
#if defined(MBEDTLS_CIPHER_MODE_CBC)
    if( opt.todo.aes_cbc )
    {
        int keysize;
        mbedtls_aes_context aes;
        mbedtls_aes_init( &aes );
        for( keysize = 128; keysize <= 256; keysize += 64 )
        {
            mbedtls_snprintf( title, sizeof( title ), "AES-CBC-%d", keysize );

            memset( buf, 0, opt.bufsize );
            memset( tmp, 0, sizeof( tmp ) );
            mbedtls_aes_setkey_enc( &aes, tmp, keysize );

            TIME_AND_TSC( title,
                mbedtls_aes_crypt_cbc( &aes, MBEDTLS_AES_ENCRYPT, opt.bufsize, tmp, buf, buf ) );
        }
        mbedtls_aes_free( &aes );
    }
#endif
#if defined(MBEDTLS_GCM_C)
    if( opt.todo.aes_gcm )
    {
        int keysize;
        mbedtls_gcm_context gcm;

        mbedtls_gcm_init( &gcm );
        for( keysize = 128; keysize <= 256; keysize += 64 )
        {
            mbedtls_snprintf( title, sizeof( title ), "AES-GCM-%d", keysize );

            memset( buf, 0, opt.bufsize );
            memset( tmp, 0, sizeof( tmp ) );
            mbedtls_gcm_setkey( &gcm, MBEDTLS_CIPHER_ID_AES, tmp, keysize );

            TIME_AND_TSC( title,
                    mbedtls_gcm_crypt_and_tag( &gcm, MBEDTLS_GCM_ENCRYPT, opt.bufsize, tmp,
                        12, NULL, 0, buf, buf, 16, tmp ) );

            mbedtls_gcm_free( &gcm );
        }
    }
#endif
#if defined(MBEDTLS_CCM_C)
    if( opt.todo.aes_ccm )
    {
        int keysize;
        mbedtls_ccm_context ccm;

        mbedtls_ccm_init( &ccm );
        for( keysize = 128; keysize <= 256; keysize += 64 )
        {
            mbedtls_snprintf( title, sizeof( title ), "AES-CCM-%d", keysize );

            memset( buf, 0, opt.bufsize );
            memset( tmp, 0, sizeof( tmp ) );
            mbedtls_ccm_setkey( &ccm, MBEDTLS_CIPHER_ID_AES, tmp, keysize );

            TIME_AND_TSC( title,
                    mbedtls_ccm_encrypt_and_tag( &ccm, opt.bufsize, tmp,
                        12, NULL, 0, buf, buf, tmp, 16 ) );

            mbedtls_ccm_free( &ccm );
        }
    }
#endif
#if defined(MBEDTLS_CMAC_C)
    if( opt.todo.aes_cmac )
    {
        unsigned char output[16];
        const mbedtls_cipher_info_t *cipher_info;
        mbedtls_cipher_type_t cipher_type;
        int keysize;

        for( keysize = 128, cipher_type = MBEDTLS_CIPHER_AES_128_ECB;
             keysize <= 256;
             keysize += 64, cipher_type++ )
        {
            mbedtls_snprintf( title, sizeof( title ), "AES-CMAC-%d", keysize );

            memset( buf, 0, opt.bufsize );
            memset( tmp, 0, sizeof( tmp ) );

            cipher_info = mbedtls_cipher_info_from_type( cipher_type );

            TIME_AND_TSC( title,
                          mbedtls_cipher_cmac( cipher_info, tmp, keysize,
                                               buf, opt.bufsize, output ) );
        }

        memset( buf, 0, opt.bufsize );
        memset( tmp, 0, sizeof( tmp ) );
        TIME_AND_TSC( "AES-CMAC-PRF-128",
                      mbedtls_aes_cmac_prf_128( tmp, 16, buf, opt.bufsize,
                                                output ) );
    }
#endif /* MBEDTLS_CMAC_C */
#endif /* MBEDTLS_AES_C */

#if defined(MBEDTLS_CAMELLIA_C) && defined(MBEDTLS_CIPHER_MODE_CBC)
    if( opt.todo.camellia )
    {
        int keysize;
        mbedtls_camellia_context camellia;
        mbedtls_camellia_init( &camellia );
        for( keysize = 128; keysize <= 256; keysize += 64 )
        {
            mbedtls_snprintf( title, sizeof( title ), "CAMELLIA-CBC-%d", keysize );

            memset( buf, 0, opt.bufsize );
            memset( tmp, 0, sizeof( tmp ) );
            mbedtls_camellia_setkey_enc( &camellia, tmp, keysize );

            TIME_AND_TSC( title,
                    mbedtls_camellia_crypt_cbc( &camellia, MBEDTLS_CAMELLIA_ENCRYPT,
                        opt.bufsize, tmp, buf, buf ) );
        }
        mbedtls_camellia_free( &camellia );
    }
#endif

#if defined(MBEDTLS_BLOWFISH_C) && defined(MBEDTLS_CIPHER_MODE_CBC)
    if( opt.todo.blowfish )
    {
        int keysize;
        mbedtls_blowfish_context blowfish;
        mbedtls_blowfish_init( &blowfish );

        for( keysize = 128; keysize <= 256; keysize += 64 )
        {
            mbedtls_snprintf( title, sizeof( title ), "BLOWFISH-CBC-%d", keysize );

            memset( buf, 0, opt.bufsize );
            memset( tmp, 0, sizeof( tmp ) );
            mbedtls_blowfish_setkey( &blowfish, tmp, keysize );

            TIME_AND_TSC( title,
                    mbedtls_blowfish_crypt_cbc( &blowfish, MBEDTLS_BLOWFISH_ENCRYPT, opt.bufsize,
                        tmp, buf, buf ) );
        }

        mbedtls_blowfish_free( &blowfish );
    }
#endif

#if defined(MBEDTLS_HAVEGE_C)
    if( opt.todo.havege )
    {
        mbedtls_havege_state hs;
        mbedtls_havege_init( &hs );
        TIME_AND_TSC( "HAVEGE", mbedtls_havege_random( &hs, buf, opt.bufsize ) );
        mbedtls_havege_free( &hs );
    }
#endif

#if defined(MBEDTLS_CTR_DRBG_C)
    if( opt.todo.ctr_drbg )
    {
        mbedtls_ctr_drbg_context ctr_drbg;

        mbedtls_ctr_drbg_init( &ctr_drbg );

        if( mbedtls_ctr_drbg_seed( &ctr_drbg, myrand, NULL, NULL, 0 ) != 0 )
            mbedtls_exit(1);
        TIME_AND_TSC( "CTR_DRBG (NOPR)",
                if( mbedtls_ctr_drbg_random( &ctr_drbg, buf, opt.bufsize ) != 0 )
                mbedtls_exit(1) );

        if( mbedtls_ctr_drbg_seed( &ctr_drbg, myrand, NULL, NULL, 0 ) != 0 )
            mbedtls_exit(1);
        mbedtls_ctr_drbg_set_prediction_resistance( &ctr_drbg, MBEDTLS_CTR_DRBG_PR_ON );
        TIME_AND_TSC( "CTR_DRBG (PR)",
                if( mbedtls_ctr_drbg_random( &ctr_drbg, buf, opt.bufsize ) != 0 )
                mbedtls_exit(1) );
        mbedtls_ctr_drbg_free( &ctr_drbg );
    }
#endif

#if defined(MBEDTLS_HMAC_DRBG_C)
    if( opt.todo.hmac_drbg )
    {
        mbedtls_hmac_drbg_context hmac_drbg;
        const mbedtls_md_info_t *md_info;

        mbedtls_hmac_drbg_init( &hmac_drbg );

#if defined(MBEDTLS_SHA1_C)
        if( ( md_info = mbedtls_md_info_from_type( MBEDTLS_MD_SHA1 ) ) == NULL )
            mbedtls_exit(1);

        if( mbedtls_hmac_drbg_seed( &hmac_drbg, md_info, myrand, NULL, NULL, 0 ) != 0 )
            mbedtls_exit(1);
        TIME_AND_TSC( "HMAC_DRBG SHA-1 (NOPR)",
                if( mbedtls_hmac_drbg_random( &hmac_drbg, buf, opt.bufsize ) != 0 )
                mbedtls_exit(1) );
        mbedtls_hmac_drbg_free( &hmac_drbg );

        if( mbedtls_hmac_drbg_seed( &hmac_drbg, md_info, myrand, NULL, NULL, 0 ) != 0 )
            mbedtls_exit(1);
        mbedtls_hmac_drbg_set_prediction_resistance( &hmac_drbg,
                                             MBEDTLS_HMAC_DRBG_PR_ON );
        TIME_AND_TSC( "HMAC_DRBG SHA-1 (PR)",
                if( mbedtls_hmac_drbg_random( &hmac_drbg, buf, opt.bufsize ) != 0 )
                mbedtls_exit(1) );
        mbedtls_hmac_drbg_free( &hmac_drbg );
#endif

#if defined(MBEDTLS_SHA256_C)
        if( ( md_info = mbedtls_md_info_from_type( MBEDTLS_MD_SHA256 ) ) == NULL )
            mbedtls_exit(1);

        if( mbedtls_hmac_drbg_seed( &hmac_drbg, md_info, myrand, NULL, NULL, 0 ) != 0 )
            mbedtls_exit(1);
        TIME_AND_TSC( "HMAC_DRBG SHA-256 (NOPR)",
                if( mbedtls_hmac_drbg_random( &hmac_drbg, buf, opt.bufsize ) != 0 )
                mbedtls_exit(1) );
        mbedtls_hmac_drbg_free( &hmac_drbg );

        if( mbedtls_hmac_drbg_seed( &hmac_drbg, md_info, myrand, NULL, NULL, 0 ) != 0 )
            mbedtls_exit(1);
        mbedtls_hmac_drbg_set_prediction_resistance( &hmac_drbg,
                                             MBEDTLS_HMAC_DRBG_PR_ON );
        TIME_AND_TSC( "HMAC_DRBG SHA-256 (PR)",
                if( mbedtls_hmac_drbg_random( &hmac_drbg, buf, opt.bufsize ) != 0 )
                mbedtls_exit(1) );
        mbedtls_hmac_drbg_free( &hmac_drbg );
#endif
    }
#endif

#if defined(MBEDTLS_RSA_C) && defined(MBEDTLS_GENPRIME)
    if( opt.todo.rsa )
    {
        int keysize;
        mbedtls_rsa_context rsa;
        for( keysize = 2048; keysize <= 4096; keysize *= 2 )
        {
            mbedtls_snprintf( title, sizeof( title ), "RSA-%d", keysize );

            mbedtls_rsa_init( &rsa, MBEDTLS_RSA_PKCS_V15, 0 );
            mbedtls_rsa_gen_key( &rsa, myrand, NULL, keysize, 65537 );

            TIME_PUBLIC( title, " public",
                    buf[0] = 0;
                    ret = mbedtls_rsa_public( &rsa, buf, buf ) );

            TIME_PUBLIC( title, "private",
                    buf[0] = 0;
                    ret = mbedtls_rsa_private( &rsa, myrand, NULL, buf, buf ) );

            mbedtls_rsa_free( &rsa );
        }
    }
#endif

#if defined(MBEDTLS_DHM_C) && defined(MBEDTLS_BIGNUM_C)
    if( opt.todo.dhm )
    {
        int dhm_sizes[] = { 2048, 3072 };
        const char *dhm_P[] = {
            MBEDTLS_DHM_RFC3526_MODP_2048_P,
            MBEDTLS_DHM_RFC3526_MODP_3072_P,
        };
        const char *dhm_G[] = {
            MBEDTLS_DHM_RFC3526_MODP_2048_G,
            MBEDTLS_DHM_RFC3526_MODP_3072_G,
        };

        mbedtls_dhm_context dhm;
        size_t olen;
        for( i = 0; (size_t) i < sizeof( dhm_sizes ) / sizeof( dhm_sizes[0] ); i++ )
        {
            mbedtls_dhm_init( &dhm );

            if( mbedtls_mpi_read_string( &dhm.P, 16, dhm_P[i] ) != 0 ||
                mbedtls_mpi_read_string( &dhm.G, 16, dhm_G[i] ) != 0 )
            {
                mbedtls_exit( 1 );
            }

            dhm.len = mbedtls_mpi_size( &dhm.P );
            mbedtls_dhm_make_public( &dhm, (int) dhm.len, buf, dhm.len, myrand, NULL );
            if( mbedtls_mpi_copy( &dhm.GY, &dhm.GX ) != 0 )
                mbedtls_exit( 1 );

            mbedtls_snprintf( title, sizeof( title ), "DHE-%d", dhm_sizes[i] );
            TIME_PUBLIC( title, "handshake",
                    ret |= mbedtls_dhm_make_public( &dhm, (int) dhm.len, buf, dhm.len,
                                            myrand, NULL );
                    ret |= mbedtls_dhm_calc_secret( &dhm, buf, opt.bufsize, &olen, myrand, NULL ) );

            mbedtls_snprintf( title, sizeof( title ), "DH-%d", dhm_sizes[i] );
            TIME_PUBLIC( title, "handshake",
                    ret |= mbedtls_dhm_calc_secret( &dhm, buf, opt.bufsize, &olen, myrand, NULL ) );

            mbedtls_dhm_free( &dhm );
        }
    }
#endif

#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_SHA256_C)
    if( opt.todo.ecdsa )
    {
        mbedtls_ecdsa_context ecdsa;
        const mbedtls_ecp_curve_info *curve_info;
        size_t sig_len;

        memset( buf, 0x2A, opt.bufsize );

        for( curve_info = mbedtls_ecp_curve_list();
             curve_info->grp_id != MBEDTLS_ECP_DP_NONE;
             curve_info++ )
        {
            mbedtls_ecdsa_init( &ecdsa );

            if( mbedtls_ecdsa_genkey( &ecdsa, curve_info->grp_id, myrand, NULL ) != 0 )
                mbedtls_exit( 1 );
            ecp_clear_precomputed( &ecdsa.grp );

            mbedtls_snprintf( title, sizeof( title ), "ECDSA-%s",
                                              curve_info->name );
            TIME_PUBLIC( title, "sign",
                    ret = mbedtls_ecdsa_write_signature( &ecdsa, MBEDTLS_MD_SHA256, buf, curve_info->bit_size,
                                                tmp, &sig_len, myrand, NULL ) );

            mbedtls_ecdsa_free( &ecdsa );
        }

        for( curve_info = mbedtls_ecp_curve_list();
             curve_info->grp_id != MBEDTLS_ECP_DP_NONE;
             curve_info++ )
        {
            mbedtls_ecdsa_init( &ecdsa );

            if( mbedtls_ecdsa_genkey( &ecdsa, curve_info->grp_id, myrand, NULL ) != 0 ||
                mbedtls_ecdsa_write_signature( &ecdsa, MBEDTLS_MD_SHA256, buf, curve_info->bit_size,
                                               tmp, &sig_len, myrand, NULL ) != 0 )
            {
                mbedtls_exit( 1 );
            }
            ecp_clear_precomputed( &ecdsa.grp );

            mbedtls_snprintf( title, sizeof( title ), "ECDSA-%s",
                                              curve_info->name );
            TIME_PUBLIC( title, "verify",
                    ret = mbedtls_ecdsa_read_signature( &ecdsa, buf, curve_info->bit_size,
                                                tmp, sig_len ) );

            mbedtls_ecdsa_free( &ecdsa );
        }
    }
#endif

#if defined(MBEDTLS_ECDH_C)
    if( opt.todo.ecdh )
    {
        mbedtls_ecdh_context ecdh;
#if defined(MBEDTLS_ECP_DP_CURVE25519_ENABLED)
        mbedtls_mpi z;
#endif
        const mbedtls_ecp_curve_info *curve_info;
        size_t olen;

        for( curve_info = mbedtls_ecp_curve_list();
             curve_info->grp_id != MBEDTLS_ECP_DP_NONE;
             curve_info++ )
        {
            mbedtls_ecdh_init( &ecdh );

            if( mbedtls_ecp_group_load( &ecdh.grp, curve_info->grp_id ) != 0 ||
                mbedtls_ecdh_make_public( &ecdh, &olen, buf, sizeof( buf),
                                  myrand, NULL ) != 0 ||
                mbedtls_ecp_copy( &ecdh.Qp, &ecdh.Q ) != 0 )
            {
                mbedtls_exit( 1 );
            }
            ecp_clear_precomputed( &ecdh.grp );

            mbedtls_snprintf( title, sizeof( title ), "ECDHE-%s",
                                              curve_info->name );
            TIME_PUBLIC( title, "handshake",
                    ret |= mbedtls_ecdh_make_public( &ecdh, &olen, buf, sizeof( buf),
                                             myrand, NULL );
                    ret |= mbedtls_ecdh_calc_secret( &ecdh, &olen, buf, opt.bufsize,
                                             myrand, NULL ) );
            mbedtls_ecdh_free( &ecdh );
        }

        /* Curve25519 needs to be handled separately */
#if defined(MBEDTLS_ECP_DP_CURVE25519_ENABLED)
        mbedtls_ecdh_init( &ecdh );
        mbedtls_mpi_init( &z );

        if( mbedtls_ecp_group_load( &ecdh.grp, MBEDTLS_ECP_DP_CURVE25519 ) != 0 ||
            mbedtls_ecdh_gen_public( &ecdh.grp, &ecdh.d, &ecdh.Qp, myrand, NULL ) != 0 )
        {
            mbedtls_exit( 1 );
        }

        TIME_PUBLIC(  "ECDHE-Curve25519", "handshake",
                ret |= mbedtls_ecdh_gen_public( &ecdh.grp, &ecdh.d, &ecdh.Q,
                                        myrand, NULL );
                ret |= mbedtls_ecdh_compute_shared( &ecdh.grp, &z, &ecdh.Qp, &ecdh.d,
                                            myrand, NULL ) );

        mbedtls_ecdh_free( &ecdh );
        mbedtls_mpi_free( &z );
#endif

        for( curve_info = mbedtls_ecp_curve_list();
             curve_info->grp_id != MBEDTLS_ECP_DP_NONE;
             curve_info++ )
        {
            mbedtls_ecdh_init( &ecdh );

            if( mbedtls_ecp_group_load( &ecdh.grp, curve_info->grp_id ) != 0 ||
                mbedtls_ecdh_make_public( &ecdh, &olen, buf, sizeof( buf),
                                  myrand, NULL ) != 0 ||
                mbedtls_ecp_copy( &ecdh.Qp, &ecdh.Q ) != 0 ||
                mbedtls_ecdh_make_public( &ecdh, &olen, buf, sizeof( buf),
                                  myrand, NULL ) != 0 )
            {
                mbedtls_exit( 1 );
            }
            ecp_clear_precomputed( &ecdh.grp );

            mbedtls_snprintf( title, sizeof( title ), "ECDH-%s",
                                              curve_info->name );
            TIME_PUBLIC( title, "handshake",
                    ret |= mbedtls_ecdh_calc_secret( &ecdh, &olen, buf, opt.bufsize,
                                             myrand, NULL ) );
            mbedtls_ecdh_free( &ecdh );
        }

        /* Curve25519 needs to be handled separately */
#if defined(MBEDTLS_ECP_DP_CURVE25519_ENABLED)
        mbedtls_ecdh_init( &ecdh );
        mbedtls_mpi_init( &z );

        if( mbedtls_ecp_group_load( &ecdh.grp, MBEDTLS_ECP_DP_CURVE25519 ) != 0 ||
            mbedtls_ecdh_gen_public( &ecdh.grp, &ecdh.d, &ecdh.Qp,
                             myrand, NULL ) != 0 ||
            mbedtls_ecdh_gen_public( &ecdh.grp, &ecdh.d, &ecdh.Q, myrand, NULL ) != 0 )
        {
            mbedtls_exit( 1 );
        }

        TIME_PUBLIC(  "ECDH-Curve25519", "handshake",
                ret |= mbedtls_ecdh_compute_shared( &ecdh.grp, &z, &ecdh.Qp, &ecdh.d,
                                            myrand, NULL ) );

        mbedtls_ecdh_free( &ecdh );
        mbedtls_mpi_free( &z );
#endif
    }
#endif

    mbedtls_printf( "\n" );

    /* TODO: Properly free all dynamically allocated memory on failure.
     *       In the benchmarks above, a failure leads to an immediate
     *       mbedtls_exit, not cleaning up dynamic storage used for MPIs,
     *       the work buffer, ... */
    mbedtls_free( buf );

#if defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C)
    mbedtls_memory_buffer_alloc_free();
#endif

#if defined(_WIN32)
    mbedtls_printf( "  Press Enter to exit this program.\n" );
    fflush( stdout ); getchar();
#endif

    return( 0 );
}

#endif /* MBEDTLS_TIMING_C */
