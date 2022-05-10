/*
 *  Multi-precision integer library, core arithmetic
 *
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

#if defined(MBEDTLS_BIGNUM_C)

#include "mbedtls/bignum.h"
#include "bignum_internal.h"
#include "bignum_core.h"
#include "bn_mul.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/error.h"
#include "constant_time_internal.h"

#include <limits.h>
#include <string.h>

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#include <stdlib.h>
#define mbedtls_printf     printf
#define mbedtls_calloc    calloc
#define mbedtls_free       free
#endif

void MPI_CORE(shift_l)( mbedtls_mpi_uint *X, size_t nx, size_t count )
{
    size_t i;
    size_t limb_shift = count / (biL    );
    size_t bit_shift  = count & (biL - 1);

    /*
     * shift by count / limb_size
     */
    if( limb_shift > 0 )
    {
        for( i = nx; i > limb_shift; i-- )
            X[i - 1] = X[i - 1 - limb_shift];
        for( ; i > 0; i-- )
            X[i - 1] = 0;
    }

    /*
     * shift by count % limb_size
     */
    if( bit_shift > 0 )
    {
        mbedtls_mpi_uint shift_out = 0;
        for( i = 0; i < nx; i++ )
        {
            mbedtls_mpi_uint last_shift_out = shift_out;
            shift_out = X[i] >> (biL - bit_shift);
            X[i] <<= bit_shift;
            X[i] |= last_shift_out;
        }
    }
}

unsigned char MPI_CORE(get_bit)( const mbedtls_mpi_uint *X, size_t nx, size_t pos )
{
    if( nx * biL <= pos )
        return( 0 );
    return( ( X[pos / biL] >> ( pos % biL ) ) & 0x01 );
}

void MPI_CORE(set_bit)( mbedtls_mpi_uint *X,
                        size_t pos, unsigned char val )
{
    size_t off = pos / biL;
    size_t idx = pos % biL;
    X[off] &= ~( (mbedtls_mpi_uint) 0x01 << idx );
    X[off] |= (mbedtls_mpi_uint) val << idx;
}

int MPI_CORE(read_binary_be)( mbedtls_mpi_uint *X, size_t nx,
                              const unsigned char *buf, size_t buflen )
{
    unsigned char *Xp = (unsigned char*) X;
    if( nx * ciL < buflen )
        return( MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL );
    const size_t overhead = ( nx * ciL ) - buflen;
    memset( Xp, 0, overhead );
    if( buflen > 0 )
    {
        memcpy( Xp + overhead, buf, buflen );
        MPI_CORE(bigendian_to_host)( X, nx );
    }
    return( 0 );
}

int MPI_CORE(read_binary_le)( mbedtls_mpi_uint *X, size_t nx,
                              const unsigned char *buf, size_t buflen )
{
    if( nx * ciL < buflen )
        return( MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL );
    memset( X, 0, nx * ciL );
    for( size_t i = 0; i < buflen; i++ )
        X[i / ciL] |= ((mbedtls_mpi_uint) buf[i]) << ((i % ciL) << 3);
    return( 0 );
}

static int mpi_check_fits( const mbedtls_mpi_uint *X, size_t nx, size_t bytes )
{
    volatile mbedtls_mpi_uint sum = 0;
    for( size_t i = bytes; i < nx * ciL; i++ )
        sum |= GET_BYTE( X, i );
    if( sum != 0 )
        return( MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL );
    return( 0 );
}

int MPI_CORE(write_binary_le)( const mbedtls_mpi_uint *X, size_t nx,
                               unsigned char *buf, size_t buflen )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t i, bytes_to_copy = nx * ciL;
    MBEDTLS_MPI_CHK( mpi_check_fits( X, nx, buflen ) );

    if( bytes_to_copy > buflen )
        bytes_to_copy = buflen;
    for( i = 0; i < bytes_to_copy; i++ )
        buf[i] = GET_BYTE( X, i );
    for( ; i < buflen; i++ )
        buf[i] = 0;

cleanup:
    return( ret );
}

int MPI_CORE(write_binary_be)( const mbedtls_mpi_uint *X, size_t nx,
                               unsigned char *buf, size_t buflen )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    MBEDTLS_MPI_CHK( MPI_CORE(write_binary_le)( X, nx, buf, buflen ) );
    unsigned char *bottom = buf, *top = buf + buflen - 1;
    for( size_t i=0; i < buflen / 2; i++, bottom++, top-- )
    {
        unsigned char l = *bottom, r = *top;
        *bottom = r; *top = l;
    }
cleanup:
    return( ret );
}


mbedtls_mpi_uint MPI_CORE(sub)( mbedtls_mpi_uint *d,
                                const mbedtls_mpi_uint *l,
                                const mbedtls_mpi_uint *r,
                                size_t n )
{
    mbedtls_mpi_uint c = 0, t, z;

    for( size_t i = 0; i < n; i++ )
    {
        z = ( l[i] <  c );    t = l[i] - c;
        c = ( t < r[i] ) + z; d[i] = t - r[i];
    }

    return( c );
}

mbedtls_mpi_uint MPI_CORE(add)( mbedtls_mpi_uint *d,
                                const mbedtls_mpi_uint *l,
                                const mbedtls_mpi_uint *r,
                                size_t n )
{
    mbedtls_mpi_uint c = 0, t;
    for( size_t i = 0; i < n; i++ )
    {
        t  = c;
        t += l[i]; c  = ( t < l[i] );
        t += r[i]; c += ( t < r[i] );
        d[i] = t;
    }
    return( c );
}

mbedtls_mpi_uint MPI_CORE(add_if)( mbedtls_mpi_uint *d,
                                   const mbedtls_mpi_uint *r,
                                   size_t n,
                                   unsigned cond )
{
    mbedtls_mpi_uint c = 0, t;
    for( size_t i = 0; i < n; i++ )
    {
        mbedtls_mpi_uint add = cond * r[i];
        t  = c;
        t += d[i]; c  = ( t < d[i] );
        t += add;  c += ( t < add  );
        d[i] = t;
    }
    return( c );
}

mbedtls_mpi_uint MPI_CORE(sub_int)( mbedtls_mpi_uint *d,
                                    const mbedtls_mpi_uint *l,
                                    mbedtls_mpi_uint c, size_t n )
{
    for( size_t i = 0; i < n; i++ )
    {
        mbedtls_mpi_uint s, t;
        s = l[i];
        t = s - c; c = ( t > s );
        d[i] = t;
    }

    return( c );
}

mbedtls_mpi_uint MPI_CORE(add_int)( mbedtls_mpi_uint *d,
                                    const mbedtls_mpi_uint *l,
                                    mbedtls_mpi_uint c, size_t n )
{
    mbedtls_mpi_uint t;
    for( size_t i = 0; i < n; i++ )
    {
        t = l[i] + c; c = ( t < c );
        d[i] = t;
    }
    return( c );
}

mbedtls_mpi_uint MPI_CORE(lt)( const mbedtls_mpi_uint *l,
                               const mbedtls_mpi_uint *r,
                               size_t n )
{
    mbedtls_mpi_uint c = 0, t, z;
    for( size_t i = 0; i < n; i++ )
    {
        z = ( l[i] <  c ); t = l[i] - c;
        c = ( t < r[i] ) + z;
    }
    return( c );
}

mbedtls_mpi_uint MPI_CORE(mla)( mbedtls_mpi_uint *d, size_t d_len,
                                const mbedtls_mpi_uint *s, size_t s_len,
                                mbedtls_mpi_uint b )
{
    mbedtls_mpi_uint c = 0; /* carry */
    if( d_len < s_len )
        s_len = d_len;
    size_t excess_len = d_len - s_len;
    size_t steps_x8 = s_len / 8;
    size_t steps_x1 = s_len & 7;

    while( steps_x8-- )
    {
        MULADDC_X8_INIT
        MULADDC_X8_CORE
        MULADDC_X8_STOP
    }

    while( steps_x1-- )
    {
        MULADDC_X1_INIT
        MULADDC_X1_CORE
        MULADDC_X1_STOP
    }

    while( excess_len-- )
    {
        *d += c; c = ( *d < c ); d++;
    }

    return( c );
}

mbedtls_mpi_uint MPI_CORE(mmla)(
           mbedtls_mpi_uint *d, size_t d_len,
           const mbedtls_mpi_uint *s, const mbedtls_mpi_uint *t, size_t st_len,
           mbedtls_mpi_uint b, mbedtls_mpi_uint a )
{
    size_t n6 = st_len / 6, nr = st_len % 6;
    size_t excess_len = d_len - ( st_len + 1 );

    mbedtls_mpi_uint c0, c1;
    mbedtls_mpi_uint d0, d1, d2, d3, d4, d5;
    mbedtls_mpi_uint s0, s1, s2, s3, s4, s5;
    mbedtls_mpi_uint t0, t1, t2, t3, t4, t5;

    c0 = c1 = 0;
    while( n6-- )
    {
        d0 = d[0]; d1 = d[1]; d2 = d[2]; d3 = d[3]; d4 = d[4]; d5 = d[5];
        s0 = s[0]; s1 = s[1]; s2 = s[2]; s3 = s[3]; s4 = s[4]; s5 = s[5];
        MPI_UINT_VMAAL_X6( d0, d1, d2, d3, d4, d5, c0,
                           s0, s1, s2, s3, s4, s5, b );
        t0 = t[0]; t1 = t[1]; t2 = t[2]; t3 = t[3]; t4 = t[4]; t5 = t[5];
        MPI_UINT_VMAAL_X6( d0, d1, d2, d3, d4, d5, c1,
                           t0, t1, t2, t3, t4, t5, a );
        d[0] = d0; d[1] = d1; d[2] = d2; d[3] = d3; d[4] = d4; d[5] = d5;
        s += 6; t += 6; d += 6;
    }

    while( nr-- )
    {
        d0 = *d;
        s0 = *s++;
        MPI_UINT_UMAAL( d0, c0, s0, b );
        t0 = *t++;
        MPI_UINT_UMAAL( d0, c1, t0, a );
        *d++ = d0;
    }

    d0 = *d;
    d0 += c0; c0  = ( d0 < c0 );
    d0 += c1; c0 += ( d0 < c1 );
    *d++ = d0;

    while( excess_len-- )
    {
        d0 = *d;
        d0 += c0; c0 = ( d0 < c0 );
        *d++ = d0;
    }

    return( c0 );
}

mbedtls_mpi_uint MPI_CORE(mmla_x4)(
           mbedtls_mpi_uint *d, size_t d_len,
           const mbedtls_mpi_uint *s, const mbedtls_mpi_uint *t, size_t st_len,
           mbedtls_mpi_uint b, mbedtls_mpi_uint a )
{
    size_t n4 = st_len / 4, nr = st_len % 4;
    size_t excess_len = d_len - ( st_len + 1 );

    mbedtls_mpi_uint c0, c1;
    mbedtls_mpi_uint d0, d1, d2, d3;
    mbedtls_mpi_uint s0, s1, s2, s3;
    mbedtls_mpi_uint t0, t1, t2, t3;

    c0 = c1 = 0;
    while( n4-- )
    {
        d0 = d[0]; d1 = d[1]; d2 = d[2]; d3 = d[3];
        s0 = s[0]; s1 = s[1]; s2 = s[2]; s3 = s[3];
        MPI_UINT_VMAAL_X4( d0, d1, d2, d3, c0,
                           s0, s1, s2, s3, b );
        t0 = t[0]; t1 = t[1]; t2 = t[2]; t3 = t[3];
        MPI_UINT_VMAAL_X4( d0, d1, d2, d3, c1,
                           t0, t1, t2, t3, a );
        d[0] = d0; d[1] = d1; d[2] = d2; d[3] = d3;
        s += 4; t += 4; d += 4;
    }

    while( nr-- )
    {
        d0 = *d;
        s0 = *s++;
        MPI_UINT_UMAAL( d0, c0, s0, b );
        t0 = *t++;
        MPI_UINT_UMAAL( d0, c1, t0, a );
        *d++ = d0;
    }

    d0 = *d;
    d0 += c0; c0  = ( d0 < c0 );
    d0 += c1; c0 += ( d0 < c1 );
    *d++ = d0;

    while( excess_len-- )
    {
        d0 = *d;
        d0 += c0; c0 = ( d0 < c0 );
        *d++ = d0;
    }

    return( c0 );
}



extern void mul_384_384( mbedtls_mpi_uint *, mbedtls_mpi_uint const *, mbedtls_mpi_uint const * );

void MPI_CORE(mul)( mbedtls_mpi_uint *X,
                    const mbedtls_mpi_uint *A, size_t a,
                    const mbedtls_mpi_uint *B, size_t b )
{
    memset( X, 0, ( a + b ) * ciL );
    if( a == 6 && b == 6 )
    {
        mul_384_384( X, A, B );
        return;
    }
    for( size_t i=0; i < b; i++ )
        (void) MPI_CORE(mla)( X + i, a + 1, A, a, B[i] );
}

void MPI_CORE(mul_truncate)( mbedtls_mpi_uint *X, size_t x_len,
                             const mbedtls_mpi_uint *A, size_t a,
                             const mbedtls_mpi_uint *B, size_t b )
{
    memset( X, 0, x_len * ciL );
    if( b > x_len )
        b = x_len;
    for( size_t i=0; i < b; i++ )
        (void) MPI_CORE(mla)( X + i, x_len - i, A, a, B[i] );
}

/*
 * Fast Montgomery initialization (thanks to Tom St Denis)
 */

mbedtls_mpi_uint MPI_CORE(mont_init)( mbedtls_mpi_uint m )
{
    mbedtls_mpi_uint m_inv = m;
    for( int i = biL; i >= 1; i /= 2 )
        m_inv *= ( 2 + ( m * m_inv ) );
    return( m_inv );
}

void MPI_CORE(sint_neg)( mbedtls_mpi_uint *X, size_t x_len )
{
    for( size_t i=0; i < x_len; i++ )
        X[i] = ~X[i];
    (void) MPI_CORE(add_int)( X, X, 1, x_len );
}

int MPI_CORE(mont_init_wide)( mbedtls_mpi_uint *X,
                              mbedtls_mpi_uint const *A, size_t A_len )

{
    int ret = MBEDTLS_ERR_MPI_ALLOC_FAILED;
    mbedtls_mpi_uint *mempool = NULL, *t0, *t1;
    size_t cur_size = 0;
    if( A_len == 0 )
        return( 0 );

    MBEDTLS_MPI_CHK( mbedtls_mpi_core_alloc( &mempool, 2 * A_len ) );
    t0 = mempool;
    t1 = mempool + A_len;

    memset( X, 0, A_len * ciL );
    X[0] = MPI_CORE(mont_init)( A[0] );
    cur_size = 1;

    while( cur_size < A_len )
    {
        /* Double precision in every iteration until reaching target width */
        size_t new_size = 2*cur_size;
        if( new_size > A_len )
            new_size = A_len;
        /* m_inv *= 2 + m * m_inv -- see mont_init for explanation */
        MPI_CORE(mul_truncate)(t0,new_size,A,new_size,X,cur_size);
        MPI_CORE(add_int)(t0,t0,2,new_size);
        MPI_CORE(mul_truncate)(t1,new_size,X,cur_size,t0,new_size);
        memcpy( X, t1, new_size*ciL );
        cur_size = new_size;
    }
    MPI_CORE(sint_neg)(X, A_len);

cleanup:

    mbedtls_free( mempool );
    return( ret );
}

void MPI_CORE(montmul_var)( mbedtls_mpi_uint *X,
                        const mbedtls_mpi_uint *A,
                        const mbedtls_mpi_uint *B,
                        size_t B_len,
                        const mbedtls_mpi_uint *N,
                        size_t n,
                        mbedtls_mpi_uint mm,
                        mbedtls_mpi_uint *T )
{
    memset( T, 0, (2*n+1)*ciL );

    for( size_t i = 0; i < n; i++, T++ )
    {
        mbedtls_mpi_uint u0, u1;
        /* T = (T + u0*B + u1*N) / 2^biL */
        u0 = A[i];
        u1 = ( T[0] + u0 * B[0] ) * mm;

        (void) MPI_CORE(mla)( T, n + 2, B, B_len, u0 );
        (void) MPI_CORE(mla)( T, n + 2, N, n, u1 );
    }

    mbedtls_mpi_uint carry, borrow, fixup;

    carry  = T[n];
    borrow = MPI_CORE(sub)( X, T, N, n );
    fixup  = carry < borrow;
    (void) MPI_CORE(add_if)( X, N, n, fixup );
}

void MPI_CORE(montmul)( mbedtls_mpi_uint *X,
                        const mbedtls_mpi_uint *A,
                        const mbedtls_mpi_uint *B,
                        size_t B_len,
                        const mbedtls_mpi_uint *N,
                        size_t n,
                        mbedtls_mpi_uint mm,
                        mbedtls_mpi_uint *T )
{
    /* Quick hack to insert specialized Montmul for p384r1 */
    if( B_len == 6 && n == 6 )
    {
        montmul_384_384( X, A, B, N, mm );
        return;
    }

    MPI_CORE(montmul_var)( X, A, B, B_len, N, n, mm, T );
}

void MPI_CORE(montmul_d)( mbedtls_mpi_uint *X,
                          const mbedtls_mpi_uint *B,
                          const mbedtls_mpi_uint *N,
                          size_t n,
                          mbedtls_mpi_uint mm,
                          mbedtls_mpi_uint *T )
{
    MPI_CORE(montmul)( X, X, B, n, N, n, mm, T );
}

void MPI_CORE(add_mod)( mbedtls_mpi_uint *X,
                        mbedtls_mpi_uint const *A,
                        mbedtls_mpi_uint const *B,
                        const mbedtls_mpi_uint *N,
                        size_t n )
{
    if( n == 6 )
    {
        addmod_384( X, A, B, N );
        return;
    }
    size_t carry, borrow = 0, fixup;
    carry  = MPI_CORE(add)( X, A, B, n );
    borrow = MPI_CORE(sub)( X, X, N, n );
    fixup  = ( carry < borrow );
    (void) MPI_CORE(add_if)( X, N, n, fixup );
}

void MPI_CORE(add_mod_d)( mbedtls_mpi_uint *X,
                          mbedtls_mpi_uint const *B,
                          const mbedtls_mpi_uint *N,
                          size_t n )
{
    MPI_CORE(add_mod)( X, X, B, N, n );
}

void MPI_CORE(neg_mod)( mbedtls_mpi_uint *X,
                        mbedtls_mpi_uint const *A,
                        const mbedtls_mpi_uint *N,
                        size_t n )
{
    size_t borrow;
    MPI_CORE(sub)( X, N, A, n );
    /* If A=0 initially, then X=N now. Detect this by
     * subtracting N and catching the carry. */
    borrow = MPI_CORE(sub)( X, X, N, n );
    (void) MPI_CORE(add_if)( X, N, n, borrow );
}

void MPI_CORE(sub_mod)( mbedtls_mpi_uint *X,
                        mbedtls_mpi_uint const *A,
                        mbedtls_mpi_uint const *B,
                        const mbedtls_mpi_uint *N,
                        size_t n )
{
    if( n == 6 )
    {
        submod_384( X, A, B, N );
        return;
    }
    size_t borrow = MPI_CORE(sub)( X, A, B, n );
    (void) MPI_CORE(add_if)( X, N, n, borrow );
}

void MPI_CORE(sub_mod_d)( mbedtls_mpi_uint *X,
                          mbedtls_mpi_uint const *B,
                          const mbedtls_mpi_uint *N,
                          size_t n )
{
    MPI_CORE(sub_mod)( X, X, B, N, n );
}

int MPI_CORE(mod_reduce)( mbedtls_mpi_uint *X,
                          mbedtls_mpi_uint const *A, size_t A_len,
                          const mbedtls_mpi_uint *N, size_t n,
                          const mbedtls_mpi_uint *RR )
{
    int ret = MBEDTLS_ERR_MPI_ALLOC_FAILED;
    mbedtls_mpi_uint *mempool, *T, *acc, mm, one=1;

    MBEDTLS_MPI_CHK( mbedtls_mpi_core_alloc( &mempool, n+2*n+1) );
    acc = mempool;
    T   = mempool + n;

    mm = MPI_CORE(mont_init)( *N ); /* Compute Montgomery constant */
    A += A_len; /* Jump to end of A */

    /* The basic idea is the following:
     * With R = 2^{n*biL}, split A w.r.t. radix R as
     * A = A0 + R A1 + R^2 A2 + ... = A0 + R(A1 + R(... R(A(n-1) + R*An))...)
     *
     * And calculate the iteration X |-> Ai + R*X via combination of
     * Montgomery multiplication with R^2 and a modular addition. */

    /* Start with top block of A */
    size_t block_size = A_len % n;
    if( block_size == 0 )
        block_size = n;

    A_len -= block_size;
    A     -= block_size;
    memset( acc, 0, n*ciL );
    memcpy( acc, A, block_size * ciL );

    while( A_len >= n )
    {
        A_len -= n;
        A     -= n;
        /* X |-> R*X mod N via Montgomery multiplication with R^2 */
        MPI_CORE(montmul_d)( acc, RR, N, n, mm, T );
        /* Add current block of A */
        MPI_CORE(add_mod)( acc, acc, A, N, n );
    }

    /* At this point, we have quasi-reduced the input to the same number
     * of limbs as the modulus. We get a canonical representative through
     * two inverse Montomgery multiplications by 1 and R^2.
     *
     * TODO: This can be done more efficiently ... one step of Montgomery
     *       reduction should be enough?
     *
     * TODO: Some call-sites seem to be fine with quasi-reduction --
     *       split this out as a separate function? */
    MPI_CORE(montmul_d)( acc, RR, N, n, mm, T );
    MPI_CORE(montmul)( X, acc, &one, 1, N, n, mm, T );

cleanup:

    mbedtls_free( mempool );
    return( ret );
}

int MPI_CORE(crt_fwd)( mbedtls_mpi_uint *TP, mbedtls_mpi_uint *TQ,
                       const mbedtls_mpi_uint *P, size_t P_len,
                       const mbedtls_mpi_uint *Q, size_t Q_len,
                       const mbedtls_mpi_uint *T, size_t T_len,
                       const mbedtls_mpi_uint *RP,
                       const mbedtls_mpi_uint *RQ )
{
    int ret = MBEDTLS_ERR_MPI_ALLOC_FAILED;
    MBEDTLS_MPI_CHK( MPI_CORE(mod_reduce)( TP, T, T_len, P, P_len, RP ) );
    MBEDTLS_MPI_CHK( MPI_CORE(mod_reduce)( TQ, T, T_len, Q, Q_len, RQ ) );
cleanup:
    return( ret );
}

size_t MPI_CORE(lsb)( mbedtls_mpi_uint const *A, size_t A_len )
{
    size_t count = 0, active = 1;
    mbedtls_mpi_uint first_nonzero = 0;

    for( size_t i = 0; i < A_len; i++ )
    {
        mbedtls_mpi_uint cur = A[i];
        first_nonzero += active * cur;
        active *= ( cur == 0 );
        count += active * biL;
    }

    active = 1;
    for( size_t j = 0; j < biL; j++ )
    {
        unsigned bit = ( first_nonzero >> j ) & 1;
        active *= ( bit == 0 );
        count += active;
    }

    count *= (1 - active);
    return( count );
}

int MPI_CORE(crt_inv)( mbedtls_mpi_uint *T,
                       mbedtls_mpi_uint *TP,
                       mbedtls_mpi_uint *TQ,
                       const mbedtls_mpi_uint *P, size_t P_len,
                       const mbedtls_mpi_uint *Q, size_t Q_len,
                       const mbedtls_mpi_uint *RP,
                       const mbedtls_mpi_uint *QinvP )
{
    int ret = MBEDTLS_ERR_MPI_ALLOC_FAILED;
    mbedtls_mpi_uint *mempool = NULL, *temp, *TQP;
    mbedtls_mpi_uint mmP, carry;
    MBEDTLS_MPI_CHK( mbedtls_mpi_core_alloc( &mempool, P_len + (2*P_len+1)) );
    TQP = mempool;
    temp = TQP + P_len;

    mmP = MPI_CORE(mont_init)( *P );

    /*
     * T = TQ + [(TP - (TQ mod P)) * (Q^-1 mod P) mod P]*Q
     */

    /* Compute (TQ mod P) within T */
    MBEDTLS_MPI_CHK( MPI_CORE(mod_reduce)( TQP, TQ, Q_len, P, P_len, RP ) );
    /* TP - (TQ mod P) */
    MPI_CORE(sub_mod)( TP, TP, TQP, P, P_len );
    /* (TP - (TQ mod P)) * (Q^-1 mod P) mod P */
    MPI_CORE(montmul_d)( TP, QinvP, P, P_len, mmP, temp );
    MPI_CORE(montmul_d)( TP, RP, P, P_len, mmP, temp );
    /* [(TP - (TQ mod P)) * (Q^-1 mod P) mod P]*Q */
    MPI_CORE(mul)( T, TP, P_len, Q, Q_len );
    /* Final result */
    carry = MPI_CORE(add)( T, T, TQ, Q_len );
    MPI_CORE(add_int)( T + Q_len, T + Q_len, carry, P_len );

cleanup:
    mbedtls_free( mempool );
    return( ret );
}

__attribute__((noinline))
int MPI_CORE(inv_mod_prime)( mbedtls_mpi_uint *X,
                             mbedtls_mpi_uint const *A,
                             const mbedtls_mpi_uint *P,
                             size_t n,
                             mbedtls_mpi_uint *RR )
{
    int ret = MBEDTLS_ERR_MPI_ALLOC_FAILED;
    mbedtls_mpi_uint *P2;
    MBEDTLS_MPI_CHK( mbedtls_mpi_core_alloc( &P2, n ) );

    /* |F_p^x| - 1 = p - 2 */
    (void) MPI_CORE(sub_int)( P2, P, 2, n );
    /* Inversion by power: g^|G| = 1 <=> g^{-1} = g^{|G|-1} */
    MBEDTLS_MPI_CHK( MPI_CORE(mod_reduce)( X, A, n, P, n, RR ) );
    MBEDTLS_MPI_CHK( MPI_CORE(exp_mod_pubexp)( X, A, P, n, P2, n, RR ) );

cleanup:

    mbedtls_free( P2 );
    return( ret );
}

/*
 * Sliding-window exponentiation: X = A^E mod N  (HAC 14.85)
 */

static size_t mpi_exp_mod_get_window_size( size_t Ebits )
{
    size_t wsize = ( Ebits > 671 ) ? 6 : ( Ebits > 239 ) ? 5 :
                   ( Ebits >  79 ) ? 4 : ( Ebits >  23 ) ? 3 : 1;

#if( MBEDTLS_MPI_WINDOW_SIZE < 6 )
    if( wsize > MBEDTLS_MPI_WINDOW_SIZE )
        wsize = MBEDTLS_MPI_WINDOW_SIZE;
#endif

    return( wsize );
}

int MPI_CORE(exp_mod)( mbedtls_mpi_uint *X,
                       mbedtls_mpi_uint const *A,
                       const mbedtls_mpi_uint *N,
                       size_t n,
                       const mbedtls_mpi_uint *E,
                       size_t E_len,
                       const mbedtls_mpi_uint *RR )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    /* heap allocated memory pool */
    mbedtls_mpi_uint *mempool = NULL;
    /* pointers to temporaries within memory pool */
    mbedtls_mpi_uint *Wtbl, *Wselect, *temp;
    /* pointers to table entries */
    mbedtls_mpi_uint *Wcur, *Wlast, *W1;

    size_t wsize, welem;
    mbedtls_mpi_uint one = 1, mm;

    mm = MPI_CORE(mont_init)( *N ); /* Compute Montgomery constant */
    E += E_len;               /* Skip to end of exponent buffer */

    wsize = mpi_exp_mod_get_window_size( E_len * biL );
    welem = 1 << wsize;

    /* Allocate memory pool and set pointers to parts of it */
    const size_t table_limbs   = welem * n;
    const size_t temp_limbs    = 2 * n + 1;
    const size_t wselect_limbs = n;
    const size_t total_limbs   = table_limbs + temp_limbs + wselect_limbs;
    MBEDTLS_MPI_CHK( mbedtls_mpi_core_alloc( &mempool, total_limbs ) );
    Wtbl    = mempool;
    Wselect = Wtbl    + table_limbs;
    temp    = Wselect + wselect_limbs;

    /*
     * Window precomputation
     */

    /* W[0] = 1 (in Montgomery presentation) */
    memset( Wtbl, 0, n * ciL ); Wtbl[0] = 1;
    MPI_CORE(montmul_d)( Wtbl, RR, N, n, mm, temp );
    Wcur = Wtbl + n;
    /* W[1] = A * R^2 * R^-1 mod N = A * R mod N */
    memcpy( Wcur, A, n * ciL );
    MPI_CORE(montmul_d)( Wcur, RR, N, n, mm, temp );
    W1 = Wcur;
    Wcur += n;
    /* W[i+1] = W[i] * W[1], i >= 2 */
    Wlast = W1;
    for( size_t i=2; i < welem; i++, Wlast += n, Wcur += n )
        MPI_CORE(montmul)( Wcur, Wlast, W1, n, N, n, mm, temp );

    /*
     * Sliding window exponentiation
     */

    /* X = 1 (in Montgomery presentation) initially */
    memcpy( X, Wtbl, n * ciL );

    size_t limb_bits_remaining = 0;
    mbedtls_mpi_uint window = 0;
    size_t window_bits = 0, cur_limb;
    while( 1 )
    {
        size_t window_bits_missing = wsize - window_bits;

        const int no_more_bits =
            ( limb_bits_remaining == 0 ) && ( E_len == 0 );
        const int window_full =
            ( window_bits_missing == 0 );

        /* Clear window if it's full or if we don't have further bits. */
        if( window_full || no_more_bits )
        {
            if( window_bits == 0 )
                break;
            /* Select table entry, square and multiply */
            mbedtls_ct_table_lookup( (unsigned char*) Wselect,
                                     (unsigned char*) Wtbl,
                                     n * ciL, welem, window );
            MPI_CORE(montmul_d)( X, Wselect, N, n, mm, temp );
            window = window_bits = 0;
            continue;
        }

        /* Load next exponent limb if necessary */
        if( limb_bits_remaining == 0 )
        {
            cur_limb = *--E;
            E_len--;
            limb_bits_remaining = biL;
        }

        /* Square */
        MPI_CORE(montmul_d)( X, X, N, n, mm, temp );

        /* Insert next exponent bit into window */
        window   <<= 1;
        window    |= ( cur_limb >> ( biL - 1 ) );
        cur_limb <<= 1;
        window_bits++;
        limb_bits_remaining--;
    }

    /* Convert X back to normal presentation */
    MPI_CORE(montmul)( X, X, &one, 1, N, n, mm, temp );

    ret = 0;

cleanup:

    mbedtls_free( mempool );
    return( ret );
}

int MPI_CORE(exp_mod_pubexp)( mbedtls_mpi_uint *X,
                              mbedtls_mpi_uint const *A,
                              const mbedtls_mpi_uint *N,
                              size_t n,
                              const mbedtls_mpi_uint *E,
                              size_t E_len,
                              const mbedtls_mpi_uint *RR )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    /* heap allocated memory pool */
    mbedtls_mpi_uint *mempool = NULL;
    /* pointers to temporaries within memory pool */
    mbedtls_mpi_uint *Wtbl, *Wselect, *temp;
    /* pointers to table entries */
    mbedtls_mpi_uint *Wcur, *Wlast, *W1;

    size_t wsize, welem;
    mbedtls_mpi_uint one = 1, mm;

    mm = MPI_CORE(mont_init)( *N ); /* Compute Montgomery constant */
    E += E_len;               /* Skip to end of exponent buffer */

    wsize = mpi_exp_mod_get_window_size( E_len * biL );
    welem = 1 << wsize;

    /* Allocate memory pool and set pointers to parts of it */
    const size_t table_limbs   = welem * n;
    const size_t temp_limbs    = 2 * n + 1;
    const size_t total_limbs   = table_limbs + temp_limbs;
    MBEDTLS_MPI_CHK( mbedtls_mpi_core_alloc( &mempool, total_limbs ) );
    Wtbl    = mempool;
    temp    = Wtbl + table_limbs;

    /*
     * Window precomputation
     */

    /* W[0] = 1 (in Montgomery presentation) */
    memset( Wtbl, 0, n * ciL ); Wtbl[0] = 1;
    MPI_CORE(montmul_d)( Wtbl, RR, N, n, mm, temp );
    Wcur = Wtbl + n;
    /* W[1] = A * R^2 * R^-1 mod N = A * R mod N */
    memcpy( Wcur, A, n * ciL );
    MPI_CORE(montmul_d)( Wcur, RR, N, n, mm, temp );
    W1 = Wcur;
    Wcur += n;
    /* W[i+1] = W[i] * W[1], i >= 2 */
    Wlast = W1;
    for( size_t i=2; i < welem; i++, Wlast += n, Wcur += n )
        MPI_CORE(montmul)( Wcur, Wlast, W1, n, N, n, mm, temp );

    /*
     * Sliding window exponentiation
     */

    /* X = 1 (in Montgomery presentation) initially */
    memcpy( X, Wtbl, n * ciL );

    size_t limb_bits_remaining = 0;
    mbedtls_mpi_uint window = 0;
    size_t window_bits = 0, cur_limb;
    while( 1 )
    {
        size_t window_bits_missing = wsize - window_bits;

        const int no_more_bits =
            ( limb_bits_remaining == 0 ) && ( E_len == 0 );
        const int window_full =
            ( window_bits_missing == 0 );

        /* Clear window if it's full or if we don't have further bits. */
        if( window_full || no_more_bits )
        {
            if( window_bits == 0 )
                break;
            Wselect = Wtbl + window * n;
            MPI_CORE(montmul_d)( X, Wselect, N, n, mm, temp );
            window = window_bits = 0;
            continue;
        }

        /* Load next exponent limb if necessary */
        if( limb_bits_remaining == 0 )
        {
            cur_limb = *--E;
            E_len--;
            limb_bits_remaining = biL;
        }

        /* Square */
        MPI_CORE(montmul_d)( X, X, N, n, mm, temp );

        /* Insert next exponent bit into window */
        window   <<= 1;
        window    |= ( cur_limb >> ( biL - 1 ) );
        cur_limb <<= 1;
        window_bits++;
        limb_bits_remaining--;
    }

    /* Convert X back to normal presentation */
    MPI_CORE(montmul)( X, X, &one, 1, N, n, mm, temp );

    ret = 0;

cleanup:

    mbedtls_free( mempool );
    return( ret );
}

void MPI_CORE(inv_mod_p384r1_mont)( mbedtls_mpi_uint *X,
                                    mbedtls_mpi_uint const *A,
                                    const mbedtls_mpi_uint *N,
                                    size_t n )
{
    mbedtls_mpi_uint tmp[9][6];
    mbedtls_mpi_uint mm;
    mm = MPI_CORE(mont_init)( *N );

    montmul_p384( tmp[0], A,      A,      N, mm );
    montmul_p384( tmp[0], tmp[0], A,      N, mm );     /* 2^2 - 1   */
    montmul_p384( tmp[1], tmp[0], A,      N, mm );
    montmul_p384( tmp[1], tmp[1], A,      N, mm );     /* 2^3 - 1   */
    montmul_p384( tmp[2], tmp[1], tmp[1], N, mm );
    montmul_p384( tmp[2], tmp[2], tmp[2], N, mm );
    montmul_p384( tmp[2], tmp[2], tmp[2], N, mm );
    montmul_p384( tmp[2], tmp[2], tmp[1], N, mm );     /* 2^6 - 1   */
    montmul_p384( tmp[3], tmp[2], tmp[2], N, mm );
    for( size_t cnt=1; cnt < 6; cnt++ )
        montmul_p384( tmp[3], tmp[3], tmp[3], N, mm );
    montmul_p384( tmp[3], tmp[3], tmp[2], N, mm );     /* 2^12 - 1  */
    montmul_p384( tmp[4], tmp[3], tmp[3], N, mm );
    for( size_t cnt=1; cnt < 3; cnt++ )
        montmul_p384( tmp[4], tmp[4], tmp[4], N, mm );
    montmul_p384( tmp[4], tmp[4], tmp[1], N, mm );     /* 2^15 - 1  */
    montmul_p384( tmp[5], tmp[4], tmp[4], N, mm );
    for( size_t cnt=1; cnt < 15; cnt++ )
        montmul_p384( tmp[5], tmp[5], tmp[5], N, mm );
    montmul_p384( tmp[5], tmp[5], tmp[4], N, mm );     /* 2^30 - 1  */
    montmul_p384( tmp[6], tmp[5], tmp[5], N, mm );
    for( size_t cnt=1; cnt < 30; cnt++ )
        montmul_p384( tmp[6], tmp[6], tmp[6], N, mm );
    montmul_p384( tmp[6], tmp[6], tmp[5], N, mm );     /* 2^60 - 1  */
    montmul_p384( tmp[7], tmp[6], tmp[6], N, mm );
    for( size_t cnt=1; cnt < 60; cnt++ )
        montmul_p384( tmp[7], tmp[7], tmp[7], N, mm );
    montmul_p384( tmp[7], tmp[7], tmp[6], N, mm );     /* 2^120 - 1 */
    montmul_p384( tmp[8], tmp[7], tmp[7], N, mm );
    for( size_t cnt=1; cnt < 120; cnt++ )
        montmul_p384( tmp[8], tmp[8], tmp[8], N, mm );
    montmul_p384( tmp[8], tmp[8], tmp[7], N, mm );     /* 2^240 - 1 */
    for( size_t cnt=0; cnt < 15; cnt++ )
        montmul_p384( tmp[8], tmp[8], tmp[8], N, mm ); /* 2^255 - 2^15 */
    montmul_p384( tmp[8], tmp[8], tmp[4], N, mm );     /* 2^255 - 1    */
    for( size_t cnt=0; cnt < 31; cnt++ )
        montmul_p384( tmp[8], tmp[8], tmp[8], N, mm ); /* 2^286 - 2^31             */
    montmul_p384( tmp[8], tmp[8], tmp[5], N, mm );     /* 2^286 - 2^31 + 2^30 - 1  */
                                                       /* 2^286 - 2^30 - 1         */
    montmul_p384( tmp[8], tmp[8], tmp[8], N, mm );
    montmul_p384( tmp[8], tmp[8], tmp[8], N, mm );     /* 2^288 - 2^32 - 2^2       */
    montmul_p384( tmp[8], tmp[8], tmp[0], N, mm );     /* 2^286 - 2^32 - 1         */
    for( size_t cnt=0; cnt < 94; cnt++ )
        montmul_p384( tmp[8], tmp[8], tmp[8], N, mm ); /* 2^382 - 2^126 - 2^94            */
    montmul_p384( tmp[8], tmp[8], tmp[5], N, mm );     /* 2^384 - 2^126 - 2^94 + 2^30 - 1 */
    montmul_p384( tmp[8], tmp[8], tmp[8], N, mm );
    montmul_p384( tmp[8], tmp[8], tmp[8], N, mm );     /* 2^384 - 2^128 - 2^96 + 2^32 - 4 */
    montmul_p384( tmp[8], tmp[8], A,      N, mm );     /* 2^384 - 2^128 - 2^96 + 2^32 - 3 */

    memcpy( X, tmp[8], n * ciL );
    mbedtls_platform_zeroize( tmp, sizeof( tmp ) );
}


void MPI_CORE(get_montgomery_constant_safe)( mbedtls_mpi_uint *RR,
                                             mbedtls_mpi_uint const *N,
                                             size_t n )
{
    /* Start with 2^0=1 */
    memset( RR, 0, n * ciL );
    RR[0] = 1;

    /* Repated doubling and modular reduction -- very slow, but compared
     * to an RSA private key operation it seems acceptable. */
    for( size_t i=0; i < 2*n*biL; i++ )
        MPI_CORE(add_mod)( RR, RR, RR, N, n );
}

/* Convert a big-endian byte array aligned to the size of mbedtls_mpi_uint
 * into the storage form used by mbedtls_mpi. */

static mbedtls_mpi_uint mpi_uint_bigendian_to_host_c( mbedtls_mpi_uint x )
{
    uint8_t i;
    unsigned char *x_ptr;
    mbedtls_mpi_uint tmp = 0;

    for( i = 0, x_ptr = (unsigned char*) &x; i < ciL; i++, x_ptr++ )
    {
        tmp <<= CHAR_BIT;
        tmp |= (mbedtls_mpi_uint) *x_ptr;
    }

    return( tmp );
}

mbedtls_mpi_uint mbedtls_mpi_core_uint_bigendian_to_host( mbedtls_mpi_uint x )
{
#if defined(__BYTE_ORDER__)

/* Nothing to do on bigendian systems. */
#if ( __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__ )
    return( x );
#endif /* __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__ */

#if ( __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__ )

/* For GCC and Clang, have builtins for byte swapping. */
#if defined(__GNUC__) && defined(__GNUC_PREREQ)
#if __GNUC_PREREQ(4,3)
#define have_bswap
#endif
#endif

#if defined(__clang__) && defined(__has_builtin)
#if __has_builtin(__builtin_bswap32)  &&                 \
    __has_builtin(__builtin_bswap64)
#define have_bswap
#endif
#endif

#if defined(have_bswap)
    /* The compiler is hopefully able to statically evaluate this! */
    switch( sizeof(mbedtls_mpi_uint) )
    {
        case 4:
            return( __builtin_bswap32(x) );
        case 8:
            return( __builtin_bswap64(x) );
    }
#endif
#endif /* __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__ */
#endif /* __BYTE_ORDER__ */

    /* Fall back to C-based reordering if we don't know the byte order
     * or we couldn't use a compiler-specific builtin. */
    return( mpi_uint_bigendian_to_host_c( x ) );
}

void MPI_CORE(bigendian_to_host)( mbedtls_mpi_uint *X, size_t nx )
{
    mbedtls_mpi_uint *cur_limb_left;
    mbedtls_mpi_uint *cur_limb_right;
    if( nx == 0 )
        return;

    /*
     * Traverse limbs and
     * - adapt byte-order in each limb
     * - swap the limbs themselves.
     * For that, simultaneously traverse the limbs from left to right
     * and from right to left, as long as the left index is not bigger
     * than the right index (it's not a problem if limbs is odd and the
     * indices coincide in the last iteration).
     */
    for( cur_limb_left = X, cur_limb_right = X + ( nx - 1 );
         cur_limb_left <= cur_limb_right;
         cur_limb_left++, cur_limb_right-- )
    {
        mbedtls_mpi_uint tmp;
        /* Note that if cur_limb_left == cur_limb_right,
         * this code effectively swaps the bytes only once. */
        tmp             = mbedtls_mpi_core_uint_bigendian_to_host( *cur_limb_left  );
        *cur_limb_left  = mbedtls_mpi_core_uint_bigendian_to_host( *cur_limb_right );
        *cur_limb_right = tmp;
    }
}

int MPI_CORE(random_be)( mbedtls_mpi_uint *X, size_t nx,
                         size_t n_bytes,
                         int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    const size_t overhead = ( nx * ciL ) - n_bytes;
    memset( X, 0, overhead );
    MBEDTLS_MPI_CHK( f_rng( p_rng, (unsigned char*) X + overhead, n_bytes ) );
    MPI_CORE(bigendian_to_host)( X, nx );
cleanup:
    return( ret );
}

void MPI_CORE(shift_r)( mbedtls_mpi_uint *X, size_t nx, size_t count )
{
    size_t i;
    size_t v0 = count /  biL;
    size_t v1 = count & (biL - 1);

    if( v0 >= nx )
        v0 = nx;

    /*
     * shift by count / limb_size
     */
    if( v0 > 0 )
    {
        for( i = 0; i < nx - v0; i++ )
            X[i] = X[i + v0];
        for( ; i < nx; i++ )
            X[i] = 0;
    }

    /*
     * shift by count % limb_size
     */
    if( v1 > 0 )
    {
        mbedtls_mpi_uint r0 = 0,r1;
        for( i = nx; i > 0; i-- )
        {
            r1 = X[i - 1] << (biL - v1);
            X[i - 1] >>= v1;
            X[i - 1] |= r0;
            r0 = r1;
        }
    }
}

int MPI_CORE(random_range_be)( mbedtls_mpi_uint *X,
                               mbedtls_mpi_uint lower_bound_uint,
                               mbedtls_mpi_uint *upper_bound,
                               size_t n,
                               size_t n_bits,
                               int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned lt_lower, lt_upper;
    mbedtls_mpi_uint *lower_bound = NULL;
    size_t n_bytes = ( n_bits + 7 ) / 8;
    size_t count   = ( n_bytes > 4 ? 30 : 250 );
    MBEDTLS_MPI_CHK( mbedtls_mpi_core_alloc( &lower_bound, n ) );
    lower_bound[0] = lower_bound_uint;
    do
    {
        MBEDTLS_MPI_CHK( MPI_CORE(random_be)( X, n, n_bytes, f_rng, p_rng ) );
        MPI_CORE(shift_r)( X, n, 8 * n_bytes - n_bits );

        if( --count == 0 )
        {
            ret = MBEDTLS_ERR_MPI_NOT_ACCEPTABLE;
            goto cleanup;
        }

        lt_lower = MPI_CORE(lt)( X, lower_bound, n );
        lt_upper = MPI_CORE(lt)( X, upper_bound, n );
    }
    while( lt_lower != 0 || lt_upper == 0 );

cleanup:
    mbedtls_free( lower_bound );
    return( ret );
}

/*************************************************************************
 *
 * Trivial wrappers around always-inline variants,
 * taking all arguments by reference.
 *
 ************************************************************************/

int mbedtls_mpi_core_add_p( mbedtls_mpi_buf const *d, mbedtls_mpi_buf const *l,
                            mbedtls_mpi_buf const *r, mbedtls_mpi_uint *carry )
{
    return( mbedtls_mpi_core_add( *d, *l, *r, carry ) );
}

int mbedtls_mpi_core_add_int_p( mbedtls_mpi_buf const *d, mbedtls_mpi_buf const *l,
                                mbedtls_mpi_uint *c, mbedtls_mpi_uint *carry )
{
    return( mbedtls_mpi_core_add_int( *d, *l, *c, carry ) );
}

int mbedtls_mpi_core_sub_p( mbedtls_mpi_buf const *d, mbedtls_mpi_buf const *l,
                            mbedtls_mpi_buf const *r, mbedtls_mpi_uint *borrow )
{
    return( mbedtls_mpi_core_sub( *d, *l, *r, borrow ) );
}

int mbedtls_mpi_core_sub_int_p( mbedtls_mpi_buf const *d, mbedtls_mpi_buf const *l,
                                mbedtls_mpi_uint c, mbedtls_mpi_uint *borrow )
{
    return( mbedtls_mpi_core_sub_int( *d, *l, c, borrow ) );
}

int mbedtls_mpi_core_mla_p( mbedtls_mpi_buf const *d, mbedtls_mpi_buf const *s,
                            mbedtls_mpi_uint b, mbedtls_mpi_uint *carry )
{
    return( mbedtls_mpi_core_mla( *d, *s, b, carry ) );
}

int mbedtls_mpi_core_mul_p( mbedtls_mpi_buf const *x, mbedtls_mpi_buf const *a, mbedtls_mpi_buf const *b )
{
    return( mbedtls_mpi_core_mul( *x, *a, *b ) );
}

int mbedtls_mpi_core_montmul_p( mbedtls_mpi_buf const *x,
                                mbedtls_mpi_buf const *a, mbedtls_mpi_buf const *n,
                                mbedtls_mpi_buf const *b, mbedtls_mpi_buf const *t,
                                mbedtls_mpi_uint mm )
{
    return( mbedtls_mpi_core_montmul( *x, *a, *n, *b, *t, mm ) );
}

int mbedtls_mpi_core_copy_p( mbedtls_mpi_buf const *a, mbedtls_mpi_buf const *b )
{
    return( mbedtls_mpi_core_copy( *a, *b ) );
}

int mbedtls_mpi_core_get_montgomery_constant_safe_p( mbedtls_mpi_buf const *rr,
                                                     mbedtls_mpi_buf const *n )
{
    return( mbedtls_mpi_core_get_montgomery_constant_safe( *rr, *n ) );
}

int mbedtls_mpi_core_exp_mod_p( mbedtls_mpi_buf const *x, mbedtls_mpi_buf const *a,
                                mbedtls_mpi_buf const *n, mbedtls_mpi_buf const *e,
                                mbedtls_mpi_buf const *rr )
{
    return( mbedtls_mpi_core_exp_mod( *x, *a, *n, *e, *rr ) );
}

int mbedtls_mpi_core_mod_reduce_p( mbedtls_mpi_buf const *x, mbedtls_mpi_buf const *a,
                                   mbedtls_mpi_buf const *n, mbedtls_mpi_buf const *rr )
{
    return( mbedtls_mpi_core_mod_reduce( *x, *a, *n, *rr ) );
}

int mbedtls_mpi_core_crt_fwd_p( mbedtls_mpi_buf const *tp,
                                mbedtls_mpi_buf const *tq,
                                mbedtls_mpi_buf const *p,
                                mbedtls_mpi_buf const *q,
                                mbedtls_mpi_buf const *t,
                                mbedtls_mpi_buf const *rp,
                                mbedtls_mpi_buf const *rq )
{
    return( mbedtls_mpi_core_crt_fwd( *tp, *tq, *p, *q, *t, *rp, *rq ) );
}

int mbedtls_mpi_core_crt_inv_p( mbedtls_mpi_buf const *t,
                                mbedtls_mpi_buf const *tp,
                                mbedtls_mpi_buf const *tq,
                                mbedtls_mpi_buf const *p,
                                mbedtls_mpi_buf const *q,
                                mbedtls_mpi_buf const *rp,
                                mbedtls_mpi_buf const *qinvp )
{
    return( mbedtls_mpi_core_crt_inv( *t, *tp, *tq, *p, *q, *rp, *qinvp ) );
}

int mbedtls_mpi_core_lt_p( mbedtls_mpi_buf const *l, mbedtls_mpi_buf const *r, unsigned *lt )
{
    return( mbedtls_mpi_core_lt( *l, *r, lt ) );
}

int mbedtls_mpi_core_cmp_p( mbedtls_mpi_buf const *a, mbedtls_mpi_buf const *b,
                            int *result )
{
    return( mbedtls_mpi_core_cmp( *a, *b, result ) );
}

int mbedtls_mpi_core_add_mod_p( mbedtls_mpi_buf const *x, mbedtls_mpi_buf const *a,
                                mbedtls_mpi_buf const *b, mbedtls_mpi_buf const *n )
{
    return( mbedtls_mpi_core_add_mod( *x, *a, *b, *n ) );
}

int mbedtls_mpi_core_add_mod_d_p( mbedtls_mpi_buf const *x,
                                  mbedtls_mpi_buf const *b, mbedtls_mpi_buf const *n )
{
    return( mbedtls_mpi_core_add_mod_p( x, x, b, n ) );
}

int mbedtls_mpi_core_neg_mod_p( mbedtls_mpi_buf const *x, mbedtls_mpi_buf const *a,
                                mbedtls_mpi_buf const *n )
{
    return( mbedtls_mpi_core_neg_mod( *x, *a, *n ) );
}

int mbedtls_mpi_core_sub_mod_p( mbedtls_mpi_buf const *x, mbedtls_mpi_buf const *a,
                                mbedtls_mpi_buf const *b, mbedtls_mpi_buf const *n )
{
    return( mbedtls_mpi_core_sub_mod( *x, *a, *b, *n ) );
}

int mbedtls_mpi_core_sub_mod_d_p( mbedtls_mpi_buf const *x,
                                  mbedtls_mpi_buf const *b, mbedtls_mpi_buf const *n )
{
    return( mbedtls_mpi_core_sub_mod_p( x, x, b, n ) );
}

int mbedtls_mpi_core_inv_mod_prime_p( mbedtls_mpi_buf const *x,
                                      mbedtls_mpi_buf const *a,
                                      mbedtls_mpi_buf const *p,
                                      mbedtls_mpi_buf const *rr )
{
    return( mbedtls_mpi_core_inv_mod_prime( *x, *a, *p, *rr ) );
}

int mbedtls_mpi_core_bigendian_to_host_p( mbedtls_mpi_buf const *p )
{
    return( mbedtls_mpi_core_bigendian_to_host( *p ) );
}

int mbedtls_mpi_core_write_binary_be_p( mbedtls_mpi_buf const *x,
                                     unsigned char *buf, size_t buflen )
{
    return( mbedtls_mpi_core_write_binary_be( *x, buf, buflen ) );
}

int mbedtls_mpi_core_random_be_p( mbedtls_mpi_buf const *x, size_t n_bytes,
                                  int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
    return( mbedtls_mpi_core_random_be( *x, n_bytes, f_rng, p_rng ) );
}

int mbedtls_mpi_core_random_range_be_p( mbedtls_mpi_buf const *x,
                                        mbedtls_mpi_uint lower_bound,
                                        mbedtls_mpi_buf const *upper_bound,
                                        size_t n_bits,
                                        int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
    return( mbedtls_mpi_core_random_range_be( *x, lower_bound, *upper_bound, n_bits,
                                              f_rng, p_rng ) );
}

int mbedtls_mpi_core_shift_r_p( mbedtls_mpi_buf const *x, size_t count )
{
    return( mbedtls_mpi_core_shift_r( *x, count ) );
}

void mbedtls_mpi_core_zero_p( mbedtls_mpi_buf const *x )
{
    memset( x->p, 0, x->n * ciL );
}

#endif /* MBEDTLS_BIGNUM_C */
