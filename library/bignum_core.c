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

void MPI_CORE(mul)( mbedtls_mpi_uint *X,
                    const mbedtls_mpi_uint *A, size_t a,
                    const mbedtls_mpi_uint *B, size_t b )
{
    memset( X, 0, ( a + b ) * ciL );
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

void MPI_CORE(montmul)( mbedtls_mpi_uint *X,
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

void MPI_CORE(montmul_d)( mbedtls_mpi_uint *X,
                          const mbedtls_mpi_uint *B,
                          const mbedtls_mpi_uint *N,
                          size_t n,
                          mbedtls_mpi_uint mm,
                          mbedtls_mpi_uint *T )
{
    MPI_CORE(montmul)( X, X, B, n, N, n, mm, T );
}

void MPI_CORE(mod_reduce_single)( mbedtls_mpi_uint *X,
                                  const mbedtls_mpi_uint *N,
                                  size_t n )
{
    size_t fixup;
    fixup = MPI_CORE(sub)( X, X, N, n );
    (void) MPI_CORE(add_if)( X, N, n, fixup );
}

void MPI_CORE(add_mod)( mbedtls_mpi_uint *X,
                        mbedtls_mpi_uint const *A,
                        mbedtls_mpi_uint const *B,
                        const mbedtls_mpi_uint *N,
                        size_t n )
{
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
    MBEDTLS_MPI_CHK( MPI_CORE(exp_mod)( X, A, P, n, P2, n, RR ) );

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
            mbedtls_ct_uint_table_lookup( Wselect, Wtbl,
                                          n, welem, window );
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
 * Trivial wrappers with some length checks
 *
 ************************************************************************/

int mbedtls_mpi_core_is_zero( mbedtls_mpi_buf const *x )
{
    size_t len = x->n;
    volatile mbedtls_mpi_uint total = 0;
    while( len-- )
        total |= x->p[len];
    return( total == 0 );
}

int mbedtls_mpi_core_add( mbedtls_mpi_buf const *d, mbedtls_mpi_buf const *l, mbedtls_mpi_buf const *r,
                          mbedtls_mpi_uint *carry )
{
    mbedtls_mpi_uint res;
    BIGNUM_CORE_CHECK( d->n == l->n && l->n == r->n );

    res = MPI_CORE(add)( d->p, l->p, r->p, d->n );
    if( carry != NULL )
        *carry = res;
    return( 0 );
}

int mbedtls_mpi_core_add_int( mbedtls_mpi_buf const *d, mbedtls_mpi_buf const *l,
                              mbedtls_mpi_uint c, mbedtls_mpi_uint *carry )
{
    mbedtls_mpi_uint res;
    BIGNUM_CORE_CHECK( d->n == l->n );

    res = MPI_CORE(add_int)( d->p, l->p, c, d->n );
    if( carry != NULL )
        *carry = res;
    return( 0 );
}

int mbedtls_mpi_core_sub( mbedtls_mpi_buf const *d, mbedtls_mpi_buf const *l,
                          mbedtls_mpi_buf const *r, mbedtls_mpi_uint *borrow )
{
    mbedtls_mpi_uint res;
    BIGNUM_CORE_CHECK( d->n == l->n && l->n == r->n );

    res = MPI_CORE(sub)( d->p, l->p, r->p, r->n );
    if( borrow != NULL )
        *borrow = res;
    return( 0 );
}

int mbedtls_mpi_core_sub_int( mbedtls_mpi_buf const *d, mbedtls_mpi_buf const *l,
                              mbedtls_mpi_uint c, mbedtls_mpi_uint *borrow )
{
    mbedtls_mpi_uint res;
    BIGNUM_CORE_CHECK( d->n == l->n );
    res = MPI_CORE(sub_int)( d->p, l->p, c, d->n );
    if( borrow != NULL )
        *borrow = res;
    return( 0 );
}

int mbedtls_mpi_core_mla( mbedtls_mpi_buf const *d, mbedtls_mpi_buf const *s,
                          mbedtls_mpi_uint b, mbedtls_mpi_uint *carry )
{
    mbedtls_mpi_uint res;
    res = MPI_CORE(mla)( d->p, d->n, s->p, s->n, b );
    if( carry != NULL )
        *carry = res;
    return( 0 );
}

int mbedtls_mpi_core_mul( mbedtls_mpi_buf const *x, mbedtls_mpi_buf const *a, mbedtls_mpi_buf const *b )
{
    BIGNUM_CORE_CHECK( x->n == a->n + b->n );
    MPI_CORE(mul)( x->p, a->p, a->n, b->p, b->n );
    return( 0 );
}

int mbedtls_mpi_core_mont_init( mbedtls_mpi_uint *m_inv,
                                mbedtls_mpi_uint m )
{
    BIGNUM_CORE_CHECK( m_inv != NULL );
    *m_inv = MPI_CORE(mont_init)( m );
    return( 0 );
}

int mbedtls_mpi_core_montmul( mbedtls_mpi_buf const *x,
                              mbedtls_mpi_buf const *a,
                              mbedtls_mpi_buf const *b,
                              mbedtls_mpi_buf const *n,
                              mbedtls_mpi_buf const *t,
                              mbedtls_mpi_uint mm )
{
    BIGNUM_CORE_CHECK( x->n == n->n &&
                       a->n == n->n &&
                       b->n <= n->n &&
                       t->n == 2*n->n + 1 );
    MPI_CORE(montmul)( x->p, a->p, b->p, b->n, n->p, n->n, mm, t->p );
    return( 0 );
}

int mbedtls_mpi_core_montmul_d( mbedtls_mpi_buf const *x,
                                mbedtls_mpi_buf const *b,
                                mbedtls_mpi_buf const *n,
                                mbedtls_mpi_buf const *t,
                                mbedtls_mpi_uint mm )
{
    BIGNUM_CORE_CHECK( x->n == n->n &&
                       b->n == n->n &&
                       t->n == 2*n->n + 1 );
    MPI_CORE(montmul_d)( x->p, b->p, n->p, n->n, mm, t->p );
    return( 0 );
}

int mbedtls_mpi_core_copy( mbedtls_mpi_buf const *a, mbedtls_mpi_buf const *b )
{
    BIGNUM_CORE_CHECK( a->n == b->n );
    memcpy( a->p, b->p, a->n * ciL );
    return( 0 );
}

int mbedtls_mpi_core_get_montgomery_constant_safe( mbedtls_mpi_buf const *rr,
                                                   mbedtls_mpi_buf const *n )
{
    BIGNUM_CORE_CHECK( rr->n == n->n );
    MPI_CORE(get_montgomery_constant_safe)( rr->p, n->p, n->n );
    return( 0 );
}

int mbedtls_mpi_core_exp_mod( mbedtls_mpi_buf const *x, mbedtls_mpi_buf const *a,
                              mbedtls_mpi_buf const *n, mbedtls_mpi_buf const *e,
                              mbedtls_mpi_buf const *rr )
{
    BIGNUM_CORE_CHECK( x->n == n->n && a->n == n->n && rr->n == n->n );
    return( MPI_CORE(exp_mod)( x->p, a->p, n->p, n->n, e->p, e->n, rr->p ) );
}

int mbedtls_mpi_core_mod_reduce( mbedtls_mpi_buf const *x, mbedtls_mpi_buf const *a,
                                 mbedtls_mpi_buf const *n, mbedtls_mpi_buf const *rr )
{
    BIGNUM_CORE_CHECK( x->n == n->n && rr->n == n->n );
    return( MPI_CORE(mod_reduce)( x->p, a->p, a->n, n->p, n->n, rr->p ) );
}

int mbedtls_mpi_core_mod_reduce_single( mbedtls_mpi_buf const *x, mbedtls_mpi_buf const *n )
{
    BIGNUM_CORE_CHECK( x->n == n->n );
    MPI_CORE(mod_reduce_single)( x->p, n->p, n->n );
    return( 0 );
}

int mbedtls_mpi_core_crt_fwd( mbedtls_mpi_buf const *tp,
                              mbedtls_mpi_buf const *tq,
                              mbedtls_mpi_buf const *p,
                              mbedtls_mpi_buf const *q,
                              mbedtls_mpi_buf const *t,
                              mbedtls_mpi_buf const *rp,
                              mbedtls_mpi_buf const *rq )
{
    BIGNUM_CORE_CHECK( tp->n == p->n && tq->n == q->n &&
                       rp->n == p->n && rq->n == q->n );
    return( MPI_CORE(crt_fwd)( tp->p, tq->p, p->p, p->n, q->p,
                               q->n, t->p, t->n, rp->p, rq->p ) );
}

int mbedtls_mpi_core_crt_inv( mbedtls_mpi_buf const *t,
                              mbedtls_mpi_buf const *tp,
                              mbedtls_mpi_buf const *tq,
                              mbedtls_mpi_buf const *p,
                              mbedtls_mpi_buf const *q,
                              mbedtls_mpi_buf const *rp,
                              mbedtls_mpi_buf const *qinvp )
{
    BIGNUM_CORE_CHECK( tp->n == p->n && tq->n == q->n && rp->n == p->n &&
                       qinvp->n == p->n && t->n == p->n + q->n );
    return( MPI_CORE(crt_inv)( t->p, tp->p, tq->p, p->p, p->n,
                               q->p, q->n, rp->p, qinvp->p ) );
}

int mbedtls_mpi_core_lt( mbedtls_mpi_buf const *l, mbedtls_mpi_buf const *r, unsigned *lt )
{
    BIGNUM_CORE_CHECK( l->n == r->n && lt != NULL );
    *lt = MPI_CORE(lt)( l->p, r->p, l->n );
    return( 0 );
}

int mbedtls_mpi_core_cmp( mbedtls_mpi_buf const *a, mbedtls_mpi_buf const *b,
                          int *result )
{
    BIGNUM_CORE_CHECK( a->n == b->n );
    *result = mbedtls_ct_memcmp( a->p, b->p, a->n * ciL );
    return( 0 );
}

int mbedtls_mpi_core_add_mod( mbedtls_mpi_buf const *x, mbedtls_mpi_buf const *a,
                              mbedtls_mpi_buf const *b, mbedtls_mpi_buf const *n )
{
    BIGNUM_CORE_CHECK( x->n == n->n && a->n == n->n && b->n == n->n );
    MPI_CORE(add_mod)(x->p,a->p,b->p,n->p,n->n);
    return( 0 );
}

int mbedtls_mpi_core_add_mod_d( mbedtls_mpi_buf const *x,
                                mbedtls_mpi_buf const *b, mbedtls_mpi_buf const *n )
{
    BIGNUM_CORE_CHECK( x->n == n->n && b->n == n->n );
    MPI_CORE(add_mod_d)(x->p,b->p,n->p,n->n);
    return( 0 );
}

int mbedtls_mpi_core_neg_mod( mbedtls_mpi_buf const *x, mbedtls_mpi_buf const *a,
                              mbedtls_mpi_buf const *n )
{
    BIGNUM_CORE_CHECK( x->n == n->n && a->n == n->n );
    MPI_CORE(neg_mod)(x->p,a->p,n->p,n->n);
    return( 0 );
}

int mbedtls_mpi_core_sub_mod( mbedtls_mpi_buf const *x, mbedtls_mpi_buf const *a,
                              mbedtls_mpi_buf const *b, mbedtls_mpi_buf const *n )
{
    BIGNUM_CORE_CHECK( x->n == n->n && a->n == n->n && b->n == n->n );
    MPI_CORE(sub_mod)(x->p,a->p,b->p,n->p,n->n);
    return( 0 );
}

int mbedtls_mpi_core_sub_mod_d( mbedtls_mpi_buf const *x,
                                mbedtls_mpi_buf const *b, mbedtls_mpi_buf const *n )
{
    BIGNUM_CORE_CHECK( x->n == n->n && b->n == n->n );
    MPI_CORE(sub_mod)(x->p,x->p,b->p,n->p,n->n);
    return( 0 );
}

int mbedtls_mpi_core_inv_mod_prime( mbedtls_mpi_buf const *x,
                                    mbedtls_mpi_buf const *a,
                                    mbedtls_mpi_buf const *p,
                                    mbedtls_mpi_buf const *rr )
{
    BIGNUM_CORE_CHECK( x->n == p->n && a->n == p->n && rr->n == p->n );
    return( MPI_CORE(inv_mod_prime)(x->p,a->p,p->p,p->n,rr->p) );
}

mbedtls_mpi_uint mbedtls_mpi_core_uint_bigendian_to_host( mbedtls_mpi_uint x );

int mbedtls_mpi_core_bigendian_to_host( mbedtls_mpi_buf const *p )
{
    MPI_CORE(bigendian_to_host)(p->p,p->n);
    return( 0 );
}

int mbedtls_mpi_core_read_binary_be( mbedtls_mpi_buf const *x,
                                     const unsigned char *buf, size_t buflen )
{
    return( MPI_CORE(read_binary_be)(x->p,x->n,buf,buflen) );
}

int mbedtls_mpi_core_read_binary_le( mbedtls_mpi_buf const *x,
                                     const unsigned char *buf, size_t buflen )
{
    return( MPI_CORE(read_binary_le)(x->p,x->n,buf,buflen) );
}

int mbedtls_mpi_core_write_binary_be( mbedtls_mpi_buf const *x,
                                      unsigned char *buf, size_t buflen )
{
    return( MPI_CORE(write_binary_be)( x->p, x->n, buf, buflen ) );
}

int mbedtls_mpi_core_write_binary_le( mbedtls_mpi_buf const *x,
                                      unsigned char *buf, size_t buflen )
{
    return( MPI_CORE(write_binary_le)( x->p, x->n, buf, buflen ) );
}

int mbedtls_mpi_core_random_be( mbedtls_mpi_buf const *x, size_t n_bytes,
                                int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
    BIGNUM_CORE_CHECK( x->n >= CHARS_TO_LIMBS( n_bytes ) );
    if( x->n == 0 )
        return( 0 );
    return( MPI_CORE(random_be)( x->p, x->n, n_bytes, f_rng, p_rng ) );
}

int mbedtls_mpi_core_random_range_be( mbedtls_mpi_buf const *x,
                                      mbedtls_mpi_uint lower_bound,
                                      mbedtls_mpi_buf const *upper_bound,
                                      size_t n_bits,
                                      int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
    BIGNUM_CORE_CHECK( x->n == upper_bound->n );
    return( MPI_CORE(random_range_be)( x->p, lower_bound, upper_bound->p,
                                       upper_bound->n, n_bits, f_rng, p_rng ) );
}

int mbedtls_mpi_core_shift_r( mbedtls_mpi_buf const *x, size_t count )
{
    MPI_CORE(shift_r)( x->p, x->n, count );
    return( 0 );
}


#endif /* MBEDTLS_BIGNUM_C */
