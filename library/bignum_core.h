/**
 *  Core bignum functions
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

#ifndef MBEDTLS_BIGNUM_CORE_H
#define MBEDTLS_BIGNUM_CORE_H

#include "common.h"
#include <string.h>

#include "mbedtls/constant_time.h"

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#define mbedtls_calloc     calloc
#endif

#define ciL    (sizeof(mbedtls_mpi_uint))         /* chars in limb  */
#define biL    (ciL << 3)                         /* bits  in limb  */
#define biH    (ciL << 2)                         /* half limb size */

//#define BIGNUM_CORE_SKIP_CHECKS

#define ALWAYS_INLINE __attribute__((always_inline)) static inline

#if !defined(BIGNUM_CORE_SKIP_CHECKS)
#define BIGNUM_CORE_CHECK(cond)                       \
    do {                                              \
        if( (cond) == 0 )                             \
            return( MBEDTLS_ERR_MPI_BAD_INPUT_DATA ); \
    } while( 0 )
#else
#define BIGNUM_CORE_CHECK(cond) do {} while( 0 )
#endif

/*
 * Convert between bits/chars and number of limbs
 * Divide first in order to avoid potential overflows
 */
#define BITS_TO_LIMBS(i)  ( (i) / biL + ( (i) % biL != 0 ) )
#define CHARS_TO_LIMBS(i) ( (i) / ciL + ( (i) % ciL != 0 ) )

#if defined(MBEDTLS_BIGNUM_C)
#include "mbedtls/bignum.h"
#endif

/* Get a specific byte, without range checks. */
#define GET_BYTE( X, i )                                        \
    ( ( ( X )[( i ) / ciL] >> ( ( ( i ) % ciL ) * 8 ) ) & 0xff )
#define GET_BYTE_MPI( X, i ) GET_BYTE( (X)->p, i )

#define MPI_CORE(func) mbedtls_mpi_core_ ## func ## _minimal

typedef struct
{
    mbedtls_mpi_uint *p;
    size_t n;
} mbedtls_mpi_buf;

/**
 * \brief        Compare to same-size large unsigned integers in constant time.
 *
 * \param l      The left operand.
 * \param r      The right operand.
 * \param n      The number of limbs in \p l and \p r.
 *
 * \return       \c 0 if \p l < \p r
 * \return       \c 1 if \p l >= \p r
 */
ALWAYS_INLINE
int mbedtls_mpi_core_alloc( mbedtls_mpi_uint** p, size_t elems )
{
    *p = mbedtls_calloc( elems, sizeof(mbedtls_mpi_uint) );
    if( *p == NULL )
        return( MBEDTLS_ERR_MPI_ALLOC_FAILED );
    return( 0 );
}

/*
 * Baremetal version of the internal bignum API
 *
 * - Buffers and lengths are passed directly
 * - Sometimes lengths arguments are elided if they repeat or are assumed
 *   to follow a simply pattern (e.g. len(c) = len(a) + len(b) for c=a*b)
 * - Many times, sanity checks are omitted.
 *
 * There is not yet a uniform rule defining when to pass parameters which are
 * implicit, and when to omit a check -- this may need refining.
 */

/**
 * \brief Perform a shift-left on a known-size large unsigned integer,
 *        ignoring the carry-out.
 *
 * \param[in,out] X     The pointer to the (little-endian) array
 *                      representing the bignum to shift.
 * \param n             Number of limbs of \p X.
 * \param count         The number of bits to shift by.
 */
void MPI_CORE(shift_l)( mbedtls_mpi_uint *X, size_t nx, size_t count );

/**
 * \brief Perform a shift-right on a known-size large unsigned integer,
 *        ignoring the carry-out.
 *
 * \param[in,out] X     The pointer to the (little-endian) array
 *                      representing the bignum to shift.
 * \param n             Number of limbs of \p X.
 * \param count         The number of bits to shift by.
 */
void MPI_CORE(shift_r)( mbedtls_mpi_uint *X, size_t nx, size_t count );

/**
 * \brief        Compare to same-size large unsigned integers in constant time.
 *
 * \param l      The left operand.
 * \param r      The right operand.
 * \param n      The number of limbs in \p l and \p r.
 *
 * \return       \c 0 if \p l < \p r
 * \return       \c 1 if \p l >= \p r
 */
mbedtls_mpi_uint MPI_CORE(lt)( const mbedtls_mpi_uint *l,
                               const mbedtls_mpi_uint *r,
                               size_t n );

/**
 * \brief Add two known-size large unsigned integers, returning the carry.
 *
 * Calculate l + r where l and r have the same size.
 * This function operates modulo (2^ciL)^n and returns the carry
 * (1 if there was a wraparound, and 0 otherwise).
 *
 * d may be aliased to l or r.
 *
 * \param[out] d        The result of the addition.
 * \param[in] l         The left operand.
 * \param[in] r         The right operand.
 * \param n             Number of limbs of \p d, \p l and \p r.
 *
 * \return              1 if `l + r >= (2^{ciL})^n`, 0 otherwise.
 */
mbedtls_mpi_uint MPI_CORE(add)( mbedtls_mpi_uint *d,
                                const mbedtls_mpi_uint *l,
                                const mbedtls_mpi_uint *r,
                                size_t n );

/**
 * \brief Constant-time conditional addition of two known-size large unsigned
 *        integers, returning the carry.
 *
 * Functionally equivalent to
 *
 * ```
 * if( cond )
 *    d += r;
 * return carry;
 * ```
 *
 * \param[in,out] d     The pointer to the (little-endian) array
 *                      representing the bignum to accumulate onto.
 * \param[in] r         The pointer to the (little-endian) array
 *                      representing the bignum to conditionally add
 *                      to \p d. This must be disjoint from \p d.
 * \param n             Number of limbs of \p d and \p l.
 * \param cond          Condition bit dictating whether addition should
 *                      happen or not. This must be \c 0 or \c 1.
 *
 * \return              1 if `d + cond*r >= (2^{ciL})^n`, 0 otherwise.
 */
mbedtls_mpi_uint MPI_CORE(add_if)( mbedtls_mpi_uint *d,
                                   const mbedtls_mpi_uint *r,
                                   size_t n,
                                   unsigned cond );

/**
 * \brief Add unsigned integer to known-size large unsigned integers.
 *        Return the carry.
 *
 * \param[out] d        The result of the addition.
 * \param[in] l         The left operand.
 * \param[in] r         The right operand.
 * \param n             Number of limbs of \p d and \p l.
 *
 * \return              1 if `l + r >= (2^{ciL})^n`, 0 otherwise.
 */
mbedtls_mpi_uint MPI_CORE(add_int)( mbedtls_mpi_uint *d,
                                    const mbedtls_mpi_uint *l,
                                    mbedtls_mpi_uint c, size_t n );

/**
 * \brief Subtract two known-size large unsigned integers, returning the borrow.
 *
 * Calculate l - r where l and r have the same size.
 * This function operates modulo (2^ciL)^n and returns the carry
 * (1 if there was a wraparound, i.e. if `l < r`, and 0 otherwise).
 *
 * d may be aliased to l or r.
 *
 * \param[out] d        The result of the subtraction.
 * \param[in] l         The left operand.
 * \param[in] r         The right operand.
 * \param n             Number of limbs of \p d, \p l and \p r.
 *
 * \return              1 if `l < r`.
 *                      0 if `l >= r`.
 */
mbedtls_mpi_uint MPI_CORE(sub)( mbedtls_mpi_uint *d,
                                const mbedtls_mpi_uint *l,
                                const mbedtls_mpi_uint *r,
                                size_t n );

/**
 * \brief Subtract unsigned integer from known-size large unsigned integers.
 *        Return the borrow.
 *
 * \param[out] d        The result of the subtraction.
 * \param[in] l         The left operand.
 * \param[in] r         The unsigned scalar to subtract.
 * \param n             Number of limbs of \p d and \p l.
 *
 * \return              1 if `l < r`.
 *                      0 if `l >= r`.
 */
mbedtls_mpi_uint MPI_CORE(sub_int)( mbedtls_mpi_uint *d,
                                    const mbedtls_mpi_uint *l,
                                    mbedtls_mpi_uint r, size_t n );

/**
 * \brief Perform a known-size multiply accumulate operation
 *
 * Add \p b * \p s to \p d.
 *
 * \param[in,out] d     The pointer to the (little-endian) array
 *                      representing the bignum to accumulate onto.
 * \param d_len         The number of limbs of \p d. This must be
 *                      at least \p s_len.
 * \param[in] s         The pointer to the (little-endian) array
 *                      representing the bignum to multiply with.
 *                      This may be the same as \p d. Otherwise,
 *                      it must be disjoint from \p d.
 * \param s_len         The number of limbs of \p s.
 * \param b             A scalar to multiply with.
 *
 * \return c            The carry at the end of the operation.
 */
mbedtls_mpi_uint MPI_CORE(mla)( mbedtls_mpi_uint *d, size_t d_len ,
                                const mbedtls_mpi_uint *s, size_t s_len,
                                mbedtls_mpi_uint b );

/**
 * \brief Perform a known-size multiplication
 *
 * \param[out] X        The pointer to the (little-endian) array
 *                      representing the product of \p a and \p b.
 *                      This must be of length \p a + \p b.
 * \param[in] A         The pointer to the (little-endian) array
 *                      representing the first factor.
 * \param a             The number of limbs in \p A.
 * \param[in] B         The pointer to the (little-endian) array
 *                      representing the second factor.
 * \param b             The number of limbs in \p B.
 */
void MPI_CORE(mul)( mbedtls_mpi_uint *X,
                    const mbedtls_mpi_uint *A, size_t a,
                    const mbedtls_mpi_uint *B, size_t b );

/**
 * \brief Perform a known-size multiplication with specified output width.
 *
 * This is equivalent to a multiplication in 2^{biL * x_len}.
 *
 * \param[out] X        The pointer to the (little-endian) array
 *                      representing the product of \p a and \p b.
 * \param x_len         The number of limbs in \p X.
 * \param[in] A         The pointer to the (little-endian) array
 *                      representing the first factor.
 * \param a             The number of limbs in \p A.
 * \param[in] B         The pointer to the (little-endian) array
 *                      representing the second factor.
 * \param b             The number of limbs in \p B.
 */
void MPI_CORE(mul_truncate)( mbedtls_mpi_uint *X, size_t x_len,
                             const mbedtls_mpi_uint *A, size_t a,
                             const mbedtls_mpi_uint *B, size_t b );

/** Montgomery multiplication: A = A * B * R^-1 mod N  (HAC 14.36)
 *
 * \param[in,out]   A   Big endian presentation of first operand.
 *                      Must have exactly \p n limbs.
 *                      On successful completion, A contains the result of
 *                      the multiplication A * B * R^-1 mod N where
 *                      R = (2^ciL)^n.
 * \param[in]       B   Big endian presentation of second operand.
 *                      Must have exactly \p n limbs.
 * \param[in]       N   Big endian presentation of the modulus.
 *                      This must be odd and have exactly \p n limbs.
 * \param[in]       n   The number of limbs in \p A, \p B, \p N.
 * \param           mm  The Montgomery constant for \p N: -N^-1 mod 2^ciL.
 *                      This can be calculated by `mpi_montg_init()`.
 * \param[in,out]   T   Temporary storage of size at least 2*n+1 limbs.
 *                      Its initial content is unused and
 *                      its final content is indeterminate.
 */
void MPI_CORE(montmul_d)( mbedtls_mpi_uint *X,
                          const mbedtls_mpi_uint *B,
                          const mbedtls_mpi_uint *N,
                          size_t n, mbedtls_mpi_uint mm,
                          mbedtls_mpi_uint *T );

/* Non-destructive and length-variable version of montmul */
void MPI_CORE(montmul)( mbedtls_mpi_uint *X,
                        const mbedtls_mpi_uint *A, const mbedtls_mpi_uint *B,
                        size_t B_len, const mbedtls_mpi_uint *N,
                        size_t n, mbedtls_mpi_uint mm,
                        mbedtls_mpi_uint *T );

/**
 * \brief          Perform a modular exponentiation with secret exponent: X = A^E mod N
 *
 * \param X        The destination MPI, as a big endian array of length \p n.
 * \param A        The base MPI, as a big endian array of length \p n.
 * \param N        The modulus, as a big endian array of length \p n.
 * \param n        The number of limbs in \p X, \p A, \p N, \p RR.
 * \param E        The exponent, as a big endian array of length \p E_len.
 * \param E_len    The number of limbs in \p E.
 * \param RR       The precomputed residue of 2^{2*biL} modulo N, as a big
 *                 endian array of length \p n.
 * \return         \c 0 if successful.
 * \return         #MBEDTLS_ERR_MPI_ALLOC_FAILED if a memory allocation failed.
 */
int MPI_CORE(exp_mod)( mbedtls_mpi_uint *X,
                       const mbedtls_mpi_uint *A,
                       const mbedtls_mpi_uint *N, size_t n,
                       const mbedtls_mpi_uint *E, size_t E_len,
                       const mbedtls_mpi_uint *RR );

/* TODO: Document */
int MPI_CORE(exp_mod_pubexp)( mbedtls_mpi_uint *X,
                              mbedtls_mpi_uint const *A,
                              const mbedtls_mpi_uint *N,
                              size_t n,
                              const mbedtls_mpi_uint *E,
                              size_t E_len,
                              const mbedtls_mpi_uint *RR );

void MPI_CORE(inv_mod_p384r1_mont)( mbedtls_mpi_uint *X,
                                    mbedtls_mpi_uint const *A,
                                    const mbedtls_mpi_uint *N,
                                    size_t n );

/* Forward CRT */
/* TODO: Document */
int MPI_CORE(crt_fwd)( mbedtls_mpi_uint *TP, mbedtls_mpi_uint *TQ,
                       const mbedtls_mpi_uint *P, size_t P_len,
                       const mbedtls_mpi_uint *Q, size_t Q_len,
                       const mbedtls_mpi_uint *T, size_t T_len,
                       const mbedtls_mpi_uint *RP,
                       const mbedtls_mpi_uint *RQ );

/* Inverse CRT */
/* TODO: Document */
int MPI_CORE(crt_inv)( mbedtls_mpi_uint *T,
                       mbedtls_mpi_uint *TP,
                       mbedtls_mpi_uint *TQ,
                       const mbedtls_mpi_uint *P, size_t P_len,
                       const mbedtls_mpi_uint *Q, size_t Q_len,
                       const mbedtls_mpi_uint *RP,
                       const mbedtls_mpi_uint *QinvP );

/* TODO: Document */
int MPI_CORE(inv_mod_prime)( mbedtls_mpi_uint *X,
                             mbedtls_mpi_uint const *A,
                             const mbedtls_mpi_uint *P, size_t n,
                             mbedtls_mpi_uint *RR );

/**
 * \brief        Perform a modular reduction
 *
 * \param X      The destination address at which to store the big endian
 *               presentation of the result of the modular reduction.
 *               This must point to a writable buffer of length \p n * ciL.
 * \param A      The address of the big endian presentation of the input.
 *               This must be a readable buffer of length \p A_len * ciL.
 * \param A_len  The number of limbs in \p A.
 * \param N      The address of the big endian presentation of the modulus.
 *               This must be a readable buffer of length \p n * ciL.
 * \param n      The number of limbs in \p n.
 * \param RR     The adddress of the big endian presentation of the precomputed
 *               Montgomery constant (2^{ciL})^{2*n} mod N.
 *               See MPI_CORE(get_montgomery_constant_safe)().
 *
 * \return       0 on success.
 * \return       MBEDTLS_ERR_MPI_ALLOC_FAILED
 */
int MPI_CORE(mod_reduce)( mbedtls_mpi_uint *X,
                   mbedtls_mpi_uint const *A, size_t A_len,
                   const mbedtls_mpi_uint *N, size_t n,
                   const mbedtls_mpi_uint *RR );

/**
 * \brief Perform a known-size modular addition.
 *
 * Calculate A + B mod N.
 *
 * \param[out] X        The result of the modular addition.
 * \param[in] A         The left operand. This must be smaller than \p N.
 * \param[in] B         The right operand. This must be smaller than \p N.
 * \param[in] N         The modulus.
 * \param n             Number of limbs of \p X, \p A, \p B and \p N.
 */
void MPI_CORE(add_mod)( mbedtls_mpi_uint *X, mbedtls_mpi_uint const *A,
                        mbedtls_mpi_uint const *B, const mbedtls_mpi_uint *N,
                        size_t n );

/* Destructive version */
void MPI_CORE(add_mod_d)( mbedtls_mpi_uint *X,
                          mbedtls_mpi_uint const *B, const mbedtls_mpi_uint *N,
                          size_t n );

/* TODO: Document */
void MPI_CORE(neg_mod)( mbedtls_mpi_uint *X, mbedtls_mpi_uint const *A,
                        const mbedtls_mpi_uint *N, size_t n );

/**
 * \brief Perform a known-size modular subtraction.
 *
 * Calculate A - B mod N.
 *
 * \param[out] X        The result of the modular subtraction.
 * \param[in] A         The left operand. This must be smaller than \p N.
 * \param[in] B         The right operand. This must be smaller than \p N.
 * \param[in] N         The modulus.
 * \param n             Number of limbs of \p X, \p A, \p B and \p N.
 */
void MPI_CORE(sub_mod)( mbedtls_mpi_uint *X, mbedtls_mpi_uint const *A,
                        mbedtls_mpi_uint const *B, const mbedtls_mpi_uint *N,
                        size_t n );

/* Destructive version */
void MPI_CORE(sub_mod_d)( mbedtls_mpi_uint *X,
                          mbedtls_mpi_uint const *B, const mbedtls_mpi_uint *N,
                          size_t n );


/* TODO: Document */
int MPI_CORE(write_binary_be)( const mbedtls_mpi_uint *X, size_t nx,
                               unsigned char *buf, size_t buflen );
int MPI_CORE(write_binary_le)( const mbedtls_mpi_uint *X, size_t nx,
                               unsigned char *buf, size_t buflen );
int MPI_CORE(read_binary_be)( mbedtls_mpi_uint *X, size_t nx,
                              const unsigned char *buf, size_t buflen );
int MPI_CORE(read_binary_le)( mbedtls_mpi_uint *X, size_t nx,
                              const unsigned char *buf, size_t buflen );
void MPI_CORE(bigendian_to_host)( mbedtls_mpi_uint *X, size_t nx );

int MPI_CORE(random_range_be)( mbedtls_mpi_uint *X,
                               mbedtls_mpi_uint min,
                               mbedtls_mpi_uint *upper_bound,
                               size_t n,
                               size_t n_bits,
                               int (*f_rng)(void *, unsigned char *, size_t), void *p_rng );

/**
 * \brief Negate a known-size large integer in 2s complement.
 *
 * \param[in,out] X     The pointer to the (little-endian) array
 *                      representing 2s-complement signed integer
 *                      to negate.
 * \param x_len         The number of limbs in \p X.
 */
void MPI_CORE(sint_neg)( mbedtls_mpi_uint *X, size_t x_len );

/**
 * \brief Extract the least significant bit from known-size large integer.
 *
 * \param[in] A     The pointer to the (little-endian) array
 *                  representing the bignum to get the lsb of.
 * \param A_len     Number of limbs of \p A.
 *
 * \return          The 0-based index of the least significant set bit,
 *                  or 0 if no bit is set.
 */
size_t MPI_CORE(lsb)( mbedtls_mpi_uint const *A, size_t A_len );

/**
 * \brief Compute a modular inversion modulo a large power of 2.
 *
 * This is equivalent to X = A^{-1} mod 2^{biL * A_len}.
 *
 * \param[out] X     The result of the inversion.
 * \param[in]  A     The pointer to the (little-endian) array
 *                   representing the bignum to invert.
 *                   This must be odd.
 * \param A_len      The number of limbs in \p A.
 *
 * \returns          \c 0 on success.
 * \returns          MBEDTLS_ERR_MPI_ALLOC_FAILED on allocation failure.
 */
int MPI_CORE(mont_init_wide)( mbedtls_mpi_uint *X,
                              mbedtls_mpi_uint const *A, size_t A_len );

/**
 * \brief Compute a negative modular inversion in mbedtls_mpi_uint
 */
mbedtls_mpi_uint MPI_CORE(mont_init)( mbedtls_mpi_uint m );

/**
 * \brief        Compute (2^{biL})^{2*n} mod N
 *
 * \param RR     The address at which to store the Montgomery constant.
 *               This must point to a writable buffer of \p n * ciL.
 * \param N      The modulus. This must be a readable buffer of length
 *               \p n * ciL.
 * \param n      The number of limbs in \p N and \p RR.
 *
 */
void MPI_CORE(get_montgomery_constant_safe)( mbedtls_mpi_uint *RR,
                                             mbedtls_mpi_uint const *N,
                                             size_t n );

/**
 * \brief Extract bit from known-size large integer.
 *
 * \warning The bit index is _not_ kept secret and may leak, e.g. through
 *          the memory access pattern invoked by this function.
 *
 * \param[in] X     The pointer to the (little-endian) array
 *                  representing the bignum to extract the bit from.
 * \param n         Number of limbs of \p X.
 * \param pos       The 0-based based (little endian) index of the bit
 *                  to extract.
 *
 * \return          1 if bit `2^pos` occurs in the 2-adic expansion of the
 *                  integer represented by \p X. 0 otherwise.
 */
unsigned char MPI_CORE(get_bit)( const mbedtls_mpi_uint *X, size_t nx, size_t pos );


/* Note: The following is an example of a function where one can elide arguments
 *       and assumption checks, but where it's questionable how much is gained. */

/**
 * \brief Set bit in known-size large integer.
 *
 * \warning The bit index is _not_ kept secret and may leak, e.g. through
 *          the memory access pattern invoked by this function.
 *
 * \param[in,out] X   The pointer to the (little-endian) array
 *                    representing the bignum to manipulate.
 * \param n           Number of limbs of \p X.
 * \param pos         The 0-based based (little endian) index of the bit to set.
 *                    This must be smaller than \p n * biL.
 * \param val         The value to set bit \p pos to. This must be \c 0 or \c 1.
 *
 */
void MPI_CORE(set_bit)( mbedtls_mpi_uint *X, size_t pos, unsigned char val );

/*
 * Some wrappers around core functions
 *
 * We experiment with multiple versions:
 * - Passing buffer+length pairs by value ( foo() variant )
 * - Passing buffer+length pairs by reference ( foo_p() variant )
 */

ALWAYS_INLINE
int mbedtls_mpi_core_add( mbedtls_mpi_buf d, mbedtls_mpi_buf l, mbedtls_mpi_buf r,
                          mbedtls_mpi_uint *carry )
{
    mbedtls_mpi_uint res;
    BIGNUM_CORE_CHECK( d.n == l.n && l.n == r.n );

    res = MPI_CORE(add)( d.p, l.p, r.p, d.n );
    if( carry != NULL )
        *carry = res;
    return( 0 );
}

ALWAYS_INLINE
int mbedtls_mpi_core_add_int( mbedtls_mpi_buf d, mbedtls_mpi_buf l,
                              mbedtls_mpi_uint c, mbedtls_mpi_uint *carry )
{
    mbedtls_mpi_uint res;
    BIGNUM_CORE_CHECK( d.n == l.n );

    res = MPI_CORE(add_int)( d.p, l.p, c, d.n );
    if( carry != NULL )
        *carry = res;
    return( 0 );
}

ALWAYS_INLINE
int mbedtls_mpi_core_sub( mbedtls_mpi_buf d, mbedtls_mpi_buf l,
                          mbedtls_mpi_buf r, mbedtls_mpi_uint *borrow )
{
    mbedtls_mpi_uint res;
    BIGNUM_CORE_CHECK( d.n == l.n && l.n == r.n );

    res = MPI_CORE(sub)( d.p, l.p, r.p, r.n );
    if( borrow != NULL )
        *borrow = res;
    return( 0 );
}

ALWAYS_INLINE
int mbedtls_mpi_core_sub_int( mbedtls_mpi_buf d, mbedtls_mpi_buf l,
                              mbedtls_mpi_uint c, mbedtls_mpi_uint *borrow )
{
    mbedtls_mpi_uint res;
    BIGNUM_CORE_CHECK( d.n == l.n );
    res = MPI_CORE(sub_int)( d.p, l.p, c, d.n );
    if( borrow != NULL )
        *borrow = res;
    return( 0 );
}


ALWAYS_INLINE
int mbedtls_mpi_core_mla( mbedtls_mpi_buf d, mbedtls_mpi_buf s,
                          mbedtls_mpi_uint b, mbedtls_mpi_uint *carry )
{
    mbedtls_mpi_uint res;
    res = MPI_CORE(mla)( d.p, d.n, s.p, s.n, b );
    if( carry != NULL )
        *carry = res;
    return( 0 );
}


ALWAYS_INLINE
int mbedtls_mpi_core_mul( mbedtls_mpi_buf x, mbedtls_mpi_buf a, mbedtls_mpi_buf b )
{
    BIGNUM_CORE_CHECK( x.n == a.n + b.n );
    MPI_CORE(mul)( x.p, a.p, a.n, b.p, b.n );
    return( 0 );
}

ALWAYS_INLINE
int mbedtls_mpi_core_mont_init( mbedtls_mpi_uint *m_inv,
                                mbedtls_mpi_uint m )
{
    BIGNUM_CORE_CHECK( m_inv != NULL );
    *m_inv = MPI_CORE(mont_init)( m );
    return( 0 );
}

ALWAYS_INLINE
int mbedtls_mpi_core_montmul( mbedtls_mpi_buf x,
                              mbedtls_mpi_buf a, mbedtls_mpi_buf n,
                              mbedtls_mpi_buf b, mbedtls_mpi_buf t,
                              mbedtls_mpi_uint mm )
{
    BIGNUM_CORE_CHECK( x.n == n.n &&
                       a.n == n.n &&
                       b.n <= n.n &&
                       t.n == 2*n.n + 1 );
    MPI_CORE(montmul)( x.p, a.p, b.p, b.n, n.p, n.n, mm, t.p );
    return( 0 );
}

ALWAYS_INLINE
int mbedtls_mpi_core_montmul_d( mbedtls_mpi_buf x,
                                mbedtls_mpi_buf n,
                                mbedtls_mpi_buf b, mbedtls_mpi_buf t,
                                mbedtls_mpi_uint mm )
{
    BIGNUM_CORE_CHECK( x.n == n.n &&
                       b.n == n.n &&
                       t.n == 2*n.n + 1 );
    MPI_CORE(montmul_d)( x.p, b.p, n.p, n.n, mm, t.p );
    return( 0 );
}

ALWAYS_INLINE
int mbedtls_mpi_core_copy( mbedtls_mpi_buf a, mbedtls_mpi_buf b )
{
    BIGNUM_CORE_CHECK( a.n == b.n );
    memcpy( a.p, b.p, a.n * ciL );
    return( 0 );
}

ALWAYS_INLINE
int mbedtls_mpi_core_get_montgomery_constant_safe( mbedtls_mpi_buf rr,
                                                   mbedtls_mpi_buf n )
{
    BIGNUM_CORE_CHECK( rr.n == n.n );
    MPI_CORE(get_montgomery_constant_safe)( rr.p, n.p, n.n );
    return( 0 );
}

ALWAYS_INLINE
int mbedtls_mpi_core_exp_mod( mbedtls_mpi_buf x, mbedtls_mpi_buf a,
                              mbedtls_mpi_buf n, mbedtls_mpi_buf e,
                              mbedtls_mpi_buf rr )
{
    BIGNUM_CORE_CHECK( x.n == n.n && a.n == n.n && rr.n == n.n );
    return( MPI_CORE(exp_mod)( x.p, a.p, n.p, n.n, e.p, e.n, rr.p ) );
}

ALWAYS_INLINE
int mbedtls_mpi_core_mod_reduce( mbedtls_mpi_buf x, mbedtls_mpi_buf a,
                                 mbedtls_mpi_buf n, mbedtls_mpi_buf rr )
{
    BIGNUM_CORE_CHECK( x.n == n.n && rr.n == n.n );
    return( MPI_CORE(mod_reduce)( x.p, a.p, a.n, n.p, n.n, rr.p ) );
}

ALWAYS_INLINE
int mbedtls_mpi_core_crt_fwd( mbedtls_mpi_buf tp,
                              mbedtls_mpi_buf tq,
                              mbedtls_mpi_buf p,
                              mbedtls_mpi_buf q,
                              mbedtls_mpi_buf t,
                              mbedtls_mpi_buf rp,
                              mbedtls_mpi_buf rq )
{
    BIGNUM_CORE_CHECK( tp.n == p.n && tq.n == q.n &&
                       rp.n == p.n && rq.n == q.n );
    return( MPI_CORE(crt_fwd)( tp.p, tq.p, p.p, p.n, q.p,
                               q.n, t.p, t.n, rp.p, rq.p ) );
}

ALWAYS_INLINE
int mbedtls_mpi_core_crt_inv( mbedtls_mpi_buf t,
                              mbedtls_mpi_buf tp,
                              mbedtls_mpi_buf tq,
                              mbedtls_mpi_buf p,
                              mbedtls_mpi_buf q,
                              mbedtls_mpi_buf rp,
                              mbedtls_mpi_buf qinvp )
{
    BIGNUM_CORE_CHECK( tp.n == p.n && tq.n == q.n && rp.n == p.n &&
                       qinvp.n == p.n && t.n == p.n + q.n );
    return( MPI_CORE(crt_inv)( t.p, tp.p, tq.p, p.p, p.n,
                               q.p, q.n, rp.p, qinvp.p ) );
}

ALWAYS_INLINE
int mbedtls_mpi_core_lt( mbedtls_mpi_buf l, mbedtls_mpi_buf r, unsigned *lt )
{
    BIGNUM_CORE_CHECK( l.n == r.n && lt != NULL );
    *lt = MPI_CORE(lt)( l.p, r.p, l.n );
    return( 0 );
}

ALWAYS_INLINE
int mbedtls_mpi_core_cmp( mbedtls_mpi_buf a, mbedtls_mpi_buf b,
                          int *result )
{
    BIGNUM_CORE_CHECK( a.n == b.n );
    *result = mbedtls_ct_memcmp( a.p, b.p, a.n * ciL );
    return( 0 );
}

ALWAYS_INLINE
int mbedtls_mpi_core_add_mod( mbedtls_mpi_buf x, mbedtls_mpi_buf a,
                              mbedtls_mpi_buf b, mbedtls_mpi_buf n )
{
    BIGNUM_CORE_CHECK( x.n == n.n && a.n == n.n && b.n == n.n );
    MPI_CORE(add_mod)(x.p,a.p,b.p,n.p,n.n);
    return( 0 );
}

ALWAYS_INLINE
int mbedtls_mpi_core_add_mod_d( mbedtls_mpi_buf x,
                                mbedtls_mpi_buf b, mbedtls_mpi_buf n )
{
    BIGNUM_CORE_CHECK( x.n == n.n && b.n == n.n );
    MPI_CORE(add_mod_d)(x.p,b.p,n.p,n.n);
    return( 0 );
}

ALWAYS_INLINE
int mbedtls_mpi_core_neg_mod( mbedtls_mpi_buf x, mbedtls_mpi_buf a,
                              mbedtls_mpi_buf n )
{
    BIGNUM_CORE_CHECK( x.n == n.n && a.n == n.n );
    MPI_CORE(neg_mod)(x.p,a.p,n.p,n.n);
    return( 0 );
}

ALWAYS_INLINE
int mbedtls_mpi_core_sub_mod( mbedtls_mpi_buf x, mbedtls_mpi_buf a,
                              mbedtls_mpi_buf b, mbedtls_mpi_buf n )
{
    BIGNUM_CORE_CHECK( x.n == n.n && a.n == n.n && b.n == n.n );
    MPI_CORE(sub_mod)(x.p,a.p,b.p,n.p,n.n);
    return( 0 );
}

ALWAYS_INLINE
int mbedtls_mpi_core_sub_mod_d( mbedtls_mpi_buf x,
                                mbedtls_mpi_buf b, mbedtls_mpi_buf n )
{
    BIGNUM_CORE_CHECK( x.n == n.n && b.n == n.n );
    MPI_CORE(sub_mod)(x.p,x.p,b.p,n.p,n.n);
    return( 0 );
}

ALWAYS_INLINE
int mbedtls_mpi_core_inv_mod_prime( mbedtls_mpi_buf x,
                                    mbedtls_mpi_buf a,
                                    mbedtls_mpi_buf p,
                                    mbedtls_mpi_buf rr )
{
    BIGNUM_CORE_CHECK( x.n == p.n && a.n == p.n && rr.n == p.n );
    return( MPI_CORE(inv_mod_prime)(x.p,a.p,p.p,p.n,rr.p) );
}

/* TODO: Document */
mbedtls_mpi_uint mbedtls_mpi_core_uint_bigendian_to_host( mbedtls_mpi_uint x );
ALWAYS_INLINE
int mbedtls_mpi_core_bigendian_to_host( mbedtls_mpi_buf p )
{
    MPI_CORE(bigendian_to_host)(p.p,p.n);
    return( 0 );
}

int mbedtls_mpi_core_bigendian_to_host_p( mbedtls_mpi_buf const *p );

ALWAYS_INLINE
int mbedtls_mpi_core_read_binary_be( mbedtls_mpi_buf x,
                                     const unsigned char *buf, size_t buflen )
{
    return( MPI_CORE(read_binary_be)(x.p,x.n,buf,buflen) );
}

ALWAYS_INLINE
int mbedtls_mpi_core_read_binary_le( mbedtls_mpi_buf x,
                                     const unsigned char *buf, size_t buflen )
{
    return( MPI_CORE(read_binary_le)(x.p,x.n,buf,buflen) );
}

ALWAYS_INLINE
int mbedtls_mpi_core_write_binary_be( mbedtls_mpi_buf x,
                                      unsigned char *buf, size_t buflen )
{
    return( MPI_CORE(write_binary_be)( x.p, x.n, buf, buflen ) );
}

ALWAYS_INLINE
int mbedtls_mpi_core_write_binary_le( mbedtls_mpi_buf x,
                                      unsigned char *buf, size_t buflen )
{
    return( MPI_CORE(write_binary_le)( x.p, x.n, buf, buflen ) );
}

int MPI_CORE(random_be)( mbedtls_mpi_uint *X, size_t nx, size_t n_bytes,
                         int (*f_rng)(void *, unsigned char *, size_t), void *p_rng );

ALWAYS_INLINE
int mbedtls_mpi_core_random_be( mbedtls_mpi_buf x, size_t n_bytes,
                                int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
    BIGNUM_CORE_CHECK( x.n >= CHARS_TO_LIMBS( n_bytes ) );
    if( x.n == 0 )
        return( 0 );
    return( MPI_CORE(random_be)( x.p, x.n, n_bytes, f_rng, p_rng ) );
}

ALWAYS_INLINE
int mbedtls_mpi_core_random_range_be( mbedtls_mpi_buf x,
                                      mbedtls_mpi_uint lower_bound,
                                      mbedtls_mpi_buf upper_bound,
                                      size_t n_bits,
                                      int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
    BIGNUM_CORE_CHECK( x.n == upper_bound.n );
    return( MPI_CORE(random_range_be)( x.p, lower_bound, upper_bound.p,
                                       upper_bound.n, n_bits, f_rng, p_rng ) );
}

ALWAYS_INLINE
int mbedtls_mpi_core_shift_r( mbedtls_mpi_buf x, size_t count )
{
    MPI_CORE(shift_r)( x.p, x.n, count );
    return( 0 );
}

/*
 *
 * Wrappers passing buffer+length pairs by reference
 *
 */

int mbedtls_mpi_core_shift_r_p( mbedtls_mpi_buf const *x, size_t count );

int mbedtls_mpi_core_add_p( mbedtls_mpi_buf const *d,
                            mbedtls_mpi_buf const *l,
                            mbedtls_mpi_buf const *r,
                            mbedtls_mpi_uint *carry );

int mbedtls_mpi_core_add_int_p( mbedtls_mpi_buf const *d,
                                mbedtls_mpi_buf const *l,
                                mbedtls_mpi_uint *c,
                                mbedtls_mpi_uint *carry );

void mbedtls_mpi_core_zero_p( mbedtls_mpi_buf const *x );

int mbedtls_mpi_core_sub_p( mbedtls_mpi_buf const *d, mbedtls_mpi_buf const *l,
                            mbedtls_mpi_buf const *r, mbedtls_mpi_uint *borrow );


int mbedtls_mpi_core_sub_int_p( mbedtls_mpi_buf const *d, mbedtls_mpi_buf const *l,
                                mbedtls_mpi_uint c, mbedtls_mpi_uint *borrow );


int mbedtls_mpi_core_mla_p( mbedtls_mpi_buf const *d, mbedtls_mpi_buf const *s,
                            mbedtls_mpi_uint b, mbedtls_mpi_uint *carry );


int mbedtls_mpi_core_mul_p( mbedtls_mpi_buf const *x, mbedtls_mpi_buf const *a, mbedtls_mpi_buf const *b );


int mbedtls_mpi_core_copy_p( mbedtls_mpi_buf const *a, mbedtls_mpi_buf const *b );


int mbedtls_mpi_core_montmul_p( mbedtls_mpi_buf const *x,
                                mbedtls_mpi_buf const *a, mbedtls_mpi_buf const *n,
                                mbedtls_mpi_buf const *b, mbedtls_mpi_buf const *t,
                                mbedtls_mpi_uint mm );

int mbedtls_mpi_core_get_montgomery_constant_safe_p( mbedtls_mpi_buf const *rr,
                                                     mbedtls_mpi_buf const *n );


int mbedtls_mpi_core_exp_mod_p( mbedtls_mpi_buf const *x, mbedtls_mpi_buf const *a,
                                mbedtls_mpi_buf const *n, mbedtls_mpi_buf const *e,
                                mbedtls_mpi_buf const *rr );


int mbedtls_mpi_core_crt_inv_p( mbedtls_mpi_buf const *t,
                                mbedtls_mpi_buf const *tp,
                                mbedtls_mpi_buf const *tq,
                                mbedtls_mpi_buf const *p,
                                mbedtls_mpi_buf const *q,
                                mbedtls_mpi_buf const *rp,
                                mbedtls_mpi_buf const *qinvp );

int mbedtls_mpi_core_crt_fwd_p( mbedtls_mpi_buf const *tp,
                                mbedtls_mpi_buf const *tq,
                                mbedtls_mpi_buf const *p,
                                mbedtls_mpi_buf const *q,
                                mbedtls_mpi_buf const *t,
                                mbedtls_mpi_buf const *rp,
                                mbedtls_mpi_buf const *rq );


int mbedtls_mpi_core_lt_p( mbedtls_mpi_buf const *l,
                           mbedtls_mpi_buf const *r,
                           unsigned *lt );


int mbedtls_mpi_core_cmp_p( mbedtls_mpi_buf const *a, mbedtls_mpi_buf const *b,
                            int *result );


int mbedtls_mpi_core_add_mod_p( mbedtls_mpi_buf const *x, mbedtls_mpi_buf const *a,
                                mbedtls_mpi_buf const *b, mbedtls_mpi_buf const *n );
int mbedtls_mpi_core_add_mod_d_p( mbedtls_mpi_buf const *x,
                                  mbedtls_mpi_buf const *b, mbedtls_mpi_buf const *n );


int mbedtls_mpi_core_neg_mod_p( mbedtls_mpi_buf const *x, mbedtls_mpi_buf const *a,
                                mbedtls_mpi_buf const *n );

int mbedtls_mpi_core_sub_mod_p( mbedtls_mpi_buf const *x,
                                mbedtls_mpi_buf const *a,
                                mbedtls_mpi_buf const *b,
                                mbedtls_mpi_buf const *n );
int mbedtls_mpi_core_sub_mod_d_p( mbedtls_mpi_buf const *x,
                                  mbedtls_mpi_buf const *b,
                                  mbedtls_mpi_buf const *n );


int mbedtls_mpi_core_write_binary_p( mbedtls_mpi_buf const *x,
                                     unsigned char *buf, size_t buflen );


int mbedtls_mpi_core_inv_mod_prime_p( mbedtls_mpi_buf const *x,
                                      mbedtls_mpi_buf const *a,
                                      mbedtls_mpi_buf const *p,
                                      mbedtls_mpi_buf const *rr );

int mbedtls_mpi_core_mod_reduce_p( mbedtls_mpi_buf const *x,
                                   mbedtls_mpi_buf const *a,
                                   mbedtls_mpi_buf const *n,
                                   mbedtls_mpi_buf const *rr );


int mbedtls_mpi_core_random_range_be_p( mbedtls_mpi_buf const *x,
                                        mbedtls_mpi_uint lower_bound,
                                        mbedtls_mpi_buf const *upper_bound,
                                        size_t n_bits,
                                        int (*f_rng)(void *, unsigned char *, size_t), void *p_rng );

int mbedtls_mpi_core_random_be_p( mbedtls_mpi_buf const *x, size_t n_bytes,
                                  int (*f_rng)(void *, unsigned char *, size_t), void *p_rng );


#endif /* MBEDTLS_BIGNUM_CORE_H */
