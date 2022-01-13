/**
 * \file ecp_arith_wrapper_fixsize_heap.h
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

#ifndef MBEDTLS_ECP_ARITH_WRAPPER_FIXSIZE_HEAP_H
#define MBEDTLS_ECP_ARITH_WRAPPER_FIXSIZE_HEAP_H

#include "mbedtls/build_info.h"
#include "mbedtls/ecp.h"

#include "ecp_arith_wrapper_fixsize_heap_typedefs.h"

#define getX(pt) ((mbedtls_ecp_mpi_internal*)&((pt)->v.X))
#define getY(pt) ((mbedtls_ecp_mpi_internal*)&((pt)->v.Y))
#define getZ(pt) ((mbedtls_ecp_mpi_internal*)&((pt)->v.Z))

#define getA(grp) ((mbedtls_ecp_mpi_internal   const*)(&((grp)->src->A)))
#define getB(grp) ((mbedtls_ecp_mpi_internal   const*)(&((grp)->src->B)))
#define getG(grp) ((mbedtls_ecp_point_internal const*)(&((grp)->src->G)))

#define getGrp(grp)       ((grp)->src)
#define getTmpDouble(grp) (mbedtls_mpi*)&(grp->tmp_double)

#define getTmp(grp,idx)   (mbedtls_mpi*)&(grp->tmp_arr[(idx)])

#define mbedtls_ecp_mpi_internal_init( x ) \
    mbedtls_mpi_init( (mbedtls_mpi*)( x ) )
#define mbedtls_ecp_mpi_internal_free( x ) \
    mbedtls_mpi_free( (mbedtls_mpi*)( x ) )
#define mbedtls_ecp_point_internal_init( x ) \
    mbedtls_ecp_point_init( (mbedtls_ecp_point*)( x ) )
#define mbedtls_ecp_point_internal_free( x ) \
    mbedtls_ecp_point_free( (mbedtls_ecp_point*)( x ) )

static int mpi_force_size_and_lock( mbedtls_mpi *X, size_t limbs )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    MBEDTLS_MPI_CHK( mbedtls_mpi_shrink( X, limbs ) );
    if( X->n != limbs )
        return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );
    X->fixedbuf = 1;
cleanup:
    return( ret );
}

static void mpi_unlock( mbedtls_mpi *X )
{
    X->fixedbuf = 0;
}

static void ecp_point_unlock( mbedtls_ecp_point *pt )
{
    mpi_unlock( &pt->X );
    mpi_unlock( &pt->Y );
    mpi_unlock( &pt->Z );
}

static int mpi_force_single( const mbedtls_ecp_group *grp,
                             mbedtls_mpi *X )
{
    return( mpi_force_size_and_lock( X, grp->P.n ) );
}

static int ecp_point_force_single( mbedtls_ecp_group const *grp,
                                   mbedtls_ecp_point *pt )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    MBEDTLS_MPI_CHK( mpi_force_single( grp, &pt->X ) );
    MBEDTLS_MPI_CHK( mpi_force_single( grp, &pt->Y ) );
    MBEDTLS_MPI_CHK( mpi_force_single( grp, &pt->Z ) );

cleanup:
    return( ret );
}

static int mpi_force_double( const mbedtls_ecp_group *grp,
                                 mbedtls_mpi *X )
{
    size_t limbs;
    if( grp->id == MBEDTLS_ECP_DP_SECP224R1 ||
        grp->id == MBEDTLS_ECP_DP_SECP256R1 ||
        grp->id == MBEDTLS_ECP_DP_SECP384R1 )
    {
        limbs = 2 * grp->P.n;
    }
    else
    {
        limbs = 2 * grp->P.n + 1;
    }

    return( mpi_force_size_and_lock( X, limbs ) );
}

#define MPI_GROW_SINGLE( X ) \
    MBEDTLS_MPI_CHK( mpi_force_single( grp, (X) ) )

static int mpi_is_single_size( const mbedtls_ecp_group *grp,
                                      const mbedtls_mpi *X )
{
    return( X->n == grp->P.n );
}

static int mbedtls_ecp_mpi_internal_from_raw_ref(
    mbedtls_ecp_group_internal const *grp,
    mbedtls_ecp_mpi_internal *X,
    mbedtls_mpi_uint *src,
    size_t num_limbs )
{
    mbedtls_mpi const v =
        MPI_FROM_RAW_REF_RW(src,num_limbs);

    if( src == NULL )
        return( 0 );

    if( num_limbs != getGrp(grp)->P.n )
        return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );

    X->v = v;
    return( 0 );
}

/* Setup routines */

static void mpi_init_many( mbedtls_mpi *arr, size_t size )
{
    while( size-- )
        mbedtls_mpi_init( arr++ );
}

static void mpi_free_many( mbedtls_mpi *arr, size_t size )
{
    while( size-- )
        mbedtls_mpi_free( arr++ );
}

static int mpi_force_single_many( mbedtls_ecp_group const *grp,
                                  mbedtls_mpi *X,
                                  size_t size )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    while( size-- )
        MBEDTLS_MPI_CHK( mpi_force_single( grp, X++ ) );
cleanup:
    return( ret );
}

#define ECP_DECL_TEMP_POINT_TMP(x) x ## _tmp
#define ECP_DECL_TEMP_POINT(x)                                          \
    mbedtls_ecp_point_internal ECP_DECL_TEMP_POINT_TMP(x);              \
    mbedtls_ecp_point_internal * const x = &ECP_DECL_TEMP_POINT_TMP(x); \
    mbedtls_ecp_point_init( (mbedtls_ecp_point*) x )
#define ECP_DECL_TEMP_MPI_TMP(x) x ## _tmp
#define ECP_DECL_TEMP_MPI(x)                                         \
    mbedtls_ecp_mpi_internal * const x =                             \
        (mbedtls_ecp_mpi_internal*)&grp->tmp_arr[cur_alloc];         \
    cur_alloc++
#define ECP_DECL_TEMP_MPI_STATIC_ARRAY(x,n)                          \
    mbedtls_ecp_mpi_internal * const x =                             \
        (mbedtls_ecp_mpi_internal*) &grp->tmp_arr[cur_alloc];        \
    cur_alloc += (n)
#define ECP_DECL_TEMP_MPI_DYNAMIC_ARRAY(x)                           \
    mbedtls_ecp_mpi_internal *x = NULL;

#define ECP_SETUP_TEMP_POINT(x)                                      \
    MBEDTLS_MPI_CHK( ecp_point_force_single( getGrp(grp),            \
                                  (mbedtls_ecp_point*) x ) )
#define ECP_SETUP_TEMP_MPI(x) do {} while( 0 )
#define ECP_SETUP_TEMP_MPI_STATIC_ARRAY(x,n) do {} while( 0 )
#define ECP_SETUP_TEMP_MPI_DYNAMIC_ARRAY(x,n)                        \
    do {                                                             \
        x = mbedtls_calloc( (n), sizeof( mbedtls_mpi ) );            \
        if( x == NULL )                                              \
        {                                                            \
            ret = MBEDTLS_ERR_ECP_ALLOC_FAILED;                      \
            goto cleanup;                                            \
        }                                                            \
        mpi_init_many( (mbedtls_mpi*) x, (n) );                      \
        MBEDTLS_MPI_CHK( mpi_force_single_many( getGrp(grp),         \
                                               (mbedtls_mpi*) x,     \
                                               (n) ) );              \
    } while( 0 )

#define ECP_FREE_TEMP_POINT(x)                                       \
    mbedtls_ecp_point_free( (mbedtls_ecp_point*) x )
#define ECP_FREE_TEMP_MPI(x) do {} while( 0 )
#define ECP_FREE_TEMP_MPI_STATIC_ARRAY(x,n) do {} while( 0 )
#define ECP_FREE_TEMP_MPI_DYNAMIC_ARRAY(x,n)                         \
    do {                                                             \
        mpi_free_many( (mbedtls_mpi*) x, (n) );                      \
        mbedtls_free( x );                                           \
    } while( 0 )

/*
 * Input conversion
 */

static int ecp_setup_internal_input(
    mbedtls_ecp_group const *grp,
    mbedtls_ecp_point *new,
    mbedtls_ecp_point const *old )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    MBEDTLS_MPI_CHK( mbedtls_ecp_copy( new, old ) );
    MBEDTLS_MPI_CHK( ecp_point_force_single( grp, new ) );
cleanup:
    return( ret );
}

#define ECP_INTERNAL_INPUT_TMP(x) x ## _tmp
#define ECP_INTERNAL_INPUT(x)  (& ECP_INTERNAL_INPUT_TMP(x))
#define ECP_INTERNAL_INPUT_AS_ORIG(x) \
    ((mbedtls_ecp_point*) ECP_INTERNAL_INPUT(x))
#define ECP_DECL_INTERNAL_INPUT(x) \
    mbedtls_ecp_point_internal ECP_INTERNAL_INPUT_TMP(x);        \
    mbedtls_ecp_point_init( ECP_INTERNAL_INPUT_AS_ORIG(x) )
#define ECP_CONVERT_INPUT(x)                            \
    MBEDTLS_MPI_CHK( ecp_setup_internal_input( grp,     \
                  ECP_INTERNAL_INPUT_AS_ORIG(x), x ) )
#define ECP_FREE_INTERNAL_INPUT(x)                      \
    mbedtls_ecp_point_free( ECP_INTERNAL_INPUT_AS_ORIG(x) )

/*
 * Output conversion
 */

#define ECP_INTERNAL_OUTPUT(x) ((mbedtls_ecp_point_internal *) x)
#define ECP_DECL_INTERNAL_OUTPUT(x) do {} while( 0 )
#define ECP_CONVERT_OUTPUT(x)                           \
    MBEDTLS_MPI_CHK( ecp_point_force_single( grp, x ) )
#define ECP_SAVE_INTERNAL_OUTPUT(x) do {} while(0)
#define ECP_FREE_INTERNAL_OUTPUT(x)                     \
    ecp_point_unlock(x)

/*
 * InOut conversion
 */
#define ECP_INTERNAL_INOUT(x) ((mbedtls_ecp_point_internal*) x)
#define ECP_DECL_INTERNAL_INOUT(x) do {} while(0)
#define ECP_CONVERT_INOUT(x)                            \
    MBEDTLS_MPI_CHK( ecp_point_force_single( grp, x ) )
#define ECP_SAVE_INTERNAL_INOUT(x) do {} while( 0 )
#define ECP_FREE_INTERNAL_INOUT(x)                      \
    ecp_point_unlock(x)

/*
 * Group conversion
 */

/* Double-check that EC group as constants of expected size. */
static int mbedtls_ecp_group_check_single_size( mbedtls_ecp_group const *grp )
{
    mbedtls_ecp_curve_type ty = mbedtls_ecp_get_type( grp );

    if( ty == MBEDTLS_ECP_TYPE_MONTGOMERY )
    {
        /* Montgomery curves are identified by G.Y being unset.
         * Moreover, B isn't needed. */
        if( !mpi_is_single_size( grp, &grp->A   ) ||
            !mpi_is_single_size( grp, &grp->G.X ) ||
            !mpi_is_single_size( grp, &grp->G.Z ) ||
            grp->B.p   != NULL                    ||
            grp->G.Y.p != NULL )
        {
            return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );
        }
        return( 0 );
    }
    else if( ty == MBEDTLS_ECP_TYPE_SHORT_WEIERSTRASS )
    {
        /* Short Weierstrass curves may have A unset as a shortcut
         * for A == -3. */
        if( ( grp->A.p != NULL && !mpi_is_single_size( grp, &grp->A ) ) ||
            !mpi_is_single_size         ( grp, &grp->B   )              ||
            !mpi_is_single_size         ( grp, &grp->G.X )              ||
            !mpi_is_single_size         ( grp, &grp->G.Y )              ||
            !mpi_is_single_size         ( grp, &grp->G.Z ) )
        {
            return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );
        }
        return( 0 );
    }

    return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );
}

static void mbedtls_ecp_group_internal_init(
    mbedtls_ecp_group_internal *grp, mbedtls_ecp_group *src )
{
    grp->src = src;
    mbedtls_mpi_init( getTmpDouble( grp ) );

    mpi_init_many( &grp->tmp_arr[0], ECP_GROUP_INTERNAL_TMP_MAX );
    grp->alloc = 0;
}

static void mbedtls_ecp_group_internal_free(
    mbedtls_ecp_group_internal *grp )
{
    mbedtls_mpi_free( getTmpDouble( grp ) );
    mpi_free_many( &grp->tmp_arr[0], ECP_GROUP_INTERNAL_TMP_MAX );
}

static int mbedtls_ecp_group_internal_setup(
    mbedtls_ecp_group_internal *grp )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    MBEDTLS_MPI_CHK( mbedtls_ecp_group_check_single_size( getGrp(grp ) ) );
    MBEDTLS_MPI_CHK( mpi_force_double( getGrp(grp), getTmpDouble( grp ) ) );
    MBEDTLS_MPI_CHK( mpi_force_single_many( getGrp(grp), &grp->tmp_arr[0],
                                            ECP_GROUP_INTERNAL_TMP_MAX ) );
cleanup:
    return( ret );
}

#define ECP_INTERNAL_GROUP_TMP(x) x ## _tmp
#define ECP_INTERNAL_GROUP(x) & ECP_INTERNAL_GROUP_TMP(x)
#define ECP_DECL_INTERNAL_GROUP(x)                                      \
    mbedtls_ecp_group_internal ECP_INTERNAL_GROUP_TMP(x);               \
    mbedtls_ecp_group_internal_init( ECP_INTERNAL_GROUP(x), x )
#define ECP_CONVERT_GROUP(x)                                            \
    MBEDTLS_MPI_CHK( mbedtls_ecp_group_internal_setup(                  \
                         ECP_INTERNAL_GROUP(x) ) )
#define ECP_FREE_INTERNAL_GROUP(x)              \
    mbedtls_ecp_group_internal_free( ECP_INTERNAL_GROUP(x) )

/*
 * Macro wrappers around ECP modular arithmetic
 *
 * Currently, these wrappers are defined via the bignum module.
 */

#define ECP_ARITH_INIT()                              \
    unsigned const alloc_at_entry = grp->alloc;       \
    unsigned cur_alloc = alloc_at_entry

#define ECP_ARITH_START()                                           \
    do {                                                            \
        if( alloc_at_entry != cur_alloc )                           \
            grp->alloc = cur_alloc;                                 \
    } while( 0 )
#define ECP_ARITH_END()                                             \
    do {                                                            \
        if( alloc_at_entry != cur_alloc )                           \
            grp->alloc = alloc_at_entry;                            \
    } while( 0 )

#define ECP_MPI_ADD( X, A, B )                                                 \
    MBEDTLS_MPI_CHK( mbedtls_mpi_add_mod( grp, &((X)->v), &((A)->v), &((B)->v) ) )

#define ECP_MPI_SUB( X, A, B )                                                 \
    MBEDTLS_MPI_CHK( mbedtls_mpi_sub_mod( grp, &((X)->v), &((A)->v), &((B)->v) ) )

#define ECP_MPI_SUB_INT( X, A, c )                                             \
    MBEDTLS_MPI_CHK( mbedtls_mpi_sub_int_mod( grp, &((X)->v), &((A)->v), c ) )

#define ECP_MPI_MUL( X, A, B )                                                 \
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mod( grp, &((X)->v), &((A)->v), &((B)->v) ) )

#define ECP_MPI_SQR( X, A )                                                    \
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mod( grp, &((X)->v), &((A)->v), &((A)->v) ) )

#define ECP_MPI_MUL_INT( X, A, c )                                             \
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_int_mod( grp, &((X)->v), &((A)->v), c ) )

#define ECP_MPI_INV( d, s )                                                \
    MBEDTLS_MPI_CHK( mbedtls_mpi_inv_mod_internal( grp, &(d)->v, &(s)->v, &getGrp(grp)->P ) )

#define ECP_MPI_MOV( X, A )                                                    \
    MBEDTLS_MPI_CHK( mbedtls_mpi_copy( &((X)->v), &((A)->v) ) )

#define ECP_MOV( d, s )                                                        \
    MBEDTLS_MPI_CHK( mbedtls_ecp_copy( (mbedtls_ecp_point*)(d),         \
                                       (mbedtls_ecp_point*) (s) ) )

#define ECP_CMP( d, s )                                                \
    mbedtls_ecp_point_cmp( (mbedtls_ecp_point*) (d),                         \
                           (mbedtls_ecp_point*) (s) )

#define ECP_ZERO( X )                                                   \
    do {                                                                \
        ECP_MPI_LSET( getX(X), 0 );                             \
        ECP_MPI_LSET( getY(X), 0 );                             \
        ECP_MPI_LSET( getZ(X), 1 );                             \
    } while( 0 )

#define ECP_MPI_SHIFT_L( X, count )                                            \
    MBEDTLS_MPI_CHK( mbedtls_mpi_shift_l_mod( grp, &((X)->v), count ) )

#define ECP_MPI_LSET( X, c )                                                   \
    MBEDTLS_MPI_CHK( mbedtls_mpi_lset( &((X)->v), c ) )

#define ECP_MPI_CMP_INT( X, c )                                                \
    mbedtls_mpi_cmp_int( &((X)->v), c )

#define ECP_MPI_CMP( X, Y )                                                    \
    mbedtls_mpi_cmp_mpi( &((X)->v), &((Y)->v) )

/* Needs f_rng, p_rng to be defined. */
#define ECP_MPI_RAND( X )                                                      \
    MBEDTLS_MPI_CHK( mbedtls_mpi_random( &((X)->v), 2, &getGrp(grp)->P, f_rng, p_rng ) )

#define ECP_MPI_COND_NEG( X, cond )                                     \
    MBEDTLS_MPI_CHK( mbedtls_mpi_cond_neg_mod( grp, &(X)->v, (cond) ) )

#define ECP_MPI_NEG( X ) ECP_MPI_COND_NEG( &((X)->v), 1 )

#define ECP_MPI_VALID( X )                      \
    ( (X)->v.p != NULL )

#define ECP_MPI_COND_ASSIGN( X, Y, cond )       \
    MBEDTLS_MPI_CHK( mbedtls_mpi_safe_cond_assign( &((X)->v), &((Y)->v), (cond) ) )

#define ECP_MPI_COND_SWAP( X, Y, cond )       \
    MBEDTLS_MPI_CHK( mbedtls_mpi_safe_cond_swap( &((X)->v), &((Y)->v), (cond) ) )

#define ECP_MPI_REDUCE(x) \
    MBEDTLS_MPI_CHK( mbedtls_mpi_mod_after_add( grp, &(x)->v, &(x)->v ) )

/*
 * Wrapper around fast quasi-modp functions, with fall-back to mbedtls_mpi_mod_mpi.
 * See the documentation of struct mbedtls_ecp_group.
 *
 * This function is in the critial loop for mbedtls_ecp_mul, so pay attention to perf.
 */
static int ecp_modp( mbedtls_mpi *dst, mbedtls_mpi *N, const mbedtls_ecp_group *grp )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    if( grp->modp == NULL )
    {
        MBEDTLS_MPI_CHK( mbedtls_mpi_mod_mpi( N, N, &grp->P ) );
        MBEDTLS_MPI_CHK( mbedtls_mpi_copy( dst, N ) );
        return( 0 );
    }

    /* N->s < 0 is a much faster test, which fails only if N is 0 */
    /* if( ( N->s < 0 && mbedtls_mpi_cmp_int( N, 0 ) != 0 ) || */
    /*     mbedtls_mpi_bitlen( N ) > 2 * grp->pbits ) */
    /* { */
    /*     return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA ); */
    /* } */

    MBEDTLS_MPI_CHK( grp->modp( N ) );

    if( grp->id != MBEDTLS_ECP_DP_SECP224R1 &&
        grp->id != MBEDTLS_ECP_DP_SECP256R1 &&
        grp->id != MBEDTLS_ECP_DP_SECP384R1 )
    {
        /* N->s < 0 is a much faster test, which fails only if N is 0 */
        while( N->s < 0 && mbedtls_mpi_cmp_int( N, 0 ) != 0 )
            MBEDTLS_MPI_CHK( mbedtls_mpi_add_mpi( N, N, &grp->P ) );

        while( mbedtls_mpi_cmp_mpi( N, &grp->P ) >= 0 )
            /* we known P, N and the result are positive */
            MBEDTLS_MPI_CHK( mbedtls_mpi_sub_abs( N, N, &grp->P ) );
    }

    MBEDTLS_MPI_CHK( mbedtls_mpi_copy( dst, N ) );

cleanup:
    return( ret );
}

/*
 * Fast mod-p functions expect their argument to be in the 0..p^2 range.
 *
 * In order to guarantee that, we need to ensure that operands of
 * mbedtls_mpi_mul_mpi are in the 0..p range. So, after each operation we will
 * bring the result back to this range.
 *
 * The following macros are shortcuts for doing that.
 */

/*
 * Reduce a mbedtls_mpi mod p in-place, general case, to use after mbedtls_mpi_mul_mpi
 */
#if defined(MBEDTLS_SELF_TEST)
#define INC_MUL_COUNT   mul_count++;
#else
#define INC_MUL_COUNT
#endif

static int mbedtls_mpi_mul_mod( mbedtls_ecp_group_internal *grp,
                                mbedtls_mpi *X,
                                const mbedtls_mpi *A,
                                const mbedtls_mpi *B )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_mpi * const tmp = (mbedtls_mpi*) getTmpDouble(grp);

    if( /*getGrp(grp)->id == MBEDTLS_ECP_DP_SECP224R1 ||*/
        getGrp(grp)->id == MBEDTLS_ECP_DP_SECP256R1 ||
        getGrp(grp)->id == MBEDTLS_ECP_DP_SECP384R1 )
    {
        size_t Psize = getGrp(grp)->P.n;
        size_t j;
        memset( tmp->p, 0, 2 * sizeof( mbedtls_mpi_uint) * Psize );
        for( j = Psize; j > 0; j-- )
            mpi_mul_hlp( Psize, A->p, tmp->p + j - 1, B->p[j - 1] );
        getGrp(grp)->modp_double( tmp->p );
        memcpy( X->p, tmp->p, sizeof( mbedtls_mpi_uint) * Psize );
        ret = 0;
    }
    else
    {
        MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( tmp, A, B ) );
        MBEDTLS_MPI_CHK( ecp_modp( X, tmp, getGrp(grp) ) );
    }

    INC_MUL_COUNT

cleanup:
    return( ret );
}

static int mbedtls_mpi_mod_after_sub( mbedtls_ecp_group_internal *grp,
                                      mbedtls_mpi *dst, mbedtls_mpi *src )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    while( src->s < 0 && mbedtls_mpi_cmp_int( src, 0 ) != 0 )
        MBEDTLS_MPI_CHK( mbedtls_mpi_add_mpi( src, src, &getGrp(grp)->P ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_copy( dst, src ) );
cleanup:
    return( ret );
}

__attribute__((unused))
static mbedtls_mpi_uint mpi_sub_hlp( size_t n,
                                     mbedtls_mpi_uint *d,
                                     const mbedtls_mpi_uint *l,
                                     const mbedtls_mpi_uint *r )
{
    size_t i;
    mbedtls_mpi_uint c = 0, t, z;

    for( i = 0; i < n; i++ )
    {
        z = ( l[i] <  c );    t = l[i] - c;
        c = ( t < r[i] ) + z; d[i] = t - r[i];
    }

    return( c );
}

__attribute__((unused))
static mbedtls_mpi_uint mpi_sub_int_hlp( size_t n,
                                         mbedtls_mpi_uint *d,
                                         const mbedtls_mpi_uint *l,
                                         mbedtls_mpi_uint r )
{
    size_t i;
    mbedtls_mpi_uint c = 0, z;

    c = ( l[0] < r ); d[0] = l[0] - r;
    for( i = 1; i < n; i++ )
    {
        z = (l[i] == 0) && (c != 0 );
        d[i] = l[i] - c;
        c = z;
    }

    return( c );
}

__attribute__((unused))
static mbedtls_mpi_uint mpi_add_hlp( size_t n,
                                     mbedtls_mpi_uint *d,
                                     const mbedtls_mpi_uint *l,
                                     const mbedtls_mpi_uint *r )
{
    size_t i;
    mbedtls_mpi_uint c = 0, t;

    for( i = 0; i < n; i++ )
    {
        t = l[i] + c; c = ( t < c );
        d[i] = t + r[i]; c += ( d[i] < t );
    }

    return( c );
}

#if defined(ECP_MPI_NEED_SUB_MOD)
/*
 * Reduce a mbedtls_mpi mod p in-place, to use after mbedtls_mpi_sub_mpi
 * N->s < 0 is a very fast test, which fails only if N is 0
 */
static int mbedtls_mpi_sub_mod( mbedtls_ecp_group_internal *grp,
                                mbedtls_mpi *X,
                                const mbedtls_mpi *A,
                                const mbedtls_mpi *B )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    if( !mpi_is_single_size( getGrp(grp), X ) ||
        !mpi_is_single_size( getGrp(grp), A ) ||
        !mpi_is_single_size( getGrp(grp), B ) )
    {
        MBEDTLS_MPI_CHK( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );
    }

    if( /*getGrp(grp)->id == MBEDTLS_ECP_DP_SECP224R1 ||*/
        getGrp(grp)->id == MBEDTLS_ECP_DP_SECP256R1 ||
        getGrp(grp)->id == MBEDTLS_ECP_DP_SECP384R1 )
    {
        size_t Psize = getGrp(grp)->P.n;
        signed char c = -mpi_sub_hlp( Psize, X->p, A->p, B->p );
        getGrp(grp)->modp_single( X->p, c );
        ret = 0;
    }
    else
    {
        mbedtls_mpi * const tmp = (mbedtls_mpi*) getTmpDouble(grp);
        MBEDTLS_MPI_CHK( mbedtls_mpi_sub_mpi( tmp, A, B ) );
        MBEDTLS_MPI_CHK( mbedtls_mpi_mod_after_sub( grp, X, tmp ) );
    }
cleanup:
    return( ret );
}
#endif /* ECP_MPI_NEED_SUB_MOD */

/*
 * Reduce a mbedtls_mpi mod p in-place, to use after mbedtls_mpi_add_mpi and mbedtls_mpi_mul_int.
 * We known P, N and the result are positive, so sub_abs is correct, and
 * a bit faster.
 */

static int mbedtls_mpi_mod_after_add( mbedtls_ecp_group_internal *grp,
                                      mbedtls_mpi *dst, mbedtls_mpi *src )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    while( mbedtls_mpi_cmp_mpi( src, &getGrp(grp)->P ) >= 0 )
        MBEDTLS_MPI_CHK( mbedtls_mpi_sub_abs( src, src, &getGrp(grp)->P ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_copy( dst, src ) );

cleanup:
    return( ret );
}

static int mbedtls_mpi_add_mod( mbedtls_ecp_group_internal *grp,
                                mbedtls_mpi *X,
                                const mbedtls_mpi *A,
                                const mbedtls_mpi *B )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    if( /*getGrp(grp)->id == MBEDTLS_ECP_DP_SECP224R1 ||*/
        getGrp(grp)->id == MBEDTLS_ECP_DP_SECP256R1 ||
        getGrp(grp)->id == MBEDTLS_ECP_DP_SECP384R1 )
    {
        size_t Psize = getGrp(grp)->P.n;
        signed char c = mpi_add_hlp( Psize, X->p, A->p, B->p );
        getGrp(grp)->modp_single( X->p, c );
        ret = 0;
    }
    else
    {
        mbedtls_mpi * const tmp = (mbedtls_mpi*) getTmpDouble(grp);
        MBEDTLS_MPI_CHK( mbedtls_mpi_add_mpi( tmp, A, B ) );
        MBEDTLS_MPI_CHK( mbedtls_mpi_mod_after_add( grp, X, tmp ) );
    }

cleanup:
    return( ret );
}

static int mbedtls_mpi_mul_int_mod( mbedtls_ecp_group_internal *grp,
                                    mbedtls_mpi *X,
                                    const mbedtls_mpi *A,
                                    mbedtls_mpi_uint c )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_mpi * const tmp = (mbedtls_mpi*) getTmpDouble(grp);

    if( /*getGrp(grp)->id == MBEDTLS_ECP_DP_SECP224R1 ||*/
        getGrp(grp)->id == MBEDTLS_ECP_DP_SECP256R1 ||
        getGrp(grp)->id == MBEDTLS_ECP_DP_SECP384R1 )
    {
        size_t Psize = getGrp(grp)->P.n;
        memset( tmp->p, 0, sizeof( mbedtls_mpi_uint) * Psize );
        mpi_mul_hlp( Psize, A->p, tmp->p, c );
        getGrp(grp)->modp_single( tmp->p, tmp->p[Psize] );
        memcpy( X->p, tmp->p, sizeof( mbedtls_mpi_uint) * Psize );
        ret = 0;
    }
    else
    {
        MBEDTLS_MPI_CHK( mbedtls_mpi_mul_int( tmp, A, c ) );
        MBEDTLS_MPI_CHK( mbedtls_mpi_mod_after_add( grp, X, tmp ) );
    }

cleanup:
    return( ret );
}

static int mbedtls_mpi_sub_int_mod( mbedtls_ecp_group_internal *grp,
                                    mbedtls_mpi *X,
                                    const mbedtls_mpi *A,
                                    mbedtls_mpi_uint c )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    if( /*getGrp(grp)->id == MBEDTLS_ECP_DP_SECP224R1 ||*/
        getGrp(grp)->id == MBEDTLS_ECP_DP_SECP256R1 ||
        getGrp(grp)->id == MBEDTLS_ECP_DP_SECP384R1 )
    {
        size_t Psize = getGrp(grp)->P.n;
        signed char carry = mpi_sub_int_hlp( Psize, X->p, A->p, c );
        getGrp(grp)->modp_single( X->p, carry );
        ret = 0;
    }
    else
    {
        mbedtls_mpi * const tmp = (mbedtls_mpi*) getTmpDouble(grp);
        MBEDTLS_MPI_CHK( mbedtls_mpi_sub_int( tmp, A, c ) );
        MBEDTLS_MPI_CHK( mbedtls_mpi_mod_after_sub( grp, X, tmp ) );
    }

cleanup:
    return( ret );
}

#if defined(ECP_MPI_NEED_SHIFT_L_MOD)
static int mbedtls_mpi_shift_l_mod( mbedtls_ecp_group_internal *grp,
                                    mbedtls_mpi *X,
                                    size_t count )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_mpi * const tmp = (mbedtls_mpi*) getTmpDouble(grp);
    MBEDTLS_MPI_CHK( mbedtls_mpi_copy( tmp, X ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_shift_l( tmp, count ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_mod_after_add( grp, X, tmp ) );
cleanup:
    return( ret );
}
#endif /* ECP_MPI_NEED_SHIFT_L_MOD */

static int mbedtls_mpi_inv_mod_internal( mbedtls_ecp_group_internal *grp,
                                         mbedtls_mpi *dst,
                                         mbedtls_mpi const *src,
                                         mbedtls_mpi const *P )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_mpi * const tmp = getTmpDouble(grp);

    MBEDTLS_MPI_CHK( mbedtls_mpi_inv_mod( tmp, src, P ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_copy( dst, tmp ) );

cleanup:
    return( ret );
}

static int mbedtls_mpi_cond_neg_mod( mbedtls_ecp_group_internal *grp,
                                     mbedtls_mpi *X,
                                     unsigned cond )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    ECP_ARITH_INIT();
    ECP_DECL_TEMP_MPI(tmp);
    ECP_ARITH_START();
    ECP_SETUP_TEMP_MPI(tmp);

    unsigned char nonzero =
        mbedtls_mpi_cmp_int( X, 0 ) != 0;

    MBEDTLS_MPI_CHK( mbedtls_mpi_sub_mpi(
                         (mbedtls_mpi*)tmp, &getGrp(grp)->P, X ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_safe_cond_assign(
                         X, (mbedtls_mpi*)tmp, nonzero & (cond) ) );

cleanup:
    ECP_ARITH_END();
    return( ret );
}

#endif /* ecp_arith_wrapper_fixsize_heap.h */
