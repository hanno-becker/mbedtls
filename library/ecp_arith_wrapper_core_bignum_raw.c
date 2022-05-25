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

#include "mbedtls/build_info.h"
#include "mbedtls/ecp.h"

#include "constant_time_internal.h"

#include "bignum_core.h"
#include "bignum_internal.h"

/*
 *
 * Type definitions for internal ECP/MPI interface
 *
 */

#define ECP_ARITH_WRAPPER_NUM_MPI_TEMPS 5
#define ECP_ARITH_WRAPPER_NUM_PT_INPUTS 2

//#define ECP_NO_RANDOMIZATION_BEFORE_NORMALIZATION
//#define ECP_NO_RANDOMIZATION_OF_COMB_TABLE

/* Coordinates */
typedef mbedtls_mpi_uint mbedtls_ecp_mpi_internal[];

/* Points */
typedef struct mbedtls_ecp_point_internal
{
    mbedtls_ecp_mpi_internal *X, *Y, *Z;
} mbedtls_ecp_point_internal;

/* Groups */
typedef struct mbedtls_ecp_group_internal
{
    mbedtls_ecp_group       *src;
    int montgomery;

    mbedtls_mpi_uint    *mempool;
    size_t            mempool_sz;

    mbedtls_ecp_mpi_internal *     P;     /* Underlying prime (referenced)     */
    size_t Pn;                            /* Number of limbs in P.             */

    mbedtls_ecp_mpi_internal *    RP;     /* Montgomery constant (referenced)  */

    mbedtls_ecp_point_internal G;
    mbedtls_ecp_mpi_internal *     A;     /* A coordinate (in Montgomery form) */
    mbedtls_ecp_mpi_internal *     B;     /* B coordinate (in Montgomery form) */
    mbedtls_ecp_mpi_internal *   tmp;     /* Temporary for modular arithmetic         */

    mbedtls_mpi_uint *             T;     /* Temporary for Montgomery multiplication. */
    mbedtls_mpi_uint *        lookup;     /* Temporary for table lookup */

    /* Temporaries for ECP arithmetic */
    mbedtls_ecp_point_internal inputs[ECP_ARITH_WRAPPER_NUM_PT_INPUTS];
    mbedtls_ecp_mpi_internal * locals[ECP_ARITH_WRAPPER_NUM_MPI_TEMPS];

    mbedtls_mpi_uint   mm;

} mbedtls_ecp_group_internal;

/* static void mpi_buf_print( const char *p, mbedtls_mpi_buf m ) */
/* { */
/*     mbedtls_mpi x = { .s = 1, .p = m.p, .n = m.n }; */
/*     fprintf( stderr, "=== PRINT BUF %s, len %u\n", p, (unsigned) m.n  ); */
/*     mbedtls_mpi_write_file( p, &x, 16, NULL ); */
/* } */
//#define mpi_buf_print(a,b) do {} while( 0 )

#define UNUSED __attribute__((unused))

/*
 *
 * Implementation of internal API
 *
 */

/*
 * Getters
 */
#define getX(pt)    ((pt)->X)
#define getY(pt)    ((pt)->Y)
#define getZ(pt)    ((pt)->Z)

#define getA(grp)   ((grp)->A)
#define getB(grp)   ((grp)->B)
#define getG(grp)   (&((grp)->G))

#define getGrp(grp) ((grp)->src)

/*
 * Temporaries
 */

#define ecp_grp_input_idx_P 0
#define ecp_grp_input_idx_Q 1

/* The internal ECP group structure pre-allocates a single array of
 * temporaries available to the curve arithmetic routines.
 *
 * Here, we statically map those temporaries to indices in this array.
 * Obviously, one has to be careful here and make sure that nested calls
 * don't use the same temporary. An alternative would be a dynamic stack
 * tracked within the ECP group structure, but considering the rather
 * small number of temporaries, this seems unnecessary.
 *
 * Note also that messing this up will most likely lead to functionally
 * incorrect results, so will be caught by tests. */

#define ecp_grp_tmp_idx_normalize_jac_T      0
#define ecp_grp_tmp_idx_normalize_jac_many_t 0
#define ecp_grp_tmp_idx_double_jac_t0        0
#define ecp_grp_tmp_idx_double_jac_t1        1
#define ecp_grp_tmp_idx_double_jac_t2        2
#define ecp_grp_tmp_idx_double_jac_t3        3
#define ecp_grp_tmp_idx_add_mixed_t0         0
#define ecp_grp_tmp_idx_add_mixed_t1         1
#define ecp_grp_tmp_idx_add_mixed_t2         2
#define ecp_grp_tmp_idx_add_mixed_t3         3
#define ecp_grp_tmp_idx_randomize_jac_l      0
#define ecp_grp_tmp_idx_check_pubkey_sw_YY   0
#define ecp_grp_tmp_idx_check_pubkey_sw_RHS  1

#define ecp_grp_tmp_idx_mul_mxz_PX           0
/* mul_mxz calls double_add_mxz */
#define   ecp_grp_tmp_idx_double_add_mxz_t0    1
#define   ecp_grp_tmp_idx_double_add_mxz_t1    2
#define   ecp_grp_tmp_idx_double_add_mxz_t2    3
#define   ecp_grp_tmp_idx_double_add_mxz_t3    4
/* mul_mxz calls randomixe_mxz */
#define   ecp_grp_tmp_idx_randomize_mxz_l      1

/* Point */
#define ECP_DECL_TEMP_POINT_TMP(ctx,x) x ## _tmp
#define ECP_DECL_TEMP_POINT(ctx,x)                                      \
    mbedtls_ecp_point_internal ECP_DECL_TEMP_POINT_TMP(ctx,x);          \
    mbedtls_ecp_point_internal * const x =                              \
        &ECP_DECL_TEMP_POINT_TMP(ctx,x);
#define ECP_SETUP_TEMP_POINT(x)                                         \
    MBEDTLS_MPI_CHK( mbedtls_ecp_point_internal_alloc( grp, x ) )
#define ECP_FREE_TEMP_POINT(x)                                          \
    mbedtls_ecp_point_internal_free( x )

/* Single width coordinate                                             */

#define ECP_DECL_TEMP_MPI(ctx,x)                                        \
    mbedtls_ecp_mpi_internal * const x =                                \
        grp->locals[ecp_grp_tmp_idx_ ## ctx ## _ ## x]
#define ECP_SETUP_TEMP_MPI(x) do {} while(0)
#define ECP_FREE_TEMP_MPI(x)  do {} while(0)

/* Dynamic array of single width coordinates                           */

#define ECP_DECL_TEMP_MPI_DYNAMIC_ARRAY(x)                              \
    mbedtls_ecp_mpi_internal **x = NULL;
#define ECP_SETUP_TEMP_MPI_DYNAMIC_ARRAY(x,n)                           \
    do {                                                                \
        x = mbedtls_calloc( (n), sizeof( *x ) );                        \
        if( x == NULL )                                                 \
        {                                                               \
            ret = MBEDTLS_ERR_ECP_ALLOC_FAILED;                         \
            goto cleanup;                                               \
        }                                                               \
        mbedtls_ecp_mpi_internal_init_many( x, (n) );                   \
        MBEDTLS_MPI_CHK( mbedtls_ecp_mpi_internal_alloc_many(           \
                             grp, x, (n) ) );                           \
    } while( 0 )
#define ECP_FREE_TEMP_MPI_DYNAMIC_ARRAY(x,n)                            \
    do {                                                                \
        mbedtls_ecp_mpi_internal_free_many( x, (n) );                   \
        mbedtls_free( x );                                              \
    } while( 0 )

#define getItem(c,i) (c)[(i)]

/*
 * Conversions
 */

#define ECP_INTERNAL_INPUT(x)    \
    & ECP_INTERNAL_GROUP(grp)->inputs[ecp_grp_input_idx_ ## x]
#define ECP_DECL_INTERNAL_INPUT(x) do {} while(0)
#define ECP_CONVERT_INPUT(x)                                            \
    MBEDTLS_MPI_CHK( mbedtls_ecp_point_internal_setup_copy(             \
             ECP_INTERNAL_GROUP(grp), ECP_INTERNAL_INPUT(x), x ) )
#define ECP_FREE_INTERNAL_INPUT(x) do {} while(0)

/* Output point                                                        */

#define ECP_INTERNAL_OUTPUT_TMP(x) x ## _tmp
#define ECP_INTERNAL_OUTPUT(x)  (& ECP_INTERNAL_OUTPUT_TMP(x))
#define ECP_DECL_INTERNAL_OUTPUT(x)                                          \
    mbedtls_ecp_point_internal ECP_INTERNAL_OUTPUT_TMP(x)
#define ECP_CONVERT_OUTPUT(x)                                                \
    MBEDTLS_MPI_CHK( mbedtls_ecp_point_internal_setup_ref(                   \
                ECP_INTERNAL_GROUP(grp), ECP_INTERNAL_OUTPUT(x), x ) )
#define ECP_SAVE_INTERNAL_OUTPUT(x)                                          \
    MBEDTLS_MPI_CHK( mbedtls_ecp_point_internal_convert_data_inv(            \
                ECP_INTERNAL_GROUP(grp), ECP_INTERNAL_OUTPUT(x) ) )
#define ECP_FREE_INTERNAL_OUTPUT(x) do {} while(0)

/* In/Out point                                                         */

#define ECP_INTERNAL_INOUT_TMP(x) x ## _tmp
#define ECP_INTERNAL_INOUT(x)  (& ECP_INTERNAL_INOUT_TMP(x))
#define ECP_DECL_INTERNAL_INOUT(x)                                           \
    mbedtls_ecp_point_internal ECP_INTERNAL_INOUT_TMP(x)
#define ECP_CONVERT_INOUT(x)                                                 \
    MBEDTLS_MPI_CHK( mbedtls_ecp_point_internal_setup_ref(                   \
           ECP_INTERNAL_GROUP(grp), ECP_INTERNAL_INOUT(x), x ) )
#define ECP_SAVE_INTERNAL_INOUT(x)                                           \
    MBEDTLS_MPI_CHK( mbedtls_ecp_point_internal_convert_data_inv(            \
                         ECP_INTERNAL_GROUP(grp), ECP_INTERNAL_INOUT(x) ) )
#define ECP_FREE_INTERNAL_INOUT(x) do {} while(0)

/* Group                                                                */

#define ECP_INTERNAL_GROUP_TMP(x) x ## _tmp
#define ECP_INTERNAL_GROUP(x) (&ECP_INTERNAL_GROUP_TMP(x))
#define ECP_DECL_INTERNAL_GROUP(x)                                            \
    mbedtls_ecp_group_internal ECP_INTERNAL_GROUP_TMP(x);                     \
    mbedtls_ecp_group_internal_init( ECP_INTERNAL_GROUP(x) )
#define ECP_CONVERT_GROUP(x)                                                  \
    MBEDTLS_MPI_CHK( mbedtls_ecp_group_internal_setup(                        \
                         ECP_INTERNAL_GROUP(x), x ) )
#define ECP_SAVE_INTERNAL_GROUP(x) do {} while( 0 )
#define ECP_FREE_INTERNAL_GROUP(x)                                            \
    mbedtls_ecp_group_internal_free( ECP_INTERNAL_GROUP(x) )

/*
 * Macro wrappers around ECP modular arithmetic
 */

/* Coordinate arithmetic */
#define ECP_MPI_ADD( X, A, B )                                                 \
    MBEDTLS_MPI_CHK( ecp_mpi_add( (X), (A), (B), grp ) )
#define ECP_MPI_ADD_D( X, B )                                                  \
    MBEDTLS_MPI_CHK( ecp_mpi_add_d( (X), (B), grp ) )
#define ECP_MPI_SUB( X, A, B )                                                 \
    MBEDTLS_MPI_CHK( ecp_mpi_sub( (X), (A), (B), grp ) )
#define ECP_MPI_SUB_D( X, B )                                                  \
    MBEDTLS_MPI_CHK( ecp_mpi_sub_d( (X), (B), grp ) )
#define ECP_MPI_MUL( X, A, B )                                                 \
    MBEDTLS_MPI_CHK( ecp_mpi_mul( (X), (A), (B), grp ) )
#define ECP_MPI_MUL_D( X, B )                                                  \
    MBEDTLS_MPI_CHK( ecp_mpi_mul_d( (X), (B), grp ) )
#define ECP_MPI_ZERO( X )                                                      \
    MBEDTLS_MPI_CHK( ecp_mpi_zero( (X), grp ) )
#define ECP_ZERO( X )                                                          \
    MBEDTLS_MPI_CHK( ecp_point_internal_zero( (X), grp ) )
#define ECP_MPI_INV( D, S )                                                    \
    MBEDTLS_MPI_CHK( ecp_mpi_inv( (D), (S), grp ) )
#define ECP_MPI_MOV( X, A )                                                    \
    MBEDTLS_MPI_CHK( ecp_mpi_copy( (X), (A), grp ) )
#define ECP_MOV( D, S )                                                        \
    MBEDTLS_MPI_CHK( ecp_copy( (D), (S), grp ) )
#define ECP_MPI_SET1( X )                                                      \
    MBEDTLS_MPI_CHK( ecp_mpi_set1( (X), grp ) )
#define ECP_MPI_CMP( X, Y, result )                                            \
    MBEDTLS_MPI_CHK( ecp_mpi_cmp( (X), (Y), (result), grp ) )
#define ECP_MPI_RAND( X )                                                      \
    MBEDTLS_MPI_CHK( ecp_mpi_rand( (X), f_rng, p_rng, grp ) )
#define ECP_MPI_NEG( X )                                                       \
    MBEDTLS_MPI_CHK( ecp_mpi_neg( (X), grp ) )
#define ECP_MPI_VALID( X )                                                     \
    ((X) != NULL)
#define ECP_MPI_COND_NEG( X, cond )                                            \
    MBEDTLS_MPI_CHK( ecp_mpi_cond_neg( (X), (cond), grp  ) )
#define ECP_MPI_COND_ASSIGN( X, Y, cond )                                      \
    MBEDTLS_MPI_CHK( ecp_mpi_cond_assign( (X), (Y), (cond), grp  ) )
#define ECP_MPI_COND_SWAP( X, Y, cond )                                        \
    MBEDTLS_MPI_CHK( ecp_mpi_cond_swap( (X), (Y), (cond), grp  ) )
#define ECP_MPI_REDUCE(X)                                                      \
    MBEDTLS_MPI_CHK( ecp_mpi_reduce( (X), grp ) )
#define ECP_MPI_IS_ZERO( X, result )                                           \
    MBEDTLS_MPI_CHK( ecp_mpi_is_zero( (X), (result), grp ) )

/* Derived */

#define ECP_MPI_CMP1( X, result )                                              \
    do {                                                                       \
        /* Very roundabout, but this macro is only used once: */               \
        /* Multiple by a non-zero number and check that it    */               \
        /* hasn't changed.                                    */               \
        ECP_MPI_MUL( grp->tmp, grp->RP, (X) );                                 \
        ECP_MPI_CMP( grp->tmp, grp->RP, (result) );                            \
    } while( 0 )
#define ECP_MPI_DOUBLE( X )                                                    \
    ECP_MPI_ADD( (X), (X), (X) )
#define ECP_MPI_MUL3( X, A )                                                   \
    do {                                                                       \
        ECP_MPI_ADD( X, A, A );                                                \
        ECP_MPI_ADD( X, X, A );                                                \
    } while( 0 )
#define ECP_MPI_SQR( X, A )                                                    \
    ECP_MPI_MUL(X,A,A)
#define ECP_MPI_SQR_D( X )                                                     \
    ECP_MPI_MUL_D(X,X)

/*
 * Initialization and freeing of instances of internal ECP/MPI types
 */

static void mbedtls_ecp_mpi_internal_free( mbedtls_ecp_mpi_internal *x )
{
    /* TODO: Zeroize -- but this needs length information */
    mbedtls_free( x );
}

UNUSED
static void mbedtls_ecp_point_internal_init( mbedtls_ecp_point_internal *x )
{
    ((void) x);
}

static void mbedtls_ecp_point_internal_free( mbedtls_ecp_point_internal *pt )
{
    mbedtls_ecp_mpi_internal_free( getX(pt) );
    mbedtls_ecp_mpi_internal_free( getY(pt) );
    mbedtls_ecp_mpi_internal_free( getZ(pt) );
    getX(pt) = getY(pt) = getZ(pt) = NULL;
}

static void mbedtls_ecp_mpi_internal_init_many( mbedtls_ecp_mpi_internal **x,
                                                size_t n )
{
    memset( x, 0, n * sizeof( *x ) );
}
static void mbedtls_ecp_mpi_internal_free_many( mbedtls_ecp_mpi_internal **x,
                                                size_t n )
{
    while( n-- )
    {
        mbedtls_ecp_mpi_internal_free( x[n] );
        x[n] = NULL;
    }
}

static int mbedtls_ecp_mpi_internal_alloc( mbedtls_ecp_group_internal *grp,
                                           mbedtls_ecp_mpi_internal **x )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    MBEDTLS_MPI_CHK( mbedtls_mpi_core_alloc( (mbedtls_mpi_uint**) x, grp->Pn ) );
    ret = 0;
cleanup:
    return( ret );
}


static int mbedtls_ecp_point_internal_alloc( mbedtls_ecp_group_internal *grp,
                                             mbedtls_ecp_point_internal *pt )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    MBEDTLS_MPI_CHK( mbedtls_ecp_mpi_internal_alloc( grp, &getX(pt) ) );
    MBEDTLS_MPI_CHK( mbedtls_ecp_mpi_internal_alloc( grp, &getY(pt) ) );
    MBEDTLS_MPI_CHK( mbedtls_ecp_mpi_internal_alloc( grp, &getZ(pt) ) );
    ret = 0;
cleanup:
    return( ret );
}

UNUSED
static int mbedtls_ecp_point_internal_setup( mbedtls_ecp_group_internal *grp,
                                             mbedtls_ecp_point_internal *pt )
{
    return( mbedtls_ecp_point_internal_alloc( grp, pt ) );
}


static int mbedtls_ecp_mpi_internal_alloc_many( mbedtls_ecp_group_internal *grp,
                                                mbedtls_ecp_mpi_internal **x,
                                                size_t n )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    while( n-- )
        MBEDTLS_MPI_CHK( mbedtls_ecp_mpi_internal_alloc( grp, x++ ) );
    ret = 0;
cleanup:
    return( ret );
}

static int mbedtls_ecp_mpi_internal_convert_data_inv( mbedtls_ecp_group_internal const *grp,
                                                      mbedtls_ecp_mpi_internal *x )
{
    if( grp->montgomery )
    {
        mbedtls_mpi_uint one = 1;
        MPI_CORE(montmul)( *x, *x, &one, 1, *grp->P, grp->Pn, grp->mm, grp->T );
    }
    return( 0 );
}

static int mbedtls_ecp_mpi_internal_convert_data_fwd( mbedtls_ecp_group_internal const *grp,
                                                      mbedtls_ecp_mpi_internal *x )
{
    if( grp->montgomery )
    {
        MPI_CORE(montmul_d)( *x, *grp->RP, *grp->P, grp->Pn, grp->mm, grp->T );
    }
    return( 0 );
}

static int mbedtls_ecp_point_internal_convert_data_inv(
    mbedtls_ecp_group_internal const *grp, mbedtls_ecp_point_internal *pt )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    MBEDTLS_MPI_CHK( mbedtls_ecp_mpi_internal_convert_data_inv( grp, getX(pt) ) );
    MBEDTLS_MPI_CHK( mbedtls_ecp_mpi_internal_convert_data_inv( grp, getY(pt) ) );
    MBEDTLS_MPI_CHK( mbedtls_ecp_mpi_internal_convert_data_inv( grp, getZ(pt) ) );
cleanup:
    return( ret );
}

__attribute__((unused))
static int mbedtls_ecp_point_internal_convert_data_fwd(
    mbedtls_ecp_group_internal const *grp, mbedtls_ecp_point_internal *pt )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    MBEDTLS_MPI_CHK( mbedtls_ecp_mpi_internal_convert_data_fwd(
                         grp, getX(pt) ) );
    MBEDTLS_MPI_CHK( mbedtls_ecp_mpi_internal_convert_data_fwd(
                         grp, getY(pt) ) );
    MBEDTLS_MPI_CHK( mbedtls_ecp_mpi_internal_convert_data_fwd(
                         grp, getZ(pt) ) );
cleanup:
    return( ret );
}

static int mbedtls_ecp_mpi_internal_setup_copy(
    mbedtls_ecp_group_internal *grp,
    mbedtls_ecp_mpi_internal **x,
    mbedtls_mpi const *x_orig )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    size_t limbs = x_orig->n;
    if( limbs > grp->Pn )
        limbs = grp->Pn;

    if( x_orig->p == NULL )
    {
        *x = NULL;
        return( 0 );
    }

    memcpy( **x,         x_orig->p, limbs * ciL );
    memset( **x + limbs, 0, ( grp->Pn - limbs ) * ciL );

    /* Convert to Montgomery presentation */
    MBEDTLS_MPI_CHK( mbedtls_ecp_mpi_internal_convert_data_fwd( grp, *x ) );
    ret = 0;

cleanup:
    return( ret );
}

static int mbedtls_ecp_point_internal_setup_copy(
    mbedtls_ecp_group_internal *grp,
    mbedtls_ecp_point_internal *pt,
    mbedtls_ecp_point const *pt_orig )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    MBEDTLS_MPI_CHK( mbedtls_ecp_mpi_internal_setup_copy(
                         grp, &getX(pt), &pt_orig->X ) );
    MBEDTLS_MPI_CHK( mbedtls_ecp_mpi_internal_setup_copy(
                         grp, &getY(pt), &pt_orig->Y ) );
    MBEDTLS_MPI_CHK( mbedtls_ecp_mpi_internal_setup_copy(
                         grp, &getZ(pt), &pt_orig->Z ) );
    ret = 0;
cleanup:
    return( ret );
}

static int mpi_force_size( mbedtls_mpi *X, size_t limbs );
static int mbedtls_ecp_mpi_internal_setup_ref(
    mbedtls_ecp_group_internal *grp,
    mbedtls_ecp_mpi_internal **x,
    mbedtls_mpi *x_orig )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    MBEDTLS_MPI_CHK( mpi_force_size( x_orig, grp->Pn ) );
    *x = (mbedtls_ecp_mpi_internal*) x_orig->p;
    ret = 0;

    MBEDTLS_MPI_CHK( mbedtls_ecp_mpi_internal_convert_data_fwd( grp, *x  ) );

cleanup:
    return( ret );
}

static void mbedtls_ecp_mpi_internal_setup_raw_ref(
    mbedtls_ecp_group_internal *grp,
    mbedtls_ecp_mpi_internal **x,
    mbedtls_mpi_uint *raw )
{
    ((void) grp);
    *x = (mbedtls_ecp_mpi_internal*) raw;
}

static void mbedtls_ecp_mpi_internal_setup_raw_copy(
    mbedtls_ecp_group_internal *grp,
    mbedtls_ecp_mpi_internal *x,
    mbedtls_mpi_uint const *raw )
{
    memcpy( *x, raw, ciL * grp->Pn );
}

static int mbedtls_ecp_point_internal_setup_ref(
    mbedtls_ecp_group_internal *grp,
    mbedtls_ecp_point_internal *pt,
    mbedtls_ecp_point *pt_orig )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    MBEDTLS_MPI_CHK( mbedtls_ecp_mpi_internal_setup_ref(
                         grp, &getX(pt), &pt_orig->X ) );
    MBEDTLS_MPI_CHK( mbedtls_ecp_mpi_internal_setup_ref(
                         grp, &getY(pt), &pt_orig->Y ) );
    MBEDTLS_MPI_CHK( mbedtls_ecp_mpi_internal_setup_ref(
                         grp, &getZ(pt), &pt_orig->Z ) );

cleanup:
    return( ret );
}

static void mbedtls_ecp_point_internal_setup_raw_ref(
    mbedtls_ecp_group_internal *grp,
    mbedtls_ecp_point_internal *pt,
    mbedtls_mpi_uint *x, mbedtls_mpi_uint *y, mbedtls_mpi_uint *z )
{
    mbedtls_ecp_mpi_internal_setup_raw_ref( grp, &getX(pt), x );
    mbedtls_ecp_mpi_internal_setup_raw_ref( grp, &getY(pt), y );
    mbedtls_ecp_mpi_internal_setup_raw_ref( grp, &getZ(pt), z );
}

#if defined(MBEDTLS_ECP_INTERNAL_ALT)
/* TODO */
#endif /* MBEDTLS_ECP_INTERNAL_ALT */

/*
 *
 * Implementation details
 *
 */

/*
 * Init / Setup / Free functions
 */

/* Coordinates */

static int mpi_force_size( mbedtls_mpi *X, size_t limbs )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    MBEDTLS_MPI_CHK( mbedtls_mpi_shrink( X, limbs ) );
    if( X->n != limbs )
        return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );
cleanup:
    return( ret );
}

/* Groups */

static void mbedtls_ecp_group_internal_init( mbedtls_ecp_group_internal *grp )
{
    memset( grp, 0, sizeof( *grp ) );
}

static void mbedtls_ecp_group_internal_free(
    mbedtls_ecp_group_internal *grp )
{
    mbedtls_platform_zeroize( grp->mempool, grp->mempool_sz );
    mbedtls_free( grp->mempool );
    mbedtls_platform_zeroize( grp, sizeof( *grp ) );
}

static int ecp_group_internal_selftest( mbedtls_ecp_group_internal *grp );
static int mbedtls_ecp_group_internal_setup(
    mbedtls_ecp_group_internal *grp,
    mbedtls_ecp_group *src )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_mpi_uint *mempool = NULL;
    grp->src = src;

    grp->montgomery = ( getGrp(grp)->modp_raw == NULL );

    size_t Pn  = getGrp(grp)->P.n;
    int have_A = ( getGrp(grp)->A.p != NULL );
    int have_B = ( getGrp(grp)->B.p != NULL );

    size_t mempool_limbs = Pn * 1      /* tmp */           +
                           Pn * 2 + 1  /* montmul temp */  +
                           Pn * 3;     /* G.{X,Y,Z}    */

    mempool_limbs += Pn * ( have_A + have_B );
    mempool_limbs += 1 * Pn * ECP_ARITH_WRAPPER_NUM_MPI_TEMPS;
    mempool_limbs += 3 * Pn * ECP_ARITH_WRAPPER_NUM_PT_INPUTS;

    /* P is referenced, not copied. */
    grp->P = (mbedtls_ecp_mpi_internal*) getGrp(grp)->P.p;
    grp->Pn = Pn;

    /* Fetch / compute Montgomery constants */
    size_t throwaway;
    mbedtls_ecp_curve_get_rp( getGrp(grp)->id,
                              (const mbedtls_mpi_uint**) &grp->RP,
                              &throwaway );
    MBEDTLS_MPI_CHK( mbedtls_mpi_core_mont_init( &grp->mm, (*grp->P)[0] ) );

    size_t mempool_sz = mempool_limbs * sizeof( mbedtls_mpi_uint );
    MBEDTLS_MPI_CHK( mbedtls_mpi_core_alloc( &mempool, mempool_limbs ) );
    grp->mempool    = mempool;
    grp->mempool_sz = mempool_sz;
    mbedtls_mpi_uint *cur = mempool;

    grp->tmp = (mbedtls_ecp_mpi_internal*) cur; cur += 1 * Pn;
    grp->G.X = (mbedtls_ecp_mpi_internal*) cur; cur += 1 * Pn;
    grp->G.Y = (mbedtls_ecp_mpi_internal*) cur; cur += 1 * Pn;
    grp->G.Z = (mbedtls_ecp_mpi_internal*) cur; cur += 1 * Pn;
    grp->T   = cur;                             cur += 2 * Pn + 1;

    grp->lookup = grp->T;

    MBEDTLS_MPI_CHK( mbedtls_ecp_point_internal_setup_copy(
                         grp, &grp->G, &getGrp(grp)->G ) );

    /* NIST curves omit A as a shortcut for A=-3 */
    if( have_A )
    {
        grp->A = (mbedtls_ecp_mpi_internal*) cur; cur += 1 * Pn;
        MBEDTLS_MPI_CHK( mbedtls_ecp_mpi_internal_setup_copy(
                             grp, &grp->A, &getGrp(grp)->A ) );
    }
    else
        grp->A = NULL;

    /* Curve25519 and Curve448 don't use B */
    if( have_B )
    {
        grp->B = (mbedtls_ecp_mpi_internal*) cur; cur += 1 * Pn;
        MBEDTLS_MPI_CHK( mbedtls_ecp_mpi_internal_setup_copy(
                             grp, &grp->B, &getGrp(grp)->B ) );
    }
    else
        grp->B = NULL;

    for( unsigned i=0; i < ECP_ARITH_WRAPPER_NUM_MPI_TEMPS; i++ )
    {
        grp->locals[i] = (mbedtls_ecp_mpi_internal*) cur; cur += Pn;
    }
    for( unsigned i=0; i < ECP_ARITH_WRAPPER_NUM_PT_INPUTS; i++ )
    {
        grp->inputs[i].X = (mbedtls_ecp_mpi_internal*) cur; cur += Pn;
        grp->inputs[i].Y = (mbedtls_ecp_mpi_internal*) cur; cur += Pn;
        grp->inputs[i].Z = (mbedtls_ecp_mpi_internal*) cur; cur += Pn;
    }

    MBEDTLS_MPI_CHK( ecp_group_internal_selftest( grp ) );

cleanup:
    return( ret );
}

/*
 * Modular arithmetic wrappers
 */

__attribute__((noinline))
static int ecp_mpi_add( mbedtls_ecp_mpi_internal *X,
                        mbedtls_ecp_mpi_internal const *A,
                        mbedtls_ecp_mpi_internal const *B,
                        mbedtls_ecp_group_internal const *grp )
{
    MPI_CORE(add_mod)( (*X), (*A), *(B), *grp->P, grp->Pn );
    return( 0 );
}

__attribute__((noinline))
static int ecp_mpi_add_d( mbedtls_ecp_mpi_internal *X,
                          mbedtls_ecp_mpi_internal const  *B,
                          mbedtls_ecp_group_internal const *grp )
{
    MPI_CORE(add_mod_d)( (*X), *(B), *grp->P, grp->Pn );
    return( 0 );
}

__attribute__((noinline))
static int ecp_mpi_sub( mbedtls_ecp_mpi_internal *X,
                        mbedtls_ecp_mpi_internal const *A,
                        mbedtls_ecp_mpi_internal const *B,
                        mbedtls_ecp_group_internal const *grp )
{
    MPI_CORE(sub_mod)( (*X), (*A), *(B), *grp->P, grp->Pn );
    return( 0 );
}

__attribute__((noinline))
static int ecp_mpi_sub_d( mbedtls_ecp_mpi_internal *X,
                          mbedtls_ecp_mpi_internal const *B,
                          mbedtls_ecp_group_internal const *grp )
{
    MPI_CORE(sub_mod_d)( (*X), *(B), *grp->P, grp->Pn );
    return( 0 );
}

__attribute__((noinline))
static int ecp_mpi_mul( mbedtls_ecp_mpi_internal *X,
                        mbedtls_ecp_mpi_internal const *A,
                        mbedtls_ecp_mpi_internal const *B,
                        mbedtls_ecp_group_internal const *grp )
{
    if( grp->montgomery )
    {
        MPI_CORE(montmul)( *X, *A, *B, grp->Pn, *grp->P, grp->Pn, grp->mm, grp->T );
        return( 0 );
    }

    /* Schoolbook multiplication followed by dedicated reduction */
    MPI_CORE(mul)( grp->T, *A, grp->Pn, *B, grp->Pn );
    getGrp(grp)->modp_raw( grp->T, 2 * grp->Pn );

    mbedtls_mpi_uint borrow, fixup, carry;
    carry = grp->T[grp->Pn];
    /* TODO: Double-check that carry is never greater than 1? */
    borrow = MPI_CORE(sub)( *X, grp->T, *grp->P, grp->Pn );
    fixup = ( carry < borrow );
    (void) MPI_CORE(add_if)( *X, *grp->P, grp->Pn, fixup );
    return( 0 );
}

__attribute__((noinline))
static int ecp_mpi_mul_d( mbedtls_ecp_mpi_internal *X,
                          mbedtls_ecp_mpi_internal const *B,
                          mbedtls_ecp_group_internal const *grp )
{
    return( ecp_mpi_mul( X, X, B, grp ) );
}

__attribute__((noinline))
static int ecp_mpi_inv( mbedtls_ecp_mpi_internal *D,
                        mbedtls_ecp_mpi_internal const *S,
                        mbedtls_ecp_group_internal const *grp )
{
    MPI_CORE(inv_mod_prime)( *D, *S, *grp->P, grp->Pn, *grp->RP );
    if( grp->montgomery )
    {
        mbedtls_ecp_mpi_internal_convert_data_fwd( grp, D );
        mbedtls_ecp_mpi_internal_convert_data_fwd( grp, D );
    }
    return( 0 );
}

__attribute__((noinline))
static int ecp_mpi_copy( mbedtls_ecp_mpi_internal *X,
                         mbedtls_ecp_mpi_internal const *A,
                         mbedtls_ecp_group_internal const *grp )
{
    memcpy( *X, *A, ciL * grp->Pn );
    return( 0 );
}

__attribute__((noinline))
static int ecp_mpi_reduce( mbedtls_ecp_mpi_internal *X,
                           mbedtls_ecp_group_internal const *grp )
{
    MPI_CORE(mod_reduce)( *X, *X, grp->Pn, *grp->P, grp->Pn, *grp->RP );
    return( 0 );
}

static int ecp_copy( mbedtls_ecp_point_internal *x,
                     mbedtls_ecp_point_internal const *y,
                     mbedtls_ecp_group_internal const *grp )
{
    size_t len = ciL * grp->Pn;
    memcpy( getX(x), getX(y), len );
    memcpy( getZ(x), getZ(y), len );
    /* In x/z coordinates, y is unset */
    if( ECP_MPI_VALID( getY(y) ) )
        memcpy( getY(x), getY(y), len );
    return( 0 );
}

__attribute__((noinline))
static int ecp_mpi_zero( mbedtls_ecp_mpi_internal *X,
                         mbedtls_ecp_group_internal const *grp )
{
    memset( *X, 0, ciL * grp->Pn );
    return( 0 );
}

static int ecp_mpi_set1( mbedtls_ecp_mpi_internal *X,
                         mbedtls_ecp_group_internal const *grp )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    ECP_MPI_ZERO( X );
    (*X)[0] = 1;
    mbedtls_ecp_mpi_internal_convert_data_fwd( grp, X );
    ret = 0;
cleanup:
    return( ret );
}

__attribute__((noinline))
static int ecp_point_internal_zero( mbedtls_ecp_point_internal *X,
                                    mbedtls_ecp_group_internal const *grp )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    ECP_MPI_SET1( getX(X) );
    if( ECP_MPI_VALID( getY(X) ) )
        ECP_MPI_SET1( getY(X) );
    ECP_MPI_ZERO( getZ(X) );
    ret = 0;
cleanup:
    return( ret );
}

static int ecp_mpi_cmp( mbedtls_ecp_mpi_internal *X,
                        mbedtls_ecp_mpi_internal const *Y,
                        int *result,
                        mbedtls_ecp_group_internal const *grp )
{
    *result = mbedtls_ct_memcmp( *X, *Y, ciL * grp->Pn );
    return( 0 );
}

static int ecp_mpi_rand( mbedtls_ecp_mpi_internal *X,
                         int (*f_rng)(void *, unsigned char *, size_t), void *p_rng,
                         mbedtls_ecp_group_internal const *grp )
{
    return( MPI_CORE(random_range_be)(
                *X, 2, *grp->P, grp->Pn, getGrp(grp)->pbits, f_rng, p_rng ) );
}

static int ecp_mpi_neg( mbedtls_ecp_mpi_internal *X,
                        mbedtls_ecp_group_internal const *grp )
{
    MPI_CORE(neg_mod)( *X, *X, *grp->P, grp->Pn );
    return( 0 );
}

static int ecp_mpi_cond_assign( mbedtls_ecp_mpi_internal *X,
                                mbedtls_ecp_mpi_internal const *Y,
                                int cond,
                                mbedtls_ecp_group_internal const *grp  )
{
    mbedtls_ct_mpi_uint_cond_assign( grp->Pn, *X, *Y, cond );
    return( 0 );
}

static int ecp_mpi_cond_neg( mbedtls_ecp_mpi_internal *X, int cond,
                             mbedtls_ecp_group_internal const *grp )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    ECP_MPI_MOV( grp->tmp, X );
    ECP_MPI_NEG( grp->tmp );
    ECP_MPI_COND_ASSIGN( X, grp->tmp, cond );
    ret = 0;
cleanup:
    return( ret );
}

static int ecp_mpi_cond_swap( mbedtls_ecp_mpi_internal *X,
                              mbedtls_ecp_mpi_internal *Y, int cond,
                              mbedtls_ecp_group_internal const *grp  )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    ECP_MPI_MOV( grp->tmp, X );
    ECP_MPI_COND_ASSIGN( grp->tmp, Y, cond );
    ECP_MPI_COND_ASSIGN( Y, X, cond );
    ECP_MPI_MOV( X, grp->tmp );
    ret = 0;
cleanup:
    return( ret );
}

static int ecp_mpi_is_zero( mbedtls_ecp_mpi_internal *X, int *result,
                            mbedtls_ecp_group_internal const *grp )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    ECP_MPI_ZERO( grp->tmp );
    ECP_MPI_CMP( X, grp->tmp, result );
    ret = 0;
cleanup:
    return( ret );
}

static int ecp_group_internal_selftest( mbedtls_ecp_group_internal *grp )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    ECP_DECL_TEMP_MPI(double_add_mxz, t0);
    ECP_DECL_TEMP_MPI(double_add_mxz, t1);
    ECP_DECL_TEMP_MPI(double_add_mxz, t2);
    ECP_DECL_TEMP_MPI(double_add_mxz, t3);
    ECP_SETUP_TEMP_MPI(t0);
    ECP_SETUP_TEMP_MPI(t1);
    ECP_SETUP_TEMP_MPI(t2);
    ECP_SETUP_TEMP_MPI(t3);

    ECP_MPI_SET1(t0);
    ECP_MPI_SET1(t1);
    ECP_MPI_SET1(t2);
    ECP_MPI_MOV(t3,grp->RP);
    ECP_MPI_MUL(t2,t3,t0);
    int cmp;
    ECP_MPI_CMP(t2,t3,&cmp);
    if( cmp != 0 )
    {
        fprintf( stderr, "SELF TEST FAIL!\n" );
        return( 1 );
    }

cleanup:
    ECP_FREE_TEMP_MPI(t0);
    ECP_FREE_TEMP_MPI(t1);
    ECP_FREE_TEMP_MPI(t2);
    ECP_FREE_TEMP_MPI(t3);
    return( ret );
}

#if defined(MBEDTLS_SELF_TEST)
#define INC_MUL_COUNT   mul_count++;
#else
#define INC_MUL_COUNT
#endif
