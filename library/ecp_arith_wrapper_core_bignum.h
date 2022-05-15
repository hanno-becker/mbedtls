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

#ifndef MBEDTLS_ECP_ARITH_WRAPPER_CORE_BIGNUM_H
#define MBEDTLS_ECP_ARITH_WRAPPER_CORE_BIGNUM_H

#include "mbedtls/build_info.h"
#include "mbedtls/ecp.h"

#include "constant_time_internal.h"

#include "ecp_arith_wrapper_core_bignum_typedefs.h"

/* static void mpi_buf_print( const char *p, mbedtls_mpi_buf m ) */
/* { */
/*     mbedtls_mpi x = { .s = 1, .p = m.p, .n = m.n }; */
/*     fprintf( stderr, "=== PRINT BUF %s, len %u\n", p, (unsigned) m.n  ); */
/*     mbedtls_mpi_write_file( p, &x, 16, NULL ); */
/* } */
#define mpi_buf_print(a,b) do {} while( 0 )


/*
 *
 * Implementation of internal API
 *
 */

/*
 * Getters
 */
#define getX(pt)    (&((pt)->X))
#define getY(pt)    (&((pt)->Y))
#define getZ(pt)    (&((pt)->Z))

#define getA(grp)   ((mbedtls_ecp_mpi_internal   const*)(&((grp)->A)))
#define getB(grp)   ((mbedtls_ecp_mpi_internal   const*)(&((grp)->B)))
#define getG(grp)   ((mbedtls_ecp_point_internal const*)(&((grp)->G)))

#define getGrp(grp) ((grp)->src)


/*
 * Temporaries
 */

#if defined(ECP_ARITH_WRAPPER_CORE_BIGNUM_LOCAL_TEMPORARIES)

/* Point */
#define ECP_DECL_TEMP_POINT_TMP(ctx,x) x ## _tmp
#define ECP_DECL_TEMP_POINT(ctx,x)                                          \
    mbedtls_ecp_point_internal              ECP_DECL_TEMP_POINT_TMP(ctx,x); \
    mbedtls_ecp_point_internal * const x = &ECP_DECL_TEMP_POINT_TMP(ctx,x); \
    mbedtls_ecp_point_internal_init( x )
#define ECP_SETUP_TEMP_POINT(x)                                     \
    MBEDTLS_MPI_CHK( mbedtls_ecp_point_internal_alloc( grp, x ) )
#define ECP_FREE_TEMP_POINT(x)              \
    mbedtls_ecp_point_internal_free( x )

/* Single width coordinate                                             */

#define ECP_DECL_TEMP_MPI_TMP(ctx,x) x ## _tmp
#define ECP_DECL_TEMP_MPI(ctx,x)                                          \
    mbedtls_ecp_mpi_internal              ECP_DECL_TEMP_MPI_TMP(ctx,x);   \
    mbedtls_ecp_mpi_internal * const x = &ECP_DECL_TEMP_MPI_TMP(ctx,x);   \
    mbedtls_ecp_mpi_internal_init( x )
#define ECP_SETUP_TEMP_MPI(x)                                             \
    MBEDTLS_MPI_CHK( mbedtls_ecp_mpi_internal_alloc( grp, x ) )
#define ECP_FREE_TEMP_MPI(x)                                              \
    mbedtls_ecp_mpi_internal_free( x )

#elif defined(ECP_ARITH_WRAPPER_CORE_BIGNUM_GLOBAL_TEMPORARIES)

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
        &ECP_DECL_TEMP_POINT_TMP(ctx,x);                                \
    mbedtls_ecp_point_internal_init( x )
#define ECP_SETUP_TEMP_POINT(x)                                         \
    MBEDTLS_MPI_CHK( mbedtls_ecp_point_internal_alloc( grp, x ) )
#define ECP_FREE_TEMP_POINT(x)                                          \
    mbedtls_ecp_point_internal_free( x )

/* Single width coordinate                                             */

#define ECP_DECL_TEMP_MPI(ctx,x)                                        \
    mbedtls_ecp_mpi_internal * const x =                                \
        &grp->locals[ecp_grp_tmp_idx_ ## ctx ## _ ## x]
#define ECP_SETUP_TEMP_MPI(x) do {} while( 0 )
#define ECP_FREE_TEMP_MPI(x)  do {} while ( 0)

#endif

/* Dynamic array of single width coordinates                           */

#define ECP_DECL_TEMP_MPI_DYNAMIC_ARRAY(x)                              \
    mbedtls_ecp_mpi_internal *x = NULL;
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

#define getItem(c,i) &(c)[(i)]

/*
 * Conversions
 */

#if defined(ECP_ARITH_WRAPPER_CORE_BIGNUM_LOCAL_TEMPORARIES)

/* Input point                                                         */

#define ECP_INTERNAL_INPUT_TMP(x) x ## _tmp
#define ECP_INTERNAL_INPUT(x)  (& ECP_INTERNAL_INPUT_TMP(x))
#define ECP_DECL_INTERNAL_INPUT(x) \
    mbedtls_ecp_point_internal ECP_INTERNAL_INPUT_TMP(x);               \
    mbedtls_ecp_point_internal_init( ECP_INTERNAL_INPUT(x) )
#define ECP_CONVERT_INPUT(x)                                            \
    MBEDTLS_MPI_CHK( mbedtls_ecp_point_internal_setup_copy(             \
            ECP_INTERNAL_GROUP(grp), ECP_INTERNAL_INPUT(x), x, 1 ) )
#define ECP_FREE_INTERNAL_INPUT(x)                                      \
    mbedtls_ecp_point_internal_input_free( ECP_INTERNAL_INPUT(x) )

#elif defined(ECP_ARITH_WRAPPER_CORE_BIGNUM_GLOBAL_TEMPORARIES)

#define ECP_INTERNAL_INPUT(x)    \
    & ECP_INTERNAL_GROUP(grp)->inputs[ecp_grp_input_idx_ ## x]
#define ECP_DECL_INTERNAL_INPUT(x) do {} while(0)
#define ECP_CONVERT_INPUT(x)                                            \
    MBEDTLS_MPI_CHK( mbedtls_ecp_point_internal_setup_copy(             \
             ECP_INTERNAL_GROUP(grp), ECP_INTERNAL_INPUT(x), x, 0 ) )
#define ECP_FREE_INTERNAL_INPUT(x)                                      \
    mbedtls_ecp_point_internal_input_free( ECP_INTERNAL_INPUT(x) )

/* #define ECP_INTERNAL_INPUT_TMP(x) x ## _tmp */
/* #define ECP_INTERNAL_INPUT(x)     & ECP_INTERNAL_INPUT_TMP(x) */
/* #define ECP_DECL_INTERNAL_INPUT(x)                                      \ */
/*     mbedtls_ecp_point_internal ECP_INTERNAL_INPUT_TMP(x) */
/* #define ECP_CONVERT_INPUT(x)                                            \ */
/*     ECP_INTERNAL_INPUT_TMP(x) =                                         \ */
/*         ECP_INTERNAL_GROUP(grp)->inputs[ecp_grp_input_idx_ ## x];       \ */
/*     MBEDTLS_MPI_CHK( mbedtls_ecp_point_internal_setup_copy(             \ */
/*              ECP_INTERNAL_GROUP(grp), ECP_INTERNAL_INPUT(x), x, 0 ) ) */
/* #define ECP_FREE_INTERNAL_INPUT(x)                                      \ */
/*     mbedtls_ecp_point_internal_input_free( ECP_INTERNAL_INPUT(x) ) */

#endif /* ECP_ARITH_WRAPPER_CORE_BIGNUM_GLOBAL_TEMPORARIES */

/* Output point                                                        */

#define ECP_INTERNAL_OUTPUT_TMP(x) x ## _tmp
#define ECP_INTERNAL_OUTPUT(x)  (& ECP_INTERNAL_OUTPUT_TMP(x))
#define ECP_DECL_INTERNAL_OUTPUT(x)                                          \
    mbedtls_ecp_point_internal ECP_INTERNAL_OUTPUT_TMP(x)
#define ECP_CONVERT_OUTPUT(x)                                                \
    MBEDTLS_MPI_CHK( mbedtls_ecp_point_internal_setup_ref(                   \
                ECP_INTERNAL_GROUP(grp), ECP_INTERNAL_OUTPUT(x), x ) )
#define ECP_SAVE_INTERNAL_OUTPUT(x)                                          \
    MBEDTLS_MPI_CHK( mbedtls_ecp_point_internal_from_mont(                   \
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
    MBEDTLS_MPI_CHK( mbedtls_ecp_point_internal_from_mont(                   \
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

#if defined(ECP_ARITH_WRAPPER_CORE_BIGNUM_BUFS_BY_VALUE)

/* Coordinate arithmetic */
#define ECP_MPI_ADD( X, A, B ) \
    MBEDTLS_MPI_CHK( mbedtls_mpi_core_add_mod( *(X), *(A), *(B), grp->P ) )
#define ECP_MPI_ADD_D( X, B ) \
    MBEDTLS_MPI_CHK( mbedtls_mpi_core_add_mod( *(X), *(X), *(B), grp->P ) )
#define ECP_MPI_SUB( X, A, B ) \
    MBEDTLS_MPI_CHK( mbedtls_mpi_core_sub_mod( *(X), *(A), *(B), grp->P ) )
#define ECP_MPI_SUB_D( X, B ) \
    MBEDTLS_MPI_CHK( mbedtls_mpi_core_sub_mod( *(X), *(X), *(B), grp->P ) )
#define ECP_MPI_MUL( X, A, B )                                                \
    MBEDTLS_MPI_CHK( mbedtls_mpi_core_montmul( *(X), *(A), grp->P,            \
                                               *(B), grp->T, grp->mm ) )
#define ECP_MPI_MUL_D( X, B )                                                 \
    MBEDTLS_MPI_CHK( mbedtls_mpi_core_montmul_d( *(X), grp->P,                \
                                                 *(B), grp->T, grp->mm ) )
#define ECP_MPI_SQR( X, A )                                                   \
    ECP_MPI_MUL(X,A,A)
#define ECP_MPI_SQR_D( X )                                                    \
    ECP_MPI_MUL_D(X,X)
#define ECP_MPI_ZERO( X )                                                     \
    mbedtls_mpi_core_zero_p(X)
#define ECP_MPI_MUL3( X, A )                                                  \
    do {                                                                      \
        ECP_MPI_ADD( (X), (A), (A) );                                         \
        ECP_MPI_ADD( (X), (X), (A) );                                         \
    } while( 0 )
#define ECP_MPI_INV( D, S )                                                   \
    do {                                                                      \
        MBEDTLS_MPI_CHK( mbedtls_mpi_core_inv_mod_prime(                      \
                             *(D), *(S), grp->P, grp->RP ) );                 \
        MBEDTLS_MPI_CHK( mbedtls_ecp_mpi_internal_to_mont( grp, (D) ) );      \
        MBEDTLS_MPI_CHK( mbedtls_ecp_mpi_internal_to_mont( grp, (D) ) );      \
    } while( 0 )
#define ECP_MPI_MOV( X, A )                                                   \
    MBEDTLS_MPI_CHK( mbedtls_mpi_core_copy( *(X), *(A) ) )
#define ECP_MPI_DOUBLE( X )                                                   \
    ECP_MPI_ADD( (X), (X), (X) )
#define ECP_MPI_SET1( X )                                                     \
    do {                                                                      \
        ECP_MPI_ZERO( X );                                                    \
        (X)->p[0] = (1);                                                      \
        MBEDTLS_MPI_CHK( mbedtls_ecp_mpi_internal_to_mont( grp, (X) ) );      \
     } while( 0 )
#define ECP_MPI_CMP( X, Y, result )                                           \
    MBEDTLS_MPI_CHK( mbedtls_mpi_core_cmp( *(X), *(Y), (result) ) )
#define ECP_MPI_RAND( X )                                                     \
    MBEDTLS_MPI_CHK( mbedtls_mpi_core_random_range_be(                        \
         *(X), 2, grp->P, getGrp(grp)->pbits, f_rng, p_rng ) )
#define ECP_MPI_COND_NEG( X, cond )                                           \
    do {                                                                      \
        ECP_MPI_MOV( &grp->tmp, (X) );                                        \
        ECP_MPI_NEG( &grp->tmp );                                             \
        ECP_MPI_COND_ASSIGN( (X), &grp->tmp, cond );                          \
    } while( 0 )
#define ECP_MPI_NEG( X )                                                      \
    MBEDTLS_MPI_CHK( mbedtls_mpi_core_neg_mod( *(X), *(X), grp->P ) )
#define ECP_MPI_VALID( X )                                                    \
    ((X)->p != NULL)
#define ECP_MPI_COND_ASSIGN( X, Y, cond )                                     \
    mbedtls_ct_mpi_uint_cond_assign( (X)->n, (X)->p, (Y)->p, (cond) )
#define ECP_MPI_COND_SWAP( X, Y, cond )                                       \
    MBEDTLS_MPI_CHK( ecp_mpi_cond_swap( grp, (X), (Y), (cond) ) )
#define ECP_MPI_CMP1( X, result )                                             \
    do {                                                                      \
        /* Very roundabout, but this macro is only used once: */              \
        /* Multiple by a non-zero number and check that it    */              \
        /* hasn't changed.                                    */              \
        ECP_MPI_MUL( &grp->tmp, &grp->RP, (X) );                              \
        ECP_MPI_CMP( &grp->tmp, &grp->RP, (result) );                         \
    } while( 0 )
#define ECP_MPI_IS_ZERO( X, result )                                          \
    MBEDTLS_MPI_CHK( ecp_mpi_is_zero( grp, (X), (result) ) )

/* Points */
#define ECP_MOV( D, S )                                                       \
    MBEDTLS_MPI_CHK( ecp_copy( D, S ) )
#define ECP_ZERO( X )                                                          \
    do {                                                                       \
        ECP_MPI_SET1( getX(X) );                                               \
        ECP_MPI_SET1( getY(X) );                                               \
        ECP_MPI_ZERO( getZ(X) );                                               \
    } while( 0 )

#elif defined(ECP_ARITH_WRAPPER_CORE_BIGNUM_BUFS_BY_REF)

/* Coordinate arithmetic */
#define ECP_MPI_ADD( X, A, B )                                                 \
    MBEDTLS_MPI_CHK( mbedtls_mpi_core_add_mod_p( (X), (A), (B), &grp->P ) )
#define ECP_MPI_ADD_D( X, B )                                                  \
    MBEDTLS_MPI_CHK( mbedtls_mpi_core_add_mod_d_p( (X), (B), &grp->P ) )
#define ECP_MPI_SUB( X, A, B )                                                 \
    MBEDTLS_MPI_CHK( mbedtls_mpi_core_sub_mod_p( (X), (A), (B), &grp->P ) )
#define ECP_MPI_SUB_D( X, B )                                                  \
    MBEDTLS_MPI_CHK( mbedtls_mpi_core_sub_mod_d_p( (X), (B), &grp->P ) )
#define ECP_MPI_MUL( X, A, B )                                                 \
    MBEDTLS_MPI_CHK( ecp_mul_mod( (X), (A), (B), grp ) )
#define ECP_MPI_MUL_D( X, B )                                                  \
    MBEDTLS_MPI_CHK( ecp_mul_mod_d( (X), (B), grp ) )
#define ECP_MPI_SQR( X, A )                                                    \
    ECP_MPI_MUL(X,A,A)
#define ECP_MPI_SQR_D( X )                                                     \
    ECP_MPI_MUL_D(X,X)
#define ECP_MPI_ZERO( X )                                                     \
    mbedtls_mpi_core_zero_p(X)
#define ECP_MPI_MUL3( X, A )                                                   \
    do {                                                                       \
        ECP_MPI_ADD( X, A, A );                                                \
        ECP_MPI_ADD( X, X, A );                                                \
    } while( 0 )
#define ECP_MPI_INV( D, S )                                                    \
    MBEDTLS_MPI_CHK( ecp_mpi_inv( grp, (D), (S) ) )
#define ECP_MPI_MOV( X, A )                                                    \
    MBEDTLS_MPI_CHK( mbedtls_mpi_core_copy_p( (X), (A) ) )
#define ECP_MPI_DOUBLE( X )                                                    \
    ECP_MPI_ADD( (X), (X), (X) )
#define ECP_MPI_SET1( X )                                                      \
    do {                                                                       \
        ECP_MPI_ZERO( X );                                                     \
        (X)->p[0] = (1);                                                       \
        MBEDTLS_MPI_CHK( mbedtls_ecp_mpi_internal_to_mont( grp, (X) ) );       \
     } while( 0 )
#define ECP_MPI_CMP( X, Y, result )                                            \
    MBEDTLS_MPI_CHK( mbedtls_mpi_core_cmp_p( (X), (Y), (result) ) )
#define ECP_MPI_RAND( X )                                                      \
    MBEDTLS_MPI_CHK( mbedtls_mpi_core_random_range_be_p(                       \
        (X), 2, &grp->P, getGrp(grp)->pbits, f_rng, p_rng ) )
#define ECP_MPI_COND_NEG( X, cond )                                            \
    do {                                                                       \
        ECP_MPI_MOV( &grp->tmp, (X) );                                         \
        ECP_MPI_NEG( &grp->tmp );                                              \
        ECP_MPI_COND_ASSIGN( (X), &grp->tmp, cond );                           \
    } while( 0 )
#define ECP_MPI_NEG( X )                                                       \
    MBEDTLS_MPI_CHK( mbedtls_mpi_core_neg_mod_p( (X), (X), &grp->P ) )
#define ECP_MPI_VALID( X )                                                     \
    ((X)->p != NULL)
#define ECP_MPI_COND_ASSIGN( X, Y, cond )                                      \
    mbedtls_ct_mpi_uint_cond_assign( (X)->n, (X)->p, (Y)->p, (cond) )
#define ECP_MPI_COND_SWAP( X, Y, cond )                                        \
    MBEDTLS_MPI_CHK( ecp_mpi_cond_swap( grp, (X), (Y), (cond) ) )
#define ECP_MPI_CMP1( X, result )                                              \
    do {                                                                       \
        /* Very roundabout, but this macro is only used once: */               \
        /* Multiple by a non-zero number and check that it    */               \
        /* hasn't changed.                                    */               \
        ECP_MPI_MUL( &grp->tmp, &grp->RP, (X) );                               \
        ECP_MPI_CMP( &grp->tmp, &grp->RP, (result) );                          \
    } while( 0 )
#define ECP_MPI_IS_ZERO( X, result )                                           \
    MBEDTLS_MPI_CHK( ecp_mpi_is_zero( grp, (X), (result) ) )
/* Points */
#define ECP_MOV( D, S )                                                        \
    MBEDTLS_MPI_CHK( ecp_copy( D, S ) )
#define ECP_ZERO( X )                                                          \
    do {                                                                       \
        ECP_MPI_ZERO( getX(X) );                                               \
        ECP_MPI_ZERO( getY(X) );                                               \
        ECP_MPI_ZERO( getZ(X) );                                               \
    } while( 0 )

#endif /* ECP_ARITH_WRAPPER_CORE_BIGNUM_XXX */

/*
 * Initialization and freeing of instances of internal ECP/MPI types
 */

#if defined(ECP_ARITH_WRAPPER_CORE_BIGNUM_LOCAL_TEMPORARIES)
static void mbedtls_ecp_mpi_internal_init( mbedtls_ecp_mpi_internal *x )
{
    memset( x, 0, sizeof( *x ) );
}
#endif

static void mbedtls_ecp_mpi_internal_free( mbedtls_ecp_mpi_internal *x )
{
    mbedtls_free( x->p );
    memset( x, 0, sizeof( *x ) );
}

static void mbedtls_ecp_point_internal_init( mbedtls_ecp_point_internal *x )
{
    memset( x, 0, sizeof( *x ) );
}
static void mbedtls_ecp_point_internal_free( mbedtls_ecp_point_internal *pt )
{
    mbedtls_ecp_mpi_internal_free( getX(pt) );
    mbedtls_ecp_mpi_internal_free( getY(pt) );
    mbedtls_ecp_mpi_internal_free( getZ(pt) );
}

static void mbedtls_ecp_mpi_internal_init_many( mbedtls_ecp_mpi_internal *x,
                                                size_t n )
{
    while( n-- )
        memset( x++, 0, sizeof( *x ) );
}
static void mbedtls_ecp_mpi_internal_free_many( mbedtls_ecp_mpi_internal *x,
                                                  size_t n )
{
    while( n-- )
        mbedtls_ecp_mpi_internal_free( x++ );
}

static int mbedtls_ecp_mpi_internal_alloc( mbedtls_ecp_group_internal *grp,
                                           mbedtls_ecp_mpi_internal *x )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    MBEDTLS_MPI_CHK( mbedtls_mpi_core_alloc( &x->p, grp->P.n ) );
    x->n = grp->P.n;
cleanup:
    return( ret );
}

static int mbedtls_ecp_point_internal_alloc( mbedtls_ecp_group_internal *grp,
                                             mbedtls_ecp_point_internal *pt )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    MBEDTLS_MPI_CHK( mbedtls_ecp_mpi_internal_alloc( grp, getX(pt) ) );
    MBEDTLS_MPI_CHK( mbedtls_ecp_mpi_internal_alloc( grp, getY(pt) ) );
    MBEDTLS_MPI_CHK( mbedtls_ecp_mpi_internal_alloc( grp, getZ(pt) ) );
cleanup:
    return( ret );
}

static int mbedtls_ecp_point_internal_setup( mbedtls_ecp_group_internal *grp,
                                             mbedtls_ecp_point_internal *pt )
{
    return( mbedtls_ecp_point_internal_alloc( grp, pt ) );
}


__attribute__((unused))
static int mbedtls_ecp_point_internal_alloc_many( mbedtls_ecp_group_internal *grp,
                                                  mbedtls_ecp_point_internal *x,
                                                  size_t n )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    while( n-- )
        MBEDTLS_MPI_CHK( mbedtls_ecp_point_internal_alloc( grp, x++ ) );
    ret = 0;
cleanup:
    return( ret );
}

static int mbedtls_ecp_mpi_internal_alloc_many( mbedtls_ecp_group_internal *grp,
                                                mbedtls_ecp_mpi_internal *x,
                                                size_t n )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    while( n-- )
        MBEDTLS_MPI_CHK( mbedtls_ecp_mpi_internal_alloc( grp, x++ ) );
    ret = 0;
cleanup:
    return( ret );
}

static int mbedtls_ecp_mpi_internal_from_mont( mbedtls_ecp_group_internal *grp,
                                               mbedtls_ecp_mpi_internal *x )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_mpi_uint one[] = {1};
    mbedtls_mpi_buf one_buf = { .p = one, .n = 1 };
#if defined(ECP_ARITH_WRAPPER_CORE_BIGNUM_BUFS_BY_VALUE)
    MBEDTLS_MPI_CHK( mbedtls_mpi_core_montmul( *x, *x, grp->P, one_buf, grp->T, grp->mm  ) );
#elif defined(ECP_ARITH_WRAPPER_CORE_BIGNUM_BUFS_BY_REF)
    MBEDTLS_MPI_CHK( mbedtls_mpi_core_montmul_p( x, x, &grp->P, &one_buf, &grp->T, grp->mm  ) );
#endif

cleanup:
    return( ret );
}

static int mbedtls_ecp_mpi_internal_to_mont( mbedtls_ecp_group_internal *grp,
                                             mbedtls_ecp_mpi_internal *x )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
#if defined(ECP_ARITH_WRAPPER_CORE_BIGNUM_BUFS_BY_VALUE)
    MBEDTLS_MPI_CHK( mbedtls_mpi_core_montmul( *x, *x, grp->P, grp->RP, grp->T, grp->mm  ) );
#elif defined(ECP_ARITH_WRAPPER_CORE_BIGNUM_BUFS_BY_REF)
    MBEDTLS_MPI_CHK( mbedtls_mpi_core_montmul_p( x, x, &grp->P, &grp->RP, &grp->T, grp->mm  ) );
#endif
cleanup:
    return( ret );
}

static int mbedtls_ecp_point_internal_from_mont( mbedtls_ecp_group_internal *grp,
                                                 mbedtls_ecp_point_internal *pt )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    MBEDTLS_MPI_CHK( mbedtls_ecp_mpi_internal_from_mont( grp, getX(pt) ) );
    MBEDTLS_MPI_CHK( mbedtls_ecp_mpi_internal_from_mont( grp, getY(pt) ) );
    MBEDTLS_MPI_CHK( mbedtls_ecp_mpi_internal_from_mont( grp, getZ(pt) ) );
cleanup:
    return( ret );
}


static int ecp_copy( mbedtls_ecp_point_internal *x,
                     mbedtls_ecp_point_internal const *y )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    MBEDTLS_MPI_CHK( mbedtls_mpi_core_copy_p( getX(x), getX(y) ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_core_copy_p( getZ(x), getZ(y) ) );
    /* In x/z coordinates, y is unset */
    if( ECP_MPI_VALID( getY(y) ) )
        MBEDTLS_MPI_CHK( mbedtls_mpi_core_copy_p( getY(x), getY(y) ) );
cleanup:
    return( ret );
}

#if defined(ECP_ARITH_WRAPPER_CORE_BIGNUM_BUFS_BY_REF)
/* Worthwhile defining this in order to save the code for putting
 * the helper parameters grp->T, grp->mm on the stack */
static int ecp_mul_mod( mbedtls_ecp_mpi_internal *x,
                        mbedtls_ecp_mpi_internal const *a,
                        mbedtls_ecp_mpi_internal const *b,
                        mbedtls_ecp_group_internal const *grp )
{
    return( mbedtls_mpi_core_montmul( *x, *a, grp->P, *b, grp->T, grp->mm ) );
}
static int ecp_mul_mod_d( mbedtls_ecp_mpi_internal *x,
                          mbedtls_ecp_mpi_internal const *b,
                          mbedtls_ecp_group_internal const *grp )
{
    return( ecp_mul_mod( x, x, b, grp ) );
}

static int ecp_mpi_inv( mbedtls_ecp_group_internal *grp,
                        mbedtls_ecp_mpi_internal *X,
                        mbedtls_ecp_mpi_internal const *A )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    MBEDTLS_MPI_CHK( mbedtls_mpi_core_inv_mod_prime_p(
                         X, A, &grp->P, &grp->RP ) );
    MBEDTLS_MPI_CHK( mbedtls_ecp_mpi_internal_to_mont( grp, X ) );
    MBEDTLS_MPI_CHK( mbedtls_ecp_mpi_internal_to_mont( grp, X ) );
cleanup:
    return( ret );
}
#endif /* ECP_ARITH_WRAPPER_CORE_BIGNUM_BUFS_BY_REF */

static int ecp_mpi_is_zero( mbedtls_ecp_group_internal const *grp,
                            mbedtls_ecp_mpi_internal const *X,
                            int *result )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    ECP_MPI_ZERO( &grp->tmp );
    ECP_MPI_CMP( X, &grp->tmp, result );
cleanup:
    return( ret );
}

static int ecp_mpi_cond_swap( mbedtls_ecp_group_internal *grp,
                              mbedtls_ecp_mpi_internal *X,
                              mbedtls_ecp_mpi_internal *Y,
                              int cond )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    ECP_MPI_MOV( &grp->tmp, X );
    ECP_MPI_COND_ASSIGN( &grp->tmp, Y, cond );
    ECP_MPI_COND_ASSIGN( Y, X, cond );
    ECP_MPI_MOV( X, &grp->tmp );
cleanup:
    return( ret );
}

static int mbedtls_ecp_mpi_internal_setup_copy(
    mbedtls_ecp_group_internal *grp,
    mbedtls_ecp_mpi_internal *x,
    mbedtls_mpi const *x_orig,
    int alloc )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    size_t limbs = x_orig->n;
    if( limbs > grp->P.n )
        limbs = grp->P.n;

    if( x_orig->p == NULL )
    {
        x->p = NULL; x->n = 0;
        return( 0 );
    }

    if( alloc )
    {
        MBEDTLS_MPI_CHK( mbedtls_mpi_core_alloc( &x->p, grp->P.n ) );
        x->n = grp->P.n;
    }

    memcpy( x->p, x_orig->p, limbs * ciL );
    memset( x->p + limbs, 0, ( grp->P.n - limbs ) * ciL );

    /* Convert to Montgomery presentation */
    MBEDTLS_MPI_CHK( mbedtls_ecp_mpi_internal_to_mont( grp, x ) );
    ret = 0;

cleanup:
    return( ret );
}

static void mbedtls_ecp_mpi_internal_input_free( mbedtls_ecp_mpi_internal *x )
{
#if defined(ECP_ARITH_WRAPPER_CORE_BIGNUM_LOCAL_TEMPORARIES)
    mbedtls_platform_zeroize( x->p, x->n * ciL );
    mbedtls_free( x->p );
    x->p = NULL;
    x->n = 0;
#else
    ((void) x);
#endif
}

static void mbedtls_ecp_point_internal_input_free( mbedtls_ecp_point_internal *pt )
{
    mbedtls_ecp_mpi_internal_input_free( getX(pt) );
    mbedtls_ecp_mpi_internal_input_free( getY(pt) );
    mbedtls_ecp_mpi_internal_input_free( getZ(pt) );
}

static int mbedtls_ecp_point_internal_setup_copy(
    mbedtls_ecp_group_internal *grp,
    mbedtls_ecp_point_internal *pt,
    mbedtls_ecp_point const *pt_orig,
    int alloc )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    MBEDTLS_MPI_CHK( mbedtls_ecp_mpi_internal_setup_copy(
                         grp, getX(pt), &pt_orig->X, alloc ) );
    MBEDTLS_MPI_CHK( mbedtls_ecp_mpi_internal_setup_copy(
                         grp, getY(pt), &pt_orig->Y, alloc ) );
    MBEDTLS_MPI_CHK( mbedtls_ecp_mpi_internal_setup_copy(
                         grp, getZ(pt), &pt_orig->Z, alloc ) );
cleanup:
    return( ret );
}

static int mpi_force_size( mbedtls_mpi *X, size_t limbs );
static int mbedtls_ecp_mpi_internal_setup_ref(
    mbedtls_ecp_group_internal *grp,
    mbedtls_ecp_mpi_internal *x,
    mbedtls_mpi *x_orig )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    MBEDTLS_MPI_CHK( mpi_force_size( x_orig, grp->P.n ) );
    x->p = x_orig->p;
    x->n = grp->P.n;
    ret = 0;

    MBEDTLS_MPI_CHK( mbedtls_ecp_mpi_internal_to_mont( grp, x ) );

cleanup:
    return( ret );
}

static int mbedtls_ecp_point_internal_setup_ref(
    mbedtls_ecp_group_internal *grp,
    mbedtls_ecp_point_internal *pt,
    mbedtls_ecp_point *pt_orig )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    MBEDTLS_MPI_CHK( mbedtls_ecp_mpi_internal_setup_ref(
                         grp, getX(pt), &pt_orig->X ) );
    MBEDTLS_MPI_CHK( mbedtls_ecp_mpi_internal_setup_ref(
                         grp, getY(pt), &pt_orig->Y ) );
    MBEDTLS_MPI_CHK( mbedtls_ecp_mpi_internal_setup_ref(
                         grp, getZ(pt), &pt_orig->Z ) );

cleanup:
    return( ret );
}

static void mbedtls_ecp_point_internal_free_Z(
    mbedtls_ecp_group_internal const *grp, mbedtls_ecp_point_internal *pt )
{
    ((void) grp);
    mbedtls_ecp_mpi_internal_free( getZ(pt) );
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

static int mbedtls_ecp_group_internal_setup(
    mbedtls_ecp_group_internal *grp,
    mbedtls_ecp_group *src )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_mpi_uint *mempool = NULL;
    grp->src = src;

    size_t Pn  = getGrp(grp)->P.n;
    int have_A = ( getGrp(grp)->A.p != NULL );
    int have_B = ( getGrp(grp)->B.p != NULL );

    size_t mempool_limbs = Pn * 1      /* tmp */           +
                           Pn * 2 + 1  /* montmul temp */  +
                           Pn * 3;     /* G.{X,Y,Z}    */

    /* P is referenced, not copied. */
    grp->P.p = getGrp(grp)->P.p; grp->P.n = getGrp(grp)->P.n;

    /* Fetch / compute Montgomery constants */
    mbedtls_ecp_curve_get_rp( getGrp(grp)->id,
                              (const mbedtls_mpi_uint**) &grp->RP.p,
                              &grp->RP.n );
    MBEDTLS_MPI_CHK( mbedtls_mpi_core_mont_init( &grp->mm, *grp->P.p ) );

    mempool_limbs += Pn * ( have_A + have_B );
#if defined(ECP_ARITH_WRAPPER_CORE_BIGNUM_GLOBAL_TEMPORARIES)
    mempool_limbs += 1 * Pn * ECP_ARITH_WRAPPER_NUM_MPI_TEMPS;
    mempool_limbs += 3 * Pn * ECP_ARITH_WRAPPER_NUM_PT_INPUTS;
#endif

    size_t mempool_sz = mempool_limbs * sizeof( mbedtls_mpi_uint );
    MBEDTLS_MPI_CHK( mbedtls_mpi_core_alloc( &mempool, mempool_limbs ) );
    grp->mempool    = mempool;
    grp->mempool_sz = mempool_sz;
    mbedtls_mpi_uint *cur = mempool;

    mbedtls_mpi_buf tmp = { .p = cur,  .n = 1 * Pn     }; cur += 1 * Pn;
    mbedtls_mpi_buf T   = { .p = cur,  .n = 2 * Pn + 1 }; cur += 2 * Pn + 1;
    grp->tmp = tmp; grp->T = T;

    mbedtls_mpi_buf GX = { .p = cur,  .n = 1 * Pn }; cur += 1 * Pn;
    mbedtls_mpi_buf GY = { .p = cur,  .n = 1 * Pn }; cur += 1 * Pn;
    mbedtls_mpi_buf GZ = { .p = cur,  .n = 1 * Pn }; cur += 1 * Pn;
    grp->G.X = GX; grp->G.Y = GY; grp->G.Z = GZ;
    MBEDTLS_MPI_CHK( mbedtls_ecp_point_internal_setup_copy(
                         grp, &grp->G, &getGrp(grp)->G, 0 ) );

    /* NIST curves omit A as a shortcut for A=-3 */
    if( have_A )
    {
        mbedtls_mpi_buf A = { .p = cur, .n = 1 * Pn }; cur += 1 * Pn;
        grp->A = A;
        MBEDTLS_MPI_CHK( mbedtls_ecp_mpi_internal_setup_copy(
                             grp, &grp->A, &getGrp(grp)->A, 0 ) );
    }
    else
    {
        grp->A.p = NULL; grp->A.n = 0;
    }

    /* Curve25519 and Curve448 don't use B */
    if( have_B )
    {
        mbedtls_mpi_buf B = { .p = cur, .n = 1 * Pn }; cur += 1 * Pn;
        grp->B = B;
        MBEDTLS_MPI_CHK( mbedtls_ecp_mpi_internal_setup_copy(
                             grp, &grp->B, &getGrp(grp)->B, 0 ) );
    }
    else
    {
        grp->B.p = NULL; grp->B.n = 0;
    }

#if defined(ECP_ARITH_WRAPPER_CORE_BIGNUM_GLOBAL_TEMPORARIES)
    for( unsigned i=0; i < ECP_ARITH_WRAPPER_NUM_MPI_TEMPS; i++ )
    {
        grp->locals[i].p = cur;
        grp->locals[i].n = Pn;
        cur += Pn;
    }
    for( unsigned i=0; i < ECP_ARITH_WRAPPER_NUM_PT_INPUTS; i++ )
    {
        grp->inputs[i].X.p = cur; grp->inputs[i].X.n = Pn; cur += Pn;
        grp->inputs[i].Y.p = cur; grp->inputs[i].Y.n = Pn; cur += Pn;
        grp->inputs[i].Z.p = cur; grp->inputs[i].Z.n = Pn; cur += Pn;
    }
#endif /* ECP_ARITH_WRAPPER_CORE_BIGNUM_GLOBAL_TEMPORARIES */

cleanup:
    return( ret );
}

/*
 * Modular arithmetic wrappers
 */

#if defined(MBEDTLS_SELF_TEST)
#define INC_MUL_COUNT   mul_count++;
#else
#define INC_MUL_COUNT
#endif

#endif /* MBEDTLS_ECP_ARITH_WRAPPER_CORE_BIGNUM_H */
