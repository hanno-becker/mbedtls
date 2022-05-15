/**
 * \file ecp_arith_wrapper_dynamic_typedefs.h
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

#ifndef MBEDTLS_ECP_ARITH_WRAPPER_CORE_BIGNUM_TYPEDEFS_H
#define MBEDTLS_ECP_ARITH_WRAPPER_CORE_BIGNUM_TYPEDEFS_H

#include "mbedtls/build_info.h"
#include "mbedtls/bignum.h"
#include "mbedtls/ecp.h"

#include "bignum_internal.h"
#include "bignum_core.h"

/*
 *
 * Type definitions for internal ECP/MPI interface
 *
 */

//#define ECP_ARITH_WRAPPER_CORE_BIGNUM_LOCAL_TEMPORARIES
#define ECP_ARITH_WRAPPER_CORE_BIGNUM_GLOBAL_TEMPORARIES

//#define ECP_ARITH_WRAPPER_CORE_BIGNUM_BUFS_BY_VALUE
#define ECP_ARITH_WRAPPER_CORE_BIGNUM_BUFS_BY_REF

#if defined(ECP_ARITH_WRAPPER_CORE_BIGNUM_GLOBAL_TEMPORARIES)
#define ECP_ARITH_WRAPPER_NUM_MPI_TEMPS 5
#define ECP_ARITH_WRAPPER_NUM_PT_INPUTS 2
#endif /* ECP_ARITH_WRAPPER_CORE_BIGNUM_GLOBAL_TEMPORARIES */

//#define ECP_NO_RANDOMIZATION_BEFORE_NORMALIZATION
//#define ECP_NO_RANDOMIZATION_OF_COMB_TABLE

/* Coordinates */
typedef mbedtls_mpi_buf mbedtls_ecp_mpi_internal;

/* Points */
typedef struct mbedtls_ecp_point_internal
{
    mbedtls_mpi_buf X,Y,Z;
} mbedtls_ecp_point_internal;

/* Groups */
typedef struct mbedtls_ecp_group_internal
{
    mbedtls_ecp_group       *src;

    mbedtls_mpi_uint    *mempool;
    size_t            mempool_sz;

    mbedtls_mpi_buf     P;     /* Underlying prime (referenced)     */
    mbedtls_mpi_buf    RP;     /* Montgomery constant (referenced)  */

    mbedtls_ecp_point_internal G;
    mbedtls_mpi_buf     A;     /* A coordinate (in Montgomery form) */
    mbedtls_mpi_buf     B;     /* B coordinate (in Montgomery form) */
    mbedtls_mpi_buf     T;     /* Temporary for Montgomery multiplication. */
    mbedtls_mpi_buf   tmp;     /* Temporary for modular arithmetic         */

#if defined(ECP_ARITH_WRAPPER_CORE_BIGNUM_GLOBAL_TEMPORARIES)
    /* Temporaries for ECP arithmetic */
    mbedtls_ecp_point_internal inputs[ECP_ARITH_WRAPPER_NUM_PT_INPUTS];
    mbedtls_mpi_buf locals[ECP_ARITH_WRAPPER_NUM_MPI_TEMPS];
#endif

    mbedtls_mpi_uint   mm;

} mbedtls_ecp_group_internal;

/*
 * Macro initialization
 */

#define MPI_BUF_FROM_RAW_REF_RO( P, N )                 \
    {                                                   \
        .p = (mbedtls_mpi_uint*) (P),                   \
        .n = (N),                                       \
    }

#define MPI_BUF_FROM_RAW_STATIC_REF( P )                \
    MPI_BUF_FROM_RAW_REF_RO(                            \
           P, sizeof( P ) / sizeof( mbedtls_mpi_uint ) )

#define MPI_BUF_FROM_RAW_REF_RW( P, N )                 \
    {                                                   \
        .p = (P),                                       \
        .n = (N),                                       \
    }

#define MPI_BUF_UNSET()                                 \
    {                                                   \
        .p = NULL,                                      \
        .n = 0,                                         \
    }

#define ECP_POINT_INTERNAL_INIT_XY_Z1( x, y )                 \
      {                                                       \
          .X = MPI_BUF_FROM_RAW_STATIC_REF( x ),              \
          .Y = MPI_BUF_FROM_RAW_STATIC_REF( y ),              \
          .Z = MPI_BUF_FROM_RAW_REF_RO(                       \
              mpi_one, sizeof(x) / sizeof(mbedtls_mpi_uint) ) \
      }

#define ECP_POINT_INTERNAL_INIT_XY_Z0( x, y )                 \
      {                                                       \
          .X = MPI_BUF_FROM_RAW_STATIC_REF( x ),              \
          .Y = MPI_BUF_FROM_RAW_STATIC_REF( y ),              \
          .Z = MPI_BUF_UNSET()                                \
      }

#define ECP_DP_SECP192R1_USE_MONTGOMERY
#define ECP_DP_SECP224R1_USE_MONTGOMERY
#define ECP_DP_SECP256R1_USE_MONTGOMERY
#define ECP_DP_SECP384R1_USE_MONTGOMERY
#define ECP_DP_SECP521R1_USE_MONTGOMERY
#define ECP_DP_BP256R1_USE_MONTGOMERY
#define ECP_DP_BP384R1_USE_MONTGOMERY
#define ECP_DP_BP512R1_USE_MONTGOMERY
#define ECP_DP_SECP192K1_USE_MONTGOMERY
#define ECP_DP_SECP224K1_USE_MONTGOMERY
#define ECP_DP_SECP256K1_USE_MONTGOMERY

#endif /* MBEDTLS_ECP_ARITH_WRAPPER_CORE_BIGNUM_TYPEDEFS_H */
