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

    /* Temporaries for ECP arithmetic */
    mbedtls_ecp_point_internal inputs[ECP_ARITH_WRAPPER_NUM_PT_INPUTS];
    mbedtls_ecp_mpi_internal * locals[ECP_ARITH_WRAPPER_NUM_MPI_TEMPS];

    mbedtls_mpi_uint   mm;

} mbedtls_ecp_group_internal;

/*
 * Macro initialization
 */

#define ECP_POINT_INTERNAL_INIT_XY_Z1( x, y )                 \
      {                                                       \
          .X = (mbedtls_ecp_mpi_internal*) (x),               \
          .Y = (mbedtls_ecp_mpi_internal*) (y),               \
          .Z = NULL,                                          \
      }

#define ECP_POINT_INTERNAL_INIT_XY_Z0( x, y )                 \
      {                                                       \
          .X = (mbedtls_ecp_mpi_internal*) (x),               \
          .Y = (mbedtls_ecp_mpi_internal*) (y),               \
          .Z = NULL,                                          \
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

#endif /* MBEDTLS_ECP_ARITH_WRAPPER_CORE_BIGNUM_RAW_TYPEDEFS_H */
