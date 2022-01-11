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

#ifndef MBEDTLS_ECP_ARITH_WRAPPER_DYNAMIC_TYPEDEFS_H
#define MBEDTLS_ECP_ARITH_WRAPPER_DYNAMIC_TYPEDEFS_H

#include "mbedtls/build_info.h"
#include "mbedtls/bignum.h"
#include "mbedtls/ecp.h"

#include "bignum_internal.h"

/* Internal structure representing EC point coordinates */
typedef struct
{
    mbedtls_mpi v;
} mbedtls_ecp_mpi_internal;

/* Internal structure representing EC points */
typedef struct
{
    mbedtls_ecp_point v;
} mbedtls_ecp_point_internal;

#define MBEDTLS_ECP_MAX_LIMBS 65
#define MBEDTLS_ECP_MAX_LIMBS_DOUBLE 2*MBEDTLS_ECP_MAX_LIMBS + 1

/* Internal structure representing EC groups */
#define ECP_GROUP_INTERNAL_TMP_MAX 6
typedef struct
{
    mbedtls_ecp_group  *src;
    mbedtls_mpi  tmp_single;
    mbedtls_mpi  tmp_double;
    mbedtls_mpi  tmp_arr[ECP_GROUP_INTERNAL_TMP_MAX];
    unsigned  alloc;
} mbedtls_ecp_group_internal;

#define ECP_POINT_INIT_XY_Z1( x, y )                          \
      {                                                       \
          .X = MPI_FROM_RAW_STATIC_REF( x ),                  \
          .Y = MPI_FROM_RAW_STATIC_REF( y ),                  \
          .Z = MPI_FROM_RAW_REF_RO(                           \
              mpi_one, sizeof(x) / sizeof(mbedtls_mpi_uint) ) \
      }

#define ECP_POINT_INIT_XY_Z0( x, y )                          \
      {                                                       \
          .X = MPI_FROM_RAW_STATIC_REF( x ),                  \
          .Y = MPI_FROM_RAW_STATIC_REF( y ),                  \
          .Z = MPI_UNSET()                                    \
      }

#define ECP_POINT_INTERNAL_INIT_XY_Z1( x, y )                 \
      {                                                       \
          .v = ECP_POINT_INIT_XY_Z1(x,y)                      \
      }

#define ECP_POINT_INTERNAL_INIT_XY_Z0( x, y )                 \
      {                                                       \
          .v = ECP_POINT_INIT_XY_Z0(x,y)                      \
      }

#endif /* ecp_arith_wrapper_dynamic_typedefs.h */
