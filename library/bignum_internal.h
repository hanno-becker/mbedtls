/**
 *  Internal bignum functions
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

#ifndef MBEDTLS_BIGNUM_INTERNAL_H
#define MBEDTLS_BIGNUM_INTERNAL_H

#include "common.h"

#include "mbedtls/build_info.h"
#include "mbedtls/bignum.h"

int mbedtls_mpi_get_montgomery_constant_unsafe( mbedtls_mpi *RR,
                                                mbedtls_mpi const *N );

int mbedtls_mpi_resize_clear( mbedtls_mpi *X, size_t limbs );

#define MPI_FROM_RAW_REF_RO( P, N )                     \
    {                                                   \
        .s = 1,                                         \
        .p = (mbedtls_mpi_uint*) (P),                   \
        .n = (N),                                       \
    }

#define MPI_FROM_RAW_STATIC_REF( P )                    \
    MPI_FROM_RAW_REF_RO(                                \
           P, sizeof( P ) / sizeof( mbedtls_mpi_uint ) )

#define MPI_FROM_RAW_REF_RW( P, N )                     \
    {                                                   \
        .s = 1,                                         \
        .p = (P),                                       \
        .n = (N),                                       \
    }

#define MPI_UNSET()                                     \
    {                                                   \
        .s = 1,                                         \
        .p = NULL,                                      \
        .n = 0,                                         \
    }

#endif /* MBEDTLS_BIGNUM_INTERNAL_H */
