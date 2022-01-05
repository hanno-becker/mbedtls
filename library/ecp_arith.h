/**
 * \file ecp_arith.h
 *
 * \brief Wrappers for internal EC point and coordinate structures
 *        and low-level prime modular arithmetic operating on them
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

#ifndef MBEDTLS_ECP_ARITH_H
#define MBEDTLS_ECP_ARITH_H

#include "mbedtls/build_info.h"
#include "ecp_arith_typedefs.h"

/* Most modular arithmetic operations are needed unconditionally.
 * Modular subtraction and left-shift, however, may be unnecessary
 * provided alternative implementations for suitable parts of the
 * ECP module have been plugged in. */

#if ( defined(MBEDTLS_ECP_SHORT_WEIERSTRASS_ENABLED) && \
      !( defined(MBEDTLS_ECP_NO_FALLBACK) && \
         defined(MBEDTLS_ECP_DOUBLE_JAC_ALT) && \
         defined(MBEDTLS_ECP_ADD_MIXED_ALT) ) ) || \
    ( defined(MBEDTLS_ECP_MONTGOMERY_ENABLED) && \
      !( defined(MBEDTLS_ECP_NO_FALLBACK) && \
         defined(MBEDTLS_ECP_DOUBLE_ADD_MXZ_ALT) ) )
#define ECP_MPI_NEED_SUB_MOD
#endif

#if defined(MBEDTLS_ECP_SHORT_WEIERSTRASS_ENABLED) && \
    !( defined(MBEDTLS_ECP_NO_FALLBACK) && \
       defined(MBEDTLS_ECP_DOUBLE_JAC_ALT) && \
       defined(MBEDTLS_ECP_ADD_MIXED_ALT) )
#define ECP_MPI_NEED_SHIFT_L_MOD
#endif

#if defined(ECP_ARITH_WRAPPER_FIXSIZE_HEAP)
#include "ecp_arith_wrapper_fixsize_heap.h"
#endif /* ECP_ARITH_WRAPPER_FIXSIZE_HEAP */

#endif /* ecp_arith.h */
