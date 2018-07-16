/**
 * \file mps.h
 *
 * \brief Message Processing Stack
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
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
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */

#ifndef MBEDTLS_MPS_H
#define MBEDTLS_MPS_H

#include "transport.h"
#include "transform.h"
#include "reader.h"
#include "writer.h"
#include "layer3.h"

/**
 * MPS-specific error codes
 */
/* TODO: Put proper error code constants in here. */
#define MBEDTLS_ERR_MPS_RETRY_ON_CONDITION    0x01
#define MBEDTLS_ERR_MPS_NO_FORWARD            0x02
#define MBEDTLS_ERR_MPS_WRITE_PORT_ACTIVE     0x03
#define MBEDTLS_ERR_MPS_BLOCKED               0x04
#define MBEDTLS_ERR_MPS_TIMEOUT               0x05
#define MBEDTLS_ERR_MPS_INVALID_ALERT         0x06
#define MBEDTLS_ERR_MPS_FATAL_ALERT           0x07
#define MBEDTLS_ERR_MPS_INTERNAL_ERROR        0x08
#define MBEDTLS_ERR_MPS_PORT_NOT_ACTIVE       0x09
#define MBEDTLS_ERR_MPS_REQUEST_TOO_LARGE     0x09
#define MBEDTLS_ERR_MPS_DOUBLE_REQUEST        0x0a
#define MBEDTLS_ERR_MPS_OPERATION_UNSUPPORTED 0x0b
#define MBEDTLS_ERR_MPS_OPTION_UNSUPPORTED    0x0c
#define MBEDTLS_ERR_MPS_OPTION_SET            0x0d
#define MBEDTLS_ERR_MPS_PARAM_MISSING         0x0e
#define MBEDTLS_ERR_MPS_PARAM_MISMATCH        0x0f
#define MBEDTLS_ERR_MPS_UNEXPECTED_FLIGHT     0x10
#define MBEDTLS_ERR_MPS_NO_PROGRESS           0x11
#define MBEDTLS_ERR_MPS_NOT_BLOCKED           0x12
#define MBEDTLS_ERR_MPS_UNTRACKED_DIGEST      0x13
#define MBEDTLS_ERR_MPS_CLOSE_NOTIFY          0x14
#define MBEDTLS_ERR_MPS_FATAL_ALERT_RECEIVED  0x15
#define MBEDTLS_ERR_MPS_BAD_EPOCH             0x16

#define MBEDTLS_MPS_MODE_STREAM   MBEDTLS_SSL_TRANSPORT_STREAM
#define MBEDTLS_MPS_MODE_DATAGRAM MBEDTLS_SSL_TRANSPORT_DATAGRAM

#define MBEDTLS_MPS_MAX_FLIGHT_LENGTH 5

/**
 * Enumeration of alerts
 */
typedef enum
{
    MBEDTLS_MPS_ALERT_NO_RENEGOTIATION
    /* TODO: Add (D)TLS alert types here, see ssl.h.
     * Either use the same constants as in the standard,
     * or keep them abstract here and provide a translation
     * function. */
} mbedtls_mps_alert_t;

/**
 * Blocking reasons
 */
typedef enum
{
    MBEDTLS_MPS_ERROR_NONE = 0,
    MBEDTLS_MPS_ERROR_ALERT_SENT,
    MBEDTLS_MPS_ERROR_ALERT_RECEIVED,
    MBEDTLS_MPS_ERROR_INTERNAL_ERROR
} mbedtls_mps_blocking_reason_t;

typedef struct
{
    /* Indexed union:
     * - If avail is ALERT_SENT or ALERT_RECEIVED, info.alert is valid.
     * - If avail is INTERNAL_ERROR, avail.err is valid.
     * - Otherwise, info is invalid.
     */
    mbedtls_mps_blocking_reason_t reason;
    union
    {
        mbedtls_mps_alert_t alert;
        int err;
    } info;
} mbedtls_mps_blocking_info_t;

/**
 * Connection closure state of MPS
 */
typedef enum
{
    MBEDTLS_MPS_STATE_OPEN = 0,    /*!< The connection is open.               */
    MBEDTLS_MPS_STATE_WRITE_ONLY,  /*!< The peer has closed its writing
                                    *   side, but we may still send data.     */
    MBEDTLS_MPS_STATE_READ_ONLY,   /*!< We have closed the writing side,
                                    *   but the peer may still send data.     */
    MBEDTLS_MPS_STATE_CLOSED,      /*!< The connection is fully closed.       */
    MBEDTLS_MPS_STATE_BLOCKED      /*!< The MPS is blocked after an error.    */
} mbedtls_mps_connection_state_t;

/**
 * Flight handling state
 */
typedef enum
{
    MBEDTLS_MPS_FLIGHT_DONE = 0,
    MBEDTLS_MPS_FLIGHT_RECEIVING,
    MBEDTLS_MPS_FLIGHT_SENDING
} mbedtls_mps_flight_state_t;

/**
 * \brief   Message options
 *
 * 8-bit flags indicating flight contribution of a message.
 *
 * Bit(s)   Meaning
 * 0 .. 1   Contribution to flight & handshake:
 *          0: No contribution
 *          1: Contributes to flight
 *          2: Ends flight
 *          3: Ends handshake
 *
 * 2 .. 6   Reserved
 *
 * 7        Validity flag
 *          Used to determine if the flags have been set
 *          This bit realized the `Optional` nature of the
 *          `Options` variable in the read state.
 */
typedef uint8_t mbedtls_mps_msg_flags;
#define MBEDTLS_MPS_FLAGS_MASK       ( 1u << 7 )
#define MBEDTLS_MPS_FLIGHT_MASK      ( 3u << 0 )
#define MBEDTLS_MPS_FLIGHT_NONE      ( 0u << 0 )
#define MBEDTLS_MPS_FLIGHT_ADD       ( 1u << 0 )
#define MBEDTLS_MPS_FLIGHT_END       ( 2u << 0 )
#define MBEDTLS_MPS_FLIGHT_FINISHED  ( 3u << 0 )

/**
 * Dependencies on external interfaces
 */
typedef uint8_t mbedtls_mps_dependencies;
#define MBEDTLS_MPS_BLOCK_READ  ( 1u << 0 )
#define MBEDTLS_MPS_BLOCK_WRITE ( 1u << 1 )

/*
 * Return values from parsing/writing functions
 */
#define MBEDTLS_MPS_HANDSHAKE_DONE   0
#define MBEDTLS_MPS_HANDSHAKE_PAUSE  1

/**
 * The security parameter struct mbedtls_ssl_transform is entirely opaque
 * to the MPS. The MPS only uses its instances through configurable payload
 * encryption and decryption functions of type mbedtls_transform_record_t
 * defined below.
 */

/**
 * \brief       Callback for retransmission of outgoing handshake messages.
 *
 * \param ctx   Opaque context passed to the retransmission function.
 *              Must not be altered because multiple retransmissions
 *              must be guaranteed to produce the same results.
 *
 * \note        If possible, it is advisable to use the same function
 *              that was used to write the message in the first place.
 */
typedef int (*mbedtls_mps_write_callback_t) ( const void* ctx,
                                              mbedtls_writer *writer );


/**
 * Structure representing backups of outgoing messages for
 * potential retransmission.
 */

#define MPS_RETRANSMISSION_HANDLE_RAW       0 /*!< A raw copy of the outgoing
                                               *   message is available.      */
#define MPS_RETRANSMISSION_HANDLE_CALLBACK  1 /*!< A callback for retransmission
                                               *   is available.              */

/*! A complete incoming flight has been received. */
#define MPS_INCOMING_FLIGHT_FINISHED 0
/*! We're currently receiving an incoming flight. */
#define MPS_INCOMING_FLIGHT_ONGOING  1

typedef struct
{
    mbedtls_mps_epoch_id epoch; /*!< The epoch used to send the message. */

    uint8_t type; /*!< The type of the retransmission handle.
                   *   Supported values are:
                   *   - #MPS_RETRANSMISSION_HANDLE_RAW
                   *   - #MPS_RETRANSMISSION_HANDLE_CALLBACK.   */

    /*! Union indexed by \c type containing the actual
     *  retransmission handle. */
    union
    {
        /*! Raw buffer holding backup of outgoing message. Valid
         *  if and only if \c type has value #MPS_RETRANSMISSION_HANDLE_RAW. */
        struct
        {
            unsigned char *buf; /*!< The buffer holding the message backup. */
            size_t         len; /*!< The length of the message backup.      */
        } raw;

        /*! Callback for retransmission. Valid if and only if \c type
         *  has value #MPS_RETRANSMISSION_HANDLE_CALLBACK. */
        mbedtls_mps_write_callback_t *callback;

    } handle;

} mps_retransmission_handle;

/**
 * MPS Configuration
 */

typedef struct
{
    uint8_t mode;
    mps_l3 *l3;
} mps_config;

/**
 * MPS context
 */

typedef struct
{
    mps_config conf;

    /* Security configuration */
    mbedtls_mps_epoch_id in_epoch;
    mbedtls_mps_epoch_id out_epoch;

    /* Connection state */
    uint8_t alert_pending;
    mbedtls_mps_connection_state_t state;
    mbedtls_mps_blocking_info_t blocking_info;

    /* Read state */
    struct
    {
        mbedtls_mps_msg_type_t state;

        /* Note:
         * This is slightly memory-inefficient because the data
         * is already stored in the underlying Layer 3 context.
         * Comments:
         * - It is unavoidable to use an mps_l3_handshake_in instance
         *   at some point, because that's how Layer 3 reports the
         *   handshake contents. For TLS, it might be stack-allocated in
         *   mbedtls_mps_read_handshake(), setup via mps_l3_read_handshake()
         *   and used to fill the target structure mbedtls_mps_handshake_in
         *   in that function.
         * - For DTLS, it is unavoidable to have a separate instance of
         *   mps_l3_handshake_in than the one reported by Layer 3, because
         *   of handshake message reassembly. So, in this case at least,
         *   we must store it in the MPS context.
         * Currently, we decided to treat TLS and DTLS uniformly by
         * having the mps_l3_handshake_in instance in the MPS context
         * in any case.
         * Given that choice, it comes at no additional cost to also
         * have the alert type and reader pointer here.
         */
        union
        {
            mbedtls_mps_alert_t alert;
            mbedtls_reader*     app;
            mps_l3_handshake_in hs;
        } data;

    } in;

    /* Write state */
    struct
    {
        mbedtls_mps_msg_type_t state;

        union
        {
            mps_l3_handshake_out hs;
            mps_l3_alert_out  alert;
            mps_l3_app_out      app;
            mps_l3_ccs_out      ccs;
        } data;

    } out;

    /* Flight state */
    struct
    {
        /*! This indicates the state of the retransmission state machine.
         *  See the documentation of ::mbedtls_mps_flight_state_t for more. */
        mbedtls_mps_flight_state_t state;

        uint8_t next_receive_seq; /*!< The sequence number of the next incoming
                                   *   or outgoing handshake message. */

        /*! The state of outgoing flights. */
        struct
        {
            /*! The length of the outgoing flight. */
            uint8_t length;

            /*! A list of backup handles to be used in case the flight,
             *  or parts of it, need to be retransmitted. */
            mps_retransmission_handle backup[ MBEDTLS_MPS_MAX_FLIGHT_LENGTH ];
        } out;

        /*! The state of incoming flights. */
        struct
        {
            /*! Indicates if the incoming flight is still under construction
             *  (value #MPS_INCOMING_FLIGHT_ONGOING) or complete
             *  (value #MPS_INCOMING_FLIGHT_FINISHED).
             *
             *  Note: When switching from retransmission state
             *  #MBEDTLS_MPS_FLIGHT_SENDING to #MBEDTLS_MPS_FLIGHT_RECEIVING,
             *  the last incoming flight is not reset and put into state
             *  #MPS_INCOMING_FLIGHT_ONGOING immediately, because we might
             *  receive retransmissions of the old flight. Only if the first
             *  message belonging to the new incoming flight is received,
             *  the incoming flight is reset and put into state
             *  #MPS_INCOMING_FLIGHT_ONGOING.
             */
            uint8_t state;

            /*! The length of the incoming flight, indicating at the same
             *  time which entries in \c epoch_id are valid. */
            uint8_t length;
            /*! The list of epochs used. */
            mbedtls_mps_epoch_id epoch_id[ MBEDTLS_MPS_MAX_FLIGHT_LENGTH ];

        } in;

        /*! Structure containing all state related to message
         *  reassembly and buffering of future messages. */
        struct
        {
            /* TODO: Implement message reassembly.           */
            /* TODO: Implement buffering of future messages. */
            int dummy;
        } buffering;

    } retransmission;

} mbedtls_mps;

/**
 * \brief                Set the underlying transport callbacks for the MPS.
 *
 * \param mps            The MPS context to use.
 * \param f_send         Send data to underlying transport
 * \param f_recv         Receive data from underlying transport
 * \param f_recv_timeout Receive data from underlying transport, with timeout.
 *
 * \return               \c 0 on success.
 * \return               A negative error code on failure.
 */
int mbedtls_mps_set_bio( mbedtls_mps *mps, void *p_bio,
                         mbedtls_mps_send_t *f_send,
                         mbedtls_mps_recv_t *f_recv,
                         mbedtls_mps_recv_timeout_t *f_recv_timeout );

/**
 * MPS maintenance
 */

/**
 * \brief                Initialize an MPS context.
 *
 * \param mps            The MPS context to initialize.
 *
 * \return               \c 0 on success.
 * \return               A negative error code on failure.
 */
int mbedtls_mps_init( mbedtls_mps *mps,
                      mps_l3 *l3, uint8_t mode );

/**
 * \brief                Free an MPS context.
 *
 * \param mps            The MPS context to free.
 *
 * \return               \c 0 on success.
 * \return               A negative error code on failure.
 */
int mbedtls_mps_free( mbedtls_mps *mps );

/**
 * Read interface
 */

/* Structure representing an incoming handshake message. */
typedef struct
{
    uint8_t   type;             /*!< Type of handshake message           */
    size_t  length;             /*!< Length of entire handshake message  */
    mbedtls_reader_ext *handle; /*!< Reader to retrieve message contents */

    uint8_t add[8];             /*!< Opaque, additional data to be used for
                                 *   checksum calculations. */
    uint8_t addlen;             /*!< The length of the additional data. */
} mbedtls_mps_handshake_in;

/**
 * \brief       Attempt to read an incoming message.
 *
 * \param mps   The MPS context to use.
 *
 * \return      A negative error code on failure.
 * \return      #MBEDTLS_MPS_APPLICATION, or
 *              #MBEDTLS_MPS_HANDSHAKE, or
 *              #MBEDTLS_MPS_ALERT, or
 *              #MBEDTLS_MPS_CCS
 *              otherwise, indicating which content type was fetched.
 *
 * \note        On success, you can query the type-specific message contents
 *              using one of mbedtls_mps_read_handshake(), mbedtls_mps_read_alert(),
 *              or mbedtls_mps_read_application().
 */
int mbedtls_mps_read( mbedtls_mps *mps );

/**
 * \brief       Check if a message has been read.
 *
 * \param mps   The MPS context to use.
 *
 * \return      #MBEDTLS_ERR_MPS_BLOCKED if MPS is blocked.
 * \return      #MBEDTLS_MPS_PORT_NONE if no message is available.
 * \return      #MBEDTLS_MPS_PORT_APPLICATION, or
 *              #MBEDTLS_MPS_PORT_HANDSHAKE, or
 *              #MBEDTLS_MPS_PORT_ALERT, or
 *              #MBEDTLS_MPS_PORT_CCS,
 *              otherwise, indicating the message's record content type.
 *
 * \note        This function doesn't do any processing and
 *              and only reports if a message is available
 *              through a prior call to mbedtls_mps_read().
 */
int mbedtls_mps_read_check( mbedtls_mps const *mps );

/**
 * \brief       Get a handle to the contents of a pending handshake message.
 *
 * \param mps   The MPS context to use.
 * \param msg   The address to hold the handshake handle.
 *
 * \return      \c 0 on success.
 * \return      A negative error code on failure.
 *
 * \note        This function should only be called after a successful
 *              call to mbedtls_mps_read() or mbedtls_mps_check() returning
 *              #MBEDTLS_MPS_PORT_HANDSHAKE. Otherwise, the function
 *              will silently fail.
 */
int mbedtls_mps_read_handshake( mbedtls_mps *mps,
                                mbedtls_mps_handshake_in *msg );

/**
 * \brief       Get the contents of a pending application data message.
 *
 * \param mps   The MPS context to use.
 * \param rd    The address at which to store the read handle
 *              to be used to access the application data.
 *
 * \return      \c 0 on success.
 * \return      A negative error code on failure.
 *
 * \note        This function should only be called after a successful
 *              call to mbedtls_mps_read() or mbedtls_mps_check() returning
 *              #MBEDTLS_MPS_PORT_APPLICATION. Otherwise, the function
 *              will silently fail.
 */
int mbedtls_mps_read_application( mbedtls_mps *mps,
                                  mbedtls_reader **rd );

/**
 * \brief       Get the type of a pending alert message.
 *
 * \param mps   The MPS context to use.
 * \param type  The address to hold the type of the received alert.
 *
 * \return      \c 0 on success.
 * \return      A negative error code on failure.
 *
 * \note        This function should only be called after a successful
 *              call to mbedtls_mps_read() or mbedtls_mps_check() returning
 *              #MBEDTLS_MPS_PORT_ALERT. Otherwise, the function
 *              will silently fail.
 */
int mbedtls_mps_read_alert( mbedtls_mps const *mps,
                            mbedtls_mps_alert_t *type );

/**
 * \brief          Set the options for the current incoming message.
 *
 * \param mps      The MPS context to use.
 * \param flags    The bitmask indicating if and how the current message
 *                 contributes to the current flight and handshake.
 *                 See the documentation of ::mbedtls_mps_msg_flags for more
 *                 information.
 *
 * \return         \c 0 on success.
 * \return         A negative error code on failure.
 *
 */
int mbedtls_mps_read_set_flags( mbedtls_mps *mps, mbedtls_mps_msg_flags flags );

/**
 * \brief          Pause the reading of an incoming handshake message.
 *
 * \param mps      The MPS context to use.
 *
 * \return         \c 0 on success.
 * \return         A negative error code on failure.
 *
 * \note           If this function succeeds, the MPS holds back the reader
 *                 used to fetch the message contents and returns it to the
 *                 MPS-client on the next successful reading of a handshake
 *                 message via mbedtls_mps_read().
 */
int mbedtls_mps_read_pause( mbedtls_mps *mps );

/**
 * \brief          Conclude the reading of an incoming message (of any type).
 *
 * \param mps      The MPS context to use.
 *
 * \return         \c 0 on success.
 * \return         A negative error code on failure.
 *
 */
int mbedtls_mps_read_consume( mbedtls_mps *mps );

/**
 * \brief          Check which external interfaces (like the underlying
 *                 transport) need to become available in order for the MPS
 *                 to be able to make progress towards fetching a new message.
 *
 * \param mps      The MPS context to use.
 * \param flags    The pointer ready to receive the bitflag indicating
 *                 the external dependencies.
 *
 * \return         \c 0 on success. In that case,
 *                 *flags holds a bitwise OR of some of the following flags:
 *                 - #MBEDTLS_MPS_BLOCK_READ
 *                   The underlying transport must signal incoming data.
 *                 - #MBEDTLS_MPS_BLOCK_WRITE
 *                   The underlying transport must be ready to write data.
 * \return         A negative error code on failure.
 *
 * \note           #MBEDTLS_MPS_BLOCK_READ need not be set here, as there
 *                 might be more internally buffered data waiting to be
 *                 processed, e.g. if there is more than one records within
 *                 a single datagram.
 *
 */
int mbedtls_mps_read_dependencies( mbedtls_mps *mps,
                                   mbedtls_mps_dependencies *flags );

/*
 * The following function constitutes an abstraction break
 * unavoidable by the DTLS standard, so it seems:
 * The standard mandates that a HelloVerifyRequest in DTLS
 * MUST be sent with the same record sequence number as the
 * ClientHello it is replying to.
 */
/**
 * \brief       Get the sequence number of the record to which the
 *              currently opened message belongs.
 *
 * \param mps   The MPS context to use.
 * \param seq   Pointer to write the record sequence number to.
 *
 * \warning     This function constitutes an abstraction break
 *              and should ONLY be used if it is unavoidable by
 *              the standard.
 *
 * \note        This function must be called between a pair of
 *              mbedtls_mps_read() and mbedtls_mps_read_consume() calls.
 *
 * \return      \c 0 on success.
 * \return      A negative error code on failure.
 *
 */
int mbedtls_mps_get_sequence_number( mbedtls_mps *mps, uint8_t seq[8] );

/**
 * Write interface
 */

#define MBEDTLS_MPS_LENGTH_UNKNOWN (-1)

/* Structure representing an outgoing handshake message. */
typedef struct
{
    uint8_t type;           /*!< Type of handshake message.
                             *
                             *   This field MUST be set by the user before
                             *   calling mbedtls_mps_write_handshake().       */

    int32_t length;         /*!< The length of the handshake message to be
                             *   written, or #MBEDTLS_MPS_LENGTH_UNKNOWN
                             *   if the length is determined at write-time.
                             *   In this case, pausing is not possible for
                             *   the handshake message (because the headers
                             *   for handshake fragments include the total
                             *   length of the handshake message).
                             *
                             *   This field MUST be set by the user before
                             *   calling mbedtls_mps_write_handshake().       */

    mbedtls_writer_ext *handle; /*!< Write-handle to handshake message content.
                                 *
                                 *   This field is set by the MPS implementation
                                 *   of mbedtls_mps_write_handshake(). Any
                                 *   previous value will be ignored and
                                 *   overwritten.       */

    uint8_t add[8];        /*!< Read only additional data attached to the
                            *   handshake message. Concretely, this is empty for
                            *   TLS and contains the handshake sequence number
                            *   for DTLS.
                            *
                            *   This is exposed to allow it to enter
                            *   checksum computations.
                            *
                            *   This field is set by the MPS implementation
                            *   of mbedtls_mps_write_handshake().             */

    uint8_t addlen;         /*!< The length of the additional data.
                             *
                             *   This field is set by the MPS implementation
                             *   of mbedtls_mps_write_handshake().            */
} mbedtls_mps_handshake_out;

/* Structure representing an outgoing application data message. */
typedef struct
{
    uint8_t* app;   /*!< Application data buffer. Its content
                     *   may be modified by the application. */
    size_t app_len; /*!< Size of application data buffer.    */

    size_t *written; /*!< Set by the user, indicating the amount
                      *   of the application data buffer that has
                      *   been filled with outgoing data.     */
} mbedtls_mps_app_out;

/**
 * \brief          Indicate the contribution of the current outgoing
 *                 message to the flight.
 *
 * \param mps      The MPS context to use.
 * \param flags    The bitmask indicating if and how the current message
 *                 contributes to the current flight and handshake.
 *
 * \return         \c 0 on success.
 * \return         A negative error code on failure.
 *
 */
int mbedtls_mps_write_set_flags( mbedtls_mps *mps, mbedtls_mps_msg_flags flags );

/**
 * \brief          Set the retransmission callback for the current
 *                 outgoing handshake message.
 *
 * \param mps      The MPS context to use.
 * \param callback The retransmission callback of the current outgoing message,
 *                 or \c NULL if MPS should make a raw copy of the message.
 * \param ctx      Opaque context to be passed to the retransmission callback.
 *
 * \note           If this function is not called, MPS by default
 *                 makes a raw copy of the message.
 *
 * \return         \c 0 on success.
 * \return         A negative error code on failure.
 *
 */
int mbedtls_mps_write_set_callback( mbedtls_mps *mps, const void *ctx,
                                    mbedtls_mps_write_callback_t *callback );

/**
 * \brief        Attempt to start writing a handshake message.
 *
 * \param mps    The MPS context ot use.
 * \param msg    The pointer to a structure which defines the type
 *               and optionally the length of the handshake message
 *               to be written (provided by the user), and to which
 *               the write handle and additional data provided by MPS
 *               should be written on success.
 *               See the documentation of mbedtls_mps_handshake_out
 *               for more information.
 *
 * \return       \c 0 on success.
 * \return       A negative error code on failure.
 *
 */
int mbedtls_mps_write_handshake( mbedtls_mps *mps,
                                 mbedtls_mps_handshake_out *msg );

/**
 * \brief       Attempt to start writing application data.
 *
 * \param mps   The MPS context to use.
 * \param app   The address to hold the outgoing application
 *              data buffer structure on success.
 *
 * \return       \c 0 on success.
 * \return       A negative error code on failure.
 *
 */
int mbedtls_mps_write_application( mbedtls_mps *mps,
                                   mbedtls_writer **app );

/**
 * \brief       Attempt to start writing a non-fatal alert.
 *
 * \param mps        The MPS context to use.
 * \param alert_type The type of the alert to be sent.
 *
 * \return           \c 0 on success.
 * \return           A negative error code on failure.
 *
 */
int mbedtls_mps_write_alert( mbedtls_mps *mps,
                             mbedtls_mps_alert_t alert_type );

/**
 * \brief            Attempt to start writing a ChangeCipherSpec message.
 *
 * \param mps        The MPS context to use.
 *
 * \return           \c 0 on success.
 * \return           A negative error code on failure.
 *
 * \note             Even if there is no content to be specified for
 *                   ChangeCipherSpec messages, the writing must currently
 *                   still be explicitly concluded through a call to
 *                   mbedtls_mps_dispatch() in uniformity with the handling
 *                   of the other content types.
 *
 *                   Originally, this splitting was mandatory because
 *                   mbedtls_mps_dispatch() might attempt to deliver
 *                   the outgoing message to the underlying transport
 *                   immediately. In that case, we must be able to tell
 *                   apart the following situations:
 *                   (a) The call returned WANT_WRITE because there was still
 *                       data to be flushed, but the underlying transport
 *                       wasn't available.
 *                   (b) The call returned WANT_WRITE because the alert/CCS
 *                       message could be prepared but not yet delivered
 *                       to the underlying transport.
 *                   In case (a), the writing of the alert/CCS hasn't
 *                   commenced, hence we need to call this function again
 *                   for a retry. In case (b), in contrast, the record holding
 *                   the alert/CCS has been prepared and only its delivery
 *                   needs to be retried via mbedtls_mps_flush().
 *
 *                   However, the current version of MPS does never attempt
 *                   immediate delivery of messages to the underlying transport,
 *                   and hence one might omit the explicit call to
 *                   mbedtls_mps_dispatch() in this case. For now, however,
 *                   we keep it for uniformity.
 *
 */
int mbedtls_mps_write_ccs( mbedtls_mps *mps );

/**
 * \brief          Pause the writing of an outgoing handshake message.
 *
 * \param mps      The MPS context to use.
 *
 * \return         \c 0 on success.
 * \return         A negative error code on failure.
 *
 * \note           If this function succeeds, the MPS holds back the writer
 *                 used to write the message contents and returns it to the
 *                 user on the next successful call to mbedtls_mps_write().
 */
int mbedtls_mps_write_pause( mbedtls_mps *mps );

/**
 * \brief          Conclude the writing of the current outgoing message.
 *
 * \param mps      The MPS context to use.
 *
 * \return         \c 0 on success.
 * \return         A negative error code on failure.
 *
 * \note           This call does not necessarily immediately encrypt and
 *                 deliver the message to the underlying transport. If that
 *                 is desired, additionally mbedtls_mps_flush() must be
 *                 called afterwards.
 *
 * \note           Encryption may be postponed because there's more space
 *                 in the current record. If the current record is full but
 *                 there's more space in the current datagram, the record
 *                 would be decrypted but not yet delivered to the underlying
 *                 transport.
 */
int mbedtls_mps_dispatch( mbedtls_mps *mps );

/**
 * \brief          Enforce that all messages dispatched since the last call
 *                 to this function get encrypted and delivered to the
 *                 underlying transport.
 *
 * \param mps      The MPS context to use.
 *
 * \return          \c 0 on success. In this case, all previously dispatched
 *                  messages have been delivered.
 * \return          #MBEDTLS_ERR_MPS_WANT_WRITE if the underlying transport
 *                  could not yet deliver all messages. In this case, the
 *                  call is remembered and it is guaranteed that no call to
 *                  mbedtls_mps_write() succeeds before all messages have
 *                  been delivered.
 * \return          Another negative error code otherwise.
 *
 */
int mbedtls_mps_flush( mbedtls_mps *mps );

/**
 * \brief          Check which external interfaces need to become
 *                 available in order for the MPS to be able to make
 *                 progress towards starting the writing of a new message.
 *
 * \param mps      The MPS context to use.
 * \param flags    Pointer ready to receive the bitflag indicating
 *                 the external dependencies.
 *
 * \return         \c 0 on success. In this case, \c *flags holds a
 *                 bitwise OR of some of the following flags:
 *                 - #MBEDTLS_MPS_BLOCK_READ
 *                   The underlying transport must signal incoming data.
 *                 - #MBEDTLS_MPS_BLOCK_WRITE
 *                   The underlying transport must be ready to write data.
 * \return         A negative error code otherwise.
 *
 * \note           A typical example for this is #MBEDTLS_MPS_BLOCK_WRITE
 *                 being set after a call to mbedtls_mps_flush().
 *
 */
int mbedtls_mps_write_dependencies( mbedtls_mps *mps,
                                    mbedtls_mps_dependencies *flags );

/*
 * The following function constitutes an abstraction break
 * unavoidable by the DTLS standard, so it seems:
 * The standard mandates that a HelloVerifyRequest in DTLS
 * MUST be sent with the same record sequence number as the
 * ClientHello it is replying to.
 */
/**
 * \brief       Force record sequence number of next record to be written
 *              (DTLS only).
 *
 * \param mps   The MPS context to use.
 * \param seq   Buffer holding record sequence number to use next.
 *
 * \warning     This function constitutes an abstraction break
 *              and should ONLY be used if it is unavoidable by
 *              the standard. It should almost always be fine to
 *              let the MPS choose the record sequence number.
 *
 * \note        This function must be called before starting the
 *              write to which it applies (this is because forcing
 *              the record sequence number most likely mandates
 *              the use of a new record when starting the next write,
 *              while normally the MPS would attempt to merge
 *              messages of the same content type in the same record).
 *
 * \return      \c 0 on success.
 * \return      A negative error code otherwise.
 */
int mbedtls_mps_force_sequence_number( mbedtls_mps *mps, uint8_t seq[8] );


/**
 * Security parameter interface
 */

/**
 * \brief        Register the next epoch of security parameters.
 *
 * \param mps    The MPS context to use.
 * \param params The address of the new security parameter set to register.
 * \param id     The address at which to store the identifier through
 *               which the security parameter set can subsequently be
 *               identified.
 *
 * \note         The registration of the new security parameter set does
 *               not yet put it to use for reading or writing. To that end,
 *               use the functions mbedtls_mps_set_incoming_keys() and
 *               mbedtls_mps_set_outgoing_keys(), passing the identifier
 *               this function has written to \p id.
.
 * \note         The security parameter set \p params must be heap-allocated,
 *               and calling this function transfers ownership entirely to the
 *               MPS. In particular, no read, write or deallocation operation
 *               must be performed on \p params by the user after this function
 *               has been called. This leads to the following usage flow:
 *               - Allocate an ::mbedtls_mps_transform_t instance
 *                 from the heap to hold the new security parameters.
 *               - Initialize and configure the security parameters.
 *               - Register the security parameters through
 *                 a call to this function.
 *               - Enable the security parameters for reading
 *                 and/or writing via mbedtls_mps_set_incoming_kets()
 *                 or mbedtls_mps_set_outgoing_keys().
 *
 * \return       \c 0 on success.
 * \return       A negative error code otherwise.
 */
int mbedtls_mps_add_key_material( mbedtls_mps *mps,
                                  mbedtls_mps_transform_t *params,
                                  mbedtls_mps_epoch_id *id );

/**
 * \brief        Set the security parameters for subsequent incoming messages.
 *
 * \param mps    The MPS context to use.
 * \param id     The identifier of a set of security parameters
 *               previously registered via mbedtls_mps_add_key_material().
 *
 * \return       \c 0 on success.
 * \return       A negative error code otherwise.
 */
int mbedtls_mps_set_incoming_keys( mbedtls_mps *mps,
                                   mbedtls_mps_epoch_id id );

/**
 * \brief        Set the security parameters for subsequent outgoing messages.
 *
 * \param mps    The MPS context to use.
 * \param params The identifier for a set of security parameters
 *               previously registered via mbedtls_mps_add_key_material().
 *
 * \return       \c 0 on success.
 * \return       A negative error code otherwise.
 */
int mbedtls_mps_set_outgoing_keys( mbedtls_mps *mps,
                                   mbedtls_mps_epoch_id id );

/**
 * Error handling and shutdown interface
 */

/**
 * \brief       Send a fatal alert of the given type
 *
 * \param mps        MPS context
 * \param alert_type Type of alert to be sent.
 *
 * \return      \c 0 on success.
 * \return      A negative error code otherwise.
 *
 * \note        This call blocks the MPS except for mbedtls_mps_flush()
 *              which might still be called in case this function returns
 *              #MBEDTLS_ERR_WANT_WRITE, indicating that the alert couldn't
 *              be delivered.
 *              After delivery of the fatal alert, the user must free ths MPS.
 */
int mbedtls_mps_send_fatal( mbedtls_mps *mps, mbedtls_mps_alert_t alert_type );

/**
 * \brief       Initiate or proceed with orderly shutdown.
 *
 * \param mps   MPS context
 *
 * \return      0 on success, nonzero error code otherwise.
 *
 * \note        This call closes the write-side of the connection and
 *              notifies the peer through an appropriate alert. Afterwards,
 *              the MPS' write functions are blocked, except for
 *              mbedtls_mps_flush() which might still be called in
 *              case this function returns #MBEDTLS_ERR_WANT_WRITE,
 *              indicating that the notification couldn't be delivered.
 */
int mbedtls_mps_close( mbedtls_mps *mps );

mbedtls_mps_connection_state_t mbedtls_mps_connection_state( mbedtls_mps const *mps );

int mbedtls_mps_error_state( mbedtls_mps const *mps,
                             mbedtls_mps_blocking_info_t *info );

#endif /* MBEDTLS_MPS_H */
