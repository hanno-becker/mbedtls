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

/**
 * MPS-specific error codes
 */
/* TODO: Put proper error code constants in here. */
#define MBEDTLS_ERR_MPS_RETRY_ON_CONDITION  0x00
#define MBEDTLS_ERR_MPS_WRITE_PORT_ACTIVE   0x00
#define MBEDTLS_ERR_MPS_BLOCKED             0x00
#define MBEDTLS_ERR_MPS_TIMEOUT             0x00
#define MBEDTLS_ERR_MPS_FATAL_ALERT         0x00
#define MBEDTLS_ERR_MPS_INTERNAL_ERROR      0x00
#define MBEDTLS_ERR_MPS_PORT_NOT_ACTIVE     0x00
#define MBEDTLS_ERR_MPS_REQUEST_TOO_LARGE   0x00
#define MBEDTLS_ERR_MPS_DOUBLE_REQUEST      0x00
#define MBEDTLS_ERR_MPS_OPTION_UNSUPPORTED  0x00
#define MBEDTLS_ERR_MPS_OPTION_SET          0x00
#define MBEDTLS_ERR_MPS_PARAM_MISSING       0x00
#define MBEDTLS_ERR_MPS_PARAM_MISMATCH      0x00
#define MBEDTLS_ERR_MPS_UNEXPECTED_FLIGHT   0x00
#define MBEDTLS_ERR_MPS_NO_PROGRESS         0x00
#define MBEDTLS_ERR_MPS_NOT_BLOCKED         0x00
#define MBEDTLS_ERR_MPS_UNTRACKED_DIGEST    0x00

#define MBEDTLS_ERR_READER_OUT_OF_DATA      0x00
#define MBEDTLS_ERR_READER_DATA_LEFT        0x00
#define MBEDTLS_ERR_READER_OUT_OF_BOUNDS    0x00
#define MBEDTLS_ERR_READER_TOO_MANY_GROUPS  0x00
#define MBEDTLS_ERR_READER_NO_GROUP         0x00

#define MBEDTLS_ERR_WRITER_OUT_OF_SPACE     0x00
#define MBEDTLS_ERR_WRITER_DATA_LEFT        0x00
#define MBEDTLS_ERR_WRITER_OUT_OF_BOUNDS    0x00
#define MBEDTLS_ERR_WRITER_TOO_MANY_GROUPS  0x00
#define MBEDTLS_ERR_WRITER_NO_GROUP         0x00


/**
 * Identifiers for record content types
 */
typedef enum
{
    MBEDTLS_MPS_PORT_NONE = 0,
    MBEDTLS_MPS_PORT_APPLICATION,
    MBEDTLS_MPS_PORT_HANDSHAKE,
    MBEDTLS_MPS_PORT_ALERT,
    MBEDTLS_MPS_PORT_CCS,
    MBEDTLS_MPS_PORT_ACK /* Used MPS-internally only */
} mbedtls_mps_port_t;

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
 * Availability state for MPS
 */
typedef enum
{
    MBEDTLS_MPS_ERROR_NONE = 0,
    MBEDTLS_MPS_ERROR_ALERT_SENT,
    MBEDTLS_MPS_ERROR_ALERT_RECEIVED,
    MBEDTLS_MPS_ERROR_INTERNAL_ERROR
} mbedtls_mps_availability_t;

typedef struct
{
    /* Indexed union:
     * - If avail is ALERT_SENT or ALERT_RECEIVED, info.alert is valid.
     * - If avail is INTERNAL_ERROR, avail.err is valid.
     * - Otherwise, info is invalid.
     */
    mbedtls_mps_availability_t avail;
    union
    {
        mbedtls_mps_alert_t alert;
        int err;
    } info;
} mbedtls_mps_state_t;

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
    MBEDTLS_MPS_STATE_CLOSED       /*!< The connection is fully closed.       */
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

struct mbedtls_mps;
struct mbedtls_writer;
struct mbedtls_reader;
struct mbedtls_ssl_transform;
typedef struct mbedtls_ssl_transform mbedtls_ssl_transform;
typedef struct mbedtls_writer mbedtls_writer;
typedef struct mbedtls_reader mbedtls_reader;

/**
 * \brief MPS reader objects
 *
 * An MPS reader allows to gradually fetch and process an incoming data stream,
 * and to pause and resume processing while saving intermediate state.
 *
 */

/**
 * \brief           Fetch a chunk of incoming data from the reader
 *
 * \param reader    Initialized reader
 * \param desired   Desired amount of data to be read
 * \param buffer    Address to store the buffer pointer in.
 * \param buflen    Address to store the actual buffer length in,
 *                  or NULL.
 *
 * \return
 *                  - 0 on success; in this caese, *buf holds the address
 *                    of a buffer of size *buflen (if buflen != NULL) or
 *                    of size desired (if buflen == NULL).
 *                  - MBEDTLS_ERR_READER_OUT_OF_DATA if there is not enough
 *                    data available to serve the read request.
 *                  - Potentially other nonzero error codes.
 *
 * \note            Passing NULL as buflen is a convenient way to
 *                  indicate that fragmentation is not tolerated.
 *                  Its functionally equivalent to passing a valid
 *                  address as buflen and checking *buflen == desired
 *                  afterwards.
 */
int mbedtls_reader_get( mbedtls_reader *reader, size_t desired,
                        unsigned char const **buffer, size_t *buflen );

/**
 * \brief           Signal that all incoming data in the data buffers
 *                  fetched since the last call to this function
 *                  have been fully processed, and update the reader's state.
 *
 * \param reader    Reader context
 * \param state     New global state for the reader
 *
 * \note            Once this function is called, you must not use the pointers
 *                  corresponding to the committed chunks anymore.
 *
 */
int mbedtls_reader_commit( mbedtls_reader *reader, unsigned state );

/**
 * \brief           Fetch the reader state
 *
 * \param reader    Reader context
 * \return          The last state set at a call to mbedtls_reader_commit,
 *                  or 0 if the reader is used for the first time and hasn't
 *                  been paused before.
 *
 * TO DISCUSS:
 * We must have a way to hold back information while pausing the
 * processing of a long incoming message. There are two alternatives here:
 * 1) Provide a stack-like interface to save the temporary information
 *    within a reader when pausing a reading process.
 * 2) Save the temporary information in special fields in ssl_handshake.
 *    One could use a union over the temporary structures for all messages,
 *    as only one is needed at a time.
 */
int mbedtls_reader_state( mbedtls_reader *reader );

/**
 * \brief              Open a logical sub-buffer within reader
 *
 * \param reader       Reader context
 * \param group_size   The size of the sub-buffer, measured from
 *                     the last committed offset.
 *
 * \return
 *                     - 0 on success
 *                     - MBEDTLS_ERR_READER_OUT_OF_BOUNDS if the the group
 *                       would exceed its parent group. This is a very important
 *                       error condition that would e.g. catch if the length
 *                       field for some substructure (e.g. an extension within
 *                       a Hello message) claims that substructure to be
 *                       larger than the message itself.
 *                     - MBEDTLS_ERR_READER_TOO_MANY_GROUPS if the internal
 *                       threshold for the maximum number of groups exceeded.
 *                       This is an internal error, and it should be
 *                       statically verifiable that it doesn't occur.
 */
int mbedtls_reader_group_open( mbedtls_reader *reader, size_t group_size );

/**
 * \brief                Close the current logical sub-buffer within reader
 *
 * \param   reader       Reader context
 *
 * \return
 *                       - 0 on success
 *                       - MBEDTLS_ERR_READER_DATA_LEFT if there is data
 *                         left unprocessed in the current group.
 *                       - MBEDTLS_ERR_READER_NO_GROUP if there is no
 *                         group opened currently.
 *
 * TODO: Specify whether uncommitted data is permitted when making this call.
 */
int mbedtls_reader_group_close( mbedtls_reader *reader );

/**
 * \brief                Query for the number of bytes remaining in the
 *                       latest logical sub-buffer.
 *
 * \param   reader       Reader context
 *
 * \return               Number of bytes remaining in the last group
 *                       opened via `mbedtls_reader_group_open`; if there
 *                       is no such, the number of byts remaining in the
 *                       entire message.
 *
 * \note                 This is independent of the number of bytes actually
 *                       internally available within the reader.
 */
size_t mbedtls_reader_bytes_remaining( mbedtls_reader *reader );

/**
 * \brief MPS writer objects
 *
 * An MPS writer allows to gradually fetch buffers to write content
 * of outgoing messages into, and to pause and resume processing while
 * saving intermediate state in case there's temporarily not enough
 * write-space available.
 *
 */

/**
 * \brief           Query for a buffer ready to receive outgoing data.
 *
 * \param writer    Initialized writer
 * \param desired   Desired size of output buffer
 * \param buffer    Address to store the buffer pointer in.
 * \param buflen    Address to store the actual buffer length in,
 *                  or NULL.
 *
 * \return
 *                  - 0 on success; in this case, *buffer holds the address
 *                    of a buffer of size *buflen (if buflen != NULL) or
 *                    size desired (if buflen == NULL).
 *                  - MBEDTLS_ERR_WRITER_OUT_OF_SPACE if there is not
 *                    enough space available in the writer.
 *                  - Potentially other nonzero error codes.
 *
 * \note            Passing NULL as buflen is a convenient way to
 *                  indicate that fragmentation is not tolerated.
 *                  It's functionally equivalent to passing a valid
 *                  address as buflen and checking *buflen == desired
 *                  afterwards.
 */
int mbedtls_mps_writer_get( mbedtls_writer *writer, size_t desired,
                            unsigned char **buffer, size_t *buflen );

/**
 * \brief         Signal that all outgoing data buffers fetched since
 *                the last call to this function are fully written,
 *                and update the writer's state.
 *
 * \param writer  Writer context
 * \param state   New global state for the reader
 *
 * \return        0 on success, nonzero error code otherwise.
 *
 * \note          This function invalidates the outgoing data buffer
 *                that are being committed. You must not use the pointers
 *                corresponding to the committed chunks anymore afterwards.
 *
 */
int mbedtls_mps_writer_commit( mbedtls_writer *writer, unsigned state );

/**
 * \brief           Get the writer's state
 *
 * \param writer    Writer context
 *
 * \return          The last state set at a call to mbedtls_writer_commit,
 *                  or 0 if the reader is used for the first time and hasn't
 *                  been paused before.
 */
int mbedtls_writer_state( mbedtls_writer *writer );

/**
 * \brief              Open a logical sub-buffer within writer
 *
 * \param writer       Writer context
 * \param group_size   The size of the sub-buffer, measured from
 *                     the last committed offset.
 *
 * \return
 *                     - 0 on success
 *                     - MBEDTLS_ERR_WRITER_OUT_OF_BOUNDS if the the group
 *                       would exceed its parent group. This is a very important
 *                       error condition that would e.g. catch if the length
 *                       field for some substructure (e.g. an extension within
 *                       a Hello message) claims that substructure to be
 *                       larger than the message itself.
 *                     - MBEDTLS_ERR_WRITER_TOO_MANY_GROUPS if the internal
 *                       threshold for the maximum number of groups exceeded.
 *                       This is an internal error, and it should be
 *                       statically verifiable that it doesn't occur.
 */
int mbedtls_writer_group_open( mbedtls_writer *writer, size_t group_size );

/**
 * \brief         Close the current logical sub-buffer within writer
 *
 * \param writer  Writer context
 *
 * \return
 *                - 0 on success
 *                - MBEDTLS_ERR_WRITER_DATA_LEFT if there is data
 *                  left unprocessed in the current group.
 *                - MBEDTLS_ERR_WRITER_NO_GROUP if there is no
 *                  group opened currently.
 */
int mbedtls_writer_group_close( mbedtls_writer *writer );

/**
 * The security parameter struct mbedtls_ssl_transform is entirely opaque
 * to the MPS. The MPS only uses its instances through configurable payload
 * encryption and decryption functions of type mbedtls_transform_record_t
 * defined below.
 */

/**
 * Representation of record frames
 *
 * The header layout is chosen to facilitate the computation of
 * authentication tags which often use the header bytes laid out
 * exactly as in the struct; note that it does not match what's
 * transferred on the wire.
 *
 * Instances come in two flavors:
 * (1) Encrypted
 *     These always have data_offset = 0
 * (2) Unencrypted
 *     These have data_offset set to the length of the
 *     fixed part of the IV used for encryption.
 *
 * Instances are supposed to be manipulated exclusively through
 * functions of type mbedtls_transform_record_t defined below;
 * these are outside the scope of the MPS.
 *
 * The reason for the data_offset in the unencrypted case
 * is to allow for in-place conversion of an unencrypted to
 * an encrypted record. If the offset wasn't included, the
 * encrypted content would need to be shifted afterwards to
 * make space for the fixed IV.
 *
 */
typedef struct
{
    uint8_t ctr[8];         /*!< Record sequence number        */
    uint8_t type;           /*!< Record type                   */
    uint8_t ver[2];         /*!< SSL/TLS version               */
    uint8_t len[2];         /*!< Content length, little endian */

    unsigned char *buf;     /*!< Buffer enclosing record content */
    size_t buf_len;         /*!< Buffer length */
    size_t data_offset;     /*!< Offset of record content */
    size_t data_len;        /*!< Length of record content */

} mbedtls_mps_record;

/* Retrieve the data offset of encrypted records for the given transform */
size_t mbedtls_transform_get_offset( mbedtls_ssl_transform *params );

/* Function signature of decryption and encryption functions */
typedef int (*mbedtls_transform_record_t) (
    mbedtls_ssl_transform *params, /* Security parameters                    */
    mbedtls_mps_record *record,    /* Record to be encrypted/decrypted       */
    int (*f_rng)(void *, unsigned char *, size_t), /* PRNG for IV generation */
    void *p_rng );

/**
 * MPS configuration
 */

/**
 * \brief                Set underlying transport callbacks for the MPS
 *
 * \param mps            MPS context
 * \param f_send         Send data to underlying transport
 * \param f_recv         Receive data from underlying transport
 * \param f_recv_timeout Receive data from underlying transport, with timeout.
 *
 * \return               0 on success, nonzero error code otherwise.
 */
int mbedtls_mps_set_bio( mbedtls_mps *mps, void *p_bio,
                         mbedtls_ssl_send_t *f_send,
                         mbedtls_ssl_recv_t *f_recv,
                         mbedtls_ssl_recv_timeout_t *f_recv_timeout );

/**
 * Read interface
 */

/* Structure representing an incoming handshake message. */
typedef struct
{
    uint8_t   type;         /*!< Type of handshake message           */
    size_t  length;         /*!< Length of entire handshake message  */
    mbedtls_reader *reader; /*!< Reader to retrieve message contents */

    uint8_t const *seq;     /*!< Handshake sequence number; exposed
                             *   only for checksum computations.     */
} mbedtls_mps_handshake_in;

/* Structure representing an incoming application data message. */
typedef struct
{
    uint8_t* app;   /*!< Application data buffer. Its content
                     *   may be modified by the application. */
    size_t app_len; /*!< Size of application data buffer.    */

} mbedtls_mps_app_in;

typedef mbedtls_mps_msg_flags mbedtls_mps_flags;

/**
 * \brief       Attempt to read an incoming message
 *
 * \param mps   MPS context
 *
 * \return
 *              - Negative value on error,
 *              - MBEDTLS_MPS_PORT_APPLICATION, or
 *                MBEDTLS_MPS_PORT_HANDSHAKE, or
 *                MBEDTLS_MPS_PORT_ALERT, or
 *                MBEDTLS_MPS_PORT_CCS
 *                otherwise, indicating which content type was fetched.
 *
 * \note        On success, you can query the type-specific message contents
 *              using one of mbedtls_mps_read_handshake, mbedtls_mps_read_alert,
 *              or mbedtls_mps_read_application.
 */
int mbedtls_mps_read( mbedtls_mps *mps );

/**
 * \brief       Check if a message has been read
 *
 * \param mps   MPS context
 *
 * \return
 *              - MBEDTLS_ERR_MPS_BLOCKED if MPS is blocked,
 *              - MBEDTLS_MPS_PORT_NONE if no message is available, or
 *              - MBEDTLS_MPS_PORT_APPLICATION, or
 *                MBEDTLS_MPS_PORT_HANDSHAKE, or
 *                MBEDTLS_MPS_PORT_ALERT, or
 *                MBEDTLS_MPS_PORT_CCS,
 *                otherwise, indicating the message's record content type.
 *
 * \note        This function doesn't do any processing and
 *              and only reports if a message is available
 *              through a prior call to `mbedtls_mps_read`.
 */
int mbedtls_mps_read_check( mbedtls_mps const *mps );

/**
 * \brief       Get contents of pending handshake message
 *
 * \param mps   MPS context
 * \param msg   Address to hold the handshake handle.
 *
 * \return      0 on success, nonzero error code otherwise.
 *
 * \note        This function should only be called after a successful
 *              call to mbedtls_mps_read or mbedtls_mps_check returning
 *              MBEDTLS_MPS_PORT_HANDSHAKE. Otherwise, the function
 *              will silently fail.
 */
int mbedtls_mps_read_handshake( mbedtls_mps *mps,
                                mbedtls_mps_handshake_in **msg );

/**
 * \brief       Get contents of pending application data message
 *
 * \param mps   MPS context
 * \param app   Address to hold the application data handle.
 *
 * \return      0 on success, nonzero error code otherwise.
 *
 * \note        This function should only be called after a successful
 *              call to mbedtls_mps_read or mbedtls_mps_check returning
 *              MBEDTLS_MPS_PORT_APPLICATION. Otherwise, the function
 *              will silently fail.
 */
int mbedtls_mps_read_application( mbedtls_mps *mps,
                                  mbedtls_mps_app_in **app );

/**
 * \brief       Get type of pending alert
 *
 * \param mps        MPS context
 * \param alert_type Address to hold the type of the received alert.
 *
 * \return      0 on success, nonzero error code otherwise.
 *
 * \note        This function should only be called after a successful
 *              call to mbedtls_mps_read or mbedtls_mps_check returning
 *              MBEDTLS_MPS_PORT_ALERT. Otherwise, the function
 *              will silently fail.
 */
int mbedtls_mps_read_alert( mbedtls_mps const *mps,
                            mbedtls_mps_alert_t *alert_type );

/**
 * \brief          Set options for the current incoming message
 *
 * \param mps      MPS context
 * \param flags    Bitmask indicating if and how the current message
 *                 contributes to the current flight and handshake.
 *
 * \return         0 on success, nonzero error code otherwise.
 *
 */
int mbedtls_mps_read_set_flags( mbedtls_mps *mps, mbedtls_mps_flags flags );

/**
 * \brief          Pause the reading of an incoming handshake message.
 *
 * \param mps      MPS context
 *
 * \return         0 on success, nonzero error code otherwise.
 *
 * \note           If this function succeeds, the MPS holds back the reader
 *                 used to fetch the message contents and returns it to the
 *                 MPS-client on the next successful reading of a handshake
 *                 message via mbedtls_mps_read.
 */
int mbedtls_mps_read_pause( mbedtls_mps *mps );

/**
 * \brief          Conclude the reading of an incoming message (of any type).
 *
 * \param mps      MPS context
 *
 * \return         0 on success, nonzero error code otherwise.
 *
 */
int mbedtls_mps_read_consume( mbedtls_mps *mps );

/**
 * \brief          Check which external interfaces (like the underlying
 *                 transport) need to become available in order for the MPS
 *                 to be able to make progress towards fetching a new message.
 *
 * \param mps      MPS context
 * \param flags    Pointer ready to receive the bitflag indicating
 *                 the external dependencies.
 *
 * \return         0 on success, nonzero error code otherwise. On success,
 *                 *flags holds a bitwise OR of some of the following flags:
 *                 - MBEDTLS_MPS_BLOCK_READ
 *                   The underlying transport must signal incoming data.
 *                 - MBEDTLS_MPS_BLOCK_WRITE
 *                   The underlying transport must be ready to write data.
 *
 * \note           MBEDTLS_MPS_BLOCK_READ need not be set here, as there
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
 * \param mps   MPS context
 * \param seq   Pointer to write the record sequence number to.
 *
 * \warning     This function constitutes an abstraction break
 *              and should ONLY be used if it is unavoidable by
 *              the standard.
 *
 * \note        This function must be called between a pair of
 *              mbedtls_mps_read and mbedtls_mps_read_consume calls.
 *
 * \return      0 on success, nonzero error code otherwise.
 */
int mbedtls_mps_get_sequence_number( mbedtls_mps *mps, uint8_t seq[8] );

/**
 * Write interface
 */

/* Structure representing an outgoing handshake message. */
typedef struct
{
    uint8_t type;           /*!< Type of handshake message; MUST be set
                             *   by MPS-client before closing or pausing.     */
    mbedtls_writer *handle; /*!< Write-handle to handshake message content    */

    uint8_t const *seq;     /*!< Read only handshake sequence number
                             *   Set by the MPS when preparing this struct,
                             *   and only exposed to allow it to enter
                             *   checksum computations.                       */
} mbedtls_mps_handshake_out;

/* Structure representing an outgoing application data message. */
typedef struct
{
    uint8_t* app;   /*!< Application data buffer. Its content
                     *   may be modified by the application. */
    size_t app_len; /*!< Size of application data buffer.    */

    size_t written; /*!< Set by the user, indicating the amount
                     *   of the application data buffer that has
                     *   been filled with outgoing data.     */
} mbedtls_mps_app_out;

typedef mbedtls_mps_msg_flags mbedtls_mps_flags;

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
 * \brief       Prepare writing a message of the given type
 *
 * \param  mps  MPS context
 * \param port  Content type of message to be written; may be
 *              MBEDTLS_MPS_PORT_APPLICATION, or
 *              MBEDTLS_MPS_PORT_HANDSHAKE, or
 *              MBEDTLS_MPS_PORT_ALERT, or
 *              MBEDTLS_MPS_PORT_CCS.
 *
 * \return      0 on success, nonzero error code on failure.
 */
int mbedtls_mps_write( mbedtls_mps *mps, mbedtls_mps_port_t port );

/**
 * \brief          Set options for outgoing message
 *
 * \param mps      MPS context
 * \param flags    Bitmask indicating if and how the current message
 *                 contributes to the current flight and handshake.
 *
 * \return         0 on success, nonzero error code otherwise.
 *
 */
int mbedtls_mps_write_set_flags( mbedtls_mps *mps, mbedtls_mps_flags flags );

/**
 * \brief          Set retransmission callback for outgoing handshake message
 *
 * \param mps      MPS context
 * \param callback Callback for potential retransmission of the current outgoing
 *                 message, or NULL to have the MPS make a copy of the message.
 * \param ctx      Opaque context to be passed to the retransmission callback.
 *
 * \return         0 on success, nonzero error code otherwise.
 *
 */
int mbedtls_mps_write_set_callback( mbedtls_mps *mps, const void *ctx,
                                    mbedtls_mps_write_callback_t *callback );

/**
 * \brief       Get handle to prepare the type and content
 *              of the next outgoing handshake message.
 *
 * \param mps    MPS context
 * \param writer Address to hold the write handle.
 *
 * \return      0 on success, nonzero error code otherwise.
 */
int mbedtls_mps_write_handshake( mbedtls_mps *mps,
                                 mbedtls_mps_handshake_out **writer );

/**
 * \brief       Get buffer to write outgoing application data to
 *
 * \param mps   MPS context
 * \param app   Address to hold the outgoing application data buffer structure.
 *
 * \return      0 on success, nonzero error code otherwise.
 */
int mbedtls_mps_write_application( mbedtls_mps *mps,
                                   mbedtls_mps_app_out **app );

/**
 * \brief       Set type of outgoing alert message
 *
 * \param mps        MPS context
 * \param alert_type Type of alert to be sent
 *
 * \return      0 on success, nonzero error code otherwise.
 */
int mbedtls_mps_write_alert( mbedtls_mps *mps,
                             mbedtls_mps_alert_t alert_type );

/**
 * \brief          Pause the writing of an outgoing handshake message.
 *
 * \param mps      MPS context
 * \param length   Total length of the handshake message.
 *
 * \return         0 on success, nonzero error code otherwise.
 *
 * \note           Any handshake message fragment must contain the total
 *                 size of the handshake message to which it belongs.
 *                 It is therefore not possible to dispatch earlier message
 *                 fragments without knowing the final message length upfront.
 *
 * \note           If this function succeeds, the MPS holds back the writer
 *                 used to write the message contents and returns it to the
 *                 user on the next successful call to `mbedtls_mps_write`.
 */
int mbedtls_mps_write_pause( mbedtls_mps *mps, size_t length );

/**
 * \brief          Conclude the writing of the current outgoing message.
 *
 * \param mps      MPS context
 *
 * \return         0 on success, nonzero error code otherwise.
 *
 * \note           This call does not necessarily immediately encrypt and
 *                 deliver the message to the underlying transport. If that
 *                 is desired, additionally `mbedtls_mps_write_flush` must be
 *                 called afterwards.
 *
 * \note           Encryption may be postponed because there's more space
 *                 in the current record. If the current record is full but
 *                 there's more space in the current datagram, the record
 *                 would be decrypted but not yet delivered to the underlying
 *                 transport.
 */
int mbedtls_mps_write_dispatch( mbedtls_mps *mps );

/**
 * \brief          Enforce that all messages dispatched since the last call
 *                 to this function get encrypted and delivered to the
 *                 underlying transport.
 *
 * \param mps      MPS context
 *
 * \return
 *                 - 0 on success. In this case, all previously dispatched
 *                   messages have been delivered.
 *                 - MBEDTLS_ERR_MPS_WANT_WRITE if the underlying transport
 *                   could not yet deliver all messages. In this case, the
 *                   call is remembered and it is guaranteed that no call to
 *                   `mbedtls_mps_write` succeeds before all messages have
 *                   been delivered.
 *                 - Another nonzero error code otherwise.
 *
 */
int mbedtls_mps_write_flush( mbedtls_mps *mps );

/**
 * \brief          Check which external interfaces need to become
 *                 available in order for the MPS to be able to make
 *                 progress towards starting the writing of a new message.
 *
 * \param mps      MPS context
 * \param flags    Pointer ready to receive the bitflag indicating
 *                 the external dependencies.
 *
 * \return         0 on success, nonzero error code otherwise. On success,
 *                 *flags holds a bitwise OR of some of the following flags:
 *                 - MBEDTLS_MPS_BLOCK_READ
 *                   The underlying transport must signal incoming data.
 *                 - MBEDTLS_MPS_BLOCK_WRITE
 *                   The underlying transport must be ready to write data.
 *
 * \note           A typical example for this is MBEDTLS_MPS_BLOCK_WRITE
 *                 being set after a call to `mbedtls_mps_write_flush`.
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
 * \param mps   MPS context
 * \param seq   Buffer holding record sequence number to use next
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
 * \return      0 on success, nonzero error code otherwise.
 */
int mbedtls_mps_force_sequence_number( mbedtls_mps *mps, uint8_t seq[8] );


/**
 * Security parameter interface
 */

/**
 * \brief        Set security parameters for subsequent incoming messages.
 *
 * \param mps    MPS context
 * \param params Security parameter set
 *
 * \return      0 on success, nonzero error code otherwise.
 */
int mbedtls_mps_set_incoming_keys( mbedtls_mps *mps, mbedtls_ssl_transform *params );

/**
 * \brief        Set security parameters for subsequent outgoing messages.
 *
 * \param mps    MPS context
 * \param params Security parameter set
 *
 * \return      0 on success, nonzero error code otherwise.
 */
int mbedtls_mps_set_outgoing_keys( mbedtls_mps *mps, mbedtls_ssl_transform *params );

/**
 * Error handling and shutdown interface
 */

/**
 * \brief       Send a fatal alert of the given type
 *
 * \param mps        MPS context
 * \param alert_type Type of alert to be sent.
 *
 * \return      0 on success, nonzero error code otherwise.
 *
 * \note        This call blocks the MPS except for `mbedtls_mps_write_flush`
 *              which might still be called in case this function returns
 *              MBEDTLS_ERR_WANT_WRITE, indicating that the alert couldn't
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
 *              `mbedtls_mps_write_flush` which might still be called in
 *              case this function returns `MBEDTLS_ERR_WANT_WRITE`,
 *              indicating that the notification couldn't be delivered.
 */
int mbedtls_mps_close( mbedtls_mps *mps );

mbedtls_mps_connection_state_t mbedtls_mps_connection_state( mbedtls_mps const *mps );

mbedtls_mps_state_t mbedtls_mps_error_state( mbedtls_mps const *mps );


/*************************************************************************************************
 * The following structs reflect the abstract MPS state as described in the specification.
 * While any implementation of the MPS should provide a map transforming its internal state
 * into this abstract state, the abstract state will not be used in production code, but at
 * most in a minimal reference implementation of the MPS.
 *************************************************************************************************/

/* MPS configuration */

typedef struct
{
    /*
     * Basic configuration
     */

    /* SSL/TLS version in use */
    int version;

    /* Server/Client
     * This is probably relevant only in very few places, one being
     * the potential server-side acceptance of SSLv2 records for the
     * purpose of being able to deal with SSLv2 ClientHello's. */
    int endpoint;

    /*
     * Underlying transport configuration
     */

    /* Stream or datagram */
    int transport_type;

    mbedtls_ssl_send_t *f_send; /* Callback for network send */
    mbedtls_ssl_recv_t *f_recv; /* Callback for network receive */
    mbedtls_ssl_recv_timeout_t *f_recv_timeout;
                                /* Callback for network receive with timeout */
    void *p_bio;                /* context for I/O operations   */

    /*
     * Security configuration
     */

    mbedtls_transform_record_t *decrypt_f; /* Callback for decryption */
    mbedtls_transform_record_t *encrypt_f; /* Callback for encryption */

    /* Maximum number of messages with bad MAC tolerated */
    unsigned badmac_limit;

} mbedtls_mps_config;

/* Read state as in the spec */

typedef struct
{
    mbedtls_mps_port_t active;
    union
    {
        mbedtls_mps_handshake_in *handshake;
        mbedtls_reader           *application;
        mbedtls_mps_alert_t       alert;
    } port;

    /* This incorporates a bit indicating whether
     * the options have been set, realizing the
     * optional nature of this field in the spec. */
    mbedtls_mps_flags options;

    mbedtls_mps_handshake_in *paused_handshake;
    mbedtls_mps_flags         paused_options;

    mbedtls_mps_dependencies blockers;

} mbedtls_mps_read_state;

/* Write state as in the spec */

typedef struct
{
    mbedtls_mps_port_t active;
    union
    {
        mbedtls_mps_handshake_out *handshake;
        mbedtls_writer            *application;
        mbedtls_mps_alert_t        alert;
    } port;

    /* This incorporates a bit indicating whether
     * the options have been set, realizing the
     * optional nature of this field in the spec. */
    mbedtls_mps_flags options;
    int paused_handshake;

    mbedtls_mps_dependencies blockers;

} mbedtls_mps_write_state;

/* Abstract state as in the spec */

typedef struct
{
    /*
     * Sanity state
     */
    mbedtls_mps_state_t error;
    mbedtls_mps_connection_state_t closure;

    /*
     * Security state
     */
    mbedtls_ssl_transform *transform_in;
    mbedtls_ssl_transform *transform_out;

    /*
     * Read & Write states
     */
    mbedtls_mps_read_state   read;
    mbedtls_mps_write_state write;

    /*
     * Flight state
     */
    mbedtls_mps_flight_state_t flight_state;

} mbedtls_mps_state_abstract;
