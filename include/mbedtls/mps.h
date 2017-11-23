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

/*
 * MPS compile time configuration
 */

#define MBEDTLS_MPS_MAX_CHECKSUM 4

/*
 * MPS-specific error codes
 */

#define MBEDTLS_ERR_MPS_RETRY_ON_CONDITION          0x00 /*< Read or write port activation is blocked by some condition (e.g., the underlying transport being unavailable). */
#define MBEDTLS_ERR_MPS_WRITE_PORT_ACTIVE           0x00 /*< An attempt to open a read-port failed because a write-port was active.                                         */
#define MBEDTLS_ERR_MPS_BLOCKED                     0x00 /*< The MPS is in blocked state and cannot be used anymore except for the purpose of graceful shutdown.            */
#define MBEDTLS_ERR_MPS_TIMEOUT                     0x00 /*< TODO: Document                                                                                                 */
#define MBEDTLS_ERR_MPS_FATAL_ALERT                 0x00 /*< A fatal alert was received from the peer                                                                       */
#define MBEDTLS_ERR_MPS_INTERNAL_ERROR              0x00 /*< An internal error happened. TODO: Does this automatically block the MPS?                                       */
#define MBEDTLS_ERR_MPS_PORT_NOT_ACTIVE             0x00 /*< Some request to e.g. fetch data from a read-port failed because the respective port wasn't active.             */
#define MBEDTLS_ERR_MPS_REQUEST_TOO_LARGE           0x00 /*< The previous unsuccessful fetching request from the MPS reader is too large to be buffered.                    */
#define MBEDTLS_ERR_MPS_DOUBLE_REQUEST              0x00 /*< TODO: Document                                                                                                 */
#define MBEDTLS_ERR_MPS_OPTION_UNSUPPORTED          0x00 /*< TODO: Document                                                                                                 */
#define MBEDTLS_ERR_MPS_OPTION_SET                  0x00 /*< TODO: Document                                                                                                 */
#define MBEDTLS_ERR_MPS_PARAM_MISSING               0x00 /*< TODO: Document                                                                                                 */
#define MBEDTLS_ERR_MPS_PARAM_MISMATCH              0x00 /*< TODO: Document                                                                                                 */
#define MBEDTLS_ERR_MPS_UNEXPECTED_FLIGHT           0x00 /*< TODO: Document                                                                                                 */
#define MBEDTLS_ERR_MPS_NO_PROGRESS                 0x00 /*< TODO: Document                                                                                                 */
#define MBEDTLS_ERR_MPS_NOT_BLOCKED                 0x00 /*< TODO: Document                                                                                                 */
#define MBEDTLS_ERR_MPS_UNTRACKED_DIGEST            0x00 /*< TODO: Document                                                                                                 */
#define MBEDTLS_ERR_MPS_READER_FRAGMENT_TOO_SMALL   0x00 /*< TODO: Document                                                                                                 */
#define MBEDTLS_ERR_MPS_READER_DATA_LEFT            0x00 /*< An attempt to close a reader group failed because there was unprocessed data left.                             */
#define MBEDTLS_ERR_MPS_READER_OUT_OF_BOUNDS        0x00 /*< A read request from the reader exceeds the logical bounds of the currently active group.                       */
#define MBEDTLS_ERR_MPS_READER_NO_GROUP             0x00 /*< There was an attempt to close a non-existing reader group.                                                     */


/*
 * Identifiers for record types
 */

typedef enum
{
    MBEDTLS_MPS_PORT_NONE = 0,
    MBEDTLS_MPS_PORT_APPLICATION,
    MBEDTLS_MPS_PORT_HANDSHAKE,
    MBEDTLS_MPS_PORT_ALERT,
    MBEDTLS_MPS_PORT_CCS,
    MBEDTLS_MPS_PORT_ACK /* not used on the MPS interface */
} mbedtls_mps_port_t;

/*
 * Shutdown state of MPS
 */

typedef enum
{
    MBEDTLS_MPS_SHUTDOWN_NONE = 0,            /*< No shutdown in progress                       */
    MBEDTLS_MPS_SHUTDOWN_ALERT_SENT,          /*< Fatal alert sent but not yet acknowledged     */
    MBEDTLS_MPS_SHUTDOWN_ALERT_SENT_ACK,      /*< Fatal alert sent and acknowledged             */
    MBEDTLS_MPS_SHUTDOWN_ALERT_RECEIVED,      /*< Fatal alert received but not yet acknowledged */
    MBEDTLS_MPS_SHUTDOWN_ALERT_RECEIVED_ACK   /*< Fatal alert received and acknowledged         */
} mbedtls_mps_shutdown_t;

/**
 * Availability state for MPS
 */

typedef enum
{
    MBEDTLS_MPS_STATE_READY = 0,              /*< The MPS is in normal operation                          */
    MBEDTLS_MPS_STATE_BLOCKED_ERROR,          /*< The MPS got blocked because of an internal error        */
    MBEDTLS_MPS_STATE_BLOCKED_ALERT_SENT,     /*< The MPS got blocked because the user sent a fatal alert */
    MBEDTLS_MPS_STATE_BLOCKED_ALERT_RECEIVED  /*< The MPS got blocked because a fatal alert was received  */
} mbedtls_mps_state_t;

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
 * Enumeration of all alerts
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
 * \brief   Message options
 *
 * 8-bit flags indicating contribution of a message
 * to the handshake checksum and/or flights.
 *
 * Bit(s)   Meaning
 * 0        Contribution to checksum:
 *          0: No
 *          1: Yes
 *
 * 1 .. 2   Contribution to flight & handshake:
 *          0: No contribution
 *          1: Contributes to flight
 *          2: Ends flight
 *          3: Ends handshake
 *
 * 3 .. 6   Reserved
 *
 * 7        Validity flag
 *          Used to determine if the flags have been set
 *          This bit realized the `Optional` nature of the
 *          `Options` variable in the read state.
 */
typedef uint8_t mbedtls_mps_msg_flags;

#define MBEDTLS_MPS_FLAGS_VALID      ( 1u << 7 )

#define MBEDTLS_MPS_CHECKSUM_MASK    ( 1u << 0 )
#define MBEDTLS_MPS_CHECKSUM_NONE    ( 0u << 0 )
#define MBEDTLS_MPS_CHECKSUM_ADD     ( 1u << 0 )

#define MBEDTLS_MPS_FLIGHT_MASK      ( 3u << 1 )
#define MBEDTLS_MPS_FLIGHT_NONE      ( 0u << 1 )
#define MBEDTLS_MPS_FLIGHT_ADD       ( 1u << 1 )
#define MBEDTLS_MPS_FLIGHT_END       ( 2u << 1 )
#define MBEDTLS_MPS_FLIGHT_FINISHED  ( 3u << 1 )

/*
 * Return values from parsing/writing functions
 */

#define MBEDTLS_MPS_HANDSHAKE_DONE   0
#define MBEDTLS_MPS_HANDSHAKE_PAUSE  1


struct mbedtls_mps;

/*
 * External interfaces
 */

/* The security parameter struct mbedtls_ssl_transform is entirely opaque
 * for the MPS. It only uses its instances through the following two functions
 * performing encryption resp. decryption using them. */

struct mbedtls_ssl_transform;
typedef struct mbedtls_ssl_transform mbedtls_ssl_transform;

/*
 * Internal representation of record frames
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
 * The reason for the data_offset in the unencrypted case
 * is to allow for in-place conversion of an unencrypted to
 * an encrypted record. If the offset wasn't included, the
 * encrypted content would need to be shifted afterwards to
 * make space for the fixed IV.
 *
 */
typedef struct
{
    uint8_t ctr[8];         /*< Record sequence number        */
    uint8_t type;           /*< Record type                   */
    uint8_t ver[2];         /*< SSL/TLS version               */
    uint8_t len[2];         /*< Content length, little endian */

    unsigned char *buf;     /*< Memory buffer enclosing the record content */
    size_t buf_len;         /*< Buffer length */
    size_t data_offset;     /*< Offset of record content */
    size_t data_len;        /*< Length of record content */

} mbedtls_mps_record;

/* Retrieve the data offset of encrypted records for the given transform */
size_t mbedtls_transform_get_offset( mbedtls_ssl_transform *params );

/* Function signature of decryption and encryption functions */
typedef int (*mbedtls_transform_record_t) (
    mbedtls_ssl_transform *params, /* Security parameters                    */
    mbedtls_mps_record *record,    /* Record to be encrypted/decrypted       */
    int (*f_rng)(void *, unsigned char *, size_t), /* PRNG for IV generation */
    void *p_rng );

/* NOTE: DTLS 1.3 only, and only if the KeyUpdate message doesn't get revived.
 *
 * As of Draft-01 of DTLS 1.3, key update happens silently through an increase
 * of the epoch value. This means that the MPS cannot always know the security
 * parameters for incoming messages in advance, but must be able to query for
 * them if it doesn't have key material for the incoming message's epoch.
 *
 * This function is supposed to perform a the key update corresponding
 * to an increase of the epoch by one.
 */
typedef int (*mbedtls_transform_reschedule_t) ( mbedtls_ssl_transform *old,
                                                mbedtls_ssl_transform *new );


/**
 * MPS configuration
 */

/* NOTE: There's probably a lot going to be added here. */

int mbedtls_mps_set_bio( mbedtls_mps *mps, void *p_bio,
                         mbedtls_ssl_send_t *f_send,
                         mbedtls_ssl_recv_t *f_recv,
                         mbedtls_ssl_recv_timeout_t *f_recv_timeout );

/**
 * Generic reader/writer interface
 */

struct mbedtls_writer;
struct mbedtls_reader;
typedef struct mbedtls_writer mbedtls_writer;
typedef struct mbedtls_reader mbedtls_reader;

int mbedtls_mps_writer_get( mbedtls_writer *writer, size_t desired,
                            unsigned char **buffer, size_t *buflen );
int mbedtls_mps_writer_commit( mbedtls_writer *writer, size_t amount, unsigned state );
int mbedtls_mps_writer_stash( mbedtls_writer *writer );

/**
 * \brief MPS Reader objects
 *
 * An MPS reader allows to gradually fetch and process an incoming data stream,
 * and to pause and resume processing while saving intermediate state.
 *
 * TODO: Describe abstract model
 *
 */

/**
 * \brief           Fetch a data chunk from the reader
 *
 * \param reader    Initialized reader
 * \param desired   Desired amount of data to be read
 * \param buffer    Address to store the buffer pointer in
 * \param buflen    Address to store the actual buffer length in,
 *                  or NULL.
 *
 * \return          0 on success; a non-zero error code otherwise.
 *                  On success, *buf holds the address of a buffer
 *                  of size *buflen (if buflen != NULL) or desired
 *                  (if buflen == NULL).
 *
 * \note            Passing NULL as buflen is a convenient way to
 *                  indicate that fragmentation is not tolerated.
 *                  It's functionally equivalent to passing a valid
 *                  address as buflen and checking *buflen == desired
 *                  afterwards.
 */
int mbedtls_mps_reader_get( mbedtls_reader *reader, size_t desired,
                            unsigned char const **buffer, size_t *buflen );

/**
 * \brief               Consume chunks
 *
 * \param reader        Reader context
 * \param num_chunks    Number of chunks to be consumed
 * \param state         New global state for the reader
 *
 * This function marks a number of previously fetched chunks of data as fully
 * processed and invalidates their respective buffers. Subsequent fetch calls
 * will not return this the processed chunks again.
 *
 * Once this function is called, you must not use the pointers
 * corresponding to the commited chunks anymore.
 *
 */
int mbedtls_mps_reader_commit( mbedtls_reader *reader, int num_chunks, unsigned state );

/**
 * \brief               Put chunks on hold for future processing
 *
 * \param reader        Reader context
 * \param num_chunks    Number of chunks to be stashed
 *
 * This function puts a number of previously fetched chunks on hold for future
 * processing.
 *
 * THINK: Is this really necessary? Why not implicitly stashing
 *        what hasn't been commited when the reader is paused?
 *        Keep it simple...
 */
int mbedtls_mps_reader_stash( mbedtls_reader *reader, size_t num_chunks );

/**
 * \brief           Fetch the reader state
 *
 * \param reader    Reader context
 * \return          The last state set at a call to mbedtls_mps_reader_commit,
 *                  or 0 if the reader is used for the first time and hasn't
 *                  been paused before.
 */
int mbedtls_mps_reader_state( mbedtls_reader *reader );

/* TO DISCUSS:
 *
 * We must have a way to hold back information while pausing the
 * processing of a long incoming message. There are two alternatives here:
 * 1) Provide a stack-like interface to save the temporary information
 *    within a reader when pausing a reading process.
 * 2) Save the temporary information in special fields in ssl_handshake.
 *    One could use a union over the temporary structures for all messages,
 *    as only one is needed at a time.
 */

/**
 * \brief              Open a logical sub-buffer within reader
 *
 * \param reader       Reader context
 * \param group_size   The size of the sub-buffer, measured from
 *                     the last committed offset.
 *
 * \return
 *                     - 0 on success
 *                     - MBEDTLS_ERR_MPS_READER_OUT_OF_BOUNDS if the the group
 *                       would exceed its parent group. This is a very important
 *                       error condition that would e.g. catch if the length
 *                       field for some substructure (e.g. an extension within
 *                       a Hello message) claims that substructure to be
 *                       larger than the message itself.
 *                     - MBEDTLS_ERR_MPS_TOO_MANY_GROUPS if the internal
 *                       threshold for the maximum number of groups exceeded.
 *                       This is an internal error, and it should be
 *                       statically verifiable that it doesn't occur.
 */
int mbedtls_mps_reader_group_open( mbedtls_reader *reader, size_t group_size );

/**
 * \brief                Close the current logical sub-buffer within reader
 *
 * \param   reader       Reader context
 *
 * \return
 *                       - 0 on success
 *                       - MBEDTLS_ERR_MPS_READER_DATA_LEFT if there is data
 *                         left unprocessed in the current group.
 *                       - MBEDTLS_ERR_MPS_READER_NO_GROUP if there is no
 *                         group opened currently.
 *
 * TODO: Specify whether uncommited data is permitted when making this call.
 */
int mbedtls_mps_reader_group_close( mbedtls_reader *reader );

/* TODO
 * Clarify if this returns the number of bytes remaining in the current group,
 * the entire logical buffer, or even only the internal buffer.
 * The number of logical bytes remaining in the current group seems to
 * be the most natural choice.
 */
size_t mbedtls_mps_reader_bytes_remaining( mbedtls_reader *reader );

/**
 * Read interface
 */

typedef struct
{
    uint8_t  type; /*< Type of handshake message, e.g. MBEDTLS_SSL_HS_HANDSHAKE */
    size_t length; /*< Length of entire handshake message content               */
    mbedtls_reader *reader; /*< Pausable reader to read the handshake message   */

} mbedtls_mps_handshake_in;

typedef mbedtls_mps_msg_flags mbedtls_mps_read_flags;

typedef uint8_t mbedtls_mps_blockers;
#define MBEDTLS_MPS_BLOCK_READ  ( 1u << 0 )
#define MBEDTLS_MPS_BLOCK_WRITE ( 1u << 1 )
#define MBEDTLS_MPS_BLOCK_ALLOC ( 1u << 2 )

/**
 * \brief       Attempt to open a read-port
 *
 * \param  mps  MPS context
 *
 * \return
 *              - Negative value on error,
 *              - MBEDTLS_MPS_PORT_APPLICATION, or
 *                MBEDTLS_MPS_PORT_HANDSHAKE, or
 *                MBEDTLS_MPS_PORT_ALERT, or
 *                MBEDTLS_MPS_PORT_CCS, or
 *                MBEDTLS_MPS_PORT_ACK
 *                otherwise, indicating which read-port is active.
 */
int mbedtls_mps_read_activate( mbedtls_mps *mps );

/**
 * \brief       Check if and which read-port is currently open
 *
 * \param mps   MPS context
 *
 * \return
 *              - MBEDTLS_ERR_MPS_BLOCKED if MPS is blocked,
 *              - MBEDTLS_MPS_PORT_NONE if no read-port is active,
 *              - MBEDTLS_MPS_PORT_APPLICATION, or
 *                MBEDTLS_MPS_PORT_HANDSHAKE, or
 *                MBEDTLS_MPS_PORT_ALERT, or
 *                MBEDTLS_MPS_PORT_CCS, or
 *                MBEDTLS_MPS_PORT_ACK
 *                otherwise, indicating which read-port is active.
 */
int mbedtls_mps_read_check( mbedtls_mps const *mps );

/* Set options for incoming message:
 * - Checksum contribution
 * - Flight contribution */
/**
 * \brief          Set options for an incoming message
 *
 * \param mps      MPS context
 * \param flags    Bitmask indicating if and howthe current
 *                 message contributes to checksum computations
 *                 and the current flight and handshake.
 *
 * \return
 *                 - 0 on success
 *                 - TODO: Specify error codes
 *
 */
int mbedtls_mps_read_set_flags( mbedtls_mps *mps, mbedtls_mps_read_flags flags );

/* (Get handles to) Read data */
int mbedtls_mps_read_handshake( mbedtls_mps const *mps, mbedtls_mps_handshake_in **msg );
int mbedtls_mps_read_application( mbedtls_mps const *mps, size_t desired,
                                  unsigned char **buffer, size_t *buf_len );
int mbedtls_mps_read_alert( mbedtls_mps const *mps, mbedtls_mps_alert_t *alert_type );

/* Conclude read operation */
int mbedtls_mps_read_pause( mbedtls_mps *mps );
int mbedtls_mps_read_consume( mbedtls_mps *mps );

/* See if there's anything blocking read-port activation */
int mbedtls_mps_read_blockers( mbedtls_mps *mps, mbedtls_mps_blockers *flags );

/**
 * Write interface
 */

typedef struct
{
    uint8_t  type;
    size_t length;
    mbedtls_writer *handle;

} mbedtls_mps_handshake_out;

typedef mbedtls_mps_msg_flags mbedtls_mps_write_flags;

typedef int (*mbedtls_mps_write_callback_t) ( const void* ctx, mbedtls_writer *writer );

/* Attempt to open a write-port */
int mbedtls_mps_write_activate( mbedtls_mps *mps, mbedtls_mps_port_t port );

/* Set options for outgoing message:
 * - Checksum contribution
 * - Flight contribution
 * - Register retransmission callback */
int mbedtls_mps_write_set_flags( mbedtls_mps *mps, mbedtls_mps_write_flags flags );
int mbedtls_mps_write_set_callback( mbedtls_mps *mps, mbedtls_mps_write_callback_t *callback );

/* (Get handles to) Write data */
int mbedtls_mps_write_handshake( mbedtls_mps *mps, mbedtls_mps_handshake_out **writer );
int mbedtls_mps_write_application( mbedtls_mps *mps, size_t desired,
                                   unsigned char **buffer, size_t *buf_len );
int mbedtls_mps_write_alert( mbedtls_mps *mps, mbedtls_mps_alert_t alert_type );

/* Finishing a write operation */
int mbedtls_mps_write_pause( mbedtls_mps *mps, size_t desired );
int mbedtls_mps_write_dispatch( mbedtls_mps *mps );
int mbedtls_mps_write_flush( mbedtls_mps *mps );

/* See if there's anything blocking write-port activation */
int mbedtls_mps_write_blockers( mbedtls_mps *mps, mbedtls_mps_blockers *flags );

/**
 * Checksum interface
 */

/* NOTE: For SSLv3 the message transcript contained in the CertificateVerify
 *       also includes the master secret, hence involves temporarily amending
 *       some data to the transcript, finishing it, and afterwards continuing
 *       with the state before the amending. It seems easiest to solve this by
 *       having the interface the MD contexts used internally.
 *       With that, checksum_clear and checksum_amend are in principle redundant;
 *       it's up to discussion whether we want to keep them here for convenience.
 */

/* Reset the checksum computation */
int mbedtls_mps_checksum_reset( mbedtls_mps *mps );

/* Manually add data to the checksum computation */
int mbedtls_mps_checksum_amend( mbedtls_mps *mps, unsigned char *buf, size_t buf_len );

/* Retrieve current MD context state for the given MD type */
int mbedtls_mps_checksum_state( mbedtls_mps *mps, mbedtls_md_context_t *ctx,
                                mbedtls_md_type_t type );

/* Add/remove message digest to checksum handler */
int mbedtls_mps_checksum_add   ( mbedtls_mps *mps, mbedtls_md_type_t type );
int mbedtls_mps_checksum_remove( mbedtls_mps *mps, mbedtls_md_type_t type );

/**
 * Security parameter interface
 */

int mbedtls_mps_set_incoming_keys( mbedtls_mps *mps, mbedtls_ssl_transform *in_keys );
int mbedtls_mps_set_outgoing_keys( mbedtls_mps *mps, mbedtls_ssl_transform *out_keys );

/**
 * Error handling and shutdown interface
 */

/* Send a fatal alert and attempt shutdown */
int mbedtls_mps_send_fatal( mbedtls_mps *mps, mbedtls_mps_alert_t alert_type );

/* Initiate or proceed with shutdown (e.g., acknowledge the receipt of a fatal alert) */
int mbedtls_mps_shutdown( mbedtls_mps *mps );

mbedtls_mps_shutdown_t mbedtls_mps_shutdown_state( mbedtls_mps const *mps );
mbedtls_mps_state_t mbedtls_mps_availability_state( mbedtls_mps const *mps );


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
    mbedtls_transform_reschedule_t *reschedule_f; /* DTLS 1.3 only (if at all) */

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
    mbedtls_mps_read_flags options;

    mbedtls_mps_handshake_in *paused_handshake;
    mbedtls_mps_read_flags    paused_options;

    mbedtls_mps_blockers blockers;

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
    mbedtls_mps_write_flags options;
    int paused_handshake;

    mbedtls_mps_blockers blockers;

} mbedtls_mps_write_state;

/* Abstract state as in the spec */

typedef struct
{
    /*
     * Sanity state
     */
    mbedtls_mps_state_t blocked;
    union
    {
        int error_code;
        mbedtls_mps_alert_t sent_alert_type;
        mbedtls_mps_alert_t recv_alert_type;
    } info;

    mbedtls_mps_shutdown_t shutdown;

    /*
     * Checksum state
     */
    mbedtls_md_info_t*  checksum_types[ MBEDTLS_MPS_MAX_CHECKSUM + 1 ];
    mbedtls_md_context_t checksum_ctxs[ MBEDTLS_MPS_MAX_CHECKSUM ];

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
