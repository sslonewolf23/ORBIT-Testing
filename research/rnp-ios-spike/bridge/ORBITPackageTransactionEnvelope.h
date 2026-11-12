#ifndef ORBIT_PACKAGE_TRANSACTION_ENVELOPE_H
#define ORBIT_PACKAGE_TRANSACTION_ENVELOPE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define ORBIT_TRANSACTION_ENVELOPE_VERSION 1U
#define ORBIT_TRANSACTION_ENVELOPE_HEADER_SIZE 44U
#define ORBIT_TRANSACTION_ENVELOPE_MAX_JOURNAL (16U * 1024U * 1024U)
#define ORBIT_TRANSACTION_ENVELOPE_MAX_OWNERSHIP (16U * 1024U * 1024U)
#define ORBIT_TRANSACTION_ENVELOPE_MAX_PAYLOAD (48U * 1024U * 1024U)
#define ORBIT_TRANSACTION_ENVELOPE_TRANSACTION_ID_BYTES 16U

typedef enum {
    ORBIT_TRANSACTION_ENVELOPE_EMPTY = 0,
    ORBIT_TRANSACTION_ENVELOPE_ACTIVE = 1
} orbit_transaction_envelope_state_code;

typedef enum {
    ORBIT_TRANSACTION_ENVELOPE_PHASE_NONE = 0,
    ORBIT_TRANSACTION_ENVELOPE_APPLYING = 1,
    ORBIT_TRANSACTION_ENVELOPE_ROLLING_BACK = 2,
    ORBIT_TRANSACTION_ENVELOPE_COMMITTED = 3
} orbit_transaction_envelope_phase;

typedef enum {
    ORBIT_TRANSACTION_ENVELOPE_OK = 0,
    ORBIT_TRANSACTION_ENVELOPE_INVALID_ARGUMENT,
    ORBIT_TRANSACTION_ENVELOPE_INVALID_STATE,
    ORBIT_TRANSACTION_ENVELOPE_BUFFER_TOO_SMALL,
    ORBIT_TRANSACTION_ENVELOPE_MALFORMED,
    ORBIT_TRANSACTION_ENVELOPE_LIMIT,
    ORBIT_TRANSACTION_ENVELOPE_INVALID_TRANSITION
} orbit_transaction_envelope_code;

/* Payloads are canonical byte strings produced by the journal and ownership
 * codecs. This envelope codec does not authenticate them. The persistence
 * adapter must MAC the complete encoded envelope and anchor its revision
 * independently before accepting a write or recovery decision. */
typedef struct {
    uint64_t revision;
    uint8_t state;
    uint8_t phase;
    uint8_t transaction_id[ORBIT_TRANSACTION_ENVELOPE_TRANSACTION_ID_BYTES];
    const uint8_t *journal_payload;
    size_t journal_length;
    const uint8_t *committed_ownership;
    size_t committed_ownership_length;
    const uint8_t *pending_ownership;
    size_t pending_ownership_length;
} orbit_package_transaction_envelope;

orbit_transaction_envelope_code orbit_package_transaction_envelope_encode(
    const orbit_package_transaction_envelope *envelope,
    uint8_t *output, size_t output_capacity, size_t *output_length);

/* Caller provides independent buffers. Decoded pointers refer to those
 * buffers; the decoder never allocates and never retains input pointers. */
orbit_transaction_envelope_code orbit_package_transaction_envelope_decode(
    const uint8_t *payload, size_t payload_length,
    uint8_t *journal_buffer, size_t journal_capacity,
    uint8_t *committed_ownership_buffer, size_t committed_ownership_capacity,
    uint8_t *pending_ownership_buffer, size_t pending_ownership_capacity,
    orbit_package_transaction_envelope *envelope);

/* Validate the only legal durable state transitions. Call this before the
 * backend's single compare-and-swap of the complete authenticated envelope. */
orbit_transaction_envelope_code orbit_package_transaction_envelope_validate_transition(
    const orbit_package_transaction_envelope *previous,
    const orbit_package_transaction_envelope *next);

#endif
