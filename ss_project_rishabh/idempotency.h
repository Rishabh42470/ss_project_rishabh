#ifndef IDEMPOTENCY_H
#define IDEMPOTENCY_H

#include <stddef.h>
#include "models.h"

#define IDEMPOTENCY_NEW_REQUEST       0
#define IDEMPOTENCY_MATCH             1
#define IDEMPOTENCY_IN_PROGRESS       2
#define IDEMPOTENCY_CONFLICT         -1
#define IDEMPOTENCY_ERROR            -2

/* Generate a cryptographically secure 128-bit hex UUID from /dev/urandom */
int generate_request_id(char *out_id, size_t max_len);

/* Validate that request ID meets length and hex format rules */
int validate_request_id(const char *request_id);

/* Compute stable SHA-256 fingerprint for canonical representation */
void compute_payload_fingerprint(
    const char *operation,
    int authenticated_user_id,
    const char *raw_args,
    char output_fingerprint[MAX_FINGERPRINT_LEN]
);

/* Look up an existing request by ID and check for conflicts */
int lookup_request_result(
    const char *request_id,
    int authenticated_user_id,
    const char *operation,
    const char *payload_fingerprint,
    RequestResult *out_result
);

/* Atomically register a request as IN_PROGRESS */
int register_request(
    const char *request_id,
    int authenticated_user_id,
    const char *operation,
    const char *payload_fingerprint
);

/* Update a registered request to COMPLETED with transaction ID and response */
int complete_request(
    const char *request_id,
    const char *response_code,
    const char *response_message,
    int transaction_id
);

/* Update a registered request to REJECTED or FAILED */
int reject_or_fail_request(
    const char *request_id,
    const char *status, /* REJECTED or FAILED */
    const char *response_code,
    const char *response_message
);

#endif /* IDEMPOTENCY_H */
