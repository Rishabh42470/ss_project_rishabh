#include "idempotency.h"
#include "storage.h"
#include "sha256.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

int generate_request_id(char *out_id, size_t max_len)
{
    if (!out_id || max_len < 33) return -1;

    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return -1;

    uint8_t bytes[16];
    ssize_t bytes_read = 0;
    while (bytes_read < (ssize_t)sizeof(bytes)) {
        ssize_t r = read(fd, bytes + bytes_read, sizeof(bytes) - bytes_read);
        if (r <= 0) {
            close(fd);
            return -1;
        }
        bytes_read += r;
    }
    close(fd);

    for (int i = 0; i < 16; i++) {
        sprintf(out_id + (i * 2), "%02x", bytes[i]);
    }
    out_id[32] = '\0';
    return 0;
}

int validate_request_id(const char *request_id)
{
    if (!request_id) return 0;
    size_t len = strlen(request_id);
    
    /* 32 hex chars standard or 36 chars UUID */
    if (len == 32) {
        for (size_t i = 0; i < 32; i++) {
            if (!isxdigit((unsigned char)request_id[i])) return 0;
        }
        return 1;
    } else if (len == 36) {
        for (size_t i = 0; i < 36; i++) {
            if (i == 8 || i == 13 || i == 18 || i == 23) {
                if (request_id[i] != '-') return 0;
            } else {
                if (!isxdigit((unsigned char)request_id[i])) return 0;
            }
        }
        return 1;
    }
    return 0;
}

void compute_payload_fingerprint(
    const char *operation,
    int authenticated_user_id,
    const char *raw_args,
    char output_fingerprint[MAX_FINGERPRINT_LEN]
) {
    char canonical[1024];
    snprintf(canonical, sizeof(canonical), "%s|%d|%s",
             operation ? operation : "",
             authenticated_user_id,
             raw_args ? raw_args : "");
    sha256_string(canonical, output_fingerprint);
}

int lookup_request_result(
    const char *request_id,
    int authenticated_user_id,
    const char *operation,
    const char *payload_fingerprint,
    RequestResult *out_result
) {
    if (!validate_request_id(request_id)) {
        return IDEMPOTENCY_ERROR;
    }

    RequestResult existing;
    int rc = get_request_result(request_id, &existing);
    if (rc != 0) {
        /* Not found -> safe new request */
        return IDEMPOTENCY_NEW_REQUEST;
    }

    /* Record was found, populate output */
    if (out_result) {
        *out_result = existing;
    }

    /* Compare user, operation, and payload fingerprint */
    if (existing.user_id != authenticated_user_id ||
        strcmp(existing.operation, operation) != 0 ||
        strcmp(existing.payload_fingerprint, payload_fingerprint) != 0) {
        /* Idempotency conflict! Same request ID used with mismatched args/user */
        return IDEMPOTENCY_CONFLICT;
    }

    if (strcmp(existing.status, "IN_PROGRESS") == 0) {
        return IDEMPOTENCY_IN_PROGRESS;
    }

    return IDEMPOTENCY_MATCH;
}

static void safe_copy(char *dest, const char *src, size_t dest_size)
{
    if (!dest || dest_size == 0) return;
    if (!src) {
        dest[0] = '\0';
        return;
    }
    size_t i = 0;
    while (i + 1 < dest_size && src[i] != '\0') {
        dest[i] = src[i];
        i++;
    }
    dest[i] = '\0';
}

int register_request(
    const char *request_id,
    int authenticated_user_id,
    const char *operation,
    const char *payload_fingerprint
) {
    if (!validate_request_id(request_id)) {
        return -1;
    }

    RequestResult res;
    memset(&res, 0, sizeof(res));
    safe_copy(res.request_id, request_id, sizeof(res.request_id));
    res.user_id = authenticated_user_id;
    safe_copy(res.operation, operation, sizeof(res.operation));
    safe_copy(res.payload_fingerprint, payload_fingerprint, sizeof(res.payload_fingerprint));
    safe_copy(res.status, "IN_PROGRESS", sizeof(res.status));
    res.transaction_id = 0;
    res.created_at = time(NULL);
    res.updated_at = res.created_at;

    return save_new_request_result(&res);
}

int complete_request(
    const char *request_id,
    const char *response_code,
    const char *response_message,
    int transaction_id
) {
    RequestResult res;
    if (get_request_result(request_id, &res) != 0) {
        return -1;
    }

    safe_copy(res.status, "COMPLETED", sizeof(res.status));
    safe_copy(res.response_code, response_code ? response_code : "", sizeof(res.response_code));
    safe_copy(res.response_message, response_message ? response_message : "", sizeof(res.response_message));
    res.transaction_id = transaction_id;
    res.updated_at = time(NULL);

    return update_request_result(&res);
}

int reject_or_fail_request(
    const char *request_id,
    const char *status,
    const char *response_code,
    const char *response_message
) {
    RequestResult res;
    if (get_request_result(request_id, &res) != 0) {
        return -1;
    }

    safe_copy(res.status, status ? status : "FAILED", sizeof(res.status));
    safe_copy(res.response_code, response_code ? response_code : "", sizeof(res.response_code));
    safe_copy(res.response_message, response_message ? response_message : "", sizeof(res.response_message));
    res.updated_at = time(NULL);

    return update_request_result(&res);
}
