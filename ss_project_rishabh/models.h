#ifndef MODELS_H
#define MODELS_H

#include <time.h>
#include <stdint.h>

#define MAX_USERNAME_LEN      64
#define MAX_PASSWORD_LEN      64
#define MAX_HASH_LEN          128
#define MAX_ROLE_LEN          32
#define MAX_TYPE_LEN          32
#define MAX_STATUS_LEN        32
#define MAX_DETAILS_LEN       128
#define MAX_FEEDBACK_LEN      256
#define MAX_REQ_ID_LEN        128
#define MAX_FINGERPRINT_LEN   128
#define MAX_RESP_CODE_LEN     64
#define MAX_RESP_MSG_LEN      256

/* User roles */
typedef enum {
    ROLE_UNKNOWN  = 0,
    ROLE_CUSTOMER = 1,
    ROLE_EMPLOYEE = 2,
    ROLE_MANAGER  = 3,
    ROLE_ADMIN    = 4
} UserRole;

/* Idempotency / Request States */
typedef enum {
    REQ_STATE_NONE = 0,
    REQ_STATE_IN_PROGRESS,
    REQ_STATE_COMPLETED,
    REQ_STATE_REJECTED,
    REQ_STATE_FAILED
} RequestState;

/* User representation */
typedef struct {
    int user_id;
    char username[MAX_USERNAME_LEN];
    char password_hash[MAX_HASH_LEN];
    UserRole role;
    int active;
} User;

/* Account representation */
typedef struct {
    int account_id;
    int user_id;
    long long balance_cents;
    int active;
} Account;

/* Financial Transaction */
typedef struct {
    int transaction_id;
    int account_id;
    char type[MAX_TYPE_LEN]; /* DEPOSIT, WITHDRAW, TRANSFER_IN, TRANSFER_OUT, LOAN_CREDIT */
    long long amount_cents;
    int related_account_id;
    char details[MAX_DETAILS_LEN];
    time_t timestamp;
} Transaction;

/* Loan Application */
typedef struct {
    int loan_id;
    int account_id;
    long long amount_cents;
    char status[MAX_STATUS_LEN]; /* PENDING, APPROVED, REJECTED */
    int assigned_employee_id;
    time_t created_at;
    time_t processed_at;
} Loan;

/* Feedback entry */
typedef struct {
    int feedback_id;
    int user_id;
    char message[MAX_FEEDBACK_LEN];
    time_t timestamp;
} Feedback;

/* Stored Result for Idempotency */
typedef struct {
    char request_id[MAX_REQ_ID_LEN];
    int user_id;
    char operation[MAX_TYPE_LEN];
    char payload_fingerprint[MAX_FINGERPRINT_LEN];
    char status[MAX_STATUS_LEN];
    char response_code[MAX_RESP_CODE_LEN];
    char response_message[MAX_RESP_MSG_LEN];
    int transaction_id;
    time_t created_at;
    time_t updated_at;
} RequestResult;

/* Helper function signatures for enum-to-string */
const char* role_to_string(UserRole role);
UserRole string_to_role(const char *str);

#endif /* MODELS_H */
