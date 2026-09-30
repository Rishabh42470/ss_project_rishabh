#ifndef PROTOCOL_H
#define PROTOCOL_H

#define DEFAULT_PORT          8080
#define BUFFER_SIZE           4096
#define MAX_PAYLOAD_LEN       2048

/* Delimiters */
#define FIELD_DELIM_CHAR      '|'
#define FIELD_DELIM_STR       "|"
#define PACKET_DELIM_CHAR     '\n'
#define PACKET_DELIM_STR      "\n"

/* Command strings */
#define CMD_LOGIN             "LOGIN"
#define CMD_LOGOUT            "LOGOUT"
#define CMD_CHANGE_PASSWORD   "CHANGE_PASSWORD"

/* Customer financial commands (idempotent) */
#define CMD_DEPOSIT           "DEPOSIT"
#define CMD_WITHDRAW          "WITHDRAW"
#define CMD_TRANSFER          "TRANSFER"
#define CMD_APPLY_LOAN        "APPLY_LOAN"

/* Customer queries */
#define CMD_GET_BALANCE       "GET_BALANCE"
#define CMD_GET_TRANSACTIONS  "GET_TRANSACTIONS"
#define CMD_VIEW_MY_LOANS     "VIEW_MY_LOANS"
#define CMD_SUBMIT_FEEDBACK   "SUBMIT_FEEDBACK"

/* Employee commands */
#define CMD_GET_ASSIGNED_LOANS "GET_ASSIGNED_LOANS"
#define CMD_PROCESS_LOAN      "PROCESS_LOAN"
#define CMD_VIEW_CUSTOMER     "VIEW_CUSTOMER"

/* Manager commands */
#define CMD_GET_ALL_LOANS     "GET_ALL_LOANS"
#define CMD_ASSIGN_LOAN       "ASSIGN_LOAN"
#define CMD_SET_ACCOUNT_STATUS "SET_ACCOUNT_STATUS"
#define CMD_VIEW_ALL_FEEDBACK "VIEW_ALL_FEEDBACK"

/* Administrator commands */
#define CMD_ADD_USER          "ADD_USER"
#define CMD_MODIFY_USER       "MODIFY_USER"
#define CMD_VIEW_ALL_USERS    "VIEW_ALL_USERS"
#define CMD_VIEW_ALL_ACCOUNTS "VIEW_ALL_ACCOUNTS"

/* Response Status Prefixes */
#define RESP_SUCCESS          "SUCCESS"
#define RESP_ERROR            "ERROR"

/* Response Codes */
#define CODE_REQUEST_COMPLETED         "REQUEST_COMPLETED"
#define CODE_REQUEST_ALREADY_COMPLETED "REQUEST_ALREADY_COMPLETED"
#define CODE_IDEMPOTENCY_CONFLICT      "IDEMPOTENCY_CONFLICT"
#define CODE_SESSION_ACTIVE            "SESSION_ACTIVE"
#define CODE_NOT_AUTHENTICATED         "NOT_AUTHENTICATED"
#define CODE_NOT_AUTHORIZED           "NOT_AUTHORIZED"
#define CODE_INVALID_REQUEST_ID        "INVALID_REQUEST_ID"
#define CODE_INVALID_ARGS              "INVALID_ARGS"
#define CODE_INSUFFICIENT_FUNDS        "INSUFFICIENT_FUNDS"
#define CODE_ACCOUNT_INACTIVE          "ACCOUNT_INACTIVE"
#define CODE_NOT_FOUND                 "NOT_FOUND"
#define CODE_STORAGE_ERROR             "STORAGE_ERROR"

#endif /* PROTOCOL_H */
