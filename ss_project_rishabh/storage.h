#ifndef STORAGE_H
#define STORAGE_H

#include <stddef.h>
#include "models.h"

#define DATA_DIR               "data"
#define SESSIONS_DIR           "data/sessions"
#define LOCK_FILE              "data/bank.lock"
#define USERS_FILE             "data/users.txt"
#define ACCOUNTS_FILE          "data/accounts.txt"
#define TRANSACTIONS_FILE      "data/transactions.txt"
#define LOANS_FILE             "data/loans.txt"
#define FEEDBACK_FILE          "data/feedback.txt"
#define REQUEST_RESULTS_FILE   "data/request_results.txt"
#define JOURNAL_FILE           "data/journal.log"

/* Initialization and recovery */
int storage_init_and_recover(void);

/* POSIX Database Locking */
int acquire_db_lock(int exclusive);
void release_db_lock(int lock_fd);

/* Inode session locking for single-session enforcement */
int acquire_user_session_lock(int user_id);
void release_user_session_lock(int session_fd);

/* User Management */
int get_user_by_username(const char *username, User *out_user);
int get_user_by_id(int user_id, User *out_user);
int add_user(const char *username, const char *password_hash, UserRole role, User *out_user);
int update_user_password(int user_id, const char *new_password_hash);
int update_user_details(int user_id, const char *new_username, UserRole new_role, int active);
int get_all_users(User *out_users, int max_users, int *out_count);

/* Account Management */
int get_account_by_id(int account_id, Account *out_account);
int get_account_by_user_id(int user_id, Account *out_account);
int create_account(int user_id, long long initial_balance_cents, Account *out_account);
int update_account_balance(int account_id, long long new_balance_cents);
int set_account_active(int account_id, int active);
int get_all_accounts(Account *out_accounts, int max_accounts, int *out_count);

/* Transaction Management */
int record_transaction(int account_id, const char *type, long long amount_cents, int related_account_id, const char *details, int *out_tx_id);
int get_transactions_by_account(int account_id, Transaction *out_txs, int max_txs, int *out_count);

/* Loan Management */
int create_loan(int account_id, long long amount_cents, int *out_loan_id);
int get_loan_by_id(int loan_id, Loan *out_loan);
int get_loans_by_account(int account_id, Loan *out_loans, int max_loans, int *out_count);
int get_loans_by_employee(int employee_id, Loan *out_loans, int max_loans, int *out_count);
int get_all_loans(Loan *out_loans, int max_loans, int *out_count);
int assign_loan(int loan_id, int employee_id);
int update_loan_status(int loan_id, const char *status);

/* Feedback Management */
int add_feedback(int user_id, const char *message, int *out_feedback_id);
int get_all_feedback(Feedback *out_feedback, int max_items, int *out_count);

/* Request Results / Idempotency records */
int get_request_result(const char *request_id, RequestResult *out_res);
int save_new_request_result(const RequestResult *res);
int update_request_result(const RequestResult *res);

/* Atomic Financial Transactions with Multi-File Consistency */
int execute_deposit(
    const char *request_id,
    int account_id,
    long long amount_cents,
    int *out_tx_id,
    char *err_msg,
    size_t err_size
);

int execute_withdraw(
    const char *request_id,
    int account_id,
    long long amount_cents,
    int *out_tx_id,
    char *err_msg,
    size_t err_size
);

int execute_transfer(
    const char *request_id,
    int sender_account_id,
    int receiver_account_id,
    long long amount_cents,
    int *out_tx_id,
    char *err_msg,
    size_t err_size
);

int execute_loan_process(
    const char *request_id,
    int loan_id,
    const char *decision,
    int employee_id,
    int *out_tx_id,
    char *err_msg,
    size_t err_size
);

#endif /* STORAGE_H */
