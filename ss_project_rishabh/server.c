#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "protocol.h"
#include "models.h"
#include "storage.h"
#include "idempotency.h"
#include "sha256.h"

/* Signal handler to reap zombie child processes */
static void sigchld_handler(int sig)
{
    (void)sig;
    int saved_errno = errno;
    while (waitpid(-1, NULL, WNOHANG) > 0);
    errno = saved_errno;
}

/* Helper to send response line */
static int send_response(int fd, const char *msg)
{
    size_t len = strlen(msg);
    ssize_t sent = 0;
    while (sent < (ssize_t)len) {
        ssize_t s = write(fd, msg + sent, len - sent);
        if (s <= 0) {
            if (s < 0 && errno == EINTR) continue;
            return -1;
        }
        sent += s;
    }
    return 0;
}

/* Helper to read a line terminated with '\n' from socket */
static ssize_t read_line(int fd, char *buf, size_t max_len)
{
    size_t idx = 0;
    while (idx + 1 < max_len) {
        char c;
        ssize_t r = read(fd, &c, 1);
        if (r <= 0) {
            if (r < 0 && errno == EINTR) continue;
            return (idx > 0) ? (ssize_t)idx : r;
        }
        if (c == '\r') continue;
        if (c == '\n') break;
        buf[idx++] = c;
    }
    buf[idx] = '\0';
    return (ssize_t)idx;
}

/* Forward declaration */
static void handle_client(int client_fd);

int main(int argc, char *argv[])
{
    int port = DEFAULT_PORT;
    if (argc >= 2) {
        port = atoi(argv[1]);
        if (port <= 1024 || port > 65535) {
            fprintf(stderr, "Invalid port %d. Using default %d.\n", port, DEFAULT_PORT);
            port = DEFAULT_PORT;
        }
    }

    printf("===================================================\n");
    printf("   Banking Management System - Server Starting    \n");
    printf("===================================================\n");

    /* Initialize storage and run crash recovery */
    if (storage_init_and_recover() != 0) {
        fprintf(stderr, "FATAL: Failed to initialize storage or perform crash recovery.\n");
        exit(EXIT_FAILURE);
    }
    printf("[+] Storage initialized & crash-recovery checks complete.\n");

    /* Setup SIGCHLD handler to prevent zombie processes */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sigchld_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART | SA_NOCLDWAIT;
    if (sigaction(SIGCHLD, &sa, NULL) < 0) {
        perror("sigaction(SIGCHLD)");
        exit(EXIT_FAILURE);
    }

    /* Ignore SIGPIPE so client disconnects do not crash server */
    signal(SIGPIPE, SIG_IGN);

    /* Create TCP socket */
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in address;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(port);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, 64) < 0) {
        perror("listen");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    printf("[+] Server listening on 0.0.0.0:%d\n", port);
    printf("[+] Process ID: %d. Ready to accept connections...\n", getpid());

    while (1) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);
        if (client_fd < 0) {
            if (errno == EINTR) continue;
            perror("accept");
            continue;
        }

        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));

        /* Fork process for concurrent client handling */
        pid_t pid = fork();
        if (pid < 0) {
            perror("fork");
            close(client_fd);
            continue;
        }

        if (pid == 0) {
            /* Child process */
            close(server_fd);
            printf("[Worker %d] Connected from %s:%d\n", getpid(), client_ip, ntohs(client_addr.sin_port));
            handle_client(client_fd);
            printf("[Worker %d] Client disconnected. Terminating.\n", getpid());
            close(client_fd);
            exit(0);
        } else {
            /* Parent process */
            close(client_fd);
        }
    }

    close(server_fd);
    return 0;
}

/* Client Session Handler */
static void handle_client(int client_fd)
{
    char in_buf[BUFFER_SIZE];
    char out_buf[BUFFER_SIZE];

    int authenticated = 0;
    User cur_user;
    memset(&cur_user, 0, sizeof(cur_user));
    int session_lock_fd = -1;

    while (1) {
        ssize_t n = read_line(client_fd, in_buf, sizeof(in_buf));
        if (n <= 0) break; /* Connection closed or error */

        /* Split command into tokens */
        char *line = in_buf;
        char *cmd = strsep(&line, FIELD_DELIM_STR);
        if (!cmd || strlen(cmd) == 0) continue;

        /* 1. LOGIN */
        if (strcmp(cmd, CMD_LOGIN) == 0) {
            char *username = strsep(&line, FIELD_DELIM_STR);
            char *password = strsep(&line, FIELD_DELIM_STR);

            if (!username || !password) {
                send_response(client_fd, "ERROR|" CODE_INVALID_ARGS "|Usage: LOGIN|username|password\n");
                continue;
            }

            if (authenticated) {
                send_response(client_fd, "ERROR|" CODE_INVALID_ARGS "|Already logged in. Please logout first.\n");
                continue;
            }

            int lock_fd = acquire_db_lock(0);
            User u;
            int rc = get_user_by_username(username, &u);
            release_db_lock(lock_fd);

            if (rc != 0) {
                send_response(client_fd, "ERROR|AUTH_FAILED|Invalid username or password.\n");
                continue;
            }

            char hash[MAX_HASH_LEN];
            sha256_string(password, hash);
            if (strcmp(hash, u.password_hash) != 0) {
                send_response(client_fd, "ERROR|AUTH_FAILED|Invalid username or password.\n");
                continue;
            }

            if (!u.active) {
                send_response(client_fd, "ERROR|" CODE_ACCOUNT_INACTIVE "|Your user account is inactive. Contact Administrator.\n");
                continue;
            }

            /* Single-session enforcement via POSIX inode lock */
            int s_fd = acquire_user_session_lock(u.user_id);
            if (s_fd == -1) {
                send_response(client_fd, "ERROR|" CODE_SESSION_ACTIVE "|Another active session exists for this user. Only one session allowed.\n");
                continue;
            } else if (s_fd < 0) {
                send_response(client_fd, "ERROR|" CODE_STORAGE_ERROR "|Failed to acquire session lock.\n");
                continue;
            }

            authenticated = 1;
            cur_user = u;
            session_lock_fd = s_fd;

            snprintf(out_buf, sizeof(out_buf), "SUCCESS|LOGIN_OK|%d|%s|%s\n",
                     cur_user.user_id, cur_user.username, role_to_string(cur_user.role));
            send_response(client_fd, out_buf);
            continue;
        }

        /* 2. LOGOUT */
        if (strcmp(cmd, CMD_LOGOUT) == 0) {
            if (authenticated) {
                release_user_session_lock(session_lock_fd);
                session_lock_fd = -1;
                authenticated = 0;
                memset(&cur_user, 0, sizeof(cur_user));
            }
            send_response(client_fd, "SUCCESS|LOGGED_OUT|Successfully logged out.\n");
            continue;
        }

        /* Check authentication for all subsequent operations */
        if (!authenticated) {
            send_response(client_fd, "ERROR|" CODE_NOT_AUTHENTICATED "|Please login first.\n");
            continue;
        }

        /* 3. CHANGE_PASSWORD */
        if (strcmp(cmd, CMD_CHANGE_PASSWORD) == 0) {
            char *old_pass = strsep(&line, FIELD_DELIM_STR);
            char *new_pass = strsep(&line, FIELD_DELIM_STR);

            if (!old_pass || !new_pass || strlen(new_pass) < 4) {
                send_response(client_fd, "ERROR|" CODE_INVALID_ARGS "|Usage: CHANGE_PASSWORD|old_pass|new_pass (min 4 chars)\n");
                continue;
            }

            char old_hash[MAX_HASH_LEN];
            sha256_string(old_pass, old_hash);

            int db_lock = acquire_db_lock(1);
            User u;
            get_user_by_id(cur_user.user_id, &u);
            if (strcmp(old_hash, u.password_hash) != 0) {
                release_db_lock(db_lock);
                send_response(client_fd, "ERROR|AUTH_FAILED|Current password does not match.\n");
                continue;
            }

            char new_hash[MAX_HASH_LEN];
            sha256_string(new_pass, new_hash);
            update_user_password(cur_user.user_id, new_hash);
            strncpy(cur_user.password_hash, new_hash, sizeof(cur_user.password_hash) - 1);
            release_db_lock(db_lock);

            send_response(client_fd, "SUCCESS|PASSWORD_CHANGED|Password successfully updated.\n");
            continue;
        }

        /* 4. GET_BALANCE (Customer only) */
        if (strcmp(cmd, CMD_GET_BALANCE) == 0) {
            if (cur_user.role != ROLE_CUSTOMER) {
                send_response(client_fd, "ERROR|" CODE_NOT_AUTHORIZED "|Only customers have a bank balance.\n");
                continue;
            }

            int db_lock = acquire_db_lock(0);
            Account acc;
            int rc = get_account_by_user_id(cur_user.user_id, &acc);
            release_db_lock(db_lock);

            if (rc != 0) {
                send_response(client_fd, "ERROR|" CODE_NOT_FOUND "|Account not found.\n");
            } else {
                snprintf(out_buf, sizeof(out_buf), "SUCCESS|BALANCE|%d|%lld|%d\n",
                         acc.account_id, acc.balance_cents, acc.active);
                send_response(client_fd, out_buf);
            }
            continue;
        }

        /* 5. GET_TRANSACTIONS (Customer only) */
        if (strcmp(cmd, CMD_GET_TRANSACTIONS) == 0) {
            if (cur_user.role != ROLE_CUSTOMER) {
                send_response(client_fd, "ERROR|" CODE_NOT_AUTHORIZED "|Only customers have transactions.\n");
                continue;
            }

            int db_lock = acquire_db_lock(0);
            Account acc;
            if (get_account_by_user_id(cur_user.user_id, &acc) != 0) {
                release_db_lock(db_lock);
                send_response(client_fd, "ERROR|" CODE_NOT_FOUND "|Account not found.\n");
                continue;
            }

            Transaction txs[128];
            int count = 0;
            get_transactions_by_account(acc.account_id, txs, 128, &count);
            release_db_lock(db_lock);

            /* Format response */
            send_response(client_fd, "START_TRANSACTIONS\n");
            for (int i = 0; i < count; i++) {
                char ts_str[64];
                struct tm *tm_info = localtime(&txs[i].timestamp);
                strftime(ts_str, sizeof(ts_str), "%Y-%m-%d %H:%M:%S", tm_info);
                snprintf(out_buf, sizeof(out_buf), "TX|%d|%s|%.2f|%d|%s|%s\n",
                         txs[i].transaction_id, txs[i].type,
                         (double)txs[i].amount_cents / 100.0,
                         txs[i].related_account_id, txs[i].details, ts_str);
                send_response(client_fd, out_buf);
            }
            send_response(client_fd, "END_TRANSACTIONS\n");
            continue;
        }

        /* 6. DEPOSIT (Idempotent) */
        if (strcmp(cmd, CMD_DEPOSIT) == 0) {
            if (cur_user.role != ROLE_CUSTOMER) {
                send_response(client_fd, "ERROR|" CODE_NOT_AUTHORIZED "|Only customers can deposit.\n");
                continue;
            }

            char *req_id = strsep(&line, FIELD_DELIM_STR);
            char *amt_str = strsep(&line, FIELD_DELIM_STR);
            if (!req_id || !amt_str) {
                send_response(client_fd, "ERROR|" CODE_INVALID_ARGS "|Usage: DEPOSIT|req_id|amount_cents\n");
                continue;
            }

            if (!validate_request_id(req_id)) {
                send_response(client_fd, "ERROR|" CODE_INVALID_REQUEST_ID "|Invalid request ID.\n");
                continue;
            }

            long long amt = atoll(amt_str);
            if (amt <= 0) {
                send_response(client_fd, "ERROR|" CODE_INVALID_ARGS "|Amount must be positive.\n");
                continue;
            }

            /* Fingerprint representation */
            char raw_args[64];
            snprintf(raw_args, sizeof(raw_args), "%lld", amt);
            char fp[MAX_FINGERPRINT_LEN];
            compute_payload_fingerprint(CMD_DEPOSIT, cur_user.user_id, raw_args, fp);

            int db_lock = acquire_db_lock(1);
            RequestResult rr;
            int idemp_res = lookup_request_result(req_id, cur_user.user_id, CMD_DEPOSIT, fp, &rr);

            if (idemp_res == IDEMPOTENCY_MATCH) {
                release_db_lock(db_lock);
                snprintf(out_buf, sizeof(out_buf), "SUCCESS|" CODE_REQUEST_ALREADY_COMPLETED "|%s|%d|%s\n",
                         req_id, rr.transaction_id, rr.response_message);
                send_response(client_fd, out_buf);
                continue;
            } else if (idemp_res == IDEMPOTENCY_CONFLICT) {
                release_db_lock(db_lock);
                send_response(client_fd, "ERROR|" CODE_IDEMPOTENCY_CONFLICT "|Request ID reused with different content or user.\n");
                continue;
            } else if (idemp_res == IDEMPOTENCY_IN_PROGRESS) {
                release_db_lock(db_lock);
                send_response(client_fd, "ERROR|IN_PROGRESS|Request is currently being processed. Retry shortly.\n");
                continue;
            }

            /* Register new request */
            register_request(req_id, cur_user.user_id, CMD_DEPOSIT, fp);

            Account acc;
            if (get_account_by_user_id(cur_user.user_id, &acc) != 0) {
                reject_or_fail_request(req_id, "REJECTED", CODE_NOT_FOUND, "Customer account not found");
                release_db_lock(db_lock);
                send_response(client_fd, "ERROR|" CODE_NOT_FOUND "|Customer account not found.\n");
                continue;
            }

            int tx_id = 0;
            char err_msg[128] = {0};
            int exec_rc = execute_deposit(req_id, acc.account_id, amt, &tx_id, err_msg, sizeof(err_msg));
            if (exec_rc == 0) {
                char succ_msg[128];
                snprintf(succ_msg, sizeof(succ_msg), "Deposited $%.2f successfully", (double)amt / 100.0);
                complete_request(req_id, CODE_REQUEST_COMPLETED, succ_msg, tx_id);
                release_db_lock(db_lock);
                snprintf(out_buf, sizeof(out_buf), "SUCCESS|" CODE_REQUEST_COMPLETED "|%s|%d|%s\n",
                         req_id, tx_id, succ_msg);
                send_response(client_fd, out_buf);
            } else {
                reject_or_fail_request(req_id, "REJECTED", CODE_STORAGE_ERROR, err_msg);
                release_db_lock(db_lock);
                snprintf(out_buf, sizeof(out_buf), "ERROR|" CODE_STORAGE_ERROR "|%s\n", err_msg);
                send_response(client_fd, out_buf);
            }
            continue;
        }

        /* 7. WITHDRAW (Idempotent) */
        if (strcmp(cmd, CMD_WITHDRAW) == 0) {
            if (cur_user.role != ROLE_CUSTOMER) {
                send_response(client_fd, "ERROR|" CODE_NOT_AUTHORIZED "|Only customers can withdraw.\n");
                continue;
            }

            char *req_id = strsep(&line, FIELD_DELIM_STR);
            char *amt_str = strsep(&line, FIELD_DELIM_STR);
            if (!req_id || !amt_str) {
                send_response(client_fd, "ERROR|" CODE_INVALID_ARGS "|Usage: WITHDRAW|req_id|amount_cents\n");
                continue;
            }

            if (!validate_request_id(req_id)) {
                send_response(client_fd, "ERROR|" CODE_INVALID_REQUEST_ID "|Invalid request ID.\n");
                continue;
            }

            long long amt = atoll(amt_str);
            if (amt <= 0) {
                send_response(client_fd, "ERROR|" CODE_INVALID_ARGS "|Amount must be positive.\n");
                continue;
            }

            char raw_args[64];
            snprintf(raw_args, sizeof(raw_args), "%lld", amt);
            char fp[MAX_FINGERPRINT_LEN];
            compute_payload_fingerprint(CMD_WITHDRAW, cur_user.user_id, raw_args, fp);

            int db_lock = acquire_db_lock(1);
            RequestResult rr;
            int idemp_res = lookup_request_result(req_id, cur_user.user_id, CMD_WITHDRAW, fp, &rr);

            if (idemp_res == IDEMPOTENCY_MATCH) {
                release_db_lock(db_lock);
                if (strcmp(rr.status, "COMPLETED") == 0) {
                    snprintf(out_buf, sizeof(out_buf), "SUCCESS|" CODE_REQUEST_ALREADY_COMPLETED "|%s|%d|%s\n",
                             req_id, rr.transaction_id, rr.response_message);
                } else {
                    snprintf(out_buf, sizeof(out_buf), "ERROR|%s|%s\n",
                             rr.response_code, rr.response_message);
                }
                send_response(client_fd, out_buf);
                continue;
            } else if (idemp_res == IDEMPOTENCY_CONFLICT) {
                release_db_lock(db_lock);
                send_response(client_fd, "ERROR|" CODE_IDEMPOTENCY_CONFLICT "|Request ID reused with different content or user.\n");
                continue;
            } else if (idemp_res == IDEMPOTENCY_IN_PROGRESS) {
                release_db_lock(db_lock);
                send_response(client_fd, "ERROR|IN_PROGRESS|Request is currently being processed. Retry shortly.\n");
                continue;
            }

            register_request(req_id, cur_user.user_id, CMD_WITHDRAW, fp);

            Account acc;
            if (get_account_by_user_id(cur_user.user_id, &acc) != 0) {
                reject_or_fail_request(req_id, "REJECTED", CODE_NOT_FOUND, "Customer account not found");
                release_db_lock(db_lock);
                send_response(client_fd, "ERROR|" CODE_NOT_FOUND "|Customer account not found.\n");
                continue;
            }

            int tx_id = 0;
            char err_msg[128] = {0};
            int exec_rc = execute_withdraw(req_id, acc.account_id, amt, &tx_id, err_msg, sizeof(err_msg));
            if (exec_rc == 0) {
                char succ_msg[128];
                snprintf(succ_msg, sizeof(succ_msg), "Withdrew $%.2f successfully", (double)amt / 100.0);
                complete_request(req_id, CODE_REQUEST_COMPLETED, succ_msg, tx_id);
                release_db_lock(db_lock);
                snprintf(out_buf, sizeof(out_buf), "SUCCESS|" CODE_REQUEST_COMPLETED "|%s|%d|%s\n",
                         req_id, tx_id, succ_msg);
                send_response(client_fd, out_buf);
            } else {
                const char *err_code = (exec_rc == -4) ? CODE_INSUFFICIENT_FUNDS : CODE_STORAGE_ERROR;
                reject_or_fail_request(req_id, "REJECTED", err_code, err_msg);
                release_db_lock(db_lock);
                snprintf(out_buf, sizeof(out_buf), "ERROR|%s|%s\n", err_code, err_msg);
                send_response(client_fd, out_buf);
            }
            continue;
        }

        /* 8. TRANSFER (Idempotent) */
        if (strcmp(cmd, CMD_TRANSFER) == 0) {
            if (cur_user.role != ROLE_CUSTOMER) {
                send_response(client_fd, "ERROR|" CODE_NOT_AUTHORIZED "|Only customers can transfer funds.\n");
                continue;
            }

            char *req_id = strsep(&line, FIELD_DELIM_STR);
            char *recv_id_str = strsep(&line, FIELD_DELIM_STR);
            char *amt_str = strsep(&line, FIELD_DELIM_STR);

            if (!req_id || !recv_id_str || !amt_str) {
                send_response(client_fd, "ERROR|" CODE_INVALID_ARGS "|Usage: TRANSFER|req_id|receiver_acc_id|amount_cents\n");
                continue;
            }

            if (!validate_request_id(req_id)) {
                send_response(client_fd, "ERROR|" CODE_INVALID_REQUEST_ID "|Invalid request ID.\n");
                continue;
            }

            int recv_acc_id = atoi(recv_id_str);
            long long amt = atoll(amt_str);
            if (amt <= 0 || recv_acc_id <= 0) {
                send_response(client_fd, "ERROR|" CODE_INVALID_ARGS "|Invalid receiver account or non-positive amount.\n");
                continue;
            }

            char raw_args[128];
            snprintf(raw_args, sizeof(raw_args), "%d|%lld", recv_acc_id, amt);
            char fp[MAX_FINGERPRINT_LEN];
            compute_payload_fingerprint(CMD_TRANSFER, cur_user.user_id, raw_args, fp);

            int db_lock = acquire_db_lock(1);
            RequestResult rr;
            int idemp_res = lookup_request_result(req_id, cur_user.user_id, CMD_TRANSFER, fp, &rr);

            if (idemp_res == IDEMPOTENCY_MATCH) {
                release_db_lock(db_lock);
                if (strcmp(rr.status, "COMPLETED") == 0) {
                    snprintf(out_buf, sizeof(out_buf), "SUCCESS|" CODE_REQUEST_ALREADY_COMPLETED "|%s|%d|%s\n",
                             req_id, rr.transaction_id, rr.response_message);
                } else {
                    snprintf(out_buf, sizeof(out_buf), "ERROR|%s|%s\n",
                             rr.response_code, rr.response_message);
                }
                send_response(client_fd, out_buf);
                continue;
            } else if (idemp_res == IDEMPOTENCY_CONFLICT) {
                release_db_lock(db_lock);
                send_response(client_fd, "ERROR|" CODE_IDEMPOTENCY_CONFLICT "|Request ID reused with different content or user.\n");
                continue;
            } else if (idemp_res == IDEMPOTENCY_IN_PROGRESS) {
                release_db_lock(db_lock);
                send_response(client_fd, "ERROR|IN_PROGRESS|Request is currently being processed. Retry shortly.\n");
                continue;
            }

            register_request(req_id, cur_user.user_id, CMD_TRANSFER, fp);

            Account sender_acc;
            if (get_account_by_user_id(cur_user.user_id, &sender_acc) != 0) {
                reject_or_fail_request(req_id, "REJECTED", CODE_NOT_FOUND, "Sender account not found");
                release_db_lock(db_lock);
                send_response(client_fd, "ERROR|" CODE_NOT_FOUND "|Sender account not found.\n");
                continue;
            }

            int tx_id = 0;
            char err_msg[128] = {0};
            int exec_rc = execute_transfer(req_id, sender_acc.account_id, recv_acc_id, amt, &tx_id, err_msg, sizeof(err_msg));
            if (exec_rc == 0) {
                char succ_msg[128];
                snprintf(succ_msg, sizeof(succ_msg), "Transferred $%.2f to account %d", (double)amt / 100.0, recv_acc_id);
                complete_request(req_id, CODE_REQUEST_COMPLETED, succ_msg, tx_id);
                release_db_lock(db_lock);
                snprintf(out_buf, sizeof(out_buf), "SUCCESS|" CODE_REQUEST_COMPLETED "|%s|%d|%s\n",
                         req_id, tx_id, succ_msg);
                send_response(client_fd, out_buf);
            } else {
                const char *err_code = (exec_rc == -4) ? CODE_INSUFFICIENT_FUNDS : CODE_INVALID_ARGS;
                reject_or_fail_request(req_id, "REJECTED", err_code, err_msg);
                release_db_lock(db_lock);
                snprintf(out_buf, sizeof(out_buf), "ERROR|%s|%s\n", err_code, err_msg);
                send_response(client_fd, out_buf);
            }
            continue;
        }

        /* 9. APPLY_LOAN (Customer only, Idempotent) */
        if (strcmp(cmd, CMD_APPLY_LOAN) == 0) {
            if (cur_user.role != ROLE_CUSTOMER) {
                send_response(client_fd, "ERROR|" CODE_NOT_AUTHORIZED "|Only customers can apply for loans.\n");
                continue;
            }

            char *req_id = strsep(&line, FIELD_DELIM_STR);
            char *amt_str = strsep(&line, FIELD_DELIM_STR);
            if (!req_id || !amt_str) {
                send_response(client_fd, "ERROR|" CODE_INVALID_ARGS "|Usage: APPLY_LOAN|req_id|amount_cents\n");
                continue;
            }

            if (!validate_request_id(req_id)) {
                send_response(client_fd, "ERROR|" CODE_INVALID_REQUEST_ID "|Invalid request ID.\n");
                continue;
            }

            long long amt = atoll(amt_str);
            if (amt <= 0) {
                send_response(client_fd, "ERROR|" CODE_INVALID_ARGS "|Loan amount must be positive.\n");
                continue;
            }

            char raw_args[64];
            snprintf(raw_args, sizeof(raw_args), "%lld", amt);
            char fp[MAX_FINGERPRINT_LEN];
            compute_payload_fingerprint(CMD_APPLY_LOAN, cur_user.user_id, raw_args, fp);

            int db_lock = acquire_db_lock(1);
            RequestResult rr;
            int idemp_res = lookup_request_result(req_id, cur_user.user_id, CMD_APPLY_LOAN, fp, &rr);

            if (idemp_res == IDEMPOTENCY_MATCH) {
                release_db_lock(db_lock);
                snprintf(out_buf, sizeof(out_buf), "SUCCESS|" CODE_REQUEST_ALREADY_COMPLETED "|%s|%d|%s\n",
                         req_id, rr.transaction_id, rr.response_message);
                send_response(client_fd, out_buf);
                continue;
            } else if (idemp_res == IDEMPOTENCY_CONFLICT) {
                release_db_lock(db_lock);
                send_response(client_fd, "ERROR|" CODE_IDEMPOTENCY_CONFLICT "|Request ID reused with different content or user.\n");
                continue;
            }

            register_request(req_id, cur_user.user_id, CMD_APPLY_LOAN, fp);

            Account acc;
            if (get_account_by_user_id(cur_user.user_id, &acc) != 0) {
                reject_or_fail_request(req_id, "REJECTED", CODE_NOT_FOUND, "Customer account not found");
                release_db_lock(db_lock);
                send_response(client_fd, "ERROR|" CODE_NOT_FOUND "|Customer account not found.\n");
                continue;
            }

            int loan_id = 0;
            if (create_loan(acc.account_id, amt, &loan_id) > 0) {
                char succ_msg[128];
                snprintf(succ_msg, sizeof(succ_msg), "Loan application #%d submitted successfully", loan_id);
                complete_request(req_id, CODE_REQUEST_COMPLETED, succ_msg, loan_id);
                release_db_lock(db_lock);
                snprintf(out_buf, sizeof(out_buf), "SUCCESS|" CODE_REQUEST_COMPLETED "|%s|%d|%s\n",
                         req_id, loan_id, succ_msg);
                send_response(client_fd, out_buf);
            } else {
                reject_or_fail_request(req_id, "FAILED", CODE_STORAGE_ERROR, "Failed to record loan application");
                release_db_lock(db_lock);
                send_response(client_fd, "ERROR|" CODE_STORAGE_ERROR "|Failed to submit loan application.\n");
            }
            continue;
        }

        /* 10. VIEW_MY_LOANS (Customer only) */
        if (strcmp(cmd, CMD_VIEW_MY_LOANS) == 0) {
            if (cur_user.role != ROLE_CUSTOMER) {
                send_response(client_fd, "ERROR|" CODE_NOT_AUTHORIZED "|Only customers can view their loans.\n");
                continue;
            }

            int db_lock = acquire_db_lock(0);
            Account acc;
            if (get_account_by_user_id(cur_user.user_id, &acc) != 0) {
                release_db_lock(db_lock);
                send_response(client_fd, "ERROR|" CODE_NOT_FOUND "|Customer account not found.\n");
                continue;
            }

            Loan loans[64];
            int count = 0;
            get_loans_by_account(acc.account_id, loans, 64, &count);
            release_db_lock(db_lock);

            send_response(client_fd, "START_LOANS\n");
            for (int i = 0; i < count; i++) {
                char ts_str[64];
                struct tm *tm_info = localtime(&loans[i].created_at);
                strftime(ts_str, sizeof(ts_str), "%Y-%m-%d %H:%M:%S", tm_info);
                snprintf(out_buf, sizeof(out_buf), "LOAN|%d|%.2f|%s|%d|%s\n",
                         loans[i].loan_id, (double)loans[i].amount_cents / 100.0,
                         loans[i].status, loans[i].assigned_employee_id, ts_str);
                send_response(client_fd, out_buf);
            }
            send_response(client_fd, "END_LOANS\n");
            continue;
        }

        /* 11. SUBMIT_FEEDBACK (Customer only) */
        if (strcmp(cmd, CMD_SUBMIT_FEEDBACK) == 0) {
            if (cur_user.role != ROLE_CUSTOMER) {
                send_response(client_fd, "ERROR|" CODE_NOT_AUTHORIZED "|Only customers submit feedback.\n");
                continue;
            }

            char *msg = strsep(&line, FIELD_DELIM_STR);
            if (!msg || strlen(msg) == 0) {
                send_response(client_fd, "ERROR|" CODE_INVALID_ARGS "|Feedback message cannot be empty.\n");
                continue;
            }

            int db_lock = acquire_db_lock(1);
            int fb_id = 0;
            add_feedback(cur_user.user_id, msg, &fb_id);
            release_db_lock(db_lock);

            send_response(client_fd, "SUCCESS|FEEDBACK_SAVED|Thank you for your feedback!\n");
            continue;
        }

        /* 12. EMPLOYEE: GET_ASSIGNED_LOANS */
        if (strcmp(cmd, CMD_GET_ASSIGNED_LOANS) == 0) {
            if (cur_user.role != ROLE_EMPLOYEE && cur_user.role != ROLE_MANAGER) {
                send_response(client_fd, "ERROR|" CODE_NOT_AUTHORIZED "|Only employees and managers can view assigned loans.\n");
                continue;
            }

            int db_lock = acquire_db_lock(0);
            Loan loans[64];
            int count = 0;
            get_loans_by_employee(cur_user.user_id, loans, 64, &count);
            release_db_lock(db_lock);

            send_response(client_fd, "START_LOANS\n");
            for (int i = 0; i < count; i++) {
                char ts_str[64];
                struct tm *tm_info = localtime(&loans[i].created_at);
                strftime(ts_str, sizeof(ts_str), "%Y-%m-%d %H:%M:%S", tm_info);
                snprintf(out_buf, sizeof(out_buf), "LOAN|%d|%d|%.2f|%s|%s\n",
                         loans[i].loan_id, loans[i].account_id,
                         (double)loans[i].amount_cents / 100.0,
                         loans[i].status, ts_str);
                send_response(client_fd, out_buf);
            }
            send_response(client_fd, "END_LOANS\n");
            continue;
        }

        /* 13. EMPLOYEE: PROCESS_LOAN (Idempotent) */
        if (strcmp(cmd, CMD_PROCESS_LOAN) == 0) {
            if (cur_user.role != ROLE_EMPLOYEE && cur_user.role != ROLE_MANAGER) {
                send_response(client_fd, "ERROR|" CODE_NOT_AUTHORIZED "|Only employees/managers can process loans.\n");
                continue;
            }

            char *req_id = strsep(&line, FIELD_DELIM_STR);
            char *loan_id_str = strsep(&line, FIELD_DELIM_STR);
            char *decision = strsep(&line, FIELD_DELIM_STR);

            if (!req_id || !loan_id_str || !decision) {
                send_response(client_fd, "ERROR|" CODE_INVALID_ARGS "|Usage: PROCESS_LOAN|req_id|loan_id|APPROVED_or_REJECTED\n");
                continue;
            }

            if (!validate_request_id(req_id)) {
                send_response(client_fd, "ERROR|" CODE_INVALID_REQUEST_ID "|Invalid request ID.\n");
                continue;
            }

            int loan_id = atoi(loan_id_str);
            if (loan_id <= 0 || (strcasecmp(decision, "APPROVED") != 0 && strcasecmp(decision, "REJECTED") != 0)) {
                send_response(client_fd, "ERROR|" CODE_INVALID_ARGS "|Decision must be APPROVED or REJECTED.\n");
                continue;
            }

            char raw_args[128];
            snprintf(raw_args, sizeof(raw_args), "%d|%s", loan_id, decision);
            char fp[MAX_FINGERPRINT_LEN];
            compute_payload_fingerprint(CMD_PROCESS_LOAN, cur_user.user_id, raw_args, fp);

            int db_lock = acquire_db_lock(1);
            RequestResult rr;
            int idemp_res = lookup_request_result(req_id, cur_user.user_id, CMD_PROCESS_LOAN, fp, &rr);

            if (idemp_res == IDEMPOTENCY_MATCH) {
                release_db_lock(db_lock);
                snprintf(out_buf, sizeof(out_buf), "SUCCESS|" CODE_REQUEST_ALREADY_COMPLETED "|%s|%d|%s\n",
                         req_id, rr.transaction_id, rr.response_message);
                send_response(client_fd, out_buf);
                continue;
            } else if (idemp_res == IDEMPOTENCY_CONFLICT) {
                release_db_lock(db_lock);
                send_response(client_fd, "ERROR|" CODE_IDEMPOTENCY_CONFLICT "|Request ID reused with different content or user.\n");
                continue;
            }

            register_request(req_id, cur_user.user_id, CMD_PROCESS_LOAN, fp);

            int tx_id = 0;
            char err_msg[128] = {0};
            int exec_rc = execute_loan_process(req_id, loan_id, decision, cur_user.user_id, &tx_id, err_msg, sizeof(err_msg));
            if (exec_rc == 0) {
                char succ_msg[128];
                snprintf(succ_msg, sizeof(succ_msg), "Loan #%d %s successfully", loan_id, decision);
                complete_request(req_id, CODE_REQUEST_COMPLETED, succ_msg, tx_id);
                release_db_lock(db_lock);
                snprintf(out_buf, sizeof(out_buf), "SUCCESS|" CODE_REQUEST_COMPLETED "|%s|%d|%s\n",
                         req_id, tx_id, succ_msg);
                send_response(client_fd, out_buf);
            } else {
                reject_or_fail_request(req_id, "REJECTED", CODE_INVALID_ARGS, err_msg);
                release_db_lock(db_lock);
                snprintf(out_buf, sizeof(out_buf), "ERROR|" CODE_INVALID_ARGS "|%s\n", err_msg);
                send_response(client_fd, out_buf);
            }
            continue;
        }

        /* 14. EMPLOYEE/MANAGER: VIEW_CUSTOMER */
        if (strcmp(cmd, CMD_VIEW_CUSTOMER) == 0) {
            if (cur_user.role == ROLE_CUSTOMER) {
                send_response(client_fd, "ERROR|" CODE_NOT_AUTHORIZED "|Customers cannot inspect other accounts.\n");
                continue;
            }

            char *acc_id_str = strsep(&line, FIELD_DELIM_STR);
            if (!acc_id_str) {
                send_response(client_fd, "ERROR|" CODE_INVALID_ARGS "|Usage: VIEW_CUSTOMER|account_id\n");
                continue;
            }

            int acc_id = atoi(acc_id_str);
            int db_lock = acquire_db_lock(0);
            Account acc;
            User cust_user;
            if (get_account_by_id(acc_id, &acc) == 0 && get_user_by_id(acc.user_id, &cust_user) == 0) {
                release_db_lock(db_lock);
                snprintf(out_buf, sizeof(out_buf), "SUCCESS|CUSTOMER_INFO|%d|%s|%.2f|%s\n",
                         acc.account_id, cust_user.username,
                         (double)acc.balance_cents / 100.0,
                         acc.active ? "ACTIVE" : "INACTIVE");
                send_response(client_fd, out_buf);
            } else {
                release_db_lock(db_lock);
                send_response(client_fd, "ERROR|" CODE_NOT_FOUND "|Customer account not found.\n");
            }
            continue;
        }

        /* 15. MANAGER: GET_ALL_LOANS */
        if (strcmp(cmd, CMD_GET_ALL_LOANS) == 0) {
            if (cur_user.role != ROLE_MANAGER && cur_user.role != ROLE_ADMIN) {
                send_response(client_fd, "ERROR|" CODE_NOT_AUTHORIZED "|Only managers/admins can view all loans.\n");
                continue;
            }

            int db_lock = acquire_db_lock(0);
            Loan loans[128];
            int count = 0;
            get_all_loans(loans, 128, &count);
            release_db_lock(db_lock);

            send_response(client_fd, "START_LOANS\n");
            for (int i = 0; i < count; i++) {
                char ts_str[64];
                struct tm *tm_info = localtime(&loans[i].created_at);
                strftime(ts_str, sizeof(ts_str), "%Y-%m-%d %H:%M:%S", tm_info);
                snprintf(out_buf, sizeof(out_buf), "LOAN|%d|%d|%.2f|%s|%d|%s\n",
                         loans[i].loan_id, loans[i].account_id,
                         (double)loans[i].amount_cents / 100.0,
                         loans[i].status, loans[i].assigned_employee_id, ts_str);
                send_response(client_fd, out_buf);
            }
            send_response(client_fd, "END_LOANS\n");
            continue;
        }

        /* 16. MANAGER: ASSIGN_LOAN (Idempotent) */
        if (strcmp(cmd, CMD_ASSIGN_LOAN) == 0) {
            if (cur_user.role != ROLE_MANAGER && cur_user.role != ROLE_ADMIN) {
                send_response(client_fd, "ERROR|" CODE_NOT_AUTHORIZED "|Only managers can assign loans.\n");
                continue;
            }

            char *req_id = strsep(&line, FIELD_DELIM_STR);
            char *loan_id_str = strsep(&line, FIELD_DELIM_STR);
            char *emp_id_str = strsep(&line, FIELD_DELIM_STR);

            if (!req_id || !loan_id_str || !emp_id_str) {
                send_response(client_fd, "ERROR|" CODE_INVALID_ARGS "|Usage: ASSIGN_LOAN|req_id|loan_id|emp_id\n");
                continue;
            }

            if (!validate_request_id(req_id)) {
                send_response(client_fd, "ERROR|" CODE_INVALID_REQUEST_ID "|Invalid request ID.\n");
                continue;
            }

            int loan_id = atoi(loan_id_str);
            int emp_id = atoi(emp_id_str);

            char raw_args[128];
            snprintf(raw_args, sizeof(raw_args), "%d|%d", loan_id, emp_id);
            char fp[MAX_FINGERPRINT_LEN];
            compute_payload_fingerprint(CMD_ASSIGN_LOAN, cur_user.user_id, raw_args, fp);

            int db_lock = acquire_db_lock(1);
            RequestResult rr;
            int idemp_res = lookup_request_result(req_id, cur_user.user_id, CMD_ASSIGN_LOAN, fp, &rr);

            if (idemp_res == IDEMPOTENCY_MATCH) {
                release_db_lock(db_lock);
                snprintf(out_buf, sizeof(out_buf), "SUCCESS|" CODE_REQUEST_ALREADY_COMPLETED "|%s|0|%s\n",
                         req_id, rr.response_message);
                send_response(client_fd, out_buf);
                continue;
            } else if (idemp_res == IDEMPOTENCY_CONFLICT) {
                release_db_lock(db_lock);
                send_response(client_fd, "ERROR|" CODE_IDEMPOTENCY_CONFLICT "|Request ID reused with different content or user.\n");
                continue;
            }

            register_request(req_id, cur_user.user_id, CMD_ASSIGN_LOAN, fp);

            User emp;
            if (get_user_by_id(emp_id, &emp) != 0 || (emp.role != ROLE_EMPLOYEE && emp.role != ROLE_MANAGER)) {
                reject_or_fail_request(req_id, "REJECTED", CODE_NOT_FOUND, "Employee not found or invalid role");
                release_db_lock(db_lock);
                send_response(client_fd, "ERROR|" CODE_NOT_FOUND "|Employee ID not found.\n");
                continue;
            }

            if (assign_loan(loan_id, emp_id) == 0) {
                char succ_msg[128];
                snprintf(succ_msg, sizeof(succ_msg), "Loan #%d assigned to employee %s (ID %d)", loan_id, emp.username, emp_id);
                complete_request(req_id, CODE_REQUEST_COMPLETED, succ_msg, 0);
                release_db_lock(db_lock);
                snprintf(out_buf, sizeof(out_buf), "SUCCESS|" CODE_REQUEST_COMPLETED "|%s|0|%s\n", req_id, succ_msg);
                send_response(client_fd, out_buf);
            } else {
                reject_or_fail_request(req_id, "FAILED", CODE_STORAGE_ERROR, "Failed to assign loan");
                release_db_lock(db_lock);
                send_response(client_fd, "ERROR|" CODE_STORAGE_ERROR "|Failed to assign loan.\n");
            }
            continue;
        }

        /* 17. MANAGER: SET_ACCOUNT_STATUS (Idempotent) */
        if (strcmp(cmd, CMD_SET_ACCOUNT_STATUS) == 0) {
            if (cur_user.role != ROLE_MANAGER && cur_user.role != ROLE_ADMIN) {
                send_response(client_fd, "ERROR|" CODE_NOT_AUTHORIZED "|Only managers/admins can alter account status.\n");
                continue;
            }

            char *req_id = strsep(&line, FIELD_DELIM_STR);
            char *acc_id_str = strsep(&line, FIELD_DELIM_STR);
            char *active_str = strsep(&line, FIELD_DELIM_STR);

            if (!req_id || !acc_id_str || !active_str) {
                send_response(client_fd, "ERROR|" CODE_INVALID_ARGS "|Usage: SET_ACCOUNT_STATUS|req_id|account_id|1_or_0\n");
                continue;
            }

            if (!validate_request_id(req_id)) {
                send_response(client_fd, "ERROR|" CODE_INVALID_REQUEST_ID "|Invalid request ID.\n");
                continue;
            }

            int acc_id = atoi(acc_id_str);
            int active = atoi(active_str);

            char raw_args[128];
            snprintf(raw_args, sizeof(raw_args), "%d|%d", acc_id, active);
            char fp[MAX_FINGERPRINT_LEN];
            compute_payload_fingerprint(CMD_SET_ACCOUNT_STATUS, cur_user.user_id, raw_args, fp);

            int db_lock = acquire_db_lock(1);
            RequestResult rr;
            int idemp_res = lookup_request_result(req_id, cur_user.user_id, CMD_SET_ACCOUNT_STATUS, fp, &rr);

            if (idemp_res == IDEMPOTENCY_MATCH) {
                release_db_lock(db_lock);
                snprintf(out_buf, sizeof(out_buf), "SUCCESS|" CODE_REQUEST_ALREADY_COMPLETED "|%s|0|%s\n",
                         req_id, rr.response_message);
                send_response(client_fd, out_buf);
                continue;
            } else if (idemp_res == IDEMPOTENCY_CONFLICT) {
                release_db_lock(db_lock);
                send_response(client_fd, "ERROR|" CODE_IDEMPOTENCY_CONFLICT "|Request ID reused with different content or user.\n");
                continue;
            }

            register_request(req_id, cur_user.user_id, CMD_SET_ACCOUNT_STATUS, fp);

            if (set_account_active(acc_id, active) == 0) {
                char succ_msg[128];
                snprintf(succ_msg, sizeof(succ_msg), "Account #%d set to %s", acc_id, active ? "ACTIVE" : "INACTIVE");
                complete_request(req_id, CODE_REQUEST_COMPLETED, succ_msg, 0);
                release_db_lock(db_lock);
                snprintf(out_buf, sizeof(out_buf), "SUCCESS|" CODE_REQUEST_COMPLETED "|%s|0|%s\n", req_id, succ_msg);
                send_response(client_fd, out_buf);
            } else {
                reject_or_fail_request(req_id, "FAILED", CODE_NOT_FOUND, "Account not found");
                release_db_lock(db_lock);
                send_response(client_fd, "ERROR|" CODE_NOT_FOUND "|Account not found.\n");
            }
            continue;
        }

        /* 18. MANAGER: VIEW_ALL_FEEDBACK */
        if (strcmp(cmd, CMD_VIEW_ALL_FEEDBACK) == 0) {
            if (cur_user.role != ROLE_MANAGER && cur_user.role != ROLE_ADMIN) {
                send_response(client_fd, "ERROR|" CODE_NOT_AUTHORIZED "|Only managers/admins can view feedback.\n");
                continue;
            }

            int db_lock = acquire_db_lock(0);
            Feedback fbs[128];
            int count = 0;
            get_all_feedback(fbs, 128, &count);
            release_db_lock(db_lock);

            send_response(client_fd, "START_FEEDBACK\n");
            for (int i = 0; i < count; i++) {
                char ts_str[64];
                struct tm *tm_info = localtime(&fbs[i].timestamp);
                strftime(ts_str, sizeof(ts_str), "%Y-%m-%d %H:%M:%S", tm_info);
                snprintf(out_buf, sizeof(out_buf), "FB|%d|%d|%s|%s\n",
                         fbs[i].feedback_id, fbs[i].user_id, fbs[i].message, ts_str);
                send_response(client_fd, out_buf);
            }
            send_response(client_fd, "END_FEEDBACK\n");
            continue;
        }

        /* 19. ADMIN: ADD_USER (Idempotent) */
        if (strcmp(cmd, CMD_ADD_USER) == 0) {
            if (cur_user.role != ROLE_ADMIN) {
                send_response(client_fd, "ERROR|" CODE_NOT_AUTHORIZED "|Only administrators can add users.\n");
                continue;
            }

            char *req_id = strsep(&line, FIELD_DELIM_STR);
            char *new_user = strsep(&line, FIELD_DELIM_STR);
            char *new_pass = strsep(&line, FIELD_DELIM_STR);
            char *role_str = strsep(&line, FIELD_DELIM_STR);
            char *init_bal_str = strsep(&line, FIELD_DELIM_STR);

            if (!req_id || !new_user || !new_pass || !role_str) {
                send_response(client_fd, "ERROR|" CODE_INVALID_ARGS "|Usage: ADD_USER|req_id|username|password|role|initial_balance_cents\n");
                continue;
            }

            if (!validate_request_id(req_id)) {
                send_response(client_fd, "ERROR|" CODE_INVALID_REQUEST_ID "|Invalid request ID.\n");
                continue;
            }

            UserRole r = string_to_role(role_str);
            if (r == ROLE_UNKNOWN) {
                send_response(client_fd, "ERROR|" CODE_INVALID_ARGS "|Invalid role. Use CUSTOMER, EMPLOYEE, MANAGER, or ADMIN.\n");
                continue;
            }

            long long init_bal = init_bal_str ? atoll(init_bal_str) : 0;
            char raw_args[256];
            snprintf(raw_args, sizeof(raw_args), "%s|%s|%lld", new_user, role_str, init_bal);
            char fp[MAX_FINGERPRINT_LEN];
            compute_payload_fingerprint(CMD_ADD_USER, cur_user.user_id, raw_args, fp);

            int db_lock = acquire_db_lock(1);
            RequestResult rr;
            int idemp_res = lookup_request_result(req_id, cur_user.user_id, CMD_ADD_USER, fp, &rr);

            if (idemp_res == IDEMPOTENCY_MATCH) {
                release_db_lock(db_lock);
                snprintf(out_buf, sizeof(out_buf), "SUCCESS|" CODE_REQUEST_ALREADY_COMPLETED "|%s|%d|%s\n",
                         req_id, rr.transaction_id, rr.response_message);
                send_response(client_fd, out_buf);
                continue;
            } else if (idemp_res == IDEMPOTENCY_CONFLICT) {
                release_db_lock(db_lock);
                send_response(client_fd, "ERROR|" CODE_IDEMPOTENCY_CONFLICT "|Request ID reused with different content or user.\n");
                continue;
            }

            register_request(req_id, cur_user.user_id, CMD_ADD_USER, fp);

            char hash[MAX_HASH_LEN];
            sha256_string(new_pass, hash);

            User created;
            int uid = add_user(new_user, hash, r, &created);
            if (uid > 0) {
                int acc_id = 0;
                if (r == ROLE_CUSTOMER) {
                    Account acc;
                    create_account(uid, init_bal, &acc);
                    acc_id = acc.account_id;
                }
                char succ_msg[128];
                snprintf(succ_msg, sizeof(succ_msg), "Created user %s (ID %d, Acc %d)", new_user, uid, acc_id);
                complete_request(req_id, CODE_REQUEST_COMPLETED, succ_msg, acc_id);
                release_db_lock(db_lock);
                snprintf(out_buf, sizeof(out_buf), "SUCCESS|" CODE_REQUEST_COMPLETED "|%s|%d|%s\n", req_id, acc_id, succ_msg);
                send_response(client_fd, out_buf);
            } else {
                const char *err = (uid == -2) ? "Username already exists" : "Failed to create user";
                reject_or_fail_request(req_id, "REJECTED", CODE_INVALID_ARGS, err);
                release_db_lock(db_lock);
                snprintf(out_buf, sizeof(out_buf), "ERROR|" CODE_INVALID_ARGS "|%s\n", err);
                send_response(client_fd, out_buf);
            }
            continue;
        }

        /* 20. ADMIN: MODIFY_USER (Idempotent) */
        if (strcmp(cmd, CMD_MODIFY_USER) == 0) {
            if (cur_user.role != ROLE_ADMIN) {
                send_response(client_fd, "ERROR|" CODE_NOT_AUTHORIZED "|Only administrators can modify users.\n");
                continue;
            }

            char *req_id = strsep(&line, FIELD_DELIM_STR);
            char *uid_str = strsep(&line, FIELD_DELIM_STR);
            char *new_uname = strsep(&line, FIELD_DELIM_STR);
            char *role_str = strsep(&line, FIELD_DELIM_STR);
            char *active_str = strsep(&line, FIELD_DELIM_STR);

            if (!req_id || !uid_str || !role_str || !active_str) {
                send_response(client_fd, "ERROR|" CODE_INVALID_ARGS "|Usage: MODIFY_USER|req_id|user_id|new_username|role|active\n");
                continue;
            }

            if (!validate_request_id(req_id)) {
                send_response(client_fd, "ERROR|" CODE_INVALID_REQUEST_ID "|Invalid request ID.\n");
                continue;
            }

            int target_uid = atoi(uid_str);
            UserRole r = string_to_role(role_str);
            int active = atoi(active_str);

            char raw_args[256];
            snprintf(raw_args, sizeof(raw_args), "%d|%s|%s|%d", target_uid, new_uname ? new_uname : "", role_str, active);
            char fp[MAX_FINGERPRINT_LEN];
            compute_payload_fingerprint(CMD_MODIFY_USER, cur_user.user_id, raw_args, fp);

            int db_lock = acquire_db_lock(1);
            RequestResult rr;
            int idemp_res = lookup_request_result(req_id, cur_user.user_id, CMD_MODIFY_USER, fp, &rr);

            if (idemp_res == IDEMPOTENCY_MATCH) {
                release_db_lock(db_lock);
                snprintf(out_buf, sizeof(out_buf), "SUCCESS|" CODE_REQUEST_ALREADY_COMPLETED "|%s|0|%s\n",
                         req_id, rr.response_message);
                send_response(client_fd, out_buf);
                continue;
            } else if (idemp_res == IDEMPOTENCY_CONFLICT) {
                release_db_lock(db_lock);
                send_response(client_fd, "ERROR|" CODE_IDEMPOTENCY_CONFLICT "|Request ID reused with different content or user.\n");
                continue;
            }

            register_request(req_id, cur_user.user_id, CMD_MODIFY_USER, fp);

            if (update_user_details(target_uid, new_uname, r, active) == 0) {
                char succ_msg[128];
                snprintf(succ_msg, sizeof(succ_msg), "User #%d updated successfully", target_uid);
                complete_request(req_id, CODE_REQUEST_COMPLETED, succ_msg, 0);
                release_db_lock(db_lock);
                snprintf(out_buf, sizeof(out_buf), "SUCCESS|" CODE_REQUEST_COMPLETED "|%s|0|%s\n", req_id, succ_msg);
                send_response(client_fd, out_buf);
            } else {
                reject_or_fail_request(req_id, "FAILED", CODE_NOT_FOUND, "User ID not found");
                release_db_lock(db_lock);
                send_response(client_fd, "ERROR|" CODE_NOT_FOUND "|User ID not found.\n");
            }
            continue;
        }

        /* 21. ADMIN: VIEW_ALL_USERS */
        if (strcmp(cmd, CMD_VIEW_ALL_USERS) == 0) {
            if (cur_user.role != ROLE_ADMIN) {
                send_response(client_fd, "ERROR|" CODE_NOT_AUTHORIZED "|Only administrators can list users.\n");
                continue;
            }

            int db_lock = acquire_db_lock(0);
            User users[128];
            int count = 0;
            get_all_users(users, 128, &count);
            release_db_lock(db_lock);

            send_response(client_fd, "START_USERS\n");
            for (int i = 0; i < count; i++) {
                snprintf(out_buf, sizeof(out_buf), "USER|%d|%s|%s|%s\n",
                         users[i].user_id, users[i].username,
                         role_to_string(users[i].role),
                         users[i].active ? "ACTIVE" : "INACTIVE");
                send_response(client_fd, out_buf);
            }
            send_response(client_fd, "END_USERS\n");
            continue;
        }

        /* 22. ADMIN: VIEW_ALL_ACCOUNTS */
        if (strcmp(cmd, CMD_VIEW_ALL_ACCOUNTS) == 0) {
            if (cur_user.role != ROLE_ADMIN && cur_user.role != ROLE_MANAGER) {
                send_response(client_fd, "ERROR|" CODE_NOT_AUTHORIZED "|Only administrators and managers can list accounts.\n");
                continue;
            }

            int db_lock = acquire_db_lock(0);
            Account accs[128];
            int count = 0;
            get_all_accounts(accs, 128, &count);
            release_db_lock(db_lock);

            send_response(client_fd, "START_ACCOUNTS\n");
            for (int i = 0; i < count; i++) {
                snprintf(out_buf, sizeof(out_buf), "ACCOUNT|%d|%d|%.2f|%s\n",
                         accs[i].account_id, accs[i].user_id,
                         (double)accs[i].balance_cents / 100.0,
                         accs[i].active ? "ACTIVE" : "INACTIVE");
                send_response(client_fd, out_buf);
            }
            send_response(client_fd, "END_ACCOUNTS\n");
            continue;
        }

        /* Unknown command */
        send_response(client_fd, "ERROR|UNKNOWN_COMMAND|Unrecognized command.\n");
    }

    /* Cleanup on disconnect */
    if (session_lock_fd >= 0) {
        release_user_session_lock(session_lock_fd);
    }
}
