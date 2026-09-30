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
#include <errno.h>
#include <termios.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "protocol.h"
#include "models.h"
#include "idempotency.h"

static char g_server_ip[64] = "127.0.0.1";
static int  g_server_port   = DEFAULT_PORT;

/* Session info */
static int  g_logged_in = 0;
static int  g_user_id   = 0;
static char g_username[MAX_USERNAME_LEN] = {0};
static char g_password[MAX_PASSWORD_LEN] = {0};
static char g_role_str[MAX_ROLE_LEN]     = {0};
static UserRole g_role                   = ROLE_UNKNOWN;

/* Terminal password masking */
static void get_password_masked(const char *prompt, char *password, size_t max_len)
{
    printf("%s", prompt);
    fflush(stdout);

    struct termios old_term, new_term;
    tcgetattr(STDIN_FILENO, &old_term);
    new_term = old_term;
    new_term.c_lflag &= ~(ECHO);
    tcsetattr(STDIN_FILENO, TCSANOW, &new_term);

    if (fgets(password, max_len, stdin) != NULL) {
        size_t len = strlen(password);
        while (len > 0 && (password[len - 1] == '\n' || password[len - 1] == '\r')) {
            password[len - 1] = '\0';
            len--;
        }
    }
    tcsetattr(STDIN_FILENO, TCSANOW, &old_term);
    printf("\n");
}

/* Safe line input that rejects pipe delimiter */
static int get_input_line(const char *prompt, char *buf, size_t max_len)
{
    printf("%s", prompt);
    fflush(stdout);
    if (!fgets(buf, max_len, stdin)) return -1;

    size_t len = strlen(buf);
    while (len > 0 && (buf[len - 1] == '\n' || buf[len - 1] == '\r')) {
        buf[len - 1] = '\0';
        len--;
    }

    if (strchr(buf, FIELD_DELIM_CHAR) != NULL) {
        printf("[!] Error: Character '%c' is reserved and cannot be entered.\n", FIELD_DELIM_CHAR);
        return -2;
    }
    return 0;
}

/* Connect socket with configurable timeout */
static int connect_to_server(const char *ip, int port, int timeout_sec)
{
    int sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_fd < 0) return -1;

    struct timeval tv;
    tv.tv_sec = timeout_sec;
    tv.tv_usec = 0;
    setsockopt(sock_fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
    setsockopt(sock_fd, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof(tv));

    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, ip, &serv_addr.sin_addr) <= 0) {
        close(sock_fd);
        return -1;
    }

    if (connect(sock_fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        close(sock_fd);
        return -1;
    }

    return sock_fd;
}

/* Read single line response */
static ssize_t sock_read_line(int fd, char *buf, size_t max_len)
{
    size_t idx = 0;
    while (idx + 1 < max_len) {
        char c;
        ssize_t r = read(fd, &c, 1);
        if (r <= 0) {
            if (r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                return -2; /* Timeout */
            }
            return (idx > 0) ? (ssize_t)idx : r;
        }
        if (c == '\r') continue;
        if (c == '\n') break;
        buf[idx++] = c;
    }
    buf[idx] = '\0';
    return (ssize_t)idx;
}

/* Send a command string */
static int sock_send(int fd, const char *msg)
{
    size_t len = strlen(msg);
    ssize_t sent = 0;
    while (sent < (ssize_t)len) {
        ssize_t s = write(fd, msg + sent, len - sent);
        if (s <= 0) {
            return -1;
        }
        sent += s;
    }
    return 0;
}

/* Robust RPC with Automatic Idempotent Retry */
static int execute_rpc_with_retry(
    int *p_sock_fd,
    const char *cmd_name,
    const char *payload_without_req_id,
    char *out_resp,
    size_t out_resp_size
) {
    char req_id[MAX_REQ_ID_LEN];
    if (generate_request_id(req_id, sizeof(req_id)) != 0) {
        printf("[!] Failed to generate cryptographically secure request ID.\n");
        return -1;
    }

    char full_cmd[BUFFER_SIZE];
    if (payload_without_req_id && strlen(payload_without_req_id) > 0) {
        snprintf(full_cmd, sizeof(full_cmd), "%s|%s|%s\n", cmd_name, req_id, payload_without_req_id);
    } else {
        snprintf(full_cmd, sizeof(full_cmd), "%s|%s\n", cmd_name, req_id);
    }

    int attempts = 0;
    const int max_attempts = 3;

    while (attempts < max_attempts) {
        attempts++;
        if (sock_send(*p_sock_fd, full_cmd) == 0) {
            ssize_t r = sock_read_line(*p_sock_fd, out_resp, out_resp_size);
            if (r > 0) {
                /* Successfully received response */
                return 0;
            }
            if (r == -2) {
                printf("[!] Request timed out (Attempt %d/%d). Possible response loss.\n", attempts, max_attempts);
            } else {
                printf("[!] Connection broken (Attempt %d/%d).\n", attempts, max_attempts);
            }
        } else {
            printf("[!] Send failed (Attempt %d/%d).\n", attempts, max_attempts);
        }

        /* If we are here, transmission or reception failed.
           Perform Automatic Reconnect & Idempotent Retry with EXACT same request_id! */
        close(*p_sock_fd);
        *p_sock_fd = -1;

        if (attempts >= max_attempts) break;

        printf("[*] Reconnecting to server and retrying with identical request ID: %s...\n", req_id);
        sleep(1);

        *p_sock_fd = connect_to_server(g_server_ip, g_server_port, 4);
        if (*p_sock_fd < 0) {
            printf("[!] Reconnection failed. Retrying in next attempt...\n");
            continue;
        }

        /* Re-authenticate session */
        if (g_logged_in) {
            char login_cmd[256];
            snprintf(login_cmd, sizeof(login_cmd), "LOGIN|%s|%s\n", g_username, g_password);
            if (sock_send(*p_sock_fd, login_cmd) == 0) {
                char login_resp[BUFFER_SIZE];
                sock_read_line(*p_sock_fd, login_resp, sizeof(login_resp));
                /* Re-login completed */
            }
        }
    }

    printf("[!] RPC failed after %d attempts.\n", max_attempts);
    return -1;
}

/* Parse and display standard financial response */
static void handle_financial_response(const char *resp)
{
    char resp_copy[BUFFER_SIZE];
    strncpy(resp_copy, resp, sizeof(resp_copy) - 1);
    resp_copy[sizeof(resp_copy) - 1] = '\0';

    char *p = resp_copy;
    char *status = strsep(&p, FIELD_DELIM_STR);
    char *code = strsep(&p, FIELD_DELIM_STR);

    if (status && strcmp(status, RESP_SUCCESS) == 0) {
        if (code && strcmp(code, CODE_REQUEST_ALREADY_COMPLETED) == 0) {
            char *req_id = strsep(&p, FIELD_DELIM_STR);
            char *tx_id = strsep(&p, FIELD_DELIM_STR);
            char *msg = p;
            printf("\n=======================================================\n");
            printf("  [IDEMPOTENCY NOTIFICATION] DUPLICATE REQUEST DETECTED\n");
            printf("  Request ID : %s\n", req_id ? req_id : "N/A");
            printf("  Tx ID      : %s (Original Result Replayed)\n", tx_id ? tx_id : "0");
            printf("  Details    : %s\n", msg ? msg : "Success");
            printf("  Status     : Protected! No duplicate funds deducted/added.\n");
            printf("=======================================================\n\n");
        } else if (code && strcmp(code, CODE_REQUEST_COMPLETED) == 0) {
            char *req_id = strsep(&p, FIELD_DELIM_STR);
            char *tx_id = strsep(&p, FIELD_DELIM_STR);
            char *msg = p;
            printf("\n-------------------------------------------------------\n");
            printf("  [SUCCESS] Operation Completed Successfully\n");
            printf("  Request ID : %s\n", req_id ? req_id : "N/A");
            printf("  Tx ID      : %s\n", tx_id ? tx_id : "0");
            printf("  Details    : %s\n", msg ? msg : "Success");
            printf("-------------------------------------------------------\n\n");
        } else {
            printf("\n[+] %s\n\n", p ? p : code);
        }
    } else {
        printf("\n[-] ERROR: [%s] %s\n\n", code ? code : "UNKNOWN", p ? p : "");
    }
}

/* Customer Menu */
static void run_customer_menu(int *sock_fd)
{
    while (g_logged_in) {
        printf("=== Customer Portal [%s] ===\n", g_username);
        printf("1. View Balance\n");
        printf("2. Deposit Funds (Idempotent)\n");
        printf("3. Withdraw Funds (Idempotent)\n");
        printf("4. Transfer Funds (Idempotent)\n");
        printf("5. Apply for Loan (Idempotent)\n");
        printf("6. View My Loans\n");
        printf("7. Transaction History\n");
        printf("8. Submit Feedback\n");
        printf("9. Change Password\n");
        printf("0. Logout\n");

        char choice[16];
        if (get_input_line("Select an option: ", choice, sizeof(choice)) != 0) continue;

        if (strcmp(choice, "1") == 0) {
            sock_send(*sock_fd, "GET_BALANCE\n");
            char resp[BUFFER_SIZE];
            if (sock_read_line(*sock_fd, resp, sizeof(resp)) > 0) {
                int acc_id = 0, active = 0;
                long long bal_cents = 0;
                if (sscanf(resp, "SUCCESS|BALANCE|%d|%lld|%d", &acc_id, &bal_cents, &active) == 3) {
                    printf("\n------------------------------------------------\n");
                    printf(" Account ID : %d\n", acc_id);
                    printf(" Balance    : $%.2f\n", (double)bal_cents / 100.0);
                    printf(" Status     : %s\n", active ? "ACTIVE" : "INACTIVE");
                    printf("------------------------------------------------\n\n");
                } else {
                    printf("[-] %s\n\n", resp);
                }
            }
        } else if (strcmp(choice, "2") == 0) {
            char amt_str[32];
            if (get_input_line("Enter deposit amount ($): ", amt_str, sizeof(amt_str)) != 0) continue;
            double amt = atof(amt_str);
            if (amt <= 0.0) {
                printf("[!] Invalid amount.\n");
                continue;
            }
            long long amt_cents = (long long)(amt * 100.0 + 0.5);
            char payload[64];
            snprintf(payload, sizeof(payload), "%lld", amt_cents);

            char resp[BUFFER_SIZE];
            if (execute_rpc_with_retry(sock_fd, CMD_DEPOSIT, payload, resp, sizeof(resp)) == 0) {
                handle_financial_response(resp);
            }
        } else if (strcmp(choice, "3") == 0) {
            char amt_str[32];
            if (get_input_line("Enter withdrawal amount ($): ", amt_str, sizeof(amt_str)) != 0) continue;
            double amt = atof(amt_str);
            if (amt <= 0.0) {
                printf("[!] Invalid amount.\n");
                continue;
            }
            long long amt_cents = (long long)(amt * 100.0 + 0.5);
            char payload[64];
            snprintf(payload, sizeof(payload), "%lld", amt_cents);

            char resp[BUFFER_SIZE];
            if (execute_rpc_with_retry(sock_fd, CMD_WITHDRAW, payload, resp, sizeof(resp)) == 0) {
                handle_financial_response(resp);
            }
        } else if (strcmp(choice, "4") == 0) {
            char recv_str[32], amt_str[32];
            if (get_input_line("Enter recipient Account ID: ", recv_str, sizeof(recv_str)) != 0) continue;
            if (get_input_line("Enter transfer amount ($): ", amt_str, sizeof(amt_str)) != 0) continue;

            double amt = atof(amt_str);
            if (amt <= 0.0) {
                printf("[!] Invalid amount.\n");
                continue;
            }
            long long amt_cents = (long long)(amt * 100.0 + 0.5);
            char payload[128];
            snprintf(payload, sizeof(payload), "%s|%lld", recv_str, amt_cents);

            char resp[BUFFER_SIZE];
            if (execute_rpc_with_retry(sock_fd, CMD_TRANSFER, payload, resp, sizeof(resp)) == 0) {
                handle_financial_response(resp);
            }
        } else if (strcmp(choice, "5") == 0) {
            char amt_str[32];
            if (get_input_line("Enter loan amount requested ($): ", amt_str, sizeof(amt_str)) != 0) continue;
            double amt = atof(amt_str);
            if (amt <= 0.0) {
                printf("[!] Invalid loan amount.\n");
                continue;
            }
            long long amt_cents = (long long)(amt * 100.0 + 0.5);
            char payload[64];
            snprintf(payload, sizeof(payload), "%lld", amt_cents);

            char resp[BUFFER_SIZE];
            if (execute_rpc_with_retry(sock_fd, CMD_APPLY_LOAN, payload, resp, sizeof(resp)) == 0) {
                handle_financial_response(resp);
            }
        } else if (strcmp(choice, "6") == 0) {
            sock_send(*sock_fd, "VIEW_MY_LOANS\n");
            char resp[BUFFER_SIZE];
            sock_read_line(*sock_fd, resp, sizeof(resp));
            if (strcmp(resp, "START_LOANS") == 0) {
                printf("\n------------------- My Loans -------------------\n");
                printf("%-8s %-12s %-12s %-8s %-20s\n", "Loan ID", "Amount ($)", "Status", "Emp ID", "Created At");
                while (sock_read_line(*sock_fd, resp, sizeof(resp)) > 0) {
                    if (strcmp(resp, "END_LOANS") == 0) break;
                    int l_id = 0, emp_id = 0;
                    double amt = 0.0;
                    char status[32] = {0}, ts[64] = {0};
                    if (sscanf(resp, "LOAN|%d|%lf|%31[^|]|%d|%63[^\n]", &l_id, &amt, status, &emp_id, ts) == 5) {
                        printf("%-8d $%-11.2f %-12s %-8d %-20s\n", l_id, amt, status, emp_id, ts);
                    }
                }
                printf("------------------------------------------------\n\n");
            } else {
                printf("[-] %s\n\n", resp);
            }
        } else if (strcmp(choice, "7") == 0) {
            sock_send(*sock_fd, "GET_TRANSACTIONS\n");
            char resp[BUFFER_SIZE];
            sock_read_line(*sock_fd, resp, sizeof(resp));
            if (strcmp(resp, "START_TRANSACTIONS") == 0) {
                printf("\n-------------------- Transaction Passbook --------------------\n");
                printf("%-6s %-14s %-12s %-8s %-22s %-20s\n",
                       "Tx ID", "Type", "Amount ($)", "Rel Acc", "Details", "Date/Time");
                while (sock_read_line(*sock_fd, resp, sizeof(resp)) > 0) {
                    if (strcmp(resp, "END_TRANSACTIONS") == 0) break;
                    int tx_id = 0, rel_acc = 0;
                    double amt = 0.0;
                    char type[32] = {0}, details[128] = {0}, ts[64] = {0};
                    if (sscanf(resp, "TX|%d|%31[^|]|%lf|%d|%127[^|]|%63[^\n]",
                               &tx_id, type, &amt, &rel_acc, details, ts) >= 5) {
                        printf("%-6d %-14s $%-11.2f %-8d %-22s %-20s\n",
                               tx_id, type, amt, rel_acc, details, ts);
                    }
                }
                printf("--------------------------------------------------------------\n\n");
            } else {
                printf("[-] %s\n\n", resp);
            }
        } else if (strcmp(choice, "8") == 0) {
            char fb[256];
            if (get_input_line("Enter your feedback/complaint: ", fb, sizeof(fb)) != 0) continue;
            char cmd[512];
            snprintf(cmd, sizeof(cmd), "SUBMIT_FEEDBACK|%s\n", fb);
            sock_send(*sock_fd, cmd);
            char resp[BUFFER_SIZE];
            if (sock_read_line(*sock_fd, resp, sizeof(resp)) > 0) {
                printf("[+] %s\n\n", resp);
            }
        } else if (strcmp(choice, "9") == 0) {
            char old_pass[MAX_PASSWORD_LEN], new_pass[MAX_PASSWORD_LEN];
            get_password_masked("Enter current password: ", old_pass, sizeof(old_pass));
            get_password_masked("Enter new password: ", new_pass, sizeof(new_pass));

            char cmd[256];
            snprintf(cmd, sizeof(cmd), "CHANGE_PASSWORD|%s|%s\n", old_pass, new_pass);
            sock_send(*sock_fd, cmd);
            char resp[BUFFER_SIZE];
            if (sock_read_line(*sock_fd, resp, sizeof(resp)) > 0) {
                printf("[+] %s\n\n", resp);
                if (strstr(resp, "SUCCESS")) {
                    strncpy(g_password, new_pass, sizeof(g_password) - 1);
                }
            }
        } else if (strcmp(choice, "0") == 0) {
            sock_send(*sock_fd, "LOGOUT\n");
            g_logged_in = 0;
            printf("[+] Logged out successfully.\n\n");
            break;
        }
    }
}

/* Employee Menu */
static void run_employee_menu(int *sock_fd)
{
    while (g_logged_in) {
        printf("=== Employee Dashboard [%s] ===\n", g_username);
        printf("1. View Assigned Loans\n");
        printf("2. Process Loan (Approve/Reject - Idempotent)\n");
        printf("3. View Customer Account Details\n");
        printf("4. Change Password\n");
        printf("0. Logout\n");

        char choice[16];
        if (get_input_line("Select an option: ", choice, sizeof(choice)) != 0) continue;

        if (strcmp(choice, "1") == 0) {
            sock_send(*sock_fd, "GET_ASSIGNED_LOANS\n");
            char resp[BUFFER_SIZE];
            sock_read_line(*sock_fd, resp, sizeof(resp));
            if (strcmp(resp, "START_LOANS") == 0) {
                printf("\n---------------- Assigned Loans ----------------\n");
                printf("%-8s %-12s %-12s %-12s %-20s\n", "Loan ID", "Account ID", "Amount ($)", "Status", "Date Applied");
                while (sock_read_line(*sock_fd, resp, sizeof(resp)) > 0) {
                    if (strcmp(resp, "END_LOANS") == 0) break;
                    int l_id = 0, acc_id = 0;
                    double amt = 0.0;
                    char status[32] = {0}, ts[64] = {0};
                    if (sscanf(resp, "LOAN|%d|%d|%lf|%31[^|]|%63[^\n]", &l_id, &acc_id, &amt, status, ts) >= 4) {
                        printf("%-8d %-12d $%-11.2f %-12s %-20s\n", l_id, acc_id, amt, status, ts);
                    }
                }
                printf("------------------------------------------------\n\n");
            } else {
                printf("[-] %s\n\n", resp);
            }
        } else if (strcmp(choice, "2") == 0) {
            char l_id_str[32], dec[32];
            if (get_input_line("Enter Loan ID: ", l_id_str, sizeof(l_id_str)) != 0) continue;
            if (get_input_line("Enter Decision (APPROVED / REJECTED): ", dec, sizeof(dec)) != 0) continue;

            char payload[128];
            snprintf(payload, sizeof(payload), "%s|%s", l_id_str, dec);

            char resp[BUFFER_SIZE];
            if (execute_rpc_with_retry(sock_fd, CMD_PROCESS_LOAN, payload, resp, sizeof(resp)) == 0) {
                handle_financial_response(resp);
            }
        } else if (strcmp(choice, "3") == 0) {
            char acc_str[32];
            if (get_input_line("Enter Account ID: ", acc_str, sizeof(acc_str)) != 0) continue;
            char cmd[64];
            snprintf(cmd, sizeof(cmd), "VIEW_CUSTOMER|%s\n", acc_str);
            sock_send(*sock_fd, cmd);
            char resp[BUFFER_SIZE];
            if (sock_read_line(*sock_fd, resp, sizeof(resp)) > 0) {
                int acc_id = 0;
                char uname[64] = {0}, act[32] = {0};
                double bal = 0.0;
                if (sscanf(resp, "SUCCESS|CUSTOMER_INFO|%d|%63[^|]|%lf|%31[^\n]", &acc_id, uname, &bal, act) == 4) {
                    printf("\n---------------- Customer Info ----------------\n");
                    printf(" Account ID : %d\n", acc_id);
                    printf(" Username   : %s\n", uname);
                    printf(" Balance    : $%.2f\n", bal);
                    printf(" Status     : %s\n", act);
                    printf("-----------------------------------------------\n\n");
                } else {
                    printf("[-] %s\n\n", resp);
                }
            }
        } else if (strcmp(choice, "4") == 0) {
            char old_pass[MAX_PASSWORD_LEN], new_pass[MAX_PASSWORD_LEN];
            get_password_masked("Enter current password: ", old_pass, sizeof(old_pass));
            get_password_masked("Enter new password: ", new_pass, sizeof(new_pass));

            char cmd[256];
            snprintf(cmd, sizeof(cmd), "CHANGE_PASSWORD|%s|%s\n", old_pass, new_pass);
            sock_send(*sock_fd, cmd);
            char resp[BUFFER_SIZE];
            if (sock_read_line(*sock_fd, resp, sizeof(resp)) > 0) {
                printf("[+] %s\n\n", resp);
                if (strstr(resp, "SUCCESS")) {
                    strncpy(g_password, new_pass, sizeof(g_password) - 1);
                }
            }
        } else if (strcmp(choice, "0") == 0) {
            sock_send(*sock_fd, "LOGOUT\n");
            g_logged_in = 0;
            printf("[+] Logged out.\n\n");
            break;
        }
    }
}

/* Manager Menu */
static void run_manager_menu(int *sock_fd)
{
    while (g_logged_in) {
        printf("=== Manager Dashboard [%s] ===\n", g_username);
        printf("1. View All Loan Applications\n");
        printf("2. Assign Loan to Employee (Idempotent)\n");
        printf("3. Activate / Deactivate Customer Account (Idempotent)\n");
        printf("4. View All Customer Accounts\n");
        printf("5. View Customer Feedback\n");
        printf("6. Change Password\n");
        printf("0. Logout\n");

        char choice[16];
        if (get_input_line("Select an option: ", choice, sizeof(choice)) != 0) continue;

        if (strcmp(choice, "1") == 0) {
            sock_send(*sock_fd, "GET_ALL_LOANS\n");
            char resp[BUFFER_SIZE];
            sock_read_line(*sock_fd, resp, sizeof(resp));
            if (strcmp(resp, "START_LOANS") == 0) {
                printf("\n-------------------- All Loan Applications --------------------\n");
                printf("%-8s %-12s %-12s %-12s %-10s %-20s\n", "Loan ID", "Account ID", "Amount ($)", "Status", "Emp ID", "Created At");
                while (sock_read_line(*sock_fd, resp, sizeof(resp)) > 0) {
                    if (strcmp(resp, "END_LOANS") == 0) break;
                    int l_id = 0, acc_id = 0, emp_id = 0;
                    double amt = 0.0;
                    char status[32] = {0}, ts[64] = {0};
                    if (sscanf(resp, "LOAN|%d|%d|%lf|%31[^|]|%d|%63[^\n]", &l_id, &acc_id, &amt, status, &emp_id, ts) >= 5) {
                        printf("%-8d %-12d $%-11.2f %-12s %-10d %-20s\n", l_id, acc_id, amt, status, emp_id, ts);
                    }
                }
                printf("---------------------------------------------------------------\n\n");
            } else {
                printf("[-] %s\n\n", resp);
            }
        } else if (strcmp(choice, "2") == 0) {
            char l_id_str[32], emp_id_str[32];
            if (get_input_line("Enter Loan ID: ", l_id_str, sizeof(l_id_str)) != 0) continue;
            if (get_input_line("Enter Employee User ID to assign: ", emp_id_str, sizeof(emp_id_str)) != 0) continue;

            char payload[128];
            snprintf(payload, sizeof(payload), "%s|%s", l_id_str, emp_id_str);

            char resp[BUFFER_SIZE];
            if (execute_rpc_with_retry(sock_fd, CMD_ASSIGN_LOAN, payload, resp, sizeof(resp)) == 0) {
                handle_financial_response(resp);
            }
        } else if (strcmp(choice, "3") == 0) {
            char acc_str[32], act_str[32];
            if (get_input_line("Enter Account ID: ", acc_str, sizeof(acc_str)) != 0) continue;
            if (get_input_line("Set Status (1 = Active, 0 = Inactive): ", act_str, sizeof(act_str)) != 0) continue;

            char payload[128];
            snprintf(payload, sizeof(payload), "%s|%s", acc_str, act_str);

            char resp[BUFFER_SIZE];
            if (execute_rpc_with_retry(sock_fd, CMD_SET_ACCOUNT_STATUS, payload, resp, sizeof(resp)) == 0) {
                handle_financial_response(resp);
            }
        } else if (strcmp(choice, "4") == 0) {
            sock_send(*sock_fd, "VIEW_ALL_ACCOUNTS\n");
            char resp[BUFFER_SIZE];
            sock_read_line(*sock_fd, resp, sizeof(resp));
            if (strcmp(resp, "START_ACCOUNTS") == 0) {
                printf("\n---------------- Accounts ----------------\n");
                printf("%-12s %-10s %-14s %-10s\n", "Account ID", "User ID", "Balance ($)", "Status");
                while (sock_read_line(*sock_fd, resp, sizeof(resp)) > 0) {
                    if (strcmp(resp, "END_ACCOUNTS") == 0) break;
                    int a_id = 0, u_id = 0;
                    double bal = 0.0;
                    char act[32] = {0};
                    if (sscanf(resp, "ACCOUNT|%d|%d|%lf|%31[^\n]", &a_id, &u_id, &bal, act) == 4) {
                        printf("%-12d %-10d $%-13.2f %-10s\n", a_id, u_id, bal, act);
                    }
                }
                printf("------------------------------------------\n\n");
            } else {
                printf("[-] %s\n\n", resp);
            }
        } else if (strcmp(choice, "5") == 0) {
            sock_send(*sock_fd, "VIEW_ALL_FEEDBACK\n");
            char resp[BUFFER_SIZE];
            sock_read_line(*sock_fd, resp, sizeof(resp));
            if (strcmp(resp, "START_FEEDBACK") == 0) {
                printf("\n---------------- Customer Feedback ----------------\n");
                printf("%-6s %-10s %-35s %-20s\n", "ID", "User ID", "Message", "Timestamp");
                while (sock_read_line(*sock_fd, resp, sizeof(resp)) > 0) {
                    if (strcmp(resp, "END_FEEDBACK") == 0) break;
                    int f_id = 0, u_id = 0;
                    char msg[256] = {0}, ts[64] = {0};
                    if (sscanf(resp, "FB|%d|%d|%255[^|]|%63[^\n]", &f_id, &u_id, msg, ts) == 4) {
                        printf("%-6d %-10d %-35s %-20s\n", f_id, u_id, msg, ts);
                    }
                }
                printf("---------------------------------------------------\n\n");
            } else {
                printf("[-] %s\n\n", resp);
            }
        } else if (strcmp(choice, "6") == 0) {
            char old_pass[MAX_PASSWORD_LEN], new_pass[MAX_PASSWORD_LEN];
            get_password_masked("Enter current password: ", old_pass, sizeof(old_pass));
            get_password_masked("Enter new password: ", new_pass, sizeof(new_pass));

            char cmd[256];
            snprintf(cmd, sizeof(cmd), "CHANGE_PASSWORD|%s|%s\n", old_pass, new_pass);
            sock_send(*sock_fd, cmd);
            char resp[BUFFER_SIZE];
            if (sock_read_line(*sock_fd, resp, sizeof(resp)) > 0) {
                printf("[+] %s\n\n", resp);
                if (strstr(resp, "SUCCESS")) {
                    strncpy(g_password, new_pass, sizeof(g_password) - 1);
                }
            }
        } else if (strcmp(choice, "0") == 0) {
            sock_send(*sock_fd, "LOGOUT\n");
            g_logged_in = 0;
            printf("[+] Logged out.\n\n");
            break;
        }
    }
}

/* Administrator Menu */
static void run_admin_menu(int *sock_fd)
{
    while (g_logged_in) {
        printf("=== Administrator Console [%s] ===\n", g_username);
        printf("1. Add New User (Idempotent)\n");
        printf("2. Modify User Details (Idempotent)\n");
        printf("3. View All System Users\n");
        printf("4. View All Bank Accounts\n");
        printf("5. Change Password\n");
        printf("0. Logout\n");

        char choice[16];
        if (get_input_line("Select an option: ", choice, sizeof(choice)) != 0) continue;

        if (strcmp(choice, "1") == 0) {
            char uname[64], pass[64], role[32], bal_str[32];
            if (get_input_line("Enter new username: ", uname, sizeof(uname)) != 0) continue;
            get_password_masked("Enter new user password: ", pass, sizeof(pass));
            if (get_input_line("Enter role (CUSTOMER / EMPLOYEE / MANAGER / ADMIN): ", role, sizeof(role)) != 0) continue;

            long long init_cents = 0;
            if (strcasecmp(role, "CUSTOMER") == 0) {
                if (get_input_line("Enter initial balance ($): ", bal_str, sizeof(bal_str)) != 0) continue;
                init_cents = (long long)(atof(bal_str) * 100.0 + 0.5);
            }

            char payload[256];
            snprintf(payload, sizeof(payload), "%s|%s|%s|%lld", uname, pass, role, init_cents);

            char resp[BUFFER_SIZE];
            if (execute_rpc_with_retry(sock_fd, CMD_ADD_USER, payload, resp, sizeof(resp)) == 0) {
                handle_financial_response(resp);
            }
        } else if (strcmp(choice, "2") == 0) {
            char uid_str[32], new_uname[64], role[32], act_str[32];
            if (get_input_line("Enter target User ID: ", uid_str, sizeof(uid_str)) != 0) continue;
            if (get_input_line("Enter new username (or press enter to keep): ", new_uname, sizeof(new_uname)) != 0) continue;
            if (get_input_line("Enter role (CUSTOMER/EMPLOYEE/MANAGER/ADMIN): ", role, sizeof(role)) != 0) continue;
            if (get_input_line("Enter active status (1 = Active, 0 = Inactive): ", act_str, sizeof(act_str)) != 0) continue;

            char payload[256];
            snprintf(payload, sizeof(payload), "%s|%s|%s|%s", uid_str, new_uname, role, act_str);

            char resp[BUFFER_SIZE];
            if (execute_rpc_with_retry(sock_fd, CMD_MODIFY_USER, payload, resp, sizeof(resp)) == 0) {
                handle_financial_response(resp);
            }
        } else if (strcmp(choice, "3") == 0) {
            sock_send(*sock_fd, "VIEW_ALL_USERS\n");
            char resp[BUFFER_SIZE];
            sock_read_line(*sock_fd, resp, sizeof(resp));
            if (strcmp(resp, "START_USERS") == 0) {
                printf("\n---------------- System Users ----------------\n");
                printf("%-8s %-20s %-14s %-10s\n", "User ID", "Username", "Role", "Status");
                while (sock_read_line(*sock_fd, resp, sizeof(resp)) > 0) {
                    if (strcmp(resp, "END_USERS") == 0) break;
                    int u_id = 0;
                    char u_name[64] = {0}, r_str[32] = {0}, act[32] = {0};
                    if (sscanf(resp, "USER|%d|%63[^|]|%31[^|]|%31[^\n]", &u_id, u_name, r_str, act) == 4) {
                        printf("%-8d %-20s %-14s %-10s\n", u_id, u_name, r_str, act);
                    }
                }
                printf("----------------------------------------------\n\n");
            } else {
                printf("[-] %s\n\n", resp);
            }
        } else if (strcmp(choice, "4") == 0) {
            sock_send(*sock_fd, "VIEW_ALL_ACCOUNTS\n");
            char resp[BUFFER_SIZE];
            sock_read_line(*sock_fd, resp, sizeof(resp));
            if (strcmp(resp, "START_ACCOUNTS") == 0) {
                printf("\n---------------- Accounts ----------------\n");
                printf("%-12s %-10s %-14s %-10s\n", "Account ID", "User ID", "Balance ($)", "Status");
                while (sock_read_line(*sock_fd, resp, sizeof(resp)) > 0) {
                    if (strcmp(resp, "END_ACCOUNTS") == 0) break;
                    int a_id = 0, u_id = 0;
                    double bal = 0.0;
                    char act[32] = {0};
                    if (sscanf(resp, "ACCOUNT|%d|%d|%lf|%31[^\n]", &a_id, &u_id, &bal, act) == 4) {
                        printf("%-12d %-10d $%-13.2f %-10s\n", a_id, u_id, bal, act);
                    }
                }
                printf("------------------------------------------\n\n");
            } else {
                printf("[-] %s\n\n", resp);
            }
        } else if (strcmp(choice, "5") == 0) {
            char old_pass[MAX_PASSWORD_LEN], new_pass[MAX_PASSWORD_LEN];
            get_password_masked("Enter current password: ", old_pass, sizeof(old_pass));
            get_password_masked("Enter new password: ", new_pass, sizeof(new_pass));

            char cmd[256];
            snprintf(cmd, sizeof(cmd), "CHANGE_PASSWORD|%s|%s\n", old_pass, new_pass);
            sock_send(*sock_fd, cmd);
            char resp[BUFFER_SIZE];
            if (sock_read_line(*sock_fd, resp, sizeof(resp)) > 0) {
                printf("[+] %s\n\n", resp);
                if (strstr(resp, "SUCCESS")) {
                    strncpy(g_password, new_pass, sizeof(g_password) - 1);
                }
            }
        } else if (strcmp(choice, "0") == 0) {
            sock_send(*sock_fd, "LOGOUT\n");
            g_logged_in = 0;
            printf("[+] Logged out.\n\n");
            break;
        }
    }
}

int main(int argc, char *argv[])
{
    if (argc >= 2) {
        strncpy(g_server_ip, argv[1], sizeof(g_server_ip) - 1);
    }
    if (argc >= 3) {
        g_server_port = atoi(argv[2]);
    }

    printf("========================================================\n");
    printf("   CLI Banking Management System (Idempotent Client)   \n");
    printf("   Target: %s:%d\n", g_server_ip, g_server_port);
    printf("========================================================\n\n");

    int sock_fd = connect_to_server(g_server_ip, g_server_port, 4);
    if (sock_fd < 0) {
        fprintf(stderr, "[-] Could not connect to server at %s:%d: %s\n",
                g_server_ip, g_server_port, strerror(errno));
        exit(EXIT_FAILURE);
    }

    while (1) {
        if (!g_logged_in) {
            printf("--- Main Menu ---\n");
            printf("1. Login\n");
            printf("0. Exit\n");

            char choice[16];
            if (get_input_line("Select an option: ", choice, sizeof(choice)) != 0) continue;

            if (strcmp(choice, "1") == 0) {
                char uname[MAX_USERNAME_LEN], pass[MAX_PASSWORD_LEN];
                if (get_input_line("Username: ", uname, sizeof(uname)) != 0) continue;
                get_password_masked("Password: ", pass, sizeof(pass));

                char cmd[256];
                snprintf(cmd, sizeof(cmd), "LOGIN|%s|%s\n", uname, pass);
                if (sock_send(sock_fd, cmd) != 0) {
                    printf("[-] Send failed. Server may be down.\n");
                    continue;
                }

                char resp[BUFFER_SIZE];
                if (sock_read_line(sock_fd, resp, sizeof(resp)) > 0) {
                    char *p = resp;
                    char *st = strsep(&p, FIELD_DELIM_STR);
                    char *cd = strsep(&p, FIELD_DELIM_STR);

                    if (st && strcmp(st, RESP_SUCCESS) == 0 && cd && strcmp(cd, "LOGIN_OK") == 0) {
                        g_user_id = atoi(strsep(&p, FIELD_DELIM_STR));
                        char *u = strsep(&p, FIELD_DELIM_STR);
                        char *r = strsep(&p, FIELD_DELIM_STR);

                        strncpy(g_username, u ? u : uname, sizeof(g_username) - 1);
                        strncpy(g_password, pass, sizeof(g_password) - 1);
                        strncpy(g_role_str, r ? r : "", sizeof(g_role_str) - 1);
                        g_role = string_to_role(g_role_str);
                        g_logged_in = 1;

                        printf("\n[+] Welcome, %s! Logged in as %s (User ID: %d).\n\n",
                               g_username, g_role_str, g_user_id);

                        if (g_role == ROLE_CUSTOMER) {
                            run_customer_menu(&sock_fd);
                        } else if (g_role == ROLE_EMPLOYEE) {
                            run_employee_menu(&sock_fd);
                        } else if (g_role == ROLE_MANAGER) {
                            run_manager_menu(&sock_fd);
                        } else if (g_role == ROLE_ADMIN) {
                            run_admin_menu(&sock_fd);
                        } else {
                            printf("[-] Unknown role.\n");
                            g_logged_in = 0;
                        }
                    } else {
                        printf("\n[-] Login failed: %s\n\n", p ? p : cd);
                    }
                }
            } else if (strcmp(choice, "0") == 0) {
                printf("[*] Exiting. Goodbye!\n");
                break;
            }
        }
    }

    if (sock_fd >= 0) close(sock_fd);
    return 0;
}
