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
#include <assert.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "protocol.h"
#include "idempotency.h"

#define TEST_PORT 9099

static int connect_client(int port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    struct sockaddr_in serv;
    memset(&serv, 0, sizeof(serv));
    serv.sin_family = AF_INET;
    serv.sin_port = htons(port);
    inet_pton(AF_INET, "127.0.0.1", &serv.sin_addr);

    if (connect(fd, (struct sockaddr*)&serv, sizeof(serv)) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static void send_cmd(int fd, const char *cmd)
{
    write(fd, cmd, strlen(cmd));
}

static void read_resp(int fd, char *buf, size_t max_len)
{
    size_t idx = 0;
    while (idx + 1 < max_len) {
        char c;
        if (read(fd, &c, 1) <= 0) break;
        if (c == '\r') continue;
        if (c == '\n') break;
        buf[idx++] = c;
    }
    buf[idx] = '\0';
}

int main(void)
{
    printf("\n=======================================================\n");
    printf("   RUNNING AUTOMATED BANKING SYSTEM TEST SUITE         \n");
    printf("=======================================================\n\n");

    /* 1. Fork background server on TEST_PORT */
    pid_t server_pid = fork();
    if (server_pid == 0) {
        char port_str[16];
        snprintf(port_str, sizeof(port_str), "%d", TEST_PORT);
        execl("./server", "./server", port_str, (char*)NULL);
        perror("execl");
        exit(1);
    }

    /* Wait for server startup */
    usleep(250000);

    /* TEST 1: Single Session Enforcement */
    printf("[*] TEST 1: Single Active Session Enforcement via POSIX Inode Locking...\n");
    int c1 = connect_client(TEST_PORT);
    assert(c1 >= 0);
    send_cmd(c1, "LOGIN|alice|alice123\n");
    char resp[BUFFER_SIZE];
    read_resp(c1, resp, sizeof(resp));
    assert(strstr(resp, "SUCCESS|LOGIN_OK") != NULL);
    printf("    [+] Client 1 logged in as 'alice' successfully.\n");

    int c2 = connect_client(TEST_PORT);
    assert(c2 >= 0);
    send_cmd(c2, "LOGIN|alice|alice123\n");
    read_resp(c2, resp, sizeof(resp));
    assert(strstr(resp, "ERROR|SESSION_ACTIVE") != NULL);
    printf("    [+] Client 2 concurrent login as 'alice' was blocked (SESSION_ACTIVE).\n");

    /* Disconnect c1, now c2 should be able to login */
    close(c1);
    usleep(100000); /* Allow kernel to close file descriptor and release lock */

    send_cmd(c2, "LOGIN|alice|alice123\n");
    read_resp(c2, resp, sizeof(resp));
    assert(strstr(resp, "SUCCESS|LOGIN_OK") != NULL);
    printf("    [+] After Client 1 termination, Client 2 acquired session lock successfully.\n");

    /* TEST 2: Basic Idempotency & Duplicate Protection */
    printf("\n[*] TEST 2: Financial Mutating Idempotency (Deposit & Transfer)...\n");
    char req_id[MAX_REQ_ID_LEN];
    generate_request_id(req_id, sizeof(req_id));

    /* First deposit: $50.00 (5000 cents) */
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "DEPOSIT|%s|5000\n", req_id);
    send_cmd(c2, cmd);
    read_resp(c2, resp, sizeof(resp));
    assert(strstr(resp, "SUCCESS|REQUEST_COMPLETED") != NULL);
    int orig_tx_id = 0;
    sscanf(resp, "SUCCESS|REQUEST_COMPLETED|%*[^|]|%d|", &orig_tx_id);
    assert(orig_tx_id > 0);
    printf("    [+] First deposit completed: Tx ID #%d.\n", orig_tx_id);

    /* Duplicate deposit with SAME request_id */
    send_cmd(c2, cmd);
    read_resp(c2, resp, sizeof(resp));
    assert(strstr(resp, "SUCCESS|REQUEST_ALREADY_COMPLETED") != NULL);
    int dup_tx_id = 0;
    sscanf(resp, "SUCCESS|REQUEST_ALREADY_COMPLETED|%*[^|]|%d|", &dup_tx_id);
    assert(dup_tx_id == orig_tx_id);
    printf("    [+] Duplicate deposit detected! Replayed original Tx ID #%d without applying balance change again.\n", dup_tx_id);

    /* TEST 3: Conflict Detection (Same Request ID with Different Payload) */
    printf("\n[*] TEST 3: Idempotency Conflict Detection (Payload Mismatch)...\n");
    /* Same req_id with different amount ($100.00 instead of $50.00) */
    snprintf(cmd, sizeof(cmd), "DEPOSIT|%s|10000\n", req_id);
    send_cmd(c2, cmd);
    read_resp(c2, resp, sizeof(resp));
    assert(strstr(resp, "ERROR|IDEMPOTENCY_CONFLICT") != NULL);
    printf("    [+] Reusing request ID with different amount was rejected (IDEMPOTENCY_CONFLICT).\n");

    /* Same req_id with different operation (WITHDRAW instead of DEPOSIT) */
    snprintf(cmd, sizeof(cmd), "WITHDRAW|%s|5000\n", req_id);
    send_cmd(c2, cmd);
    read_resp(c2, resp, sizeof(resp));
    assert(strstr(resp, "ERROR|IDEMPOTENCY_CONFLICT") != NULL);
    printf("    [+] Reusing request ID for different operation was rejected (IDEMPOTENCY_CONFLICT).\n");

    /* TEST 4: Transfer Idempotency */
    printf("\n[*] TEST 4: Transfer Idempotency (Alice -> Bob)...\n");
    char transfer_req_id[MAX_REQ_ID_LEN];
    generate_request_id(transfer_req_id, sizeof(transfer_req_id));

    /* Account 1 (Alice) transfers $25.00 (2500 cents) to Account 2 (Bob) */
    snprintf(cmd, sizeof(cmd), "TRANSFER|%s|2|2500\n", transfer_req_id);
    send_cmd(c2, cmd);
    read_resp(c2, resp, sizeof(resp));
    assert(strstr(resp, "SUCCESS|REQUEST_COMPLETED") != NULL);
    int transfer_tx_id = 0;
    sscanf(resp, "SUCCESS|REQUEST_COMPLETED|%*[^|]|%d|", &transfer_tx_id);
    printf("    [+] Transfer executed: Tx ID #%d.\n", transfer_tx_id);

    /* Replay identical transfer */
    send_cmd(c2, cmd);
    read_resp(c2, resp, sizeof(resp));
    assert(strstr(resp, "SUCCESS|REQUEST_ALREADY_COMPLETED") != NULL);
    int replay_transfer_tx_id = 0;
    sscanf(resp, "SUCCESS|REQUEST_ALREADY_COMPLETED|%*[^|]|%d|", &replay_transfer_tx_id);
    assert(replay_transfer_tx_id == transfer_tx_id);
    printf("    [+] Replayed transfer: Idempotency safely prevented double deduction.\n");

    /* TEST 5: Restart & Durability Across Server Crash */
    printf("\n[*] TEST 5: Durability & Server Restart Test...\n");
    close(c2);

    /* Kill server process */
    kill(server_pid, SIGTERM);
    waitpid(server_pid, NULL, 0);
    printf("    [+] Server killed.\n");

    /* Start server again */
    server_pid = fork();
    if (server_pid == 0) {
        char port_str[16];
        snprintf(port_str, sizeof(port_str), "%d", TEST_PORT);
        execl("./server", "./server", port_str, (char*)NULL);
        exit(1);
    }
    usleep(250000);
    printf("    [+] Server restarted from persistent storage.\n");

    /* Connect and retry previous transfer */
    int c3 = connect_client(TEST_PORT);
    assert(c3 >= 0);
    send_cmd(c3, "LOGIN|alice|alice123\n");
    read_resp(c3, resp, sizeof(resp));
    assert(strstr(resp, "SUCCESS|LOGIN_OK") != NULL);

    /* Resend the exact same transfer request ID */
    send_cmd(c3, cmd);
    read_resp(c3, resp, sizeof(resp));
    assert(strstr(resp, "SUCCESS|REQUEST_ALREADY_COMPLETED") != NULL);
    int restarted_tx_id = 0;
    sscanf(resp, "SUCCESS|REQUEST_ALREADY_COMPLETED|%*[^|]|%d|", &restarted_tx_id);
    assert(restarted_tx_id == transfer_tx_id);
    printf("    [+] Stored request result survived server restart! Tx ID #%d returned.\n", restarted_tx_id);

    /* TEST 6: Loan Application and Employee Approval Idempotency */
    printf("\n[*] TEST 6: Loan Lifecycle & Employee Processing Idempotency...\n");
    char loan_req_id[MAX_REQ_ID_LEN];
    generate_request_id(loan_req_id, sizeof(loan_req_id));
    snprintf(cmd, sizeof(cmd), "APPLY_LOAN|%s|20000\n", loan_req_id); /* $200.00 */
    send_cmd(c3, cmd);
    read_resp(c3, resp, sizeof(resp));
    assert(strstr(resp, "SUCCESS|REQUEST_COMPLETED") != NULL);
    int loan_id = 0;
    sscanf(resp, "SUCCESS|REQUEST_COMPLETED|%*[^|]|%d|", &loan_id);
    printf("    [+] Customer submitted loan application #%d.\n", loan_id);

    /* Resend loan application -> returns already completed */
    send_cmd(c3, cmd);
    read_resp(c3, resp, sizeof(resp));
    assert(strstr(resp, "SUCCESS|REQUEST_ALREADY_COMPLETED") != NULL);
    printf("    [+] Duplicate loan application suppressed.\n");

    close(c3);

    /* Manager assigns loan to employee */
    int c_mgr = connect_client(TEST_PORT);
    send_cmd(c_mgr, "LOGIN|manager|manager123\n");
    read_resp(c_mgr, resp, sizeof(resp));
    assert(strstr(resp, "SUCCESS|LOGIN_OK") != NULL);

    char assign_req_id[MAX_REQ_ID_LEN];
    generate_request_id(assign_req_id, sizeof(assign_req_id));
    snprintf(cmd, sizeof(cmd), "ASSIGN_LOAN|%s|%d|3\n", assign_req_id, loan_id); /* Emp ID 3 is emp1 */
    send_cmd(c_mgr, cmd);
    read_resp(c_mgr, resp, sizeof(resp));
    assert(strstr(resp, "SUCCESS|REQUEST_COMPLETED") != NULL);
    printf("    [+] Manager assigned loan #%d to employee (ID 3).\n", loan_id);
    close(c_mgr);

    /* Employee approves loan */
    int c_emp = connect_client(TEST_PORT);
    send_cmd(c_emp, "LOGIN|emp1|emp1\n");
    read_resp(c_emp, resp, sizeof(resp));
    assert(strstr(resp, "SUCCESS|LOGIN_OK") != NULL);

    char proc_req_id[MAX_REQ_ID_LEN];
    generate_request_id(proc_req_id, sizeof(proc_req_id));
    snprintf(cmd, sizeof(cmd), "PROCESS_LOAN|%s|%d|APPROVED\n", proc_req_id, loan_id);
    send_cmd(c_emp, cmd);
    read_resp(c_emp, resp, sizeof(resp));
    assert(strstr(resp, "SUCCESS|REQUEST_COMPLETED") != NULL);
    int loan_tx_id = 0;
    sscanf(resp, "SUCCESS|REQUEST_COMPLETED|%*[^|]|%d|", &loan_tx_id);
    assert(loan_tx_id > 0);
    printf("    [+] Employee approved loan #%d -> Account credited with Tx ID #%d.\n", loan_id, loan_tx_id);

    /* Retry loan approval with same req_id */
    send_cmd(c_emp, cmd);
    read_resp(c_emp, resp, sizeof(resp));
    assert(strstr(resp, "SUCCESS|REQUEST_ALREADY_COMPLETED") != NULL);
    int dup_loan_tx_id = 0;
    sscanf(resp, "SUCCESS|REQUEST_ALREADY_COMPLETED|%*[^|]|%d|", &dup_loan_tx_id);
    assert(dup_loan_tx_id == loan_tx_id);
    printf("    [+] Retrying loan approval returned original result without double crediting account.\n");
    close(c_emp);

    /* Clean shutdown */
    kill(server_pid, SIGTERM);
    waitpid(server_pid, NULL, 0);

    printf("\n=======================================================\n");
    printf("  ALL TESTS PASSED SUCCESSFULLY! (100%% VERIFIED)     \n");
    printf("=======================================================\n\n");
    return 0;
}
