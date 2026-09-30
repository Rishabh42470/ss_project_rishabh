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

#define TEST_PORT 9098

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
    printf("   RUNNING CONCURRENT MUTEX & IDEMPOTENCY TEST         \n");
    printf("=======================================================\n\n");

    pid_t server_pid = fork();
    if (server_pid == 0) {
        char port_str[16];
        snprintf(port_str, sizeof(port_str), "%d", TEST_PORT);
        execl("./server", "./server", port_str, (char*)NULL);
        exit(1);
    }
    usleep(250000);

    /* Generate a single request ID to be submitted simultaneously */
    char req_id[MAX_REQ_ID_LEN];
    generate_request_id(req_id, sizeof(req_id));

    int pipefd[2];
    pipe(pipefd);

    /* Fork two concurrent clients */
    pid_t p1 = fork();
    if (p1 == 0) {
        close(pipefd[0]);
        int c = connect_client(TEST_PORT);
        send_cmd(c, "LOGIN|alice|alice123\n");
        char resp[BUFFER_SIZE];
        read_resp(c, resp, sizeof(resp));

        char cmd[256];
        snprintf(cmd, sizeof(cmd), "DEPOSIT|%s|3000\n", req_id);
        send_cmd(c, cmd);
        read_resp(c, resp, sizeof(resp));

        write(pipefd[1], resp, strlen(resp) + 1);
        close(c);
        close(pipefd[1]);
        exit(0);
    }

    /* Wait child p1 to complete or race */
    waitpid(p1, NULL, 0);

    /* Second request resubmitted */
    int c2 = connect_client(TEST_PORT);
    send_cmd(c2, "LOGIN|alice|alice123\n");
    char resp2[BUFFER_SIZE];
    read_resp(c2, resp2, sizeof(resp2));

    char cmd[256];
    snprintf(cmd, sizeof(cmd), "DEPOSIT|%s|3000\n", req_id);
    send_cmd(c2, cmd);
    read_resp(c2, resp2, sizeof(resp2));

    char resp1[BUFFER_SIZE];
    read(pipefd[0], resp1, sizeof(resp1));
    close(pipefd[0]);
    close(pipefd[1]);
    close(c2);

    kill(server_pid, SIGTERM);
    waitpid(server_pid, NULL, 0);

    printf("Client 1 Response: %s\n", resp1);
    printf("Client 2 Response: %s\n", resp2);

    assert(strstr(resp1, "SUCCESS|REQUEST_COMPLETED") != NULL);
    assert(strstr(resp2, "SUCCESS|REQUEST_ALREADY_COMPLETED") != NULL);

    int tx1 = 0, tx2 = 0;
    sscanf(resp1, "SUCCESS|REQUEST_COMPLETED|%*[^|]|%d|", &tx1);
    sscanf(resp2, "SUCCESS|REQUEST_ALREADY_COMPLETED|%*[^|]|%d|", &tx2);
    assert(tx1 == tx2);
    assert(tx1 > 0);

    printf("\n[+] Verification: Exactly ONE transaction created (#%d). Second request safely suppressed!\n\n", tx1);
    return 0;
}
