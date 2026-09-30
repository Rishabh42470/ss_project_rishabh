# Banking Management System with Idempotency & OS Concurrency Control

A CLI-based Banking Management System implemented entirely in standard **C (C11/C99)**. This project leverages Linux system calls and operating system fundamentals to provide **duplicate request protection (idempotency)**, **single-session enforcement**, **multi-process concurrency**, and **crash-consistent multi-file storage**.

---

## 1. Operating System & System Software Concepts Implemented

1. **Process-Level Concurrency (`fork`, `sigaction`, `waitpid`)**:
   - The server operates as a concurrent daemon. Each connecting client is dispatched to an isolated child process via `fork()`.
   - Zombie child processes are reaped asynchronously using `sigaction(SIGCHLD, ...)` with `SA_RESTART | SA_NOCLDWAIT` and `waitpid(-1, NULL, WNOHANG)`.
   - `SIGPIPE` is ignored to ensure client disconnects do not terminate server worker processes.

2. **POSIX Advisory File Locking (`fcntl`)**:
   - Inter-process synchronization is coordinated across worker processes via `fcntl(fd, F_SETLKW, &fl)` on `data/bank.lock`.
   - Mutating requests (transfers, deposits, withdrawals, loan processing) acquire **Exclusive Write Locks (`F_WRLCK`)**.
   - Read-only queries acquire **Shared Read Locks (`F_RDLCK`)**.

3. **Inode-Based Single Active Session Enforcement**:
   - Enforces strictly **one active terminal session per user**.
   - Upon authentication, the process acquires an exclusive non-blocking lock (`fcntl(..., F_SETLK, ...)`) on `data/sessions/user_<user_id>.lock`.
   - If another terminal attempts to login concurrently, the kernel returns `EACCES`/`EAGAIN`, and login is rejected with `SESSION_ACTIVE`.
   - **Zero Leak Guarantee**: When a client terminal disconnects, times out, or crashes, the Linux kernel **automatically releases** the file lock on process termination.

4. **Crash Consistency & Atomic File Updates (`fsync`, `rename`, Journaling)**:
   - Text files are replaced atomically using the temporary file + `fsync()` + `rename()` pattern, guaranteeing inode-level atomicity on POSIX filesystems.
   - Multi-file mutations (updating `accounts.txt`, `transactions.txt`, and `request_results.txt`) use a **Write-Ahead Journal (`data/journal.log`)**.
   - On server startup, the storage layer inspects the journal and reconciles or rolls back interrupted operations.

5. **Hardware Entropy & Idempotency (`/dev/urandom`, SHA-256)**:
   - Request IDs are generated on the client by reading 16 cryptographically random bytes from `/dev/urandom` and formatting as a 128-bit hex UUID.
   - Server computes a canonical SHA-256 payload fingerprint (`OPERATION|USER_ID|ARGS...`) to distinguish identical retransmissions from conflicting parameter modifications (`IDEMPOTENCY_CONFLICT`).

6. **Terminal I/O Controls (`termios`)**:
   - Password inputs in the CLI client disable terminal echo using `tcgetattr()` and `tcsetattr()`.

---

## 2. Project Directory Structure

```text
ssproject_rishabh/
├── client.c              # CLI menus, masked input, RPC with auto-retry
├── server.c              # Concurrent TCP server, fork handler, request routing
├── storage.c / .h        # POSIX locks, text DB parsing, atomic updates, journal
├── idempotency.c / .h    # 128-bit UUID generation, payload fingerprints, duplicate detection
├── models.c / .h         # Domain entities (User, Account, Transaction, Loan, etc.)
├── protocol.h            # Framing, pipe-delimited opcodes, response status codes
├── sha256.c / .h         # Self-contained FIPS 180-4 SHA-256 implementation
├── test_system.c         # End-to-end automated integration test suite
├── test_concurrency.c    # Concurrent race condition and duplicate protection test
├── build.sh              # Direct compilation script
├── Makefile              # Makefile targets (all, test, clean, reset-data)
└── data/
    ├── users.txt
    ├── accounts.txt
    ├── transactions.txt
    ├── loans.txt
    ├── feedback.txt
    ├── request_results.txt
    ├── journal.log
    ├── bank.lock
    └── sessions/
```

---

## 3. How to Build and Run

### Building
Compile with the build script:
```bash
./build.sh
```
Or with `make` (if installed):
```bash
make
```

### Running the Server
```bash
./server [PORT]
# Default port is 8080. Example:
./server 8080
```

### Running the Client
Open one or more terminal windows:
```bash
./client [SERVER_IP] [PORT]
# Example:
./client 127.0.0.1 8080
```

---

## 4. Default Accounts & Credentials

The system automatically initializes default accounts if the database is clean:

| Username | Password | Role | Description / Initial Balance |
| :--- | :--- | :--- | :--- |
| **`alice`** | `alice123` | `CUSTOMER` | Customer Account #1 with **$1,000.00** |
| **`bob`** | `bob123` | `CUSTOMER` | Customer Account #2 with **$500.00** |
| **`emp1`** | `emp1` | `EMPLOYEE` | Loan Approval Officer |
| **`manager`** | `manager123` | `MANAGER` | Loan Assignment & Account Manager |
| **`admin`** | `admin123` | `ADMIN` | System Administrator |

---

## 5. Verification & Automated Tests

To run the automated integration test suite:
```bash
./test_system
```
This tests:
1. Single active session enforcement via POSIX inode locking.
2. Financial idempotency on deposits and withdrawals.
3. Payload conflict detection (`IDEMPOTENCY_CONFLICT`).
4. Transfer idempotency between accounts.
5. Server kill and recovery test: verifies that stored request records survive process crashes and return original transaction IDs.
6. Loan application lifecycle and employee approval idempotency.

To run the concurrent duplicate suppression test:
```bash
./test_concurrency
```
This spawns concurrent child processes sending the same request ID at the same moment, verifying that exactly one transaction executes while the second is safely replayed.
