#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif

#include "storage.h"
#include "sha256.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>

/* Safe copy that guarantees null termination */
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

/* Helper to strip newline characters */
static void trim_newline(char *str)
{
    if (!str) return;
    size_t len = strlen(str);
    while (len > 0 && (str[len - 1] == '\n' || str[len - 1] == '\r')) {
        str[len - 1] = '\0';
        len--;
    }
}

/* Ensure data directory and session directory exist */
static int ensure_directories(void)
{
    if (mkdir(DATA_DIR, 0755) != 0 && errno != EEXIST) {
        return -1;
    }
    if (mkdir(SESSIONS_DIR, 0755) != 0 && errno != EEXIST) {
        return -1;
    }
    int fd = open(LOCK_FILE, O_CREAT | O_RDWR, 0644);
    if (fd >= 0) close(fd);
    return 0;
}

/* POSIX fcntl lock for database synchronization */
int acquire_db_lock(int exclusive)
{
    int fd = open(LOCK_FILE, O_CREAT | O_RDWR, 0644);
    if (fd < 0) return -1;

    struct flock fl;
    memset(&fl, 0, sizeof(fl));
    fl.l_type = exclusive ? F_WRLCK : F_RDLCK;
    fl.l_whence = SEEK_SET;
    fl.l_start = 0;
    fl.l_len = 0;

    while (fcntl(fd, F_SETLKW, &fl) < 0) {
        if (errno == EINTR) continue;
        close(fd);
        return -1;
    }
    return fd;
}

void release_db_lock(int lock_fd)
{
    if (lock_fd < 0) return;
    struct flock fl;
    memset(&fl, 0, sizeof(fl));
    fl.l_type = F_UNLCK;
    fl.l_whence = SEEK_SET;
    fl.l_start = 0;
    fl.l_len = 0;
    fcntl(lock_fd, F_SETLK, &fl);
    close(lock_fd);
}

/* Single-session enforcement via POSIX inode locking */
int acquire_user_session_lock(int user_id)
{
    char session_file[256];
    snprintf(session_file, sizeof(session_file), "%s/user_%d.lock", SESSIONS_DIR, user_id);

    int fd = open(session_file, O_CREAT | O_RDWR, 0600);
    if (fd < 0) return -2;

    struct flock fl;
    memset(&fl, 0, sizeof(fl));
    fl.l_type = F_WRLCK;
    fl.l_whence = SEEK_SET;
    fl.l_start = 0;
    fl.l_len = 0;

    /* Non-blocking lock test */
    if (fcntl(fd, F_SETLK, &fl) < 0) {
        if (errno == EACCES || errno == EAGAIN) {
            close(fd);
            return -1; /* Session already active */
        }
        close(fd);
        return -2; /* System error */
    }

    return fd;
}

void release_user_session_lock(int session_fd)
{
    if (session_fd >= 0) {
        struct flock fl;
        memset(&fl, 0, sizeof(fl));
        fl.l_type = F_UNLCK;
        fl.l_whence = SEEK_SET;
        fl.l_start = 0;
        fl.l_len = 0;
        fcntl(session_fd, F_SETLK, &fl);
        close(session_fd);
    }
}

/* Journaling operations */
static int append_journal_entry(
    long op_id,
    const char *request_id,
    const char *type,
    const char *details,
    const char *status
) {
    FILE *fp = fopen(JOURNAL_FILE, "a");
    if (!fp) return -1;

    fprintf(fp, "%ld|%s|%s|%s|%s|%ld\n",
            op_id,
            request_id ? request_id : "",
            type ? type : "",
            details ? details : "",
            status ? status : "",
            (long)time(NULL));
    fflush(fp);
    fsync(fileno(fp));
    fclose(fp);
    return 0;
}

/* Find max ID in any file where ID is the first pipe-separated column */
static int get_max_id_from_file(const char *filepath)
{
    FILE *fp = fopen(filepath, "r");
    if (!fp) return 0;

    int max_id = 0;
    char line[1024];
    while (fgets(line, sizeof(line), fp)) {
        int id = 0;
        if (sscanf(line, "%d|", &id) == 1) {
            if (id > max_id) max_id = id;
        }
    }
    fclose(fp);
    return max_id;
}

/* Users */
int get_user_by_username(const char *username, User *out_user)
{
    if (!username) return -1;
    FILE *fp = fopen(USERS_FILE, "r");
    if (!fp) return -1;

    char line[1024];
    int found = -1;
    while (fgets(line, sizeof(line), fp)) {
        trim_newline(line);
        char u_name[MAX_USERNAME_LEN] = {0};
        char p_hash[MAX_HASH_LEN] = {0};
        char r_str[MAX_ROLE_LEN] = {0};
        int u_id = 0, active = 1;

        if (sscanf(line, "%d|%63[^|]|%64[^|]|%15[^|]|%d",
                   &u_id, u_name, p_hash, r_str, &active) >= 4) {
            if (strcmp(u_name, username) == 0) {
                if (out_user) {
                    out_user->user_id = u_id;
                    strncpy(out_user->username, u_name, sizeof(out_user->username) - 1);
                    strncpy(out_user->password_hash, p_hash, sizeof(out_user->password_hash) - 1);
                    out_user->role = string_to_role(r_str);
                    out_user->active = active;
                }
                found = 0;
                break;
            }
        }
    }
    fclose(fp);
    return found;
}

int get_user_by_id(int user_id, User *out_user)
{
    FILE *fp = fopen(USERS_FILE, "r");
    if (!fp) return -1;

    char line[1024];
    int found = -1;
    while (fgets(line, sizeof(line), fp)) {
        trim_newline(line);
        char u_name[MAX_USERNAME_LEN] = {0};
        char p_hash[MAX_HASH_LEN] = {0};
        char r_str[MAX_ROLE_LEN] = {0};
        int u_id = 0, active = 1;

        if (sscanf(line, "%d|%63[^|]|%64[^|]|%15[^|]|%d",
                   &u_id, u_name, p_hash, r_str, &active) >= 4) {
            if (u_id == user_id) {
                if (out_user) {
                    out_user->user_id = u_id;
                    strncpy(out_user->username, u_name, sizeof(out_user->username) - 1);
                    strncpy(out_user->password_hash, p_hash, sizeof(out_user->password_hash) - 1);
                    out_user->role = string_to_role(r_str);
                    out_user->active = active;
                }
                found = 0;
                break;
            }
        }
    }
    fclose(fp);
    return found;
}

int add_user(const char *username, const char *password_hash, UserRole role, User *out_user)
{
    if (!username || !password_hash) return -1;

    /* Check if username already exists */
    User existing;
    if (get_user_by_username(username, &existing) == 0) {
        return -2; /* Already exists */
    }

    int next_id = get_max_id_from_file(USERS_FILE) + 1;
    FILE *fp = fopen(USERS_FILE, "a");
    if (!fp) return -1;

    fprintf(fp, "%d|%s|%s|%s|1\n", next_id, username, password_hash, role_to_string(role));
    fflush(fp);
    fsync(fileno(fp));
    fclose(fp);

    if (out_user) {
        out_user->user_id = next_id;
        strncpy(out_user->username, username, sizeof(out_user->username) - 1);
        strncpy(out_user->password_hash, password_hash, sizeof(out_user->password_hash) - 1);
        out_user->role = role;
        out_user->active = 1;
    }
    return next_id;
}

int update_user_password(int user_id, const char *new_password_hash)
{
    FILE *fp = fopen(USERS_FILE, "r");
    if (!fp) return -1;

    char tmp_file[256];
    snprintf(tmp_file, sizeof(tmp_file), "%s.tmp.%d", USERS_FILE, getpid());
    FILE *out = fopen(tmp_file, "w");
    if (!out) {
        fclose(fp);
        return -1;
    }

    char line[1024];
    int updated = -1;
    while (fgets(line, sizeof(line), fp)) {
        trim_newline(line);
        char u_name[MAX_USERNAME_LEN] = {0};
        char p_hash[MAX_HASH_LEN] = {0};
        char r_str[MAX_ROLE_LEN] = {0};
        int u_id = 0, active = 1;

        if (sscanf(line, "%d|%63[^|]|%64[^|]|%15[^|]|%d",
                   &u_id, u_name, p_hash, r_str, &active) >= 4) {
            if (u_id == user_id) {
                fprintf(out, "%d|%s|%s|%s|%d\n", u_id, u_name, new_password_hash, r_str, active);
                updated = 0;
            } else {
                fprintf(out, "%s\n", line);
            }
        } else {
            fprintf(out, "%s\n", line);
        }
    }
    fclose(fp);
    fflush(out);
    fsync(fileno(out));
    fclose(out);

    if (updated == 0) {
        rename(tmp_file, USERS_FILE);
    } else {
        unlink(tmp_file);
    }
    return updated;
}

int update_user_details(int user_id, const char *new_username, UserRole new_role, int active)
{
    FILE *fp = fopen(USERS_FILE, "r");
    if (!fp) return -1;

    char tmp_file[256];
    snprintf(tmp_file, sizeof(tmp_file), "%s.tmp.%d", USERS_FILE, getpid());
    FILE *out = fopen(tmp_file, "w");
    if (!out) {
        fclose(fp);
        return -1;
    }

    char line[1024];
    int updated = -1;
    while (fgets(line, sizeof(line), fp)) {
        trim_newline(line);
        char u_name[MAX_USERNAME_LEN] = {0};
        char p_hash[MAX_HASH_LEN] = {0};
        char r_str[MAX_ROLE_LEN] = {0};
        int u_id = 0, cur_active = 1;

        if (sscanf(line, "%d|%63[^|]|%64[^|]|%15[^|]|%d",
                   &u_id, u_name, p_hash, r_str, &cur_active) >= 4) {
            if (u_id == user_id) {
                const char *final_name = (new_username && strlen(new_username) > 0) ? new_username : u_name;
                const char *final_role = (new_role != ROLE_UNKNOWN) ? role_to_string(new_role) : r_str;
                fprintf(out, "%d|%s|%s|%s|%d\n", u_id, final_name, p_hash, final_role, active);
                updated = 0;
            } else {
                fprintf(out, "%s\n", line);
            }
        } else {
            fprintf(out, "%s\n", line);
        }
    }
    fclose(fp);
    fflush(out);
    fsync(fileno(out));
    fclose(out);

    if (updated == 0) {
        rename(tmp_file, USERS_FILE);
    } else {
        unlink(tmp_file);
    }
    return updated;
}

int get_all_users(User *out_users, int max_users, int *out_count)
{
    FILE *fp = fopen(USERS_FILE, "r");
    if (!fp) {
        if (out_count) *out_count = 0;
        return 0;
    }

    int count = 0;
    char line[1024];
    while (fgets(line, sizeof(line), fp) && count < max_users) {
        trim_newline(line);
        char u_name[MAX_USERNAME_LEN] = {0};
        char p_hash[MAX_HASH_LEN] = {0};
        char r_str[MAX_ROLE_LEN] = {0};
        int u_id = 0, active = 1;

        if (sscanf(line, "%d|%63[^|]|%64[^|]|%15[^|]|%d",
                   &u_id, u_name, p_hash, r_str, &active) >= 4) {
            out_users[count].user_id = u_id;
            strncpy(out_users[count].username, u_name, sizeof(out_users[count].username) - 1);
            strncpy(out_users[count].password_hash, p_hash, sizeof(out_users[count].password_hash) - 1);
            out_users[count].role = string_to_role(r_str);
            out_users[count].active = active;
            count++;
        }
    }
    fclose(fp);
    if (out_count) *out_count = count;
    return 0;
}

/* Accounts */
int get_account_by_id(int account_id, Account *out_account)
{
    FILE *fp = fopen(ACCOUNTS_FILE, "r");
    if (!fp) return -1;

    char line[1024];
    int found = -1;
    while (fgets(line, sizeof(line), fp)) {
        trim_newline(line);
        int a_id = 0, u_id = 0, active = 1;
        long long bal = 0;
        if (sscanf(line, "%d|%d|%lld|%d", &a_id, &u_id, &bal, &active) >= 3) {
            if (a_id == account_id) {
                if (out_account) {
                    out_account->account_id = a_id;
                    out_account->user_id = u_id;
                    out_account->balance_cents = bal;
                    out_account->active = active;
                }
                found = 0;
                break;
            }
        }
    }
    fclose(fp);
    return found;
}

int get_account_by_user_id(int user_id, Account *out_account)
{
    FILE *fp = fopen(ACCOUNTS_FILE, "r");
    if (!fp) return -1;

    char line[1024];
    int found = -1;
    while (fgets(line, sizeof(line), fp)) {
        trim_newline(line);
        int a_id = 0, u_id = 0, active = 1;
        long long bal = 0;
        if (sscanf(line, "%d|%d|%lld|%d", &a_id, &u_id, &bal, &active) >= 3) {
            if (u_id == user_id) {
                if (out_account) {
                    out_account->account_id = a_id;
                    out_account->user_id = u_id;
                    out_account->balance_cents = bal;
                    out_account->active = active;
                }
                found = 0;
                break;
            }
        }
    }
    fclose(fp);
    return found;
}

int create_account(int user_id, long long initial_balance_cents, Account *out_account)
{
    int next_id = get_max_id_from_file(ACCOUNTS_FILE) + 1;
    FILE *fp = fopen(ACCOUNTS_FILE, "a");
    if (!fp) return -1;

    fprintf(fp, "%d|%d|%lld|1\n", next_id, user_id, initial_balance_cents);
    fflush(fp);
    fsync(fileno(fp));
    fclose(fp);

    if (out_account) {
        out_account->account_id = next_id;
        out_account->user_id = user_id;
        out_account->balance_cents = initial_balance_cents;
        out_account->active = 1;
    }
    return next_id;
}

int update_account_balance(int account_id, long long new_balance_cents)
{
    FILE *fp = fopen(ACCOUNTS_FILE, "r");
    if (!fp) return -1;

    char tmp_file[256];
    snprintf(tmp_file, sizeof(tmp_file), "%s.tmp.%d", ACCOUNTS_FILE, getpid());
    FILE *out = fopen(tmp_file, "w");
    if (!out) {
        fclose(fp);
        return -1;
    }

    char line[1024];
    int updated = -1;
    while (fgets(line, sizeof(line), fp)) {
        trim_newline(line);
        int a_id = 0, u_id = 0, active = 1;
        long long bal = 0;
        if (sscanf(line, "%d|%d|%lld|%d", &a_id, &u_id, &bal, &active) >= 3) {
            if (a_id == account_id) {
                fprintf(out, "%d|%d|%lld|%d\n", a_id, u_id, new_balance_cents, active);
                updated = 0;
            } else {
                fprintf(out, "%s\n", line);
            }
        } else {
            fprintf(out, "%s\n", line);
        }
    }
    fclose(fp);
    fflush(out);
    fsync(fileno(out));
    fclose(out);

    if (updated == 0) {
        rename(tmp_file, ACCOUNTS_FILE);
    } else {
        unlink(tmp_file);
    }
    return updated;
}

int set_account_active(int account_id, int active)
{
    FILE *fp = fopen(ACCOUNTS_FILE, "r");
    if (!fp) return -1;

    char tmp_file[256];
    snprintf(tmp_file, sizeof(tmp_file), "%s.tmp.%d", ACCOUNTS_FILE, getpid());
    FILE *out = fopen(tmp_file, "w");
    if (!out) {
        fclose(fp);
        return -1;
    }

    char line[1024];
    int updated = -1;
    while (fgets(line, sizeof(line), fp)) {
        trim_newline(line);
        int a_id = 0, u_id = 0, cur_active = 1;
        long long bal = 0;
        if (sscanf(line, "%d|%d|%lld|%d", &a_id, &u_id, &bal, &cur_active) >= 3) {
            if (a_id == account_id) {
                fprintf(out, "%d|%d|%lld|%d\n", a_id, u_id, bal, active);
                updated = 0;
            } else {
                fprintf(out, "%s\n", line);
            }
        } else {
            fprintf(out, "%s\n", line);
        }
    }
    fclose(fp);
    fflush(out);
    fsync(fileno(out));
    fclose(out);

    if (updated == 0) {
        rename(tmp_file, ACCOUNTS_FILE);
    } else {
        unlink(tmp_file);
    }
    return updated;
}

int get_all_accounts(Account *out_accounts, int max_accounts, int *out_count)
{
    FILE *fp = fopen(ACCOUNTS_FILE, "r");
    if (!fp) {
        if (out_count) *out_count = 0;
        return 0;
    }

    int count = 0;
    char line[1024];
    while (fgets(line, sizeof(line), fp) && count < max_accounts) {
        trim_newline(line);
        int a_id = 0, u_id = 0, active = 1;
        long long bal = 0;
        if (sscanf(line, "%d|%d|%lld|%d", &a_id, &u_id, &bal, &active) >= 3) {
            out_accounts[count].account_id = a_id;
            out_accounts[count].user_id = u_id;
            out_accounts[count].balance_cents = bal;
            out_accounts[count].active = active;
            count++;
        }
    }
    fclose(fp);
    if (out_count) *out_count = count;
    return 0;
}

/* Transactions */
int record_transaction(
    int account_id,
    const char *type,
    long long amount_cents,
    int related_account_id,
    const char *details,
    int *out_tx_id
) {
    int next_id = get_max_id_from_file(TRANSACTIONS_FILE) + 1;
    FILE *fp = fopen(TRANSACTIONS_FILE, "a");
    if (!fp) return -1;

    time_t now = time(NULL);
    fprintf(fp, "%d|%d|%s|%lld|%d|%s|%ld\n",
            next_id, account_id, type, amount_cents, related_account_id,
            details ? details : "", (long)now);
    fflush(fp);
    fsync(fileno(fp));
    fclose(fp);

    if (out_tx_id) *out_tx_id = next_id;
    return next_id;
}

int get_transactions_by_account(int account_id, Transaction *out_txs, int max_txs, int *out_count)
{
    FILE *fp = fopen(TRANSACTIONS_FILE, "r");
    if (!fp) {
        if (out_count) *out_count = 0;
        return 0;
    }

    int count = 0;
    char line[1024];
    while (fgets(line, sizeof(line), fp) && count < max_txs) {
        trim_newline(line);
        int tx_id = 0, a_id = 0, rel_id = 0;
        char type[MAX_TYPE_LEN] = {0};
        char details[MAX_DETAILS_LEN] = {0};
        long long amt = 0;
        long ts = 0;

        if (sscanf(line, "%d|%d|%31[^|]|%lld|%d|%127[^|]|%ld",
                   &tx_id, &a_id, type, &amt, &rel_id, details, &ts) >= 5) {
            if (a_id == account_id || rel_id == account_id) {
                out_txs[count].transaction_id = tx_id;
                out_txs[count].account_id = a_id;
                strncpy(out_txs[count].type, type, sizeof(out_txs[count].type) - 1);
                out_txs[count].amount_cents = amt;
                out_txs[count].related_account_id = rel_id;
                strncpy(out_txs[count].details, details, sizeof(out_txs[count].details) - 1);
                out_txs[count].timestamp = (time_t)ts;
                count++;
            }
        }
    }
    fclose(fp);
    if (out_count) *out_count = count;
    return 0;
}

/* Loans */
int create_loan(int account_id, long long amount_cents, int *out_loan_id)
{
    int next_id = get_max_id_from_file(LOANS_FILE) + 1;
    FILE *fp = fopen(LOANS_FILE, "a");
    if (!fp) return -1;

    time_t now = time(NULL);
    fprintf(fp, "%d|%d|%lld|PENDING|0|%ld|0\n",
            next_id, account_id, amount_cents, (long)now);
    fflush(fp);
    fsync(fileno(fp));
    fclose(fp);

    if (out_loan_id) *out_loan_id = next_id;
    return next_id;
}

int get_loan_by_id(int loan_id, Loan *out_loan)
{
    FILE *fp = fopen(LOANS_FILE, "r");
    if (!fp) return -1;

    char line[1024];
    int found = -1;
    while (fgets(line, sizeof(line), fp)) {
        trim_newline(line);
        int l_id = 0, a_id = 0, emp_id = 0;
        long long amt = 0;
        char status[MAX_STATUS_LEN] = {0};
        long created = 0, processed = 0;

        if (sscanf(line, "%d|%d|%lld|%31[^|]|%d|%ld|%ld",
                   &l_id, &a_id, &amt, status, &emp_id, &created, &processed) >= 4) {
            if (l_id == loan_id) {
                if (out_loan) {
                    out_loan->loan_id = l_id;
                    out_loan->account_id = a_id;
                    out_loan->amount_cents = amt;
                    strncpy(out_loan->status, status, sizeof(out_loan->status) - 1);
                    out_loan->assigned_employee_id = emp_id;
                    out_loan->created_at = (time_t)created;
                    out_loan->processed_at = (time_t)processed;
                }
                found = 0;
                break;
            }
        }
    }
    fclose(fp);
    return found;
}

int get_loans_by_account(int account_id, Loan *out_loans, int max_loans, int *out_count)
{
    FILE *fp = fopen(LOANS_FILE, "r");
    if (!fp) {
        if (out_count) *out_count = 0;
        return 0;
    }

    int count = 0;
    char line[1024];
    while (fgets(line, sizeof(line), fp) && count < max_loans) {
        trim_newline(line);
        int l_id = 0, a_id = 0, emp_id = 0;
        long long amt = 0;
        char status[MAX_STATUS_LEN] = {0};
        long created = 0, processed = 0;

        if (sscanf(line, "%d|%d|%lld|%31[^|]|%d|%ld|%ld",
                   &l_id, &a_id, &amt, status, &emp_id, &created, &processed) >= 4) {
            if (a_id == account_id) {
                out_loans[count].loan_id = l_id;
                out_loans[count].account_id = a_id;
                out_loans[count].amount_cents = amt;
                strncpy(out_loans[count].status, status, sizeof(out_loans[count].status) - 1);
                out_loans[count].assigned_employee_id = emp_id;
                out_loans[count].created_at = (time_t)created;
                out_loans[count].processed_at = (time_t)processed;
                count++;
            }
        }
    }
    fclose(fp);
    if (out_count) *out_count = count;
    return 0;
}

int get_loans_by_employee(int employee_id, Loan *out_loans, int max_loans, int *out_count)
{
    FILE *fp = fopen(LOANS_FILE, "r");
    if (!fp) {
        if (out_count) *out_count = 0;
        return 0;
    }

    int count = 0;
    char line[1024];
    while (fgets(line, sizeof(line), fp) && count < max_loans) {
        trim_newline(line);
        int l_id = 0, a_id = 0, emp_id = 0;
        long long amt = 0;
        char status[MAX_STATUS_LEN] = {0};
        long created = 0, processed = 0;

        if (sscanf(line, "%d|%d|%lld|%31[^|]|%d|%ld|%ld",
                   &l_id, &a_id, &amt, status, &emp_id, &created, &processed) >= 4) {
            if (emp_id == employee_id) {
                out_loans[count].loan_id = l_id;
                out_loans[count].account_id = a_id;
                out_loans[count].amount_cents = amt;
                strncpy(out_loans[count].status, status, sizeof(out_loans[count].status) - 1);
                out_loans[count].assigned_employee_id = emp_id;
                out_loans[count].created_at = (time_t)created;
                out_loans[count].processed_at = (time_t)processed;
                count++;
            }
        }
    }
    fclose(fp);
    if (out_count) *out_count = count;
    return 0;
}

int get_all_loans(Loan *out_loans, int max_loans, int *out_count)
{
    FILE *fp = fopen(LOANS_FILE, "r");
    if (!fp) {
        if (out_count) *out_count = 0;
        return 0;
    }

    int count = 0;
    char line[1024];
    while (fgets(line, sizeof(line), fp) && count < max_loans) {
        trim_newline(line);
        int l_id = 0, a_id = 0, emp_id = 0;
        long long amt = 0;
        char status[MAX_STATUS_LEN] = {0};
        long created = 0, processed = 0;

        if (sscanf(line, "%d|%d|%lld|%31[^|]|%d|%ld|%ld",
                   &l_id, &a_id, &amt, status, &emp_id, &created, &processed) >= 4) {
            out_loans[count].loan_id = l_id;
            out_loans[count].account_id = a_id;
            out_loans[count].amount_cents = amt;
            strncpy(out_loans[count].status, status, sizeof(out_loans[count].status) - 1);
            out_loans[count].assigned_employee_id = emp_id;
            out_loans[count].created_at = (time_t)created;
            out_loans[count].processed_at = (time_t)processed;
            count++;
        }
    }
    fclose(fp);
    if (out_count) *out_count = count;
    return 0;
}

int assign_loan(int loan_id, int employee_id)
{
    FILE *fp = fopen(LOANS_FILE, "r");
    if (!fp) return -1;

    char tmp_file[256];
    snprintf(tmp_file, sizeof(tmp_file), "%s.tmp.%d", LOANS_FILE, getpid());
    FILE *out = fopen(tmp_file, "w");
    if (!out) {
        fclose(fp);
        return -1;
    }

    char line[1024];
    int updated = -1;
    while (fgets(line, sizeof(line), fp)) {
        trim_newline(line);
        int l_id = 0, a_id = 0, emp_id = 0;
        long long amt = 0;
        char status[MAX_STATUS_LEN] = {0};
        long created = 0, processed = 0;

        if (sscanf(line, "%d|%d|%lld|%31[^|]|%d|%ld|%ld",
                   &l_id, &a_id, &amt, status, &emp_id, &created, &processed) >= 4) {
            if (l_id == loan_id) {
                fprintf(out, "%d|%d|%lld|%s|%d|%ld|%ld\n",
                        l_id, a_id, amt, status, employee_id, created, processed);
                updated = 0;
            } else {
                fprintf(out, "%s\n", line);
            }
        } else {
            fprintf(out, "%s\n", line);
        }
    }
    fclose(fp);
    fflush(out);
    fsync(fileno(out));
    fclose(out);

    if (updated == 0) {
        rename(tmp_file, LOANS_FILE);
    } else {
        unlink(tmp_file);
    }
    return updated;
}

int update_loan_status(int loan_id, const char *status)
{
    FILE *fp = fopen(LOANS_FILE, "r");
    if (!fp) return -1;

    char tmp_file[256];
    snprintf(tmp_file, sizeof(tmp_file), "%s.tmp.%d", LOANS_FILE, getpid());
    FILE *out = fopen(tmp_file, "w");
    if (!out) {
        fclose(fp);
        return -1;
    }

    char line[1024];
    int updated = -1;
    time_t now = time(NULL);
    while (fgets(line, sizeof(line), fp)) {
        trim_newline(line);
        int l_id = 0, a_id = 0, emp_id = 0;
        long long amt = 0;
        char cur_status[MAX_STATUS_LEN] = {0};
        long created = 0, processed = 0;

        if (sscanf(line, "%d|%d|%lld|%31[^|]|%d|%ld|%ld",
                   &l_id, &a_id, &amt, cur_status, &emp_id, &created, &processed) >= 4) {
            if (l_id == loan_id) {
                fprintf(out, "%d|%d|%lld|%s|%d|%ld|%ld\n",
                        l_id, a_id, amt, status, emp_id, created, (long)now);
                updated = 0;
            } else {
                fprintf(out, "%s\n", line);
            }
        } else {
            fprintf(out, "%s\n", line);
        }
    }
    fclose(fp);
    fflush(out);
    fsync(fileno(out));
    fclose(out);

    if (updated == 0) {
        rename(tmp_file, LOANS_FILE);
    } else {
        unlink(tmp_file);
    }
    return updated;
}

/* Feedback */
int add_feedback(int user_id, const char *message, int *out_feedback_id)
{
    int next_id = get_max_id_from_file(FEEDBACK_FILE) + 1;
    FILE *fp = fopen(FEEDBACK_FILE, "a");
    if (!fp) return -1;

    time_t now = time(NULL);
    fprintf(fp, "%d|%d|%s|%ld\n", next_id, user_id, message ? message : "", (long)now);
    fflush(fp);
    fsync(fileno(fp));
    fclose(fp);

    if (out_feedback_id) *out_feedback_id = next_id;
    return next_id;
}

int get_all_feedback(Feedback *out_feedback, int max_items, int *out_count)
{
    FILE *fp = fopen(FEEDBACK_FILE, "r");
    if (!fp) {
        if (out_count) *out_count = 0;
        return 0;
    }

    int count = 0;
    char line[1024];
    while (fgets(line, sizeof(line), fp) && count < max_items) {
        trim_newline(line);
        int f_id = 0, u_id = 0;
        char msg[MAX_FEEDBACK_LEN] = {0};
        long ts = 0;

        if (sscanf(line, "%d|%d|%255[^|]|%ld", &f_id, &u_id, msg, &ts) >= 3) {
            out_feedback[count].feedback_id = f_id;
            out_feedback[count].user_id = u_id;
            strncpy(out_feedback[count].message, msg, sizeof(out_feedback[count].message) - 1);
            out_feedback[count].timestamp = (time_t)ts;
            count++;
        }
    }
    fclose(fp);
    if (out_count) *out_count = count;
    return 0;
}

/* Request Results / Idempotency */
int get_request_result(const char *request_id, RequestResult *out_res)
{
    if (!request_id) return -1;
    FILE *fp = fopen(REQUEST_RESULTS_FILE, "r");
    if (!fp) return -1;

    char line[2048];
    int found = -1;
    while (fgets(line, sizeof(line), fp)) {
        trim_newline(line);
        char r_id[MAX_REQ_ID_LEN] = {0};
        int u_id = 0;
        char op[MAX_TYPE_LEN] = {0};
        char fp_str[MAX_FINGERPRINT_LEN] = {0};
        char status[MAX_STATUS_LEN] = {0};
        char r_code[MAX_RESP_CODE_LEN] = {0};
        char r_msg[MAX_RESP_MSG_LEN] = {0};
        int tx_id = 0;
        long created = 0, updated = 0;

        /* request_id|user_id|operation|payload_fingerprint|status|response_code|response_message|transaction_id|created_at|updated_at */
        char *p = line;
        char *token;
        int col = 0;
        while ((token = strsep(&p, "|")) != NULL) {
            col++;
            switch (col) {
                case 1: safe_copy(r_id, token, sizeof(r_id)); break;
                case 2: u_id = atoi(token); break;
                case 3: safe_copy(op, token, sizeof(op)); break;
                case 4: safe_copy(fp_str, token, sizeof(fp_str)); break;
                case 5: safe_copy(status, token, sizeof(status)); break;
                case 6: safe_copy(r_code, token, sizeof(r_code)); break;
                case 7: safe_copy(r_msg, token, sizeof(r_msg)); break;
                case 8: tx_id = atoi(token); break;
                case 9: created = atol(token); break;
                case 10: updated = atol(token); break;
            }
        }

        if (col >= 5 && strcmp(r_id, request_id) == 0) {
            if (out_res) {
                safe_copy(out_res->request_id, r_id, sizeof(out_res->request_id));
                out_res->user_id = u_id;
                safe_copy(out_res->operation, op, sizeof(out_res->operation));
                safe_copy(out_res->payload_fingerprint, fp_str, sizeof(out_res->payload_fingerprint));
                safe_copy(out_res->status, status, sizeof(out_res->status));
                safe_copy(out_res->response_code, r_code, sizeof(out_res->response_code));
                safe_copy(out_res->response_message, r_msg, sizeof(out_res->response_message));
                out_res->transaction_id = tx_id;
                out_res->created_at = (time_t)created;
                out_res->updated_at = (time_t)updated;
            }
            found = 0;
            break;
        }
    }
    fclose(fp);
    return found;
}

int save_new_request_result(const RequestResult *res)
{
    if (!res) return -1;
    FILE *fp = fopen(REQUEST_RESULTS_FILE, "a");
    if (!fp) return -1;

    fprintf(fp, "%s|%d|%s|%s|%s|%s|%s|%d|%ld|%ld\n",
            res->request_id,
            res->user_id,
            res->operation,
            res->payload_fingerprint,
            res->status,
            res->response_code,
            res->response_message,
            res->transaction_id,
            (long)res->created_at,
            (long)res->updated_at);
    fflush(fp);
    fsync(fileno(fp));
    fclose(fp);
    return 0;
}

int update_request_result(const RequestResult *res)
{
    if (!res) return -1;
    FILE *fp = fopen(REQUEST_RESULTS_FILE, "r");
    if (!fp) return -1;

    char tmp_file[256];
    snprintf(tmp_file, sizeof(tmp_file), "%s.tmp.%d", REQUEST_RESULTS_FILE, getpid());
    FILE *out = fopen(tmp_file, "w");
    if (!out) {
        fclose(fp);
        return -1;
    }

    char line[2048];
    int updated = -1;
    while (fgets(line, sizeof(line), fp)) {
        char line_copy[2048];
        strncpy(line_copy, line, sizeof(line_copy) - 1);
        line_copy[sizeof(line_copy) - 1] = '\0';
        trim_newline(line_copy);

        char r_id[MAX_REQ_ID_LEN] = {0};
        char *p = line_copy;
        char *token = strsep(&p, "|");
        if (token) strncpy(r_id, token, sizeof(r_id) - 1);

        if (strcmp(r_id, res->request_id) == 0) {
            fprintf(out, "%s|%d|%s|%s|%s|%s|%s|%d|%ld|%ld\n",
                    res->request_id,
                    res->user_id,
                    res->operation,
                    res->payload_fingerprint,
                    res->status,
                    res->response_code,
                    res->response_message,
                    res->transaction_id,
                    (long)res->created_at,
                    (long)res->updated_at);
            updated = 0;
        } else {
            fputs(line, out);
        }
    }
    fclose(fp);
    fflush(out);
    fsync(fileno(out));
    fclose(out);

    if (updated == 0) {
        rename(tmp_file, REQUEST_RESULTS_FILE);
    } else {
        unlink(tmp_file);
    }
    return updated;
}

/* Atomic Financial Transactions */

int execute_deposit(
    const char *request_id,
    int account_id,
    long long amount_cents,
    int *out_tx_id,
    char *err_msg,
    size_t err_size
) {
    if (amount_cents <= 0) {
        if (err_msg) snprintf(err_msg, err_size, "Deposit amount must be positive");
        return -1;
    }

    Account acc;
    if (get_account_by_id(account_id, &acc) != 0) {
        if (err_msg) snprintf(err_msg, err_size, "Account ID %d not found", account_id);
        return -2;
    }
    if (!acc.active) {
        if (err_msg) snprintf(err_msg, err_size, "Account ID %d is inactive", account_id);
        return -3;
    }

    long op_id = (long)time(NULL);
    char details[128];
    snprintf(details, sizeof(details), "acc=%d;amt=%lld", account_id, amount_cents);
    append_journal_entry(op_id, request_id, "DEPOSIT", details, "PREPARED");

    /* Update balance */
    long long new_bal = acc.balance_cents + amount_cents;
    if (update_account_balance(account_id, new_bal) != 0) {
        if (err_msg) snprintf(err_msg, err_size, "Failed to update account balance");
        return -4;
    }

    /* Record transaction */
    int tx_id = 0;
    if (record_transaction(account_id, "DEPOSIT", amount_cents, 0, "Cash deposit", &tx_id) < 0) {
        if (err_msg) snprintf(err_msg, err_size, "Failed to write transaction record");
        return -5;
    }

    append_journal_entry(op_id, request_id, "DEPOSIT", details, "COMMITTED");

    if (out_tx_id) *out_tx_id = tx_id;
    return 0;
}

int execute_withdraw(
    const char *request_id,
    int account_id,
    long long amount_cents,
    int *out_tx_id,
    char *err_msg,
    size_t err_size
) {
    if (amount_cents <= 0) {
        if (err_msg) snprintf(err_msg, err_size, "Withdrawal amount must be positive");
        return -1;
    }

    Account acc;
    if (get_account_by_id(account_id, &acc) != 0) {
        if (err_msg) snprintf(err_msg, err_size, "Account ID %d not found", account_id);
        return -2;
    }
    if (!acc.active) {
        if (err_msg) snprintf(err_msg, err_size, "Account ID %d is inactive", account_id);
        return -3;
    }
    if (acc.balance_cents < amount_cents) {
        if (err_msg) snprintf(err_msg, err_size, "Insufficient funds. Available: $%.2f, Requested: $%.2f",
                              (double)acc.balance_cents / 100.0, (double)amount_cents / 100.0);
        return -4;
    }

    long op_id = (long)time(NULL);
    char details[128];
    snprintf(details, sizeof(details), "acc=%d;amt=%lld", account_id, amount_cents);
    append_journal_entry(op_id, request_id, "WITHDRAW", details, "PREPARED");

    long long new_bal = acc.balance_cents - amount_cents;
    if (update_account_balance(account_id, new_bal) != 0) {
        if (err_msg) snprintf(err_msg, err_size, "Failed to update account balance");
        return -5;
    }

    int tx_id = 0;
    if (record_transaction(account_id, "WITHDRAW", amount_cents, 0, "Cash withdrawal", &tx_id) < 0) {
        if (err_msg) snprintf(err_msg, err_size, "Failed to write transaction record");
        return -6;
    }

    append_journal_entry(op_id, request_id, "WITHDRAW", details, "COMMITTED");

    if (out_tx_id) *out_tx_id = tx_id;
    return 0;
}

int execute_transfer(
    const char *request_id,
    int sender_account_id,
    int receiver_account_id,
    long long amount_cents,
    int *out_tx_id,
    char *err_msg,
    size_t err_size
) {
    if (amount_cents <= 0) {
        if (err_msg) snprintf(err_msg, err_size, "Transfer amount must be positive");
        return -1;
    }
    if (sender_account_id == receiver_account_id) {
        if (err_msg) snprintf(err_msg, err_size, "Sender and receiver account cannot be the same");
        return -1;
    }

    Account sender, receiver;
    if (get_account_by_id(sender_account_id, &sender) != 0) {
        if (err_msg) snprintf(err_msg, err_size, "Sender account %d not found", sender_account_id);
        return -2;
    }
    if (!sender.active) {
        if (err_msg) snprintf(err_msg, err_size, "Sender account %d is inactive", sender_account_id);
        return -3;
    }
    if (get_account_by_id(receiver_account_id, &receiver) != 0) {
        if (err_msg) snprintf(err_msg, err_size, "Receiver account %d not found", receiver_account_id);
        return -2;
    }
    if (!receiver.active) {
        if (err_msg) snprintf(err_msg, err_size, "Receiver account %d is inactive", receiver_account_id);
        return -3;
    }
    if (sender.balance_cents < amount_cents) {
        if (err_msg) snprintf(err_msg, err_size, "Insufficient funds. Available: $%.2f, Requested: $%.2f",
                              (double)sender.balance_cents / 100.0, (double)amount_cents / 100.0);
        return -4;
    }

    long op_id = (long)time(NULL);
    char details[128];
    snprintf(details, sizeof(details), "from=%d;to=%d;amt=%lld",
             sender_account_id, receiver_account_id, amount_cents);
    append_journal_entry(op_id, request_id, "TRANSFER", details, "PREPARED");

    /* Atomic balance updates */
    long long new_sender_bal = sender.balance_cents - amount_cents;
    long long new_receiver_bal = receiver.balance_cents + amount_cents;

    if (update_account_balance(sender_account_id, new_sender_bal) != 0) {
        if (err_msg) snprintf(err_msg, err_size, "Failed to update sender account balance");
        return -5;
    }
    if (update_account_balance(receiver_account_id, new_receiver_bal) != 0) {
        /* Rollback sender */
        update_account_balance(sender_account_id, sender.balance_cents);
        if (err_msg) snprintf(err_msg, err_size, "Failed to update receiver account balance");
        return -5;
    }

    /* Record transactions for both parties */
    int tx_sender = 0;
    record_transaction(sender_account_id, "TRANSFER_OUT", amount_cents, receiver_account_id,
                       "Transfer to receiver", &tx_sender);

    int tx_receiver = 0;
    record_transaction(receiver_account_id, "TRANSFER_IN", amount_cents, sender_account_id,
                       "Transfer from sender", &tx_receiver);

    append_journal_entry(op_id, request_id, "TRANSFER", details, "COMMITTED");

    if (out_tx_id) *out_tx_id = tx_sender;
    return 0;
}

int execute_loan_process(
    const char *request_id,
    int loan_id,
    const char *decision,
    int employee_id,
    int *out_tx_id,
    char *err_msg,
    size_t err_size
) {
    Loan loan;
    if (get_loan_by_id(loan_id, &loan) != 0) {
        if (err_msg) snprintf(err_msg, err_size, "Loan application %d not found", loan_id);
        return -1;
    }
    if (strcmp(loan.status, "PENDING") != 0) {
        if (err_msg) snprintf(err_msg, err_size, "Loan application %d is already %s", loan_id, loan.status);
        return -2;
    }

    long op_id = (long)time(NULL);
    char details[128];
    snprintf(details, sizeof(details), "loan=%d;dec=%s;emp=%d", loan_id, decision, employee_id);
    append_journal_entry(op_id, request_id, "PROCESS_LOAN", details, "PREPARED");

    if (strcasecmp(decision, "APPROVED") == 0) {
        Account acc;
        if (get_account_by_id(loan.account_id, &acc) != 0 || !acc.active) {
            if (err_msg) snprintf(err_msg, err_size, "Associated account %d is invalid or inactive", loan.account_id);
            return -3;
        }

        /* Update loan status */
        update_loan_status(loan_id, "APPROVED");

        /* Credit account balance */
        update_account_balance(loan.account_id, acc.balance_cents + loan.amount_cents);

        /* Record transaction */
        int tx_id = 0;
        char tx_detail[64];
        snprintf(tx_detail, sizeof(tx_detail), "Loan disbursement #%d", loan_id);
        record_transaction(loan.account_id, "LOAN_CREDIT", loan.amount_cents, 0, tx_detail, &tx_id);

        append_journal_entry(op_id, request_id, "PROCESS_LOAN", details, "COMMITTED");
        if (out_tx_id) *out_tx_id = tx_id;
    } else {
        /* REJECTED */
        update_loan_status(loan_id, "REJECTED");
        append_journal_entry(op_id, request_id, "PROCESS_LOAN", details, "COMMITTED");
        if (out_tx_id) *out_tx_id = 0;
    }

    return 0;
}

/* Initialization and recovery */
int storage_init_and_recover(void)
{
    if (ensure_directories() != 0) {
        return -1;
    }

    int lock_fd = acquire_db_lock(1);
    if (lock_fd < 0) {
        return -1;
    }

    /* Seed default users if users.txt is empty or missing */
    FILE *fp_user = fopen(USERS_FILE, "r");
    int need_seed = 0;
    if (!fp_user) {
        need_seed = 1;
    } else {
        fseek(fp_user, 0, SEEK_END);
        if (ftell(fp_user) == 0) need_seed = 1;
        fclose(fp_user);
    }

    if (need_seed) {
        char hash[65];
        /* 1: Admin */
        sha256_string("admin123", hash);
        add_user("admin", hash, ROLE_ADMIN, NULL);

        /* 2: Manager */
        sha256_string("manager123", hash);
        add_user("manager", hash, ROLE_MANAGER, NULL);

        /* 3: Employee */
        sha256_string("emp1", hash);
        add_user("emp1", hash, ROLE_EMPLOYEE, NULL);

        /* 4: Alice (Customer) */
        sha256_string("alice123", hash);
        User u_alice;
        add_user("alice", hash, ROLE_CUSTOMER, &u_alice);
        create_account(u_alice.user_id, 100000, NULL); /* $1000.00 */

        /* 5: Bob (Customer) */
        sha256_string("bob123", hash);
        User u_bob;
        add_user("bob", hash, ROLE_CUSTOMER, &u_bob);
        create_account(u_bob.user_id, 50000, NULL); /* $500.00 */
    }

    /* Crash recovery check on journal */
    FILE *fp_j = fopen(JOURNAL_FILE, "r");
    if (fp_j) {
        char line[1024];
        /* Store recent prepared operations */
        while (fgets(line, sizeof(line), fp_j)) {
            trim_newline(line);
            long op_id = 0;
            char req_id[MAX_REQ_ID_LEN] = {0};
            char type[MAX_TYPE_LEN] = {0};
            char details[128] = {0};
            char status[MAX_STATUS_LEN] = {0};
            long ts = 0;

            if (sscanf(line, "%ld|%64[^|]|%31[^|]|%127[^|]|%31[^|]|%ld",
                       &op_id, req_id, type, details, status, &ts) >= 5) {
                if (strcmp(status, "PREPARED") == 0 && strlen(req_id) > 0) {
                    RequestResult rr;
                    if (get_request_result(req_id, &rr) == 0) {
                        if (strcmp(rr.status, "IN_PROGRESS") == 0) {
                            /* Recover: check if transaction was committed in transactions.txt */
                            /* If not committed, mark failed */
                            strncpy(rr.status, "FAILED", sizeof(rr.status) - 1);
                            strncpy(rr.response_code, "RECOVERED_AFTER_CRASH", sizeof(rr.response_code) - 1);
                            strncpy(rr.response_message, "Transaction was interrupted and rolled back during crash recovery", sizeof(rr.response_message) - 1);
                            rr.updated_at = time(NULL);
                            update_request_result(&rr);
                        }
                    }
                }
            }
        }
        fclose(fp_j);
    }

    release_db_lock(lock_fd);
    return 0;
}
