#!/usr/bin/env bash
set -e

CC=${CC:-gcc}
CFLAGS="-Wall -Wextra -pedantic -std=c11 -D_POSIX_C_SOURCE=200809L -D_DEFAULT_SOURCE -g"

echo "[*] Compiling common objects..."
$CC $CFLAGS -c sha256.c models.c storage.c idempotency.c

echo "[*] Compiling server..."
$CC $CFLAGS -c server.c
$CC $CFLAGS -o server server.o sha256.o models.o storage.o idempotency.o

echo "[*] Compiling client..."
$CC $CFLAGS -c client.c
$CC $CFLAGS -o client client.o sha256.o models.o storage.o idempotency.o

echo "[*] Compiling test suite..."
$CC $CFLAGS -c test_system.c test_concurrency.c
$CC $CFLAGS -o test_system test_system.o sha256.o models.o storage.o idempotency.o
$CC $CFLAGS -o test_concurrency test_concurrency.o sha256.o models.o storage.o idempotency.o

mkdir -p data/sessions

echo "[+] Build complete: 'server', 'client', 'test_system', and 'test_concurrency' successfully generated."
