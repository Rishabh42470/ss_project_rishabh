CC = gcc
CFLAGS = -Wall -Wextra -pedantic -std=c11 -D_POSIX_C_SOURCE=200809L -D_DEFAULT_SOURCE -g

COMMON_SRCS = sha256.c models.c storage.c idempotency.c
COMMON_OBJS = $(COMMON_SRCS:.c=.o)

all: server client

server: server.o $(COMMON_OBJS)
	$(CC) $(CFLAGS) -o $@ $^

client: client.o $(COMMON_OBJS)
	$(CC) $(CFLAGS) -o $@ $^

test: test_system test_concurrency
	./test_system
	./test_concurrency

test_system: test_system.o $(COMMON_OBJS)
	$(CC) $(CFLAGS) -o $@ $^

test_concurrency: test_concurrency.o $(COMMON_OBJS)
	$(CC) $(CFLAGS) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f *.o server client test_system test_concurrency data/*.tmp.*

reset-data:
	rm -rf data/*
	mkdir -p data/sessions

.PHONY: all clean reset-data test
