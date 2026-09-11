CC = gcc
CFLAGS = -std=c11 -O3 -Wall -Wextra -Werror -Wformat -Wformat-security -fstack-protector-strong -fPIE -fno-strict-aliasing -D_FORTIFY_SOURCE=2 -I./src
LDFLAGS = -Wl,-z,relro,-z,now -pie -lsodium -lpthread

SRC_DIR = src
BIN_DIR = bin
TEST_DIR = tests

SRCS = $(SRC_DIR)/executive.c $(SRC_DIR)/core.c $(SRC_DIR)/interlocks.c $(SRC_DIR)/telemetry.c $(SRC_DIR)/transport.c $(SRC_DIR)/tree.c $(SRC_DIR)/heartbeat.c
OBJS = $(SRCS:.c=.o)

all: directories $(BIN_DIR)/gate0-exec

directories:
	mkdir -p $(BIN_DIR)

$(BIN_DIR)/gate0-exec: $(OBJS)
	$(CC) $(OBJS) -o $@ $(LDFLAGS)
	@echo "[+] Gate Zero Unified Executive compiled with maximum hardening."

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

test: directories
	$(CC) $(CFLAGS) $(TEST_DIR)/test_gate0.c $(SRC_DIR)/core.c $(SRC_DIR)/interlocks.c $(SRC_DIR)/telemetry.c -o $(BIN_DIR)/gate0-test $(LDFLAGS)
	$(BIN_DIR)/gate0-test

clean:
	rm -f $(SRC_DIR)/*.o $(BIN_DIR)/*

.PHONY: all directories test clean
