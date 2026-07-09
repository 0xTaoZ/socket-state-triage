CC ?= cc
CFLAGS ?= -std=c11 -Wall -Wextra -Werror -pedantic

BIN := socket-state-triage
SRC := src/main.c

.PHONY: all test clean

all: $(BIN)

$(BIN): $(SRC)
	$(CC) $(CFLAGS) -o $@ $(SRC)

test: all
	./tests/run_tests.sh

clean:
	rm -f $(BIN)
