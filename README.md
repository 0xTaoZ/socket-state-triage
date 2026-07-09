# socket-state-triage

Small C command-line tool for reviewing Linux socket listings during a basic host check.

It reads output shaped like `ss -tuna` and prints:

- total listening sockets
- TCP and UDP row counts
- broad IPv4 listeners bound to `0.0.0.0`
- broad IPv6 listeners bound to `[::]`
- `review:` lines for broad listeners worth checking

This is not a vulnerability scanner. It is a small parsing project for practicing C, Makefiles, tests, and blue-team command-line habits.

## Build

```sh
make
```

## Run

Pipe live socket output:

```sh
ss -tuna | ./socket-state-triage
```

Or read a saved sample:

```sh
./socket-state-triage samples/ss-output.txt
```

Example output:

```text
review: tcp listener on 0.0.0.0:8080
review: tcp listener on [::]:8443
listening sockets: 3
tcp sockets: 3
udp sockets: 2
broad IPv4 binds: 1
broad IPv6 binds: 1
```

## Test

```sh
make test
```

The tests use only POSIX shell commands and the local C compiler.
