# socket-state-triage

Small C command-line tool for reviewing Linux socket listings during a basic host check.

It reads output shaped like `ss -tuna` and prints:

- total listening sockets
- established socket rows
- TCP and UDP row counts
- broad IPv4 binds to `0.0.0.0`
- broad IPv6 binds to `[::]`
- wildcard binds shown as `*`
- loopback-only binds to `127.*` or `[::1]`
- broad binds on privileged ports below 1024
- established TCP sockets whose local address is not loopback
- established TCP sockets with a non-private IPv4 peer
- `review:` lines for socket rows worth checking

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

Limit review lines while keeping full summary counts:

```sh
./socket-state-triage --limit 5 samples/ss-output.txt
```

Print only the summary counts:

```sh
./socket-state-triage --summary-only samples/ss-output.txt
```

Example output:

```text
review: tcp broad bind on 0.0.0.0:8080
review: tcp broad bind on [::]:8443
review: tcp wildcard bind on *:9090
review: tcp remote established socket on 10.0.0.5:22
review: tcp remote established socket on 10.0.0.5:443
review: tcp non-private peer on 203.0.113.20:52100
review: udp broad bind on 0.0.0.0:5353
listening sockets: 4
established sockets: 2
tcp sockets: 6
udp sockets: 2
broad IPv4 binds: 2
broad IPv6 binds: 1
wildcard binds: 1
loopback-only binds: 2
privileged broad binds: 0
remote established sockets: 2
non-private established peers: 1
```

## Test

```sh
make test
```

The tests use only POSIX shell commands and the local C compiler.
