#!/bin/sh
set -eu

tmp_output="$(mktemp)"
trap 'rm -f "$tmp_output"' EXIT

./socket-state-triage <<'EOF' >"$tmp_output"
Netid State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process
tcp   LISTEN 0      128    127.0.0.1:5432   0.0.0.0:*
tcp   ESTAB  0      0      10.0.0.5:22      10.0.0.9:52844
udp   UNCONN 0      0      127.0.0.53:53    0.0.0.0:*
EOF

grep -q "listening sockets: 1" "$tmp_output"

./socket-state-triage <<'EOF' >"$tmp_output"
Netid State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process
tcp   LISTEN 0      128    0.0.0.0:8080   0.0.0.0:*
tcp   LISTEN 0      128    127.0.0.1:5432 0.0.0.0:*
EOF

grep -q "broad IPv4 binds: 1" "$tmp_output"
