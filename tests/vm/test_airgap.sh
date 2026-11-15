#!/usr/bin/env bash
# Task 4G.5: air-gap behaviour test. Runs inside the booted AIRLOCK guest as root (by
# tests/run-qemu-tests.sh) with a virtual network card attached to a working network.
# Config checks (tests/goss/network.yaml) do not prove the air gap; this does.
#
# Phase 1, as shipped: the interface is down. DNS, HTTP, and ping must all fail.
# Phase 2, root tries: the test brings the interface up by hand with an address and a default
#   route, as a user with sudo could. The firewall must still stop DNS, HTTP, and ping.
# Positive control (--positive-control): the firewall is flushed for a moment and the same
#   probes must now succeed, which proves the network is live and the probes work. The
#   firewall and the interface are restored afterwards, even on failure.
#
# Defaults suit QEMU user networking (-netdev user): gateway 10.0.2.2, DNS 10.0.2.3, guest
# address 10.0.2.15/24. For an HTTP probe that can succeed, the harness runs a web server on
# the host's loopback and passes its port (QEMU maps 10.0.2.2 to the host's 127.0.0.1).
#
# Usage: test_airgap.sh [--iface NAME] [--gateway IP] [--dns IP] [--addr CIDR]
#                       [--http-host IP] [--http-port N] [--name DNSNAME] [--positive-control]
# Env: AIRLOCK_AIRGAP_POSITIVE=1 is the same as --positive-control; AIRLOCK_TEST_NIC=0 (set by
# tests/run-qemu-tests.sh when no card is attached) skips the test.
# Exit: 0 pass, 1 fail, 77 skip (not root, no network card).
set -euo pipefail

IFACE="${AIRLOCK_AIRGAP_IFACE:-}"
GATEWAY="${AIRLOCK_AIRGAP_GATEWAY:-10.0.2.2}"
DNS="${AIRLOCK_AIRGAP_DNS:-10.0.2.3}"
ADDR="${AIRLOCK_AIRGAP_ADDR:-10.0.2.15/24}"
HTTP_HOST="${AIRLOCK_AIRGAP_HTTP_HOST:-}"
HTTP_PORT="${AIRLOCK_AIRGAP_HTTP_PORT:-80}"
NAME="${AIRLOCK_AIRGAP_NAME:-example.com}"
POSITIVE="${AIRLOCK_AIRGAP_POSITIVE:-0}"

usage() { sed -n '2,/^set -euo/{/^set -euo/d;s/^# \{0,1\}//;p}' "$0"; }

while (($#)); do
  case "$1" in
    --iface) IFACE="${2:?--iface needs a name}"; shift 2 ;;
    --gateway) GATEWAY="${2:?--gateway needs an address}"; shift 2 ;;
    --dns) DNS="${2:?--dns needs an address}"; shift 2 ;;
    --addr) ADDR="${2:?--addr needs an address/prefix}"; shift 2 ;;
    --http-host) HTTP_HOST="${2:?--http-host needs an address}"; shift 2 ;;
    --http-port) HTTP_PORT="${2:?--http-port needs a port}"; shift 2 ;;
    --name) NAME="${2:?--name needs a DNS name}"; shift 2 ;;
    --positive-control) POSITIVE=1; shift ;;
    -h | --help) usage; exit 0 ;;
    *) echo "test_airgap: unknown option '$1'. Run with --help." >&2; exit 2 ;;
  esac
done
HTTP_HOST="${HTTP_HOST:-$GATEWAY}"

skip() { echo "skip: $*"; exit 77; }
fail() { echo "FAIL: $*" >&2; exit 1; }

[[ "$(id -u)" -eq 0 ]] || skip "needs root (the air gap must hold against root)"
[[ "${AIRLOCK_TEST_NIC:-1}" != 0 ]] || skip "no network card attached (run tests/run-qemu-tests.sh with --nic)"
for tool in ip nft python3 timeout; do
  command -v "$tool" >/dev/null 2>&1 || fail "'$tool' is missing from the image"
done

if [[ -z "$IFACE" ]]; then
  for path in /sys/class/net/*; do
    name="${path##*/}"
    [[ "$name" == lo || ! -e "$path/device" ]] && continue
    IFACE="$name"
    break
  done
fi
[[ -n "$IFACE" && -e "/sys/class/net/$IFACE" ]] \
  || skip "needs a virtual network card attached (QEMU -nic user); none found"

# ------------------------------------------------------------------ probes
# shellcheck disable=SC2317 # called through the PROBES array
probe_ping() { timeout 5 ping -n -c 1 -W 2 "$GATEWAY" >/dev/null 2>&1; }

# Raw DNS query over UDP: any reply at all means traffic got through.
# shellcheck disable=SC2317 # called through the PROBES array
probe_dns_direct() {
  timeout 6 python3 -I - "$DNS" "$NAME" <<'PY' >/dev/null 2>&1
import random, socket, struct, sys
server, name = sys.argv[1], sys.argv[2]
qid = random.randrange(65536)
q = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)
q += b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0"
q += struct.pack(">HH", 1, 1)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(4)
s.sendto(q, (server, 53))
data, _ = s.recvfrom(512)
sys.exit(0 if data[:2] == q[:2] else 1)
PY
}

# The system resolver (resolved is masked, so this should fail at once).
# shellcheck disable=SC2317 # called through the PROBES array
probe_dns_system() { timeout 6 getent hosts "$NAME" >/dev/null 2>&1; }

# TCP connect and an HTTP request: success only if an HTTP status line comes back.
# shellcheck disable=SC2317 # called through the PROBES array
probe_http() {
  timeout 6 python3 -I - "$HTTP_HOST" "$HTTP_PORT" <<'PY' >/dev/null 2>&1
import socket, sys
s = socket.create_connection((sys.argv[1], int(sys.argv[2])), timeout=4)
s.sendall(b"HEAD / HTTP/1.0\r\nHost: airlock-test\r\n\r\n")
sys.exit(0 if s.recv(16).startswith(b"HTTP/") else 1)
PY
}

PROBES=(probe_ping probe_dns_direct probe_dns_system probe_http)

# run_probes LABEL: prints one line per probe; sets REACHED to the number that got through.
REACHED=0
run_probes() {
  local label="$1" probe
  REACHED=0
  for probe in "${PROBES[@]}"; do
    if "$probe"; then
      echo "  $label: ${probe#probe_} REACHED the network"
      REACHED=$((REACHED + 1))
    else
      echo "  $label: ${probe#probe_} blocked"
    fi
  done
}

# ------------------------------------------------------------------ restore on exit
FLUSHED=0
restore() {
  if ((FLUSHED)); then
    nft -f /etc/nftables.conf 2>/dev/null || systemctl restart nftables.service 2>/dev/null || true
  fi
  ip route del default via "$GATEWAY" dev "$IFACE" 2>/dev/null || true
  ip addr del "$ADDR" dev "$IFACE" 2>/dev/null || true
  ip link set dev "$IFACE" down 2>/dev/null || true
}
trap restore EXIT

bring_up() {
  ip link set dev "$IFACE" up
  ip addr add "$ADDR" dev "$IFACE" 2>/dev/null || true
  ip route replace default via "$GATEWAY" dev "$IFACE"
  sleep 2 # let the link come up
}

echo "air-gap test on interface $IFACE (gateway $GATEWAY, DNS $DNS, HTTP $HTTP_HOST:$HTTP_PORT)"

# ------------------------------------------------------------------ phase 1: as shipped
state="$(ip -br link show dev "$IFACE" | awk '{print $2}')"
[[ "$state" == DOWN ]] || fail "$IFACE is $state at boot; every interface must be down (task 3.6)"
if ip route show default | grep -q .; then fail "a default route exists at boot (task 3.5)"; fi
nft list ruleset | grep -q 'hook output priority filter; policy drop;' \
  || fail "the drop-all firewall is not loaded (task 3.7)"
echo "phase 1: as shipped"
run_probes "as shipped"
((REACHED == 0)) || fail "$REACHED probe(s) reached the network with the system as shipped"

# ------------------------------------------------------------------ phase 2: root tries
echo "phase 2: root brings $IFACE up with $ADDR and a default route"
bring_up
run_probes "interface up"
((REACHED == 0)) || fail "$REACHED probe(s) reached the network after root raised the interface; the firewall did not hold"
restore

# ------------------------------------------------------------------ positive control
if ((POSITIVE)); then
  echo "positive control: firewall flushed for a moment"
  FLUSHED=1
  nft flush ruleset
  bring_up
  run_probes "no firewall"
  restore
  FLUSHED=0
  nft list ruleset | grep -q 'hook output priority filter; policy drop;' \
    || fail "the firewall did not come back after the positive control"
  if ((REACHED == 0)); then
    fail "no probe reached the network even with the firewall off, so the air-gap result proves nothing; check the QEMU network card setup"
  fi
  echo "positive control: $REACHED probe(s) succeeded without the firewall, so the probes work"
fi

echo "pass: DNS, HTTP, and ping all fail from root, with the interface down and up"
exit 0
