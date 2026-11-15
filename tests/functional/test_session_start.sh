#!/usr/bin/env bash
# Tasks 4.10, 4.11, 4.15, 4F.6, 2B.14, 4C.22 (session half), surviving risk 14:
# forensic-session-start makes a new session log and records authority, clock check (offset
# logged, clock never changed), write-blocker answer, kernel, tool versions, lsblk, read-only
# flags, radios, network, image age (warning past the limit), and the ASSETS check.
# Runs anywhere: fake sysfs/procfs trees, a fake lsblk tree, and stub hwclock/timedatectl.
# shellcheck source=tests/functional/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

require_cmd python3
export AIRLOCK_PYLIB="$PYLIB"
export AIRLOCK_RUN_DIR="$TEST_TMP/run"
CMD="$BIN_DIR/forensic-session-start"
SESS="$AIRLOCK_SESSION_DIR"

# ---------------------------------------------------------------- fakes
FS="$TEST_TMP/sys"
export AIRLOCK_SYSFS="$FS"
export AIRLOCK_PROCFS="$TEST_TMP/proc"
mkdir -p "$FS/class/rtc/rtc0" "$FS/class/rfkill/rfkill0" "$FS/class/net/lo" "$FS/class/net/enp1s0" \
  "$AIRLOCK_PROCFS/net"
for name in sda sda1 sdb sdb1; do mkdir -p "$FS/class/block/$name"; done
echo 0 >"$FS/class/block/sda/ro"
echo 0 >"$FS/class/block/sda1/ro"
echo 1 >"$FS/class/block/sdb/ro"
echo 1 >"$FS/class/block/sdb1/ro"
printf '2026-11-15\n' >"$FS/class/rtc/rtc0/date"
printf '09:00:00\n' >"$FS/class/rtc/rtc0/time"
printf 'wlan\n' >"$FS/class/rfkill/rfkill0/type"
printf 'phy0\n' >"$FS/class/rfkill/rfkill0/name"
echo 1 >"$FS/class/rfkill/rfkill0/soft"
echo 0 >"$FS/class/rfkill/rfkill0/hard"
printf '0x9\n' >"$FS/class/net/lo/flags"
printf 'unknown\n' >"$FS/class/net/lo/operstate"
printf '0x1002\n' >"$FS/class/net/enp1s0/flags"
printf 'down\n' >"$FS/class/net/enp1s0/operstate"
printf 'Iface\tDestination\tGateway\n' >"$AIRLOCK_PROCFS/net/route"
: >"$AIRLOCK_PROCFS/net/ipv6_route"
printf 'BOOT_IMAGE=/vmlinuz noresume systemd.gpt_auto=0\n' >"$AIRLOCK_PROCFS/cmdline"
cat >"$TEST_TMP/lsblk.json" <<'JSON'
{"blockdevices": [
  {"name": "sda", "path": "/dev/sda", "type": "disk", "size": 64000000000, "ro": false, "rm": true,
   "model": "AIRLOCK STICK", "children": [
     {"name": "sda1", "path": "/dev/sda1", "type": "part", "size": 1000, "ro": false, "rm": true,
      "mountpoints": ["/"]}]},
  {"name": "sdb", "path": "/dev/sdb", "type": "disk", "size": 500000000000, "ro": true, "rm": false,
   "model": "Evidence", "serial": "EV1", "children": [
     {"name": "sdb1", "path": "/dev/sdb1", "type": "part", "size": 2000, "ro": true, "rm": false}]}
]}
JSON
export AIRLOCK_LSBLK_JSON="$TEST_TMP/lsblk.json"

CLOCK_CALLS="$TEST_TMP/clock.calls"
: >"$CLOCK_CALLS"
stub hwclock "
printf 'hwclock %s\n' \"\$*\" >>'$CLOCK_CALLS'
case \" \$* \" in
  *' --show '*) python3 -c 'import datetime as d, os; print((d.datetime.now(d.UTC) + d.timedelta(seconds=int(os.environ.get(\"HW_SKEW\", \"0\")))).isoformat(sep=\" \"))' ;;
  *) exit 3 ;;
esac"
stub timedatectl "printf 'timedatectl %s\n' \"\$*\" >>'$CLOCK_CALLS'"
stub date "printf 'date %s\n' \"\$*\" >>'$CLOCK_CALLS'"

today="$(python3 -c 'import datetime as d; print(d.datetime.now(d.UTC).strftime("%Y-%m-%dT00:00:00Z"))')"
old="$(python3 -c 'import datetime as d; print((d.datetime.now(d.UTC)-d.timedelta(days=200)).strftime("%Y-%m-%dT%H:%M:%SZ"))')"
printf '{"build_date": "%s", "version": "0.1.0", "git_commit": "abc123", "schema": 1}\n' "$today" \
  >"$AIRLOCK_ETC_DIR/build-info.json"

events() { python3 -c 'import json,sys; print(" ".join(json.loads(l)["event"] for l in open(sys.argv[1])))' "$1"; }
field() { # field LOG EVENT EXPR  -> python expression over the record d
  python3 - "$1" "$2" "$3" <<'PY'
import json, sys
path, event, expr = sys.argv[1:4]
recs = [json.loads(l) for l in open(path, encoding="utf-8")]
d = [r for r in recs if r["event"] == event][-1]
print(eval(expr, {"d": d}))  # noqa: S307 -- test helper, expression from this script
PY
}

# ---------------------------------------------------------------- authority is required
run "$CMD" --yes </dev/null
assert_eq "$RC" 1 "--yes without --authority-ack stops"
assert_contains "$OUT" "--authority-ack" "says which flag to pass"
LOG1="$(readlink -f "$SESS/current.log")"
assert_contains "$(events "$LOG1")" "session_start authority_missing" "authority_missing logged first"
assert_not_contains "$(events "$LOG1")" "session_ready" "no session_ready without authority"

# ---------------------------------------------------------------- full non-interactive run
sleep 1 # new session file name (one per second)
REF="$(python3 -c 'import datetime as d; print((d.datetime.now(d.UTC)+d.timedelta(seconds=20)).strftime("%Y-%m-%dT%H:%M:%SZ"))')"
run "$CMD" --authority-ack --reference-time "$REF" --reference-source "radio clock" \
  --write-blocker yes --blocker-model "Example UltraBlock" --yes </dev/null
assert_eq "$RC" 0 "session start: $OUT"
LOG2="$(readlink -f "$SESS/current.log")"
assert_ne "$LOG2" "$LOG1" "a new session file each run"
[[ "$(basename -- "$LOG2")" =~ ^[0-9]{8}T[0-9]{6}Z(-[0-9]+)?\.log$ ]] || fail "session file name: $LOG2"
ev="$(events "$LOG2")"
for e in session_start authority_ack clock_check write_blocker kernel tool_versions lsblk \
  readonly_flags rfkill network_state image_age session_ready; do
  assert_contains " $ev " " $e " "event $e logged"
done
[[ " $ev " =~ \ asset_check(_unavailable|_failed)?\  ]] || fail "asset check result logged: $ev"
assert_eq "${ev%% *}" session_start "session_start is the first line"
assert_eq "$(field "$LOG2" authority_ack 'd["via"]')" flag "authority via flag"
assert_eq "$(field "$LOG2" clock_check 'd["status"], d["reference_source"], d["system_time_changed"]')" \
  "('reference_entered', 'radio clock', False)" "clock check record"
assert_eq "$(field "$LOG2" clock_check 'd["hardware_clock"]["source"], abs(d["hardware_minus_system_seconds"]) < 5')" \
  "('hwclock', True)" "hardware clock read with hwclock"
off="$(field "$LOG2" clock_check 'abs(d["offset_seconds"] - (__import__("airlock_common.timeutil").timeutil.parse_iso(d["reference_time"]) - __import__("airlock_common.timeutil").timeutil.parse_iso(d["system_utc_at_entry"])).total_seconds()) < 0.01')"
assert_eq "$off" True "offset = reference - system time at entry"
assert_eq "$(field "$LOG2" write_blocker 'd["answer"], d["model"], d["via"]')" \
  "('yes', 'Example UltraBlock', 'flag')" "write blocker answer"
assert_eq "$(field "$LOG2" readonly_flags 'd["boot_disk"], d["writable_unexpected"]')" "('/dev/sda', [])" "read-only flags"
assert_eq "$(field "$LOG2" readonly_flags '[(x["name"], x["readonly"]) for x in d["devices"]]')" \
  "[('sda', False), ('sda1', False), ('sdb', True), ('sdb1', True)]" "every disk and partition"
assert_eq "$(field "$LOG2" rfkill 'd["unblocked"]')" "[]" "radios blocked"
assert_eq "$(field "$LOG2" network_state 'd["ok"], d["up_besides_loopback"]')" "(True, [])" "network off"
assert_eq "$(field "$LOG2" image_age 'd["status"], d["age_days"], d["max_age_days"]')" "('ok', 0, 90)" "image age"
assert_eq "$(field "$LOG2" kernel 'd["cmdline"]')" "BOOT_IMAGE=/vmlinuz noresume systemd.gpt_auto=0" "kernel cmdline"
assert_eq "$(field "$LOG2" tool_versions '"python3" in d["commands"] and d["commands"]["python3"]["status"]')" present "python3 version logged"
assert_contains "$(field "$LOG2" tool_versions 'd["absent"]')" "llama-server" "missing tools logged as absent"
assert_contains "$OUT" "second layer" "advisory calls the software flag a second layer"
assert_contains "$OUT" "owner's permission or the legal authority" "authority text on screen"
for bad in "off by" "not blocked" "network interface" "days old" "is writable" "No hardware write blocker" "local time"; do
  assert_not_contains "$OUT" "$bad" "no '$bad' warning on a clean PC"
done

# A hardware clock a whole number of hours off suggests a local-time RTC (Windows PCs).
sleep 1
run env HW_SKEW=7200 "$CMD" --authority-ack --clock-ok --write-blocker yes --yes </dev/null
assert_eq "$RC" 0 "session start with a skewed hardware clock: $OUT"
assert_contains "$OUT" "local time" "local-time hardware clock warning"

# The clock is never set.
assert_eq "$(grep -v '^hwclock --show --utc$' "$CLOCK_CALLS" || true)" "" "only hwclock --show was run"

# ---------------------------------------------------------------- warnings
sleep 1
echo 0x1003 >"$FS/class/net/enp1s0/flags"
echo 0 >"$FS/class/rfkill/rfkill0/soft"
echo 0 >"$FS/class/block/sdb/ro"
printf '{"build_date": "%s", "version": "0.1.0"}\n' "$old" >"$AIRLOCK_ETC_DIR/build-info.json"
rm -f -- "$STUB_DIR/hwclock"
run "$CMD" --authority-ack --yes </dev/null
assert_eq "$RC" 0 "session start with problems still records: $OUT"
LOG3="$(readlink -f "$SESS/current.log")"
assert_contains "$OUT" "200 days old (limit 90)" "old image warning (4F.6)"
assert_contains "$OUT" "Reflash" "old image says what to do"
assert_contains "$OUT" "/dev/sdb is writable" "writable evidence drive warning"
assert_contains "$OUT" "A radio is not blocked" "radio warning"
assert_contains "$OUT" "network interface is up" "network warning"
assert_contains "$OUT" "clock was not checked" "unchecked clock warning"
assert_contains "$OUT" "No hardware write blocker recorded" "no blocker warning"
assert_eq "$(field "$LOG3" image_age 'd["status"], d["too_old"]')" "('too_old', True)" "image_age too_old"
assert_eq "$(field "$LOG3" clock_check 'd["status"], d["via"], d["offset_seconds"]')" "('not_checked', 'default', None)" "clock default"
assert_eq "$(field "$LOG3" clock_check 'd["hardware_clock"]["source"]')" sysfs "rtc read from sysfs without hwclock"
assert_eq "$(field "$LOG3" write_blocker 'd["answer"], d["via"]')" "('unknown', 'default')" "blocker default"
assert_eq "$(field "$LOG3" session_ready 'len(d["warnings"]) >= 6')" True "warnings logged in session_ready"

# A drive unlocked for output is not reported as unexpected.
sleep 1
mkdir -p "$AIRLOCK_RUN_DIR/rw-allow"
echo '{}' >"$AIRLOCK_RUN_DIR/rw-allow/sdb"
run "$CMD" --authority-ack --clock-ok --write-blocker no --yes </dev/null
assert_eq "$RC" 0 "session start with an unlocked output drive: $OUT"
assert_not_contains "$OUT" "/dev/sdb is writable" "unlocked output drive is expected"
LOG4="$(readlink -f "$SESS/current.log")"
assert_eq "$(field "$LOG4" clock_check 'd["status"], d["offset_seconds"]')" "('confirmed', 0.0)" "--clock-ok"

# ---------------------------------------------------------------- bad reference time
run "$CMD" --authority-ack --reference-time "2026-11-15 09:00" --yes </dev/null
assert_eq "$RC" 1 "reference time without a zone is refused"
assert_contains "$OUT" "Z at the end" "says how to write it"

# ---------------------------------------------------------------- the log folder is not writable
if command -v setpriv >/dev/null 2>&1 && [[ "$(id -u)" -eq 0 ]]; then
  chmod -R a+rX "$TEST_TMP"
  chmod 0755 "$SESS"
  run setpriv --reuid=65534 --regid=65534 --clear-groups "$CMD" --authority-ack --yes
  if [[ "$OUT" != *"Permission denied: '/home"* ]]; then
    assert_eq "$RC" 1 "unwritable session folder: $OUT"
    assert_contains "$OUT" "sudo" "says to use sudo"
  fi
fi

pass "forensic-session-start records state, asks with flags, never sets the clock, warns"
