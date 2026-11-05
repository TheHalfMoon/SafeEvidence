#!/usr/bin/env bash
# TA-03: format, test, lint and license checks with OS-level network denial after fetch.
# Run from product/ on a hosted runner. Positive controls first prove the probes can reach the
# network. Inside isolation, probes must fail with a connection-level exit code, and the test
# `ta03_network_denied` must fail to open a socket from a test binary.
set -euo pipefail

PROBE_HOST="https://github.com"
PROBE_IP="https://1.1.1.1"
command -v curl >/dev/null

inner='set -euo pipefail
export SAFEEVIDENCE_TA03_ISOLATED=1
for url in "'"$PROBE_HOST"'" "'"$PROBE_IP"'"; do
  code=0
  curl -sS -m 10 -o /dev/null "$url" || code=$?
  echo "TA-03 negative control: $url exit $code"
  # 6 name resolution, 7 connect refused or blocked, 28 timeout. Anything else proves nothing.
  case "$code" in
    6|7|28) ;;
    *) echo "TA-03 FAIL: unexpected probe result for $url" >&2; exit 1 ;;
  esac
done
cargo fmt --all -- --check
cargo test --offline --locked --workspace --all-targets
cargo test --offline --locked --workspace --test ta03_network_denied -- --nocapture
cargo clippy --offline --locked --workspace --all-targets -- -D warnings
cargo deny --offline check'

curl -sS -m 30 -o /dev/null "$PROBE_HOST"
curl -sS -m 30 -o /dev/null "$PROBE_IP"
echo "TA-03 positive control: both probes reachable before isolation"

case "${RUNNER_OS:-}" in
  Linux)
    # A new empty network namespace has no route to anything.
    sudo unshare -n -- sudo -E -u "$(id -un)" env "PATH=$PATH" "HOME=$HOME" bash -c "$inner"
    ;;
  macOS)
    sandbox-exec -p '(version 1)(allow default)(deny network-outbound (remote ip))' bash -c "$inner"
    ;;
  Windows)
    # WEAKER than Linux and macOS. Default-deny outbound kills the hosted runner, so this
    # blocks named programs only. The build and its build scripts run before the block,
    # and any program not listed here is not blocked.
    restore() {
      powershell.exe -NoProfile -Command \
        "Get-NetFirewallRule -DisplayName 'SafeEvidenceTA03' -ErrorAction SilentlyContinue | Remove-NetFirewallRule" || true
    }
    trap restore EXIT
    cargo clippy --offline --locked --workspace --all-targets -- -D warnings
    cargo test --offline --locked --workspace --all-targets --no-run --message-format=json \
      | python -c "import json,sys
for line in sys.stdin:
    try:
        exe = json.loads(line).get('executable')
    except ValueError:
        continue
    if exe:
        print(exe)" > ta03_programs.txt
    test -s ta03_programs.txt
    for tool in curl cargo rustc clippy-driver cargo-clippy cargo-fmt rustfmt cargo-deny; do
      found="$(rustup which "$tool" 2>/dev/null || command -v "$tool")"
      cygpath -w "$found" >> ta03_programs.txt
      if [ "$tool" = cargo ]; then cygpath -w "$(command -v cargo)" >> ta03_programs.txt; fi
    done
    export TA03_PROGRAMS="$(cygpath -w "$PWD/ta03_programs.txt")"
    powershell.exe -NoProfile -Command '
      $ErrorActionPreference = "Stop"
      $paths = Get-Content $env:TA03_PROGRAMS | Where-Object { $_ } | Sort-Object -Unique
      foreach ($path in $paths) {
        Write-Output "TA-03 block outbound: $path"
        New-NetFirewallRule -DisplayName "SafeEvidenceTA03" -Direction Outbound -Action Block -Program $path | Out-Null
      }
    '
    bash -c "$inner"
    # Anything rebuilt after the block would have run unblocked, so refuse that.
    cargo test --offline --locked --workspace --all-targets --no-run --message-format=json \
      | python -c "import json,sys
for line in sys.stdin:
    try:
        exe = json.loads(line).get('executable')
    except ValueError:
        continue
    if exe:
        print(exe)" > ta03_after.txt
    python -c "import sys
blocked = set(open('ta03_programs.txt').read().split(chr(10)))
ran = [x for x in open('ta03_after.txt').read().split(chr(10)) if x]
missing = [x for x in ran if x not in blocked]
print('TA-03 test binaries ran blocked:', len(ran))
sys.exit('TA-03 FAIL: unblocked binaries: %s' % missing if missing else 0)"
    rm -f ta03_programs.txt ta03_after.txt
    ;;
  *)
    echo "TA-03 FAIL: unsupported runner OS '${RUNNER_OS:-}'" >&2
    exit 1
    ;;
esac
echo "TA-03 isolated run complete on ${RUNNER_OS}"
