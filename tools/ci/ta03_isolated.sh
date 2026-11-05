#!/usr/bin/env bash
# TA-03: format, test, lint and license checks with OS-level network denial after fetch.
# Run from product/ on a hosted runner. A negative control must prove the denial, and a
# positive control first proves the probe can reach the network, so neither passes vacuously.
set -euo pipefail

PROBE_URL="https://github.com"

inner='set -euo pipefail
if curl -sS -m 10 -o /dev/null "'"$PROBE_URL"'" 2>/dev/null; then
  echo "TA-03 FAIL: network reachable inside isolation" >&2
  exit 1
fi
echo "TA-03 negative control: network denied"
cargo fmt --all -- --check
cargo test --offline --locked --workspace --all-targets
cargo clippy --offline --locked --workspace --all-targets -- -D warnings
cargo deny --offline check'

curl -sS -m 30 -o /dev/null "$PROBE_URL"
echo "TA-03 positive control: network reachable before isolation"

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
    rm -f ta03_programs.txt
    ;;
  *)
    echo "TA-03 FAIL: unsupported runner OS '${RUNNER_OS:-}'" >&2
    exit 1
    ;;
esac
echo "TA-03 isolated run complete on ${RUNNER_OS}"
