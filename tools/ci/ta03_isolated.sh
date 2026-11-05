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
    restore() {
      powershell.exe -NoProfile -Command \
        "Set-NetFirewallProfile -All -DefaultOutboundAction Allow; Get-NetFirewallRule -DisplayName 'SafeEvidenceTA03' -ErrorAction SilentlyContinue | Remove-NetFirewallRule" || true
    }
    trap restore EXIT
    # Default-deny outbound, excepting only the hosted runner's own processes.
    powershell.exe -NoProfile -Command '
      $ErrorActionPreference = "Stop"
      $paths = Get-Process -Name "Runner.*","provjobd*" -ErrorAction SilentlyContinue | ForEach-Object { $_.Path } | Where-Object { $_ } | Sort-Object -Unique
      if (-not $paths) { throw "no runner process found" }
      foreach ($path in $paths) {
        Write-Output "TA-03 allow outbound: $path"
        New-NetFirewallRule -DisplayName "SafeEvidenceTA03" -Direction Outbound -Action Allow -Program $path | Out-Null
      }
      Set-NetFirewallProfile -All -DefaultOutboundAction Block
    '
    bash -c "$inner"
    ;;
  *)
    echo "TA-03 FAIL: unsupported runner OS '${RUNNER_OS:-}'" >&2
    exit 1
    ;;
esac
echo "TA-03 isolated run complete on ${RUNNER_OS}"
