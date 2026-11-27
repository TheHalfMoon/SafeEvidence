# Plan Amendment `plan-v1.2` (2026-11-05)

Amends TA-03 and `plan-v1.1` A4 by pointer. Frozen artifacts and digests are unchanged.

## Founder decision

Question: "Does the weaker Windows form count as passing TA-03?"
Answer, selected in the Claude Code session: "Accept for now".

## Effect

On hosted Windows only, TA-03's "network disabled after fetch" is met by outbound firewall blocks on named
programs: the Cargo and Rust tools, the probe, and every compiled test binary, as run by
`tools/ci/ta03_isolated.sh`. Linux and macOS still need full OS-level denial.

## Known gap

On Windows, the build and its build scripts run before the block, and programs not listed are not blocked. A
Windows-only build script could reach the network without this check detecting it. Default-deny outbound
is not available as an alternative: it lost the hosted runner at commit `deaf128`.

## Limits

- This acceptance is temporary. It must be revisited before any release (M6), with full isolation or a new decision.
- It accepts the form of the check only. TA-03 passes only when the script's controls pass in CI on all three OSes on
  the exact commit.
- It closes no other gate.
