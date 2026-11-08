"""Summarises `windows_socket_poll.ps1` output: the sockets the desktop app and its WebView2 processes held.

Evidence for VS-1a's no-socket capture (`plan-v1.1` section C). It reports and does not fail, except when
the poller never saw the app. Usage: python tools/ci/windows_socket_report.py <poll output> [port a known listener holds]
"""
import collections
import sys

LOOPBACK = ("127.", "::1", "::ffff:127.")
UNSPECIFIED = ("0.0.0.0", "::")


def kind(local, remote, state):
    if state == "Listen":
        where = "loopback" if local.startswith(LOOPBACK) else "NOT LOOPBACK"
        return f"LISTENING {where}"
    if state == "Bound":
        where = "loopback" if local.startswith(LOOPBACK) else "NOT LOOPBACK"
        return f"udp bound {where}"
    if remote in UNSPECIFIED or not remote:
        return "unconnected"
    return "loopback" if remote.startswith(LOOPBACK) else "NOT LOOPBACK"


samples = 0
seen = collections.Counter()
trees = collections.Counter()
for line in open(sys.argv[1], encoding="utf-8-sig", errors="replace"):
    parts = line.strip().split("|")
    if parts[0] == "tree":
        trees[parts[1]] += 1
        continue
    if parts[0] == "samples":
        samples = int(parts[1])
        continue
    if len(parts) != 7:
        continue
    proto, name, local, local_port, remote, remote_port, state = parts
    # A listening or bound socket has no peer: netstat shows its remote end as 0.0.0.0:0.
    port = local_port if state in ("Listen", "Bound") else remote_port
    seen[(name, proto, kind(local, remote, state), port, state)] += 1

if samples == 0:
    sys.exit("the poller never saw the app")
print(f"Samples with the app running: {samples}. Sockets seen, counted per sample:")
for (name, proto, where, port, state), count in sorted(seen.items()):
    print(f"  {count:5d}  {where:28s} {proto} port {port:6s} {state:12s} {name}")
outside = sum(c for k, c in seen.items() if k[2].endswith("NOT LOOPBACK"))
listening = sum(c for k, c in seen.items() if k[2].startswith("LISTENING"))
print(f"Not loopback: {outside}. Listening: {listening}.")
print("Processes counted as the app, by sample:", dict(trees))
# A control: a socket the run is known to hold must be seen, or a poller that sees nothing would pass.
expected = sys.argv[2] if len(sys.argv) > 2 else None
if expected and not any(k[3] == expected and k[4] == "Listen" for k in seen):
    sys.exit(f"the poller never saw the known listener on port {expected}, so this capture cannot be trusted")
