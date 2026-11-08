"""Summarises `windows_socket_poll.ps1` output: the sockets the desktop app and its WebView2 processes held.

Evidence for VS-1a's no-socket capture (`plan-v1.1` section C). It reports and does not fail, except when
the poller never saw the app. Usage: python tools/ci/windows_socket_report.py <poll output> [port a known listener holds | webview2]
"""
import collections
import ipaddress
import sys

UNSPECIFIED = ("0.0.0.0", "::")


def is_loopback(address):
    """Parses the address; an unparsable one counts as outside loopback, so it is shown, not hidden."""
    try:
        parsed = ipaddress.ip_address(address.split("%")[0])
    except ValueError:
        return False
    if parsed.version == 6 and parsed.ipv4_mapped is not None:
        parsed = parsed.ipv4_mapped
    return parsed.is_loopback


def kind(local, remote, state):
    if state == "Listen":
        where = "loopback" if is_loopback(local) else "NOT LOOPBACK"
        return f"LISTENING {where}"
    if state == "Bound":
        where = "loopback" if is_loopback(local) else "NOT LOOPBACK"
        return f"udp bound {where}"
    if remote in UNSPECIFIED or not remote:
        return "unconnected"
    return "loopback" if is_loopback(remote) else "NOT LOOPBACK"


samples = 0
parsed_rows = 0
seen = collections.Counter()
trees = collections.Counter()
outside_endpoints = collections.Counter()
for line in open(sys.argv[1], encoding="utf-8-sig", errors="replace"):
    parts = line.strip().split("|")
    if parts[0] == "tree":
        trees[parts[1]] += 1
        continue
    if parts[0] == "parsed":
        parsed_rows += int(parts[1])
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
    if kind(local, remote, state).endswith("NOT LOOPBACK"):
        outside_endpoints[(name, proto, local if state in ("Listen", "Bound") else remote, port, state)] += 1

if samples == 0:
    sys.exit("the poller never saw the app")
if parsed_rows == 0:
    sys.exit("the poller parsed no socket rows at all, so this capture cannot be trusted")
print(f"Samples with the app running: {samples}. Sockets seen, counted per sample:")
for (name, proto, where, port, state), count in sorted(seen.items()):
    print(f"  {count:5d}  {where:28s} {proto} port {port:6s} {state:12s} {name}")
outside = sum(c for k, c in seen.items() if k[2].endswith("NOT LOOPBACK"))
listening = sum(c for k, c in seen.items() if k[2].startswith("LISTENING"))
print(f"Not loopback: {outside}. Listening: {listening}.")
print("Processes counted as the app, by sample:", dict(trees))
print(f"Socket rows parsed system-wide, all samples: {parsed_rows}.")
print("Endpoints outside loopback (remote address, or local address for a listening or bound socket):")
for (name, proto, host, port, state), count in sorted(outside_endpoints.items()):
    print(f"  {count:5d}  {proto} {host} port {port} {state} {name}")
# A control: a socket the run is known to hold must be seen, or a poller that sees nothing would pass.
expected = sys.argv[2] if len(sys.argv) > 2 else None
# A build without a debugging port has no known listener. Then the control is weaker: WebView2's processes
# must have been seen in the app's tree, so the poller at least walked the processes that hold sockets.
if expected == "webview2":
    if not any("msedgewebview2.exe" in names.split(",") for names in trees):
        sys.exit("the poller never saw WebView2 in the app's process tree, so this capture cannot be trusted")
elif expected and not any(k[3] == expected and k[4] == "Listen" for k in seen):
    sys.exit(f"the poller never saw the known listener on port {expected}, so this capture cannot be trusted")
