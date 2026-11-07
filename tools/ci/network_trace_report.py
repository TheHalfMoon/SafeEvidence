"""Lists the internet-family socket calls, and resolver-socket connects, in an `strace -ff` trace.

Evidence for VS-1a's no-socket capture (`plan-v1.1` section C). It reports and does not fail, except
when no trace was written. Usage: python3 tools/ci/network_trace_report.py <trace directory>
"""
import collections, glob, re, sys
files = sorted(glob.glob(sys.argv[1] + "/trace.*"))
if not files:
    sys.exit("no trace was written")
# Only the address fields decide loopback, never a quoted payload.
address = re.compile(r'inet_addr\("([^"]+)"\)|inet_pton\(AF_INET6, "([^"]+)"')
def is_loopback(host):
    return host.startswith("127.") or host == "::1" or host.startswith("::ffff:127.")
resolvers = ("/run/systemd/resolve/", "/var/run/nscd/", "/run/nscd/", "/run/avahi-daemon/", "/var/run/avahi-daemon/")
starts, calls, lines = collections.Counter(), collections.Counter(), []
for path in files:
    program = "unknown"
    for line in open(path, encoding="utf-8", errors="replace"):
        line = line.strip()
        if line.startswith("execve(") and line.endswith("= 0"):
            program = line.split('"')[1]
            starts[program] += 1
            continue
        call = line.split("(")[0]
        if call == "connect" and "AF_UNIX" in line and any(r in line for r in resolvers):
            calls[(program, call, "NAME LOOKUP through a resolver socket")] += 1
            lines.append(line)
            continue
        if "AF_INET" not in line or call == "socket":
            continue
        hosts = [h for pair in address.findall(line) for h in pair if h]
        port = re.search(r"htons\((\d+)\)", line)
        where = "loopback" if hosts and all(is_loopback(h) for h in hosts) else "NOT LOOPBACK"
        where += f" port {port.group(1)}" if port else ""
        if port and port.group(1) == "53":
            where += " (NAME LOOKUP)"
        if call in ("bind", "listen", "accept", "accept4"):
            where = "LISTENING " + where
        calls[(program, call, where)] += 1
        lines.append(line)
print("Starts by program:")
for program, count in sorted(starts.items()):
    print(f"  {count:3d}  {program}")
print("Internet-family calls, and resolver-socket connects, by program:")
for (program, call, where), count in sorted(calls.items()):
    print(f"  {count:5d}  {where:45s} {call:8s} {program}")
def total(word):
    return sum(c for (_, _, w), c in calls.items() if word in w)
print(f"Not loopback: {total('NOT LOOPBACK')}. Name lookups: {total('NAME LOOKUP')}. Listening: {total('LISTENING')}.")
print("Every reported call, as traced:")
for line in lines:
    print("  " + line[:300])
