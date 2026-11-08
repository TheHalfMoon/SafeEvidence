// Listens on loopback port 80 and records what connects and what bytes arrive. Windows CI only. It uses no packages.
//
// WebView2 holds a loopback connection to port 80 while the app runs. The app's pages load from
// http://tauri.localhost, which WebView2 serves inside the app, so the open question is whether any bytes cross that
// connection. CI stops the kernel HTTP service first, so this listener owns the port. It answers nothing. For each
// connection it records the peer, when it opened and closed, the byte count and the first bytes, escaped. Connections
// still open when the stop file appears are recorded as open. It runs until the stop file exists.
//
// Usage: node e2e/port80_listener.mjs <report file> <stop file> [port, 80 by default]
import { existsSync, writeFileSync } from "node:fs";
import net from "node:net";

const HEAD_BYTES = 300;
const [reportPath, stopPath, portText = "80"] = process.argv.slice(2);
const port = Number(portText);
const started = Date.now();
const seconds = () => ((Date.now() - started) / 1000).toFixed(1);
const records = [];

function listen(host) {
  const server = net.createServer((socket) => {
    const record = { peer: socket.remoteAddress, opened: seconds(), closed: "open", bytes: 0, head: Buffer.alloc(0) };
    records.push(record);
    socket.on("data", (chunk) => {
      record.bytes += chunk.length;
      if (record.head.length < HEAD_BYTES) {
        record.head = Buffer.concat([record.head, chunk]).subarray(0, HEAD_BYTES);
      }
    });
    socket.on("error", () => {});
    socket.on("close", () => {
      record.closed = `${seconds()}s`;
    });
  });
  // A port it cannot take ends the run, so a listener that never listened cannot report a quiet port.
  server.on("error", (error) => {
    console.error(`cannot listen on ${host} port ${port}: ${error.message}`);
    process.exit(1);
  });
  server.listen({ host, port, ipv6Only: host === "::1" });
}

listen("127.0.0.1");
listen("::1");
const timer = setInterval(() => {
  if (!existsSync(stopPath)) return;
  clearInterval(timer);
  const lines = [`connections|${records.length}`];
  for (const r of records) {
    const head = JSON.stringify(r.head.toString("latin1"));
    lines.push(`connection|${r.peer}|opened ${r.opened}s|closed ${r.closed}|${r.bytes}|${head}`);
  }
  writeFileSync(reportPath, lines.join("\n") + "\n");
  process.exit(0);
}, 200);
