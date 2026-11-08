// Listens on loopback port 80 and records what connects and what bytes arrive. Windows CI only. It uses no packages.
//
// WebView2 holds a loopback connection to port 80 while the app runs. The app's pages load from
// http://tauri.localhost, which WebView2 serves inside the app, so the open question is whether any bytes cross that
// connection. CI stops the kernel HTTP service first, so this listener owns the port. It answers nothing, and records
// each connection's byte count and its first bytes, escaped. It runs until the stop file exists.
//
// Usage: node e2e/port80_listener.mjs <report file> <stop file> [port, 80 by default]
import { existsSync, writeFileSync } from "node:fs";
import net from "node:net";

const [reportPath, stopPath, portText = "80"] = process.argv.slice(2);
const port = Number(portText);
const records = [];
const servers = [];

function listen(host) {
  const server = net.createServer((socket) => {
    const chunks = [];
    const peer = socket.remoteAddress;
    socket.on("data", (chunk) => chunks.push(chunk));
    socket.on("error", () => {});
    socket.on("close", () => {
      const received = Buffer.concat(chunks);
      const head = JSON.stringify(received.subarray(0, 300).toString("latin1"));
      records.push({ peer, bytes: received.length, head });
    });
  });
  server.listen({ host, port, ipv6Only: host === "::1" });
  servers.push(server);
}

listen("127.0.0.1");
listen("::1");
const timer = setInterval(() => {
  if (!existsSync(stopPath)) return;
  clearInterval(timer);
  for (const server of servers) server.close();
  // CI closes the app before the stop file, so its connections have closed and been recorded by now.
  setTimeout(() => {
    const lines = [`connections|${records.length}`, ...records.map((r) => `connection|${r.peer}|${r.bytes}|${r.head}`)];
    writeFileSync(reportPath, lines.join("\n") + "\n");
    process.exit(0);
  }, 2000);
}, 200);
