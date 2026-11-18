#!/usr/bin/env node
/**
 * Capture a browser page via Chrome DevTools Protocol.
 *
 * Usage: capture_browser.mjs <dest-png> [--port PORT] [--url URL] [--index N]
 *
 * Connects to an already-running Chrome/Chromium with --remote-debugging-port.
 * No --enable-automation flag is involved: the automation banner never appears.
 * The page is identified by URL substring (--url) or by target index (--index).
 * Without either, the first (most recent) page is used.
 */
import { writeFileSync } from "node:fs";

const args = process.argv.slice(2);
const dest = args[0];
if (!dest) { console.error("usage: capture_browser.mjs <dest.png> [--port N] [--url U] [--index I]"); process.exit(1); }

let port = 9222, urlMatch = "", pageIndex = -1;
for (let i = 1; i < args.length; i += 2) {
  if (args[i] === "--port") port = Number(args[i + 1]);
  else if (args[i] === "--url") urlMatch = args[i + 1];
  else if (args[i] === "--index") pageIndex = Number(args[i + 1]);
}

const targets = await fetch(`http://127.0.0.1:${port}/json`).then((r) => r.json());
const pages = targets.filter((t) => t.type === "page");
if (!pages.length) { console.error("no pages open"); process.exit(1); }

let target;
if (urlMatch) {
  target = pages.find((p) => p.url.includes(urlMatch));
  if (!target) { console.error(`no page matching "${urlMatch}"`); process.exit(1); }
} else if (pageIndex >= 0) {
  target = pages[pageIndex];
  if (!target) { console.error(`no page at index ${pageIndex}`); process.exit(1); }
} else {
  target = pages[0];
}

const wsUrl = target.webSocketDebuggerUrl;
if (!wsUrl) { console.error("no WebSocket debugger URL for the target"); process.exit(1); }

const screenshot = await new Promise((resolve, reject) => {
  const ws = new WebSocket(wsUrl);
  const timer = setTimeout(() => { ws.close(); reject(new Error("CDP timeout")); }, 15000);
  ws.onopen = () => {
    ws.send(JSON.stringify({ id: 1, method: "Page.captureScreenshot", params: { format: "png" } }));
  };
  ws.onmessage = (event) => {
    clearTimeout(timer);
    const msg = JSON.parse(typeof event.data === "string" ? event.data : event.data.toString());
    if (msg.id === 1 && msg.result?.data) {
      ws.close();
      resolve(msg.result.data);
    } else if (msg.error) {
      ws.close();
      reject(new Error(msg.error.message));
    }
  };
  ws.onerror = (err) => { clearTimeout(timer); reject(err); };
});

writeFileSync(dest, Buffer.from(screenshot, "base64"));
const info = JSON.stringify({ url: target.url, title: target.title, bytes: Buffer.from(screenshot, "base64").length });
process.stdout.write(info);
