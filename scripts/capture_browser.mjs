#!/usr/bin/env node
/**
 * Capture a browser page via Chrome DevTools Protocol, either by connecting to
 * a loopback CDP port or by launching an isolated temporary Chromium profile.
 *
 * Usage:
 *   capture_browser.mjs <dest-png> [--port PORT] [--url URL] [--index N]
 *   capture_browser.mjs <dest-png> --isolated --launch <url> [--timeout MS]
 *   capture_browser.mjs <dest-png> --isolated --url <url> [--timeout MS]
 *
 * Isolated mode uses a fresh temporary --user-data-dir under Xvfb (or
 * --headless=new when Xvfb is unavailable), suppresses the automation banner
 * via --test-type (never --no-sandbox), never connects to the operator's
 * personal Chrome profile, and tears down browser + profile in finally.
 */
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { spawn } from "node:child_process";
import { pathToFileURL } from "node:url";

const PNG_MAGIC = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
const LOOPBACK_HOSTS = new Set(["127.0.0.1", "localhost", "::1", "[::1]"]);

export function assertPlainPath(file) {
  const raw = String(file ?? "");
  if (!raw.trim()) throw new Error("Path must not be empty");
  const absolute = path.resolve(raw);
  const root = path.parse(absolute).root;
  let realRoot;
  try {
    realRoot = fs.realpathSync.native(root);
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
    realRoot = root;
  }
  const normalize = (s) =>
    process.platform === "win32"
      ? path.normalize(s).toLowerCase()
      : path.normalize(s);
  if (normalize(realRoot) !== normalize(root))
    throw new Error("Redirected harness paths are not allowed");
  let current = root;
  for (const segment of [
    "",
    ...path.relative(root, absolute).split(path.sep).filter(Boolean),
  ]) {
    if (segment) current = path.join(current, segment);
    const stat = fs.lstatSync(current, { throwIfNoEntry: false });
    if (!stat) continue;
    if (
      stat.isSymbolicLink() ||
      (!stat.isFile() && !stat.isDirectory()) ||
      (stat.isFile() && stat.nlink > 1)
    )
      throw new Error("Linked or special harness paths are not allowed");
    let real, parent;
    try {
      real = fs.realpathSync.native(current);
      parent = fs.realpathSync.native(path.dirname(current));
    } catch (error) {
      const code = error?.code;
      if (code === "ENOENT" || code === "EPERM" || code === "EACCES") continue;
      throw error;
    }
    const expected = path.join(parent, path.basename(current));
    const held = fs.lstatSync(expected, { throwIfNoEntry: false });
    const resolved = fs.lstatSync(real, { throwIfNoEntry: false });
    if (!held || !resolved) continue;
    if (held.isSymbolicLink() !== resolved.isSymbolicLink())
      throw new Error("Redirected harness paths are not allowed");
    if (
      !held.isSymbolicLink() &&
      (held.dev !== resolved.dev || held.ino !== resolved.ino)
    )
      throw new Error("Redirected harness paths are not allowed");
  }
}

export function validatePort(value) {
  const raw = String(value ?? "").trim();
  if (!/^\d+$/.test(raw))
    throw new Error(`Invalid CDP port: ${value}`);
  const port = Number(raw);
  if (!Number.isInteger(port) || port < 1 || port > 65535)
    throw new Error(`CDP port out of range (1..65535): ${value}`);
  return port;
}

export function validateLoopbackWsUrl(wsUrl) {
  let parsed;
  try {
    parsed = new URL(String(wsUrl ?? ""));
  } catch {
    throw new Error("Invalid WebSocket debugger URL");
  }
  if (parsed.protocol !== "ws:")
    throw new Error(`Unsupported WebSocket protocol: ${parsed.protocol}`);
  if (!LOOPBACK_HOSTS.has(parsed.hostname.toLowerCase()))
    throw new Error(`Refusing non-loopback CDP WebSocket host: ${parsed.hostname}`);
  return parsed.toString();
}

export function validateLaunchUrl(rawUrl) {
  const value = String(rawUrl ?? "").trim();
  if (!value) throw new Error("Launch URL is required for isolated mode");
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error(`Invalid launch URL: ${value}`);
  }
  if (!["http:", "https:", "data:", "about:"].includes(parsed.protocol))
    throw new Error(`Unsupported URL scheme for browser launch: ${parsed.protocol}`);
  return value;
}

export function parseArgs(args) {
  let dest = "";
  let port = 9222;
  let urlMatch = "";
  let pageIndex = -1;
  let isolated = false;
  let launchUrl = "";
  let timeoutMs = 20000;

  const needValue = (flag, idx) => {
    if (idx + 1 >= args.length)
      throw new Error(`Missing value for ${flag}`);
    return args[idx + 1];
  };

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === "--port") {
      port = validatePort(needValue(arg, i));
      i++;
    } else if (arg === "--url") {
      urlMatch = needValue(arg, i);
      i++;
    } else if (arg === "--index") {
      const rawIdx = needValue(arg, i).trim();
      if (!/^\d+$/.test(rawIdx))
        throw new Error(`Invalid page index: ${rawIdx}`);
      pageIndex = Number(rawIdx);
      i++;
    } else if (arg === "--isolated") {
      isolated = true;
    } else if (arg === "--launch") {
      isolated = true;
      launchUrl = needValue(arg, i);
      i++;
    } else if (arg === "--timeout") {
      const rawTimeout = needValue(arg, i).trim();
      const parsed = Number(rawTimeout);
      if (!Number.isInteger(parsed) || parsed < 1000 || parsed > 120000)
        throw new Error(`Invalid timeout (1000..120000 ms): ${rawTimeout}`);
      timeoutMs = parsed;
      i++;
    } else if (arg.startsWith("--")) {
      throw new Error(`Unknown option: ${arg}`);
    } else if (!dest) {
      dest = arg;
    } else {
      throw new Error(`Unexpected positional argument: ${arg}`);
    }
  }

  if (!dest)
    throw new Error(
      "usage: capture_browser.mjs <dest.png> [--port N] [--url U] [--index I] [--isolated] [--launch URL]",
    );
  assertPlainPath(dest);
  if (isolated && !launchUrl) launchUrl = urlMatch;
  if (isolated) launchUrl = validateLaunchUrl(launchUrl);
  return { dest, port, urlMatch, pageIndex, isolated, launchUrl, timeoutMs };
}

function findExecutable(candidates, names) {
  const isExe = (file) => {
    try {
      const stat = fs.statSync(file);
      if (!stat.isFile()) return false;
      return process.platform === "win32" || (stat.mode & 0o111) !== 0;
    } catch {
      return false;
    }
  };
  for (const candidate of candidates) {
    if (isExe(candidate)) return candidate;
  }
  const pathDirs = (process.env.PATH || "").split(path.delimiter).filter(Boolean);
  for (const dir of pathDirs) {
    for (const name of names) {
      const candidate = path.join(dir, name);
      if (isExe(candidate)) return candidate;
    }
  }
  return undefined;
}

async function fetchJson(url, timeoutMs = 5000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(url, { signal: controller.signal });
    if (!response.ok)
      throw new Error(`CDP HTTP ${response.status} from ${url}`);
    return await response.json();
  } finally {
    clearTimeout(timer);
  }
}

export function cdpScreenshot(wsUrl, timeoutMs = 15000, waitReady = false) {
  const safeWs = validateLoopbackWsUrl(wsUrl);
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(safeWs);
    let settled = false;
    let activeId = 1;
    let readyPollTimer;
    const finish = (err, data) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (readyPollTimer) clearTimeout(readyPollTimer);
      try {
        ws.close();
      } catch {}
      if (err) reject(err);
      else resolve(data);
    };
    const timer = setTimeout(
      () => finish(new Error("CDP timeout")),
      timeoutMs,
    );
    const sendCapture = () => {
      activeId = 2;
      ws.send(
        JSON.stringify({
          id: 2,
          method: "Page.captureScreenshot",
          params: { format: "png" },
        }),
      );
    };
    const checkReady = () => {
      activeId = 1;
      ws.send(
        JSON.stringify({
          id: 1,
          method: "Runtime.evaluate",
          params: { expression: "document.readyState", returnByValue: true },
        }),
      );
    };
    ws.onopen = () => {
      if (waitReady) checkReady();
      else {
        activeId = 1;
        ws.send(
          JSON.stringify({
            id: 1,
            method: "Page.captureScreenshot",
            params: { format: "png" },
          }),
        );
      }
    };
    ws.onmessage = (event) => {
      let msg;
      try {
        const raw =
          typeof event.data === "string"
            ? event.data
            : Buffer.isBuffer(event.data)
              ? event.data.toString("utf8")
              : String(event.data);
        msg = JSON.parse(raw);
      } catch {
        return;
      }
      if (!msg || typeof msg.id !== "number") return;
      if (waitReady && msg.id === 1 && activeId === 1) {
        const state = msg.result?.result?.value;
        if (state === "complete") {
          readyPollTimer = setTimeout(sendCapture, 150);
        } else {
          readyPollTimer = setTimeout(checkReady, 100);
        }
        return;
      }
      const expectedId = waitReady ? 2 : 1;
      if (msg.id !== expectedId) return;
      if (msg.error) {
        finish(new Error(msg.error.message || "CDP error"));
        return;
      }
      if (msg.result?.data) {
        finish(null, msg.result.data);
        return;
      }
      finish(new Error("CDP Page.captureScreenshot returned no image data"));
    };
    ws.onerror = (err) =>
      finish(
        err instanceof Error
          ? err
          : new Error(err?.message || "CDP WebSocket error"),
      );
    ws.onclose = () =>
      finish(new Error("CDP WebSocket closed before screenshot response"));
  });
}

function writePng(dest, base64) {
  const buf = Buffer.from(base64, "base64");
  if (buf.length < 32 || !buf.subarray(0, 8).equals(PNG_MAGIC))
    throw new Error("Captured payload is not a valid PNG");
  const resolved = path.resolve(dest);
  assertPlainPath(resolved);
  fs.mkdirSync(path.dirname(resolved), { recursive: true, mode: 0o700 });
  assertPlainPath(resolved);
  fs.writeFileSync(resolved, buf, { mode: 0o600 });
  return buf.length;
}

async function captureAttach(opts) {
  const targets = await fetchJson(`http://127.0.0.1:${opts.port}/json`, 5000);
  if (!Array.isArray(targets)) throw new Error("Invalid CDP target list");
  const pages = targets.filter((t) => t && t.type === "page");
  if (!pages.length) throw new Error("no pages open");

  let target;
  if (opts.urlMatch) {
    target = pages.find((p) => String(p.url || "").includes(opts.urlMatch));
    if (!target) throw new Error(`no page matching "${opts.urlMatch}"`);
  } else if (opts.pageIndex >= 0) {
    target = pages[opts.pageIndex];
    if (!target) throw new Error(`no page at index ${opts.pageIndex}`);
  } else {
    target = pages[0];
  }

  if (!target.webSocketDebuggerUrl)
    throw new Error("no WebSocket debugger URL for the target");

  const data = await cdpScreenshot(target.webSocketDebuggerUrl, 15000, false);
  const bytes = writePng(opts.dest, data);
  return { url: target.url, title: target.title, bytes };
}

function killProcessGroup(proc) {
  if (!proc?.pid) return;
  if (process.platform !== "win32") {
    try {
      process.kill(-proc.pid, "SIGTERM");
    } catch {}
  } else {
    try {
      proc.kill("SIGTERM");
    } catch {}
  }
}

function forceKillProcessGroup(proc) {
  if (!proc?.pid) return;
  if (process.platform !== "win32") {
    try {
      process.kill(-proc.pid, "SIGKILL");
    } catch {}
  } else {
    try {
      proc.kill("SIGKILL");
    } catch {}
  }
}

async function captureIsolated(opts) {
  const browserBin = findExecutable(
    [
      "/usr/bin/chromium",
      "/usr/bin/chromium-browser",
      "/usr/bin/google-chrome",
      "/opt/google/chrome/chrome",
    ],
    ["chromium", "chromium-browser", "google-chrome"],
  );
  if (!browserBin)
    throw new Error("No Chromium or Google Chrome executable found");

  const xvfbDisabled =
    (process.env.HARNESS_CAPTURE_XVFB ?? "auto").trim() === "off";
  const xvfbBin =
    process.platform !== "win32" && !xvfbDisabled
      ? findExecutable(["/usr/bin/xvfb-run", "/usr/local/bin/xvfb-run"], ["xvfb-run"])
      : undefined;

  const userDataDir = fs.mkdtempSync(path.join(os.tmpdir(), "harness-browser-"));
  const browserArgs = [
    `--user-data-dir=${userDataDir}`,
    "--no-first-run",
    "--no-default-browser-check",
    "--disable-default-apps",
    "--disable-background-networking",
    "--disable-sync",
    "--metrics-recording-only",
    "--test-type",
    "--remote-debugging-port=0",
    "--window-size=1280,800",
    ...(xvfbBin ? [] : ["--headless=new"]),
    opts.launchUrl,
  ];
  const cmd = xvfbBin ? xvfbBin : browserBin;
  const cmdArgs = xvfbBin
    ? ["-a", "-s", "-screen 0 1280x800x24", browserBin, ...browserArgs]
    : browserArgs;

  const proc = spawn(cmd, cmdArgs, {
    detached: process.platform !== "win32",
    stdio: ["ignore", "ignore", "pipe"],
  });
  let stderr = "";
  proc.stderr?.on("data", (chunk) => {
    if (stderr.length < 4096) stderr += chunk.toString("utf8");
  });
  let exited = false;
  let exitCode = null;
  proc.once("exit", (code) => {
    exited = true;
    exitCode = code;
  });

  try {
    const deadline = Date.now() + opts.timeoutMs;
    const activePortFile = path.join(userDataDir, "DevToolsActivePort");
    let cdpPort = 0;
    while (Date.now() < deadline) {
      if (exited)
        throw new Error(
          `Isolated browser exited early (${exitCode}): ${stderr.slice(0, 300)}`,
        );
      if (fs.existsSync(activePortFile)) {
        const lines = fs
          .readFileSync(activePortFile, "utf8")
          .split(/\r?\n/)
          .map((l) => l.trim())
          .filter(Boolean);
        if (lines.length >= 1 && /^\d+$/.test(lines[0])) {
          cdpPort = validatePort(lines[0]);
          break;
        }
      }
      await new Promise((r) => setTimeout(r, 50));
    }
    if (!cdpPort)
      throw new Error(
        `Timed out waiting for isolated browser DevTools port: ${stderr.slice(0, 300)}`,
      );

    let target;
    while (Date.now() < deadline) {
      try {
        const targets = await fetchJson(`http://127.0.0.1:${cdpPort}/json`, 2000);
        if (Array.isArray(targets)) {
          const pages = targets.filter((t) => t && t.type === "page");
          target =
            pages.find(
              (p) =>
                p.url &&
                (p.url === opts.launchUrl ||
                  !p.url.startsWith("chrome://") && p.url !== "about:blank"),
            ) || pages[0];
          if (target?.webSocketDebuggerUrl) break;
        }
      } catch {}
      await new Promise((r) => setTimeout(r, 100));
    }
    if (!target?.webSocketDebuggerUrl)
      throw new Error("Isolated browser opened no debuggable page target");

    const remaining = Math.max(2000, deadline - Date.now());
    const data = await cdpScreenshot(target.webSocketDebuggerUrl, remaining, true);
    const bytes = writePng(opts.dest, data);
    return { url: target.url, title: target.title, bytes, isolated: true };
  } finally {
    killProcessGroup(proc);
    const waitEnd = Date.now() + 500;
    while (!exited && Date.now() < waitEnd) {
      await new Promise((r) => setTimeout(r, 25));
    }
    if (!exited) forceKillProcessGroup(proc);
    try {
      fs.rmSync(userDataDir, { recursive: true, force: true });
    } catch {}
  }
}

export async function runCapture(argv = process.argv.slice(2)) {
  const opts = parseArgs(argv);
  return opts.isolated ? captureIsolated(opts) : captureAttach(opts);
}

const isMain = (() => {
  if (!process.argv[1]) return false;
  try {
    return (
      import.meta.url ===
      pathToFileURL(fs.realpathSync(process.argv[1])).href
    );
  } catch {
    return import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href;
  }
})();

if (isMain) {
  runCapture()
    .then((info) => {
      process.stdout.write(JSON.stringify(info));
    })
    .catch((err) => {
      console.error(err instanceof Error ? err.message : String(err));
      process.exit(1);
    });
}
