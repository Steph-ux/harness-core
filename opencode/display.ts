/**
 * Display and host-command helpers for visual attestations.
 *
 * A capture is one window, never the desktop. A recorded trace is shown in
 * an isolated Xvfb terminal when available (or the operator's terminal if
 * Xvfb is disabled), or printed otherwise. Isolated browser captures run in
 * a dedicated temporary profile under Xvfb or headless mode without touching
 * the operator's personal browser or foreground focus.
 */
import * as fs from "node:fs";
import * as path from "node:path";
import { spawnSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { coreRoot } from "./paths";
import { assertPlainPath } from "../src/util";

function findExecutable(
  candidates: readonly string[],
  names: readonly string[],
): string | undefined {
  const isExe = (file: string) => {
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
  const exts =
    process.platform === "win32"
      ? (process.env.PATHEXT || ".EXE;.CMD;.BAT").split(";").filter(Boolean)
      : [""];
  for (const dir of pathDirs) {
    for (const name of names) {
      for (const ext of exts) {
        const candidate = path.join(dir, name + ext);
        if (isExe(candidate)) return candidate;
      }
    }
  }
  return undefined;
}

export function hasXvfb(): boolean {
  if (process.platform === "win32") return false;
  if ((process.env.HARNESS_CAPTURE_XVFB ?? "auto").trim() === "off")
    return false;
  return Boolean(
    findExecutable(["/usr/bin/xvfb-run", "/usr/local/bin/xvfb-run"], ["xvfb-run"]),
  );
}

export function findBrowserExecutable(): string | undefined {
  return findExecutable(
    [
      "/usr/bin/chromium",
      "/usr/bin/chromium-browser",
      "/usr/bin/google-chrome",
      "/opt/google/chrome/chrome",
    ],
    ["chromium", "chromium-browser", "google-chrome"],
  );
}

/** A command of the host, with its output. */
export function runCommand(
  command: string,
  args: string[],
  timeout = 10000,
  env?: Record<string, string>,
  allowFailure = false,
): string {
  const result = spawnSync(command, args, {
    encoding: "utf8",
    timeout,
    env: env ? { ...process.env, ...env } : process.env,
  });
  if (result.error)
    throw new Error(`${command} failed: ${result.error.message}`);
  if (result.status !== 0 && !allowFailure)
    throw new Error(
      `${command} failed: ${String(result.stderr || result.stdout || "").slice(
        0,
        300,
      )}`,
    );
  return result.stdout ?? "";
}

/**
 * Render a recorded trace the way a report can print it.
 *
 * Runs inside an isolated Xvfb terminal when available (or on the operator's
 * display if Xvfb is disabled), then captures and closes the window. Without a
 * display/Xvfb, or when the terminal is switched off, a printed rendering is
 * produced instead. Neither path runs the command again.
 */
export function renderTrace(
  text: string,
  dest: string,
  title: string,
  command: string,
  cwd: string,
): "qterminal" | "printed" {
  const display = process.env.DISPLAY?.trim();
  const mode = (process.env.HARNESS_CAPTURE_TERMINAL ?? "auto").trim();
  const terminal = findExecutable(
    ["/usr/bin/qterminal", "/usr/local/bin/qterminal"],
    ["qterminal"],
  );
  const xvfb = hasXvfb();
  if (mode !== "off" && terminal && (xvfb || display)) {
    const source = path.join(path.dirname(dest), `.trace-${randomUUID()}.txt`);
    fs.writeFileSync(source, `$ ${command}\n\n${text}\n`, { mode: 0o600 });
    try {
      runCommand(
        "sh",
        [
          path.join(coreRoot(), "scripts", "capture_terminal.sh"),
          display ?? "",
          cwd,
          title,
          source,
          dest,
        ],
        45000,
      );
      if (fs.existsSync(dest) && fs.statSync(dest).size > 100)
        return "qterminal";
    } catch {
      /* the printed rendering below is the fallback */
    } finally {
      fs.rmSync(source, { force: true });
    }
  }
  const source = path.join(path.dirname(dest), `.trace-${randomUUID()}.txt`);
  fs.writeFileSync(source, text, { mode: 0o600 });
  try {
    runCommand(
      "python3",
      [
        path.join(coreRoot(), "scripts", "render_trace.py"),
        source,
        dest,
        title,
        command,
      ],
      30000,
    );
  } finally {
    fs.rmSync(source, { force: true });
  }
  return "printed";
}

export interface IsolatedBrowserCaptureOptions {
  url: string;
  dest: string;
  timeoutMs?: number;
}

export interface IsolatedBrowserCaptureResult {
  url: string;
  title: string;
  bytes: number;
  isolated: boolean;
}

/**
 * Capture a browser page inside a fresh temporary profile (never the personal
 * browser) and an isolated Xvfb display or headless mode.
 */
export function captureBrowserIsolated(
  options: IsolatedBrowserCaptureOptions,
): IsolatedBrowserCaptureResult {
  const rawUrl = String(options.url ?? "").trim();
  if (!rawUrl) throw new Error("A URL is required for isolated browser capture");
  let parsed: URL;
  try {
    parsed = new URL(rawUrl);
  } catch {
    throw new Error("Invalid URL for isolated browser capture");
  }
  if (!["http:", "https:", "data:", "about:"].includes(parsed.protocol))
    throw new Error("Unsupported URL scheme for isolated browser capture");
  const dest = path.resolve(String(options.dest ?? ""));
  if (!String(options.dest ?? "").trim())
    throw new Error("A destination path is required");
  assertPlainPath(dest);
  const timeoutMs =
    options.timeoutMs !== undefined &&
    Number.isFinite(options.timeoutMs) &&
    options.timeoutMs > 0
      ? Math.min(Math.round(options.timeoutMs), 120000)
      : 30000;
  const script = path.join(coreRoot(), "scripts", "capture_browser.mjs");
  const stdout = runCommand(
    process.execPath,
    [
      script,
      dest,
      "--isolated",
      "--launch",
      rawUrl,
      "--timeout",
      String(timeoutMs),
    ],
    timeoutMs + 10000,
  );
  return { ...JSON.parse(stdout), isolated: true };
}

export function commandArguments(value: unknown): string[] {
  if (
    !Array.isArray(value) ||
    !value.length ||
    value.length > 256 ||
    value.some(
      (part) =>
        typeof part !== "string" ||
        part.length > 32768 ||
        /[\0\r\n]/.test(part),
    )
  )
    throw new Error("argv must contain 1..256 valid command arguments");
  return value;
}

/**
 * The windows the display shows.
 *
 * The titles are read one by one and paired with the ids, because a title
 * search in the display tool does not accept a partial name.
 */
export function listWindows(display?: string): { id: string; title: string }[] {
  const env = display ? { DISPLAY: display } : undefined;
  const ids = runCommand(
    "xdotool",
    ["search", "--onlyvisible", "--name", "."],
    10000,
    env,
    true,
  )
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean);
  const windows: { id: string; title: string }[] = [];
  for (const id of ids) {
    let title = "";
    try {
      title = runCommand("xdotool", ["getwindowname", id], 5000, env).trim();
    } catch {
      continue;
    }
    windows.push({ id, title });
  }
  return windows;
}

/** The id of the root window: the desktop itself. */
export function rootWindowId(display?: string): string {
  const out = runCommand(
    "xwininfo",
    ["-root"],
    10000,
    display ? { DISPLAY: display } : undefined,
  );
  const match = /Window id:\s*(0x[0-9a-f]+)/i.exec(out);
  return match ? match[1] : "";
}

/** The size of a window, as the display tool reports it. */
export function windowGeometry(
  id: string,
  display?: string,
): { width: number; height: number } {
  const out = runCommand(
    "xwininfo",
    ["-id", id],
    10000,
    display ? { DISPLAY: display } : undefined,
  );
  const width = Number(/Width:\s*(\d+)/.exec(out)?.[1]);
  const height = Number(/Height:\s*(\d+)/.exec(out)?.[1]);
  return { width, height };
}

/**
 * The picture of one window.
 *
 * The capture is taken of that window and of nothing else, so the desktop
 * never appears in it.
 */
export function captureWindow(
  id: string,
  dest: string,
  display?: string,
): { width: number; height: number; bytes: number } {
  runCommand(
    "import",
    ["-window", id, dest],
    20000,
    display ? { DISPLAY: display } : undefined,
  );
  const stat = fs.statSync(dest);
  if (!stat.isFile() || stat.size < 32)
    throw new Error("the capture file is empty");
  const size = runCommand("identify", ["-format", "%w %h", dest], 10000).trim();
  const [width, height] = size.split(" ").map((value) => Number(value));
  return { width, height, bytes: stat.size };
}

/** A path or argument, quoted for the shell only when it needs it. */
export function quoteArgument(value: string): string {
  return /^[A-Za-z0-9_@%+=:,./-]+$/.test(value)
    ? value
    : `'${String(value).replace(/'/g, `'\\''`)}'`;
}
