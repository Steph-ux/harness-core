/**
 * Display and host-command helpers for visual attestations.
 *
 * A capture is one window, never the desktop. A recorded trace is shown in
 * the operator's terminal when a display exists, or printed otherwise.
 */
import * as fs from "node:fs";
import * as path from "node:path";
import { spawnSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { coreRoot } from "./paths";

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
 * On the operator's display the trace is shown in their own terminal, with
 * their theme, then the window is captured and closed. Without a display, or
 * when the terminal is switched off, a printed rendering is produced instead.
 * Neither path runs the command again.
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
  const terminal = ["/usr/bin/qterminal", "/usr/local/bin/qterminal"].find(
    (file) => fs.existsSync(file),
  );
  if (mode !== "off" && display && terminal) {
    const source = path.join(path.dirname(dest), `.trace-${randomUUID()}.txt`);
    fs.writeFileSync(source, `$ ${command}\n\n${text}\n`, { mode: 0o600 });
    try {
      runCommand(
        "sh",
        [
          path.join(coreRoot(), "scripts", "capture_terminal.sh"),
          display,
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

export function waitForTerminalCommand(session: string, marker: string): void {
  for (let attempt = 0; attempt < 300; attempt++) {
    const pane = runCommand(
      "tmux",
      ["capture-pane", "-p", "-t", session],
      10000,
    );
    if (pane.split("\n").some((line) => line.trim() === `${marker}:0`)) return;
    spawnSync("sleep", ["0.1"]);
  }
  throw new Error("the evidence command did not finish within 30 seconds");
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
