/**
 * The framing rules of a visual attestation.
 *
 * A capture proves what a window showed. It is therefore never the desktop:
 * a screenshot of the whole screen carries whatever else the operator had on
 * it, and that is not evidence of anything. A capture is one window, and it
 * must look like that window.
 *
 * The rules live here, neutral, so that every host frames a capture the same
 * way and can prove it did.
 */
import * as path from "node:path";
import { assertPlainPath } from "./util";

function parseWindowId(value: unknown): bigint | null {
  const raw = String(value ?? "").trim().toLowerCase();
  if (/^0x[0-9a-f]+$/.test(raw) || /^[0-9]+$/.test(raw)) return BigInt(raw);
  return null;
}

export interface WindowInfo {
  id: string;
  title: string;
}

export interface WindowGeometry {
  width: number;
  height: number;
}

export interface CaptureResult {
  path: string;
  bytes: number;
  window: string;
  title: string;
  width: number;
  height: number;
}

/** The title of the window the harness owns, when it owns one. */
export const EVIDENCE_TITLE = "harness-evidence";

/** How far a capture may differ from the window it claims to show. */
export const FRAME_TOLERANCE = 32;

/**
 * The smallest window that can be a subject.
 *
 * A window of a few pixels is a minimized or unmapped window. Capturing it
 * would produce a picture of nothing, and the capture tool of the host fails
 * on it with a misleading message.
 */
export const MINIMUM_WINDOW = 16;

/**
 * The window with that title.
 *
 * The match must be unique: two windows with the same title mean the capture
 * could show the wrong one.
 */
export function selectWindow(
  windows: readonly WindowInfo[],
  title: string,
): WindowInfo {
  if (typeof title !== "string" || !title.trim())
    throw new Error("A capture needs the title of the window to show");
  const matches = windows.filter((window) => window.title === title);
  if (matches.length !== 1)
    throw new Error(
      matches.length === 0
        ? "No window carries that title"
        : "Several windows carry that title, the capture could show the wrong one",
    );
  return matches[0];
}

/** The window with that id. */
export function selectWindowById(
  windows: readonly WindowInfo[],
  id: string,
): WindowInfo {
  const wanted = String(id ?? "").trim();
  if (!wanted) throw new Error("A capture needs a window");
  const wantedNum = parseWindowId(wanted);
  const matches = windows.filter((window) => {
    const wid = window.id.trim();
    if (wid === wanted) return true;
    if (wantedNum === null) return false;
    const widNum = parseWindowId(wid);
    return widNum !== null && widNum === wantedNum;
  });
  if (matches.length !== 1)
    throw new Error("No window carries that id");
  return matches[0];
}

/**
 * The root window is the desktop. It is never a subject.
 *
 * The id of the root is a real window id, so refusing the zero id is not
 * enough: the root has to be compared.
 */
export function assertNotRoot(rootId: string, targetId: string): void {
  const root = String(rootId ?? "").trim().toLowerCase();
  const target = String(targetId ?? "").trim().toLowerCase();
  if (!target) throw new Error("A capture needs a window");
  const rootNum = parseWindowId(root);
  const targetNum = parseWindowId(target);
  if (targetNum !== null && targetNum === 0n)
    throw new Error("The desktop is not a subject of a capture");
  if (rootNum !== null && targetNum !== null && rootNum === targetNum)
    throw new Error("The desktop is not a subject of a capture");
  if (root && root === target)
    throw new Error("The desktop is not a subject of a capture");
}

/** The file a capture is written to, inside the capture root and nowhere else. */
export function captureDestination(root: string, name: string): string {
  if (typeof root !== "string" || !root.trim() || !path.isAbsolute(root))
    throw new Error("Capture root must be absolute");
  if (typeof name !== "string" || !/^[a-z0-9-]{8,80}$/.test(name))
    throw new Error("Invalid capture name");
  const resolvedRoot = path.resolve(root);
  assertPlainPath(resolvedRoot);
  const dest = path.resolve(resolvedRoot, `${name}.png`);
  if (path.dirname(dest) !== resolvedRoot)
    throw new Error("Capture path escaped its directory");
  assertPlainPath(dest);
  return dest;
}

/**
 * The name of a capture.
 *
 * It carries the observation it attests, so the link survives on the disk and
 * not only in the store.
 */
export function captureName(observationId: string, label?: string): string {
  if (typeof observationId !== "string")
    throw new Error("Invalid observation id");
  const id = observationId.trim();
  if (!/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}$/.test(id))
    throw new Error("Invalid observation id");
  const normalizedId = id
    .toLowerCase()
    .replace(/[_.:]+/g, "-")
    .replace(/^-+|-+$/g, "");
  if (!normalizedId || !/^[a-z0-9-]+$/.test(normalizedId))
    throw new Error("Invalid observation id");
  if (label !== undefined && label !== null && typeof label !== "string")
    throw new Error("Invalid capture label");
  const cleanLabel = label
    ? String(label)
        .toLowerCase()
        .replace(/[^a-z0-9-]+/g, "-")
        .replace(/^-+|-+$/g, "")
        .slice(0, 40)
        .replace(/-+$/g, "")
    : "";
  const suffix = cleanLabel ? `-${cleanLabel}` : "";
  const name = `${normalizedId}${suffix}`;
  if (!/^[a-z0-9-]{8,80}$/.test(name))
    throw new Error("Invalid capture name");
  return name;
}

/**
 * Whether the capture really shows the window it claims to show.
 *
 * A capture of the desktop has the size of the screen; a capture of a window
 * has the size of that window. The two are told apart by their dimensions.
 */
export function isFramed(
  capture: WindowGeometry,
  window: WindowGeometry,
): boolean {
  if (!Number.isFinite(capture.width) || !Number.isFinite(capture.height))
    return false;
  if (!Number.isFinite(window.width) || !Number.isFinite(window.height))
    return false;
  if (capture.width < MINIMUM_WINDOW || capture.height < MINIMUM_WINDOW)
    return false;
  if (window.width < MINIMUM_WINDOW || window.height < MINIMUM_WINDOW)
    return false;
  return (
    Math.abs(capture.width - window.width) <= FRAME_TOLERANCE &&
    Math.abs(capture.height - window.height) <= FRAME_TOLERANCE
  );
}

/**
 * The link between a capture and the observation it attests.
 *
 * It is what lets a later session check the picture instead of trusting it.
 */
export interface CaptureLink {
  observationId: string;
  path: string;
  window: string;
  title: string;
  width: number;
  height: number;
  bytes: number;
  takenAt: string;
}

const ISO_TIMESTAMP_RE =
  /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,9})?(?:Z|[+-](?:[01]\d|2[0-3]):[0-5]\d)$/;

function isValidIsoTimestamp(value: string): boolean {
  const m = ISO_TIMESTAMP_RE.exec(value);
  if (!m) return false;
  const year = Number(m[1]);
  const month = Number(m[2]);
  const day = Number(m[3]);
  const hour = Number(m[4]);
  const minute = Number(m[5]);
  const second = Number(m[6]);
  if (month < 1 || month > 12 || day < 1 || day > 31) return false;
  if (hour > 23 || minute > 59 || second > 59) return false;
  const calendar = new Date(Date.UTC(year, month - 1, day));
  if (
    calendar.getUTCFullYear() !== year ||
    calendar.getUTCMonth() !== month - 1 ||
    calendar.getUTCDate() !== day
  )
    return false;
  return Number.isFinite(Date.parse(value));
}

export function captureLink(
  observationId: string,
  result: CaptureResult,
  takenAt: string,
): CaptureLink {
  if (
    typeof observationId !== "string" ||
    !/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}$/.test(observationId)
  )
    throw new Error("Invalid observation id");
  if (!result || typeof result !== "object" || Array.isArray(result))
    throw new Error("Invalid capture result");
  if (typeof result.path !== "string" || !result.path.trim())
    throw new Error("Invalid capture path");
  if (typeof result.window !== "string" || !result.window.trim())
    throw new Error("Invalid capture window");
  if (typeof result.title !== "string")
    throw new Error("Invalid capture title");
  if (
    !Number.isInteger(result.width) ||
    result.width <= 0 ||
    !Number.isInteger(result.height) ||
    result.height <= 0
  )
    throw new Error("Invalid capture dimensions");
  if (!Number.isInteger(result.bytes) || result.bytes <= 0)
    throw new Error("Invalid capture size");
  const cleanTakenAt = typeof takenAt === "string" ? takenAt.trim() : "";
  if (!cleanTakenAt || !isValidIsoTimestamp(cleanTakenAt))
    throw new Error("Invalid capture timestamp");
  return {
    observationId,
    path: result.path,
    window: result.window,
    title: result.title,
    width: result.width,
    height: result.height,
    bytes: result.bytes,
    takenAt: cleanTakenAt,
  };
}
