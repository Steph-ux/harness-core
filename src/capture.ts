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
  const matches = windows.filter((window) => window.id.trim() === wanted);
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
  if (root && root === target)
    throw new Error("The desktop is not a subject of a capture");
  if (target === "0x0" || target === "0")
    throw new Error("The desktop is not a subject of a capture");
}

/** The file a capture is written to, inside the capture root and nowhere else. */
export function captureDestination(root: string, name: string): string {
  if (!path.isAbsolute(root)) throw new Error("Capture root must be absolute");
  if (!/^[a-z0-9-]{8,80}$/.test(name))
    throw new Error("Invalid capture name");
  const dest = path.resolve(root, `${name}.png`);
  if (path.dirname(dest) !== path.resolve(root))
    throw new Error("Capture path escaped its directory");
  return dest;
}

/**
 * The name of a capture.
 *
 * It carries the observation it attests, so the link survives on the disk and
 * not only in the store.
 */
export function captureName(observationId: string, label?: string): string {
  const id = String(observationId ?? "").trim();
  if (!/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}$/.test(id))
    throw new Error("Invalid observation id");
  const suffix = label
    ? `-${String(label).toLowerCase().replace(/[^a-z0-9-]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 40)}`
    : "";
  const name = `${id.toLowerCase()}${suffix}`;
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

export function captureLink(
  observationId: string,
  result: CaptureResult,
  takenAt: string,
): CaptureLink {
  if (!/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}$/.test(String(observationId ?? "")))
    throw new Error("Invalid observation id");
  return {
    observationId,
    path: result.path,
    window: result.window,
    title: result.title,
    width: result.width,
    height: result.height,
    bytes: result.bytes,
    takenAt,
  };
}
