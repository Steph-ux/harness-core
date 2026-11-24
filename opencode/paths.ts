/**
 * Where the plugin finds the core and the shared state.
 *
 * The plugin may be loaded from a copy, a link or a package directory. The
 * core is reached by an absolute path rather than a relative one, so the
 * loader never decides where the proof comes from.
 */
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

export function coreRoot(): string {
  return (
    process.env.HARNESS_CORE?.trim() ||
    path.dirname(
      path.dirname(fs.realpathSync(fileURLToPath(import.meta.url))),
    )
  );
}

export function defaultStateDir(): string {
  return path.join(os.homedir(), ".local", "share", "harness-core", "state");
}
