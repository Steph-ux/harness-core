/**
 * The harness refuses a path that is redirected.
 *
 * The state lives outside the repository, so every write goes through
 * assertPlainPath. A path that a link points elsewhere would let the
 * harness write outside the directory the operator declared, so it is
 * refused.
 *
 * The check compares the object a path denotes, not the way it is spelled:
 * Windows keeps a short name for the same directory (C:\Users\STEPHA~1 is
 * C:\Users\stephanea) and macOS links /var to /private/var. Those are
 * aliases, not redirections, and a refused alias would make the harness
 * unusable on the operator's own machine.
 */
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const CORE = path.resolve(__dirname, "..");

module.exports = async ({ assert, jiti }) => {
  const { assertPlainPath } = jiti(path.join(CORE, "src", "util.ts"));
  const workspace = fs.mkdtempSync(path.join(os.tmpdir(), "harness-paths-"));
  const real = fs.realpathSync.native(workspace);

  // The ordinary path is accepted.
  assert.doesNotThrow(
    () => assertPlainPath(path.join(workspace, "knowledge.sqlite")),
    "a plain path is accepted",
  );
  assert.doesNotThrow(
    () => assertPlainPath(path.join(real, "knowledge.sqlite")),
    "the resolved spelling of the same path is accepted",
  );

  // The short name of a directory is an alias, not a redirection.
  const short = os.tmpdir();
  if (path.resolve(short) !== path.resolve(real)) {
    assert.doesNotThrow(
      () => assertPlainPath(path.join(short, "probe.sqlite")),
      "a short directory name is an alias and is accepted",
    );
  }

  // A link that points elsewhere is refused: the harness would write
  // outside the directory the operator declared.
  const target = path.join(real, "target");
  fs.mkdirSync(target, { recursive: true });
  const link = path.join(real, "redirect");
  try {
    fs.symlinkSync(target, link, process.platform === "win32" ? "junction" : "dir");
    assert.throws(
      () => assertPlainPath(path.join(link, "knowledge.sqlite")),
      /Linked or special harness paths are not allowed/,
      "a redirected path is refused",
    );
  } finally {
    try {
      fs.unlinkSync(link);
    } catch {
      /* the link was never created */
    }
  }

  // A directory that does not exist yet is not refused: the harness writes
  // its state into a directory it creates.
  assert.doesNotThrow(
    () => assertPlainPath(path.join(workspace, "not-yet", "state.sqlite")),
    "a path that does not exist yet is accepted",
  );

  fs.rmSync(workspace, { recursive: true, force: true });
};
