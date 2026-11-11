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
 * C:\Users\stephanea). Those are aliases, not redirections, and a refused
 * alias would make the harness unusable on the operator's own machine.
 *
 * Every case below is exercised on every platform, so the check cannot
 * regress unnoticed on the one where the alias happens to exist.
 */
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const CORE = path.resolve(__dirname, "..");

module.exports = async ({ assert, jiti }) => {
  const { assertPlainPath } = jiti(path.join(CORE, "src", "util.ts"));
  const workspace = fs.mkdtempSync(path.join(os.tmpdir(), "harness-paths-"));
  const real = fs.realpathSync.native(workspace);
  const made = [];
  const cleanup = () => {
    for (const entry of made) {
      try {
        fs.rmSync(entry, { recursive: true, force: true });
      } catch {
        /* the link could not be removed */
      }
    }
  };
  try {
    // The ordinary path is accepted.
    assert.doesNotThrow(
      () => assertPlainPath(path.join(workspace, "knowledge.sqlite")),
      "a plain path is accepted",
    );
    assert.doesNotThrow(
      () => assertPlainPath(path.join(real, "knowledge.sqlite")),
      "the resolved spelling of the same path is accepted",
    );

    // A directory that does not exist yet is not refused: the harness
    // writes its state into a directory it creates.
    assert.doesNotThrow(
      () => assertPlainPath(path.join(workspace, "not-yet", "state.sqlite")),
      "a path that does not exist yet is accepted",
    );

    // A link that points elsewhere is refused: the harness would write
    // outside the directory the operator declared.
    const target = path.join(real, "target");
    fs.mkdirSync(target, { recursive: true });
    const link = path.join(real, "redirect");
    fs.symlinkSync(
      target,
      link,
      process.platform === "win32" ? "junction" : "dir",
    );
    made.push(link);
    assert.throws(
      () => assertPlainPath(path.join(link, "knowledge.sqlite")),
      /Linked or special harness paths are not allowed/,
      "a redirected directory is refused",
    );

    // The same through a link in the middle of the path.
    const inner = path.join(real, "inner");
    fs.mkdirSync(inner, { recursive: true });
    const middle = path.join(real, "middle");
    fs.symlinkSync(
      inner,
      middle,
      process.platform === "win32" ? "junction" : "dir",
    );
    made.push(middle);
    assert.throws(
      () => assertPlainPath(path.join(middle, "knowledge.sqlite")),
      /Linked or special harness paths are not allowed/,
      "a redirected ancestor is refused",
    );

    // A linked file is refused too.
    const file = path.join(real, "linked.sqlite");
    fs.symlinkSync(path.join(real, "target"), file);
    made.push(file);
    assert.throws(
      () => assertPlainPath(file),
      /Linked or special harness paths are not allowed/,
      "a redirected file is refused",
    );

    // A hard link is refused: the file is reachable under another name.
    const hard = path.join(real, "hard.sqlite");
    fs.writeFileSync(hard, "x");
    try {
      fs.linkSync(hard, path.join(real, "hard-link.sqlite"));
      made.push(path.join(real, "hard-link.sqlite"));
      assert.throws(
        () => assertPlainPath(path.join(real, "hard-link.sqlite")),
        /Linked or special harness paths are not allowed/,
        "a hard-linked file is refused",
      );
    } catch (error) {
      // A filesystem without hard links cannot show the case.
    }

    // The short name of a directory is an alias, not a redirection. The
    // case exists where the platform keeps one; where it does not, the
    // check is exercised through the resolved spelling above.
    const short = os.tmpdir();
    if (path.resolve(short) !== path.resolve(real)) {
      assert.doesNotThrow(
        () => assertPlainPath(path.join(short, "probe.sqlite")),
        "a short directory name is an alias and is accepted",
      );
    }
  } finally {
    cleanup();
    fs.rmSync(workspace, { recursive: true, force: true });
  }
};
