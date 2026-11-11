#!/usr/bin/env node
/**
 * The standalone gate of the harness core.
 *
 * The suites live next to the code they exercise, so they can run without any
 * agent host installed. The Pi harness keeps its own gate and calls these same
 * suites; this runner is what a clone of the repository can run on its own.
 */
const fs = require("node:fs");
const path = require("node:path");
const realAssert = require("node:assert/strict");

/** Count real assertion calls instead of trusting hardcoded suite totals. */
function countingAssert() {
  let count = 0;
  const proxy = new Proxy(realAssert, {
    get(target, property, receiver) {
      const value = Reflect.get(target, property, receiver);
      if (typeof value !== "function") return value;
      return (...args) => {
        count++;
        return value.apply(target, args);
      };
    },
  });
  return { proxy, read: () => count };
}

// Explicit consent for the synthetic verifier providers in fixture tests only.
process.env.HARNESS_VERIFIER_PROVIDERS="test,Ed";
const root = path.resolve(__dirname, "..");
const modules = path.join(root, "node_modules");
const { createJiti } = require(path.join(modules, "jiti"));

/**
 * The cross-host checks read the other host's own module, so the runtimes it
 * imports have to resolve. They live in the Pi installation, which is not part
 * of this repository; the aliases point at it when it is installed.
 */
const home = process.env.USERPROFILE || process.env.HOME;
const releases = path.join(home, ".pi/agent/install/releases");
const piVersion = fs.existsSync(releases)
  ? fs.readdirSync(releases)
      .filter((version) => fs.existsSync(path.join(releases, version, "node_modules/jiti")))
      .sort((a, b) => a.localeCompare(b, undefined, { numeric: true }))
      .pop()
  : undefined;
const piModules = piVersion ? path.join(releases, piVersion, "node_modules") : undefined;
const resolvePi = (name) => require.resolve(name, { paths: [piModules] });
const alias = {};
if (piModules) {
  alias["@earendil-works/pi-agent-core"] = path.join(piModules, "@earendil-works/pi-agent-core/dist/index.js");
  alias["@earendil-works/pi-ai"] = path.join(piModules, "@earendil-works/pi-ai/dist/compat.js");
  alias["@earendil-works/pi-tui"] = path.join(piModules, "@earendil-works/pi-tui/dist/index.js");
  alias["@earendil-works/pi-coding-agent"] = path.join(piModules, "@earendil-works/pi-coding-agent/dist/utils/frontmatter.js");
  for (const name of ["typebox", "typebox/compile", "typebox/value"]) {
    try { alias[name] = resolvePi(name); } catch { /* the host does not ship it */ }
  }
}
const jiti = createJiti(__filename, { alias });

const suites = fs
  .readdirSync(__dirname)
  .filter((name) => name.startsWith("opencode-") && name.endsWith(".cjs"))
  .filter((name) => name !== "opencode-fixture.cjs")
  .map((name) => name.replace(/\.cjs$/, ""))
  .sort();

/**
 * A suite that needs a platform the machine does not have is skipped, not
 * failed. The command supervision of a traced process is Linux-only, so the
 * suites that exercise it cannot run elsewhere; they are the coverage of
 * that guarantee, and the guarantee is checked on Linux.
 */
class SkipSuite extends Error {}
const skip = (reason) => {
  throw new SkipSuite(reason);
};

(async () => {
  let count = 0;
  let skipped = 0;
  for (const suite of suites) {
    const counted = countingAssert();
    try {
      await require(path.join(__dirname, `${suite}.cjs`))({
        assert: counted.proxy,
        jiti,
        modules,
        root,
        harness: root,
        skip,
      });
    } catch (error) {
      if (error instanceof SkipSuite) {
        console.log(`SKIP ${suite}: ${error.message}`);
        skipped++;
        continue;
      }
      throw error;
    }
    const checks = counted.read();
    console.log(`PASS ${suite}: ${checks} checks`);
    count += checks;
  }
  console.log(
    `ALL PASS: ${count} checks; ${suites.length - skipped} suites, ${skipped} skipped`,
  );
})().catch((error) => {
  console.error(error.stack || error.message);
  process.exitCode = 1;
});
