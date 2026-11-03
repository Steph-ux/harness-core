#!/usr/bin/env node
/**
 * The harness core must stay host-neutral.
 *
 * It is shared by more than one agent host, so a single import of a host
 * runtime would tie it to that host and break the next port. This check
 * fails loudly rather than letting the dependency creep back in.
 */
const fs = require("node:fs");
const path = require("node:path");

const root = path.resolve(__dirname, "..");
const sourceRoot = path.join(root, "src");
const FORBIDDEN = [
  "@earendil-works/pi-",
  "@opencode-ai/",
  "opencode/",
  "./preflight",
  "./workers",
  "./router",
  "./runtime",
  "./native-",
  "./process-tools",
  "./owned-exec",
];

const offenders = [];
const files = fs
  .readdirSync(sourceRoot)
  .filter((name) => name.endsWith(".ts"));
for (const file of files) {
  const text = fs.readFileSync(path.join(sourceRoot, file), "utf8");
  for (const pattern of FORBIDDEN) {
    if (text.includes(pattern))
      offenders.push(`${file} references ${pattern}`);
  }
}

// The core must also resolve on its own: every internal import has to point
// at a file that exists in this package.
const known = new Set(files.map((name) => `./${name.replace(/\.ts$/, "")}`));
for (const file of files) {
  const text = fs.readFileSync(path.join(sourceRoot, file), "utf8");
  for (const match of text.matchAll(/from "(\.\/[a-z0-9-]+)"/g)) {
    if (!known.has(match[1]))
      offenders.push(`${file} imports missing ${match[1]}`);
  }
}

if (offenders.length) {
  console.error("Harness core is not host-neutral:");
  for (const line of offenders) console.error(`  ${line}`);
  process.exit(1);
}
console.log(
  `Harness core is host-neutral: ${files.length} files, 0 host imports, 0 dangling imports.`,
);
