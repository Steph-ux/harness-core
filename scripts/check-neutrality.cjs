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
const defaultSourceRoot = path.join(root, "src");
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

// Hardcoded client prefixes must never live in host-neutral src/ code.
// Preserve HOST_METHODS / routing contracts in src/routing.ts ("opencode").
const CLIENT_PREFIX_RE =
  /(?<![a-z0-9])(?:boa|mtn|julaya|snedai|anip|loterie)-/i;

function stripCommentsPreserveStrings(source) {
  return source.replace(
    /("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|`(?:\\.|[^`\\])*`)|\/\/[^\n]*|\/\*[\s\S]*?\*\//g,
    (match, str) => str || "",
  );
}

function collectSourceFiles(dir, prefix = "") {
  const out = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const rel = prefix ? `${prefix}/${entry.name}` : entry.name;
    if (entry.isDirectory()) {
      out.push(...collectSourceFiles(path.join(dir, entry.name), rel));
    } else if (entry.isFile() && (entry.name.endsWith(".ts") || entry.name.endsWith(".cjs"))) {
      out.push(rel);
    }
  }
  return out.sort();
}

function extractImports(code) {
  const specs = [];
  const patterns = [
    /(?:^|[;\n])\s*(?:import|export)\s+(?:type\s+)?(?:[^'"\n;]*?\s+from\s+)?(['"])([^'"]+)\1/gm,
    /\bimport\s*\(\s*(['"])([^'"]+)\1\s*\)/g,
    /\brequire\s*\(\s*(['"])([^'"]+)\1\s*\)/g,
  ];
  for (const re of patterns) {
    for (const match of code.matchAll(re)) {
      specs.push(match[2]);
    }
  }
  return specs;
}

function checkNeutrality(sourceRoot = defaultSourceRoot, options = {}) {
  const checkClientPrefixes = options.checkClientPrefixes !== false;

  const files = collectSourceFiles(sourceRoot);
  const known = new Set();
  for (const file of files) {
    const posix = `./${file.replace(/\\/g, "/")}`;
    known.add(posix);
    if (posix.endsWith(".ts")) known.add(posix.replace(/\.ts$/, ""));
    if (posix.endsWith(".cjs")) known.add(posix.replace(/\.cjs$/, ""));
  }

  const offenders = [];
  for (const file of files) {
    const full = path.join(sourceRoot, file);
    const text = fs.readFileSync(full, "utf8");
    for (const pattern of FORBIDDEN) {
      if (text.includes(pattern)) offenders.push(`${file} references ${pattern}`);
    }
    if (
      /Mes-outils|[\\/]home[\\/][a-z0-9_-]+[\\/]hacking[\\/]|[\\/]Users[\\/][a-z0-9_-]+[\\/]hacking[\\/]/i.test(
        text,
      )
    ) {
      offenders.push(`${file} embeds a personal tool directory`);
    }
    const code = stripCommentsPreserveStrings(text);
    if (checkClientPrefixes && CLIENT_PREFIX_RE.test(code)) {
      offenders.push(`${file} embeds a hardcoded client prefix`);
    }

    const fileDir = path.posix.dirname(file.replace(/\\/g, "/"));
    for (const spec of extractImports(code)) {
      if (spec.startsWith("../") || spec === "..") {
        offenders.push(`${file} imports outside src (${spec})`);
      } else if (spec.startsWith("./")) {
        const resolved =
          fileDir === "."
            ? spec
            : `./${path.posix.normalize(path.posix.join(fileDir, spec))}`;
        if (!known.has(resolved)) {
          offenders.push(`${file} imports missing ${spec}`);
        }
      } else if (!spec.startsWith("node:")) {
        offenders.push(`${file} imports non-builtin ${spec}`);
      }
    }
  }

  return { files, offenders };
}

module.exports = { checkNeutrality };

if (require.main === module) {
  const { files, offenders } = checkNeutrality(defaultSourceRoot);
  if (offenders.length) {
    console.error("Harness core is not host-neutral:");
    for (const line of offenders) console.error(`  ${line}`);
    process.exit(1);
  }
  console.log(
    `Harness core is host-neutral: ${files.length} files, 0 host imports, 0 dangling imports.`,
  );
}
