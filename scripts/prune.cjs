#!/usr/bin/env node
/**
 * Bounded retention for the knowledge store.
 *
 * Messages older than the window are removed. Observations are the evidence a
 * claim rests on and are never pruned; the audit log is append-only by schema.
 * This is an operator maintenance command, never a tool the model can call.
 *
 * Usage:
 *   node scripts/prune.cjs [--messages-days 180] [--dry-run]
 */
const path = require("node:path");
const { createJiti } = require(path.join(__dirname, "..", "node_modules/jiti"));
const jiti = createJiti(__filename);
const { KnowledgeStore } = jiti(
  path.join(__dirname, "..", "src", "store.ts"),
);

const state =
  process.env.HARNESS_STATE_ROOT ||
  path.join(process.env.HOME || process.env.USERPROFILE, ".local", "share", "harness-core", "state");
const file = process.env.HARNESS_KNOWLEDGE || path.join(state, "knowledge.sqlite");

const value = (name, fallback) => {
  const index = process.argv.indexOf(name);
  if (index < 0) return fallback;
  const parsed = Number(process.argv[index + 1]);
  if (!Number.isFinite(parsed)) throw new Error(`Invalid ${name}`);
  return parsed;
};
const days = value("--messages-days", 180);
const dryRun = process.argv.includes("--dry-run");

const store = new KnowledgeStore(file);
const bytesBefore = store.size();
const candidates = store.pruneMessages(days, true);
const removed = dryRun ? 0 : store.pruneMessages(days);
const bytesAfterPrune = store.size();
if (!dryRun) store.vacuum();
const bytesAfter = store.size();
store.close();

console.log(
  JSON.stringify(
    {
      file,
      messagesDays: days,
      dryRun,
      candidates,
      removed,
      bytesBefore,
      bytesAfterPrune,
      bytesAfter,
      kept: [
        "observations: the evidence a claim rests on",
        "audit_log: append-only by schema",
        "findings, reports, artifacts: mission records",
      ],
    },
    null,
    2,
  ),
);
