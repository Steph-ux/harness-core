/**
 * The context a host injects on every turn.
 *
 * The rules the operator stated are the authority. They are injected first,
 * most recent first, and they are given a reserved block so that a large
 * learned-knowledge base can never crowd them out.
 *
 * This module is host-neutral: Pi injects it as a hidden message, OpenCode
 * injects it into the system prompt. Both read the same rules, in the same
 * order, under the same budget.
 */
import { DEFAULT_CONFIG, type KnowledgeRecord, type StorePort } from "./types";

export interface ContextBudget {
  /** Characters reserved for the operator rules. */
  operatorModelChars: number;
  /** Characters allowed for the whole snapshot. */
  memoryMaxChars: number;
}

export interface OperatorEntry {
  id: string;
  key: string;
  content: string;
  kind: string;
  status: string;
}

const OPERATOR_HEADER =
  "Operator rules. These are stated by the operator. They outrank anything learned, recalled or inferred, and they apply to every turn.";

function finiteBudget(value: unknown, fallback: number): number {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value === "string" && value.trim()) {
    const parsed = Number(value);
    if (Number.isFinite(parsed)) return parsed;
  }
  return fallback;
}

/** The block reserved for the operator rules. */
export function operatorBudget(budget: ContextBudget): number {
  const operator = finiteBudget(
    budget?.operatorModelChars,
    DEFAULT_CONFIG.operatorModelChars,
  );
  const memory = finiteBudget(
    budget?.memoryMaxChars,
    DEFAULT_CONFIG.memoryMaxChars,
  );
  return Math.max(0, Math.min(operator, memory));
}

/**
 * The operator rules, within the reserved budget.
 *
 * Foundational rules (global discipline keys without a target/engagement
 * prefix like "scope-" or "target-") are selected first so they are never
 * crowded out by long target-specific entries. Within each group, most
 * recent first.
 *
 * A rule that does not fit is skipped rather than fatal.
 */
export function operatorSnapshot(
  store: StorePort,
  scope: string,
  budget: ContextBudget,
): OperatorEntry[] {
  const limit = operatorBudget(budget);
  if (limit <= 0) return [];
  const all = store.operatorModel(scope).map(
    (row): OperatorEntry => ({
      id: row.id,
      key: row.key,
      content: row.content,
      kind: row.kind,
      status: row.status,
    }),
  );
  const foundational: OperatorEntry[] = [];
  const contextual: OperatorEntry[] = [];
  for (const entry of all) {
    if (isFoundational(entry.key)) foundational.push(entry);
    else contextual.push(entry);
  }
  const selected: OperatorEntry[] = [];
  const accountHeader = limit > OPERATOR_HEADER.length;
  let chars = accountHeader ? OPERATOR_HEADER.length : 0;
  for (const entry of [...foundational, ...contextual]) {
    const cost = accountHeader
      ? operatorLineCost(entry)
      : operatorEntryCost(entry);
    if (chars + cost > limit) continue;
    selected.push(entry);
    chars += cost;
  }
  return selected;
}

function operatorEntryCost(entry: OperatorEntry): number {
  return entry.key.length + 2 + entry.content.length + 1;
}

function operatorLineCost(entry: OperatorEntry): number {
  return 1 + 1 + entry.key.length + 2 + entry.content.length;
}

const TARGET_PREFIX =
  /^(?:scope|target|cible|client|engagement|mission|project|projet|perimetre|perimeter|abandon|exploitation|authorized|autorise|exclude|exclusion|out-of-scope|in-scope|host|domain|asset|env|environment|deep-enumeration)-/i;
const DATED_KEY = /\b\d{4}-\d{2}-\d{2}\b/;

function isFoundational(key: string): boolean {
  return !TARGET_PREFIX.test(key) && !DATED_KEY.test(key);
}

/**
 * The text a host injects for the operator rules.
 *
 * Each rule is a single line prefixed by its key. The compact format avoids
 * the JSON overhead (id, kind, status fields) that inflated the block by ~40%.
 */
export function operatorBlock(entries: OperatorEntry[]): string {
  if (!entries.length) return "";
  const lines = [OPERATOR_HEADER];
  for (const entry of entries) {
    lines.push(`[${entry.key}] ${entry.content}`);
  }
  return lines.join("\n");
}

/** The rules of a store, as the host would inject them, for one scope. */
export function operatorContext(
  store: StorePort,
  scope: string,
  budget: ContextBudget,
): { entries: OperatorEntry[]; block: string; chars: number } {
  const entries = operatorSnapshot(store, scope, budget);
  const block = operatorBlock(entries);
  return { entries, block, chars: block.length };
}

/** The knowledge records that are not operator rules, for a host that wants them. */
export function learnedKnowledge(
  store: StorePort,
  scope: string,
): KnowledgeRecord[] {
  return store
    .getKnowledge(scope, undefined, 200)
    .filter((row) => row.kind !== "operator");
}
