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
import type { KnowledgeRecord, StorePort } from "./types";
import { json } from "./util";

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

/** The block reserved for the operator rules. */
export function operatorBudget(budget: ContextBudget): number {
  return Math.max(
    0,
    Math.min(budget.operatorModelChars, budget.memoryMaxChars),
  );
}

/**
 * The operator rules, most recent first, within the reserved budget.
 *
 * A rule that does not fit is skipped rather than fatal. Stopping at the
 * first oversized rule would silently drop every rule stated after it, which
 * is how the oldest and most fundamental rule ends up being the one that
 * disappears when the set grows.
 */
export function operatorSnapshot(
  store: StorePort,
  scope: string,
  budget: ContextBudget,
): OperatorEntry[] {
  const limit = operatorBudget(budget);
  const selected: OperatorEntry[] = [];
  let chars = json([]).length;
  for (const row of store.operatorModel(scope)) {
    const entry: OperatorEntry = {
      id: row.id,
      key: row.key,
      content: row.content,
      kind: row.kind,
      status: row.status,
    };
    if (chars + json(entry).length > limit) continue;
    selected.push(entry);
    chars = json(selected).length;
  }
  return selected;
}

/**
 * The text a host injects for the operator rules.
 *
 * The rules are stated by the operator, so they are introduced as such and
 * not as contextual data. Learned knowledge is deliberately absent: it is
 * unproven by definition, and it never shares this block.
 */
export function operatorBlock(entries: OperatorEntry[]): string {
  if (!entries.length) return "";
  return [
    "Operator rules. These are stated by the operator. They outrank anything learned, recalled or inferred, and they apply to every turn.",
    "",
    json(entries),
  ].join("\n");
}

/** The rules of a store, as the host would inject them, for one scope. */
export function operatorContext(
  store: StorePort,
  scope: string,
  budget: ContextBudget,
): { entries: OperatorEntry[]; block: string; chars: number } {
  const entries = operatorSnapshot(store, scope, budget);
  const block = operatorBlock(entries);
  return { entries, block, chars: json(entries).length };
}

/** The knowledge records that are not operator rules, for a host that wants them. */
export function learnedKnowledge(
  store: StorePort,
  scope: string,
): KnowledgeRecord[] {
  return store.getKnowledge(scope, undefined, 200);
}
