/**
 * What the harness loaded for a turn, and what it skipped.
 *
 * This is host-neutral on purpose: it describes a selection, not the mechanism
 * that produced it. Each host fills it in its own terms.
 */
export interface SkillActivation {
  name: string;
  filePath: string;
  tier: "global" | "project" | "learned";
  reason: string;
  hash: string;
  chars: number;
  version?: number;
}

export interface SkillTrace {
  enabled: boolean;
  loaded: SkillActivation[];
  skipped: { name: string; reason: string }[];
  chars: number;
  maxChars: number;
}
