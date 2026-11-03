import * as fs from "node:fs";
import * as path from "node:path";
import { randomUUID } from "node:crypto";
import {
  DEFAULT_CONFIG,
  SKILL_DOMAINS,
  type HarnessConfig,
  type LearningCategory,
  type Observation,
  type SkillProposal,
  type SkillRevision,
  type StorePort,
} from "./types";
import { assertLearningText, hash } from "./util";

const CATEGORIES: readonly LearningCategory[] = [
  "false-positive-patterns",
  "tool-usage-patterns",
  "investigation-patterns",
  "environment-patterns",
];
interface Index {
  latestVersion: number;
  activeVersion: number | null;
}
interface State {
  category: LearningCategory;
  index: Index;
  latest: SkillRevision;
  active: SkillRevision | null;
}
interface Support {
  confidence: number;
  sourceSessions: string[];
  lastVerified: string | null;
  failed: boolean;
  supportingSessions: number;
}

/**
 * The scope a method leaves its project for. Only methods travel: what one
 * target answered is worthless on the next and would carry one engagement
 * into another.
 */
export const GLOBAL_SCOPE = "global";

function validScope(scope: string): void {
  if (scope === GLOBAL_SCOPE) return;
  if (
    typeof scope !== "string" ||
    scope.length !== 32 ||
    !/^project-[a-f0-9]{24}$/.test(scope)
  )
    throw new Error("Invalid project scope slug");
}
function validName(name: string): void {
  if (
    typeof name !== "string" ||
    name !== name.trim() ||
    name.length > 31 ||
    !/^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$/.test(name) ||
    /^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])$/i.test(name)
  )
    throw new Error("Invalid learned skill name");
}
function identifier(value: string): void {
  if (
    typeof value !== "string" ||
    value !== value.trim() ||
    !/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/.test(value)
  )
    throw new Error("Invalid evidence or session identifier");
  assertLearningText(value);
}
function learningText(value: string): void {
  assertLearningText(value);
  if (/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/u.test(value))
    throw new Error("Control characters are not accepted in learned skills");
}
function proposalCopy(proposal: SkillProposal, promoted = false): SkillProposal {
  if (!proposal || typeof proposal !== "object")
    throw new Error("Invalid skill proposal");
  validName(proposal.name);
  if (!CATEGORIES.includes(proposal.category))
    throw new Error("Invalid learning category");
  if (
    proposal.domains !== undefined &&
    (!Array.isArray(proposal.domains) ||
      proposal.domains.length > 8 ||
      proposal.domains.some((domain) => !SKILL_DOMAINS.includes(domain)))
  )
    throw new Error("Invalid skill domain");
  learningText(proposal.description);
  for (const [items, required] of [
    [proposal.prerequisites, false],
    [proposal.procedure, true],
  ] as const) {
    if (
      !Array.isArray(items) ||
      items.length > 100 ||
      (required && !items.length)
    )
      throw new Error("Invalid skill instruction list");
    items.forEach(learningText);
  }
  if (promoted) {
    // A global method has no evidence of its own: the observations that proved
    // it stay in the project, where they can be replayed.
    if (
      !Array.isArray(proposal.evidence) ||
      proposal.evidence.length ||
      !Array.isArray(proposal.validation) ||
      proposal.validation.length
    )
      throw new Error("A promoted method carries no project evidence");
  } else {
    if (
      !Array.isArray(proposal.evidence) ||
      !proposal.evidence.length ||
      proposal.evidence.length > 200
    )
      throw new Error("Evidence is required");
    proposal.evidence.forEach(identifier);
    if (
      !Array.isArray(proposal.validation) ||
      !proposal.validation.length ||
      proposal.validation.length > 200
    )
      throw new Error("Observed validation is required");
    for (const check of proposal.validation) {
      if (!check || typeof check !== "object")
        throw new Error("Invalid evidence check");
      identifier(check.observationId);
      learningText(check.contains);
      const meaningful = check.contains.trim();
      if (
        meaningful.length < 4 ||
        (meaningful.match(/[\p{L}\p{N}]/gu) ?? []).length < 3 ||
        /^(?:ok|true|false|null|undefined|success|done|pass|fail|failed|error)$/i.test(
          meaningful,
        )
      )
        throw new Error("Validation must contain a meaningful observed string");
      if (!proposal.evidence.includes(check.observationId))
        throw new Error("Validation observation must be in evidence");
    }
  }
  const authored = [
    proposal.description,
    ...proposal.prerequisites,
    ...proposal.procedure,
    ...proposal.validation.map((check) => check.contains),
  ];
  if (authored.reduce((size, text) => size + text.length, 0) > 24000)
    throw new Error("Learned skill content is too large");
  const checks = new Map(
    proposal.validation.map((check) => [
      JSON.stringify([check.observationId, check.contains]),
      { observationId: check.observationId, contains: check.contains },
    ]),
  );
  return {
    name: proposal.name,
    description: proposal.description,
    category: proposal.category,
    domains: [...new Set(proposal.domains ?? [])].sort(),
    prerequisites: [...proposal.prerequisites],
    procedure: [...proposal.procedure],
    validation: [...checks.values()],
    evidence: [...new Set(proposal.evidence)],
  };
}
const NARRATIVE =
  /\b(?:this session|today'?s session|the user asked|l'op[ée]rateur a demand[ée]|on a essay[ée]|we tried several|aucun n'a march[ée]|check manually|v[ée]rifier manuellement)\b|\b(?:PR|issue|ticket)\s*#?\d+\b/i;
const PREFERENCE =
  /\b(?:the user prefers|user preference|always reply|always respond|r[ée]pondre en fran[çc]ais|pr[ée]f[èe]re que|standing preference|ne jamais utiliser d'emoji)\b/i;
const ACTION =
  /\b(?:read|run|use|confirm|extract|open|launch|check|parse|map|crop|verify|call|query|list|search|lire|lancer|confirmer|extraire|v[ée]rifier|appeler)\b/i;
/** A skill is a method a later session can follow. A diary, a dead end, or a preference is not. */
export function assertReusableMethod(proposal: SkillProposal): void {
  const authored = [proposal.description, ...proposal.procedure].join("\n");
  if (NARRATIVE.test(authored))
    throw new Error("A skill must be a reusable method, not a session narrative");
  if (PREFERENCE.test(authored) && !proposal.procedure.some((step) => ACTION.test(step)))
    throw new Error("A stated preference belongs in operator memory, not a skill");
}
function sameProcedure(left: SkillProposal, right: SkillProposal): boolean {
  return (
    JSON.stringify([
      left.description,
      left.domains ?? [],
      left.prerequisites,
      left.procedure,
    ]) ===
    JSON.stringify([
      right.description,
      right.domains ?? [],
      right.prerequisites,
      right.procedure,
    ])
  );
}
function markdown(value: string): string {
  return value.replace(/[\\`*_[\]<>#]/g, "\\$&").replace(/\r?\n/g, " ");
}
function runtimeNameFor(scope: string, name: string): string {
  return `learned-${scope === GLOBAL_SCOPE ? "global" : scope.slice(8)}-${name}`;
}
function render(revision: SkillRevision): string {
  const runtimeName = runtimeNameFor(revision.scope, revision.name);
  const observationLink = (id: string) =>
    `cyber-harness://observations/${revision.scope}/${encodeURIComponent(id)}`;
  const promoted = revision.scope === GLOBAL_SCOPE;
  return [
    "---",
    `name: ${JSON.stringify(runtimeName)}`,
    `description: ${JSON.stringify(revision.description)}`,
    "metadata:",
    `  version: ${revision.version}`,
    `  confidence: ${revision.confidence}`,
    `  scope: ${JSON.stringify(revision.scope)}`,
    `  status: ${JSON.stringify(revision.status)}`,
    `  domains: ${JSON.stringify(revision.domains ?? [])}`,
    `  last_verified: ${JSON.stringify(revision.lastVerified)}`,
    "---",
    "",
    `# ${revision.name}`,
    "",
    "## Prerequisites",
    "",
    ...(revision.prerequisites.length
      ? revision.prerequisites.map((item) => `- ${item}`)
      : ["No additional prerequisites."]),
    "",
    "## Procedure",
    "",
    ...revision.procedure.map((item, index) => `${index + 1}. ${item}`),
    "",
    ...(promoted
      ? [
          "## Provenance",
          "",
          `A method promoted from ${revision.promotedFrom?.length ?? 0} project scope(s). The observations that proved it stay in the project that produced them.`,
          "",
          ...(revision.promotedFrom ?? []).map((slug) => `- ${slug}`),
          "",
        ]
      : [
          "## Validation",
          "",
          ...revision.validation.map(
            (check) =>
              `- [Observation ${markdown(check.observationId)}](${observationLink(check.observationId)}) contains: ${markdown(JSON.stringify(check.contains))}`,
          ),
          "",
          "## Evidence",
          "",
          ...revision.evidence.map(
            (id) => `- [Observation ${markdown(id)}](${observationLink(id)})`,
          ),
          "",
          "### Source sessions",
          "",
          ...revision.sourceSessions.map(
            (id) =>
              `- [Session ${markdown(id)}](cyber-harness://sessions/${revision.scope}/${encodeURIComponent(id)})`,
          ),
          "",
        ]),
  ].join("\n");
}

const FILE_EXTENSION =
  /\.(?:js|mjs|cjs|ts|tsx|jsx|json|jsonl|map|md|txt|log|html|htm|css|scss|py|sh|bash|ps1|yml|yaml|toml|ini|conf|cfg|xml|sql|db|sqlite|sqlite3|pem|crt|key|csv|tsv|pdf|docx|xlsx|pptx|zip|tar|gz|b64|apk|jar|so|dll|exe|bin|img|iso|png|jpe?g|gif|svg|webp|mp4|webm|wav|mp3|go|rs|java|rb|php|c|h|cpp|hpp|cs|kt|swift|dart)$/i;

/** Things that make a method belong to one engagement and nowhere else. */
const LOCAL_DETAIL: readonly [RegExp, string][] = [
  [/\bhttps?:\/\//i, "a URL"],
  [/\bwww\./i, "a URL"],
  [/\b\d{1,3}(?:\.\d{1,3}){3}\b/, "an IP address"],
  [/\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b/i, "an email address"],
  [/\b[A-Fa-f0-9]{32,}\b/, "a hash or a key"],
  [/\b[A-Za-z0-9+/_-]{32,}={0,2}\b/, "a token"],
];
const HOSTNAME = /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b/gi;

function hostnames(text: string): string[] {
  const found: string[] = [];
  for (const token of text.match(HOSTNAME) ?? []) {
    // A file name is not a host, and neither is an abbreviation or a version.
    if (FILE_EXTENSION.test(token)) continue;
    if (/^\d/.test(token)) continue;
    if (/^[a-z]\.[a-z]$/i.test(token)) continue;
    if (/^(?:e\.g|i\.e|etc|cf|vs|ex)\./i.test(token)) continue;
    found.push(token);
  }
  return found;
}

/**
 * A method that crosses into every project must not carry the project with it.
 * A host, an address or a key is what makes a method local, so the promotion
 * is refused rather than quietly rewritten: what is shared stays the
 * operator's decision.
 */
export function assertGloballyReusable(revision: SkillProposal): void {
  const authored = [
    revision.description,
    ...revision.prerequisites,
    ...revision.procedure,
  ];
  const text = authored.join("\n");
  for (const [pattern, what] of LOCAL_DETAIL)
    if (pattern.test(text))
      throw new Error(
        `A global method cannot carry ${what}: it belongs to the project`,
      );
  const hosts = hostnames(text);
  if (hosts.length)
    throw new Error(
      "A global method cannot name a host: it belongs to the project",
    );
}

/** Evidence-backed skills. Only paths() results are intended for runtime discovery. */
export class SkillUpdater {
  private readonly root: string;
  private readonly store: StorePort;
  private readonly minimumSessions: number;
  private readonly minimumConfidence: number;

  constructor(
    stateRoot: string,
    store: StorePort,
    config: Pick<
      HarnessConfig,
      "minimumSkillSessions" | "minimumSkillConfidence"
    >,
  ) {
    if (typeof stateRoot !== "string" || !stateRoot.trim())
      throw new Error("Invalid skill state root");
    this.root = path.join(path.resolve(stateRoot), "skills");
    this.store = store;
    this.minimumSessions =
      config?.minimumSkillSessions ?? DEFAULT_CONFIG.minimumSkillSessions;
    this.minimumConfidence =
      config?.minimumSkillConfidence ?? DEFAULT_CONFIG.minimumSkillConfidence;
    if (
      !Number.isSafeInteger(this.minimumSessions) ||
      this.minimumSessions < 1 ||
      !Number.isFinite(this.minimumConfidence) ||
      this.minimumConfidence < 0 ||
      this.minimumConfidence > 1
    )
      throw new Error("Invalid skill activation thresholds");
    this.guard();
    this.createDirectory(this.root);
    for (const tree of ["candidates", "revisions", "learned"])
      this.createDirectory(path.join(this.root, tree));
  }

  propose(
    scope: string,
    proposal: SkillProposal,
    stated?: string,
  ): SkillRevision {
    this.begin(scope);
    if (scope === GLOBAL_SCOPE)
      throw new Error(
        "A method reaches the global scope by promotion, not by proposal",
      );
    const operatorStated = stated?.trim() ?? "";
    if (!operatorStated) assertReusableMethod(proposal);
    else this.store.audit(scope, "skill.operator-priority", {
      name: proposal.name,
      stated: operatorStated.slice(0, 500),
    });
    let incoming = proposalCopy(proposal);
    // Check the caller's evidence before merging: an old valid check must not mask a fabricated new one.
    this.support(scope, incoming);
    const state = this.state(scope, incoming.name);
    if (state && state.category !== incoming.category)
      throw new Error("A logical skill cannot change learning category");
    this.checkRuntime(scope, incoming.name, incoming.category, state);
    if (state && sameProcedure(state.latest, incoming)) {
      incoming = proposalCopy({
        ...incoming,
        evidence: [
          ...new Set([...state.latest.evidence, ...incoming.evidence]),
        ],
        validation: [...state.latest.validation, ...incoming.validation],
      });
    }
    const support = this.support(scope, incoming);
    if (support.supportingSessions < 1)
      throw new Error("Unresolved failure is not a method");
    const status = this.canActivate(support) ? "active" : "candidate";
    if (
      state &&
      status === state.latest.status &&
      JSON.stringify(proposalCopy(state.latest)) === JSON.stringify(incoming)
    )
      return state.latest;
    const revision = this.revision(scope, incoming, status, support);
    this.publish(revision, state);
    this.store.audit(
      scope,
      status === "active" ? "skill.activated" : "skill.candidate",
      this.auditDetail(revision),
    );
    return revision;
  }

  list(scope: string): SkillRevision[] {
    this.begin(scope);
    return this.visible(scope)
      .map((state) => state.latest)
      .sort((left, right) => left.name.localeCompare(right.name));
  }

  load(
    scope: string,
    name: string,
  ): { revision: SkillRevision; content: string } {
    this.begin(scope);
    validName(name);
    const state = this.visible(scope).find((row) => row.latest.name === name);
    if (!state?.active) throw new Error("No active learned skill");
    const owner = state.latest.scope;
    const content = this.checkRuntime(owner, name, state.category, state);
    return { revision: state.active, content: content! };
  }

  paths(scope: string): string[] {
    return this.active(scope).map((skill) => skill.filePath);
  }

  /** Includes an older active version while the latest revision is still a candidate. */
  active(scope: string): { revision: SkillRevision; filePath: string }[] {
    this.begin(scope);
    return this.visible(scope)
      .filter((state) => state.active)
      .sort((left, right) => left.latest.name.localeCompare(right.latest.name))
      .map((state) => {
        const owner = state.latest.scope;
        this.checkRuntime(owner, state.latest.name, state.category, state);
        return {
          revision: state.active!,
          filePath: this.runtimeFile(owner, state.category, state.latest.name),
        };
      });
  }

  /**
   * Promote an active method out of its project. The method crosses; its
   * evidence does not, and a method that names a host, an address or a key is
   * refused: what is shared must not carry one engagement into the next.
   */
  promote(scope: string, name: string): SkillRevision {
    this.begin(scope);
    if (scope === GLOBAL_SCOPE)
      throw new Error("A global method is already shared");
    validName(name);
    const target = this.state(GLOBAL_SCOPE, name);
    const state = this.state(scope, name);
    if (!state?.active) {
      // The method is visible here through the global scope only: it is
      // already shared and there is nothing to promote.
      if (target?.active) return target.active;
      throw new Error(
        "Only an active method can be promoted: a candidate has no confirmed use",
      );
    }
    const active = state.active;
    assertGloballyReusable(active);
    const incoming = proposalCopy(
      { ...active, evidence: [], validation: [] },
      true,
    );
    if (target && target.category !== incoming.category)
      throw new Error("A logical skill cannot change learning category");
    if (
      target &&
      sameProcedure(target.latest, incoming) &&
      target.latest.status === "active" &&
      (target.latest.promotedFrom ?? []).includes(scope)
    )
      return target.latest;
    const from = [...new Set([...(target?.latest.promotedFrom ?? []), scope])].sort();
    const support: Support = {
      confidence: Math.max(active.confidence, target?.latest.confidence ?? 0),
      sourceSessions: [],
      lastVerified: active.lastVerified,
      failed: false,
      supportingSessions: from.length,
    };
    const revision = this.revision(
      GLOBAL_SCOPE,
      incoming,
      "active",
      support,
      from,
    );
    this.publish(revision, target);
    this.store.audit(scope, "skill.promoted", {
      name,
      to: GLOBAL_SCOPE,
      version: revision.version,
      promotedFrom: from,
    });
    return revision;
  }

  rollback(scope: string, name: string, version: number): SkillRevision {
    this.begin(scope);
    if (scope === GLOBAL_SCOPE)
      throw new Error("A shared method is retired by deprecation, not rolled back");
    validName(name);
    if (!Number.isSafeInteger(version) || version < 1)
      throw new Error("Invalid archived skill version");
    const state = this.state(scope, name);
    if (!state) throw new Error("No skill history to roll back");
    this.checkRuntime(scope, name, state.category, state);
    if (state.index.activeVersion === version)
      throw new Error(
        "Rollback requires an archived, not current, active version",
      );
    const archived = this.readRevision(scope, state.category, name, version);
    if (archived.status !== "active")
      throw new Error(
        "Rollback requires a previously published active version",
      );
    const proposal = proposalCopy(archived);
    const support = this.support(scope, proposal);
    if (!this.canActivate(support))
      throw new Error(
        "Archived skill no longer has sufficient successful evidence",
      );
    const revision = this.revision(scope, proposal, "active", support);
    this.publish(revision, state);
    this.store.audit(scope, "skill.rollback", {
      ...this.auditDetail(revision),
      fromVersion: state.index.activeVersion,
      archivedVersion: version,
    });
    return revision;
  }

  /** Archive an active learned skill that has not been used inside the idle window. Never deletes the revision. */
  archiveUnused(
    scope: string,
    exposures: { detail: string; timestamp: string }[] = [],
    idleDays = 45,
    now = Date.now(),
  ): string[] {
    this.begin(scope);
    if (!Number.isFinite(idleDays) || idleDays < 1 || idleDays > 3650)
      throw new Error("Invalid skill archive window");
    const idleMs = idleDays * 86_400_000;
    const lastUsed = new Map<string, number>();
    for (const row of exposures) {
      const at = Date.parse(row.timestamp);
      if (!Number.isFinite(at)) continue;
      let skills: { name?: string }[] = [];
      try {
        const detail = JSON.parse(row.detail);
        if (Array.isArray(detail?.skills)) skills = detail.skills;
      } catch {
        continue;
      }
      for (const skill of skills) {
        if (typeof skill?.name !== "string") continue;
        lastUsed.set(skill.name, Math.max(lastUsed.get(skill.name) ?? 0, at));
      }
    }
    const archived: string[] = [];
    for (const state of this.states(scope)) {
      if (!state.active) continue;
      const verified = Date.parse(state.active.lastVerified ?? "");
      const seen = lastUsed.get(state.active.name);
      const latest = Math.max(
        Number.isFinite(verified) ? verified : 0,
        seen ?? 0,
      );
      if (!latest || now - latest < idleMs) continue;
      try {
        this.store.audit(scope, "skill.curator", {
          name: state.active.name,
          idleDays,
          lastSeen: new Date(latest).toISOString(),
        });
        this.deprecate(scope, state.active.name);
        archived.push(state.active.name);
      } catch {
        continue;
      }
    }
    return archived.sort();
  }

  deprecate(scope: string, name: string): void {
    this.begin(scope);
    validName(name);
    const state = this.state(scope, name);
    if (!state) throw new Error("No learned skill to deprecate");
    this.checkRuntime(scope, name, state.category, state);
    if (state.latest.status === "deprecated") return;
    const previous = state.active ?? state.latest;
    // Deprecation does not require available or still-successful evidence.
    const revision = this.revision(
      scope,
      proposalCopy(previous, previous.scope === GLOBAL_SCOPE),
      "deprecated",
      {
        confidence: previous.confidence,
        sourceSessions: previous.sourceSessions,
        lastVerified: previous.lastVerified,
        failed: false,
        supportingSessions: 0,
      },
      previous.promotedFrom ? [...previous.promotedFrom] : undefined,
    );
    this.publish(revision, state);
    this.store.audit(scope, "skill.deprecated", this.auditDetail(revision));
  }

  private begin(scope: string): void {
    validScope(scope);
    this.guard();
  }
  private canActivate(support: Support): boolean {
    return (
      !support.failed &&
      support.supportingSessions >= this.minimumSessions &&
      support.confidence >= this.minimumConfidence
    );
  }
  private support(scope: string, proposal: SkillProposal): Support {
    const observations = this.store.evidence(scope, [...proposal.evidence]);
    if (!Array.isArray(observations))
      throw new Error("Invalid evidence response");
    const byId = new Map<string, Observation>();
    for (const observation of observations) {
      if (
        !observation ||
        !proposal.evidence.includes(observation.id) ||
        byId.has(observation.id)
      )
        throw new Error("Unexpected or duplicate evidence");
      if (observation.scope !== scope)
        throw new Error("Evidence belongs to another scope");
      identifier(observation.id);
      identifier(observation.sessionId);
      if (
        typeof observation.success !== "boolean" ||
        typeof observation.output !== "string" ||
        typeof observation.timestamp !== "string" ||
        !Number.isFinite(Date.parse(observation.timestamp))
      )
        throw new Error("Invalid observation evidence");
      byId.set(observation.id, observation);
    }
    for (const id of proposal.evidence)
      if (!byId.has(id))
        throw new Error("Referenced evidence does not exist in this scope");
    for (const check of proposal.validation) {
      if (!byId.get(check.observationId)!.output.includes(check.contains))
        throw new Error(
          "Validation string is not present in the observed output",
        );
    }
    const successes = new Set<string>();
    const failures = new Set<string>();
    let lastVerified: string | null = null;
    for (const observation of byId.values()) {
      (observation.success ? successes : failures).add(observation.sessionId);
      if (
        observation.success &&
        (!lastVerified ||
          Date.parse(observation.timestamp) > Date.parse(lastVerified))
      )
        lastVerified = new Date(observation.timestamp).toISOString();
    }
    return {
      confidence: successes.size / (successes.size + failures.size),
      sourceSessions: [...new Set([...successes, ...failures])].sort(),
      lastVerified,
      failed: failures.size > 0,
      supportingSessions: successes.size,
    };
  }

  private revision(
    scope: string,
    proposal: SkillProposal,
    status: SkillRevision["status"],
    support: Support,
    promotedFrom?: string[],
  ): SkillRevision {
    const revision: SkillRevision = {
      ...proposal,
      scope,
      status,
      version: this.nextVersion(scope, proposal.category, proposal.name),
      confidence: support.confidence,
      sourceSessions: [...support.sourceSessions],
      lastVerified: support.lastVerified,
      contentHash: "",
      ...(promotedFrom ? { promotedFrom: [...promotedFrom] } : {}),
    };
    revision.contentHash = hash(render(revision));
    return revision;
  }
  private archiveDirectory(
    scope: string,
    category: LearningCategory,
    name: string,
  ): string {
    return path.join(this.root, "revisions", scope, category, name);
  }
  private candidateFile(
    scope: string,
    category: LearningCategory,
    name: string,
  ): string {
    return path.join(
      this.root,
      "candidates",
      scope,
      category,
      name,
      "revision.json",
    );
  }
  private runtimeFile(
    scope: string,
    category: LearningCategory,
    name: string,
  ): string {
    return path.join(
      this.root,
      "learned",
      scope,
      category,
      runtimeNameFor(scope, name),
      "SKILL.md",
    );
  }
  private nextVersion(
    scope: string,
    category: LearningCategory,
    name: string,
  ): number {
    const directory = this.archiveDirectory(scope, category, name);
    if (!this.ownedStat(directory)) return 1;
    let maximum = 0;
    for (const entry of fs.readdirSync(directory)) {
      const match = /^([1-9][0-9]*)\.(?:json|md)$/.exec(entry);
      if (match) maximum = Math.max(maximum, Number(match[1]));
    }
    if (!Number.isSafeInteger(maximum + 1))
      throw new Error("Skill version limit reached");
    return maximum + 1;
  }

  private state(scope: string, name: string): State | null {
    let result: State | null = null;
    for (const category of CATEGORIES) {
      const file = path.join(
        this.archiveDirectory(scope, category, name),
        "index.json",
      );
      if (!this.ownedStat(file)) continue;
      if (result)
        throw new Error("Logical skill has multiple learning categories");
      const index = JSON.parse(this.readFile(file)) as Index;
      if (
        !index ||
        !Number.isSafeInteger(index.latestVersion) ||
        index.latestVersion < 1 ||
        (index.activeVersion !== null &&
          (!Number.isSafeInteger(index.activeVersion) ||
            index.activeVersion < 1 ||
            index.activeVersion > index.latestVersion))
      )
        throw new Error("Invalid skill revision index");
      const latest = this.readRevision(
        scope,
        category,
        name,
        index.latestVersion,
      );
      const active =
        index.activeVersion === null
          ? null
          : this.readRevision(scope, category, name, index.activeVersion);
      if (active && active.status !== "active")
        throw new Error("Invalid active skill revision index");
      if (
        (latest.status === "active" &&
          index.activeVersion !== latest.version) ||
        (latest.status === "deprecated" && active)
      )
        throw new Error("Inconsistent skill revision index");
      result = { category, index, latest, active };
    }
    return result;
  }
  private states(scope: string): State[] {
    const names = new Set<string>();
    for (const category of CATEGORIES) {
      const directory = path.join(this.root, "revisions", scope, category);
      if (!this.ownedStat(directory)) continue;
      for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
        if (!entry.isDirectory()) continue;
        validName(entry.name);
        names.add(entry.name);
      }
    }
    return [...names]
      .map((name) => this.state(scope, name))
      .filter((state): state is State => state !== null);
  }

  /**
   * What a project can see: its own methods, then the global ones. A project
   * method of the same name wins, so a local correction stays local until it
   * is promoted in turn.
   */
  private visible(scope: string): State[] {
    const local = this.states(scope);
    if (scope === GLOBAL_SCOPE) return local;
    const names = new Set(local.map((state) => state.latest.name));
    return [
      ...local,
      ...this.states(GLOBAL_SCOPE).filter(
        (state) => !names.has(state.latest.name),
      ),
    ];
  }
  private readRevision(
    scope: string,
    category: LearningCategory,
    name: string,
    version: number,
  ): SkillRevision {
    const directory = this.archiveDirectory(scope, category, name);
    const stored = JSON.parse(
      this.readFile(path.join(directory, `${version}.json`)),
    ) as SkillRevision;
    const shared = stored.scope === GLOBAL_SCOPE;
    const proposal = proposalCopy(stored, shared);
    if (
      stored.scope !== scope ||
      stored.name !== name ||
      stored.category !== category ||
      stored.version !== version ||
      !["candidate", "active", "deprecated"].includes(stored.status) ||
      !Number.isFinite(stored.confidence) ||
      stored.confidence < 0 ||
      stored.confidence > 1 ||
      !Array.isArray(stored.sourceSessions) ||
      stored.sourceSessions.length > 200 ||
      (!shared && !stored.sourceSessions.length) ||
      (stored.lastVerified !== null &&
        (typeof stored.lastVerified !== "string" ||
          !Number.isFinite(Date.parse(stored.lastVerified)))) ||
      typeof stored.contentHash !== "string" ||
      !/^[a-f0-9]{64}$/.test(stored.contentHash)
    )
      throw new Error("Invalid archived skill revision");
    if (shared) {
      if (
        !Array.isArray(stored.promotedFrom) ||
        !stored.promotedFrom.length ||
        stored.promotedFrom.length > 200 ||
        stored.promotedFrom.some(
          (slug) =>
            typeof slug !== "string" ||
            !/^project-[a-f0-9]{24}$/.test(slug),
        )
      )
        throw new Error("Invalid promoted method provenance");
    } else if (stored.promotedFrom !== undefined) {
      throw new Error("A project method cannot carry shared provenance");
    }
    stored.sourceSessions.forEach(identifier);
    const revision: SkillRevision = {
      ...proposal,
      scope,
      version,
      status: stored.status,
      confidence: stored.confidence,
      sourceSessions: [...stored.sourceSessions],
      lastVerified: stored.lastVerified,
      contentHash: stored.contentHash,
      ...(shared ? { promotedFrom: [...stored.promotedFrom!] } : {}),
    };
    const content = this.readFile(path.join(directory, `${version}.md`));
    if (hash(content) !== revision.contentHash || render(revision) !== content)
      throw new Error("Archived skill content hash mismatch");
    return revision;
  }

  private checkRuntime(
    scope: string,
    name: string,
    category: LearningCategory,
    state: State | null,
  ): string | null {
    const file = this.runtimeFile(scope, category, name);
    const present = this.ownedStat(file);
    if (!state?.active) {
      if (present)
        throw new Error("Refusing to overwrite an untracked learned skill");
      return null;
    }
    if (!present)
      throw new Error(
        "Stale active skill: runtime file was removed externally",
      );
    const content = this.readFile(file);
    if (hash(content) !== state.active.contentHash)
      throw new Error(
        "Stale active skill: external edit changed its content hash",
      );
    return content;
  }
  private publish(revision: SkillRevision, state: State | null): void {
    const { scope, category, name, version } = revision;
    this.guard();
    this.checkRuntime(scope, name, category, state);
    const directory = this.archiveDirectory(scope, category, name);
    const content = render(revision);
    this.createDirectory(directory);
    // Archives are append-only, including candidate and deprecated records. Never replace an archive.
    this.writeNew(path.join(directory, `${version}.md`), content);
    this.writeNew(
      path.join(directory, `${version}.json`),
      `${JSON.stringify(revision, null, 2)}\n`,
    );
    const candidate = this.candidateFile(scope, category, name);
    if (revision.status === "active") {
      this.writeMutable(this.runtimeFile(scope, category, name), content, () =>
        this.checkRuntime(scope, name, category, state),
      );
      this.removeFile(candidate);
    } else if (revision.status === "candidate") {
      this.writeMutable(candidate, `${JSON.stringify(revision, null, 2)}\n`);
    } else {
      this.checkRuntime(scope, name, category, state);
      this.removeFile(this.runtimeFile(scope, category, name));
      this.removeFile(candidate);
    }
    const index: Index = {
      latestVersion: version,
      activeVersion:
        revision.status === "active"
          ? version
          : revision.status === "deprecated"
            ? null
            : (state?.index.activeVersion ?? null),
    };
    this.writeMutable(
      path.join(directory, "index.json"),
      `${JSON.stringify(index)}\n`,
    );
  }
  private auditDetail(revision: SkillRevision): object {
    return {
      name: revision.name,
      category: revision.category,
      version: revision.version,
      status: revision.status,
      confidence: revision.confidence,
      sourceSessions: revision.sourceSessions,
      evidence: revision.evidence,
      contentHash: revision.contentHash,
    };
  }

  // Reject symlinks (including Windows junctions), redirected/reparse ancestors, and multiply-linked files.
  // Check the whole owned tree at entry, and check individual paths again immediately before I/O.
  private nodeStat(file: string): fs.Stats | undefined {
    const stat = fs.lstatSync(file, { throwIfNoEntry: false });
    if (!stat) return undefined;
    if (stat.isSymbolicLink() || (!stat.isDirectory() && !stat.isFile()))
      throw new Error(
        "Symlink or special path is not allowed in learned skills",
      );
    if (stat.isFile() && stat.nlink > 1)
      throw new Error("Hard-linked learned skill files are not allowed");
    const canonical = fs.realpathSync.native(file);
    const compare = (value: string) =>
      process.platform === "win32"
        ? path.normalize(value).toLowerCase()
        : path.normalize(value);
    if (compare(canonical) !== compare(path.resolve(file)))
      throw new Error("Reparse or redirected skill path is not allowed");
    return stat;
  }
  private ancestors(file: string): void {
    const absolute = path.resolve(file);
    const root = path.parse(absolute).root;
    let current = root;
    this.nodeStat(root);
    for (const segment of path
      .relative(root, absolute)
      .split(path.sep)
      .filter(Boolean)) {
      current = path.join(current, segment);
      this.nodeStat(current);
    }
  }
  private ownedStat(file: string): fs.Stats | undefined {
    const relative = path.relative(this.root, path.resolve(file));
    if (
      relative === ".." ||
      relative.startsWith(`..${path.sep}`) ||
      path.isAbsolute(relative)
    )
      throw new Error("Path escapes the owned learned skill tree");
    this.ancestors(file);
    return this.nodeStat(file);
  }
  private guard(): void {
    this.ancestors(this.root);
    if (!this.nodeStat(this.root)) return;
    const directories = [this.root];
    while (directories.length) {
      const directory = directories.pop()!;
      const stat = this.nodeStat(directory);
      if (!stat?.isDirectory())
        throw new Error("Invalid learned skill root directory");
      for (const entry of fs.readdirSync(directory)) {
        const file = path.join(directory, entry);
        if (this.nodeStat(file)?.isDirectory()) directories.push(file);
      }
    }
  }
  private createDirectory(directory: string): void {
    this.ownedStat(directory);
    const absolute = path.resolve(directory);
    const root = path.parse(absolute).root;
    let current = root;
    for (const segment of path
      .relative(root, absolute)
      .split(path.sep)
      .filter(Boolean)) {
      current = path.join(current, segment);
      let stat = this.nodeStat(current);
      if (!stat) {
        fs.mkdirSync(current, { mode: 0o700 });
        stat = this.nodeStat(current);
      }
      if (!stat?.isDirectory())
        throw new Error("Skill path component is not a directory");
    }
  }
  private readFile(file: string): string {
    const expected = this.ownedStat(file);
    if (!expected?.isFile()) throw new Error("Missing learned skill file");
    const fd = fs.openSync(
      file,
      fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0),
    );
    try {
      const actual = fs.fstatSync(fd);
      if (
        !actual.isFile() ||
        actual.nlink > 1 ||
        actual.ino !== expected.ino ||
        actual.dev !== expected.dev
      )
        throw new Error("Learned skill path changed during read");
      return fs.readFileSync(fd, "utf8");
    } finally {
      fs.closeSync(fd);
    }
  }
  private writeNew(file: string, content: string): void {
    if (this.ownedStat(file))
      throw new Error("Immutable skill revision already exists");
    const fd = fs.openSync(
      file,
      fs.constants.O_WRONLY |
        fs.constants.O_CREAT |
        fs.constants.O_EXCL |
        (fs.constants.O_NOFOLLOW ?? 0),
      0o600,
    );
    try {
      fs.writeFileSync(fd, content, "utf8");
    } finally {
      fs.closeSync(fd);
    }
  }
  private writeMutable(
    file: string,
    content: string,
    beforeReplace?: () => unknown,
  ): void {
    this.createDirectory(path.dirname(file));
    this.ownedStat(file);
    const temporary = `${file}.${randomUUID()}.tmp`;
    try {
      this.writeNew(temporary, content);
      this.ownedStat(file);
      beforeReplace?.();
      fs.renameSync(temporary, file);
    } finally {
      this.removeFile(temporary);
    }
  }
  private removeFile(file: string): void {
    const stat = this.ownedStat(file);
    if (!stat) return;
    if (!stat.isFile())
      throw new Error("Refusing to remove a non-file skill path");
    fs.unlinkSync(file);
  }
}
