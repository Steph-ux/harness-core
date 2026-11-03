import type { SkillTrace } from "./skill-trace";

export type LearningCategory =
  | "false-positive-patterns"
  | "tool-usage-patterns"
  | "investigation-patterns"
  | "environment-patterns";
export const SKILL_DOMAINS = [
  "reconnaissance",
  "web-security",
  "cloud",
  "linux",
  "windows",
  "network",
  "malware-analysis",
  "forensics",
] as const;
export type SkillDomain = (typeof SKILL_DOMAINS)[number];
export type RunStatus = "active" | "completed" | "aborted" | "error";
export interface SessionRecord {
  id: string;
  scope: string;
  cwd: string;
  status: RunStatus;
  updatedAt: string;
}
export interface Observation {
  id: string;
  sessionId: string;
  scope: string;
  tool: string;
  input: unknown;
  output: string;
  success: boolean;
  timestamp: string;
  hash: string;
}
export interface EvidenceCheck {
  observationId: string;
  contains: string;
}
export interface KnowledgeProposal {
  key: string;
  content: string;
  kind: "environment" | "workflow" | "false-positive" | "preference";
  evidence: string[];
}
export interface KnowledgeRecord extends KnowledgeProposal {
  id: string;
  scope: string;
  status: "active" | "pending";
  createdAt: string;
}
/** An operator-declared rule. Declared, not discovered: it needs no evidence. */
export interface OperatorRule {
  key: string;
  content: string;
}
export interface SearchHit {
  sessionId: string;
  entryId: string;
  role: string;
  text: string;
  timestamp: string;
}
export interface SkillProposal {
  name: string;
  description: string;
  category: LearningCategory;
  domains?: SkillDomain[];
  prerequisites: string[];
  procedure: string[];
  validation: EvidenceCheck[];
  evidence: string[];
}
export interface SkillRevision extends SkillProposal {
  scope: string;
  version: number;
  status: "candidate" | "active" | "deprecated";
  confidence: number;
  sourceSessions: string[];
  lastVerified: string | null;
  contentHash: string;
  /**
   * The project scopes a global method was promoted from. A global revision
   * carries no evidence of its own: the observations stay in the project that
   * produced them, so nothing from one engagement crosses into another.
   */
  promotedFrom?: string[];
}
export interface ReviewProposal {
  knowledge: KnowledgeProposal[];
  skills: SkillProposal[];
}
export interface ReviewRecord {
  sessionId: string;
  scope: string;
  digest: string;
  status: "pending" | "running" | "completed" | "cancelled" | "error";
  detail: string;
  updatedAt: string;
}
export interface StorePort {
  upsertSession(session: SessionRecord): void;
  recordMessage(
    sessionId: string,
    scope: string,
    entryId: string,
    role: string,
    text: string,
    timestamp: string,
  ): void;
  recordObservation(observation: Omit<Observation, "hash">): Observation;
  evidence(scope: string, ids: string[]): Observation[];
  observationsForSession(
    sessionId: string,
    scope: string,
    limit?: number,
  ): Observation[];
  proposeKnowledge(scope: string, proposal: KnowledgeProposal): KnowledgeRecord;
  setOperatorRule(scope: string, rule: OperatorRule): KnowledgeRecord;
  operatorModel(scope: string): KnowledgeRecord[];
  getKnowledge(
    scope: string,
    query?: string,
    limit?: number,
  ): KnowledgeRecord[];
  pendingKnowledge(scope: string): KnowledgeRecord[];
  resolveKnowledge(scope: string, id: string, approve: boolean): void;
  searchSessions(scope: string, query: string, limit?: number): SearchHit[];
  browseSession(
    scope: string,
    sessionId: string,
    offset?: number,
    limit?: number,
  ): SearchHit[];
  recordReview(review: Omit<ReviewRecord, "updatedAt">): void;
  reviews(scope: string, limit?: number): ReviewRecord[];
  audit(scope: string, event: string, detail: unknown): void;
  close(): void;
}
export interface HarnessConfig {
  enabled: boolean;
  reviewEnabled: boolean;
  reviewDelayMs: number;
  reviewTimeoutMs: number;
  reviewMaxChars: number;
  reviewMaxOutputTokens: number;
  reviewModel: string | null;
  maxParallel: number;
  workerTimeoutMs: number;
  maxWorkerTurns: number;
  maxWorkerToolCalls: number;
  maxWorkerInputTokens: number;
  maxWorkerOutputTokens: number;
  minimumSkillSessions: number;
  minimumSkillConfidence: number;
  memoryMaxChars: number;
  operatorModelChars: number;
  routerEnabled: boolean;
  routerModel: string | null;
  autoSkillsEnabled: boolean;
  autoSkillsMaxCount: number;
  autoSkillsMaxChars: number;
  autoToolsEnabled: boolean;
  autoToolsMaxCount: number;
}
export const DEFAULT_CONFIG: HarnessConfig = {
  enabled: true,
  reviewEnabled: true,
  reviewDelayMs: 3000,
  reviewTimeoutMs: 90000,
  reviewMaxChars: 20000,
  reviewMaxOutputTokens: 16384,
  reviewModel: null,
  maxParallel: 3,
  workerTimeoutMs: 120000,
  maxWorkerTurns: 8,
  maxWorkerToolCalls: 16,
  maxWorkerInputTokens: 48000,
  maxWorkerOutputTokens: 4096,
  minimumSkillSessions: 2,
  minimumSkillConfidence: 0.75,
  memoryMaxChars: 12000,
  operatorModelChars: 5000,
  routerEnabled: true,
  routerModel: null,
  autoSkillsEnabled: true,
  autoSkillsMaxCount: 5,
  autoSkillsMaxChars: 48000,
  autoToolsEnabled: true,
  autoToolsMaxCount: 8,
};
export const WORKER_ROLES = [
  "recon-agent",
  "web-agent",
  "network-agent",
  "windows-agent",
  "linux-agent",
  "code-agent",
  "threat-intel-agent",
  "forensics-agent",
  "report-agent",
  "verification-agent",
] as const;
export type WorkerRole = (typeof WORKER_ROLES)[number];
export interface WorkerTask {
  id: string;
  role: WorkerRole;
  task: string;
  context?: string;
  tools?: string[];
  scope?: string;
  writePaths?: string[];
}
export interface WorkerResult {
  id: string;
  role: WorkerRole;
  status: "completed" | "aborted" | "error" | "budget-exceeded";
  summary: string;
  observations: string[];
  evidence: string[];
  hypotheses: string[];
  observationIds?: string[];
  blockers: string[];
  toolCalls: number;
  turns: number;
  inputTokens: number;
  elapsedMs: number;
  artifact?: string;
  skillActivation?: SkillTrace;
}
