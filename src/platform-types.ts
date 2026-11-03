import type { EvidenceCheck } from "./types";
export const STAGES = [
  "scope-validation",
  "recon",
  "enumeration",
  "analysis",
  "validation",
  "evidence",
  "report",
] as const;
export type NodeState =
  | "PENDING"
  | "RUNNING"
  | "WAITING_APPROVAL"
  | "COMPLETED"
  | "FAILED"
  | "SKIPPED";
export interface GraphNode {
  id: string;
  dependsOn: string[];
}
export interface Mission {
  id: string;
  scope: string;
  title: string;
  boundaries: string;
  state: NodeState;
  nodes: {
    id: string;
    state: NodeState;
    dependsOn: string[];
    result: unknown;
    attempt: number;
  }[];
}
export interface FindingProposal {
  missionId: string;
  title: string;
  severity: "informational" | "low" | "medium" | "high" | "critical";
  description: string;
  limitations: string;
  evidence: string[];
  sources: string[];
  checks: (EvidenceCheck & {
    purpose: "reproduction" | "positive-control" | "negative-control";
  })[];
}
export interface SearchResult {
  id: string;
  kind: "mission" | "evidence" | "finding" | "source" | "knowledge";
  title: string;
  excerpt: string;
  reference: string;
  hash: string;
  missionId?: string;
}
export interface SourceSpec {
  id: string;
  scope: string;
  location: string;
  kind: "file" | "folder" | "url";
  enabled: boolean;
  maxFiles: number;
  maxBytes: number;
}
export interface SourceChunk {
  id: string;
  scope: string;
  sourceId: string;
  uri: string;
  title: string;
  text: string;
  hash: string;
  current: boolean;
  ordinal: number;
}
