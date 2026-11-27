import type { Observation, StorePort } from "./types";
import { observationId } from "./observation-id";
import { json, now, textOf } from "./util";

export interface ProcessCompletion {
  sessionId: string;
  cwd: string;
  tool: string;
  toolCallId: string;
  jobId: string;
  background: boolean;
  finishedAt?: string;
  result: {
    content: { type: string; text?: string }[];
    details: Record<string, unknown>;
    isError?: boolean;
  };
}
function hasBackgroundJob(value: unknown): boolean {
  if (!value || typeof value !== "object") return false;
  const record = value as { status?: unknown; jobId?: unknown };
  return (
    record.status === "background" &&
    typeof record.jobId === "string" &&
    record.jobId.trim().length > 0
  );
}
/** A successful handoff is not successful execution, including when importing old transcripts. */
export function processHandoff(value: any): boolean {
  if (hasBackgroundJob(value?.details)) return true;
  if (hasBackgroundJob(value?.structuredContent)) return true;
  if (!Array.isArray(value?.content)) return false;
  for (const part of value.content) {
    if (
      !part ||
      typeof part !== "object" ||
      part.type !== "text" ||
      typeof part.text !== "string" ||
      part.text.length > 24000
    )
      continue;
    try {
      const parsed = JSON.parse(part.text);
      if (hasBackgroundJob(parsed)) return true;
    } catch {
      /* Ordinary output is not a process handoff. */
    }
  }
  return false;
}
export function recordProcessOutcome(
  store: StorePort,
  scope: string,
  event: ProcessCompletion,
) {
  const { observationId: _ignored, ...details } = event.result.details ?? {};
  const summary = Array.isArray(event.result.content)
    ? textOf({ content: event.result.content }).trim().slice(0, 12000)
    : "";
  const outputPayload = summary
    ? details.content === undefined
      ? { ...details, content: summary }
      : { ...details, contentSummary: summary }
    : details;
  return store.recordObservation({
    id: observationId(
      event.sessionId,
      `${event.toolCallId}:job:${event.jobId}:final`,
    ),
    sessionId: event.sessionId,
    scope,
    tool: event.tool,
    input: {
      phase: "final",
      jobId: event.jobId,
      originalToolCallId: event.toolCallId,
      background: event.background,
    },
    output: json(outputPayload),
    success:
      !event.result.isError &&
      details.status === "success" &&
      details.exitCode === 0,
    timestamp: event.finishedAt ?? now(),
  });
}

/** A tool-returned ID is a link only if the scoped immutable record proves this exact call/job. */
export function linkedProcessOutcome(
  store: StorePort,
  scope: string,
  sessionId: string,
  toolCallId: string,
  tool: string,
  value: any,
): Observation | undefined {
  const details = value?.details;
  if (
    typeof details?.jobId !== "string" ||
    typeof details?.observationId !== "string" ||
    details.observationId !==
      observationId(sessionId, `${toolCallId}:job:${details.jobId}:final`)
  )
    return;
  try {
    const observed = store.evidence(scope, [details.observationId])[0];
    const input = observed?.input as
      | { phase?: unknown; originalToolCallId?: unknown; jobId?: unknown }
      | undefined;
    if (
      observed?.scope === scope &&
      observed.sessionId === sessionId &&
      observed.tool === tool &&
      input?.phase === "final" &&
      input.originalToolCallId === toolCallId &&
      input.jobId === details.jobId
    )
      return observed;
  } catch {
    /* Unverified links fall back to the actual tool/transcript observation. */
  }
}
