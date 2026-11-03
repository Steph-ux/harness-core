import type { Observation, StorePort } from "./types";
import { observationId } from "./observation-id";
import { json, now } from "./util";

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
/** A successful handoff is not successful execution, including when importing old transcripts. */
export function processHandoff(value: any): boolean {
  if (value?.details?.status === "background" && value.details.jobId)
    return true;
  if (
    value?.structuredContent?.status === "background" &&
    value.structuredContent.jobId
  )
    return true;
  for (const part of value?.content ?? []) {
    if (
      part.type !== "text" ||
      typeof part.text !== "string" ||
      part.text.length > 24000
    )
      continue;
    try {
      const parsed = JSON.parse(part.text);
      if (parsed?.status === "background" && typeof parsed.jobId === "string")
        return true;
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
  const { observationId: _ignored, ...details } = event.result.details;
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
    output: json(details),
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
