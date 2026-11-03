/**
 * The identity of an observation, derived from the session and the tool call.
 *
 * It lives here rather than in the worker runner so that any host can mint an
 * observation id without depending on an agent runtime.
 */
import { hash } from "./util";

export function observationId(sessionId: string, toolCallId: string): string {
  return `obs-${hash(`${sessionId}:${toolCallId}`).slice(0, 32)}`;
}
