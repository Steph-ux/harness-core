/** Native permission boundary for reporting, capitalization and post-restitution cleanup. */
import * as fs from "node:fs";
import * as path from "node:path";
import { json } from "../src/util";
export function addWorkflowTools(editor: any, s: any) {
  const str = { type: "string" },
    strings = { type: "array", items: str };
  const add = (
    name: string,
    description: string,
    actions: string[],
    properties: any,
    run: any,
  ) =>
    editor.add({
      name,
      description,
      input: {
        type: "object",
        properties: {
          action: { type: "string", enum: actions },
          ...properties,
        },
        required: ["action"],
        additionalProperties: false,
      },
      execute: async (i: any, c: any) => {
        if (!actions.includes(i.action))
          throw new Error("Invalid workflow action");
        const scope = await s.scopeOf(c.sessionID);
        s.ensureSession(c.sessionID, scope);
        return { content: json(await run(i, c, scope)) };
      },
    });
  add(
    "cyber_report",
    "Freeze verified evidence, register Word/PDF and rendered pages, record human review, then restitution.",
    [
      "snapshot",
      "artifact",
      "register",
      "get",
      "review",
      "restitution",
      "status",
    ],
    {
      missionId: str,
      reportId: str,
      config: { type: "object", additionalProperties: true },
      path: str,
      kind: {
        type: "string",
        enum: [
          "evidence",
          "poc",
          "capture",
          "script",
          "rule",
          "fixture",
          "report-docx",
          "report-pdf",
          "report-qa",
        ],
      },
      observationIds: strings,
      caption: str,
      artifactIds: strings,
      pagesReviewed: { type: "array", items: { type: "integer", minimum: 1 } },
      decision: { type: "string", enum: ["approved", "changes-required"] },
      notes: str,
      evidenceId: str,
      statement: str,
    },
    async (i: any, c: any, scope: string) => {
      if (i.action === "snapshot")
        return s.workflow.snapshot(scope, i.missionId, i.config);
      if (i.action === "artifact") {
        const engagement = s.platform.missionRoot(scope, i.missionId);
        // The three deliverables live in a folder of their own, inside the
        // engagement, so a report is never a loose file next to the notes.
        if (engagement && String(i.kind ?? "").startsWith("report-")) {
          const file = path.resolve(i.path);
          const top = path.relative(engagement, file).split(path.sep)[0];
          if (!/^rapport(-v\d+)?$/.test(top))
            throw new Error(
              "Report artifacts belong in <engagement>/rapport-vN",
            );
        }
        return s.workflow.registerArtifact(
          scope,
          i.missionId,
          i,
          engagement ?? s.sessionCwd.get(c.sessionID) ?? s.instanceCwd,
        );
      }
      if (i.action === "status") return s.workflow.status(scope, i.missionId);
      if (i.action === "get") return s.workflow.report(scope, i.reportId);
      if (i.action === "register")
        return s.workflow.registerReport(scope, i.reportId, i.artifactIds);
      if (i.action === "review") {
        const input = {
          pagesReviewed: i.pagesReviewed,
          decision: i.decision,
          reviewer: `operator:${c.sessionID}`,
          notes: i.notes,
        };
        s.workflow.assertReportReview(scope, i.reportId, input);
        await s.assertOperatorDecision(
          s.ctx,
          c,
          `report-review:${i.reportId}:${i.decision}`,
        );
        return s.workflow.reviewReport(scope, i.reportId, input);
      }
      s.workflow.assertRestitution(
        scope,
        i.reportId,
        i.evidenceId,
        `operator:${c.sessionID}`,
        i.statement,
      );
      await s.assertOperatorDecision(
        s.ctx,
        c,
        `report-restitution:${i.reportId}`,
      );
      return s.workflow.recordRestitution(
        scope,
        i.reportId,
        i.evidenceId,
        `operator:${c.sessionID}`,
        i.statement,
      );
    },
  );
  add(
    "cyber_capitalise",
    "Record one bounded mission learning pass. Validated artifacts need distinct observed positive and negative tests. No model weight changes or recursive skill generation.",
    ["record", "status"],
    {
      missionId: str,
      outcome: { type: "string", enum: ["none", "candidate", "validated"] },
      reason: str,
      artifactIds: strings,
      tests: {
        type: "array",
        items: {
          type: "object",
          properties: {
            observationId: str,
            contains: str,
            kind: { type: "string", enum: ["positive", "negative"] },
          },
          required: ["observationId", "contains", "kind"],
          additionalProperties: false,
        },
      },
    },
    async (i: any, _: any, scope: string) =>
      i.action === "status"
        ? s.workflow.status(scope, i.missionId)
        : s.workflow.capitalization(scope, i.missionId, {
            outcome: i.outcome,
            reason: i.reason,
            artifactIds: i.artifactIds ?? [],
            tests: i.tests ?? [],
          }),
  );
  add(
    "cyber_cleanup",
    "Clean only after recorded restitution of the reviewed report. Execution and verification are distinct traced processes; real exit status determines completion.",
    ["plan", "run", "verify", "result", "get"],
    {
      id: str,
      reportId: str,
      description: str,
      argv: strings,
      verifyArgv: strings,
      timeout: { type: "number", exclusiveMinimum: 0, maximum: 600 },
    },
    async (i: any, c: any, scope: string) => {
      if (i.action === "plan")
        return s.workflow.cleanupPlan(
          scope,
          i.reportId,
          i.description,
          i.argv,
          i.verifyArgv,
        );
      const cleanup = s.workflow.cleanup(scope, i.id);
      if (i.action === "get") {
        const { argv, verifyArgv, ...safe } = cleanup;
        return safe;
      }
      if (i.action === "result") {
        const record = s.processes.get(
            scope,
            cleanup.status === "verifying"
              ? cleanup.verificationProcessId
              : cleanup.processId,
          ),
          outcome = s.verifiedOutcome(record);
        if (!outcome || outcome.status === "running")
          return {
            id: i.id,
            status: cleanup.status,
            processStatus: s.processStatus(record),
          };
        return s.workflow.cleanupResult(
          scope,
          i.id,
          record.id,
          outcome.status === "succeeded" && outcome.exitCode === 0,
        );
      }
      const verification = i.action === "verify";
      s.workflow.assertCleanupStart(scope, i.id, verification);
      const argv = verification ? cleanup.verifyArgv : cleanup.argv,
        command = argv
          .map((v: string) => "'" + v.replaceAll("'", "'\\''") + "'")
          .join(" "),
        seconds = i.timeout ?? 120;
      if (!Number.isFinite(seconds) || seconds <= 0 || seconds > 600)
        throw new Error("Invalid cleanup deadline");
      await s.assertOperatorDecision(
        s.ctx,
        c,
        `cleanup:${cleanup.reportId}:${cleanup.id}:${i.action}`,
      );
      await s.assertProcessPermission(s.ctx, c, command);
      c.signal?.throwIfAborted();
      const record = s.processes.prepare(
        scope,
        c.sessionID,
        command,
        s.sessionCwd.get(c.sessionID) ?? s.instanceCwd,
        seconds * 1000,
      );
      s.workflow.cleanupStarted(scope, i.id, record.id, verification);
      let started: any, stored: any;
      try {
        started = s.spawnTraced(command, {
          cwd: record.cwd,
          logPath: record.logPath,
          deadlineMs: record.deadlineMs,
          argv,
        });
        stored = s.processes.add({ ...record, ...started });
      } catch (error) {
        if (started?.pid) s.stopProcess(started.pid);
        s.workflow.cleanupResult(scope, i.id, record.id, false);
        throw error;
      }
      return {
        cleanupId: i.id,
        process: s.publicProcess(stored),
        note: "Launch is not a cleanup result. Read the process, record its result, then run and record a separate verification.",
      };
    },
  );
}
