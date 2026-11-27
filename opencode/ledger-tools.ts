/**
 * Task tree and investigation register, at the OpenCode boundary.
 *
 * A task closes only against successful observations. A hypothesis confirms
 * only with a reproduction and a negative control that observe different
 * outputs. The stores stay in the core; this file only registers the tools.
 */
import * as path from "node:path";
import { assertPlainPath, atomicWrite } from "../src/util";

const LEDGER_ID_RE = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}$/;

function assertOptionalLedgerId(value: unknown, kind: string): void {
  if (value === undefined) return;
  if (typeof value !== "string" || !LEDGER_ID_RE.test(value))
    throw new Error(`Invalid ${kind} id`);
}

export function addLedgerTools(editor: any, s: any) {
  editor.add({
    name: "cyber_tasks",
    description:
      "Keep the running step list. A task closes only against a successful observation. A blocked task must give its reason. Use the cyber_memory action recent to obtain the observation ids that prove the work.",
    input: {
      type: "object",
      properties: {
        action: {
          type: "string",
          enum: [
            "add",
            "start",
            "complete",
            "block",
            "remove",
            "list",
            "review",
            "tree",
            "markdown",
            "export",
            "assets",
            "coverage",
          ],
          description:
            "What to do with the task list. tree reads the hierarchy, markdown renders it, export writes couverture.md into the engagement, assets creates one branch per known entity, coverage creates a bounded deep profile.",
        },
        profile: {
          type: "string",
          enum: Object.keys(s.COVERAGE_PROFILES),
          description: "Deep coverage profile: mobile, cloud, harness or gaps.",
        },
        title: { type: "string", description: "Task title, for add." },
        id: {
          type: "string",
          description: "Task id, for start, complete, block and remove.",
        },
        reason: { type: "string", description: "Why the task is blocked." },
        evidence: {
          type: "array",
          items: { type: "string" },
          description: "Observation ids that close the task.",
        },
        dependsOn: {
          type: "array",
          items: { type: "string" },
          description: "Tasks that must close first.",
        },
        parent: {
          type: "string",
          description: "The parent task, for add: a sub-step of a larger one.",
        },
      },
      required: ["action"],
      additionalProperties: false,
    },
    execute: async (input: any, context: any) => {
      const scope = await s.scopeOf(context.sessionID);
      const action = String(input.action);
      if (action === "add") {
        if (!input.title) throw new Error("add requires a title");
        return {
          content: JSON.stringify(
            s.taskStore.add(scope, {
              title: input.title,
              dependsOn: input.dependsOn,
              parent: input.parent,
            }),
          ),
        };
      }
      if (action === "list") {
        return {
          content: JSON.stringify({
            tasks: s.taskStore.list(scope),
            delegable: s.taskStore.delegable(scope),
          }),
        };
      }
      if (action === "tree")
        return { content: JSON.stringify(s.taskStore.tree(scope)) };
      if (action === "markdown")
        return { content: s.taskStore.markdown(scope) };
      if (action === "export") {
        const mission = s.platform.active(scope),
          root = mission
            ? s.platform.missionRoot(scope, mission.id)
            : undefined;
        if (!root)
          throw new Error(
            "An engagement root is required to write the coverage map",
          );
        assertPlainPath(root);
        const file = path.join(root, "couverture.md");
        assertPlainPath(file);
        atomicWrite(file, s.taskStore.markdown(scope));
        return { content: JSON.stringify({ path: file }) };
      }
      if (action === "assets") {
        const existing = new Set(
          s.taskStore.list(scope).map((entry: any) => entry.title),
        );
        const seen = new Set<string>();
        const assets = [
          "host",
          "domain",
          "ip",
          "url",
          "service",
          "technology",
          "certificate",
          "account",
          "repo",
          "org",
          "person",
        ]
          .flatMap((type) => s.platform.entities(scope, { type, limit: 100 }))
          .filter((asset: any) => {
            const title = `${asset.type}:${asset.key}`.slice(0, 200);
            if (existing.has(title) || seen.has(title)) return false;
            seen.add(title);
            return true;
          })
          .slice(0, 50);
        const created: string[] = [];
        for (const asset of assets) {
          const title = `${asset.type}:${asset.key}`.slice(0, 200);
          const parent = s.taskStore.add(scope, { title });
          created.push(parent.id);
          for (const step of s.assetSteps(asset.type))
            created.push(
              s.taskStore.add(scope, {
                title: `${title} — ${step}`,
                parent: parent.id,
              }).id,
            );
        }
        return {
          content: JSON.stringify({ assets: assets.length, created }),
        };
      }
      if (action === "coverage") {
        const profileName = String(input.profile ?? "");
        const profile = s.coverageProfile(profileName);
        const contract = s.coverageContract(profileName);
        const planted = s.taskStore
          .list(scope)
          .find(
            (entry: { title: string; parentId?: string }) =>
              entry.title === profile.title && !entry.parentId,
          );
        if (planted) {
          return {
            content: JSON.stringify({
              profile: profileName,
              title: profile.title,
              created: [],
              steps: profile.steps.length,
              contract,
            }),
          };
        }
        const root = s.taskStore.add(scope, { title: profile.title });
        const created = [root.id];
        for (const step of profile.steps)
          created.push(
            s.taskStore.add(scope, {
              title: step,
              parent: root.id,
            }).id,
          );
        return {
          content: JSON.stringify({
            profile: profileName,
            title: profile.title,
            created,
            steps: profile.steps.length,
            contract,
          }),
        };
      }
      if (action === "review") {
        const packet = s.taskStore.review(scope);
        const ids = [
          ...new Set(packet.closed.flatMap((entry: any) => entry.evidence)),
        ];
        return {
          content: JSON.stringify({
            ...packet,
            observations: s.knowledge.evidence(scope, ids).map((item: any) => ({
              id: item.id,
              tool: item.tool,
              success: item.success,
              output: item.output.slice(0, 2000),
            })),
          }),
        };
      }
      if (!input.id) throw new Error(`${action} requires a task id`);
      if (action === "start")
        return {
          content: JSON.stringify(s.taskStore.start(scope, input.id)),
        };
      if (action === "remove") {
        s.taskStore.remove(scope, input.id);
        return {
          content: JSON.stringify({
            removed: input.id,
            tasks: s.taskStore.list(scope),
          }),
        };
      }
      if (action === "block") {
        if (!input.reason)
          throw new Error("a blocked task requires a reason");
        return {
          content: JSON.stringify(
            s.taskStore.block(scope, input.id, input.reason),
          ),
        };
      }
      if (!input.evidence?.length)
        throw new Error(
          "a completed task requires the observation ids that prove it",
        );
      const proven = s.knowledge.evidence(scope, input.evidence);
      if (proven.some((item: any) => !item.success))
        throw new Error("task evidence must be successful observations");
      return {
        content: JSON.stringify(
          s.taskStore.complete(scope, input.id, input.evidence),
        ),
      };
    },
  });

  editor.add({
    name: "cyber_investigation",
    description:
      "Drive the investigation itself: declare hypotheses and test them, track which surfaces are tested or blocked, and read the directives the harness derives from your observations. A hypothesis confirms only with a successful reproduction and a negative control that observe different outputs; a refuted one is not revisited. The harness injects mandatory directives when you loop, stagnate, or conclude before covering the surface.",
    input: {
      type: "object",
      properties: {
        action: {
          type: "string",
          enum: ["hypothesis", "surface", "status"],
          description:
            "hypothesis manages the hypothesis register, surface manages coverage, status reads the assembled state and its directives.",
        },
        op: {
          type: "string",
          enum: [
            "propose",
            "test",
            "evidence",
            "control",
            "refute",
            "list",
            "add",
            "start",
            "complete",
            "block",
          ],
          description:
            "For hypothesis: propose/test/evidence/control/refute/list. For surface: add/start/complete/block/list.",
        },
        id: {
          type: "string",
          description:
            "Hypothesis or surface id. Omit on propose/add to generate one.",
        },
        text: {
          type: "string",
          description: "The hypothesis statement, for propose.",
        },
        label: { type: "string", description: "The surface label, for add." },
        reason: { type: "string", description: "Why a surface is blocked." },
        observationId: {
          type: "string",
          description:
            "The observation bound as reproduction, negative control, or refutation.",
        },
        evidence: {
          type: "array",
          items: { type: "string" },
          description: "Observation ids that prove a surface was tested.",
        },
      },
      required: ["action"],
      additionalProperties: false,
    },
    execute: async (input: any, context: any) => {
      const scope = await s.scopeOf(context.sessionID);
      const action = String(input.action);
      const op = String(input.op ?? "");

      if (action === "status") {
        const nowMs = Date.now();
        s.investigation.tick(scope, nowMs);
        const explicitCov = s.investigation.coverageSummary(scope);
        const tasks = s.taskStore.list(scope);
        const coverage =
          explicitCov.total > 0
            ? explicitCov
            : s.taskCoverageSummary(tasks);
        const state = s.assembleInvestigation({
          observations: s.knowledge.observationsForSession(
            context.sessionID,
            scope,
            30,
          ),
          tasks,
          hypotheses: s.investigation.hypotheses(scope),
          coverage,
          nowMs,
        });
        return {
          content: JSON.stringify({
            coverage: state.coverage,
            hypotheses: state.hypotheses,
            stagnation: state.stagnation,
            directives: s.directives(state),
          }),
        };
      }

      if (action === "hypothesis") {
        if (op === "list")
          return {
            content: JSON.stringify(s.investigation.hypotheses(scope)),
          };
        if (op === "propose") {
          if (!input.text)
            throw new Error("propose requires a hypothesis text");
          assertOptionalLedgerId(input.id, "hypothesis");
          return {
            content: JSON.stringify(
              s.investigation.proposeHypothesis(scope, input.text, input.id),
            ),
          };
        }
        if (!input.id) throw new Error(`${op} requires a hypothesis id`);
        if (op === "test")
          return {
            content: JSON.stringify(
              s.investigation.testHypothesis(scope, input.id),
            ),
          };
        if (op === "evidence" || op === "control" || op === "refute") {
          if (!input.observationId)
            throw new Error(`${op} requires an observationId`);
          const [obs] = s.knowledge.evidence(scope, [input.observationId]);
          if (!obs)
            throw new Error("the observation does not exist in this scope");
          if ((op === "evidence" || op === "control") && !obs.success)
            throw new Error(
              op === "control"
                ? "a negative control must be a successful observation"
                : "a reproduction must be a successful observation",
            );
          const outputHash = s.hash(obs.output);
          return {
            content: JSON.stringify(
              op === "evidence"
                ? s.investigation.evidenceHypothesis(
                    scope,
                    input.id,
                    input.observationId,
                    outputHash,
                  )
                : op === "control"
                  ? s.investigation.controlHypothesis(
                      scope,
                      input.id,
                      input.observationId,
                      outputHash,
                    )
                  : s.investigation.refuteHypothesis(
                      scope,
                      input.id,
                      input.observationId,
                    ),
            ),
          };
        }
        throw new Error(`unknown hypothesis op ${op}`);
      }

      if (action === "surface") {
        if (op === "list") {
          const ec = s.investigation.coverageSummary(scope);
          return {
            content: JSON.stringify(
              ec.total > 0
                ? ec
                : s.taskCoverageSummary(s.taskStore.list(scope)),
            ),
          };
        }
        if (op === "add") {
          if (!input.label) throw new Error("add requires a surface label");
          assertOptionalLedgerId(input.id, "surface");
          const id = input.id ?? `surface-${Date.now().toString(36)}`;
          s.investigation.addSurface(scope, id, input.label);
          return { content: JSON.stringify({ added: id }) };
        }
        if (!input.id) throw new Error(`${op} requires a surface id`);
        if (op === "start") {
          s.investigation.startSurface(scope, input.id);
          return { content: JSON.stringify({ started: input.id }) };
        }
        if (op === "block") {
          if (!input.reason)
            throw new Error("a blocked surface requires a reason");
          s.investigation.blockSurface(scope, input.id, input.reason);
          return { content: JSON.stringify({ blocked: input.id }) };
        }
        if (op === "complete") {
          if (!input.evidence?.length)
            throw new Error("a tested surface requires observation ids");
          const proven = s.knowledge.evidence(scope, input.evidence);
          if (!proven.length || !proven.every((item: any) => item.success))
            throw new Error(
              "surface evidence must be successful observations",
            );
          s.investigation.completeSurface(scope, input.id, input.evidence);
          return { content: JSON.stringify({ tested: input.id }) };
        }
        throw new Error(`unknown surface op ${op}`);
      }

      throw new Error(`unknown investigation action ${action}`);
    },
  });
}
