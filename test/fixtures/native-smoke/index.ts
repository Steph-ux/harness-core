/** SDK fixture loaded only by scripts/native-smoke.cjs. It uses no model or target. */
import * as fs from "node:fs";
export default {
  id: "harness.test.native",
  setup(ctx: any) {
    if (
      !process.env.HARNESS_NATIVE_RESULT ||
      ctx.location.directory !== process.env.HARNESS_CORE
    )
      return;
    const timer = setTimeout(
      () =>
        void (async () => {
          const result: any = {};
          try {
            const tools = await ctx.tool.list();
            result.tools = tools
              .map((t: any) => t.name)
              .filter((n: string) => n.startsWith("cyber_"));
            const session = await ctx.session.create({
              title: "Synthetic local SDK smoke",
              permissions: [{ action: "shell", resource: "*", effect: "deny" }],
            });
            const context = {
              sessionID: session.id,
              agent: "build",
              messageID: "msg_harnessNativeSmoke",
              id: "call_harnessNativeSmoke",
              signal: new AbortController().signal,
              progress: async () => {},
            };
            result.tasks = JSON.parse(
              (
                await tools
                  .find((t: any) => t.name === "cyber_tasks")
                  .execute({ action: "list" }, context)
              ).content,
            );
            const processTool = tools.find(
              (t: any) => t.name === "cyber_process",
            );
            result.list = await processTool.execute(
              { action: "list" },
              context,
            );
            try {
              await processTool.execute(
                {
                  action: "run",
                  argv: ["node", "-e", "console.log('SYNTHETIC_SMOKE')"],
                  timeout: 2,
                },
                context,
              );
              result.unexpectedLaunch = true;
            } catch (error) {
              result.refusal = String(error);
            }
          } catch (error) {
            result.error = String(error);
          }
          fs.writeFileSync(
            process.env.HARNESS_NATIVE_RESULT!,
            JSON.stringify(result),
            { mode: 0o600 },
          );
        })(),
      1000,
    );
    return () => clearTimeout(timer);
  },
};
