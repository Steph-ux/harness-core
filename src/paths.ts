/**
 * Where the harness keeps its state.
 *
 * The state is shared: the observations, the knowledge, the tasks, the learned
 * methods and the engagement ledger live in one place, whichever host wrote
 * them. Its home is therefore neutral — it must not sit inside the directory
 * of a host that can go away.
 */
import * as os from "node:os";
import * as path from "node:path";

/** The root of the harness state, shared by every host. */
export function harnessHome(): string {
  const override = process.env.HARNESS_HOME?.trim();
  if (override) return path.resolve(override);
  return path.join(os.homedir(), ".local", "share", "harness-core");
}

/** The directory of the shared store. */
export function stateRoot(): string {
  const override = process.env.HARNESS_STATE_ROOT?.trim();
  if (override) return path.resolve(override);
  return path.join(harnessHome(), "state");
}
