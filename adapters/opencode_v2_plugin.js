// Safe YOLO managed OpenCode V2 plugin. Written by `safe-yolo install --harness opencode`.
// Do not edit: doctor compares this file with the copy rendered from the pinned release.
import { spawn } from "node:child_process";

const COMMAND = /* SAFE_YOLO_COMMAND */ [];
const TIMEOUT_MS = 10000;

function decide(payload) {
  return new Promise((resolve) => {
    let settled = false;
    const finish = (result) => {
      if (!settled) {
        settled = true;
        resolve(result);
      }
    };
    let child;
    try {
      child = spawn(COMMAND[0], COMMAND.slice(1), { stdio: ["pipe", "pipe", "pipe"] });
    } catch (error) {
      finish({ error: String(error?.message ?? error) });
      return;
    }
    let out = "";
    let err = "";
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      finish({ error: `no decision within ${TIMEOUT_MS} ms` });
    }, TIMEOUT_MS);
    child.stdout.on("data", (chunk) => (out += chunk));
    child.stderr.on("data", (chunk) => (err += chunk));
    child.on("error", (error) => {
      clearTimeout(timer);
      finish({ error: String(error?.message ?? error) });
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      if (code !== 0) {
        finish({ error: `exit ${code}${err ? `: ${err.trim().slice(0, 300)}` : ""}` });
        return;
      }
      try {
        const decision = JSON.parse(out);
        if (decision?.decision === "allow" || decision?.decision === "deny") {
          finish({ decision });
          return;
        }
      } catch {}
      finish({ error: "adapter returned no decision" });
    });
    child.stdin.on("error", () => {});
    child.stdin.end(JSON.stringify(payload));
  });
}

export default {
  id: "safe-yolo",
  async setup(ctx) {
    const directory = ctx.location?.directory;
    await ctx.tool.hook("execute.before", async (event) => {
      const result = await decide({
        tool: event.tool,
        sessionID: event.sessionID,
        callID: event.id,
        args: event.input ?? {},
        cwd: directory,
      });
      if (result.error) {
        throw new Error(`Safe YOLO fail-closed: adapter unavailable (${result.error})`);
      }
      if (result.decision.decision === "deny") {
        throw new Error(result.decision.reason || `Safe YOLO denied [${result.decision.policy_id}]`);
      }
    });
  },
};
