// Safe YOLO managed OpenCode V2 plugin. Written by `safe-yolo install --harness opencode`.
// Do not edit: doctor compares this file with the copy rendered from the active release.
import { spawn } from "node:child_process";

const COMMAND = /* SAFE_YOLO_COMMAND */ [];
const TIMEOUT_MS = 10000;

function decide(payload) {
  return new Promise((resolve) => {
    let child;
    let timer;
    let settled = false;
    let out = "";
    let err = "";
    const finish = (result) => {
      if (!settled) {
        settled = true;
        clearTimeout(timer);
        resolve(result);
      }
    };
    // The bootstrap runs the adapter as its own child, so stop the whole process group.
    const fail = (message) => {
      if (!settled && child?.pid) {
        try {
          process.kill(-child.pid, "SIGKILL");
        } catch {}
      }
      finish({ error: message });
    };
    try {
      child = spawn(COMMAND[0], COMMAND.slice(1), { stdio: ["pipe", "pipe", "pipe"], detached: true });
    } catch (error) {
      finish({ error: String(error?.message ?? error) });
      return;
    }
    timer = setTimeout(() => fail(`no decision within ${TIMEOUT_MS} ms`), TIMEOUT_MS);
    child.on("error", (error) => fail(String(error?.message ?? error)));
    for (const name of ["stdin", "stdout", "stderr"]) {
      child[name].on("error", (error) => fail(`${name}: ${error?.message ?? error}`));
    }
    child.stdout.on("data", (chunk) => (out += chunk));
    child.stderr.on("data", (chunk) => (err += chunk));
    child.on("close", (code) => {
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
