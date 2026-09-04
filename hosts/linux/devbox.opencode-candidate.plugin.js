// Non-active Safe YOLO 3.0 deny-only OpenCode candidate.
// Replace placeholders only through operator maintenance after install.
// Call ~/.config/opencode/plugins/safe-yolo.js only through that reviewed copy.

const PYTHON = "/usr/bin/python3";
const BOOTSTRAP = "/home/dev/.safe-yolo/bootstrap.py";
const RELEASE = "/home/dev/.safe-yolo/releases/3.0.0-alpha.5";
const MANIFEST_SHA256 = "REPLACE_AFTER_INSTALL";
const STATE_DIR = "/home/dev/.safe-yolo/state";

function runAdapter(payload) {
  const input = Buffer.from(JSON.stringify(payload), "utf8");
  const proc = Bun.spawnSync(
    [
      PYTHON,
      BOOTSTRAP,
      "--release",
      RELEASE,
      "--manifest-sha256",
      MANIFEST_SHA256,
      "--entry",
      "opencode_v3",
      "--state-dir",
      STATE_DIR,
    ],
    {
      stdin: input,
      stdout: "pipe",
      stderr: "pipe",
    },
  );
  const out = proc.stdout ? Buffer.from(proc.stdout).toString("utf8").trim() : "";
  const err = proc.stderr ? Buffer.from(proc.stderr).toString("utf8").trim() : "";
  return { exitCode: proc.exitCode ?? 1, out, err };
}

function parseDecision(out) {
  if (!out) return null;
  try {
    const parsed = JSON.parse(out);
    if (parsed && typeof parsed.decision === "string") return parsed;
    return null;
  } catch {
    return null;
  }
}

export const SafeYolo = async ({ client, directory }) => {
  const log = async (level, message, extra) => {
    try {
      await client.app.log({ body: { service: "safe-yolo", level, message, extra } });
    } catch {
      // Structured logging is best-effort.
    }
  };

  return {
    "tool.execute.before": async (input, output) => {
      const payload = {
        tool: input.tool,
        sessionID: input.sessionID,
        callID: input.callID,
        args: output.args ?? {},
        cwd: output.args?.workdir || directory,
      };
      let decision = null;
      let adapterError = null;
      try {
        const { exitCode, out, err } = runAdapter(payload);
        if (exitCode !== 0) {
          adapterError = `adapter exit ${exitCode}${err ? `: ${err.slice(0, 300)}` : ""}`;
        } else {
          decision = parseDecision(out);
          if (!decision) adapterError = "adapter returned no decision";
        }
      } catch (error) {
        adapterError = String(error?.message || error).slice(0, 300);
      }

      if (adapterError && !decision) {
        await log("error", `Safe YOLO adapter unavailable (${adapterError})`, {
          tool: input.tool,
          sessionID: input.sessionID,
        });
        throw new Error(`Safe YOLO fail-closed: adapter unavailable (${adapterError})`);
      }

      await log(
        decision.decision === "deny" ? "warn" : "info",
        `Safe YOLO ${decision.decision} [${decision.policy_id}] ${input.tool}`,
        {
          tool: input.tool,
          sessionID: input.sessionID,
          decision: decision.decision,
          policy_id: decision.policy_id,
        },
      );

      if (decision.decision === "deny") {
        throw new Error(decision.reason || `Safe YOLO [${decision.policy_id}]: denied`);
      }
    },
  };
};
