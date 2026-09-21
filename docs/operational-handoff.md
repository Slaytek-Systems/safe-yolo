# Safe YOLO operational handoff

## State

The baseline is live on both hosts. Do not infer activation from source changes alone: the active Codex hook pin and a live audit record are the authority.

| Host | Active release | Evidence |
| --- | --- | --- |
| macOS (`/Users/slayga`) | `1.0.10` | Manifest `b06de186e90987978cd77622ba54b043f534e1718d80da0938d616bdee544d6a`; canonical hook pin and live `pwd` smoke audited. |
| devbox (`/home/dev`) | `1.0.11` | Manifest `c6463a59644cb33a0c833d93001b04e7c4b383041e26e9360a49fe1878c9df7a`; remote installer and doctor passed; Navigator verified the repaired live agent path. |

Both hosts use `approval_policy = "never"` and `sandbox_mode = "danger-full-access"`. The active policy provides deterministic backpressure for direct tool calls. It is not containment for scripts or interpreters running as the same operating-system identity; durable safety depends on scoped authority and recoverability below the hook.

## Baseline capabilities

- Normal code, tests, commits, and clean feature-branch pushes proceed without approval prompts.
- Codex task/thread read, create, archive, message, and collaboration tools are classified rather than fail-closed as unknown.
- macOS protects credential/system surfaces (`~/.ssh`, shell profiles, LaunchAgents, Keychain access).
- Direct destructive filesystem actions, force pushes, secret exposure, control-plane mutation, and unproven production deploys receive deterministic backpressure.
- macOS permits only two exact remote Safe YOLO maintenance actions for `devbox`: canonical-source fast-forward pull and the fixed remote updater. Explicit no-session transport and visible ordinary remote commands are classified by their actual consequence; interactive, hidden, redirected-maintenance, and restricted remote execution remains blocked.

## Reopen protocol

1. Start with the active hook, not source state:
   - macOS: inspect `~/.codex/hooks.json`, then `~/.safe-yolo/state/audit.jsonl`.
   - devbox: inspect `~/.codex/hooks.json`, then `~/.safe-yolo/state/audit.jsonl`.
2. Run `scripts/doctor.py` against the release and its recorded manifest.
3. For a reported friction: capture the exact tool name/command and policy/audit decision; add a regression test; release and activate on the affected host; prove one live action before declaring it fixed.
4. Never manually edit an immutable release. Use `scripts/install.py`; it refuses silent bootstrap replacement. The devbox updater is `scripts/remote_update.py` and is reached only through the narrow macOS host contract.

## Remaining work

### Approved, non-urgent hygiene

`/home/dev/.safe-yolo/releases/1.0.5` is incomplete and inactive. It is approved for reversible quarantine, but do not delete it. Bundle that move with a future devbox maintenance release to avoid a standalone hook-trust cycle.

### Optional future capability: production release contracts

Agents intentionally cannot deploy to production yet. A project-specific release contract would permit a deployment only after externally verifiable evidence for the exact target, CI/artifact/commit, rollback path, and post-deploy smoke. Choose the first pilot project before implementing this.

## Durable source of truth

- Repository: `https://github.com/Slaytek-Systems/safe-yolo`
- Active configuration: each host's `~/.codex/hooks.json`
- Immutable releases: each host's `~/.safe-yolo/releases/`
- Evidence: each host's `~/.safe-yolo/state/audit.jsonl`
- Rollback artifacts: each host's `~/.safe-yolo/backups/`
