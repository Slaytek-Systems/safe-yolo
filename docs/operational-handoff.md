# Safe YOLO operational handoff

## State

Do not infer activation from source changes alone: each host's active hook pin and `safe-yolo doctor --all` are the authority.

| Host | Active release | Evidence |
| --- | --- | --- |
| macOS (`/Users/slayga`) | `3.0.0-beta.6` (Codex, Cursor) | Upgraded 2026-10-09 from `3.0.0-alpha.1` with Homebrew `python3.14`; ZIP SHA-256 `5d00ffad9dd02f66ba4448b4091ac7e0ae151ed0a3f331680dde82290a80f382`, source `cbe505aad652a4696653024637c84210abcc9ce7`; `doctor --all` healthy with allow/deny canaries. Codex needs the new hook hash trusted in `/hooks` after each install or update. Claude Code keeps its own `PreToolUse` validators and Grok its own hooks; neither runs Safe YOLO. |
| devbox (`/home/dev`) | `3.0.0-beta.4` (Codex `codex_v3`) | Read from the active Codex hook pin, 2026-10-09. |

Both hosts use `approval_policy = "never"` and `sandbox_mode = "danger-full-access"`. The active policy provides deterministic backpressure for direct tool calls. It is not containment for scripts or interpreters running as the same operating-system identity; durable safety depends on scoped authority and recoverability below the hook.

## Baseline capabilities

- Normal code, tests, commits, and clean feature-branch pushes proceed without approval prompts.
- Codex task/thread read, create, archive, message, and collaboration tools are classified rather than fail-closed as unknown.
- macOS protects credential/system surfaces (`~/.ssh`, shell profiles, LaunchAgents, Keychain access).
- Direct destructive filesystem actions, force pushes, secret exposure, control-plane mutation, and unproven production deploys receive deterministic backpressure.
- Visible noninteractive remote commands such as `ssh -n devbox uptime` are allowed from `3.0.0-alpha.9` on; the remote command is still checked for credential, deletion, production, and enforcement consequences. Interactive shells, subsystems, alternate SSH config, and route overrides stay blocked. Releases before alpha.9 deny every `ssh`.

## Reopen protocol

1. Start with the active hook, not source state:
   - Read the `--release` and `--entry` in `~/.codex/hooks.json` (and Cursor's hooks file where installed).
   - Compare that release with the latest published one; most friction on an old host is already fixed upstream.
2. Run `~/.local/bin/safe-yolo doctor --all` (3.0.0-beta.5 and later). Older installs predate the global command and must be reinstalled with the public installer once.
3. For a reported friction: capture the exact tool name/command and policy/audit decision; add a regression test; release and activate on the affected host; prove one live action before declaring it fixed.
4. Never manually edit an immutable release. Update with `safe-yolo update` or the public installer; both refuse to replace foreign hooks.

## Remaining work

### Approved, non-urgent hygiene

`/home/dev/.safe-yolo/releases/1.0.5` is incomplete and inactive. It is approved for reversible quarantine, but do not delete it. Bundle that move with a future devbox maintenance release to avoid a standalone hook-trust cycle.

### Optional future capability: production release contracts

Agents intentionally cannot deploy to production yet. A project-specific release contract would permit a deployment only after externally verifiable evidence for the exact target, CI/artifact/commit, rollback path, and post-deploy smoke. Choose the first pilot project before implementing this.

## Durable source of truth

- Repository: `https://github.com/Slaytek-Systems/safe-yolo`
- Active configuration: each host's `~/.codex/hooks.json`
- Immutable releases: each host's `~/.safe-yolo/releases/`
- Evidence: `safe-yolo doctor --all` on each host
- Rollback artifacts: each host's `~/.safe-yolo/backups/`
