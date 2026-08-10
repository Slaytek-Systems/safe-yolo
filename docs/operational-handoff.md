# Safe YOLO operational handoff

## State

The baseline is live on both hosts. Do not infer activation from source changes alone: the active Codex hook pin and a live audit record are the authority.

| Host | Observed active release | Current source |
| --- | --- | --- |
| macOS (`/Users/slayga`) | `1.0.10`; re-run doctor before changing the pin | `feat/consequence-kernel`, version `1.1.0` candidate |
| devbox (`/home/dev`) | Exact active pin requires a fresh doctor receipt | Clean `fix/cursor-autonomy-hardening`, version `1.0.17` at the convergence audit |

Both hosts use `approval_policy = "never"` and `sandbox_mode = "danger-full-access"`. Deterministic policy enforcement remains the safety boundary.

## Baseline capabilities

- Normal code, tests, commits, and clean feature-branch pushes proceed without approval prompts.
- Codex task/thread read, create, archive, message, and collaboration tools are classified rather than fail-closed as unknown.
- macOS protects credential/system surfaces (`~/.ssh`, shell profiles, LaunchAgents, Keychain access).
- Permanent deletion, force pushes, secret exposure, control-plane mutation, and unproven release actions remain hard-blocked.
- Recoverable removal uses the manifest-pinned quarantine and restore path.
- macOS permits exact audited devbox inspection and maintenance contracts. Unmatched remote execution requires scoped authority.
- Opaque interpreters and unknown tools are method-blocked so the objective can continue through a reviewable route.

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

### Required future capability: production release contracts

Agents intentionally cannot deploy or push release tags without a project-specific external release contract proving the exact target, commit/artifact, gates, rollback path, issuer, and expiry. Choose the first pilot project before implementing the evidence broker.

## Durable source of truth

- Repository: `https://github.com/Mattslayga/safe-yolo`
- Active configuration: each host's `~/.codex/hooks.json`
- Immutable releases: each host's `~/.safe-yolo/releases/`
- Evidence: each host's `~/.safe-yolo/state/audit.jsonl`
- Rollback artifacts: each host's `~/.safe-yolo/backups/`
