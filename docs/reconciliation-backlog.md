# Reconciliation backlog

This is the explicit migration backlog between the preserved Mac reference and the authoritative devbox baseline. It is policy work, not a host cutover.

## Chosen direction

Use the richer Mac v0.2 action vocabulary as the starting schema, retain devbox’s single authoritative Codex adapter model, and add devbox-only constitutional protections:

- `network.public_exposure`
- `remote.execute`
- `release.production`

`release.production` is not permanently Red in the final policy. Raw deploy commands remain Red; one exact release may be promoted to Blue only by an externally verifiable, short-lived release contract.

## P0 — safety semantics

1. **Policy merge** — preserve Mac action classes for records, authenticated network access, GitHub PR lifecycle, and deployment evidence; add devbox remote-execution/public-exposure protections.
2. **Control-plane protection** — protect the policy release, engine, adapters, tests, Codex config, hooks, and rules on both hosts. Mac's legacy native path guard currently leaves Codex config/rules writable; the canonical adapter must close that gap.
3. **Secret and exfiltration rules** — carry forward Mac’s Railway wrapper/selector/dynamic-token cases and devbox’s credential-file, Azure, BWS, upload, and authenticated-fetch cases.
4. **Destruction and history** — preserve deletion, truncate/unlink equivalents, Git discard/history rewrite, force-push, tag-push, and protected-branch cases as constitutional or exact-capability policy.
5. **Remote and persistent systems** — preserve macOS LaunchAgent/AppleScript concerns and devbox systemd/Docker/remote-shell concerns as host facts beneath shared `system.modify` and `remote.execute` policy.
6. **Unknown tools** — retain devbox's fail-closed handling for unclassified side-effecting tool types.

## P1 — autonomous work quality

1. Move Mac's safe feature-push constraints (same repository, named non-protected branch, `origin`, no force/broad flags) into common conformance cases.
2. Keep Fallow as a separate deterministic quality gate, not a safety override. Define when it is required and how its result is recorded.
3. Preserve Mac's package-manager, inline-interpreter, shebang-script, and opaque-shell method blocks where the consequence cannot be classified.
4. Reconcile project-specific workspace launchers into declarative, repository-scoped contracts; do not hard-code one client/project into the global engine.

## P2 — Codex compatibility

1. Permit inert Codex-managed metadata such as `approvals_reviewer = "user"` when `approval_policy = "never"`.
2. Verify hook event payloads and tool-name coverage against every supported Codex app-server/CLI version.
3. Pin expected hook bootstrap hashes and make `doctor` report stale trust entries, orphan hooks, policy version, active adapter, and audit permissions.

## Required conformance evidence

- A common corpus must include every preserved Mac hard-barrier case and every devbox engine/security case.
- Each case specifies a policy decision, not merely a host-script output.
- macOS and Linux adapters must produce identical decisions for common cases.
- Runtime smoke tests use harmless fixture actions only; no live destructive probes.
- A production-release fixture proves that local files alone cannot satisfy a release contract.

## Deliberate exclusions

- Runtime audit logs, session state, credentials, Codex databases, and caches remain outside source control.
- No agent-driven self-update path.
- No generic human-text or slash-command bypass for Red actions.
