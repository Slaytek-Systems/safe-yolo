# Architecture contract

## Operating posture

Target Codex posture on each host:

```toml
approval_policy = "never"
sandbox_mode = "danger-full-access"
```

Safe YOLO—not approval prompts or any single harness sandbox—is the authoritative consequence boundary. Supported harnesses translate native lifecycle events into the normalized request contract and translate one shared decision back into native enforcement.

## Constitutional law

Every valuable asset must be independently recoverable or protected by exact authority. Safe YOLO governs consequences at the closest reliable boundary instead of trying to prove the internal behaviour of every development command.

- `block_hard` is reserved for unrecoverable destruction, credential exposure or exfiltration, privilege escalation, safety-control-plane tampering, and equivalent consequences.
- `block_method` rejects an unclassified tool surface or a mechanism that bypasses an asset boundary while preserving the objective. It is fail-closed but not a declaration that the intended outcome is forbidden.
- `require_capability` represents exact, scoped, expiring authority. The wire name remains stable for adapter compatibility; semantically it is authority, not a generic escape hatch.
- `allow_report` is autonomous and auditable. It does not ask the operator to babysit routine work.

Risk colours are policy authoring vocabulary. The stable runtime contract is the five decision outcomes in `contracts/decision.schema.json`.

## Invariants

1. Constitutional Red actions cannot be overridden.
2. Unknown side-effecting tool types fail closed as method blocks until an adapter supplies a consequence mapping.
3. Harness/policy modification requires an exact, short-lived, session-bound maintenance capability.
4. The adapter audits decisions without retaining raw secrets or tool content.
5. A canonical conformance corpus produces equivalent decisions across macOS and Linux.
6. Host adapters declare facts (paths, service managers, launchers); they cannot weaken common policy.
7. Raw production deploy commands are blocked. A release is permitted only through a repository-specific, externally verifiable contract.
8. Recoverable removal uses the manifest-pinned quarantine helper and records an append-only restore receipt.
9. A harness is not certified merely because it declares hooks. Its live failure mode and covered tool surfaces must be proved.
10. Ordinary repository development is autonomous. Safety comes from recoverable local state and independent boundaries around Git history, credentials, production, services, and durable data—not from maintaining an exhaustive command allowlist.

## Recovery state

Structured Codex and Cursor writes checkpoint every exact target before the adapter returns permission. Existing files are copied with size and SHA-256 evidence and absent targets are recorded. Structured writes through symlinks fail closed because the apparent path is not the mutated object. A failed or oversized checkpoint blocks the write as `recovery.unavailable`. Recovery materialization requires a new empty destination and never overwrites current work.

The store is append-only, private to the host user, and capped at 1 GiB per host. Reaching the cap blocks further structured writes rather than deleting recovery evidence or exhausting the disk silently.

Shell commands with mutable or unknown effects take one Git workspace checkpoint per session turn. The checkpoint binds the committed HEAD, a binary patch for dirty tracked state, and hashed copies of non-ignored untracked files and symlinks. Multiple shell calls in the turn reuse the original pre-turn state. Known read-only command shapes remain autonomous outside repositories; output redirects are treated as mutations. Mutable shell work outside a committed Git workspace requires an explicit recovery contract and otherwise fails closed.

Git checkpoints cover repository state; they do not claim to recover ignored files, paths outside the checkout, network calls, or service state. Those assets require their own host/provider recovery proof. Explicit isolation remains optional for downloaded or intentionally untrusted code, not the default route for ordinary repository work.

Version 1.1.0 remains a source candidate until the adapters pass live hook-failure, checkpoint, non-obstruction, and cross-host conformance probes.

## Trust boundaries

- Codex’s trusted lifecycle-hook registration is the local bootstrap boundary.
- The active release must be hash-verified by a minimal bootstrap before loading the engine; verification failure blocks tool use.
- Release evidence must come from external, agent-non-writable sources and bind exact repository, target commit/artifact, environment, service, and expiry.
- A repository-local file alone is never sufficient deployment proof.

## Explicit non-goals

- No security guarantee against a malicious local account outside Codex’s controlled tool path.
- No automatic harness update from an agent session.
- No generic escape hatches, slash-command overrides, or arbitrary command allowlists for Red actions.
- No universal transaction broker or attempt to model every executable before ordinary development can proceed.

## Harness certification

- **Certified:** pre-effect denial is proved for every mutating tool surface, hook/bootstrap failure is fail-closed, the control plane is protected, and the common corpus passes.
- **Layered:** gaps in hook coverage or failure semantics are contained by an independent sandbox or kernel boundary.
- **Advisory:** decisions are logged or prompted but a bypass remains. Advisory integrations must never be described as Safe YOLO enforcement.

Codex and Cursor are the first shared-engine adapters. Pi, Hermes, Claude Code, and Grok should appropriate the normalized protocol rather than copy policy rules.
