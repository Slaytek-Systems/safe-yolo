# Architecture contract

## Operating posture

Target Codex posture on each host:

```toml
approval_policy = "never"
sandbox_mode = "danger-full-access"
```

Safe YOLO—not approval prompts or any single harness sandbox—is the authoritative consequence boundary. Supported harnesses translate native lifecycle events into the normalized request contract and translate one shared decision back into native enforcement.

## Constitutional law

Every autonomous mutation must either be demonstrably recoverable or bounded by exact authority. Every potentially unrecoverable consequence must be stopped before execution.

- `block_hard` is reserved for unrecoverable destruction, credential exposure or exfiltration, privilege escalation, safety-control-plane tampering, and equivalent consequences.
- `block_method` rejects an opaque or unclassified route while preserving the objective. It is fail-closed but not a declaration that the intended outcome is forbidden.
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

## Trust boundaries

- Codex’s trusted lifecycle-hook registration is the local bootstrap boundary.
- The active release must be hash-verified by a minimal bootstrap before loading the engine; verification failure blocks tool use.
- Release evidence must come from external, agent-non-writable sources and bind exact repository, target commit/artifact, environment, service, and expiry.
- A repository-local file alone is never sufficient deployment proof.

## Explicit non-goals

- No security guarantee against a malicious local account outside Codex’s controlled tool path.
- No automatic harness update from an agent session.
- No generic escape hatches, slash-command overrides, or arbitrary command allowlists for Red actions.

## Harness certification

- **Certified:** pre-effect denial is proved for every mutating tool surface, hook/bootstrap failure is fail-closed, the control plane is protected, and the common corpus passes.
- **Layered:** gaps in hook coverage or failure semantics are contained by an independent sandbox or kernel boundary.
- **Advisory:** decisions are logged or prompted but a bypass remains. Advisory integrations must never be described as Safe YOLO enforcement.

Codex and Cursor are the first shared-engine adapters. Pi, Hermes, Claude Code, and Grok should appropriate the normalized protocol rather than copy policy rules.
