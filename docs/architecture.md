# Architecture contract

## Operating posture

Target Codex posture on each host:

```toml
approval_policy = "never"
sandbox_mode = "danger-full-access"
```

Safe YOLO is deterministic consequence backpressure for direct tool calls. It is not the authoritative security boundary for repository code: scripts and interpreters run as the agent's operating-system identity and can perform actions hidden from the top-level command. Each supported host may run the same policy engine through one Codex `PreToolUse` adapter, but durable protection belongs to operating-system identity, scoped credentials, provider controls, and proved recovery.

## Invariants

1. Constitutional Red actions cannot be overridden.
2. Unknown side-effecting tool types fail closed.
3. Harness/policy modification requires an exact, short-lived, session-bound maintenance capability.
4. The adapter audits decisions without retaining raw secrets or tool content.
5. A canonical conformance corpus produces equivalent decisions across macOS and Linux.
6. Host adapters declare facts (paths, service managers, launchers); they cannot weaken common policy.
7. Raw production deploy commands are blocked. A release is permitted only through a repository-specific, externally verifiable contract.
8. Repository scripts, interpreters, and launchers execute normally; Safe YOLO does not maintain script allowlists or claim to inspect their internal effects.

## Trust boundaries

- Codex’s trusted lifecycle-hook registration is the local bootstrap boundary.
- The active release must be hash-verified by a minimal bootstrap before loading the engine; verification failure blocks tool use.
- Release evidence must come from external, agent-non-writable sources and bind exact repository, target commit/artifact, environment, service, and expiry.
- A repository-local file alone is never sufficient deployment proof.
- Direct-command denial is defense in depth, not containment. A host is eligible for this policy only when same-user code cannot reach unacceptable irreversible authority or when that state has a proved restore path.

## Explicit non-goals

- No security guarantee against a malicious local account outside Codex’s controlled tool path.
- No security guarantee against repository code, interpreters, shell functions, or wrappers running inside the same account.
- No automatic harness update from an agent session.
- No generic escape hatches, slash-command overrides, or arbitrary command allowlists for Red actions.
