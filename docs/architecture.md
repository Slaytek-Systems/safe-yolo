# Architecture contract

## Operating posture

Target Codex posture on each host:

```toml
approval_policy = "never"
sandbox_mode = "danger-full-access"
```

Safe YOLO—not approval prompts or the native Codex sandbox—is the authoritative safety boundary. Each supported host runs the same policy engine through one authoritative Codex `PreToolUse` adapter.

## Invariants

1. Constitutional Red actions cannot be overridden.
2. Unknown side-effecting tool types fail closed.
3. Harness/policy modification requires an exact, short-lived, session-bound maintenance capability.
4. The adapter audits decisions without retaining raw secrets or tool content.
5. A canonical conformance corpus produces equivalent decisions across macOS and Linux.
6. Host adapters declare facts (paths, service managers, launchers); they cannot weaken common policy.
7. Raw production deploy commands are blocked. A release is permitted only through a repository-specific, externally verifiable contract.
8. Raw Git force pushes remain constitutional Red. A named stack manager may own a separately reviewed Blue action only when its default preserves lease checks, stale-remote rejection, repository verification, and explicit merge authority; bypass flags remain blocked.

## Trust boundaries

- Codex’s trusted lifecycle-hook registration is the local bootstrap boundary.
- The active release must be hash-verified by a minimal bootstrap before loading the engine; verification failure blocks tool use.
- Release evidence must come from external, agent-non-writable sources and bind exact repository, target commit/artifact, environment, service, and expiry.
- A repository-local file alone is never sufficient deployment proof.

## Explicit non-goals

- No security guarantee against a malicious local account outside Codex’s controlled tool path.
- No automatic harness update from an agent session.
- No generic escape hatches, slash-command overrides, or arbitrary command allowlists for Red actions.
