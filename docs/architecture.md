# Safe YOLO 2.0 architecture contract

## Capability

Permit ordinary agent work without classification maintenance. Interrupt a small set of direct consequences, show the person what would happen, and bind any approval to one exact retry.

Safe YOLO is backpressure, not containment. Durable protection remains scoped operating-system and provider authority, protected production systems, recoverable state, and operator-owned activation.

## Canonical decisions

The kernel returns exactly three outcomes:

- `allow` — continue immediately;
- `approval_required` — deny once and offer the ask-user journey;
- `operator_only` — deny without an in-task override.

Default is `allow`. Unknown tools are allowed. There is no tool-name registry, script registry, interpreter registry, trusted-path list, shell data-flow analysis, provenance inference, or generic fail-closed classification.

Approval-eligible direct consequences are:

- filesystem deletion;
- Git history or destructive ref mutation;
- production mutation;
- remote shell execution;
- privilege-changing execution;
- binding a service to a public interface.

Operator-only consequences are:

- credential material access or environment-wide credential dumping;
- modification of Safe YOLO or the hook surface that enforces it.

The direct recognizers are deliberately narrow. Composition such as wrappers, scripts, inline programs, shell chains, or a new semantic tool can route around them. That is an accepted property of backpressure and must not be repaired with another general classifier.

## Approval receipt

`PreToolUse` fingerprints the canonical tuple of tool name, tool input, and working directory. The first consequential attempt stores only the fingerprint, consequence, task/turn scope, expiry, and hash of the expected `request_user_input` arguments. Raw tool input is not persisted.

The denial tells the agent to call `request_user_input` with exact arguments. A `PostToolUse` hook observes both those arguments and the host-produced response. Only the currently observed Codex Desktop shape—one exact recommended answer in the nested answer list—mints a receipt. An explicit rejection closes the pending request. Empty, missing, or malformed answers mint nothing and retain the same pending request so the exact prompt can be presented again.

The pending request remains in host-local state for up to thirty minutes and is scoped to the same task and turn. The receipt expires after five minutes, matches one exact action fingerprint, and is consumed by one retry. Neither is returned to the model.

Codex hooks cannot currently turn a `PreToolUse` denial directly into an approval prompt. The blocked attempt followed by ask and retry is therefore intentional.

## Shared truth and surfaces

The consequence and receipt rules live in `engine/`; adapters only translate lifecycle payloads. Codex Desktop is the first proved surface. Cursor, Codex CLI/TUI response-shape parity, and semantic consequence metadata from future tools are deferred until each surface can be observed and tested without permissive parsing.

## Release boundary

The 2.0 candidate reuses immutable release manifests, hash-verifying bootstrap, and non-overwriting installation. It does not import the 1.x classifier or prompt-capability path. Source integration, immutable installation, hook activation, live runtime proof, and host recovery proof remain separate outcomes.

Safe YOLO cannot install or activate its own enforcement release. Credential exposure and enforcement modification require an operator-maintenance path outside the governed agent session.
