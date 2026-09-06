# Safe YOLO 3.0 architecture contract

## Capability

Permit ordinary agent work without permission ceremony. Deny a small set of direct actions and tell the agent which safe method to use instead.

Safe YOLO is backpressure, not containment. Durable protection remains scoped operating-system and provider authority, protected production systems, recoverable state, and operator-owned activation.

## Canonical decisions

The runtime returns exactly two outcomes:

- `allow` — continue immediately;
- `deny` — stop the method and name the safer route.

Default is `allow`. Unknown tools and unreadable hook payloads are allowed because they do not establish an explicit restricted action. There is no tool-name registry, script registry, interpreter registry, trusted-path list, shell data-flow analysis, provenance inference, or generic fail-closed classification.

Restricted direct actions are:

- filesystem deletion;
- Git history or destructive ref mutation;
- production mutation;
- remote commands whose local string carries a restricted consequence (`scp`/`rsync` remain `remote.execute` in the v1 inspector; interactive SSH is transport and is not inspected after login);
- privilege-changing execution;
- binding a service to a public interface;
- credential material access or environment-wide credential dumping;
- modification of Safe YOLO or the hook surface that enforces it.

Current-repository pull-request merges are ordinary shipping and remain allowed. Protection bypasses such as `gh pr merge --admin` and cross-repository `-R/--repo` merges are denied. Direct deployment CLIs remain denied in favor of repository-owned merge and deployment workflows.

The direct recognizers are deliberately narrow. Composition such as wrappers, scripts, inline programs, shell chains, or a new semantic tool can route around them. That is an accepted property of backpressure and must not be repaired with another general classifier.

## No approval state

The current runtime is stateless. It has no approval request, receipt, token, timer, retry allowance, or `PostToolUse` hook. The same restricted action receives the same denial every time. Human silence or a tool timeout cannot change the result.

## Shared truth and surfaces

The direct consequence rules live in `engine/`; adapters only translate lifecycle payloads. Codex is the first 3.0 surface. Cursor parity and semantic consequence metadata from future tools are deferred until each surface can be observed and tested.

## Release boundary

The 3.0 candidate reuses immutable release manifests, hash-verifying bootstrap, and non-overwriting installation. Source integration, immutable installation, hook activation, live runtime proof, and host recovery proof remain separate outcomes.

Safe YOLO cannot install or activate its own enforcement release. Credential exposure and enforcement modification require an operator-maintenance path outside the governed agent session.
