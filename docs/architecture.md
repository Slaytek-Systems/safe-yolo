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
- interactive or opaque remote shell execution and visible restricted remote effects;
- privilege-changing execution;
- binding a service to a public interface;
- credential material access or environment-wide credential dumping;
- modification of Safe YOLO or the hook surface that enforces it.

Current-repository pull-request merges are ordinary shipping and remain allowed. Protection bypasses such as `gh pr merge --admin` and cross-repository `-R/--repo` merges are denied. Direct deployment CLIs remain denied in favor of repository-owned merge and deployment workflows.

The direct recognizers are deliberately narrow. Composition such as wrappers, scripts, inline programs, shell chains, or a new semantic tool can route around them. That is an accepted property of backpressure and must not be repaired with another general classifier.

SSH is one shared recognizer rather than an adapter exception. Explicit no-session forwarding and visible ordinary remote commands are allowed. Interactive shells, subsystems, alternate configuration files, and restricted local or remote commands remain denied. The exact Devbox maintenance command is accepted only when its host and command match the contract and no command-line host, route, port, user, jump, proxy, control-socket, or config override can redirect it.

## No approval state

The current runtime is stateless. It has no approval request, receipt, token, timer, retry allowance, or `PostToolUse` hook. The same restricted action receives the same denial every time. Human silence or a tool timeout cannot change the result.

## Shared truth and surfaces

The direct consequence rules live in `engine/`; adapters only translate native
lifecycle payloads and responses. The distribution CLI owns discovery,
installation receipts, immutable release pins, doctor checks, and rollback.
No harness owns policy behavior that another adapter cannot reach.

Every installed hook invokes a bootstrap inside the immutable, manifest-covered
release and carries the selected Safe YOLO, user, and harness configuration
roots. This keeps non-default installs inside the same protected path model.

Harness lifecycle support is promoted independently. An included adapter is
not called supported until its native configuration, direct allow/deny
canaries, doctor, and exact deactivation journey pass. This keeps staged
releases honest without turning Codex or any other harness into the product.

## Release boundary

The 3.0 candidate reuses immutable release manifests, hash-verifying bootstrap, and non-overwriting installation. Source integration, immutable installation, hook activation, live runtime proof, and host recovery proof remain separate outcomes.

Safe YOLO cannot install or activate its own enforcement release. Credential exposure and enforcement modification require an operator-maintenance path outside the governed agent session.
