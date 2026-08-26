# Safe YOLO

Portable, deterministic safety rails for high-agency coding agents.

Safe YOLO pairs full local autonomy with deterministic backpressure on visibly dangerous tool calls. Repository scripts, interpreters, and launchers are ordinary development execution; they do not require a per-script registry.

Safe YOLO is not a containment boundary for code running as the same operating-system identity. A script can perform operations that are not visible in its top-level invocation. Irreversible protection must therefore live below the command hook: scoped credentials and provider permissions, recoverable local state, protected production systems, and explicit operator-owned activation. The hook remains useful for preventing obvious accidental commands, but it must never be presented as proof that arbitrary same-user code is safe.

## Status

Bootstrap repository. No host is installed or modified from this repository yet.

## Design

- `policy/` — portable direct-command policy and protected-surface declarations.
- `engine/` — deterministic evaluator and scoped capability model.
- `adapters/codex/` — Codex lifecycle-hook transport.
- `hosts/` — macOS and Linux facts only; never separate policy semantics.
- `contracts/` — externally verifiable release-contract definitions.
- `tests/` — shared conformance corpus, adapter tests, and runtime smoke checks.
- `scripts/` — explicit operator install and health-check entry points.

See [architecture](docs/architecture.md) and the [cutover plan](docs/cutover.md).
