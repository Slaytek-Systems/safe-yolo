# Safe YOLO

Portable, deterministic safety rails for high-agency coding agents.

Safe YOLO deliberately pairs full local autonomy with consequence-based hard boundaries: agents can perform ordinary, recoverable work without approval loops, but cannot autonomously perform irreversible destruction, credential exposure, privilege escalation, policy tampering, or unproven production release actions.

## Status

Bootstrap repository. No host is installed or modified from this repository yet.

## Design

- `policy/` — portable constitutional policy and protected-surface declarations.
- `engine/` — deterministic evaluator and scoped capability model.
- `adapters/codex/` — Codex lifecycle-hook transport.
- `hosts/` — macOS and Linux facts only; never separate policy semantics.
- `contracts/` — externally verifiable release-contract definitions.
- `tests/` — shared conformance corpus, adapter tests, and runtime smoke checks.
- `scripts/` — explicit operator install and health-check entry points.

See [architecture](docs/architecture.md) and the [cutover plan](docs/cutover.md).
