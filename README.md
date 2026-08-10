# Safe YOLO

Portable, deterministic safety rails for high-agency coding agents.

Safe YOLO deliberately pairs full local autonomy with consequence-based hard boundaries: agents can perform ordinary, recoverable work without approval loops, but cannot autonomously perform irreversible destruction, credential exposure, privilege escalation, policy tampering, or unproven production release actions.

## Status

Codex is active on macOS and devbox through older manifest-pinned releases. Version 1.1.0 is a source candidate with structured-write checkpoints and a Cursor fail-closed wiring contract; it is not activation-ready until shell recovery and live host certification pass. Source state is not activation evidence.

## Design

- `policy/` — portable constitutional policy and protected-surface declarations.
- `engine/` — deterministic evaluator and scoped capability model.
- `adapters/` — thin Codex and Cursor lifecycle transports over one consequence engine.
- `hosts/` — macOS and Linux facts only; never separate policy semantics.
- `contracts/` — normalized request/decision schemas, host facts, and externally verifiable release contracts.
- `tests/` — shared conformance corpus, adapter tests, and runtime smoke checks.
- `scripts/` — explicit operator install and health-check entry points.

See [architecture](docs/architecture.md) and the [cutover plan](docs/cutover.md).
