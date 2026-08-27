# Safe YOLO

Safe YOLO is small, deterministic backpressure for high-agency coding agents.

The 2.0 candidate defaults to allow. It interrupts only direct, visible consequences and never asks whether an unknown tool, script, interpreter, wrapper, or composed shell program is generally trustworthy.

An approval-eligible action follows one contract:

1. deny the first attempt;
2. ask the person through Codex `request_user_input` with a sanitized action summary and exact fingerprint;
3. record the host-observed answer without exposing a token to the model;
4. allow one identical retry in the same task turn;
5. consume the receipt.

Credential access and modification of the enforcement surface are operator-only. They never offer an in-task approval route.

## Status

`2.0.0-alpha.1` is a source candidate only. It is not installed or active on any host. The installed 1.x runtime and the legacy engine/adapters in this repository remain untouched for rollback and comparison.

## Candidate implementation

- `engine/consequences_v2.py` — default-allow direct consequence kernel.
- `engine/approvals_v2.py` — exact, expiring, one-shot approval ledger.
- `adapters/codex_v2.py` — Codex `PreToolUse` and `PostToolUse` transport.
- `tests/unit/test_v2_*` — kernel, receipt, and executable-hook journeys.
- `hosts/linux/devbox.v2-candidate.hooks.json` — non-active cutover example.

Existing release verification and immutable installation plumbing is reused. Existing 1.x classification and prompt-capability code is not imported by the 2.0 candidate.

See the [architecture contract](docs/architecture.md) and [reversible cutover plan](docs/cutover.md).
