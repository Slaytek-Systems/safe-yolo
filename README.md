# Safe YOLO

Safe YOLO is small, deterministic backpressure for high-agency coding agents.

Everything is allowed except a short, explicit set of direct actions. A restricted action is denied with a safer route. It is never converted into a human approval prompt.

The deny set is:

- permanent filesystem deletion;
- raw Git history or ref destruction;
- direct deployment or infrastructure mutation, including protection bypasses;
- remote or privileged execution;
- public network exposure;
- credential access; and
- modification of Safe YOLO or its hook surface.

Ordinary feature-branch pushes, pull-request creation, and protected merges without bypass flags remain allowed. Repository checks and branch protection decide whether a merge is ready.

## Status

`3.0.0-alpha.2` is the current source candidate. Repository state does not prove installation or activation; hosts install immutable releases through separately reviewed operator maintenance. Earlier immutable releases and adapters remain available for rollback and comparison.

## Candidate implementation

- `engine/consequences_v3.py` — current deny-only direct consequence policy.
- `adapters/codex_v3.py` — stateless Codex `PreToolUse` transport.
- `adapters/devin_v3.py` — stateless Devin `PreToolUse` transport over the same kernel.
- `tests/unit/test_v3_*` and `tests/unit/test_devin_adapter.py` — allow, deny, release, and executable-hook journeys.
- `hosts/linux/devbox.v3-candidate.hooks.json` — non-active cutover example.

Existing release verification and immutable installation plumbing is reused. The 3.0 runtime has no approval ledger, receipt, expiry, retry, or `PostToolUse` path.

See the [architecture contract](docs/architecture.md) and [reversible cutover plan](docs/cutover.md).
