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

Ordinary feature-branch pushes, pull-request creation, and protected merges
without bypass flags remain allowed. Verified merged-branch retirement is part
of the repository's guarded landing workflow and remains allowed there,
including GitHub's transactional `--delete-branch` merge option. Raw ref
deletion remains denied because the command alone cannot prove that the ref is
merged or unchanged. Repository checks and branch protection decide whether a
merge is ready.

## Status

`3.0.0-alpha.6` is the current source candidate. Repository state does not prove installation or activation; hosts install immutable releases through separately reviewed operator maintenance. Earlier immutable releases and adapters remain available for rollback and comparison.

## Candidate implementation

- `engine/consequences_v3.py` — current deny-only direct consequence policy. Output redirects and mutating executables bind `enforcement.modify` to the actual write target; v3 adapters declare trusted scratch roots (`/tmp` and `~/tmp` by default, replaceable with `--scratch`) so `rm`/`unlink`/`rmdir` and structured `delete_file`/`remove_file` inside those roots is allowed.
- `adapters/codex_v3.py` — stateless Codex `PreToolUse` transport.
- `adapters/devin_v3.py` — stateless Devin `PreToolUse` transport over the same kernel.
- `adapters/claude_code_v3.py` — stateless Claude Code `PreToolUse` transport over the same kernel; wired from `~/.claude/settings.json` (see `hosts/linux/devbox.claude-code-candidate.settings.json`).
- `adapters/grok_v3.py` — stateless Grok CLI `PreToolUse` transport over the same kernel (see `hosts/linux/devbox.grok-candidate.hooks.json`).
- `adapters/cursor_v3.py` — stateless Cursor Agent transport over the same kernel (see `hosts/linux/devbox.cursor-candidate.hooks.json`).
- `adapters/opencode_v3.py` — stateless OpenCode `tool.execute.before` transport over the same kernel (see `hosts/linux/devbox.opencode-candidate.plugin.js`).
- `adapters/antigravity_v3.py` — stateless Antigravity ACP `PreToolUse` transport over the same kernel (see `hosts/linux/devbox.antigravity-candidate.hooks.json`).
- `tests/unit/test_v3_*`, `tests/unit/test_devin_adapter.py`, `tests/unit/test_claude_code_adapter.py`, `tests/unit/test_grok_adapter.py`, `tests/unit/test_cursor_v3_adapter.py`, and `tests/unit/test_opencode_v3_adapter.py` — allow, deny, release, and executable-hook journeys.
- `hosts/linux/devbox.v3-candidate.hooks.json` — non-active cutover example.

Existing release verification and immutable installation plumbing is reused. The 3.0 runtime has no approval ledger, receipt, expiry, retry, or `PostToolUse` path.

See the [architecture contract](docs/architecture.md) and [reversible cutover plan](docs/cutover.md).

Antigravity hook files must contain only named hook objects: the Antigravity CLI's Go loader rejects the whole `hooks.json` when any top-level value is not an object (for example a `description` string), and then logs `loaded 0 named hooks`. The ACP server's Python loader tolerates it, which is why the mistake is easy to miss. `GEMINI_HOME` is read from the hook environment because the bootstrap forwards no adapter flags.
