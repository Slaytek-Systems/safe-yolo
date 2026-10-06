# Safe YOLO

Safe YOLO is small, deterministic backpressure for high-agency coding agents.

Everything is allowed except a short, explicit set of direct actions. A restricted action is denied with a safer route. It is never converted into a human approval prompt.

The deny set is:

- permanent filesystem deletion;
- raw Git history or ref destruction;
- direct deployment or infrastructure mutation, including protection bypasses;
- interactive, hidden, or restricted remote execution, and privileged execution;
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

`3.0.0-beta.4` is the source candidate adding local deletion observations to the
private, harness-agnostic distribution beta. Installed releases remain separate. One
immutable consequence-policy kernel is exposed through native harness adapters.
Codex is supported; Claude Code and Cursor have beta lifecycle support. Other
included adapters remain adapter-only until their install, doctor, and rollback
journeys receive equivalent proof. See the [support matrix](docs/harness-support.md).

## Install the private beta

For installation without Git or GitHub access, use the versioned ZIP and
[download installation guide](docs/download-install.md). Source checkout
installation remains available below.

The proven platform is Linux with Python 3.12+. Clone this private repository
with your own GitHub account, inspect the available harnesses, then explicitly
select one:

```bash
git clone https://github.com/Slaytek-Systems/safe-yolo.git
cd safe-yolo
python3 safe-yolo harnesses
python3 safe-yolo install --harness codex
python3 safe-yolo doctor --harness codex
```

Use `claude-code` or `cursor` instead of `codex` for those beta integrations.
Installation requires a clean Git checkout. Each harness receives an independent
receipt, backup, doctor report, and deactivation path. The shared runtime is
installed only once under `~/.safe-yolo/releases/`.

The Codex integration validates, but does not change, these settings:

```toml
approval_policy = "never"
sandbox_mode = "danger-full-access"

[features]
hooks = true
```

The installer reports the native activation step for the selected harness.
Codex and Claude Code require their own hook review/reload flow. Cursor watches
its user hook file and reloads it automatically. These native observations are
kept separate from direct adapter canaries.

To verify the immutable release, hook pin, configuration, and direct runtime
canaries at any time:

```bash
python3 safe-yolo doctor --all
```

To restore the exact pre-install hook state:

```bash
python3 safe-yolo deactivate --harness codex
```

Deactivation retains the immutable release and rollback evidence. It refuses to
overwrite a harness configuration if another tool or person changed it after
installation. See [Private beta operations](docs/private-beta.md) for
distribution, upgrades, rollback, and limitations.

## Candidate implementation

- `engine/consequences_v3.py` — current deny-only direct consequence policy. Output redirects and mutating executables bind `enforcement.modify` to the actual write target; v3 adapters declare trusted scratch roots (`/tmp` and `~/tmp` by default, replaceable with `--scratch`) so `rm`/`unlink`/`rmdir` and structured `delete_file`/`remove_file` inside those roots is allowed.
- `engine/ssh_command.py` — shared SSH argv parser. Explicit no-session transport and visible ordinary remote commands are allowed; interactive shells, opaque config files, subsystems, command-bearing options with restricted effects, and redirected maintenance commands are denied.
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

Deletion candidates can be recorded as private, sanitized local SQLite observations
without changing any allow/deny decision. Use `python3 safe-yolo observations` for
the read-only grouped JSON report. See [coverage, privacy, and capacity limits](docs/deletion-observation.md).

Antigravity hook files must contain only named hook objects: the Antigravity CLI's Go loader rejects the whole `hooks.json` when any top-level value is not an object (for example a `description` string), and then logs `loaded 0 named hooks`. The ACP server's Python loader tolerates it, which is why the mistake is easy to miss. `GEMINI_HOME` is read from the hook environment because the bootstrap forwards no adapter flags.
