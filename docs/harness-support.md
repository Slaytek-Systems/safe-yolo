# Harness support matrix

Safe YOLO separates adapter availability from distribution support. An adapter
becomes lifecycle-supported only after native install, direct canaries, doctor,
and exact rollback are proven.

| Harness | Status | Install ID | Native surface | Activation note |
| --- | --- | --- | --- | --- |
| Codex | Supported | `codex` | `~/.codex/hooks.json` | Restart and review/trust the hook in `/hooks` |
| Claude Code | Beta | `claude-code` | `~/.claude/settings.json` | Restart and verify the `PreToolUse` hook in `/hooks` |
| Cursor | Beta | `cursor` | `~/.cursor/hooks.json` | Cursor watches and reloads user hooks |
| Grok | Adapter only | `grok` | Native hook/plugin surface | Lifecycle installer deferred |
| OpenCode | Beta | `opencode` | `plugins/safe-yolo.js` in the OpenCode config folder (V2) | Discovered at startup; run `opencode service restart` if the background service runs, then check `opencode api plugin.list` |
| Antigravity | Beta | `antigravity` | `safe-yolo` named group in `config/hooks.json` under the Gemini root | Start a new session and confirm the hook in `/hooks` |
| Devin | Adapter only | `devin` | Adapter transport only | No supported native installation surface |

The CLI reports the same machine-readable distinction:

```bash
python3 safe-yolo harnesses
```

`supported` and `beta` entries expose `install`, `doctor`, and `deactivate`.
`adapter-only` entries deliberately reject those commands.

Each installation records the configuration folder it wired. For every
supported harness, install refuses a different folder while that installation
is active, for example after `CODEX_HOME`, `CLAUDE_CONFIG_DIR`,
`OPENCODE_CONFIG_DIR`, `XDG_CONFIG_HOME`, `GEMINI_HOME` or `--config-home` changes. To move or
repoint a harness's configuration, run `safe-yolo uninstall --harness <id>`
first, then install against the new folder. To reinstall in place, use the
recorded folder.

OpenCode support targets OpenCode V2 (proven on 2.3.2). Safe YOLO owns one
file, `plugins/safe-yolo.js` in the OpenCode config folder. It finds that
folder the way the OpenCode 2.3.2 CLI does: a non-empty `OPENCODE_CONFIG_DIR`,
otherwise a non-empty `$XDG_CONFIG_HOME/opencode`, otherwise
`~/.config/opencode`. An empty `OPENCODE_CONFIG_DIR` counts as unset. Install refuses
when an active OpenCode installation is wired to a different folder; update
stays in the folder its receipt records. It adds no `opencode.json` entry and
leaves other plugins alone.

Install replaces a file at that path only when it can prove the file is Safe
YOLO's: byte-identical to a plugin rendered from an installed release, or the
retired V1 plugin with only its five pin constants changed. Any other file is
refused and left unchanged. The V1 copy is backed up first. Install also
refuses when the `opencode` on `PATH` reports a 1.x version, because V1 cannot
run the V2 plugin and would lose its working V1 hook. It accepts only output
that is one version line in the shape OpenCode prints, `opencode v2.3.2` or a
bare `2.3.2`, and refuses anything else, including more than one line, empty
output, or no answer within 30 seconds. This is a sanity check on the text,
not proof of which program printed it. With no `opencode` on `PATH` install
proceeds. `install` without `--harness` skips a V1 OpenCode, says why, and
still installs the other detected harnesses; `--harness opencode` refuses. The plugin file must be a regular file, not a
symlink, and its `plugins` folder must not be a symlink. Install, doctor,
update, rollback, uninstall and deactivate all apply that rule.

The plugin stops a tool call on a deny and also when the adapter fails, exits
non-zero, returns no decision, hits a pipe error, or takes more than 10
seconds. On a pipe error or timeout it stops the bootstrap and the adapter it
started.

Doctor checks the file, the release and direct canaries. It cannot prove that
the running OpenCode loaded the plugin: if `setup` fails, OpenCode logs
`failed to load plugin` and runs without Safe YOLO. After a restart, check it
against the server and location your sessions use. A bare `opencode api`
call can start or select the default server and asks about its default
location, which may not be the session you care about:

```sh
opencode api plugin.list
```

The `safe-yolo` entry must show `"state":{"status":"active"}`, and its source
must be the `plugins/safe-yolo.js` file in the config folder Safe YOLO
installed to. A plugin that
failed to load shows `"status":"failed"` with its error. The first call after
the server starts can return an empty list while plugins load; run it again.
`opencode plugin list` lists failed plugins without their status, so it is not
a check. Then, in a session, ask for `echo hello`, which should run, and
`git push --force origin main` in a scratch repository, which Safe YOLO should
deny.

Uninstall, and deactivate when there was no previous file, copy the plugin to
`~/.safe-yolo/backups/`, check the copy, check the plugin still has the bytes
Safe YOLO installed, and only then delete it. The copy's name comes from the
plugin's digest. A failed fresh install removes its plugin the same way, into
that attempt's own `backups/pre-opencode-…` folder as `failed-safe-yolo.js`. If an
uninstall stops after deleting the plugin, doctor reports the plugin missing,
and running uninstall again finds that copy and finishes. If the plugin is
missing and no matching copy exists, or the plugin changed, uninstall refuses
and changes nothing. `deactivate` restores the exact previous file when there
was one. After uninstall, restart each OpenCode server that loaded Safe YOLO
and confirm the plugin is absent.

The OpenCode adapter treats OpenCode's credential stores as credentials: the
V1 `auth.json` and the V2 SQLite database, `opencode.db` in OpenCode's data
folder (`$XDG_DATA_HOME/opencode`, otherwise `~/.local/share/opencode`, or
`OPENCODE_DB`), with its `-wal`, `-shm` and `-journal` files.

Antigravity support targets the `agy` CLI and its
[hooks contract](https://antigravity.google/docs/hooks). Safe YOLO owns one
named group, `safe-yolo`, in `config/hooks.json` under the Gemini root. It
finds the root this way: the `--config-home` folder if given, otherwise a
non-empty `GEMINI_HOME`, otherwise `~/.gemini`. The group install writes is:

```json
{
  "safe-yolo": {
    "enabled": true,
    "PreToolUse": [
      {"matcher": "*", "hooks": [{"type": "command", "command": "<pinned bootstrap>", "timeout": 10}]}
    ]
  }
}
```

The pinned bootstrap runs `--entry antigravity_v3` and passes the root as
`--harness-home`. Other named groups in the file are kept and never read or
judged. A group is Safe YOLO's only when it equals, field for field, what the
installer writes for the pin the receipt records; only the `python3`
interpreter path may differ, the command must keep the installer's spelling
and flag order, and `timeout` must be an integer. Doctor requires that group
once.

First install refuses, and changes nothing, when a `safe-yolo` group is
already there, except for a group of that same shape whose command runs a
release already present under this Safe YOLO home's `releases/` folder, with
entry `antigravity_v3`. That is the old hand-made wiring. Install backs the
file up and replaces only that group. Uninstall removes only the `safe-yolo`
group. Deactivate restores the exact previous file.

Antigravity runs a hook's decision only when the hook exits 0 and prints
JSON: `{"decision":"allow"}` passes the call on and
`{"decision":"deny","reason":"…"}` blocks it. A hook that exits non-zero is
ignored, so the call runs. For this entry the bootstrap therefore replies with
a deny and exit 0 when the release fails verification or is missing, or when
the adapter exits non-zero or prints no decision. A hook that crashes before
it can reply, runs past its 10-second timeout, or prints garbage still fails
open, and Antigravity offers no fail-closed setting.

Doctor checks the group, the release and allow and deny canaries through the
pinned command. It cannot prove Antigravity loaded the hook. Start a new
Antigravity session, run `/hooks` and confirm the `safe-yolo` `PreToolUse`
hook is listed.

One Safe YOLO home keeps one Antigravity receipt, so it wires one Gemini root.
T3 Code launches Antigravity with `GEMINI_HOME` set to a per-profile root, so
that profile reads `<profile>/config/hooks.json`, not `~/.gemini`. Install
refuses a second root while the first is active, and a second Safe YOLO home
for the same user is refused because the global `safe-yolo` command belongs
to the first. To protect a T3 profile instead of `~/.gemini`, install with
`--config-home <profile>` (or with `GEMINI_HOME` set to it). Covering both
roots at once is not supported in this release.

Current native contract references:

- [Claude Code hooks](https://code.claude.com/docs/en/hooks)
- [Cursor hooks](https://cursor.com/docs/hooks)
- [OpenCode plugins](https://opencode.ai/docs/plugins/) and [server hooks](https://opencode.ai/docs/build/plugins/server/)
- [Grok plugins and hooks](https://docs.x.ai/build/features/skills-plugins-marketplaces)
- [Antigravity hooks](https://antigravity.google/docs/hooks)
