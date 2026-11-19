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
| Antigravity | Adapter only | `antigravity` | Agent hook/plugin surface | Lifecycle installer deferred |
| Devin | Adapter only | `devin` | Adapter transport only | No supported native installation surface |

The CLI reports the same machine-readable distinction:

```bash
python3 safe-yolo harnesses
```

`supported` and `beta` entries expose `install`, `doctor`, and `deactivate`.
`adapter-only` entries deliberately reject those commands.

OpenCode support targets OpenCode V2 (proven on 2.3.2). Safe YOLO owns one
file, `plugins/safe-yolo.js` in the OpenCode config folder. It finds that
folder the way OpenCode does: `OPENCODE_CONFIG_DIR` when set, otherwise
`$XDG_CONFIG_HOME/opencode`, otherwise `~/.config/opencode`. Install refuses
when an active OpenCode installation is wired to a different folder; update
stays in the folder its receipt records. It adds no `opencode.json` entry and
leaves other plugins alone.

Install replaces a file at that path only when it can prove the file is Safe
YOLO's: byte-identical to a plugin rendered from an installed release, or the
retired V1 plugin with only its five pin constants changed. Any other file is
refused and left unchanged. The V1 copy is backed up first. Install also
refuses when the `opencode` on `PATH` reports a 1.x version, because V1 cannot
run the V2 plugin and would lose its working V1 hook; with no `opencode` on
`PATH` install proceeds. The plugin file must be a regular file, not a
symlink, and its `plugins` folder must not be a symlink. Install, doctor,
update, rollback, uninstall and deactivate all apply that rule.

The plugin stops a tool call on a deny and also when the adapter fails, exits
non-zero, returns no decision, hits a pipe error, or takes more than 10
seconds. On a pipe error or timeout it stops the bootstrap and the adapter it
started.

Doctor checks the file, the release and direct canaries. It cannot prove that
the running OpenCode loaded the plugin: if `setup` fails, OpenCode logs
`failed to load plugin` and runs without Safe YOLO. After a restart, check it:

```sh
opencode api plugin.list
```

The `safe-yolo` entry must show `"state":{"status":"active"}`. A plugin that
failed to load shows `"status":"failed"` with its error. The first call after
the server starts can return an empty list while plugins load; run it again.
`opencode plugin list` lists failed plugins without their status, so it is not
a check. Then, in a session, ask for `echo hello`, which should run, and
`git push --force origin main` in a scratch repository, which Safe YOLO should
deny.

Uninstall moves the plugin file to `~/.safe-yolo/backups/`, copying and
verifying it when that folder is on another filesystem, and can be rerun to
finish if it is interrupted. `deactivate` restores the exact previous file.

Current native contract references:

- [Claude Code hooks](https://code.claude.com/docs/en/hooks)
- [Cursor hooks](https://cursor.com/docs/hooks)
- [OpenCode plugins](https://opencode.ai/docs/plugins/) and [server hooks](https://opencode.ai/docs/build/plugins/server/)
- [Grok plugins and hooks](https://docs.x.ai/build/features/skills-plugins-marketplaces)
- [Antigravity agent hooks](https://codelabs.developers.google.com/secure-agentic-coding)
