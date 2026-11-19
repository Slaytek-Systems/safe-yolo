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
| OpenCode | Beta | `opencode` | `~/.config/opencode/plugins/safe-yolo.js` (V2) | Discovered at startup; run `opencode service restart` if the background service runs |
| Antigravity | Adapter only | `antigravity` | Agent hook/plugin surface | Lifecycle installer deferred |
| Devin | Adapter only | `devin` | Adapter transport only | No supported native installation surface |

The CLI reports the same machine-readable distinction:

```bash
python3 safe-yolo harnesses
```

`supported` and `beta` entries expose `install`, `doctor`, and `deactivate`.
`adapter-only` entries deliberately reject those commands.

OpenCode support targets OpenCode V2 (proven on 2.3.2). Safe YOLO owns one
file, `plugins/safe-yolo.js` in the OpenCode config folder, and follows
`XDG_CONFIG_HOME` as OpenCode does. It adds no `opencode.json` entry and leaves
other plugins alone. Install replaces a Safe YOLO V1 plugin (which V2 never
runs) after backing it up, and refuses any other file at that path. The plugin
stops a tool call on a deny and also when the adapter fails, times out, or
returns no decision. If OpenCode cannot load the plugin it logs
`failed to load plugin` with `plugin.id=safe-yolo` and runs without Safe YOLO;
doctor cannot see that. Uninstall moves the plugin file to
`~/.safe-yolo/backups/`; `deactivate` restores the exact previous file.

Current native contract references:

- [Claude Code hooks](https://code.claude.com/docs/en/hooks)
- [Cursor hooks](https://cursor.com/docs/hooks)
- [OpenCode plugins](https://opencode.ai/docs/plugins/) and [server hooks](https://opencode.ai/docs/build/plugins/server/)
- [Grok plugins and hooks](https://docs.x.ai/build/features/skills-plugins-marketplaces)
- [Antigravity agent hooks](https://codelabs.developers.google.com/secure-agentic-coding)
