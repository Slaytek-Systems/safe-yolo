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
| OpenCode | Adapter only | `opencode` | Global JavaScript plugin | Lifecycle installer deferred |
| Antigravity | Adapter only | `antigravity` | Agent hook/plugin surface | Lifecycle installer deferred |
| Devin | Adapter only | `devin` | Adapter transport only | No supported native installation surface |

The CLI reports the same machine-readable distinction:

```bash
python3 safe-yolo harnesses
```

`supported` and `beta` entries expose `install`, `doctor`, and `deactivate`.
`adapter-only` entries deliberately reject those commands.

Current native contract references:

- [Claude Code hooks](https://code.claude.com/docs/en/hooks)
- [Cursor hooks](https://cursor.com/docs/hooks)
- [OpenCode plugins](https://opencode.ai/docs/plugins/)
- [Grok plugins and hooks](https://docs.x.ai/build/features/skills-plugins-marketplaces)
- [Antigravity agent hooks](https://codelabs.developers.google.com/secure-agentic-coding)
