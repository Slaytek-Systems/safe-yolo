# Safe YOLO 3.0.0-beta.14

OpenCode V2 is now a beta lifecycle harness. Before this release Safe YOLO saw
no OpenCode tool call: the hand-placed plugin used the V1 API, and OpenCode V2
does not run V1 plugins. No policy decision changes; the policy is the one in
beta.13.

- `safe-yolo install --harness opencode` writes one V2 plugin,
  `plugins/safe-yolo.js`, in the OpenCode config folder (`~/.config/opencode`,
  or `$XDG_CONFIG_HOME/opencode`). It adds no `opencode.json` entry and leaves
  other plugins alone.
- The plugin sends each tool call to the pinned release and stops the call on a
  deny. It also stops the call when the adapter fails, exits non-zero, returns
  no decision, or takes more than 10 seconds.
- An existing Safe YOLO plugin at that path, such as a V1 copy, is backed up
  and replaced. Any other file there is refused and left unchanged.
- Doctor, update, rollback, uninstall and deactivate cover OpenCode. Doctor
  checks that the plugin is byte-identical to the one rendered from the pinned
  release, and runs allow and deny canaries. Uninstall moves the plugin to
  `~/.safe-yolo/backups/`; deactivate restores the exact previous file.
- The OpenCode adapter now keeps a shell call's `workdir` for both `bash` and
  `shell`, so a relative path is judged where the command runs.
- `scripts/publish.py --check` now exercises four harnesses.

Limits. If OpenCode cannot load the plugin, it logs `failed to load plugin`
and runs without Safe YOLO; doctor cannot detect that. Another plugin's
`execute.before` hook can change a tool's input after Safe YOLO has read it.
After install, run `opencode service restart` if the OpenCode background
service is running. Proven on OpenCode 2.3.2 on Linux.

Linux/Python 3.12+ is the proven platform. Codex, Claude Code, Cursor, and
OpenCode have installation lifecycles. Local customizations are preserved. The
custom distribution permission remains in effect; publication is not a change
to an OSI-approved license.
