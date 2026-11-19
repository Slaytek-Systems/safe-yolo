# Safe YOLO 3.0.0-beta.14

OpenCode V2 is now a beta lifecycle harness. OpenCode V2 skips V1 plugins,
including the hand-installed Safe YOLO V1 copy. The new plugin uses the
same policy engine as beta.13.

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
service is running.

## Codex and Claude Code lifecycle changes from beta.13
- First install appends Safe YOLO's group after the existing `PreToolUse`
  groups. Update replaces Safe YOLO's one hook where it stands. No other hook
  changes position, because Codex records hook trust by position.
- Doctor requires exactly one Safe YOLO `PreToolUse` hook, pinned to the
  installed release. Install always writes its group with matcher `*`. Doctor
  accepts `*` in Codex and `*` or an empty matcher in Claude Code. Other
  owners' hooks are not counted.
- Uninstall removes Safe YOLO's hook and leaves every other hook, including
  groups that were already empty. In Codex, a group it empties ahead of
  another group stays as an empty group, and uninstall refuses when another
  hook follows Safe YOLO's inside the same group, because removing it would
  move that hook. Uninstall keeps the file's current permissions and restores
  the Codex `description` only when the installer's own text is still there.
- Uninstall stages the new file, then compares the live file with what it
  read, then renames. A save that lands before the comparison is refused. A
  save by another program between the comparison and the rename is still
  lost; nothing locks the file.
- Update accepts a receipt from before the release-pinned bootstrap.
- Still refused at install: a `PreToolUse` value that is not a list of
  well-formed hook groups, more than one Safe YOLO hook, a Safe YOLO hook this
  installation did not write (another home or entry, or a pin split across
  `command` and `args`), a Safe YOLO hook in a group not matched to `*`, and
  any non-empty `PostToolUse` list.
- Uninstall still needs operator review when the file as first found, before
  the first install, already held a Safe YOLO hook.

Limits. Both harnesses run matching hooks concurrently. Claude Code documents
that a deny outranks every other decision. Codex's source lets any block win
and drops rewrites then; its guide states no rule. Another hook can still
rewrite a tool input that Safe YOLO allowed, and Safe YOLO does not read the
rewritten input. Safe YOLO is backpressure, not a boundary against other
same-user configuration. Cursor is unchanged and still requires Safe YOLO to
be its only `preToolUse` hook. Doctor still reports any later edit to the
harness file as "configuration changed after activation". Deactivate, rollback
and uninstall refuse after such an edit. A successful update to a different
version takes the edited file as its rollback snapshot; uninstall still
compares against the file as first found.

Linux/Python 3.12+ is the proven platform. Codex, Claude Code, Cursor, and OpenCode V2 have
installation lifecycles. Native hook trust or restart remains harness-specific.
Local customizations are preserved. The custom distribution permission remains
in effect; publication is not a change to an OSI-approved license.
