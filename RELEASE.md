# Safe YOLO 3.0.0-beta.13

Safe YOLO now owns its own `PreToolUse` hook in Codex and Claude Code, not the
whole `PreToolUse` list. No decision changes: the policy is the one in beta.12.

Before this release, install and update required Safe YOLO's hook to be the
only `PreToolUse` hook. A second hook from another tool made `safe-yolo update`
stop with "Existing Safe YOLO hook changed; refusing to overwrite it", and
`doctor` report the installation unhealthy, although Safe YOLO's own hook was
intact.

- First install appends Safe YOLO's group after the existing `PreToolUse`
  groups. Update replaces Safe YOLO's one hook where it stands. No other hook
  changes position, because Codex records hook trust by position.
- Doctor requires exactly one Safe YOLO `PreToolUse` hook, in a group matched
  to `*` and pinned to the installed release. Other owners' hooks are not
  counted.
- Uninstall removes Safe YOLO's hook and leaves every other hook. In Codex, a
  group it empties ahead of another owner's group stays as an empty group. It
  keeps the file's current permissions, restores the Codex `description` only
  when the installer's own text is still there, and refuses when the file
  changes while it works.
- Update accepts a receipt from before the release-pinned bootstrap.
- Still refused: a `PreToolUse` value that is not a list of hook groups, more
  than one Safe YOLO hook, a Safe YOLO hook this installation did not write
  (another home or entry, or a pin split across `command` and `args`), and a
  Safe YOLO hook in a group not matched to `*`.
- Still refused at install: any non-empty `PostToolUse` list, in Codex and
  Claude Code.
- Uninstall still needs operator review when the file as first found already
  held a Safe YOLO hook.

Limits. Both harnesses run matching hooks concurrently. Claude Code documents
that a deny outranks every other decision. Codex's source lets any block win
and drops rewrites then; its guide states no rule. Another hook can still
rewrite a tool input that Safe YOLO allowed, and Safe YOLO does not read the
rewritten input. Safe YOLO is backpressure, not a boundary against other
same-user configuration. Cursor is unchanged and still requires Safe YOLO to
be its only `preToolUse` hook. Doctor still reports any later edit to the
harness file as "configuration changed after activation". Deactivate, rollback
and uninstall refuse after such an edit; only a successful update to a
different version records the edited file as the new baseline.

Linux/Python 3.12+ is the proven platform. Codex, Claude Code, and Cursor have
installation lifecycles. Native hook trust or restart remains harness-specific.
Local customizations are preserved. The custom distribution permission remains
in effect; publication is not a change to an OSI-approved license.
