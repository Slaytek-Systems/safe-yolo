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

Linux/Python 3.12+ is the proven platform. Codex, Claude Code, and Cursor have
installation lifecycles. Native hook trust or restart remains harness-specific.
Local customizations are preserved. The custom distribution permission remains
in effect; publication is not a change to an OSI-approved license.
