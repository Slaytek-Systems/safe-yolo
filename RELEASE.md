# Safe YOLO 3.0.0-beta.13

In Claude Code, Safe YOLO now owns its own `PreToolUse` hook, not the whole
`PreToolUse` list. No decision changes: the policy is the one in beta.12.

Before this release, install and update required Safe YOLO's hook to be the
only `PreToolUse` hook. A second hook from another tool in Claude Code
settings made `safe-yolo update` stop with "Existing Safe YOLO hook changed;
refusing to overwrite it", and `doctor` report the installation unhealthy,
although Safe YOLO's own hook was intact.

Claude Code:

- First install appends Safe YOLO's group after the existing `PreToolUse`
  groups. Update replaces Safe YOLO's one hook where it stands. No other hook
  is changed or moved.
- Doctor requires exactly one Safe YOLO `PreToolUse` hook, pinned to the
  installed release, in a group matched to `*` or with an empty matcher.
  Install always writes `*`. Other owners' hooks are not counted.
- Uninstall removes Safe YOLO's hook, and its group when that leaves the group
  empty, and nothing else.
- Refused at install: a `PreToolUse` value that is not a list of hook groups,
  more than one Safe YOLO hook, a Safe YOLO hook this installation did not
  write (another home or entry, or a pin split across `command` and `args`),
  a Safe YOLO hook in a group not matched to `*`, and any non-empty
  `PostToolUse` list.
- Uninstall still needs operator review when the file as first found, before
  the first install, already held a Safe YOLO hook.

Codex and Cursor are unchanged: Safe YOLO must still be the only `PreToolUse`
(`preToolUse`) hook. Codex discards a whole hooks file over one declaration it
cannot load and records hook trust by position, so sharing that list safely
needs its own work.

All three harnesses:

- Uninstall keeps the file's current permissions.
- Uninstall stages the new file, then compares the live file with what it
  read, then renames. A save that lands before the comparison is refused. A
  save by another program between the comparison and the rename is still
  lost; nothing locks the file.
- In Codex, install sets `description` only when it is absent, and uninstall
  restores the earlier value only when the installer's own text is still
  there.
- Update accepts a receipt from before the release-pinned bootstrap.

Limits. Claude Code runs matching hooks concurrently and documents that a deny
outranks every other decision. Another hook can still rewrite a tool input
that Safe YOLO allowed, and Safe YOLO does not read the rewritten input. Safe
YOLO is backpressure, not a boundary against other same-user configuration.
Doctor still reports any later edit to the harness file as "configuration
changed after activation". Deactivate, rollback and uninstall refuse after
such an edit. A successful update to a different version takes the edited
file as its rollback snapshot; uninstall still compares against the file as
first found.

Linux/Python 3.12+ is the proven platform. Codex, Claude Code, and Cursor have
installation lifecycles. Native hook trust or restart remains harness-specific.
Local customizations are preserved. The custom distribution permission remains
in effect; publication is not a change to an OSI-approved license.
