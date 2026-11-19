# Safe YOLO 3.0.0-beta.13

Safe YOLO now owns its own `PreToolUse` hook in Codex and Claude Code, not the
whole `PreToolUse` list. No decision changes: the policy is the one in beta.12.

Before this release, install and update required Safe YOLO's hook to be the
only `PreToolUse` hook. A second hook from another tool made `safe-yolo update`
stop with "Existing Safe YOLO hook changed; refusing to overwrite it", and
`doctor` report the installation unhealthy, although Safe YOLO's own hook was
intact.

- Install and update keep every `PreToolUse` hook group that holds no Safe
  YOLO hook, in its original order, after Safe YOLO's own group.
- Doctor requires exactly one Safe YOLO `PreToolUse` hook, matched to `*` and
  pinned to the installed release. Other owners' hooks are not counted.
- Uninstall removes Safe YOLO's group and leaves the others.
- Still refused: a `PreToolUse` value that is not a list of hook groups, a
  Safe YOLO hook from another installation or entry, and a Safe YOLO hook that
  shares a group with another command or is not matched to `*`.

Limits. Both harnesses run matching hooks concurrently. Claude Code documents
that a deny outranks every other decision, so another hook cannot cancel a
Safe YOLO denial there. Codex documents that one hook cannot stop another from
starting, and gives no rule for combining `PreToolUse` decisions. Another hook
can still rewrite a tool input after Safe YOLO has read it. Safe YOLO is
backpressure, not a boundary against other same-user configuration. Cursor is
unchanged and still requires Safe YOLO to be its only `preToolUse` hook. A
non-empty `PostToolUse` list is still refused at install. Doctor still reports
any later edit to the harness file as "configuration changed after
activation", and deactivate, rollback and uninstall still refuse after such an
edit until the next update records the file again.

Linux/Python 3.12+ is the proven platform. Codex, Claude Code, and Cursor have
installation lifecycles. Native hook trust or restart remains harness-specific.
Local customizations are preserved. The custom distribution permission remains
in effect; publication is not a change to an OSI-approved license.
