# Safe YOLO 3.0.0-beta.13

In Claude Code, `safe-yolo update` now works when another tool's `PreToolUse`
hook sits beside Safe YOLO's. No decision changes: the policy is the one in
beta.12.

Before this release, update and doctor required Safe YOLO's hook to be the
only `PreToolUse` hook. A second hook added to Claude Code settings after
install made `safe-yolo update` stop with "Existing Safe YOLO hook changed;
refusing to overwrite it", although Safe YOLO's own hook was intact.

Claude Code:

- Safe YOLO's hook is the one command hook whose command is exactly the pin
  the installation receipt records: same bootstrap, release, manifest digest,
  entry, state folder and home folders. Every other hook belongs to someone else. It is
  not read, judged, moved or changed.
- Update replaces that one hook where it stands.
- Doctor and update require that hook exactly once, in a group whose matcher
  is `*`, the empty string or absent.
- Uninstall removes that hook, and its group when that leaves the group
  empty, and keeps the rest of the list.
- First install is unchanged: it refuses when any `PreToolUse` hook from
  another owner already exists. Add other tools' hooks after installing
  Safe YOLO.

Codex and Cursor are unchanged: Safe YOLO must be the only `PreToolUse`
(`preToolUse`) hook at install, update and doctor.

Limits. Safe YOLO does not check other owners' hooks. Claude Code can drop
the hooks in a settings file when one entry in it is malformed, for example
a `timeout` written as a string, and doctor does not detect that; check
`/hooks` in Claude Code after editing settings by hand. Claude Code runs
matching hooks concurrently and documents that a deny outranks every other
decision. Another hook can still rewrite a tool input that Safe YOLO
allowed, and Safe YOLO does not read the rewritten input. Doctor still
reports any later edit to the harness file as "configuration changed after
activation", and deactivate, rollback and uninstall refuse after such an
edit. A successful update to a different version records the edited file as
the installed file for those checks and as its rollback snapshot; uninstall
still compares against the file as first found. Those checks read the file
once at the start of the command. Nothing locks it, so a save by another
program while uninstall or rollback runs is overwritten.

Linux/Python 3.12+ is the proven platform. Codex, Claude Code, and Cursor have
installation lifecycles. Native hook trust or restart remains harness-specific.
Local customizations are preserved. The custom distribution permission remains
in effect; publication is not a change to an OSI-approved license.
