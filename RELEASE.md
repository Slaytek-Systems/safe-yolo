# Safe YOLO 3.0.0-beta.14

OpenCode V2 is now a beta lifecycle harness. OpenCode V2 skips V1 plugins,
including the hand-installed Safe YOLO V1 copy. The new plugin uses the
same policy engine as beta.13.

- `safe-yolo install --harness opencode` writes one V2 plugin,
  `plugins/safe-yolo.js`, in the folder OpenCode reads: `OPENCODE_CONFIG_DIR`
  when set, otherwise `$XDG_CONFIG_HOME/opencode`, otherwise
  `~/.config/opencode`. It adds no `opencode.json` entry and leaves other
  plugins alone. `install` with no `--harness` detects OpenCode from that
  folder even when `opencode` is not on `PATH`.
- Install refuses when the `opencode` on `PATH` is 1.x, and when an active
  OpenCode installation is wired to a different folder. Update stays in the
  folder its receipt records.
- The plugin sends each tool call to the pinned release and stops the call on a
  deny. It also stops the call when the adapter fails, exits non-zero, returns
  no decision, hits a pipe error, or takes more than 10 seconds; on a pipe
  error or timeout it stops the bootstrap and the adapter it started.
- Install replaces a file at that path only when it is byte-identical to a
  plugin rendered from an installed release, or is the retired V1 plugin with
  only its pin constants changed. The V1 copy is backed up. Any other file is
  refused and left unchanged.
- The plugin must be a regular file in a `plugins` folder that is not a
  symlink, for every lifecycle command.
- Doctor, update, rollback, uninstall and deactivate cover OpenCode. Doctor
  checks that the plugin is byte-identical to the one rendered from the pinned
  release, and runs allow and deny canaries. Uninstall moves the plugin to
  `~/.safe-yolo/backups/`, across filesystems too, and a rerun finishes an
  interrupted uninstall. Deactivate restores the exact previous file.
- The OpenCode adapter now keeps a shell call's `workdir` for both `bash` and
  `shell`, so a relative path is judged where the command runs.
- `scripts/publish.py --check` now exercises four harnesses.

Limits. If OpenCode cannot load the plugin, it logs `failed to load plugin`
and runs without Safe YOLO; doctor cannot detect that. After install, run
`opencode service restart` if the OpenCode background service is running,
then check that `opencode api plugin.list` shows the `safe-yolo` entry with
status `active`, not `failed`, and try a harmless allowed and a denied command
in a session. Another plugin's `execute.before` hook can change a tool's input
after Safe YOLO has read it.

## Changes from beta.12, first shipped in beta.13

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

Linux/Python 3.12+ is the proven platform. Codex, Claude Code, Cursor, and OpenCode V2 have
installation lifecycles. Native hook trust or restart remains harness-specific.
Local customizations are preserved. The custom distribution permission remains
in effect; publication is not a change to an OSI-approved license.
