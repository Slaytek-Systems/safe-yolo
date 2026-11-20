# Safe YOLO 3.0.0-beta.14

OpenCode V2 is now a beta lifecycle harness. OpenCode V2 skips V1 plugins,
including the hand-installed Safe YOLO V1 copy. The new plugin uses the
same policy engine as beta.13.

- `safe-yolo install --harness opencode` writes one V2 plugin,
  `plugins/safe-yolo.js`, in the folder OpenCode reads: a non-empty
  `OPENCODE_CONFIG_DIR`, otherwise `$XDG_CONFIG_HOME/opencode`, otherwise
  `~/.config/opencode`. It adds no `opencode.json` entry and leaves other
  plugins alone. `install` with no `--harness` detects OpenCode from that
  folder even when `opencode` is not on `PATH`.
- Install refuses when the `opencode` on `PATH` is 1.x or prints anything
  other than one OpenCode version line, and when an active OpenCode
  installation is wired to a different folder. The version check is a sanity
  check, not proof of which program answered. Without `--harness`, a V1
  OpenCode is skipped with a reason and the other harnesses still install.
  Update stays in the folder its receipt records.
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
  release, and runs allow and deny canaries. Uninstall copies the plugin to
  `~/.safe-yolo/backups/` under a name derived from its digest, checks both
  files, then deletes the plugin, so it works across filesystems and a rerun
  finishes an interrupted uninstall. A failed fresh install removes its plugin
  the same way, into that attempt's own `backups/pre-opencode-…` folder. Deactivate restores the exact previous file.
- The OpenCode adapter now protects the V2 credential database
  (`opencode.db` in OpenCode's data folder, or `OPENCODE_DB`) and its `-wal`,
  `-shm` and `-journal` files, as well as the V1 `auth.json`.
- The OpenCode adapter now keeps a shell call's `workdir` for both `bash` and
  `shell`, so a relative path is judged where the command runs.
- `scripts/publish.py --check` now exercises four harnesses with a temporary
  `HOME` and XDG folders and a fixture `opencode` that prints a V2 version, so
  it never runs or touches the host's OpenCode.

Limits. If OpenCode cannot load the plugin, it logs `failed to load plugin`
and runs without Safe YOLO; doctor cannot detect that. After install, run
`opencode service restart` if the OpenCode background service is running,
then check, against the server and location your sessions use, that
`opencode api plugin.list` shows the `safe-yolo` entry with status `active`,
not `failed`, from the plugin file Safe YOLO installed, and try a harmless allowed and a denied command
in a session. Another plugin's `execute.before` hook can change a tool's input
after Safe YOLO has read it.

## Changes from beta.12, first shipped in beta.13

In Claude Code, `safe-yolo update` now works when another tool's `PreToolUse`
hook sits beside Safe YOLO's. No decision changes: the policy is the one in
beta.12.

Before this release, update and doctor required Safe YOLO's hook to be the
only `PreToolUse` hook. A second hook added to Claude Code settings after
install made `safe-yolo update` stop with "Existing Safe YOLO hook changed;
refusing to overwrite it", although Safe YOLO's own hook was intact.

Claude Code:

- Safe YOLO's hook is the one entry that is, field for field, what the
  installer writes for the pin the installation receipt records: same
  bootstrap, release, manifest digest, entry, state folder and home folders,
  the same `type`, `timeout` and `statusMessage`, and no other field. Only
  the path of the `python3` interpreter may differ. An entry edited in any
  way is no longer Safe YOLO's: doctor reports it and update refuses. Every other hook belongs to someone else. It is
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
the installed file, which deactivate, rollback and uninstall check against,
and as its rollback snapshot. Uninstall restores toward the file as first
found, keeping other owners' hooks. Those checks read the file
once at the start of the command. Nothing locks it, so a save by another
program while uninstall or rollback runs is overwritten.

Linux/Python 3.12+ is the proven platform. Codex, Claude Code, Cursor, and OpenCode V2 have
installation lifecycles. Native hook trust or restart remains harness-specific.
Local customizations are preserved. The custom distribution permission remains
in effect; publication is not a change to an OSI-approved license.
