# Safe YOLO 3.0.0-beta.15

Antigravity (the `agy` CLI) is now a beta lifecycle harness. `install`,
`doctor`, `update`, `rollback`, `uninstall` and `deactivate` cover it, as they
cover Codex, Claude Code, Cursor and OpenCode. The policy is the one in
beta.12.

- `safe-yolo install --harness antigravity` writes one named group,
  `safe-yolo`, into `config/hooks.json` under the Gemini root: the
  `--config-home` folder if given, otherwise `~/.gemini`. Install ignores
  `GEMINI_HOME`, which `agy` 1.5.12 does not read. The group is enabled and
  holds one `PreToolUse` entry with matcher `*` and one command hook, timeout
  10 seconds, that runs the pinned bootstrap with `--entry antigravity_v3`.
  Every other named group in the file is kept as it was and is not judged.
  Install, update, uninstall and deactivate refuse, and leave the hooks file
  unchanged, when it holds a duplicate key anywhere or a number that Safe YOLO
  would not write back character for character, such as `1e400`, `1e-400`,
  `0.1234567890123456789`, `1.50` or `-0`; doctor reports it.
- `<root>/config` must not be a symlink, and `hooks.json`, when it exists,
  must be a regular file inside the chosen root. Install, doctor, update,
  rollback, uninstall and deactivate all refuse otherwise.
- Safe YOLO's group is the `safe-yolo` group that is, field for field, what
  the installer writes for the pin the receipt records. Only the `python3`
  interpreter path may differ. The command must keep the installer's spelling
  and flag order, and `timeout` must be an integer.
- First install refuses, and leaves the hooks file unchanged, when a
  `safe-yolo` group already exists. It may already have created the launcher
  and the release under the Safe YOLO home. One exception: a group of the
  installer's shape whose command runs a release under this Safe YOLO home's
  `releases/` folder that verifies against the command's non-empty manifest
  pin and lists the `antigravity_v3` entrypoint, through a bootstrap that
  exists, with entry `antigravity_v3`. That is how Antigravity was wired by
  hand before. Install backs the file up, then replaces only that group.
- The Antigravity adapter now replies `{"decision":"allow"}` on allow, as
  Antigravity's hook contract requires. Deny is unchanged.
- For the `antigravity_v3` entry only, read from the value of `--entry`, the
  bootstrap turns every failure it can catch into a deny reply with exit 0
  that names the failure, and stdout holds that one reply. Usage and help go
  to stderr. Failures covered: invalid arguments, a release that fails verification, is missing or has a malformed
  manifest, or an adapter that exits non-zero or prints no decision.
  Antigravity ignores a hook that exits non-zero, so the exit code alone would
  let the call run. Other entries keep their exit codes.
- Uninstall removes only the `safe-yolo` group. When install created the file
  and nothing else was added, the file is moved to `~/.safe-yolo/backups/`. Deactivate
  restores the exact previous file, including a hand-wired group it replaced.
- `scripts/publish.py --check` now exercises five harnesses. It removes
  `GEMINI_HOME`, uses a temporary `HOME`, and never runs or touches the host's
  `agy`.

Limits.

- Antigravity fails open. A hook that crashes before replying, runs past its
  timeout or prints something that is not a decision is ignored and the tool
  call runs. Antigravity has no fail-closed setting, and Safe YOLO cannot
  change that. The bootstrap's deny reply covers only the failures it can
  catch while it is running.
- Doctor checks the hooks file, the release and allow and deny canaries. The
  canaries run the exact command in the hooks file the way Antigravity does:
  split into words, no shell, the hook's timeout. A command that cannot start
  makes doctor unhealthy and is named. Doctor cannot prove Antigravity loaded
  the hook.
  After install, start a new Antigravity session and confirm the `safe-yolo`
  `PreToolUse` hook in `/hooks`.
- The path checks run before the write, so a link swapped into the path
  between the check and the write is not caught.
- One Safe YOLO home holds one Antigravity receipt, so it covers one Gemini
  root. A T3 Code profile root is covered only when you choose it with
  `--config-home <profile>`, and then `~/.gemini` is not covered. See the
  support matrix.
- Like Claude Code, doctor, uninstall and deactivate compare the whole hooks
  file with what install wrote. An edit to another named group after install
  makes doctor report the file changed and makes uninstall refuse, until an
  update to a newer release records the new file.
- Rollback runs the previous hook command's allow and deny check before it
  replaces the working hook, and refuses when that command cannot start or
  gives the wrong reply.
- Safe YOLO guards against honest mistakes, not a user working against it.
  Three cases an independent review raised are left as they are for that
  reason: doctor reads the hooks file once to check it and again to run it, so
  a file swapped between the two reads is run unchecked; taking over
  hand-made wiring accepts a release that lists the Antigravity adapter
  without a checksum for it; and a hook command edited to repeat `--entry`
  can get the wrong failure reply. No command Safe YOLO installs repeats
  `--entry`.
