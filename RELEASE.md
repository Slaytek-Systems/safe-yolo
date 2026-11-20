# Safe YOLO 3.0.0-beta.15

Antigravity (the `agy` CLI) is now a beta lifecycle harness. `install`,
`doctor`, `update`, `rollback`, `uninstall` and `deactivate` cover it, as they
cover Codex, Claude Code, Cursor and OpenCode. The policy is the one in
beta.12.

- `safe-yolo install --harness antigravity` writes one named group,
  `safe-yolo`, into `config/hooks.json` under the Gemini root: the
  `--config-home` folder if given, otherwise a non-empty `GEMINI_HOME`,
  otherwise `~/.gemini`. The group is enabled and holds one `PreToolUse`
  entry with matcher `*` and one command hook, timeout 10 seconds, that runs
  the pinned bootstrap with `--entry antigravity_v3`. Every other named group
  in the file is kept as it was and is never read or judged.
- Safe YOLO's group is the `safe-yolo` group that is, field for field, what
  the installer writes for the pin the receipt records. Only the `python3`
  interpreter path may differ. The command must keep the installer's spelling
  and flag order, and `timeout` must be an integer.
- First install refuses, and changes nothing, when a `safe-yolo` group already
  exists, with one exception: a group of the installer's shape whose command
  runs a release that already exists under this Safe YOLO home's `releases/`
  folder, with entry `antigravity_v3`. That is how Antigravity was wired by
  hand before. Install backs the file up, then replaces only that group.
- The Antigravity adapter now replies `{"decision":"allow"}` on allow, as
  Antigravity's hook contract requires. Deny is unchanged.
- For the `antigravity_v3` entry only, the bootstrap turns its own failures
  into a deny reply with exit 0 that names the failure: a release that fails
  verification or is missing, or an adapter that exits non-zero or prints no
  decision. Antigravity ignores a hook that exits non-zero, so the exit code
  alone would let the call run. Other entries still exit 2.
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
- Doctor checks the hooks file, the release and allow and deny canaries
  through the pinned command. It cannot prove Antigravity loaded the hook.
  After install, start a new Antigravity session and confirm the `safe-yolo`
  `PreToolUse` hook in `/hooks`.
- One Safe YOLO home holds one Antigravity receipt, so it wires one Gemini
  root. T3 Code runs Antigravity with `GEMINI_HOME` set to a per-profile root;
  that root's `config/hooks.json` is not covered unless it is the one root this
  home installed to. See the support matrix.
- Like Claude Code, doctor, uninstall and deactivate compare the whole hooks
  file with what install wrote. An edit to another named group after install
  makes doctor report the file changed and makes uninstall refuse, until an
  update to a newer release records the new file.
