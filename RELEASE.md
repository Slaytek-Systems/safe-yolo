# Safe YOLO 3.0.0-beta.16

One Antigravity install now covers every place Antigravity runs on the
machine. The policy is the one in beta.12 with two additions for the T3 Code
profile folder, listed below.

T3 Code runs Antigravity from a profile folder of its own, under
`~/.t3/userdata/providers/antigravity/`, with its own `config/hooks.json`.
Until now Safe YOLO managed one Antigravity hooks file, so either the terminal
`agy` or Antigravity in T3 Code was left on whatever was there before.

- `safe-yolo install --harness antigravity` installs `~/.gemini` as the
  `antigravity` harness and, when T3 Code has one Antigravity profile, that
  profile as the new `antigravity-t3` harness. Plain `safe-yolo install`
  detects both.
- Each has its own receipt. `doctor`, `update`, `rollback` and `uninstall`
  act on both. Old hand-made wiring in either file is taken over as in
  beta.15.
- `--config-home` still selects one folder and installs only the harness
  named.
- Policy: `~/.t3/userdata/providers/antigravity` and each profile folder
  directly inside it are now whole-folder search roots like `~/.gemini`; a
  search of a subfolder of a profile is still allowed. Every Antigravity hook protects the `config`
  folder and token files of each T3 Code profile, so the terminal `agy`
  cannot edit the T3 Code hooks file.
- One hooks file belongs to one harness id. If beta.15 was installed with
  `--config-home <T3 profile>`, run `safe-yolo uninstall --harness
  antigravity` first; install says so.
- When one of the two folders refuses, install still tries the other and the
  error names what was installed and what was not. Plain `safe-yolo rollback`
  skips a harness that has no previous install.
- The suggested after-install check now uses a new empty folder after
  `git init`, so nothing is pushed if the hook did not load.

Limits.

- When T3 Code has made no Antigravity profile yet, only `~/.gemini` is
  covered. Run the install again after the first Antigravity thread in T3
  Code.
- With more than one T3 Code profile, install names them and asks for
  `--harness antigravity-t3 --config-home <profile>`; one receipt covers one
  profile.
- If T3 Code moves to a new profile folder, the new folder has no hook until
  install runs again. Doctor still checks the old folder and does not notice.
- Doctor cannot prove Antigravity loaded the hook, in the terminal or in T3
  Code. Antigravity ignores a hook that crashes, times out or prints
  something that is not a decision.
- The beta.15 limits are unchanged: a top-level entry Antigravity cannot
  parse makes it drop every hook while doctor reports healthy; an edit to
  another group after install makes doctor report the file changed and makes
  uninstall refuse until the next update; a moved Python stops the launcher
  and makes reinstall refuse.
- If the T3 Code provider folder exists but cannot be listed, for example
  after a restore that left its permissions wrong, install covers only
  `~/.gemini` without saying it skipped T3 Code, and the terminal hook does
  not protect the T3 Code hooks file. Fix the folder's permissions and run
  the install again.
