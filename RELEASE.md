# Safe YOLO 3.0.0-beta.16

One Antigravity install now covers every place Antigravity runs on the
machine. The policy is the one in beta.12.

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
