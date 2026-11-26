# Safe YOLO (unreleased): the hook command no longer changes on update

Updating Safe YOLO no longer switches the guard off in Codex. Until now each
update rewrote the hook command, because it named the release folder and its
manifest digest. Codex runs a hook only while its command matches the hash
the user trusted in `/hooks`, so after every update Codex silently skipped the
hook until it was trusted again. One devbox ran unguarded for six days.

- Every harness now runs one stable command:
  `<python3> ~/.safe-yolo/hooks/<harness>.py --harness <harness> --entry
  <entry> --safe-yolo-home ~/.safe-yolo`. It names no release and no digest.
- The launcher is a copy of the active release's bootstrap. It reads the
  harness's install receipt for the release and digest, verifies the release,
  and runs it. A missing, inactive or unreadable receipt, or a release that
  is unreadable or fails verification, fails closed. Antigravity still gets a
  JSON deny with exit 0. A missing launcher exits 2 from the interpreter, as a
  missing pinned bootstrap did, which Antigravity ignores.
- An update verifies the new release, runs the allow and deny canaries
  against it directly, switches the receipt and launcher, then runs the
  canaries again through the unchanged command. If any step fails, it undoes
  each write that completed, newest first, and names any file it could not
  restore. Rollback works the same way, and checks the saved hook answers
  before it publishes it.
- Deactivate returns the harness file to its state from before Safe YOLO was
  first installed, as uninstall does, so no hook is left reading an inactive
  receipt.
- Codex, Claude Code, Cursor and Antigravity hook files stay byte for byte the
  same across updates. The OpenCode plugin stays the same unless a release
  changes its template. Running sessions pick up the new release on their next
  tool call, with no restart.
- Doctor checks the stable command, that each launcher matches its active
  release's bootstrap, and that the receipt's release verifies. It runs its
  canaries only through a launcher that matches.

Migration. The first update from 3.0.0-beta.17 or earlier recognises the old
release-pinned command and replaces it with the stable one. That one rewrite
changes the command, so Codex needs its hook trusted in `/hooks` once more.
Later updates do not change it. Codex needs trust again only if the Python
path in the command changes, for example after a Python upgrade.

Limits. The stable command still embeds the interpreter path
(`sys.executable` at install). Safe YOLO does not write Codex's trust record.
The receipt and launcher are ordinary files in the user's home, as the release
folder and the hooks file were before. Safe YOLO's integrity checks detect
corruption and drift, not a same-user process that rewrites them on purpose.
