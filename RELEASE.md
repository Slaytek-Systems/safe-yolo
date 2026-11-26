# Safe YOLO (unreleased): doctor says when Codex is skipping the guard

Codex runs a hook only if the approval saved in its `config.toml` matches the
hook. Every Safe YOLO install or update changes the hook, so Codex silently
skipped the guard until someone approved it again in `/hooks`. One machine ran
unguarded for six days this way.

- `safe-yolo doctor` now reads that approval. When it is missing or stale,
  doctor exits 1 and says "Codex will skip Safe YOLO until you approve it in
  /hooks", with the reason.
- `install` and `update` for Codex end by telling you to approve the hook in
  `/hooks` now. When the approval already matches, they say only "Restart
  Codex."
- Safe YOLO only reads Codex's approval. It never writes it.

# Safe YOLO 3.0.0-beta.17

A blocked command is now blocked however it is chained. Until now Safe YOLO
judged only the first command of a line, so `cd repo && git push --force
origin main` or `git status && rm -rf build` passed while the same command
alone was denied. That held on every harness since the 3.0 engine.

- Each command joined by `&&`, `||`, `;`, `|`, `&`, a newline or
  parentheses gets the answer it would get alone. `if`/`then`/`do` and
  similar opening words are skipped, so `for f in a b; do rm "$f"; done` is
  read as `rm`.
- A `cd` in the chain moves where later paths resolve, so `cd /tmp/x && rm
  -rf build` is judged as a delete inside `/tmp`. A `cd` inside `( … )`
  ends with the subshell.
- Quoted text, comments and heredoc bodies are data: a commit message or a
  `# note` that mentions `rm -rf` or `git push --force` is not a command.
  Redirects such as `2>&1` and `&>` are not separators. A `$( )`, `<( )` or
  `>( )` substitution is a word of the command around it.
- Commands sent over `ssh` use the same reading, so a newline now separates
  remote commands too.

Cost: an agent that chains a delete or a force push after other work is now
denied, exactly as if it had run that command alone.

Limits. Wrappers, scripts, `bash -c` and `python -c` strings, variables,
the inside of `$( )` substitutions and command output used as commands are
still not read, as the architecture
contract says.
