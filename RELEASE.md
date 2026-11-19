# Safe YOLO 3.0.0-beta.12

One new restricted direct action: a recursive search of a whole storage root
is denied as `filesystem.broad_search`. Existing denials keep their
consequence IDs and are decided first.

One agent session that searches a whole root can read tens of GB in a minute
or two and stall the disk for every other session on the machine. Measured
examples: `grep -rl <text> ~/.local/state` (75 s),
`find / -path /proc -prune -o -type d -name rag -print` (118 s).

- Denied: `grep`, `egrep` or `fgrep` with a recursive option, or `rg`, at the
  head of a simple command (bare, or under `/bin`, `/usr/bin` or
  `/usr/local/bin`), when one of its own path words is a literal absolute,
  `~` or `$HOME` path that is exactly `/`, `/home`, `/Users`, the user home,
  `/tmp`, `/var`, `/var/tmp`, or under the home `.local`, `.local/state`,
  `.local/share`, `.cache` or a harness folder (`.codex`, `.claude`,
  `.cursor`, `.grok`, `.config/opencode`, `.gemini`, `.devin`).
- Denied: `find` over `/`, `/home`, `/Users` or the user home, unless it
  carries `-maxdepth` 3 or less, or its expression opens with `-prune`, alone
  or after one `-mindepth` of 3 or less, with no `-depth`.
- Denied: a native grep tool call, such as Claude Code's Grep, whose `path`
  is an absolute path that is exactly one of the roots above. The tool does
  no shell expansion, so `~/.cache` there is allowed.
- The denial names the root and the safer route: list the root with `ls`,
  then search the named subfolder.

Everything the command text does not settle is allowed. A named subfolder, a
relative path or no path, a variable other than `$HOME`, a substitution among
the words, `HOME` named anywhere else in the command, `POSIXLY_CORRECT`, an
option the tables do not list (including `--help`, `rg --files`,
`rg --max-depth` and `find -exec`), a tool at any other path, a search behind
`timeout`, `xargs`, `bash -c` or a script, and everything after a heredoc,
backtick or unclosed quote all run. The reader does not know the working
folder, so `cd ~ && rg foo` runs. A session store below a harness folder,
such as `~/.codex/sessions`, is a named subfolder and runs. Native file-name
tools such as Glob are not covered.

There is no waiver comment. The same search receives the same denial every
time. A search that must cover a whole root goes one subfolder at a time.

This is a narrow direct recognizer for resource backpressure, not shell
interpretation or containment.

Linux/Python 3.12+ is the proven platform. Codex, Claude Code, and Cursor have
installation lifecycles. Native hook trust or restart remains harness-specific.
Local customizations are preserved. The custom distribution permission remains
in effect; publication is not a change to an OSI-approved license.
