# Safe YOLO 3.0.0-beta.11

Six direct command spellings now receive the same denials as their spaced or
literal equivalents. Existing denials keep their consequence IDs.

- Credential paths before an attached redirection are checked, as in
  `cat <key>>/tmp/x` or `cat <key></dev/null`.
- Globs in directory components are matched against the protected paths
  Safe YOLO already knows, never against the filesystem. A pattern that names
  a credential root or a path inside one is denied, as in
  `cat /home/*/<ssh dir>/id_rsa` or `cat ~/.s*/id_rsa`. A write target such
  as `touch <codex home>/c*.toml` that names an enforcement file is denied as
  `enforcement.modify`. As in bash, a component that does not start with a dot
  never matches a dot-named one, and `**` matches like `*` because globstar is
  off by default. A parent listing
  such as `ls ~/*` or `du -sh /*/*` names no protected path and stays allowed.
  Cost depends on the pattern and the protected path list, not on the size of
  the filesystem.
- Attached single-dash option values are checked as paths, as in
  `ssh-keyscan -f<key>` or `grep -f<key> file`. An attached ssh, scp or sftp
  identity such as `ssh -i<key> host` is key use, like the spaced `-i <key>`,
  unless the key is inside a user private path.
- A leading `$HOME` or `${HOME}` reads as the user home, as in
  `cat $HOME/<ssh dir>/id_rsa`.
- Spaced clobber redirections now identify their enforcement target, as in
  `echo x >| <codex home>/config.toml`, including file-descriptor prefixes.
- Fly and Vercel destroy verbs are recognized after global options such as
  `fly --access-token value apps destroy app`, `fly -a app apps destroy` or
  `vercel --token value remove project`. The `flyctl` and `vc` aliases share
  these checks. Read forms such as `vercel --token value rollback status`
  stay allowed.

The operational handoff now records the observed Claude Code hook pin on
devbox alongside its Codex pin. Both remain pending Matt's upgrade.

These are additive direct recognizers, not shell interpretation or containment.
After shell tokenization, quoted redirection and glob characters are ambiguous,
so both literal and operator or pattern readings are checked. A glob is
matched by name only. It does not follow symlinks such as `/proc/*/root`. A
pattern long enough to reach inside a protected path that is not under a dot
directory is denied even when nothing matches on disk. POSIX character
classes such as `[[:lower:]]` and brace expansion are not read as patterns,
and an attached option value is checked from its first `/` or `~`, so
`grep -f$HOME/...` is not expanded. Scripts, wrappers,
substitutions, and other command compositions can still route around direct
recognition.
Public ssh file checks still inspect names and links, not content. A public
filename that already contains private material can still read as public.

Linux/Python 3.12+ is the proven platform. Codex, Claude Code, and Cursor have
installation lifecycles. Native hook trust or restart remains harness-specific.
Local customizations are preserved. The custom distribution permission remains
in effect; publication is not a change to an OSI-approved license.
