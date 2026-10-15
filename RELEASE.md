# Safe YOLO 3.0.0-beta.11

Five direct command spellings now receive the same denials as their spaced or
literal equivalents. Existing denials keep their consequence IDs.

- Credential paths before an attached redirection are checked, as in
  `cat <key>>/tmp/x` or `cat <key></dev/null`.
- Globs in directory components are expanded against the local filesystem.
  A pattern that reaches a credential root is denied. Expansion stops after
  256 matches. On overflow, the literal directory prefix determines which
  credential roots the pattern could reach.
- Attached single-dash option values are checked as paths, as in
  `ssh-keyscan -f<key>` or `grep -f<key> file`.
- Spaced clobber redirections now identify their enforcement target, as in
  `echo x >| <codex home>/config.toml`, including file-descriptor prefixes.
- Fly and Vercel destroy verbs are recognized after global options such as
  `fly --access-token value apps destroy app` or
  `vercel --token value remove project`. The `flyctl` and `vc` aliases share
  these checks. Read forms such as `vercel --token value rollback status`
  stay allowed.

The operational handoff now records the observed Claude Code hook pin on
devbox alongside its Codex pin. Both remain pending Matt's upgrade.

These are additive direct recognizers, not shell interpretation or containment.
After shell tokenization, quoted redirection and glob characters are ambiguous,
so both literal and operator or pattern readings are checked. Glob checks
depend on the local filesystem at decision time. Scripts, wrappers, substitutions,
and other command compositions can still route around direct recognition.
Public ssh file checks still inspect names and links, not content. A public
filename that already contains private material can still read as public.

Linux/Python 3.12+ is the proven platform. Codex, Claude Code, and Cursor have
installation lifecycles. Native hook trust or restart remains harness-specific.
Local customizations are preserved. The custom distribution permission remains
in effect; publication is not a change to an OSI-approved license.
