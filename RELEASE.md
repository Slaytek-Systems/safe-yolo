# Safe YOLO 3.0.0-beta.10

Ordinary ssh setup no longer needs a workaround, and more spellings of
already-restricted production, public-bind, and environment-dump commands are
recognized.

- Allowed: a single command of one of these exact shapes on the home ssh
  directory's public files, `config`, `known_hosts`, `known_hosts.old`, and
  `*.pub`, each named literally:
  - `cat`, `head -n N`, `tail -n N`, `wc`, `grep PATTERN`, `diff`, `cmp`,
    `stat`, `file`, or `ls` with only that command's listed display options;
  - `ls` of the directory itself (names only; `-R` is denied);
  - `ssh-keygen -l`, `-B`, or `-F <host>` with `-f <public file>` and `-E`;
  - `ssh-keyscan [options] <hosts> >> <ssh dir>/known_hosts`, with that
    append as the only redirection into the directory;
  - a structured read tool on one public file.
- A matching shape exempts only those literal public-file words, plus the one
  `ssh-keyscan` append. Every redirection is still checked as in beta.9, and a
  word containing `<` or `>` is never accepted as an option value.
- Allowed: `scp -i` and `sftp -i` with a key in the ssh directory, like
  `ssh -i`. Only that option's separate value word is exempt, and only when it
  is a literal path (no glob, redirection, or substitution) placed before any
  redirection in the command and outside every `private_paths` customization.
  `ssh -i` with a key under `private_paths` is now denied too.
- Still denied, for the direct forms the hook recognizes: private keys and
  every other non-public file in the ssh directory; globs, `..`, option values,
  long options, and redirections that name the directory in a reader; every
  write except the one `ssh-keyscan` append; a public name whose symlink
  resolves to a protected or non-public target, or a regular file with more
  than one link; any public file under a `private_paths` customization; and any
  command that chains, pipes, or substitutes another command. A public name
  that links to another public file, such as `alias.pub` to `config`, reads
  like that file.
- Residual: the hook checks names and links, not content. A public name made
  outside the hook that holds private key content, such as a copy or a
  hardlink whose other name was removed, reads as public. Creating one through
  the hook is a denied write into the directory. Forms that beta.9 already
  missed stay missed: a path attached to a redirection
  (`cat <key>>/tmp/x`), a glob in a directory component, and an attached short
  option value (`ssh-keyscan -f<key>`).
- Denied as production mutation: `fly apps destroy` (also `app`, and `delete`,
  `remove`, `rm`), `fly destroy`, `fly machine destroy` (also `machines`, `m`,
  and `remove`, `rm`), `vercel remove`, `rm`, `rollback`, and `promote`, and
  `railway <group> delete` (also `remove`, `rm`) for service, volume,
  environment, bucket, functions, template, variable, and project, with the
  group aliases from `railway --help`, also when group options such as
  `--project <id>` come before the verb. `flyctl` and `vc` are read as `fly` and
  `vercel`. `vercel rollback status` and `vercel promote status` stay allowed.
- Denied as public exposure: `gunicorn -b` or `--bind`, `rails s -b` or
  `--binding`, `jupyter --ip`, and `php -S` with `0.0.0.0`, `::`, or `[::]`,
  with or without a port. Loopback addresses stay allowed.
- Denied as an environment dump: bare `export`, `export -p`, `declare -x`,
  `declare -p`, `typeset -x`, bare `set`, and `env` with abbreviated long
  options such as `env --un FOO`. Assignments, `set -e`, `set -- a b`, and
  `env -i PATH=/usr/bin make` stay allowed.

Linux/Python 3.12+ is the proven platform. Codex, Claude Code, and Cursor have
installation lifecycles. Native hook trust or restart remains harness-specific.
Local customizations are preserved. The custom distribution permission remains
in effect; publication is not a change to an OSI-approved license.
