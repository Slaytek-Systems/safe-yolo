# Safe YOLO 3.0.0-beta.10

Ordinary ssh setup no longer needs a workaround, and more spellings of
already-restricted production, public-bind, and environment-dump commands are
recognized.

- Allowed: reading the ssh client `config`, `known_hosts`, `known_hosts.old`,
  and `*.pub` files directly in the home ssh directory with `cat`, `head`,
  `tail`, `grep`, `wc`, `diff`, `cmp`, `file`, `stat`, `ls`, or
  `ssh-keygen -l`, `-B`, or `-F`, and through structured read tools.
- Allowed: `ls` of the ssh directory itself, and
  `ssh-keyscan <host> >> <ssh dir>/known_hosts`.
- Allowed: `scp -i` and `sftp -i` with a key in the ssh directory, like
  `ssh -i`.
- Still denied: private keys and every other file in the ssh directory, any
  write other than the `ssh-keyscan` append (including to `config`,
  `known_hosts` with `>`, and `authorized_keys`), recursive reads and archives
  of the directory, and any command that chains, pipes, or substitutes another
  command.
- Denied as production mutation: `fly apps destroy` (also `app`, and `delete`,
  `remove`, `rm`), `fly destroy`, `fly machine destroy` (also `machines`, `m`,
  and `remove`, `rm`), `vercel remove`, `rm`, `rollback`, and `promote`, and
  `railway <group> delete` (also `remove`, `rm`) for service, volume,
  environment, bucket, functions, template, variable, and project, with the
  group aliases from `railway --help`. `flyctl` and `vc` are read as `fly` and
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
