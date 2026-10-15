# Safe YOLO 3.0.0-beta.9

More direct forms of already-restricted commands are now recognized, and two
production checks no longer deny read-only commands.

- Denied: `ssh` short-option clusters such as `-tp 2222`, `-tl admin`, or
  `-vp2222`. The value-taking letter now consumes its value, so the remote
  command or interactive session is checked as it is without the cluster.
- Denied: commands behind leading assignments, such as `FOO=1 rm -rf build`,
  `FOO=1 sudo ls`, or `KUBECONFIG=prod.yaml kubectl apply -f x.yaml`.
  `env FOO=1 <command>` is unchanged.
- Denied as file deletion: `shred` in any form and `truncate` at any size,
  outside scratch paths. Option values such as `-s 0` or `-r ref` are not read
  as targets, so `truncate -s 0 /tmp/build.log` stays allowed.
- Denied as production mutation: `railway redeploy`, `restart`, `down`,
  `delete` (and its `rm` and `remove` aliases), `railway deployment up` or
  `redeploy`, `railway service redeploy` or `restart`, `flyctl` as `fly`, and `vc` as `vercel`.
- Denied: `kubectl` mutations after `-v`, `--v`, `--vmodule`, or `--as-uid`
  with a spaced value, such as `kubectl -v 6 apply -f x.yaml`.
- Denied: `sed -i.bak`, `-Ei`, `-ie`, `--in-place`, `--in-place=.bak`, and
  abbreviations such as `--in-pl=.bak` on Safe YOLO enforcement files.
- Allowed: `railway logs --service deploy`, `railway run npm run deploy`, and
  the local `railway dev up`. Railway commands are read at the command
  position only.
- Allowed: `kubectl --dry-run=client` and `--dry-run=server`. Bare
  `--dry-run`, `--dry-run=none`, and a dry run that may be another option's
  value stay denied.

Linux/Python 3.12+ is the proven platform. Codex, Claude Code, and Cursor have
installation lifecycles. Native hook trust or restart remains harness-specific.
Local customizations are preserved. The custom distribution permission remains
in effect; publication is not a change to an OSI-approved license.
