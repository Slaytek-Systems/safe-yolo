# Historical host references

These are source-only preservation snapshots used to reconcile the initial portable Safe YOLO release.

They intentionally exclude runtime state, audit logs, credentials, Codex session databases, caches, backups, package installations, and active configuration files that may contain secrets.

- `mac/` — complete source-only copy of the existing Mac Safe YOLO package as of this bootstrap.
- `devbox/` — recorded authoritative devbox policy/hook baseline and integrity manifest. The active devbox installation remains untouched and is the immediate operational rollback reference.

Nothing under `references/` is an installable release.
