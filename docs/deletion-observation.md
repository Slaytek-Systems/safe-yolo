# Local deletion observations

Safe YOLO can record deletion candidates after computing the existing allow or
deny decision. Observations never grant permission, weaken a denial, trigger
cleanup, or feed a model into enforcement. The configured policy still has its
existing scratch-root exceptions; logging an allowed scratch deletion does not
change that policy.

All seven v3 adapters use the same observer after their native normalization.
The installed bootstrap forwards `--state-dir`, enabling observations under
`STATE_DIR/observations/deletions.sqlite3`. Direct adapter invocations and Python
callers enable it only when an observation directory is supplied. Older adapters
and uninstalled source changes do not observe live traffic.

## Read the report

```bash
python3 safe-yolo observations
python3 safe-yolo observations --state-dir /path/to/state
python3 safe-yolo --home /path/to/safe-yolo observations
```

The command returns grouped JSON and opens SQLite read-only. An absent database
returns an empty report without creating directories. An unsafe, corrupt, or
unreadable database returns a fixed `observation unavailable` error and exit 2.
There is no purge, retry-permission, learned-rule, or deletion command.

Each group contains its harness, sanitized command shape, parsing coverage,
recognition flag, allow/deny outcome, policy ID, version, source fingerprint,
policy-context fingerprint, first/last timestamps, attempt count, distinct
known-session count, distinct known-workspace count, and attempt counts with
missing session or working-directory identity. Grouping
keeps different policy contexts and source revisions separate. Attempts count
intercepted tool invocations, not deleted targets or successfully executed work.

`rm -rf private-name` and `rm -fr another-name` both become
`rm -f -r <relative>`. Targets become fixed categories such as `<absolute>`,
`<relative>`, `<home>`, `<glob>`, and `<dynamic>`. Arbitrary flags and their values
are never copied into shapes. Commands, arguments, paths, environment values,
file contents, and native payloads are not stored.

Session and effective working-directory identities are HMAC fingerprints using
a random key private to this database. The policy-context fingerprint covers
the kernel's configured enforcement, credential, and scratch roots. The source
fingerprint covers the version and shipped Python engine/adapter files. These
fingerprints support local grouping, not cross-database identity or authenticity.
The key lives in the same private database; access to that database can enable
guessing low-entropy identities. No session ID is invented when one is absent.
Antigravity's current normalization supplies no session identity, so those
observations report missing sessions.

## Coverage and limits

`recognized=1` means the existing kernel returned `filesystem.delete` or
`git.delete_ref`. It does not mean every lexical candidate was recognized.
`coverage=complete` means the observer could describe a supported direct tool
shape; `partial` covers compounds, dynamic commands, `find`, `xargs`, or a
recognized action with incomplete shape support. `unparsed` records a lexical
candidate whose shell quoting could not be parsed. An allowed event may therefore
be an existing scratch exception or only a lexical candidate. None proves an
execution or a classifier defect.

Observation covers direct `rm`, `rmdir`, `unlink`, `shred`, `truncate`, structured
file deletion, patch deletion headers, recognizable compound candidates,
`find`/`xargs` candidates, Git clean candidates, and recognized Git ref deletion.
It deliberately does not inspect interpreter programs, scripts, file contents,
unknown semantic tools, or nested effects. Quoted command data may be ambiguous,
and lexical candidates can be false positives. Native hooks can also be skipped,
untrusted, or unsupported by a tool path. The report is incomplete operational
evidence, not a tamper-proof ledger, a deletion guarantee, or permission authority.

The observation directory is created with mode 0700 and database with mode 0600.
Existing insecure directories/files, static symlinks at any path component,
hard-linked database files, and unsafe SQLite journal/sidecar paths are refused.
These checks prevent ordinary mistakes; same-user path races and intentional
tampering remain outside this backpressure boundary.

SQLite's lock wait is 50 milliseconds. Storage holds at most 10,000 events and
16 MiB of database pages; temporary rollback-journal storage can add up to another
database's size. Storage I/O itself is not bounded by that lock timeout. At
capacity, nothing is purged: a new event fails, the hook emits the fixed diagnostic
`Safe YOLO observation unavailable`, and its exact enforcement response remains
unchanged. Contention, corruption, schema mismatch, permissions, and other logger
failures have the same enforcement behavior. Failed writes are missing from the
report; no durable dropped-event counter or complete-coverage claim is provided.

Installed runtime activation remains a separate operator action. Native Codex
trust is tied to the exact hook-definition hash and must be reviewed after a pin
change; a release/wiring doctor or a directly invoked adapter alone cannot prove
native hook execution.
