# Asset-boundary recovery

Safe YOLO protects valuable assets at the boundary that owns them. It does not try to prove the internal behaviour of every development command.

| Asset | Prevention boundary | Recovery proof required |
| --- | --- | --- |
| Repository files | Structured checkpoints, Git workspace checkpoint, normal source control | Checkpoint materialization and clean restore drill |
| Ignored and non-Git local files | Host backup system | Configured destination plus a completed restorable backup |
| Git remote history | No-force policy plus provider branch protection | Provider-side rules read-back |
| Credentials and agent control plane | Protected paths, private state, least-privilege credential availability | Permission and effective-enforcement doctor |
| Development services and durable local data | Service-specific snapshots/backups | Named restore drill without disturbing active development |
| Production services and customer data | Project release contract, provider permissions, provider backup/PITR | Project-specific external evidence; never inferred from local tests |

## Current evidence — 2026-08-10

### macOS

- `~/.safe-yolo/state`, `backups`, and `releases` are mode `0700`.
- Time Machine reports no configured destination.
- The visible APFS snapshots are OS-update snapshots, not user-data recovery evidence.
- No common alternate backup application or CLI was found in the bounded audit.

Result: repository recovery is testable, but ignored and non-Git development data are not yet covered by proven host recovery. This is a certification gap, not a reason to obstruct ordinary repository commands.

### devbox

The current macOS-to-devbox remote contract exposes only exact Safe YOLO source status, fast-forward update, and release update commands. Host filesystem, backup, and restore evidence has not been collected. Do not infer devbox recovery from Git or from the existence of a home server.

Result: decision needed on the devbox snapshot/backup authority before adding a narrow read-only doctor contract.
