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

- The Mac is a control terminal, not the durable development authority.
- `~/.safe-yolo/state`, `backups`, and `releases` are mode `0700`.
- Time Machine reports no configured destination.
- The visible APFS snapshots are OS-update snapshots, not user-data recovery evidence.
- No common alternate backup application or CLI was found in the bounded audit.

Result: the Mac may run Safe YOLO as a control terminal, but it must not remain the sole holder of completed development work. Safe feature branches must be published or transferred to devbox before a task is considered durable.

### devbox

Devbox is the primary development authority. The operator reports a weekly Proxmox backup to a dedicated 2 TB HDD. The precise Proxmox backup type, included guest/storage, retention, most recent successful run, and restore behaviour have not yet been independently verified.

Result: use Git and Safe YOLO checkpoints for recent logical recovery and the Proxmox backup for host disaster recovery. Certification requires one evidence read-back and one non-destructive restore drill; do not invent another snapshot layer before testing the existing one.
