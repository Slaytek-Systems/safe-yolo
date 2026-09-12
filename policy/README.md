# Canonical policy

`policy.json` is the portable policy source. Host adapters resolve its symbolic protected paths (`${SAFE_YOLO_HOME}`, `${CODEX_HOME}`) and may add host facts, but cannot weaken action classifications.

## Release rule

`deploy.production` is intentionally Amber by default. It becomes Blue only through `external_release_contract`; an exact human-text capability is not a substitute. The future contract verifier must bind external CI/provider evidence to the exact repository, commit/artifact, target environment/service, expiry, and rollback proof.

Raw deployment, destructive migration, and arbitrary shell-composed release paths are not contract-qualified operations when they are visible to the direct-command evaluator. Repository code is intentionally executable and can hide nested effects, so provider authorization and recovery—not this classifier—must remain the real release and destruction boundary.

## SSH rule

SSH uses the shared `engine/ssh_command.py` parser across legacy and deny-only adapters. Explicit no-session transport and visible ordinary remote commands are allowed. Interactive shells, subsystems, opaque `-F` configuration, and restricted commands embedded in remote, proxy, local, or `RemoteCommand` options are denied. A host-contract maintenance command loses its exception when command-line routing, identity, port, user, jump, proxy, or configuration overrides can redirect it.
