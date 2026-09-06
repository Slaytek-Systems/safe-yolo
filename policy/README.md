# Canonical policy

`policy.json` is the portable policy source. Host adapters resolve its symbolic protected paths (`${SAFE_YOLO_HOME}`, `${CODEX_HOME}`) and may add host facts, but cannot weaken action classifications.

## SSH transport

SSH is a transport. The local classifier inspects the local command string, not a remote login session.

- Options, destination aliases, and a remote command included in the local invocation are visible.
- When a remote command is present, it is classified with the same direct-consequence rules as a local command. Paths in that string are resolved against the local working directory and local protected roots, not the remote filesystem.
- `ssh destination` with no remote command starts an interactive remote shell. The local hook can allow that launch. It does not inspect commands typed after login. A local allow is not remote enforcement.
- `ssh -i <key-path>` and `-o IdentityFile=` use a private key for authentication. That is not reading or exposing the key. Dumping or copying private keys remains denied.

`scp` and `rsync` remain `remote.execute` in the v1 command inspector. The 3.0 kernel does not treat those executables as a distinct consequence.

## Release rule

`deploy.production` is intentionally Amber by default. It becomes Blue only through `external_release_contract`; an exact human-text capability is not a substitute. The future contract verifier must bind external CI/provider evidence to the exact repository, commit/artifact, target environment/service, expiry, and rollback proof.

Raw deployment, destructive migration, and arbitrary shell-composed release paths are not contract-qualified operations when they are visible to the direct-command evaluator. Repository code is intentionally executable and can hide nested effects, so provider authorization and recovery—not this classifier—must remain the real release and destruction boundary.
