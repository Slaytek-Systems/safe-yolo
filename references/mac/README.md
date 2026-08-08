# Safe YOLO

Safe YOLO is a harness-independent policy engine for high-autonomy agent operation with deterministic barriers against irreversible, secret-bearing, and incongruent actions.

This directory is a **staged reference implementation**. It is not installed into `~/.safe-yolo` and is not wired into any live harness.

## Proven in this slice

- Machine-readable Green, Blue, Amber, Red, and Method-block decisions.
- Constitutional Red actions cannot be overridden by a capability.
- Safe feature pushes earn Blue only with matching branch/remote context and validation.
- Production deploys earn Blue only with complete, current release evidence.
- Capabilities are opaque, expiring, session-bound, action-bound, and constraint-bound.
- Exact UserPromptSubmit commands mint turn-scoped capabilities; the next prompt revokes them.
- Maintenance capabilities apply consistently to structured writes and shell destinations.
- Permanent deletion is Red; recoverable quarantine and restore work within an active workspace.
- Literal credential-free public reads are Green.
- Dynamic targets, redirects, authenticated reads, writes, local-file transmission, metadata access, and remote-script execution are separated by consequence.
- A thin Codex adapter translates tool payloads without redefining policy.

## Run the tests

```sh
python3 -m unittest discover -s tests -v
```

## Inspect a shell command

```sh
python3 -m engine.safe_yolo --command 'git push --force-with-lease origin feature/x'
```

## Evaluate a normalized request

```sh
printf '%s\n' '{"action":"deploy.production","release_evidence":{"valid":false}}' \
  | python3 -m engine.safe_yolo
```

## Dry-run the Codex adapter

```sh
printf '%s\n' '{"tool_name":"Bash","tool_input":{"command":"rm obsolete.txt"}}' \
  | python3 -m adapters.codex --explain
```

## Audit-only Codex hook

```sh
python3 -m adapters.codex \
  --audit-only \
  --audit-log ~/.safe-yolo/state/audit.jsonl
```

Audit-only mode never returns an allow/block hook response. It records only timestamp, session/turn identity, tool name, decision, policy ID, and reason. Raw commands and tool inputs are deliberately excluded. Engine or log failures fail open so observation cannot interrupt the existing guardian.

## Authorization commands

Only exact slash commands mint capabilities:

```text
/maintenance codex hooks rules tests
/maintenance-policy git.force_push filesystem.delete
/merge-pr owner/repo#412 --squash
/push-tag owner/repo v1.2.3
/deploy-production owner/repo production
```

Natural-language requests do not mint capabilities. Capability records are selected through the Codex session and turn identity; tokens are not returned to the agent.

## Architecture

```text
Harness event
    -> thin harness adapter
    -> normalized action or command inspection
    -> canonical policy engine
    -> allow | allow_report | require_capability | block_method | block_hard
```

The adapter is transport code. Policy belongs in `policy.json` and must pass the shared corpus in `tests/cases.jsonl`.

## Deliberately not live yet

The following work remains before installation:

- a release-evidence collector bound to repository, commit, target, contract version, and validation timestamps;
- a safe public fetch wrapper that validates redirect hops;
- project-local policy overlays and release contracts;
- live Codex hook registration and fresh-session smoke tests;
- Pi, Claude, and Grok adapters;
- migration and rotation of credentials currently stored in harness configuration.

The shell inspector is a deterministic guard layer, not a complete shell security sandbox. Unknown safety-sensitive syntax must continue to expand the shared adversarial corpus.
