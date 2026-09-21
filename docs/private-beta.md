# Private beta operations

Safe YOLO 3.0.0-beta.1 is a private, source-installed Codex beta. It is meant
for invited Slaytek team members, freelancers, and students who can report
their environment and installation result.

## What the installer changes

`python3 safe-yolo install`:

1. requires a clean Git checkout and records its exact commit;
2. installs a versioned immutable runtime under `~/.safe-yolo/releases/`;
3. preserves the previous Codex hooks document in a timestamped backup;
4. adds one pinned `PreToolUse` command to `~/.codex/hooks.json`;
5. validates the Codex configuration without rewriting it;
6. runs one ordinary-work allow canary and one force-push deny canary; and
7. records enough state to verify or reverse the activation.

It refuses to replace foreign `PreToolUse` or `PostToolUse` command lifecycles.
It also refuses to overwrite a hook document changed after installation.

## First install

The repository is private. An organization owner first grants the participant
read access. Each participant then authenticates GitHub on their own machine,
clones the repository, reviews the code, and follows the README quickstart.
Do not distribute a shared token, a copied maintainer checkout, or a zip with
credentials.

The participant returns these non-secret facts:

- operating system and Python version;
- installed Safe YOLO version and source commit;
- whether `python3 safe-yolo doctor` reports `healthy: true`; and
- whether the restarted Codex session shows the reviewed hook as trusted.

## Upgrade

Pull the reviewed release into a clean checkout and rerun the installer:

```bash
git pull --ff-only
python3 safe-yolo install
python3 safe-yolo doctor
```

The prior active hook becomes the rollback target. Existing immutable releases
remain available for diagnosis and recovery.

## Deactivate or roll back

```bash
python3 safe-yolo deactivate
```

Restart Codex afterward. Deactivation restores the exact previous hooks bytes
when a previous document existed. For a fresh installation it moves the
Safe-YOLO-created hooks document into the backup area instead of erasing it.

## Support boundary

The beta currently supports Codex on Linux. The policy kernel includes adapters
for other harnesses, but their installation journeys are not part of this beta.
macOS packaging, automated hook-trust proof, a signed binary/package, hosted
updates, commercial licensing, and a customer support agreement are deferred.

Safe YOLO is backpressure, not a sandbox. It blocks a small explicit set of
direct consequences. It does not make untrusted code safe, replace repository
permissions, secure credentials, or prove a deployment is ready.
