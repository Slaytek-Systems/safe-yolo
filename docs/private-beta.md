# Private beta operations

Safe YOLO 3.0.0-beta.2 is a private, source-installed, harness-agnostic beta.
The distribution contains one immutable policy kernel and multiple native
adapters. Lifecycle support is promoted per harness according to the
[support matrix](harness-support.md).

## What the installer changes

`python3 safe-yolo install --harness <id>`:

1. requires a clean Git checkout and records its exact commit;
2. installs or reuses a versioned immutable runtime under
   `~/.safe-yolo/releases/`;
3. preserves the selected harness's previous configuration in a timestamped
   backup;
4. adds one native enforcement hook pinned to the release's manifest-covered
   bootstrap and records the selected user and harness configuration roots;
5. validates the native configuration without rewriting unrelated settings;
6. runs an ordinary-work allow canary and a force-push deny canary through that
   harness adapter; and
7. records an independent receipt under
   `~/.safe-yolo/state/installations/<harness>.json`.

It refuses to replace a foreign enforcement hook. Deactivation refuses to
overwrite configuration changed after installation.

## First install

```bash
git clone https://github.com/Slaytek-Systems/safe-yolo.git
cd safe-yolo
python3 safe-yolo harnesses
python3 safe-yolo install --harness <supported-id>
python3 safe-yolo doctor --harness <supported-id>
```

The installer prints the selected harness's native activation or verification
step. Repository access must use each participant's own GitHub identity; never
distribute a shared token or copied authenticated checkout.

## Upgrade

Pull the reviewed release into a clean checkout and rerun installation for each
active harness:

```bash
git pull --ff-only
python3 safe-yolo install --harness codex
python3 safe-yolo install --harness claude-code
python3 safe-yolo doctor --all
```

Each previous active configuration becomes that harness's rollback target.
Existing immutable releases remain available for diagnosis and recovery.
The beta.2 CLI also recognizes the beta.1 Codex receipt, so its doctor and
deactivation path remain usable. The explicit `--harness` argument is required
for new installs and upgrades.

## Deactivate

```bash
python3 safe-yolo deactivate --harness cursor
```

Deactivation restores the exact previous configuration bytes. For a fresh
configuration, it moves the Safe-YOLO-created file into the backup area rather
than erasing it.

## Support boundary

The proven platform is Linux with Python 3.12+. macOS and Windows lifecycle
acceptance remain unproven. Adapter-only harnesses are included for policy and
transport development but cannot be installed by the distribution CLI yet.

Safe YOLO is backpressure, not a sandbox. It blocks a small explicit set of
direct consequences. It does not make untrusted code safe, replace repository
permissions, secure credentials, or prove a deployment is ready.
