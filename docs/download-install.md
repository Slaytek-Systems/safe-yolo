# Install a Safe YOLO download

Give your coding agent this instruction with the release ZIP and its SHA-256:

> Install Safe YOLO for my supported coding tools from this release. Verify the
> ZIP checksum before extracting it. Read docs/download-install.md, detect the
> harnesses I use, install each supported integration, and run doctor. Preserve
> existing settings and report any conflict. Tell me which native activation
> steps remain and the installed version.

## Requirements

Linux and Python 3.12+ are the tested platform. No Git checkout, GitHub account,
package dependencies, or background service is required. The package contains
Python source. macOS and Windows acceptance is still pending.

## Install

Download the ZIP and its `.zip.sha256` file from the publisher. On Linux,
verify it before extracting (use the actual release filename):

```sh
sha256sum -c safe-yolo-3.0.0-beta.3.zip.sha256
unzip safe-yolo-3.0.0-beta.3.zip
cd safe-yolo-3.0.0-beta.3
python3 safe-yolo harnesses
```

The checksum detects corruption. Obtain both files through a trusted publisher
channel; a checksum delivered with an archive is not a publisher signature.

Install each harness you use:

```sh
python3 safe-yolo install --harness cursor
python3 safe-yolo install --harness claude-code
python3 safe-yolo install --harness codex
python3 safe-yolo doctor --all
```

Run only the relevant install commands. The installer applies to the selected
user's global harness configuration across projects. It refuses conflicting
enforcement hooks. Codex additionally requires the settings documented in the
README. Follow each installer's native activation instructions; doctor checks
the adapter directly and cannot prove that an already-running harness loaded it.

The release runs locally from `~/.safe-yolo/releases/`. Keep the extracted
download available to run doctor or deactivate; a standalone global management
command is not installed yet. There are no network calls in normal hook checks.

## Updates and customization

Download and verify the next release, extract it into a new directory, and run
its install command for each harness. Existing release files are retained.
This is the current manual update flow; `safe-yolo update` is not implemented.

Unrelated harness settings are preserved. This release does not yet implement
user policy overlays or automatic merging of custom code. Keep custom source
changes separately: modified downloads fail verification. Local customization
that survives upgrades is a remaining product milestone.

## Reverse an installation

```sh
python3 safe-yolo deactivate --harness cursor
```

Use the corresponding harness ID. This restores the configuration saved before
the most recent installation. After an upgrade, that may reactivate the previous
Safe YOLO version. It is not a complete uninstall. If configuration has changed
since installation, deactivation refuses to overwrite the newer changes.

## Maintainer build

From a clean, committed source checkout:

```sh
python3 scripts/package.py --output /path/to/downloads
```

This produces a reproducible versioned ZIP and adjacent checksum. It includes
the runtime, management scripts, and user documentation; it excludes Git
history, local state, tests, and host snapshots. Host these two files wherever
recipients can download them. Publishing to the private source repository's
Releases alone would still require repository access.
