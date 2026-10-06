# Install Safe YOLO

Give your coding agent this instruction:

> Install Safe YOLO from https://github.com/Slaytek-Systems/safe-yolo-releases.
> Read its installation guide, verify the release checksum, install my supported
> coding tools globally, and run doctor. Preserve my existing settings. Report
> the installed version and any native hook trust or restart step I need to do.

## Requirements

Linux and Python 3.12+ are the tested platform. No Git checkout, GitHub account,
package dependencies, or background service is required. The package contains
Python source. macOS and Windows acceptance is still pending.

## Install

The public release repository contains a small standard-library installer. It
downloads the newest complete 3.x release (including beta releases), verifies
its SHA-256, and installs detected supported integrations:

```sh
curl -fsSL https://raw.githubusercontent.com/Slaytek-Systems/safe-yolo-releases/main/install.py -o /tmp/safe-yolo-install.py
python3 /tmp/safe-yolo-install.py
```

Inspect the downloaded installer first if desired. To select one tool explicitly,
use `python3 /tmp/safe-yolo-install.py --harness cursor` (or `codex`, `claude-code`).
No administrator access is needed.

For a manual or offline installation, download the ZIP and its `.zip.sha256`
from Releases, verify before extraction, then run:

```sh
sha256sum -c safe-yolo-3.0.0-beta.5.zip.sha256
unzip safe-yolo-3.0.0-beta.5.zip
cd safe-yolo-3.0.0-beta.5
python3 safe-yolo harnesses
python3 safe-yolo install
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

The release runs locally from `~/.safe-yolo/releases/`. Management files are
retained under `~/.safe-yolo/management/`, so the extracted download can be moved
after installation. The global command is `~/.local/bin/safe-yolo`. Add
`~/.local/bin` to your PATH if needed, or invoke that absolute path directly.
The installer does not edit your shell profile. There are no network calls in
normal hook checks, and no background service.

## Updates and customization

```sh
safe-yolo doctor
safe-yolo update
safe-yolo doctor
```

Update downloads a verified release and updates active installations. For an
offline update use `safe-yolo update --source /path/to/extracted-release`.
Each harness is updated independently; if one fails, completed installations
remain usable. Run doctor to inspect the state before retrying.

Local customizations live outside versioned releases at
`~/.safe-yolo/customizations.json`. Install, update, rollback, and uninstall
preserve this file. For example:

```json
{
  "deny_tools": ["dangerous_tool"],
  "private_paths": ["/absolute/path/to/private-material"]
}
```

`deny_tools` names exact normalized tool IDs; `private_paths` adds paths that
agents cannot access. These options add restrictions to the default policy.
Use absolute paths. Unknown fields, invalid JSON, and oversized settings fail
closed. Edit through a human/operator session because Safe YOLO protects its
own configuration. Run doctor after editing.

The Python source is included for inspection and local modification. Arbitrary
source forks are separate from supported customization: changing a release
invalidates its integrity checks. Maintain such changes in your own checkout,
give your build a unique version, and build/install it as a separate release.
Automatic merging of arbitrary source changes is not provided.

## Roll back or uninstall

```sh
safe-yolo rollback
safe-yolo uninstall
```

Rollback restores the previous installed runtime and hook pin. Uninstall removes
the integrations installed by this lifecycle, retaining unrelated settings.
Use `--harness cursor` (or another supported ID) to act on just one integration.
Both refuse to overwrite configuration changed since the last installation.
Legacy installations whose baseline already contains an enforcement hook require
operator review for complete removal. Restart the affected harness afterward.

Inactive releases, management commands, customizations, and recovery evidence
are retained on disk. Uninstall stops enforcement; it does not erase your files.
The older `deactivate --harness <id>` command still restores the exact previous
configuration snapshot, which can reactivate an older Safe YOLO installation.

## Maintainer build

From a clean, committed source checkout:

```sh
python3 scripts/package.py --output /path/to/downloads
```

This produces a reproducible versioned ZIP and adjacent checksum. The package
includes the runtime, portable management scripts, permission notice, and user
documentation. Git history, local state, tests, host snapshots, and remote
operator maintenance scripts are excluded.

Publish both files to `Slaytek-Systems/safe-yolo-releases` under the tag
`v<VERSION>`. Copy `scripts/download.py` to its `install.py` and this guide to its
README. The development repository remains private. Verify anonymous download
and a clean-home install after publishing; private-repository Releases alone
do not provide public distribution.

## Limits

The beta provides installation lifecycles for Codex, Claude Code, and Cursor.
Other included adapters are experimental and have no supported installer yet.
Linux is verified; macOS and Windows acceptance is pending. No mobile app is
required because enforcement runs on the machine running the coding harness.
Direct doctor canaries prove adapter behavior, not that a running harness has
trusted and loaded its hook. Safe YOLO is backpressure for direct actions, not
a sandbox or security boundary against arbitrary same-user code.
