# Publish Safe YOLO

Develop, review, and publish from this repository. No distribution checkout is
needed. The software remains under `DISTRIBUTION-LICENSE.txt`; public source
availability does not replace that custom permission with an open-source license.

1. Make changes on a branch. Give every changed release a new `VERSION`, update
   `RELEASE.md`, and run `python3 -m unittest discover -s tests/unit`.
2. Commit, then run `python3 scripts/publish.py --check`. This builds from the
   clean source commit and tests an isolated Codex, Claude Code, and Cursor
   installation, doctor, update, and uninstall. It does not touch your live tools.
3. Open a PR, complete review and CI, and merge into `main`.
4. Run **Publish Safe YOLO** in GitHub Actions on `main`, or:
   `gh workflow run publish.yml --repo Slaytek-Systems/safe-yolo --ref main`.
5. Verify the public ZIP and checksum, fresh installation, and global update.

The workflow builds its own artifacts, binds the tag and package to its exact
source commit, and only grants repository write access to the publish job after
validation. Releases are prereleases during beta. It never overwrites assets or
moves tags; corrections need another version. A tag existing at another commit
blocks publication. Tag checks are observations, not immutable-tag enforcement.
Only trusted maintainers should have repository write access.

## Existing installations

The old `Slaytek-Systems/safe-yolo-releases` repo remains a compatibility archive.
The migration publishes the exact beta.7 ZIP and checksum there once. Its old
updater installs that bridge, whose management command then fetches all future
updates here. Its installer and README direct new users here. Keep old release
URLs available; do not delete or repurpose them. No subsequent releases need
mirroring. Users can also install from this repo directly.
