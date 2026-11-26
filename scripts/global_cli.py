"""Persistent management command; network access happens only on explicit update."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import sys
import tempfile
from typing import Any

from scripts.package import MANIFEST, verify_bundle


def _launcher_payload(target: Path, home: Path, user: Path) -> bytes:
    command = shlex.join([sys.executable, str(target / 'safe-yolo'), '--home', str(home), '--user-home', str(user)])
    return ('#!/bin/sh\n# Safe YOLO managed command\nexec ' + command + ' "$@"\n').encode()


def _owns_launcher(launcher: Path, home: Path, user: Path) -> bool:
    if launcher.is_symlink() or not launcher.is_file():
        return False
    try:
        payload = launcher.read_bytes()
        lines = payload.decode().splitlines()
        if len(lines) != 3:
            return False
        command = shlex.split(lines[2])
        if len(command) != 8 or command[0] != 'exec':
            return False
        target = Path(command[2]).parent
        if target.parent != home / 'management' or target.is_symlink():
            return False
        if payload != _launcher_payload(target, home, user):
            return False
        verify_bundle(target)
        return True
    except (OSError, ValueError, RuntimeError):
        return False


def install_command(source: Path, home: Path, user: Path) -> Path | None:
    # Legacy minimal source fixtures and operator installations are still supported.
    if not (source / 'safe-yolo').is_file():
        return None
    from scripts.distribute import _atomic_write
    from scripts.package import build_bundle
    version = (source / 'VERSION').read_text().strip()
    target = home / 'management' / version
    launcher = user / '.local/bin/safe-yolo'
    if launcher.exists() or launcher.is_symlink():
        if not _owns_launcher(launcher, home, user):
            raise RuntimeError(f'Refusing to overwrite an unrelated command: {launcher}')
    if target.exists():
        verify_bundle(target)
        expected = json.loads((source / MANIFEST).read_text()) if (source / MANIFEST).is_file() else None
        if expected and json.loads((target / MANIFEST).read_text()) != expected:
            raise RuntimeError('Management version already exists with different content.')
    else:
        target.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=target.parent) as temporary:
            staging = Path(temporary) / 'bundle'
            if (source / MANIFEST).is_file():
                verify_bundle(source)
                shutil.copytree(source, staging, ignore=shutil.ignore_patterns('__pycache__'))
            else:
                import subprocess
                import zipfile
                revision = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=source, text=True).strip()
                archive = build_bundle(source, Path(temporary), revision)
                with zipfile.ZipFile(archive) as bundle:
                    bundle.extractall(Path(temporary) / 'unpacked')
                staging = next((Path(temporary) / 'unpacked').iterdir())
            verify_bundle(staging)
            os.replace(staging, target)
    _atomic_write(launcher, _launcher_payload(target, home, user), 0o755)
    return launcher


def active_receipts(home: Path) -> list[dict[str, Any]]:
    from scripts.distribute import _has_harness_receipt, _read_harness_receipt
    from scripts.harness_specs import HARNESSES
    return [receipt for spec in HARNESSES if spec.lifecycle_supported and _has_harness_receipt(home, spec)
            for receipt, _ in [_read_harness_receipt(home, spec)] if receipt.get('status') == 'active']


def restore(home: Path, user: Path, harness: str, *, uninstall: bool) -> dict[str, Any]:
    from scripts.distribute import (_apply_steps, _atomic_write, _direct_command, _read_harness_receipt,
                                    _remove_own_hook, _restore_file, _retire, _run_canaries, _saved_hook,
                                    _settled_receipt, _sha256, _spec)
    from scripts.doctor import inspect_release
    from scripts.harness_wiring import config_path_problem
    spec = _spec(harness)
    recorded, path = _read_harness_receipt(home, spec)
    receipt = _settled_receipt(recorded)
    config = Path(receipt['config_path'])
    if uninstall and harness == 'opencode':
        # Safe YOLO owns the whole plugin file. A replaced V1 copy never ran on OpenCode V2,
        # so uninstall retains the file as evidence rather than restoring it.
        retained = _retire('opencode', config, receipt['installed_config_sha256'], home)
        receipt['status'] = 'inactive'
        receipt['uninstalled_config_backup'] = str(retained)
        _atomic_write(path, (json.dumps(receipt, indent=2) + '\n').encode())
        return {'status': 'inactive', 'harness': 'opencode', 'next_action': (
            'Restart every OpenCode server that loaded Safe YOLO (`opencode service restart` for the background '
            f'service, and any `opencode serve` you started), then confirm safe-yolo.js is absent from {config.parent} '
            'and `opencode api plugin.list` against that server no longer lists safe-yolo.')}
    if uninstall:
        _remove_own_hook(spec, receipt, home)
        receipt['status'] = 'inactive'
        _atomic_write(path, (json.dumps(receipt, indent=2) + '\n').encode())
        return {'status': 'inactive', 'harness': harness, 'next_action': 'Restart the harness to unload Safe YOLO.'}
    # Rollback moves from the recorded installation to its previous one. The harness file holds
    # the hook of one of the two; the settled receipt says which.
    current_bytes = None if config.is_symlink() or not config.is_file() else config.read_bytes()
    if config_path_problem(harness, config):
        current_bytes = None
    if current_bytes is None or hashlib.sha256(current_bytes).hexdigest() != receipt['installed_config_sha256']:
        raise RuntimeError('Harness configuration changed; refusing to overwrite newer work.')
    previous = recorded.get('previous_install')
    if not previous:
        raise RuntimeError('No previous installation is available for rollback.')
    backup = Path(recorded['previous_config_backup'])
    if not backup.is_file() or _sha256(backup) != previous['installed_config_sha256']:
        raise RuntimeError('Rollback configuration backup is missing or changed.')
    report = inspect_release(Path(previous['release']), previous['manifest_sha256'])
    if not report['healthy']:
        raise RuntimeError('Previous release failed verification; rollback was not applied.')
    previous_release = Path(previous['release'])
    launcher = Path(previous['launcher']) if previous.get('launcher') else None
    saved = backup.read_bytes()
    mode = recorded['previous_config_mode']
    # The hook the harness will run is the one in the saved file, and it must answer before it is
    # published: a command that cannot start restores no guard at all.
    try:
        hook_command, timeout = _saved_hook(spec, backup, home, previous)
        canaries = _run_canaries(_direct_command(hook_command, home, spec, previous), harness, timeout)
    except RuntimeError as error:
        raise RuntimeError(f'{error}; rollback was not applied.') from error
    if not all(canaries.values()):
        raise RuntimeError(f'Previous hook command failed its allow/deny check ({canaries}); '
                           'rollback was not applied.')
    # The launcher, the harness file if it differs, then the receipt.
    steps = []
    if launcher:
        previous_launcher = launcher.read_bytes() if launcher.is_file() else None
        steps.append((lambda: _atomic_write(launcher, (previous_release / 'scripts' / 'bootstrap.py').read_bytes(),
                                            0o700),
                      _restore_file(launcher, previous_launcher, 0o700)))
    if current_bytes != saved:
        steps.append((lambda: _atomic_write(config, saved, mode), _restore_file(config, current_bytes, mode)))
    current_receipt = path.read_bytes()
    steps.append((lambda: _atomic_write(path, (json.dumps(previous, indent=2) + '\n').encode()),
                  _restore_file(path, current_receipt, 0o600)))

    def check() -> None:
        # Through the published hook: the launcher and receipt it reads changed as well.
        published = _run_canaries(hook_command, harness, timeout)
        if not all(published.values()):
            raise RuntimeError(f'Previous hook command failed its allow/deny check ({published})')

    try:
        _apply_steps(steps, check)
    except RuntimeError as error:
        raise RuntimeError(f'Safe YOLO rollback was not applied; {error}') from error
    return {'status': 'active', 'harness': harness, 'version': previous['version'],
            'next_action': previous['next_action']}
