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


def _replace_if_unchanged(config: Path, expected: bytes, payload: bytes) -> None:
    """Swap in `payload` only while `config` still holds `expected`.

    The new file is fully staged first, so the comparison is the last step before
    the rename. A save by another program between those two steps is still lost.
    """
    mode = config.stat().st_mode & 0o777
    descriptor, temporary_name = tempfile.mkstemp(prefix=f'.{config.name}.', dir=config.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, 'wb') as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        if config.is_symlink() or not config.is_file() or config.read_bytes() != expected:
            raise RuntimeError('Harness configuration changed; refusing to overwrite newer work.')
        os.replace(temporary, config)
    finally:
        if temporary.exists():
            temporary.unlink()


def restore(home: Path, user: Path, harness: str, *, uninstall: bool) -> dict[str, Any]:
    from scripts.distribute import _atomic_write, _read_harness_receipt, _retire, _sha256, _spec
    receipt, path = _read_harness_receipt(home, _spec(harness))
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
    current_bytes = None if config.is_symlink() or not config.is_file() else config.read_bytes()
    if harness == 'opencode':
        from scripts.harness_wiring import opencode_plugin_path_problem
        if opencode_plugin_path_problem(config):
            current_bytes = None
    if current_bytes is None or hashlib.sha256(current_bytes).hexdigest() != receipt['installed_config_sha256']:
        raise RuntimeError('Harness configuration changed; refusing to overwrite newer work.')
    if uninstall:
        baseline = receipt.get('original_install', receipt)
        original_bytes = None
        original = {}
        if baseline['previous_config_existed']:
            original_bytes = Path(baseline['previous_config_backup']).read_bytes()
            original = json.loads(original_bytes)
        document = json.loads(current_bytes)
        event = 'preToolUse' if harness == 'cursor' else 'PreToolUse'
        original_hooks = original.get('hooks', {})
        if harness == 'claude-code':
            from scripts.harness_wiring import remove_safe_yolo_hooks, safe_yolo_hook_slots
            legacy = bool(safe_yolo_hook_slots(original_hooks.get(event)))
            others = remove_safe_yolo_hooks(document['hooks'].get(event, []))
        else:
            legacy, others = bool(original_hooks.get(event)), []
        if legacy:
            raise RuntimeError('The legacy baseline already contains an enforcement hook; a complete uninstall needs operator review.')
        if others:
            document['hooks'][event] = others
        elif event in original_hooks and not original_hooks[event]:
            document['hooks'][event] = original_hooks[event]
        else:
            document['hooks'].pop(event, None)
        if not document['hooks'] and 'hooks' not in original:
            document.pop('hooks')
        if harness == 'cursor':
            if 'version' in original:
                document['version'] = original['version']
            else:
                document.pop('version', None)
        elif harness == 'codex':
            from scripts.harness_wiring import CODEX_DESCRIPTION
            if document.get('description') == CODEX_DESCRIPTION:
                if 'description' in original:
                    document['description'] = original['description']
                else:
                    document.pop('description')
        if not document and original_bytes is None:
            from datetime import datetime, UTC
            if config.is_symlink() or not config.is_file() or config.read_bytes() != current_bytes:
                raise RuntimeError('Harness configuration changed; refusing to overwrite newer work.')
            retained = home / 'backups' / ('uninstalled-' + harness + '-' + datetime.now(UTC).strftime('%Y%m%dT%H%M%S%fZ'))
            os.replace(config, retained)
        else:
            payload = original_bytes if document == original and original_bytes is not None else (json.dumps(document, indent=2) + '\n').encode()
            _replace_if_unchanged(config, current_bytes, payload)
        receipt['status'] = 'inactive'
        _atomic_write(path, (json.dumps(receipt, indent=2) + '\n').encode())
        return {'status': 'inactive', 'harness': harness, 'next_action': 'Restart the harness to unload Safe YOLO.'}
    previous = receipt.get('previous_install')
    if not previous:
        raise RuntimeError('No previous installation is available for rollback.')
    backup = Path(receipt['previous_config_backup'])
    if not backup.is_file() or _sha256(backup) != previous['installed_config_sha256']:
        raise RuntimeError('Rollback configuration backup is missing or changed.')
    from scripts.doctor import inspect_release
    report = inspect_release(Path(previous['release']), previous['manifest_sha256'])
    if not report['healthy']:
        raise RuntimeError('Previous release failed verification; rollback was not applied.')
    _atomic_write(config, backup.read_bytes(), receipt['previous_config_mode'])
    _atomic_write(path, (json.dumps(previous, indent=2) + '\n').encode())
    return {'status': 'active', 'harness': harness, 'version': previous['version'],
            'next_action': previous['next_action']}
