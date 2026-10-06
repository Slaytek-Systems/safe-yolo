"""Persistent management command; network access happens only on explicit update."""

from __future__ import annotations

import json
import os
from pathlib import Path
import shlex
import shutil
import sys
import tempfile
from typing import Any

from scripts.package import MANIFEST, verify_bundle


def install_command(source: Path, home: Path, user: Path) -> Path | None:
    # Legacy minimal source fixtures and operator installations are still supported.
    if not (source / 'safe-yolo').is_file():
        return None
    from scripts.distribute import _atomic_write
    from scripts.package import build_bundle
    version = (source / 'VERSION').read_text().strip()
    target = home / 'management' / version
    launcher = user / '.local/bin/safe-yolo'
    marker = '# Safe YOLO managed command\n'
    if launcher.exists() or launcher.is_symlink():
        if launcher.is_symlink() or marker not in launcher.read_text():
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
    command = shlex.join([sys.executable, str(target / 'safe-yolo'), '--home', str(home), '--user-home', str(user)])
    _atomic_write(launcher, ('#!/bin/sh\n' + marker + 'exec ' + command + ' "$@"\n').encode(), 0o755)
    return launcher


def active_receipts(home: Path) -> list[dict[str, Any]]:
    from scripts.distribute import _has_harness_receipt, _read_harness_receipt
    from scripts.harness_specs import HARNESSES
    return [receipt for spec in HARNESSES if spec.lifecycle_supported and _has_harness_receipt(home, spec)
            for receipt, _ in [_read_harness_receipt(home, spec)] if receipt.get('status') == 'active']


def restore(home: Path, user: Path, harness: str, *, uninstall: bool) -> dict[str, Any]:
    from scripts.distribute import _atomic_write, _read_harness_receipt, _sha256, _spec
    receipt, path = _read_harness_receipt(home, _spec(harness))
    config = Path(receipt['config_path'])
    if config.is_symlink() or not config.is_file() or _sha256(config) != receipt['installed_config_sha256']:
        raise RuntimeError('Harness configuration changed; refusing to overwrite newer work.')
    if uninstall:
        baseline = receipt.get('original_install', receipt)
        original_bytes = None
        original = {}
        if baseline['previous_config_existed']:
            original_bytes = Path(baseline['previous_config_backup']).read_bytes()
            original = json.loads(original_bytes)
        document = json.loads(config.read_text())
        event = 'preToolUse' if harness == 'cursor' else 'PreToolUse'
        original_hooks = original.get('hooks', {})
        if original_hooks.get(event):
            raise RuntimeError('The legacy baseline already contains an enforcement hook; a complete uninstall needs operator review.')
        if event in original_hooks:
            document['hooks'][event] = original_hooks[event]
        else:
            document['hooks'].pop(event, None)
        if not document['hooks'] and 'hooks' not in original:
            document.pop('hooks')
        owned_key = 'version' if harness == 'cursor' else 'description' if harness == 'codex' else None
        if owned_key:
            if owned_key in original:
                document[owned_key] = original[owned_key]
            else:
                document.pop(owned_key, None)
        if not document and original_bytes is None:
            from datetime import datetime, UTC
            retained = home / 'backups' / ('uninstalled-' + harness + '-' + datetime.now(UTC).strftime('%Y%m%dT%H%M%S%fZ'))
            os.replace(config, retained)
        else:
            payload = original_bytes if document == original and original_bytes is not None else (json.dumps(document, indent=2) + '\n').encode()
            _atomic_write(config, payload, baseline['previous_config_mode'])
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
