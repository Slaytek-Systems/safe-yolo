"""Build and verify a portable source distribution using only the standard library."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.activate_v3 import verify_source

MANIFEST = 'distribution.json'
DIRECTORIES = {'adapters', 'engine', 'policy', 'scripts'}
FILES = {'safe-yolo', 'VERSION', 'README.md', 'docs/download-install.md',
         'docs/harness-support.md', 'docs/private-beta.md', 'docs/architecture.md'}


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def verify_bundle(source: Path) -> str:
    """Detect corruption; publisher authenticity comes from the download channel."""
    try:
        manifest = json.loads((source / MANIFEST).read_text())
        files = manifest['files']
        commit = manifest['source_commit']
        if manifest['schema_version'] != 1 or not isinstance(files, dict) or not files:
            raise ValueError('invalid manifest')
        if not isinstance(commit, str) or not re.fullmatch('[0-9a-f]{40}', commit):
            raise ValueError('invalid source revision')
        for name, expected in files.items():
            relative = Path(name)
            if relative.is_absolute() or '..' in relative.parts:
                raise ValueError('unsafe manifest path')
            path = source / relative
            if path.is_symlink() or not path.resolve().is_relative_to(source.resolve()):
                raise ValueError('unsafe payload path')
            if not path.is_file() or digest(path.read_bytes()) != expected:
                raise ValueError(f'checksum mismatch: {name}')
        actual = {
            str(path.relative_to(source)) for path in source.rglob('*')
            if path.is_file() and '__pycache__' not in path.parts and path.name != MANIFEST
        }
        if actual != set(files):
            raise ValueError('unexpected or missing distribution files')
        if (source / 'VERSION').read_text().strip() != manifest['version']:
            raise ValueError('version mismatch')
        return commit
    except (OSError, ValueError, KeyError, TypeError) as error:
        raise RuntimeError(f'Download verification failed: {error}') from error


def build_bundle(source: Path, output: Path, expected_commit: str) -> Path:
    source = source.resolve()
    commit = verify_source(source, expected_commit)
    version = (source / 'VERSION').read_text().strip()
    if not re.fullmatch(r'[0-9][A-Za-z0-9.+-]*', version):
        raise RuntimeError('Invalid release version')
    tracked = subprocess.run(['git', 'ls-files', '-z'], cwd=source,
                             capture_output=True, check=True).stdout.decode().split('\0')
    names = sorted(name for name in tracked if name and (
        name in FILES or Path(name).parts[0] in DIRECTORIES))
    payload = {}
    for name in names:
        path = source / name
        if path.is_symlink():
            raise RuntimeError(f'Refusing symlink in distribution: {name}')
        payload[name] = path.read_bytes()
    manifest = {'schema_version': 1, 'version': version, 'source_commit': commit,
                'files': {name: digest(data) for name, data in payload.items()}}
    payload[MANIFEST] = (json.dumps(manifest, sort_keys=True, indent=2) + '\n').encode()
    output.mkdir(parents=True, exist_ok=True)
    archive = output / f'safe-yolo-{version}.zip'
    with zipfile.ZipFile(archive, 'x', compression=zipfile.ZIP_DEFLATED) as bundle:
        for name, data in payload.items():
            entry = zipfile.ZipInfo(f'safe-yolo-{version}/{name}', (2020, 1, 1, 0, 0, 0))
            entry.compress_type = zipfile.ZIP_DEFLATED
            entry.external_attr = 0o100644 << 16
            bundle.writestr(entry, data)
    checksum = archive.with_suffix('.zip.sha256')
    checksum.write_text(f'{digest(archive.read_bytes())}  {archive.name}\n')
    return archive


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=ROOT)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=args.source, text=True).strip()
    print(build_bundle(args.source, args.output, commit))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
