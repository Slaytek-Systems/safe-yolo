"""Bounded, HTTPS-only downloads from the public release repository."""

import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import stat
import urllib.parse
import urllib.request
import zipfile

REPOSITORY = 'Slaytek-Systems/safe-yolo'
MAX_DOWNLOAD = 16 * 1024 * 1024


class HTTPSRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if urllib.parse.urlparse(newurl).scheme != 'https':
            raise RuntimeError('Refusing a non-HTTPS download redirect.')
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch(url: str, limit: int = MAX_DOWNLOAD) -> bytes:
    if urllib.parse.urlparse(url).scheme != 'https':
        raise RuntimeError('Downloads require HTTPS.')
    opener = urllib.request.build_opener(HTTPSRedirect())
    with opener.open(urllib.request.Request(url, headers={'User-Agent': 'safe-yolo'}), timeout=30) as response:
        data = response.read(limit + 1)
    if len(data) > limit:
        raise RuntimeError('Download exceeded the size limit.')
    return data


def extract(archive: Path, destination: Path) -> Path:
    with zipfile.ZipFile(archive) as bundle:
        entries = bundle.infolist()
        if len(entries) > 1000 or sum(item.file_size for item in entries) > MAX_DOWNLOAD:
            raise RuntimeError('Archive exceeds extraction limits.')
        names = set()
        roots = set()
        for item in entries:
            path = PurePosixPath(item.filename)
            if (path.is_absolute() or '..' in path.parts or '\\' in item.filename
                    or not path.parts or item.filename in names
                    or stat.S_ISLNK(item.external_attr >> 16)):
                raise RuntimeError('Unsafe archive path.')
            names.add(item.filename)
            roots.add(path.parts[0])
        if len(roots) != 1:
            raise RuntimeError('Archive must contain exactly one release directory.')
        bundle.extractall(destination)
    source = destination / roots.pop()
    return source


def download_latest(destination: Path) -> Path:
    releases = json.loads(fetch(f'https://api.github.com/repos/{REPOSITORY}/releases?per_page=20', 1024 * 1024))
    for release in releases:
        if release.get('draft'):
            continue
        tag = release.get('tag_name', '')
        if not re.fullmatch(r'v3\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.]+)?', tag):
            continue
        filename = f'safe-yolo-{tag[1:]}.zip'
        assets = {item['name']: item for item in release.get('assets', [])}
        if filename not in assets or filename + '.sha256' not in assets:
            continue
        base = f'https://github.com/{REPOSITORY}/releases/download/{tag}/'
        checksum = fetch(base + filename + '.sha256', 1024).decode().strip().split()
        if len(checksum) != 2 or checksum[1] != filename or not re.fullmatch('[0-9a-f]{64}', checksum[0]):
            raise RuntimeError('Invalid publisher checksum.')
        data = fetch(base + filename)
        if hashlib.sha256(data).hexdigest() != checksum[0]:
            raise RuntimeError('Download checksum mismatch.')
        destination.mkdir(parents=True, exist_ok=True)
        archive = destination / filename
        archive.write_bytes(data)
        return extract(archive, destination / 'extracted')
    raise RuntimeError('No complete public Safe YOLO release is available.')


def main() -> int:
    import subprocess
    import sys
    import tempfile
    if sys.version_info < (3, 12):
        print('Safe YOLO requires Python 3.12 or newer.', file=sys.stderr)
        return 2
    try:
        with tempfile.TemporaryDirectory(prefix='safe-yolo-install-') as temporary:
            source = download_latest(Path(temporary))
            return subprocess.run([sys.executable, str(source / 'safe-yolo'), 'install', *sys.argv[1:]], check=False).returncode
    except (RuntimeError, OSError, ValueError, zipfile.BadZipFile) as error:
        print(f'safe-yolo: {error}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
