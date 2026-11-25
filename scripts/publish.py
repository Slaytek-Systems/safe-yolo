"""Build and exercise a clean source release; publish only on explicit request."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.download import REPOSITORY, extract
from scripts.package import build_bundle, verify_bundle


def acceptance(archive: Path, revision: str) -> None:
    """Exercise the shipped bundle without touching the operator's installation."""
    with tempfile.TemporaryDirectory(prefix='safe-yolo-release-check-') as temporary:
        root = Path(temporary)
        source = extract(archive, root / 'extracted')
        if verify_bundle(source) != revision:
            raise ValueError('Source provenance mismatch')
        user = root / 'user'
        for directory in ('.codex', '.claude', '.cursor', '.config/opencode/plugins', '.gemini/config'):
            (user / directory).mkdir(parents=True)
        (user / '.codex/config.toml').write_text(
            'approval_policy = "never"\nsandbox_mode = "danger-full-access"\n[features]\nhooks = true\n')
        (user / '.claude/settings.json').write_text('{"theme": "dark"}\n')
        other_plugin = user / '.config/opencode/plugins/other.js'
        other_plugin.write_text('export default { id: "other", setup() {} }\n')
        antigravity_hooks = user / '.gemini/config/hooks.json'
        antigravity_others = '{"herdr": {"PreInvocation": [{"type": "command", "command": "herdr"}]}}\n'
        antigravity_hooks.write_text(antigravity_others)
        # The host's own `opencode --version` creates its config, data, state and cache folders, and a host V1
        # would fail the check, so the check sees only a fixture that prints the V2 version line.
        fixture = root / 'bin'
        fixture.mkdir()
        (fixture / 'opencode').write_text("#!/bin/sh\necho 'opencode v2.3.2'\n")
        (fixture / 'opencode').chmod(0o755)
        search = [str(fixture)] + [entry for entry in os.environ.get('PATH', os.defpath).split(os.pathsep)
                                   if entry and not (Path(entry) / 'opencode').exists()]
        environment = {key: value for key, value in os.environ.items()
                       if key not in {'CODEX_HOME', 'CLAUDE_CONFIG_DIR', 'OPENCODE_CONFIG_DIR', 'OPENCODE_DB',
                                      'GEMINI_HOME', 'PYTHONPATH'}}
        environment.update(HOME=str(user), PATH=os.pathsep.join(search),
                           XDG_CONFIG_HOME=str(user / '.config'), XDG_DATA_HOME=str(user / '.local/share'),
                           XDG_STATE_HOME=str(user / '.local/state'), XDG_CACHE_HOME=str(user / '.cache'))

        def run(args: list[str]) -> dict:
            result = subprocess.run(args, cwd=root, env=environment, capture_output=True,
                                    text=True, check=True)
            return json.loads(result.stdout)

        result = run([sys.executable, str(source / 'safe-yolo'), '--home', str(user / '.safe-yolo'),
                      '--user-home', str(user), 'install'])
        if {item['harness'] for item in result['reports']} != {'codex', 'claude-code', 'cursor', 'opencode',
                                                               'antigravity'}:
            raise ValueError('Expected five installed harnesses')
        source.rename(root / 'moved-download')
        launcher = str(user / '.local/bin/safe-yolo')
        if not run([launcher, 'doctor'])['healthy']:
            raise ValueError('Global doctor failed')
        run([launcher, 'update', '--source', str(root / 'moved-download')])
        run([launcher, 'uninstall'])
        if any((user / path).exists() for path in
               ('.codex/hooks.json', '.cursor/hooks.json', '.config/opencode/plugins/safe-yolo.js')):
            raise ValueError('Uninstall left an active integration')
        if (user / '.claude/settings.json').read_text() != '{"theme": "dark"}\n':
            raise ValueError('Uninstall changed unrelated settings')
        if other_plugin.read_text() != 'export default { id: "other", setup() {} }\n':
            raise ValueError('Uninstall changed another OpenCode plugin')
        if antigravity_hooks.read_text() != antigravity_others:
            raise ValueError('Uninstall changed another Antigravity hook group')


def publish(archive: Path, version: str, revision: str) -> None:
    if (os.environ.get('GITHUB_REPOSITORY') != REPOSITORY
            or os.environ.get('GITHUB_REF') != 'refs/heads/main'
            or os.environ.get('GITHUB_SHA') != revision
            or not re.fullmatch('[0-9a-f]{40}', revision)):
        raise ValueError('Publication requires the exact main workflow checkout')
    tag = f'v{version}'
    ref = f'refs/tags/{tag}'
    prefix = f'repos/{REPOSITORY}/git'

    def api(path: str):
        return json.loads(subprocess.check_output(['gh', 'api', path], text=True))

    matches = [item for item in api(f'{prefix}/matching-refs/tags/{tag}') if item['ref'] == ref]
    if matches:
        if (len(matches) != 1 or matches[0]['object']['type'] != 'commit'
                or matches[0]['object']['sha'] != revision):
            raise ValueError('Existing release tag does not match this reviewed commit')
    else:
        subprocess.run(['gh', 'api', '--method', 'POST', f'{prefix}/refs',
                        '--raw-field', f'ref={ref}', '--raw-field', f'sha={revision}'],
                       check=True, stdout=subprocess.DEVNULL)

    def verify_tag():
        observed = api(f'{prefix}/ref/tags/{tag}')
        if observed['object']['type'] != 'commit' or observed['object']['sha'] != revision:
            raise ValueError('Release tag changed during publication')

    verify_tag()
    subprocess.run(['gh', 'release', 'create', tag, str(archive),
                    str(archive.with_suffix('.zip.sha256')), '--repo', REPOSITORY,
                    '--verify-tag', '--prerelease', '--title', f'Safe YOLO {tag}',
                    '--notes-file', str(ROOT / 'RELEASE.md')], check=True)
    verify_tag()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--check', action='store_true')
    mode.add_argument('--publish', action='store_true')
    args = parser.parse_args()
    revision = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
    version = (ROOT / 'VERSION').read_text().strip()
    if not re.fullmatch(r'3\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.]+)?', version):
        raise ValueError('Invalid release version')
    with tempfile.TemporaryDirectory(prefix='safe-yolo-publish-') as temporary:
        archive = build_bundle(ROOT, Path(temporary), revision)
        acceptance(archive, revision)
        print(f'PROVEN: {version} at {revision}: bundle and five-harness lifecycle', flush=True)
        if args.publish:
            publish(archive, version, revision)


if __name__ == '__main__':
    main()
