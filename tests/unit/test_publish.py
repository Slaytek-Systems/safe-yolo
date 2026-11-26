import json
import os
import shlex
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts.package import build_bundle
from scripts.doctor import CODEX_SKIPS_SAFE_YOLO
from scripts.publish import ROOT, acceptance, check_fresh_doctor, publish


class PublicationTests(unittest.TestCase):
    revision = 'a' * 40
    environment = {'GITHUB_REPOSITORY': 'Slaytek-Systems/safe-yolo',
                   'GITHUB_REF': 'refs/heads/main', 'GITHUB_SHA': revision}

    @patch('scripts.publish.subprocess.run')
    @patch('scripts.publish.subprocess.check_output')
    def test_wrong_checkout_never_writes(self, output, run):
        for changes in ({'GITHUB_REF': 'refs/heads/feature'},
                        {'GITHUB_SHA': 'b' * 40}, {'GITHUB_REPOSITORY': 'a/fork'}):
            with self.subTest(changes=changes), patch.dict('os.environ', self.environment | changes):
                with self.assertRaises(ValueError):
                    publish(Path('/tmp/release.zip'), '3.0.0-beta.7', self.revision)
        output.assert_not_called()
        run.assert_not_called()

    @patch.dict('os.environ', environment)
    @patch('scripts.publish.subprocess.run')
    @patch('scripts.publish.subprocess.check_output')
    def test_existing_mismatched_tag_never_writes(self, output, run):
        output.return_value = json.dumps([{'ref': 'refs/tags/v3.0.0-beta.7',
                                         'object': {'type': 'commit', 'sha': 'b' * 40}}])
        with self.assertRaisesRegex(ValueError, 'does not match'):
            publish(Path('/tmp/release.zip'), '3.0.0-beta.7', self.revision)
        run.assert_not_called()

    @patch.dict('os.environ', environment)
    @patch('scripts.publish.subprocess.run')
    @patch('scripts.publish.subprocess.check_output')
    def test_tag_changed_before_release_prevents_upload(self, output, run):
        output.side_effect = ['[]', json.dumps({'object': {'type': 'commit', 'sha': 'b' * 40}})]
        with self.assertRaisesRegex(ValueError, 'changed'):
            publish(Path('/tmp/release.zip'), '3.0.0-beta.7', self.revision)
        self.assertEqual(1, run.call_count)
        self.assertNotIn('release', run.call_args.args[0])

    @patch.dict('os.environ', environment)
    @patch('scripts.publish.subprocess.run')
    @patch('scripts.publish.subprocess.check_output')
    def test_publishes_only_after_tag_matches_and_rechecks(self, output, run):
        observed = json.dumps({'object': {'type': 'commit', 'sha': self.revision}})
        output.side_effect = ['[]', observed, observed]
        publish(Path('/tmp/release.zip'), '3.0.0-beta.7', self.revision)
        self.assertEqual(3, output.call_count)
        command = run.call_args.args[0]
        self.assertIn('--verify-tag', command)
        self.assertIn('--prerelease', command)
        self.assertNotIn('--clobber', command)


class AcceptanceIsolationTests(unittest.TestCase):
    @patch('scripts.package.verify_source', return_value='a' * 40)
    def test_check_never_touches_the_callers_home_or_runs_their_opencode_or_agy(self, _verify):
        revision = 'a' * 40
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            home = root / 'caller-home'
            home.mkdir()
            host_bin = root / 'host-bin'
            host_bin.mkdir()
            host_opencode = host_bin / 'opencode'
            host_opencode.write_text('#!/bin/sh\nmkdir -p "$HOME/.local/share/opencode"\necho 1.19.6\n')
            host_opencode.chmod(0o755)
            agy_bin = root / 'agy-bin'
            agy_bin.mkdir()
            agy_ran = root / 'agy-ran'
            host_agy = agy_bin / 'agy'
            host_agy.write_text(f'#!/bin/sh\ntouch {shlex.quote(str(agy_ran))}\n')
            host_agy.chmod(0o755)
            archive = build_bundle(ROOT, root / 'bundle', revision)
            caller = {'HOME': str(home),
                      'PATH': os.pathsep.join([str(host_bin), str(agy_bin), '/usr/bin', '/bin']),
                      'XDG_CONFIG_HOME': str(home / '.config'), 'OPENCODE_CONFIG_DIR': str(home / 'oc'),
                      'GEMINI_HOME': str(home / 'gemini')}
            with patch.dict('os.environ', caller):
                acceptance(archive, revision)

            self.assertEqual([], list(home.iterdir()))
            self.assertFalse(agy_ran.exists())


class FreshDoctorTests(unittest.TestCase):
    """Release acceptance: in a fresh home only Codex is unhealthy, and only because /hooks has not approved it."""

    def reports(self):
        reports = [{'harness': harness, 'healthy': True, 'problems': [], 'canaries': {'allow': True, 'deny': True}}
                   for harness in ('codex', 'claude-code', 'cursor', 'opencode', 'antigravity')]
        reports[0].update(healthy=False, hook_approval=f'{CODEX_SKIPS_SAFE_YOLO} (no approval is saved)')
        return reports

    def check(self, reports, returncode=1):
        check_fresh_doctor(returncode, json.dumps({'healthy': False, 'reports': reports}))

    def test_accepts_only_the_codex_approval_warning(self):
        self.check(self.reports())

    def test_rejects_every_other_doctor_result(self):
        def warning_elsewhere(reports):
            reports[1].update(healthy=False, hook_approval=reports[0]['hook_approval'])

        def codex_problem(reports):
            reports[0]['problems'] = ['hooks unreadable']

        wrong = {
            'exit 0': lambda reports: 0, 'exit 2': lambda reports: 2,
            'missing codex': lambda reports: reports.pop(0),
            'codex twice': lambda reports: reports.append(dict(reports[0])),
            'warning on another harness': warning_elsewhere,
            'codex unknown': lambda reports: reports[0].update(hook_approval='Codex may skip Safe YOLO: x'),
            'codex healthy': lambda reports: reports[0].update(healthy=True),
            'empty canaries': lambda reports: reports[2].update(canaries={}),
            'failed canary': lambda reports: reports[3].update(canaries={'allow': True, 'deny': False}),
            'codex problem': codex_problem,
        }
        for name, change in wrong.items():
            with self.subTest(name):
                reports = self.reports()
                returncode = change(reports)
                with self.assertRaises(ValueError):
                    self.check(reports, returncode if isinstance(returncode, int) else 1)
        with self.assertRaises(ValueError):
            check_fresh_doctor(2, '')


if __name__ == '__main__':
    unittest.main()
