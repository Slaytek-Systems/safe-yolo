import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts.package import build_bundle
from scripts.publish import ROOT, acceptance, publish


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
    def test_check_never_touches_the_callers_home_or_runs_their_opencode(self, _verify):
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
            archive = build_bundle(ROOT, root / 'bundle', revision)
            caller = {'HOME': str(home), 'PATH': os.pathsep.join([str(host_bin), '/usr/bin', '/bin']),
                      'XDG_CONFIG_HOME': str(home / '.config'), 'OPENCODE_CONFIG_DIR': str(home / 'oc')}
            with patch.dict('os.environ', caller):
                acceptance(archive, revision)

            self.assertEqual([], list(home.iterdir()))


if __name__ == '__main__':
    unittest.main()
