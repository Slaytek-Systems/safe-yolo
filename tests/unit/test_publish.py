import json
from pathlib import Path
import unittest
from unittest.mock import patch

from scripts.publish import publish


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


if __name__ == '__main__':
    unittest.main()
