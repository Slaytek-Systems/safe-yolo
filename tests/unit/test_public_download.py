from pathlib import Path
import tempfile
import unittest
import zipfile

from email.message import Message
from unittest.mock import patch
import urllib.error

from scripts.download import extract, fetch, rate_limit_message


class PublicDownloadTests(unittest.TestCase):
    def test_rejects_non_https_before_network(self):
        with self.assertRaisesRegex(RuntimeError, 'HTTPS'):
            fetch('http://example.com/release.zip')

    def test_rejects_traversal_and_duplicate_archive_paths(self):
        for names in [('release/../../escape',), ('/absolute',), ('a/file', 'b/file'),
                      ('release/file', 'release/file')]:
            with self.subTest(names=names), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                archive = root / 'bad.zip'
                with zipfile.ZipFile(archive, 'w') as bundle:
                    for name in names:
                        bundle.writestr(name, 'bad')
                with self.assertRaises(RuntimeError):
                    extract(archive, root / 'out')


def _headers(**values):
    headers = Message()
    for name, value in values.items():
        headers[name.replace('_', '-')] = value
    return headers


class RateLimitMessageTests(unittest.TestCase):
    URL = 'https://api.github.com/repos/Slaytek-Systems/safe-yolo/releases?per_page=20'

    def test_names_request_limit_and_reset_time(self):
        message = rate_limit_message(self.URL, 403, _headers(X_RateLimit_Remaining='0',
                                     X_RateLimit_Reset='1900'), now=1000)
        self.assertIn(self.URL, message)
        self.assertIn('HTTP 403', message)
        self.assertIn('60 anonymous requests per hour', message)
        self.assertIn('in about 15 min', message)
        self.assertIn('safe-yolo update --source', message)

    def test_retry_after_wins_over_reset(self):
        message = rate_limit_message(self.URL, 429, _headers(Retry_After='30',
                                     X_RateLimit_Remaining='5'), now=1000)
        self.assertIn('in about 1 min', message)

    def test_other_errors_are_left_alone(self):
        self.assertIsNone(rate_limit_message(self.URL, 403, _headers(X_RateLimit_Remaining='12')))
        self.assertIsNone(rate_limit_message(self.URL, 404, _headers(X_RateLimit_Remaining='0')))
        self.assertIsNone(rate_limit_message(self.URL, 403, None))

    def test_fetch_raises_the_explained_error(self):
        error = urllib.error.HTTPError(self.URL, 403, 'rate limit exceeded',
                                       _headers(X_RateLimit_Remaining='0', X_RateLimit_Reset='0'), None)
        with patch('urllib.request.OpenerDirector.open', side_effect=error):
            with self.assertRaisesRegex(RuntimeError, 'rate limit reached'):
                fetch(self.URL)

    def test_fetch_keeps_other_http_errors(self):
        error = urllib.error.HTTPError(self.URL, 404, 'Not Found', _headers(), None)
        with patch('urllib.request.OpenerDirector.open', side_effect=error):
            with self.assertRaises(urllib.error.HTTPError):
                fetch(self.URL)
