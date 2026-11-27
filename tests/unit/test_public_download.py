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

    def test_primary_limit_names_request_quota_reset_and_both_routes(self):
        message = rate_limit_message(self.URL, 403, _headers(X_RateLimit_Remaining='0',
                                     X_RateLimit_Reset='1900'), now=1000)
        self.assertIn(f'api.github.com refused {self.URL}', message)
        self.assertIn('HTTP 403', message)
        self.assertIn('60 unauthenticated API requests per hour', message)
        self.assertIn('in about 15 min', message)
        self.assertIn('docs/download-install.md', message)
        self.assertIn('safe-yolo update --source', message)

    def test_retry_after_wins_over_reset(self):
        message = rate_limit_message(self.URL, 403, _headers(Retry_After='30', X_RateLimit_Remaining='0',
                                     X_RateLimit_Reset='9000'), now=1000)
        self.assertIn('in about 1 min', message)

    def test_secondary_limits_are_recognised(self):
        body = b'{"message":"You have exceeded a secondary rate limit."}'
        for code, headers, payload in [(403, _headers(X_RateLimit_Remaining='12'), body),
                                       (429, _headers(), b''), (403, _headers(Retry_After='60'), b'')]:
            with self.subTest(code=code):
                message = rate_limit_message(self.URL, code, headers, payload, now=1000)
                self.assertIn('rate limit reached', message)
                self.assertNotIn('60 unauthenticated', message)

    def test_other_errors_are_left_alone(self):
        self.assertIsNone(rate_limit_message(self.URL, 403, _headers(X_RateLimit_Remaining='12'),
                                             b'{"message":"Forbidden"}'))
        self.assertIsNone(rate_limit_message(self.URL, 404, _headers(X_RateLimit_Remaining='0')))
        self.assertIsNone(rate_limit_message(self.URL, 403, None))

    def test_malformed_timing_headers_keep_the_diagnosis(self):
        for headers in [_headers(Retry_After='\u00b2'), _headers(Retry_After=' 9' * 10),
                        _headers(Retry_After='99999999999'), _headers(X_RateLimit_Reset='abc', Retry_After='x')]:
            with self.subTest(headers=dict(headers)):
                message = rate_limit_message(self.URL, 429, headers, now=1000)
                self.assertIn('rate limit reached', message)
                self.assertIn('Try again later', message)

    def test_quota_sentence_only_for_the_rest_api(self):
        asset = 'https://objects.githubusercontent.com/release-asset'
        message = rate_limit_message(asset, 403, _headers(X_RateLimit_Remaining='0'), now=1000)
        self.assertIn(f'objects.githubusercontent.com refused {asset}', message)
        self.assertNotIn('60 unauthenticated', message)

    def test_fetch_reports_the_failing_redirected_url(self):
        asset = 'https://objects.githubusercontent.com/release-asset'
        error = urllib.error.HTTPError(asset, 429, 'Too Many Requests', _headers(), None)
        with patch('urllib.request.OpenerDirector.open', side_effect=error):
            with self.assertRaisesRegex(RuntimeError, 'objects.githubusercontent.com refused'):
                fetch('https://github.com/Slaytek-Systems/safe-yolo/releases/download/v3/x.zip')

    def test_fetch_keeps_other_http_errors(self):
        error = urllib.error.HTTPError(self.URL, 404, 'Not Found', _headers(), None)
        with patch('urllib.request.OpenerDirector.open', side_effect=error):
            with self.assertRaises(urllib.error.HTTPError):
                fetch(self.URL)
