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
        self.assertIn('api.github.com refused https://api.github.com/repos/Slaytek-Systems/safe-yolo/releases ', message)
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
                                       (429, _headers(), b''), (403, _headers(Retry_After='60'), b''),
                                       (403, _headers(X_RateLimit_Remaining='12',
                                                      Retry_After='Wed, 21 Oct 2026 07:28:00 GMT'), b'')]:
            with self.subTest(code=code, headers=dict(headers)):
                message = rate_limit_message(self.URL, code, headers, lambda: payload, now=1000)
                self.assertIn('rate limit reached', message)
                self.assertNotIn('60 unauthenticated', message)

    def test_other_errors_are_left_alone(self):
        self.assertIsNone(rate_limit_message(self.URL, 403, _headers(X_RateLimit_Remaining='12'),
                                             lambda: b'{"message":"Forbidden"}'))
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

    def test_redirected_signed_query_is_not_printed(self):
        asset = 'https://objects.githubusercontent.com/release-asset?X-Amz-Signature=secret123&token=abc'
        error = urllib.error.HTTPError(asset, 429, 'Too Many Requests', _headers(), None)
        with patch('urllib.request.OpenerDirector.open', side_effect=error):
            with self.assertRaises(RuntimeError) as caught:
                fetch('https://github.com/Slaytek-Systems/safe-yolo/releases/download/v3/x.zip')
        self.assertIn('objects.githubusercontent.com/release-asset ', str(caught.exception))
        self.assertNotIn('secret123', str(caught.exception))
        self.assertNotIn('token', str(caught.exception))

    def test_body_is_read_only_when_needed_and_read_failures_keep_the_status(self):
        import http.client

        class BrokenBody(urllib.error.HTTPError):
            reads = 0

            def read(self, *args):
                BrokenBody.reads += 1
                raise http.client.IncompleteRead(b'')

        for code, expected in [(429, RuntimeError), (404, urllib.error.HTTPError), (403, urllib.error.HTTPError)]:
            with self.subTest(code=code):
                BrokenBody.reads = 0
                error = BrokenBody(self.URL, code, 'x', _headers(), None)
                with patch('urllib.request.OpenerDirector.open', side_effect=error):
                    with self.assertRaises(expected) as caught:
                        fetch(self.URL)
                self.assertIs(type(caught.exception), BrokenBody if expected is urllib.error.HTTPError
                              else RuntimeError)
                self.assertEqual(1 if code == 403 else 0, BrokenBody.reads)

    def test_fetch_keeps_other_http_errors(self):
        error = urllib.error.HTTPError(self.URL, 404, 'Not Found', _headers(), None)
        with patch('urllib.request.OpenerDirector.open', side_effect=error):
            with self.assertRaises(urllib.error.HTTPError):
                fetch(self.URL)
