from pathlib import Path
import tempfile
import unittest
import zipfile

from scripts.download import extract, fetch


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
