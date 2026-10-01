import unittest

from engine.consequences_v2 import ConsequenceKernel


class PatchDirectiveTests(unittest.TestCase):
    def test_header_like_lines_are_retained_conservatively(self):
        patch = '\n'.join([
            '*** Begin Patch',
            '*** Update File: module.py',
            '@@',
            '+header = "*** Add File: example.py"',
            '-*** Add File: removed-example.py',
            ' *** Add File: context-example.py',
            '*** Add File: actual.py',
            '+content',
            '*** End Patch',
        ])
        self.assertEqual('\n'.join([
            '*** Begin Patch', '*** Update File: module.py',
            ' *** Add File: context-example.py',
            '*** Add File: actual.py', '*** End Patch',
        ]), ConsequenceKernel._patch_directives(patch))

    def test_non_string_has_no_directives(self):
        self.assertEqual('', ConsequenceKernel._patch_directives({'patch': 'data'}))

    def test_whitespace_prefixed_headers_are_not_lost(self):
        for prefix in (' ', '\t', '  \t'):
            header = prefix + '*** Add File: actual.py'
            self.assertEqual(header, ConsequenceKernel._patch_directives(header))


if __name__ == '__main__':
    unittest.main()
