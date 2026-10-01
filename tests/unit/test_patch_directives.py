import unittest

from engine.consequences_v2 import ConsequenceKernel


class PatchDirectiveTests(unittest.TestCase):
    def test_only_unprefixed_patch_directives_are_returned(self):
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
            '*** Add File: actual.py', '*** End Patch',
        ]), ConsequenceKernel._patch_directives(patch))

    def test_non_string_has_no_directives(self):
        self.assertEqual('', ConsequenceKernel._patch_directives({'patch': 'data'}))


if __name__ == '__main__':
    unittest.main()
