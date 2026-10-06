import json
from pathlib import Path
import tempfile
import unittest

from adapters.cursor_v3 import build_kernel


class CustomizationTests(unittest.TestCase):
    def test_custom_rules_apply_without_changing_release_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            settings = home / 'customizations.json'
            settings.write_text(json.dumps({'deny_tools': ['dangerous_tool'],
                                            'private_paths': [str(home / 'private')]}))
            kernel = build_kernel(safe_yolo_home=home, cursor_home=home / '.cursor', user_home=home)
            self.assertEqual('deny', kernel.evaluate({'tool_name': 'dangerous_tool'}).outcome)
            self.assertEqual('deny', kernel.evaluate({'tool_name': 'read_file',
                'tool_input': {'path': str(home / 'private/file')}}).outcome)
            self.assertEqual('allow', kernel.evaluate({'tool_name': 'read_file',
                'tool_input': {'path': str(home / 'ordinary')}}).outcome)

    def test_invalid_customization_fails_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            (home / 'customizations.json').write_text('{"unknown": true}')
            kernel = build_kernel(safe_yolo_home=home, cursor_home=home / '.cursor', user_home=home)
            self.assertEqual('deny', kernel.evaluate({'tool_name': 'ordinary'}).outcome)
