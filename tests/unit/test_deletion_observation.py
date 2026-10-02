import contextlib
from concurrent.futures import ThreadPoolExecutor
import io
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

from adapters.codex_v3 import build_kernel, handle_pre_tool
from engine import deletion_observation


ROOT = Path(__file__).resolve().parents[2]


class DeletionObservationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.state = self.root / 'state'

    def kernel(self, observed=True):
        options = dict(safe_yolo_home=self.root / 'safe-yolo',
                       codex_home=self.root / 'codex', user_home=self.root / 'home')
        if observed:
            options['observation_dir'] = self.state
        return build_kernel(**options)

    def payload(self, command='rm -rf private-value', session='session-a'):
        return dict(tool_name='exec_command', cwd='/workspace/private-project',
                    session_id=session, tool_input={'cmd': command})

    def report(self):
        from engine.deletion_observation import report
        return report(self.state)

    def test_denials_are_grouped_without_changing_response_or_storing_literals(self):
        kernel = self.kernel()
        for command, session in [('rm -rf private-value', 'session-a'),
                                 ('rm -fr other-secret', 'session-a'),
                                 ('rm -rf another-secret', 'session-b')]:
            payload = self.payload(command, session)
            self.assertEqual(handle_pre_tool(payload, self.kernel(False)),
                             handle_pre_tool(payload, kernel))
        report = self.report()
        self.assertEqual(3, report['total_events'])
        self.assertEqual(1, len(report['groups']))
        self.assertEqual(3, report['groups'][0]['attempts'])
        self.assertEqual(2, report['groups'][0]['sessions'])
        self.assertEqual('rm -f -r <relative>', report['groups'][0]['shape'])
        db = self.state / 'observations' / 'deletions.sqlite3'
        raw = db.read_bytes()
        for secret in (b'private-value', b'other-secret', b'private-project', b'session-a'):
            self.assertNotIn(secret, raw)

    def test_allowed_scratch_is_visible_and_non_deletion_is_not_logged(self):
        kernel = self.kernel()
        self.assertIsNone(handle_pre_tool(self.payload('rm /tmp/synthetic-only'), kernel))
        self.assertIsNone(handle_pre_tool(self.payload('git status'), kernel))
        self.assertEqual('allow', self.report()['groups'][0]['outcome'])
        self.assertEqual(1, self.report()['total_events'])

    def test_database_failure_does_not_change_denial(self):
        kernel = self.kernel()
        payload = self.payload()
        expected = handle_pre_tool(payload, self.kernel(False))
        self.state.mkdir()
        (self.state / 'observations').write_text('not a directory')
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            self.assertEqual(expected, handle_pre_tool(payload, kernel))
        self.assertIn('observation unavailable', stderr.getvalue())
        self.assertNotIn('private-value', stderr.getvalue())

    def test_executable_adapter_and_report_journey(self):
        command = [sys.executable, str(ROOT / 'adapters/codex_v3.py'),
                   '--state-dir', str(self.state)]
        result = subprocess.run(command, input=json.dumps(self.payload()),
                                text=True, capture_output=True, check=True)
        self.assertEqual('deny', json.loads(result.stdout)['hookSpecificOutput']['permissionDecision'])
        result = subprocess.run([sys.executable, str(ROOT / 'safe-yolo'), 'observations',
                                 '--state-dir', str(self.state)],
                                text=True, capture_output=True, check=True)
        self.assertEqual(1, json.loads(result.stdout)['total_events'])

    def assert_unavailable_preserves_decision(self, command='rm -rf private-value'):
        payload = self.payload(command)
        expected = handle_pre_tool(payload, self.kernel(False))
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            actual = handle_pre_tool(payload, self.kernel())
        self.assertEqual(expected, actual)
        self.assertEqual(deletion_observation.DIAGNOSTIC, stderr.getvalue())

    def database(self):
        return self.state / 'observations' / 'deletions.sqlite3'

    def test_lexical_candidates_do_not_claim_recognized_consequences(self):
        kernel = self.kernel()
        for command in ('find private-name -delete', 'echo ok && rm -rf private-name',
                        'rm "unterminated-private', 'echo rm private-name'):
            payload = self.payload(command)
            self.assertEqual(handle_pre_tool(payload, self.kernel(False)), handle_pre_tool(payload, kernel))
        result = self.report()
        self.assertEqual(3, result['total_events'])
        self.assertEqual({'partial', 'unparsed'}, {group['coverage'] for group in result['groups']})
        self.assertEqual({0}, {group['recognized'] for group in result['groups']})
        self.assertNotIn('private-name', self.database().read_bytes().decode(errors='replace'))

    def test_missing_sessions_are_not_collapsed_into_an_invented_session(self):
        handle_pre_tool(self.payload(session=''), self.kernel())
        handle_pre_tool(self.payload(session=None), self.kernel())
        group = self.report()['groups'][0]
        self.assertEqual(2, group['attempts'])
        self.assertEqual(0, group['sessions'])
        self.assertEqual(2, group['missing_session_attempts'])

    def test_newline_compounds_are_visible_without_changing_enforcement(self):
        for command in ('echo ok\nrm -rf synthetic-private',
                        'echo ok;\nrm -rf synthetic-private'):
            payload = self.payload(command)
            self.assertEqual(handle_pre_tool(payload, self.kernel(False)),
                             handle_pre_tool(payload, self.kernel()))
        quoted_data = self.payload('echo "data\nrm -rf synthetic-private"')
        self.assertIsNone(handle_pre_tool(quoted_data, self.kernel()))
        groups = self.report()['groups']
        self.assertEqual(1, len(groups))
        self.assertEqual(2, groups[0]['attempts'])
        self.assertEqual('shell <compound-deletion-candidate>', groups[0]['shape'])
        self.assertEqual('partial', groups[0]['coverage'])
        self.assertEqual(0, groups[0]['recognized'])
        self.assertEqual('allow', groups[0]['outcome'])

    def test_private_permissions_and_read_only_report(self):
        handle_pre_tool(self.payload(), self.kernel())
        database = self.database()
        self.assertEqual(0o600, database.stat().st_mode & 0o777)
        self.assertEqual(0o700, database.parent.stat().st_mode & 0o777)
        before = (database.read_bytes(), database.stat().st_mtime_ns,
                  tuple(path.name for path in database.parent.iterdir()))
        self.report()
        after = (database.read_bytes(), database.stat().st_mtime_ns,
                 tuple(path.name for path in database.parent.iterdir()))
        self.assertEqual(before, after)
        missing = self.root / 'does-not-exist'
        self.assertEqual(0, deletion_observation.report(missing)['total_events'])
        self.assertFalse(missing.exists())

    def test_lock_contention_is_short_and_cannot_change_denial(self):
        handle_pre_tool(self.payload(), self.kernel())
        with contextlib.closing(sqlite3.connect(self.database(), isolation_level=None)) as connection:
            connection.execute('BEGIN IMMEDIATE')
            started = time.monotonic()
            self.assert_unavailable_preserves_decision()
            self.assertLess(time.monotonic() - started, 0.5)
            connection.execute('ROLLBACK')
        self.assertEqual(1, self.report()['total_events'])

    def test_corruption_does_not_change_denial_or_allowed_scratch(self):
        handle_pre_tool(self.payload(), self.kernel())
        self.database().write_bytes(b'corrupt-private-database')
        self.assert_unavailable_preserves_decision()
        self.assert_unavailable_preserves_decision('rm /tmp/synthetic-only')
        with self.assertRaisesRegex(RuntimeError, '^observation unavailable$'):
            self.report()
        self.assertEqual(b'corrupt-private-database', self.database().read_bytes())

    def test_full_event_capacity_keeps_existing_records_and_denial(self):
        handle_pre_tool(self.payload(), self.kernel())
        before = self.database().read_bytes()
        with mock.patch.object(deletion_observation, 'MAX_EVENTS', 1):
            self.assert_unavailable_preserves_decision()
            self.assertTrue(self.report()['at_capacity'])
        self.assertEqual(before, self.database().read_bytes())
        self.assertEqual(1, self.report()['total_events'])

    def test_page_capacity_failure_keeps_existing_records_and_denial(self):
        handle_pre_tool(self.payload(), self.kernel())
        before = self.database().read_bytes()
        with mock.patch.object(deletion_observation, 'MAX_BYTES', 4096):
            self.assert_unavailable_preserves_decision()
        self.assertEqual(before, self.database().read_bytes())

    def test_sqlite_full_rolls_back_the_failed_event(self):
        handle_pre_tool(self.payload(), self.kernel())
        byte_limit = self.database().stat().st_size
        expected = handle_pre_tool(self.payload(), self.kernel(False))
        with mock.patch.object(deletion_observation, 'MAX_BYTES', byte_limit):
            for _ in range(100):
                count = self.report()['total_events']
                stderr = io.StringIO()
                with contextlib.redirect_stderr(stderr):
                    self.assertEqual(expected, handle_pre_tool(self.payload(), self.kernel()))
                if stderr.getvalue():
                    self.assertEqual(deletion_observation.DIAGNOSTIC, stderr.getvalue())
                    self.assertEqual(count, self.report()['total_events'])
                    self.assertGreater(count, 1)
                    self.assert_unavailable_preserves_decision()
                    self.assertEqual(count, self.report()['total_events'])
                    break
            else:
                self.fail('SQLite page limit was not exercised')

    def test_static_symlinks_are_refused_without_writing_the_target(self):
        for component in ('state', 'observations', 'deletions.sqlite3', 'deletions.sqlite3-journal'):
            with self.subTest(component=component), tempfile.TemporaryDirectory() as temporary:
                state = Path(temporary) / 'state'
                outside = Path(temporary) / 'outside'
                outside.mkdir(mode=0o700)
                directory = state / 'observations'
                if component == 'state':
                    state.symlink_to(outside, target_is_directory=True)
                elif component == 'observations':
                    state.mkdir()
                    directory.symlink_to(outside, target_is_directory=True)
                else:
                    directory.mkdir(parents=True, mode=0o700)
                    (directory / component).symlink_to(outside / 'target')
                kernel = self.kernel()
                kernel.observation_dir = state
                stderr = io.StringIO()
                with contextlib.redirect_stderr(stderr):
                    self.assertEqual(handle_pre_tool(self.payload(), self.kernel(False)),
                                     handle_pre_tool(self.payload(), kernel))
                self.assertEqual(deletion_observation.DIAGNOSTIC, stderr.getvalue())
                self.assertEqual([], list(outside.iterdir()))
                with self.assertRaisesRegex(RuntimeError, '^observation unavailable$'):
                    deletion_observation.report(state)

    def test_concurrent_writers_count_each_intercepted_attempt(self):
        def write(index):
            payload = self.payload(session=f'session-{index}')
            return handle_pre_tool(payload, self.kernel())
        with ThreadPoolExecutor(max_workers=4) as executor:
            responses = list(executor.map(write, range(4)))
        self.assertTrue(all(response['hookSpecificOutput']['permissionDecision'] == 'deny'
                            for response in responses))
        group = self.report()['groups'][0]
        self.assertEqual(4, group['attempts'])
        self.assertEqual(4, group['sessions'])

    def test_observer_exception_cannot_escape_enforcement(self):
        with mock.patch.object(deletion_observation, 'observe', side_effect=RuntimeError('private-value')):
            self.assert_unavailable_preserves_decision()

    def test_context_changes_are_not_conflated(self):
        kernel = self.kernel()
        handle_pre_tool(self.payload(), kernel)
        other = self.kernel()
        other.scratch_paths = ()
        handle_pre_tool(self.payload(), other)
        self.assertEqual(2, len(self.report()['groups']))

    def test_schema_mismatch_and_insecure_storage_cannot_change_denial(self):
        handle_pre_tool(self.payload(), self.kernel())
        with sqlite3.connect(self.database()) as connection:
            connection.execute('UPDATE metadata SET schema_version=999')
        self.assert_unavailable_preserves_decision()
        with self.assertRaisesRegex(RuntimeError, '^observation unavailable$'):
            self.report()
        self.database().chmod(0o644)
        self.assert_unavailable_preserves_decision()
        with self.assertRaisesRegex(RuntimeError, '^observation unavailable$'):
            self.report()

    def test_hard_linked_database_is_refused(self):
        handle_pre_tool(self.payload(), self.kernel())
        import os
        os.link(self.database(), self.root / 'other-link')
        before = self.database().read_bytes()
        self.assert_unavailable_preserves_decision()
        self.assertEqual(before, self.database().read_bytes())

    def test_structured_deletion_and_patch_headers_are_observed_as_data(self):
        payloads = [
            dict(tool_name='delete_file', cwd='/workspace/private-project',
                 tool_input={'path': 'private-target'}),
            dict(tool_name='apply_patch', cwd='/workspace/private-project',
                 tool_input={'patch': '*** Begin Patch\n  *** Delete File: private-target\n*** End Patch'}),
        ]
        for payload in payloads:
            self.assertEqual(handle_pre_tool(payload, self.kernel(False)), handle_pre_tool(payload, self.kernel()))
        groups = self.report()['groups']
        self.assertEqual(2, len(groups))
        self.assertEqual({1}, {group['recognized'] for group in groups})
        self.assertNotIn(b'private-target', self.database().read_bytes())

    def test_arbitrary_options_environment_and_effective_workdir_are_redacted(self):
        payload = self.payload('rm --arbitrary=private-secret /private-target')
        payload['tool_input']['workdir'] = '/workspace/effective-private'
        payload['environment'] = {'PRIVATE': 'private-secret'}
        handle_pre_tool(payload, self.kernel())
        with sqlite3.connect(self.database()) as connection:
            row = connection.execute('SELECT cwd_fingerprint FROM events').fetchone()
            key = connection.execute('SELECT fingerprint_key FROM metadata').fetchone()[0]
        self.assertEqual(deletion_observation._fingerprint(key, 'cwd', '/workspace/effective-private'), row[0])
        for value in (b'private-secret', b'private-target', b'effective-private', b'PRIVATE'):
            self.assertNotIn(value, self.database().read_bytes())
        self.assertEqual('rm <option> <absolute>', self.report()['groups'][0]['shape'])

    def test_distinct_workspaces_do_not_expose_paths(self):
        first = self.payload()
        second = self.payload()
        second['cwd'] = '/workspace/other-private-project'
        for payload in (first, second):
            handle_pre_tool(payload, self.kernel())
        group = self.report()['groups'][0]
        self.assertEqual(2, group['workspaces'])
        self.assertEqual(1, group['sessions'])
        self.assertNotIn('private-project', json.dumps(group))

    def test_relative_workdirs_use_the_resolved_workspace_identity(self):
        first = self.payload()
        first['cwd'] = '/workspace/one'
        first['tool_input']['workdir'] = '.'
        second = self.payload()
        second['cwd'] = '/workspace/two'
        second['tool_input']['workdir'] = '.'
        for payload in (first, second):
            handle_pre_tool(payload, self.kernel())
        self.assertEqual(2, self.report()['groups'][0]['workspaces'])

    def test_absolute_and_relative_workdir_aliases_group_together(self):
        first = self.payload()
        first['cwd'] = '/workspace/one'
        first['tool_input']['workdir'] = '.'
        second = self.payload()
        second['tool_input']['workdir'] = '/workspace/one'
        for payload in (first, second):
            handle_pre_tool(payload, self.kernel())
        self.assertEqual(1, self.report()['groups'][0]['workspaces'])

    def test_cli_failure_is_fixed_and_read_only(self):
        handle_pre_tool(self.payload(), self.kernel())
        self.database().write_bytes(b'corrupt-private-database')
        result = subprocess.run([sys.executable, str(ROOT / 'safe-yolo'), 'observations',
                                 '--state-dir', str(self.state)], text=True, capture_output=True)
        self.assertEqual(2, result.returncode)
        self.assertEqual('', result.stdout)
        self.assertEqual('safe-yolo: observation unavailable\n', result.stderr)
        self.assertEqual(b'corrupt-private-database', self.database().read_bytes())

    def test_observer_import_failure_and_closed_stderr_preserve_denial(self):
        expected = handle_pre_tool(self.payload(), self.kernel(False))
        with mock.patch.dict(sys.modules, {'engine.deletion_observation': None}), contextlib.redirect_stderr(io.StringIO()) as stderr:
            self.assertEqual(expected, handle_pre_tool(self.payload(), self.kernel()))
        self.assertEqual(deletion_observation.DIAGNOSTIC, stderr.getvalue())
        closed = io.StringIO()
        closed.close()
        with mock.patch.object(deletion_observation, 'observe', side_effect=RuntimeError()), contextlib.redirect_stderr(closed):
            self.assertEqual(expected, handle_pre_tool(self.payload(), self.kernel()))

    def test_patch_markers_in_added_content_are_not_deletion_observations(self):
        payload = dict(tool_name='apply_patch', cwd='/workspace/private-project',
                       tool_input={'patch': '*** Begin Patch\n*** Add File: example\n+"*** Delete File: secret"\n*** End Patch'})
        self.assertIsNone(handle_pre_tool(payload, self.kernel()))
        self.assertEqual(0, self.report()['total_events'])

    def test_native_adapter_payloads_share_shapes_and_preserve_responses(self):
        adapters = {
            'codex': ('codex_v3', 'codex_home', 'handle_pre_tool', self.payload()),
            'claude-code': ('claude_code_v3', 'claude_home', 'handle_pre_tool',
                            dict(hook_event_name='PreToolUse', tool_name='Bash', cwd='/workspace/private-project',
                                 session_id='session-a', tool_input={'command': 'rm -rf private-value'})),
            'grok': ('grok_v3', 'grok_home', 'handle_pre_tool',
                     dict(hookEventName='PreToolUse', toolName='run_terminal_command', cwd='/workspace/private-project',
                          sessionId='session-a', toolInput={'command': 'rm -rf private-value'})),
            'cursor': ('cursor_v3', 'cursor_home', 'handle',
                       dict(hook_event_name='beforeShellExecution', command='rm -rf private-value',
                            working_directory='/workspace/private-project', conversation_id='session-a')),
            'opencode': ('opencode_v3', 'opencode_config', 'handle',
                         dict(tool='bash', args={'command': 'rm -rf private-value'},
                              cwd='/workspace/private-project', session_id='session-a')),
            'devin': ('devin_v3', 'devin_config', 'handle_pre_tool',
                      dict(hook_event_name='PreToolUse', tool_name='exec', session_id='session-a',
                           tool_input={'cmd': 'rm -rf private-value', 'workdir': '/workspace/private-project'})),
            'antigravity': ('antigravity_v3', 'gemini_home', 'handle_pre_tool',
                            dict(workspacePaths=['/workspace/private-project'],
                                 toolCall={'name': 'run_command', 'args': {'CommandLine': 'rm -rf private-value'}})),
        }
        import importlib
        for name, (module_name, home_key, handler_name, payload) in adapters.items():
            with self.subTest(harness=name):
                module = importlib.import_module('adapters.' + module_name)
                options = dict(safe_yolo_home=self.root / 'safe-yolo', user_home=self.root / 'home')
                options[home_key] = self.root / module_name
                handler = getattr(module, handler_name)
                self.assertEqual(handler(payload, module.build_kernel(**options)),
                                 handler(payload, module.build_kernel(**options, observation_dir=self.state)))
        groups = self.report()['groups']
        self.assertEqual(7, len(groups))
        self.assertEqual(set(adapters), {group['harness'] for group in groups})
        self.assertEqual({'rm -f -r <relative>'}, {group['shape'] for group in groups})
        self.assertEqual({'deny'}, {group['outcome'] for group in groups})


if __name__ == '__main__':
    unittest.main()
