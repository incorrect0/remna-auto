import importlib.util
from pathlib import Path
import sys
import json
import subprocess
import tempfile
import os
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import controller as c


class ControllerTests(unittest.TestCase):
    @unittest.skipUnless(os.name == 'posix', 'PTY menu tests require POSIX')
    def test_local_launcher_returns_to_menu_after_success_and_failure(self):
        import pty
        for result_code in (0, 1):
            with self.subTest(result_code=result_code), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                # Fixture bypasses the real root check and runs no installer commands.
                source = (ROOT / 'run.sh').read_text().replace('${EUID}', '0')
                (root / 'run.sh').write_text(source)
                (root / 'setup.py').write_text("print('FAKE_NODE_FINISHED'); raise SystemExit(" + str(result_code) + ")")
                master, slave = pty.openpty()
                try:
                    process = subprocess.Popen(['bash', str(root / 'run.sh')], stdin=slave,
                                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                    os.write(master, b'2\n0\n')
                    output = process.communicate(timeout=10)[0].decode()
                    self.assertEqual(process.returncode, 0, output)
                    self.assertIn('FAKE_NODE_FINISHED', output)
                    self.assertGreaterEqual(output.count('Установить ноду на текущий сервер'), 2)
                finally:
                    os.close(master)
                    os.close(slave)

    def test_menu_reprompts_invalid_choice_and_allows_exit(self):
        with patch.object(c, 'input', side_effect=['invalid', '0'], create=True) as ask:
            self.assertEqual(c.menu(), '0')
            self.assertEqual(ask.call_count, 2)

    def test_success_returns_to_menu(self):
        with tempfile.TemporaryDirectory() as folder:
            (Path(folder) / 'settings.json').write_text('{}')
            with patch.object(c, 'HOME', Path(folder)), \
                 patch.object(c.os, 'geteuid', return_value=0, create=True), \
                 patch.object(c.sys, 'argv', ['controller.py']), \
                 patch.object(c.sys.stdin, 'isatty', return_value=True), \
                 patch.object(c, 'menu', side_effect=['1', '0']) as menu, \
                 patch.object(c, 'deploy') as deploy:
                c.main()
                self.assertEqual(menu.call_count, 2)
                deploy.assert_called_once()

    def test_failure_returns_to_menu(self):
        with tempfile.TemporaryDirectory() as folder:
            (Path(folder) / 'settings.json').write_text('{}')
            with patch.object(c, 'HOME', Path(folder)), \
                 patch.object(c.os, 'geteuid', return_value=0, create=True), \
                 patch.object(c.sys, 'argv', ['controller.py']), \
                 patch.object(c.sys.stdin, 'isatty', return_value=True), \
                 patch.object(c, 'menu', side_effect=['1', '0']) as menu, \
                 patch.object(c, 'deploy', side_effect=c.s.SetupError('test failure')):
                c.main()
                self.assertEqual(menu.call_count, 2)

    def test_broker_denies_arbitrary_urls_and_other_resources(self):
        api = Mock()
        for method, path in [('GET', 'https://other.test'), ('GET', '/api/users'),
                             ('POST', '/api/config-profiles')]:
            with self.assertRaises(c.s.SetupError):
                c.broker_request(api, method, path, {}, '203.0.113.12')
        api.request.assert_not_called()

    def test_broker_denies_changes_to_other_server(self):
        api = Mock()
        with self.assertRaises(c.s.SetupError):
            c.broker_request(api, 'POST', '/api/nodes',
                {'note': 'remna-auto:test', 'address': '203.0.113.13'}, '203.0.113.12')
        api.request.assert_not_called()

    def test_broker_rejects_foreign_node_delete(self):
        api = Mock()
        api.request.return_value = {'address': '203.0.113.13', 'note': 'remna-auto:test'}
        with self.assertRaises(c.s.SetupError):
            c.broker_request(api, 'DELETE', '/api/nodes/' + 'a' * 36, None, '203.0.113.12')
        self.assertEqual(api.request.call_count, 1)

    def test_broker_allows_owned_target(self):
        api = Mock()
        body = {'note': 'remna-auto:test', 'address': '203.0.113.12'}
        c.broker_request(api, 'POST', '/api/nodes', body, '203.0.113.12')
        api.request.assert_called_once_with('POST', '/api/nodes', body)

    def test_fingerprint_is_sha256(self):
        key = Mock();key.asbytes.return_value = b'test-public-key'
        self.assertTrue(c.fingerprint(key).startswith('SHA256:'))
        self.assertNotIn('=', c.fingerprint(key))

    def test_worker_plan_protocol_needs_no_panel_credentials(self):
        import test_setup
        profile = test_setup.FakeAPI().profile
        initial = {'domain': 'node.example.com', 'address': '203.0.113.12',
                   'profile_uuid': profile['uuid'], 'plan': True}
        replies = [initial, {'result': []}, {'result': {'configProfiles': [profile]}},
                   {'result': profile}, {'result': profile}]
        with tempfile.TemporaryDirectory() as folder:
            script = ("import remote_worker as w; from pathlib import Path; "
                      "w.s.ROOT=Path(__import__('sys').argv[1]); "
                      "w.s.country_for_ipv4=lambda ip: ('DE','Germany'); w.main()")
            result = subprocess.run([sys.executable, '-c', script, folder], cwd=ROOT,
                input=''.join(json.dumps(r) + '\n' for r in replies), text=True,
                capture_output=True, timeout=10, check=True)
        messages = [json.loads(line) for line in result.stdout.splitlines()]
        self.assertTrue(messages[-1]['done'])
        self.assertEqual(len([m for m in messages if 'api' in m]), 4)
