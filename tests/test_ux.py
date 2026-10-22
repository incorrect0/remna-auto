"""Regressions for terminal UX and interrupted/offline runs; never use a real panel."""
import contextlib
import io
import itertools
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
import shutil
import ssl
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import setup as s
import controller as c


class InterfaceTests(unittest.TestCase):
    def test_plan_never_echoes_unknown_config_fields(self):
        out = io.StringIO()
        with patch.object(s.sys, 'argv', ['setup.py', 'plan']), \
             patch.object(s, 'configure', return_value=({'domain': 'node.example.com', 'api_key': 'hidden-canary'}, Mock(), {})), \
             contextlib.redirect_stdout(out):
            s.main()
        self.assertNotIn('hidden-canary', out.getvalue())
        self.assertIn('node.example.com', out.getvalue())

    def test_secret_fields_in_public_config_are_rejected(self):
        with self.assertRaises(s.SetupError) as error:
            s.validate_config({'api_key': 'hidden-canary'})
        self.assertNotIn('hidden-canary', str(error.exception))

    def test_compact_ssh_input_defaults_and_custom_values(self):
        self.assertEqual(c.parse_ssh_target('203.0.113.12'), ('203.0.113.12', 'root', 22))
        self.assertEqual(c.parse_ssh_target('admin@203.0.113.12:2222'), ('203.0.113.12', 'admin', 2222))
        for value in ('root@not-an-ip', 'bad user@203.0.113.12', '203.0.113.12:0', '203.0.113.12:'):
            with self.subTest(value=value), self.assertRaises((ValueError, s.SetupError)):
                c.parse_ssh_target(value)

    def test_api_worker_does_not_put_credentials_in_arguments(self):
        api = s.API('https://panel.example.com', 'sample-secret-value')
        process = Mock(returncode=0)
        process.communicate.return_value = ('{"result": []}', None)
        with patch.object(s.subprocess, 'Popen', return_value=process) as create:
            self.assertEqual(api.request('GET', '/api/nodes'), [])
        self.assertNotIn('sample-secret-value', str(create.call_args))
        self.assertNotIn('https://panel.example.com', str(create.call_args))
        self.assertIn('sample-secret-value', process.communicate.call_args.kwargs['input'])

    def test_api_worker_timeout_is_bounded_and_reaped(self):
        api = s.API('https://panel.example.com', 'sample-secret-value')
        process = Mock()
        with patch.object(s.subprocess, 'Popen', return_value=process), \
             patch.object(s.time, 'monotonic', side_effect=[0, 91]):
            with self.assertRaises(s.SetupError):
                api.request('GET', '/api/nodes')
        process.kill.assert_called_once()
        process.communicate.assert_called_once()

    def test_narrow_cyrillic_wide_and_long_values(self):
        for width in (16, 24, 40, 80):
            text = '  Профиль: Россия 日本 ' + 'a' * 253
            rendered = s.wrapped(text, width)
            self.assertTrue(all(s.visible_width(line) <= width for line in rendered.splitlines()))
            self.assertIn('Россия', rendered)

    def test_preview_and_sections_fit_narrow_terminal(self):
        for width in (16, 24, 40, 80):
            out = io.StringIO()
            with patch.object(s.shutil, 'get_terminal_size', return_value=os.terminal_size((width, 24))), contextlib.redirect_stdout(out):
                s.banner()
                s.section('01 / Проверка сервера', 'Длинное описание состояния службы')
            self.assertTrue(all(s.visible_width(line) <= width for line in out.getvalue().splitlines()))

    def test_no_color_in_redirected_output(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            s.log('\x1b[31mВнимание: тест\x1b[0m')
        self.assertNotIn('\x1b', out.getvalue())

    def test_terminal_payloads_and_secret_are_not_rendered(self):
        with patch.object(s, 'SECRETS', ['sample-secret-value']):
            rendered = s.safe('\x1b]0;hostile-title\x07\x1b[2Jsample-secret-value')
        self.assertNotIn('sample-secret-value', rendered)
        self.assertNotIn('hostile-title', rendered)
        self.assertNotIn('\x1b[2J', rendered)

    def test_invalid_domain_retries_only_one_field(self):
        with patch.object(s, 'ask', side_effect=['invalid', 'node.example.com']) as ask:
            self.assertEqual(s.ask_validated('Домен', s.validate_domain), 'node.example.com')
            self.assertEqual(ask.call_count, 2)

    def test_single_profile_does_not_ask(self):
        with patch.object(s, 'ask') as ask:
            self.assertEqual(s.select_profile([{'name': 'Profile', 'uuid': 'profile-id'}]), 'profile-id')
            ask.assert_not_called()

    def test_json_error_does_not_print_file_contents(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'config.json'
            path.write_text('{"private":"sample-secret-value" BROKEN', encoding='utf-8')
            with self.assertRaises(s.SetupError) as error:
                s.read_json(path)
            self.assertNotIn('sample-secret-value', str(error.exception))

    def test_command_progress_does_not_echo_arguments(self):
        process = Mock(returncode=0)
        process.communicate.side_effect = [subprocess.TimeoutExpired('tool', 10), ('done', None)]
        with patch.object(s.subprocess, 'Popen', return_value=process), \
             patch.object(s.time, 'monotonic', side_effect=itertools.count(0, 5)), \
             patch.object(s, 'log') as log:
            result = s.run(['tool', 'sample-secret-value'])
        self.assertEqual(result.stdout, 'done')
        self.assertTrue(log.called)
        self.assertNotIn('sample-secret-value', str(log.call_args_list))

    @unittest.skipUnless(os.name == 'posix', 'Process groups require POSIX')
    def test_command_timeout_kills_waiting_process(self):
        started = time.monotonic()
        with self.assertRaises(subprocess.TimeoutExpired):
            s.run([sys.executable, '-c', 'import time;time.sleep(10)'], timeout=0.05)
        self.assertLess(time.monotonic() - started, 2)


class RecoveryTests(unittest.TestCase):
    def test_recovery_requires_explicit_confirmation(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            journal = root / 'backups' / 'attempt'
            journal.mkdir(parents=True)
            (journal / 'rollback.json').write_text(json.dumps({'completed': False}))
            (root / 'pending.json').write_text(json.dumps({'backup': str(journal)}))
            with patch.object(s, 'ROOT', root), patch.object(s, 'BACKUPS', root / 'backups'), \
                 patch.object(s, 'confirm', return_value=False), patch.object(s, 'rollback') as rollback:
                with self.assertRaises(s.SetupError):
                    s.recover_pending(Mock(), True)
                rollback.assert_not_called()
                self.assertTrue((root / 'pending.json').exists())

    def test_confirmed_recovery_clears_only_own_pending_pointer(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            journal = root / 'backups' / 'attempt'
            journal.mkdir(parents=True)
            (journal / 'rollback.json').write_text('{}')
            (root / 'pending.json').write_text(json.dumps({'backup': str(journal)}))
            with patch.object(s, 'ROOT', root), patch.object(s, 'BACKUPS', root / 'backups'), \
                 patch.object(s, 'confirm', return_value=True), patch.object(s, 'rollback') as rollback:
                s.recover_pending(Mock(), True)
                rollback.assert_called_once()
                self.assertFalse((root / 'pending.json').exists())
                self.assertTrue((journal / 'rollback.json').exists())

    def test_outside_backup_path_is_rejected_without_mutation(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / 'pending.json').write_text(json.dumps({'backup': str(root / 'elsewhere')}))
            with patch.object(s, 'ROOT', root), patch.object(s, 'BACKUPS', root / 'backups'):
                with self.assertRaises(s.SetupError):
                    s.pending_transaction()


class Channel:
    def __init__(self, chunks):
        self.chunks = list(chunks)

    def recv_ready(self):
        return bool(self.chunks)

    def recv(self, size):
        return self.chunks.pop(0)

    def recv_stderr_ready(self):
        return False

    def exit_status_ready(self):
        return not self.chunks


class SSHProtocolTests(unittest.TestCase):
    def test_partial_messages_are_preserved(self):
        channel = Channel([b'{"log":"te', b'st"}\n{"done":', b'true}\n'])
        self.assertEqual(list(c.worker_messages(channel)), [{'log': 'test'}, {'done': True}])

    def test_broken_response_is_not_success(self):
        with self.assertRaises(s.SetupError):
            list(c.worker_messages(Channel([b'{"done":'])))

    def test_invalid_response_is_actionable_without_raw_data(self):
        with self.assertRaises(s.SetupError) as error:
            list(c.worker_messages(Channel([b'sample-secret-value\n'])))
        self.assertNotIn('sample-secret-value', str(error.exception))

    def test_silent_connection_is_bounded(self):
        channel = Channel([])
        channel.exit_status_ready = lambda: False
        with patch.object(c.time, 'monotonic', side_effect=[0, 181]):
            with self.assertRaises(s.SetupError):
                list(c.worker_messages(channel))


class LocalAPITests(unittest.TestCase):
    @unittest.skipUnless(shutil.which('openssl'), 'Local TLS fixture requires openssl')
    def test_api_subprocess_with_local_trusted_tls_server(self):
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                body = json.dumps({'response': [{'name': 'Fixture'}]}).encode()
                self.send_response(200)
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        with tempfile.TemporaryDirectory() as folder:
            cert, key = Path(folder) / 'cert.pem', Path(folder) / 'key.pem'
            subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                '-keyout', str(key), '-out', str(cert), '-days', '1', '-subj', '/CN=localhost',
                '-addext', 'subjectAltName=IP:127.0.0.1'], capture_output=True, check=True, timeout=15)
            server = HTTPServer(('127.0.0.1', 0), Handler)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(cert, key)
            server.socket = context.wrap_socket(server.socket, server_side=True)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                with patch.dict(os.environ, {'SSL_CERT_FILE': str(cert)}):
                    api = s.API(f'https://127.0.0.1:{server.server_port}', 'fixture-token')
                    self.assertEqual(api.request('GET', '/api/nodes'), [{'name': 'Fixture'}])
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)
