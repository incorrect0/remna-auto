import copy
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import unittest
from unittest.mock import patch, Mock, PropertyMock
import urllib.error
import uuid

SPEC = importlib.util.spec_from_file_location('remna_setup', Path(__file__).resolve().parents[1] / 'setup.py')
s = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(s)
PROFILE = str(uuid.uuid4())
INBOUND = str(uuid.uuid4())
NODE = str(uuid.uuid4())


def config():
    return dict(panel_url='https://panel.example.com', domain='node.example.com',
                node_address='203.0.113.12', node_name='Test-Node', node_port=3001,
                country_code='DE', panel_ips=['198.51.100.10', '2001:db8::1'],
                profile_uuid=PROFILE, inbound_uuids=[INBOUND], profile_name='Profile A', vpn_ports=[8443])


def inbound():
    return {'tag': 'REALITY', 'port': 8443, 'streamSettings': {'security': 'reality',
            'realitySettings': {'target': '127.0.0.1:443', 'serverNames': ['node.example.com'], 'xver': 0}}}


class FakeAPI:
    def __init__(self):
        self.calls = []
        self.nodes = []
        self.profile = {'uuid': PROFILE, 'name': 'Profile A', 'config': {'inbounds': [inbound()]},
                        'inbounds': [{'uuid': INBOUND, 'tag': 'REALITY', 'port': 8443, 'type': 'vless'}]}

    def request(self, method, path, body=None):
        self.calls.append((method, path, copy.deepcopy(body)))
        if method == 'GET':
            if path == '/api/config-profiles':
                return {'configProfiles': [self.profile]}
            if path.startswith('/api/config-profiles/'):
                return copy.deepcopy(self.profile)
            if path == '/api/nodes':
                return copy.deepcopy(self.nodes)
            if path.startswith('/api/nodes/'):
                return copy.deepcopy(next(n for n in self.nodes if n['uuid'] == path.split('/')[-1]))
        if method == 'POST' and path == '/api/nodes':
            result = {'uuid': NODE, **body}
            self.nodes.append(result)
            return copy.deepcopy(result)
        if method == 'PATCH':
            node = next(n for n in self.nodes if n['uuid'] == body['uuid'])
            node.update(body)
            return copy.deepcopy(node)
        if method == 'DELETE':
            self.nodes = [n for n in self.nodes if n['uuid'] != path.split('/')[-1]]
            return None
        raise AssertionError((method, path))


class Tx:
    def __init__(self, install_id='operation-id', **extra):
        self.data = dict(install_id=install_id, **extra)

    def save(self):
        pass


class ValidationTests(unittest.TestCase):
    def test_defaults_and_ipv6(self):
        c = s.validate_config(config())
        self.assertEqual(c['node_port'], 3001)
        self.assertNotIn('panel_ips', c)

    def test_auto_name_collision_and_fallback(self):
        nodes = [{'uuid': NODE, 'name': 'Germany'}, {'name': 'Germany 1'}]
        self.assertEqual(s.automatic_name('Germany', nodes), 'Germany 2')
        self.assertEqual(s.automatic_name('Germany', nodes, NODE), 'Germany')
        self.assertEqual(s.automatic_name('auto-install', []), 'auto-install 1')

    def test_country_lookup_and_fallback(self):
        response = Mock()
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=False)
        response.read.return_value = json.dumps({'ip': '203.0.113.12', 'country_code': 'DE',
                                                'country_name': 'Germany'}).encode()
        opener = Mock();opener.open.return_value = response
        with patch.object(s.urllib.request, 'build_opener', return_value=opener):
            self.assertEqual(s.geo_lookup('203.0.113.12', 'ipapi'), ('DE', 'Germany'))
        with patch.object(s.subprocess, 'run', side_effect=subprocess.TimeoutExpired('geo', 3)) as calls:
            self.assertEqual(s.country_for_ipv4('203.0.113.12'), ('XX', 'auto-install'))
            self.assertEqual(calls.call_count, 2)
            self.assertTrue(all(call.kwargs['timeout'] <= 3 for call in calls.call_args_list))

    def test_geo_fallback_provider(self):
        with patch.object(s.subprocess, 'run', side_effect=[OSError('offline'),
                Mock(stdout='["DE", "Germany"]')]) as calls:
            self.assertEqual(s.country_for_ipv4('203.0.113.12'), ('DE', 'Germany'))
            self.assertEqual(calls.call_count, 2)

    def test_geo_global_deadline(self):
        with patch.object(s.time, 'monotonic', side_effect=[0, 0, 7]), \
             patch.object(s.subprocess, 'run', side_effect=subprocess.TimeoutExpired('geo', 3)) as calls:
            self.assertEqual(s.country_for_ipv4('203.0.113.12'), ('XX', 'auto-install'))
            self.assertEqual(calls.call_count, 1)

    def test_auto_inbounds_skip_reserved_and_duplicate_ports(self):
        api = FakeAPI();c = config();c['inbound_uuids'] = []
        for port in [443, 3001, 8443]:
            raw = inbound();raw['port'] = port;raw['tag'] = 'port-' + str(port)
            api.profile['config']['inbounds'].append(raw)
            api.profile['inbounds'].append({'uuid': str(uuid.uuid4()), 'tag': raw['tag'], 'port': port})
        with patch.object(s, 'occupied', return_value=''), patch.object(s, 'owned_node_pids', return_value=set()):
            s.choose_profile(api, c, False)
        self.assertEqual(c['inbound_uuids'], [INBOUND])
        self.assertEqual(c['vpn_ports'], [8443])

    def test_auto_inbounds_none_remaining(self):
        api = FakeAPI();c = config();c['inbound_uuids'] = []
        api.profile['config']['inbounds'][0]['port'] = 443
        with patch.object(s, 'owned_node_pids', return_value=set()), self.assertRaises(s.SetupError):
            s.choose_profile(api, c, False)

    def test_bbr_supported_persists_and_unsupported_skips(self):
        tx = Mock();tx.data = {}
        def execute(args, **kwargs):
            result = Mock(returncode=0)
            result.stdout = ('cubic bbr' if args[-1] == 'net.ipv4.tcp_available_congestion_control'
                             else 'bbr' if args == ['sysctl', '-n', 'net.ipv4.tcp_congestion_control'] else 'fq_codel')
            return result
        with patch.object(s, 'run', side_effect=execute):
            s.enable_bbr(tx)
        tx.write.assert_called_once()
        self.assertIn('bbr_previous', tx.data)
        tx = Mock();tx.data = {}
        with patch.object(s, 'run', return_value=Mock(stdout='cubic', returncode=0)):
            s.enable_bbr(tx)
        tx.write.assert_not_called()

    def test_bbr_failure_restores_previous_runtime(self):
        tx = Mock();tx.data = {}
        def execute(args, **kwargs):
            if args == ['sysctl', '-w', 'net.ipv4.tcp_congestion_control=bbr']:
                raise s.SetupError('denied')
            value = ('cubic bbr' if args[-1] == 'net.ipv4.tcp_available_congestion_control'
                     else 'cubic' if args[-1] == 'net.ipv4.tcp_congestion_control' else 'fq_codel')
            return Mock(stdout=value, returncode=0)
        with patch.object(s, 'run', side_effect=execute) as commands:
            s.enable_bbr(tx)
        commands.assert_any_call(['sysctl', '-w', 'net.core.default_qdisc=fq_codel'], check=False)
        commands.assert_any_call(['sysctl', '-w', 'net.ipv4.tcp_congestion_control=cubic'], check=False)
        tx.write.assert_not_called()

    def test_domain_cannot_inject_caddy(self):
        for bad in ['https://x.test', 'x.test:443', '*.test.com', 'x.test\n{ abort }', 'x.test/path', 'x.test;id']:
            with self.subTest(bad=bad), self.assertRaises(s.SetupError):
                s.validate_domain(bad)

    def test_panel_https_without_credentials_or_path(self):
        for bad in ['http://x.test', 'https://user:pass@x.test', 'https://x.test/api', 'https://x.test?a=1']:
            with self.subTest(bad=bad), self.assertRaises(s.SetupError):
                s.validate_panel_url(bad)

    def test_ports(self):
        for value in [0, 65536, -1, True, '443\nhi', '3.1', None]:
            with self.subTest(value=value), self.assertRaises(s.SetupError):
                s.validate_port(value)

    def test_management_port_fixed_and_no_allowlist(self):
        c = config();c['node_port'] = 443;c['panel_ips'] = []
        actual = s.validate_config(c)
        self.assertEqual(actual['node_port'], 3001)
        self.assertNotIn('panel_ips', actual)

    @patch.object(s.ipaddress.IPv4Address, 'is_global', new_callable=PropertyMock, return_value=True)
    def test_ipv4_local_without_dns(self, _global):
        with patch.object(s, 'local_ips', return_value={'203.0.113.12'}), \
             patch.object(s, 'resolve', side_effect=s.SetupError('no DNS')) as dns:
            self.assertEqual(s.detect_ipv4('node.example.com'), '203.0.113.12')
            dns.assert_not_called()

    @patch.object(s.ipaddress.IPv4Address, 'is_global', new_callable=PropertyMock, return_value=True)
    def test_ipv4_external_without_domain_dns(self, _global):
        with patch.object(s, 'local_ips', return_value=set()), \
             patch.object(s, 'resolve', side_effect=s.SetupError('no DNS')), \
             patch.object(s, 'run', side_effect=s.SetupError('no route')), \
             patch.object(s, 'external_ipv4', return_value='203.0.113.12'):
            self.assertEqual(s.detect_ipv4('node.example.com'), '203.0.113.12')

    @patch.object(s.ipaddress.IPv4Address, 'is_global', new_callable=PropertyMock, return_value=True)
    def test_ipv4_detection_dns_fallback_and_ambiguity(self, _global):
        with patch.object(s, 'local_ips', return_value=set()), \
             patch.object(s, 'resolve', return_value={'203.0.113.12'}), \
             patch.object(s, 'run', side_effect=s.SetupError('no route')), \
             patch.object(s, 'external_ipv4', return_value=None):
            self.assertEqual(s.detect_ipv4('node.example.com'), '203.0.113.12')
        with patch.object(s, 'local_ips', return_value=set()), \
             patch.object(s, 'resolve', return_value=set()), \
             patch.object(s, 'run', side_effect=s.SetupError('no route')), \
             patch.object(s, 'external_ipv4', return_value=None), self.assertRaises(s.SetupError):
            s.detect_ipv4('node.example.com')

    def test_only_official_images(self):
        c = config();c['node_image'] = 'unknown/evil:latest'
        with self.assertRaises(s.SetupError):
            s.validate_config(c)

    def test_caddy_exact_public_site(self):
        self.assertEqual(s.caddyfile('node.example.com'),
                         'node.example.com:443 {\n    root * /var/www/site\n    try_files {path} /index.html\n    file_server\n}\n')
        self.assertNotIn('remote_ip', s.caddyfile('node.example.com'))

    def test_profile_selected_without_mutations(self):
        api = FakeAPI();c = config()
        s.choose_profile(api, c, False)
        self.assertEqual(c['vpn_ports'], [8443])
        self.assertTrue(all(method == 'GET' for method, _, _ in api.calls))

    def test_selected_ids_must_belong_to_profile(self):
        api = FakeAPI();c = config();c['inbound_uuids'] = [str(uuid.uuid4())]
        with self.assertRaises(s.SetupError):
            s.choose_profile(api, c, False)

    def test_conflicting_vpn_ports(self):
        for port in [22, 80, 443, 3001, '400-500']:
            raw = inbound();raw['port'] = port
            with self.subTest(port=port), self.assertRaises(s.SetupError):
                s.validate_inbound(raw, config())

    def test_selfsteal_target_sni_and_proxy_protocol(self):
        for key, value in [('target', ''), ('serverNames', ['other.test']), ('xver', 1)]:
            raw = inbound();raw['streamSettings']['realitySettings'][key] = value
            with self.subTest(key=key), self.assertRaises(s.SetupError):
                s.validate_inbound(raw, config())

    def test_external_reality_target_preserved(self):
        raw = inbound();raw['streamSettings']['realitySettings'] = {
            'dest': 'other.test:443', 'serverNames': ['other.test'], 'xver': 1}
        original = copy.deepcopy(raw)
        self.assertEqual(s.validate_inbound(raw, config()), {8443})
        self.assertEqual(raw, original)

    def test_nonreality_profile_allowed(self):
        self.assertEqual(s.validate_inbound({'tag': 'tls', 'port': 9443}, config()), {9443})

    def test_secret_redaction(self):
        s.SECRETS.append('super-secret-token')
        self.assertNotIn('super-secret-token', s.safe('Oops super-secret-token'))

    def test_atomic_replaces_file_and_sets_permissions(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / 'secret'
            s.atomic(p, 'first');s.atomic(p, 'second')
            self.assertEqual(p.read_text(), 'second')
            self.assertEqual(len(list(Path(d).iterdir())), 1)
            if os.name == 'posix':
                self.assertEqual(p.stat().st_mode & 0o777, 0o600)

    def test_wrong_dns_defers_https(self):
        c = config()
        with patch.object(s, 'resolve', side_effect=[{'203.0.113.12', '2001:db8::99'}, {'203.0.113.12'}]), \
             patch.object(s, 'local_ips', return_value={'203.0.113.12'}):
            self.assertFalse(s.check_dns(c))
            self.assertFalse(c['dns_ready'])

    def test_missing_dns_defers_https(self):
        c = config()
        with patch.object(s, 'resolve', side_effect=s.SetupError('no DNS')):
            self.assertFalse(s.check_dns(c))
            self.assertFalse(c['dns_ready'])

    @unittest.skipUnless(os.name == 'posix', 'POSIX file modes')
    def test_public_site_readable_under_private_umask(self):
        old=os.umask(0o077)
        try:
            with tempfile.TemporaryDirectory() as d:
                public=Path(d)/'index.html';private=Path(d)/'.env'
                s.atomic(public,'site',0o644);s.atomic(private,'secret',0o600)
                self.assertEqual(public.stat().st_mode & 0o777,0o644)
                self.assertEqual(private.stat().st_mode & 0o777,0o600)
        finally:
            os.umask(old)

    def test_good_dns(self):
        with patch.object(s, 'resolve', return_value={'203.0.113.12'}), \
             patch.object(s, 'local_ips', return_value={'203.0.113.12'}):
            s.check_dns(config())


class LifecycleTests(unittest.TestCase):
    def test_install_without_dns_preserves_node_and_skips_tls(self):
        api=FakeAPI();original=api.request
        def request(method,path,body=None):
            if path=='/api/keygen':return {'secretKey':'NODE_SECRET_ONLY'}
            return original(method,path,body)
        api.request=request
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            with patch.object(s,'ROOT',root/'owned'),patch.object(s,'BACKUPS',root/'backups'), \
                 patch.object(s,'CADDY',root/'Caddyfile'),patch.object(s,'run',return_value=Mock(returncode=1,stdout='')), \
                 patch.object(s,'preflight'),patch.object(s,'install_dependencies'),patch.object(s,'prepare_local'), \
                 patch.object(s,'verify_tls',side_effect=AssertionError('TLS must not block missing DNS')),patch.object(s,'wait_connected',return_value={'isConnected':True}):
                cfg=config();cfg['dns_ready']=False
                s.install(cfg,api,{})
            state=json.loads((root/'owned/state.json').read_text())
            self.assertEqual(state['node_uuid'],NODE)
            self.assertFalse(state['config']['tls_ready'])
            self.assertNotIn('NODE_SECRET_ONLY',(root/'owned/state.json').read_text())
            self.assertEqual(len(api.nodes),1)

    def test_failed_healthcheck_rolls_back_new_api_node(self):
        api=FakeAPI();original=api.request
        def request(method,path,body=None):
            if path=='/api/keygen':return {'secretKey':'NODE_SECRET_ONLY'}
            return original(method,path,body)
        api.request=request
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            with patch.object(s,'ROOT',root/'owned'),patch.object(s,'STACK',root/'stack'), \
                 patch.object(s,'BACKUPS',root/'backups'),patch.object(s,'CADDY',root/'Caddyfile'), \
                 patch.object(s,'run',return_value=Mock(returncode=1,stdout='')),patch.object(s,'preflight'), \
                 patch.object(s,'install_dependencies'),patch.object(s,'prepare_local'),patch.object(s,'verify_tls'), \
                 patch.object(s,'wait_connected',side_effect=s.SetupError('Unreachable node')):
                with self.assertRaises(s.SetupError):s.install(config(),api,{})
            self.assertEqual(api.nodes,[])
            self.assertFalse((root/'owned/state.json').exists())

    def test_creation_payload_and_operation_marker(self):
        api=FakeAPI();tx=Tx()
        result=s.register_node(api,config(),{},tx)
        self.assertEqual(result,NODE)
        self.assertEqual(len(api.nodes),1)
        self.assertEqual(api.nodes[0]['configProfile']['activeInbounds'],[INBOUND])
        self.assertTrue(tx.data['registration_attempted'])
        self.assertEqual(tx.data['new_node_uuid'],NODE)

    def test_lost_post_response_reconciles_not_duplicates(self):
        api=FakeAPI();original=api.request
        def request(method,path,body=None):
            result=original(method,path,body)
            if method=='POST':
                raise s.SetupError('network timeout')
            return result
        api.request=request
        tx=Tx()
        self.assertEqual(s.register_node(api,config(),{},tx),NODE)
        self.assertEqual(len(api.nodes),1)

    def test_unknown_post_failure_is_not_success(self):
        api=FakeAPI();original=api.request
        def request(method,path,body=None):
            if method=='POST':raise s.SetupError('network timeout')
            return original(method,path,body)
        api.request=request
        with self.assertRaises(s.SetupError):s.register_node(api,config(),{},Tx())

    def test_repeat_install_updates_same_owned_uuid(self):
        api=FakeAPI();node={'uuid':NODE,**s.node_body(config(),'operation-id')}
        node['configProfile']['activeInbounds']=[{'uuid':INBOUND}]
        api.nodes=[node]
        tx=Tx()
        self.assertEqual(s.register_node(api,config(),{'node_uuid':NODE},tx),NODE)
        self.assertEqual(len(api.nodes),1)
        self.assertTrue(any(m=='PATCH' for m,_,_ in api.calls))
        self.assertEqual(tx.data['previous_node']['uuid'],NODE)

    def test_foreign_node_update_blocked(self):
        api=FakeAPI();api.nodes=[{'uuid':NODE,'note':'someone else'}]
        with self.assertRaises(s.SetupError):s.register_node(api,config(),{'node_uuid':NODE},Tx())
        self.assertFalse(any(m in ('PATCH','DELETE') for m,_,_ in api.calls))

    def test_partial_failure_restores_files_and_owned_node(self):
        api=FakeAPI();api.nodes=[{'uuid':NODE,'note':'remna-auto:operation-id'}]
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'Caddyfile';path.write_text('new config')
            saved={'bytes':s.base64.b64encode(b'previous config').decode(),'mode':0o644}
            data={'install_id':'operation-id','new_node_uuid':NODE,'files':{str(path):saved},
                  'previous_state':{},'caddy_was_active':False,'firewall_was_active':False}
            with patch.object(s,'run',return_value=Mock(returncode=0,stdout='')),patch.object(s,'compose'), \
                 patch.object(s,'STACK',Path(d)/'empty'):
                s.rollback(data,api)
            self.assertEqual(path.read_text(),'previous config')
            self.assertEqual(api.nodes,[])

    def test_post_failure_recovery_discovers_own_node_only(self):
        api=FakeAPI();api.nodes=[{'uuid':NODE,'note':'remna-auto:operation-id'}, {'uuid':'foreign','note':'other'}]
        data={'install_id':'operation-id','registration_attempted':True,'new_node_uuid':None,'files':{},
              'previous_state':{},'caddy_was_active':False,'firewall_was_active':False}
        with patch.object(s,'run',return_value=Mock(returncode=0,stdout='')),patch.object(s,'compose'):
            s.rollback(data,api)
        self.assertEqual([n['uuid'] for n in api.nodes],['foreign'])

    def test_unauthorized_api_is_not_retried_or_leaked(self):
        api=s.API('https://panel.example.com','super-secret-token')
        api.opener=Mock()
        api.opener.open.side_effect=urllib.error.HTTPError('https://panel.example.com/api/nodes',401,'Unauthorized',{},None)
        with self.assertRaises(s.SetupError) as exc:api.request('POST','/api/nodes',{})
        self.assertNotIn('super-secret-token',str(exc.exception))
        self.assertEqual(api.opener.open.call_count,1)

    def test_redirect_rejected(self):
        with self.assertRaises(s.SetupError):
            s.NoRedirect().redirect_request(None,None,302,'Redirect',{},'https://evil.example')


if __name__ == '__main__':
    unittest.main()
