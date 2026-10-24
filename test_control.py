import base64
import json
import os
import socket
import tempfile
import threading
import unittest
import urllib.request
from pathlib import Path
from unittest.mock import patch
from http.server import ThreadingHTTPServer

import control
import file_server
import storage


class FilesTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.share = self.root / 'shared'
        self.share.mkdir()
        (self.share / 'hello.txt').write_text('hello')
        self.users = self.root / 'users.dpapi'
        self.log = self.root / 'access.jsonl'
        self.permissions(read=True)
        file_server.AUTH_FAILURES.clear()
        self.server = ThreadingHTTPServer(('127.0.0.1', 0), lambda *a, **kw: file_server.FileHandler(*a, directory=str(self.share), users_path=self.users, access_log=self.log, **kw))
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.url = 'http://127.0.0.1:' + str(self.server.server_port)

    def permissions(self, **permissions):
        storage.write(self.users, {'users': [{'id': 'reader', 'password': '001234', 'permissions': permissions}]})

    def request(self, path, method='GET', data=None, password='001234', **headers):
        auth = base64.b64encode(('reader:' + password).encode()).decode()
        req = urllib.request.Request(self.url + path, data=data, method=method, headers={'Authorization': 'Basic ' + auth, **headers})
        try:
            with urllib.request.urlopen(req) as response:
                return response.status, response.read()
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        self.temp.cleanup()

    def test_encrypted_accounts_and_read(self):
        self.assertNotIn(b'001234', self.users.read_bytes())
        self.assertEqual(self.request('/hello.txt'), (200, b'hello'))
        self.assertEqual(self.request('/hello.txt', password='bad')[0], 401)
        entry = json.loads(self.log.read_text().splitlines()[0])
        self.assertIn('requestId', entry)
        self.assertEqual(entry['client'], '127.0.0.1')

    def test_permissions_enforced(self):
        self.assertEqual(self.request('/new.txt', 'PUT', b'new')[0], 403)
        self.permissions(read=True, upload=True)
        self.assertEqual(self.request('/new.txt', 'PUT', b'new')[0], 201)
        self.assertEqual(self.request('/new.txt', 'PUT', b'changed')[0], 403)
        self.permissions(read=True, upload=True, modify=True)
        self.assertEqual(self.request('/new.txt', 'PUT', b'changed')[0], 204)
        self.assertEqual(self.request('/new.txt', 'MOVE', Destination='/renamed.txt')[0], 403)
        self.permissions(read=True, rename=True)
        self.assertEqual(self.request('/new.txt', 'MOVE', Destination='/renamed.txt')[0], 204)
        self.assertEqual(self.request('/renamed.txt', 'DELETE')[0], 403)
        self.permissions(read=True, delete=True)
        self.assertEqual(self.request('/renamed.txt', 'DELETE')[0], 204)

    def test_traversal_and_rate_limit(self):
        (self.root / 'secret.txt').write_text('outside')
        self.assertNotIn(b'outside', self.request('/../secret.txt')[1])
        for _ in range(10):
            self.assertEqual(self.request('/hello.txt', password='bad')[0], 401)
        self.assertEqual(self.request('/hello.txt', password='bad')[0], 429)


class WorkflowTest(unittest.TestCase):
    def test_quoted_manual_tool_path_is_normalized_and_used(self):
        with tempfile.TemporaryDirectory() as folder:
            executable = Path(folder) / 'frpc.exe'
            executable.write_text('placeholder')
            with patch.object(control, 'RAW_FIND', return_value={'frpc': {'installed': False, 'path': None}}), patch.object(control, 'settings', return_value={'frpcPath': f'"{executable}"'}):
                found = control.find_tools()
        self.assertEqual(found['frpc'], {'installed': True, 'path': str(executable)})
        self.assertEqual(control.clean_tool_path("  'C:\\Tools\\caddy.exe' "), r'C:\Tools\caddy.exe')

    def test_ipv6_inbound_probe_is_first_and_blocks_file_service(self):
        task = {'id': 'ipv6-preflight', 'steps': []}
        control.CANCEL[task['id']] = threading.Event()
        with patch.object(control, 'ipv6_inbound_probe', side_effect=ValueError('inbound blocked')), patch.object(control, 'local_service') as local, patch.object(control, 'task_save'), patch.object(control, 'log'):
            with self.assertRaisesRegex(ValueError, 'inbound blocked'):
                control.publish(control.Job(task), 'ipv6', {})
        self.assertEqual([step['title'] for step in task['steps']], ['检测公网 IPv6 入站能力'])
        local.assert_not_called()

    def test_ipv6_inbound_probe_uses_only_assigned_address_and_cleans_up(self):
        class Listener:
            port = 43128
            entered = False
            closed = False
            def __enter__(self):
                self.entered = True
                return self
            def __exit__(self, *_):
                self.closed = True

        listener = Listener()
        info = {'available': True, 'globalAddresses': [{'IPAddress': '2001:4860:4860::8888'}]}
        with patch.object(control.core, 'probe', return_value={'ipv6': info}), patch.object(control, 'IPv6ProbeListener', return_value=listener), patch.object(control, 'external_port_status', return_value=('OPEN', {})) as external:
            result = control.ipv6_inbound_probe({'ipv6': '2001:4860:4860::8888'})
        external.assert_called_once_with('2001:4860:4860::8888', 43128)
        self.assertEqual(result['address'], '2001:4860:4860::8888')
        self.assertTrue(listener.entered)
        self.assertTrue(listener.closed)

    def test_ipv6_inbound_timeout_stops_before_dns(self):
        class Listener:
            port = 43128
            def __enter__(self): return self
            def __exit__(self, *_): pass

        info = {'available': True, 'globalAddresses': [{'IPAddress': '2001:4860:4860::8888'}]}
        with patch.object(control.core, 'probe', return_value={'ipv6': info}), patch.object(control, 'IPv6ProbeListener', return_value=Listener()), patch.object(control, 'external_port_status', return_value=('TIMEOUT', {})):
            with self.assertRaisesRegex(ValueError, '未写 DNS、未启动文件服务'):
                control.ipv6_inbound_probe({})

    def test_ipv6_probe_listener_is_independent_of_caddy(self):
        with control.IPv6ProbeListener() as listener:
            with socket.create_connection(('::1', listener.port), timeout=1) as connection:
                self.assertEqual(connection.recv(64), b'exposure-ipv6-probe\n')

    def test_cloudflare_get_retries_connection_reset(self):
        class Response:
            def __enter__(self):
                return self
            def __exit__(self, *args):
                return False
            def read(self):
                return b'{"success": true, "result": {"ok": true}}'

        reset = urllib.error.URLError(ConnectionResetError(10054, 'connection reset'))
        with patch.object(control.core.urllib.request, 'urlopen', side_effect=[reset, Response()]) as request, patch.object(control.core.time, 'sleep') as sleep:
            self.assertEqual(control.core.cf_api('token', 'GET', '/test'), {'ok': True})
        self.assertEqual(request.call_count, 2)
        sleep.assert_called_once_with(1)

    def test_ipv6_aaaa_rejects_existing_cname(self):
        def api(token, method, path, payload=None):
            if path.startswith('/zones?name='):
                return [{'id': 'zone', 'name': 'example.com'}]
            if '/dns_records?name=' in path:
                return [{'id': 'record', 'type': 'CNAME', 'content': 'tunnel.cfargotunnel.com'}]
            self.fail(f'unexpected API call: {method} {path}')

        with patch.object(control.core, 'cf_api', side_effect=api):
            with self.assertRaisesRegex(ValueError, '不能同时使用 CNAME 与 AAAA'):
                control.core.cf_upsert_direct_aaaa({'apiToken': 'token', 'hostname': 'files.example.com', 'ipv6': '2001:4860:4860::8888'})

    def test_local_routes_cannot_share_hostname(self):
        routes = {'cloudflare': {'hostname': 'files.example.com', 'tunnelId': 'tunnel'}}
        with patch.object(control.storage, 'read', return_value=routes):
            with self.assertRaisesRegex(ValueError, '不能同时用于 CNAME Tunnel 与 AAAA'):
                control.ensure_hostname_available('ipv6', 'files.example.com')

    def test_api_tunnel_name_is_checked_before_creation(self):
        def api(token, method, path, payload=None):
            if '/dns_records?name=' in path:
                return []
            if '/cfd_tunnel?' in path:
                return [{'id': 'other', 'name': 'shared-name'}]
            self.fail(f'unexpected API call: {method} {path}')

        with patch.object(control, 'find_tools', return_value={'cloudflared': {'path': 'fake.exe'}}), patch.object(control.storage, 'read', return_value={}), patch.object(control, 'domain_zone', return_value={'id': 'zone', 'account': {'id': 'account'}}), patch.object(control.core, 'cf_api', side_effect=api):
            with self.assertRaisesRegex(ValueError, '名称“shared-name”已存在'):
                control.cf_start({'cfMode': 'api', 'localPort': 8080, 'hostname': 'files.example.com', 'tunnelName': 'shared-name', 'apiToken': 'fake'})

    def test_api_aaaa_confirmation_allows_local_dns_cache_lag(self):
        dns_record = {'zoneId': 'zone', 'recordId': 'record'}
        remote = {'type': 'AAAA', 'content': '2001:4860:4860::8888'}
        with patch.object(control.core, 'cf_api', return_value=remote), patch.object(control.socket, 'getaddrinfo', side_effect=socket.gaierror(11001, 'not found')):
            message = control.confirm_ipv6_dns({'apiToken': 'token'}, 'files.example.com', '2001:4860:4860::8888', dns_record)
        self.assertIn('不再将其误判为失败', message)

    def test_tool_discovery_uses_existing_resolver_once(self):
        tools = {name: {'path': f'C:/tools/{name}.exe'} for name in control.TOOL_NAMES}
        task = {'id': 'discovery-test', 'steps': []}
        control.CANCEL[task['id']] = threading.Event()
        with patch.object(control, 'find_tools', return_value=tools) as finder, patch.object(control, 'settings', return_value={}), patch.object(control.storage, 'write'), patch.object(control, 'cmd', side_effect=lambda args, **kwargs: args[0] + ' version'):
            result = control.discover_tool_paths(control.Job(task))
        finder.assert_called_once_with()
        self.assertEqual(set(result['verified']), set(control.TOOL_NAMES))
        self.assertEqual(result['missing'], [])

    def test_cloudflare_active_connections_get_bounded_retries(self):
        attempts = []
        def fail():
            attempts.append(1)
            raise ValueError('Error deleting tunnel: code: 1022, tunnel has active connections')
        with patch.object(control.time, 'sleep') as sleep:
            with self.assertRaisesRegex(ValueError, '没有结束其他 cloudflared 进程'):
                control.delete_tunnel_with_retry(fail)
        self.assertEqual(len(attempts), 3)
        self.assertEqual([call.args[0] for call in sleep.call_args_list], [2, 4])

    def test_dns_lookup_failure_is_not_reported_as_tunnel_stopped(self):
        message = control.verification_error(urllib.error.URLError('[Errno 11001] getaddrinfo failed'))
        self.assertIn('入口进程仍在运行', message)
        self.assertIn('本机 DNS 无法解析', message)

    def test_visitor_urls_are_empty_until_route_is_created(self):
        settings = {**control.DEFAULTS, 'serverAddr': '203.0.113.10', 'remotePort': 18080, 'hostname': 'files.example.com', 'cfMode': 'api'}
        with patch.object(control, 'settings', return_value=settings), patch.object(control.storage, 'read', return_value={}):
            urls = control.visitor_urls()
        self.assertEqual(set(urls), set(control.ROUTES))
        self.assertTrue(all(item['url'] is None for item in urls.values()))
        self.assertTrue(all(not item['active'] for item in urls.values()))
        self.assertTrue(all('暂无访客地址' in item['detail'] for item in urls.values()))

    def test_visitor_url_is_retained_after_stop_but_removed_after_delete(self):
        record = {'frp': {'url': 'http://203.0.113.10:18080', 'active': False}}
        with patch.object(control, 'settings', return_value=control.DEFAULTS), patch.object(control.storage, 'read', return_value=record):
            urls = control.visitor_urls()
        self.assertEqual(urls['frp']['url'], 'http://203.0.113.10:18080')
        self.assertFalse(urls['frp']['active'])
        record.pop('frp')
        with patch.object(control, 'settings', return_value=control.DEFAULTS), patch.object(control.storage, 'read', return_value=record):
            urls = control.visitor_urls()
        self.assertIsNone(urls['frp']['url'])

    def test_tailscale_adopts_unrecorded_config_only_for_current_service(self):
        status = {'BackendState': 'Running', 'Self': {'DNSName': 'device.example.ts.net.'}}
        config = {'Web': {'device.example.ts.net:443': {'Handlers': {'/': {'Proxy': 'http://127.0.0.1:26462'}}}}}
        def run(args, **kwargs):
            if args[1:3] == ['status', '--json']:
                return json.dumps(status)
            if args[1:4] == ['serve', 'status', '--json']:
                return json.dumps(config)
            if args[1:3] == ['serve', '--bg']:
                return 'Serve started'
            return json.dumps(config)
        with patch.object(control, 'find_tools', return_value={'tailscale': {'path': 'tailscale.exe'}}), patch.object(control, 'cmd', side_effect=run), patch.object(control.storage, 'read', return_value={}):
            result = control.tail_start('serve', {'localPort': 26462})
        self.assertEqual(result['url'], 'https://device.example.ts.net')
        self.assertEqual(result['targetPort'], 26462)
        self.assertNotIn('active', result)

    def test_tailscale_does_not_adopt_unrelated_existing_config(self):
        status = {'BackendState': 'Running', 'Self': {'DNSName': 'device.example.ts.net.'}}
        config = {'Web': {'device.example.ts.net:443': {'Handlers': {'/': {'Proxy': 'http://127.0.0.1:25743'}}}}}
        def run(args, **kwargs):
            if args[1:3] == ['status', '--json']:
                return json.dumps(status)
            return json.dumps(config)
        with patch.object(control, 'find_tools', return_value={'tailscale': {'path': 'tailscale.exe'}}), patch.object(control, 'cmd', side_effect=run), patch.object(control.storage, 'read', return_value={}):
            with self.assertRaisesRegex(ValueError, '127.0.0.1:25743'):
                control.tail_start('serve', {'localPort': 26462})

    def test_existing_user_cannot_be_silently_overwritten(self):
        with patch.object(control, 'users', return_value=[{'id': 'reader'}]):
            with self.assertRaisesRegex(ValueError, '已经存在'):
                control.change_user({'id': 'reader', 'password': '123456'})

    def test_quick_tunnel_preserves_existing_named_tunnel(self):
        with patch.object(control, 'find_tools', return_value={'cloudflared': {'path': 'fake.exe'}}), patch.object(control.storage, 'read', return_value={'cloudflare': {'tunnelId': 'existing'}}), patch.object(control, 'launch') as launch:
            with self.assertRaisesRegex(ValueError, '固定域名'):
                control.cf_start({'cfMode': 'quick', 'localPort': 8080})
            launch.assert_not_called()

    def test_api_tunnel_does_not_overwrite_existing_dns(self):
        with patch.object(control, 'find_tools', return_value={'cloudflared': {'path': 'fake.exe'}}), patch.object(control.storage, 'read', return_value={}), patch.object(control, 'domain_zone', return_value={'id': 'zone', 'account': {'id': 'account'}}), patch.object(control.core, 'cf_api', return_value=[{'content': 'unrelated.example.com'}]) as api:
            with self.assertRaisesRegex(ValueError, '不会覆盖'):
                control.cf_start({'cfMode': 'api', 'localPort': 8080, 'hostname': 'files.example.com', 'apiToken': 'fake'})
            self.assertEqual(api.call_count, 1)
            self.assertEqual(api.call_args.args[1], 'GET')

    def test_failed_step_is_not_success(self):
        task = {'id': 'test', 'steps': []}
        control.CANCEL['test'] = threading.Event()
        with patch.object(control, 'task_save'), patch.object(control, 'log'):
            with self.assertRaises(ValueError):
                control.Job(task).step('test', lambda: (_ for _ in ()).throw(ValueError('rejected')))
        self.assertEqual(task['steps'][0]['status'], 'failed')

    def test_cancel_prevents_step(self):
        task = {'id': 'test', 'steps': []}
        control.CANCEL['test'] = threading.Event()
        control.CANCEL['test'].set()
        with self.assertRaises(control.Cancelled):
            control.Job(task).step('test', lambda: self.fail('cancelled step executed'))

    def test_secret_redaction(self):
        control.SECRETS.add('a-private-secret')
        self.assertNotIn('a-private-secret', control.redact('value a-private-secret'))


if __name__ == '__main__':
    unittest.main()
